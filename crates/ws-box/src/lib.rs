//! `ws-box`: one boxed run (stands in for agent.box). The child gets new user, mount, network, IPC and UTS
//! namespaces (so no network device), a Landlock ruleset (read and execute on the system, the toolchain and
//! the read-only checkout; write only in its scratch directory), a seccomp filter (no new sockets, no ptrace, no
//! mounts, no new namespaces, no module or kexec calls), rlimits and a wall-clock limit. The class it could
//! give is measured at start and written into every receipt.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use ws_core::cells::{RunOut, RunReq};
use ws_core::node::Runner;

pub struct BoxRunner {
    pub work: PathBuf,
    pub rustc: Option<PathBuf>,
    pub sysroot: Option<PathBuf>,
    pub class: String,
    tools: BTreeMap<String, String>,
    n: u64,
}

fn find_rustc() -> Option<(PathBuf, PathBuf)> {
    let out = Command::new("rustc").arg("--print").arg("sysroot").output().ok()?;
    let sys = PathBuf::from(String::from_utf8(out.stdout).ok()?.trim());
    let r = sys.join("bin/rustc");
    r.exists().then_some((r, sys))
}

impl BoxRunner {
    /// `with_tools`: offer the compile tool on this node (a worker); without it the node only runs
    /// artifacts of an input snapshot.
    pub fn detect(work: &Path, with_tools: bool) -> BoxRunner {
        std::fs::create_dir_all(work).ok();
        let class = sandbox::measure();
        let mut tools = BTreeMap::new();
        let (mut rustc, mut sysroot) = (None, None);
        if with_tools {
            if let Some((r, s)) = find_rustc() {
                if let Ok(bytes) = std::fs::read(&r) {
                    tools.insert("rustc-test".to_string(), ws_core::ref_of("ws.tools", "bin", &ws_core::h(&bytes)));
                    rustc = Some(r);
                    sysroot = Some(s);
                }
            }
        }
        BoxRunner { work: work.to_path_buf(), rustc, sysroot, class, tools, n: 0 }
    }
}

impl Runner for BoxRunner {
    fn isolation(&self) -> String {
        self.class.clone()
    }
    fn tools(&self) -> BTreeMap<String, String> {
        self.tools.clone()
    }
    fn run(&mut self, req: &RunReq, files: &[(String, Vec<u8>)]) -> Result<RunOut, String> {
        self.n += 1;
        let dir = self.work.join(format!("run-{}-{}", std::process::id(), self.n));
        let (inp, scratch) = (dir.join("in"), dir.join("scratch"));
        std::fs::create_dir_all(&scratch).map_err(|e| e.to_string())?;
        for (p, b) in files {
            if p.contains("..") || p.starts_with('/') {
                return Err(format!("bad path {p}"));
            }
            let f = inp.join(p);
            std::fs::create_dir_all(f.parent().unwrap()).map_err(|e| e.to_string())?;
            std::fs::write(&f, b).map_err(|e| e.to_string())?;
        }
        let arg = |k: &str| req.args.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let mut ro: Vec<PathBuf> = vec![inp.clone()];
        let (program, argv): (PathBuf, Vec<String>) = match req.tool.name.as_str() {
            "rustc-test" => {
                let r = self.rustc.clone().ok_or("this node has no rustc-test")?;
                ro.push(self.sysroot.clone().unwrap());
                let out = scratch.join(arg("out"));
                std::fs::create_dir_all(out.parent().unwrap()).ok();
                (r, vec!["--edition".into(), "2021".into(), "--test".into(), "-C".into(), "debuginfo=0".into(), inp.join(arg("root")).display().to_string(), "-o".into(), out.display().to_string()])
            }
            "run-test" => {
                let b = inp.join(arg("bin"));
                set_exec(&b);
                (b, vec!["--test-threads".into(), "1".into()])
            }
            other => return Err(format!("no program for tool {other} on this node")),
        };
        lock_down(&inp);
        let spec = sandbox::Spec { ro, rw: vec![scratch.clone()], class: self.class.clone(), memory_mb: req.tool.memory_mb.max(512), secs: req.tool.secs };
        let mut cmd = Command::new(&program);
        cmd.args(&argv).current_dir(&scratch).env_clear().env("PATH", "/usr/bin:/bin").env("HOME", &scratch).env("TMPDIR", &scratch).env("LANG", "C.UTF-8");
        cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        sandbox::apply(&mut cmd, spec)?;
        let mut child = cmd.spawn().map_err(|e| format!("spawn {}: {e}", program.display()))?;
        let start = Instant::now();
        let mut out_r = child.stdout.take().unwrap();
        let mut err_r = child.stderr.take().unwrap();
        let to = std::thread::spawn(move || {
            let mut s = String::new();
            std::io::Read::read_to_string(&mut out_r, &mut s).ok();
            s
        });
        let te = std::thread::spawn(move || {
            let mut s = String::new();
            std::io::Read::read_to_string(&mut err_r, &mut s).ok();
            s
        });
        let status = loop {
            if let Some(s) = child.try_wait().map_err(|e| e.to_string())? {
                break s;
            }
            if start.elapsed() > Duration::from_secs(req.tool.secs) {
                child.kill().ok();
                break child.wait().map_err(|e| e.to_string())?;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let (stdout, stderr) = (to.join().unwrap_or_default(), te.join().unwrap_or_default());
        let mut outputs = vec![];
        collect(&scratch, &scratch, &mut outputs);
        outputs.retain(|(p, _)| p.starts_with("out/"));
        unlock(&dir);
        std::fs::remove_dir_all(&dir).ok();
        Ok(RunOut { exit: status.code().unwrap_or(-1), stdout, stderr: stderr.chars().take(20_000).collect(), outputs, isolation: self.class.clone(), replayed: false })
    }
}

fn collect(base: &Path, d: &Path, out: &mut Vec<(String, Vec<u8>)>) {
    if let Ok(rd) = std::fs::read_dir(d) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                collect(base, &p, out);
            } else if let Ok(b) = std::fs::read(&p) {
                out.push((p.strip_prefix(base).unwrap().display().to_string(), b));
            }
        }
    }
}

#[cfg(unix)]
fn set_exec(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o555)).ok();
}
#[cfg(not(unix))]
fn set_exec(_: &Path) {}

/// The checkout is read-only for the box (Landlock enforces it; the modes say it too).
#[cfg(unix)]
fn lock_down(d: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(rd) = std::fs::read_dir(d) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                lock_down(&p);
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o555)).ok();
            } else {
                let m = std::fs::metadata(&p).map(|m| m.permissions().mode()).unwrap_or(0o444);
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(if m & 0o111 != 0 { 0o555 } else { 0o444 })).ok();
            }
        }
    }
}
#[cfg(not(unix))]
fn lock_down(_: &Path) {}

#[cfg(unix)]
fn unlock(d: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o755)).ok();
    if let Ok(rd) = std::fs::read_dir(d) {
        for e in rd.flatten() {
            if e.path().is_dir() {
                unlock(&e.path());
            }
        }
    }
}
#[cfg(not(unix))]
fn unlock(_: &Path) {}

#[cfg(target_os = "linux")]
pub mod sandbox {
    use landlock::{path_beneath_rules, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, ABI};
    use std::os::unix::process::CommandExt;
    use std::path::PathBuf;
    use std::process::Command;

    pub struct Spec {
        pub ro: Vec<PathBuf>,
        pub rw: Vec<PathBuf>,
        pub class: String,
        pub memory_mb: u64,
        pub secs: u64,
    }

    const SYS_RO: &[&str] = &["/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/sys/devices/system/cpu"];

    fn landlock(ro: &[PathBuf], rw: &[PathBuf]) -> Result<bool, String> {
        let abi = ABI::V1;
        let mut ro: Vec<PathBuf> = ro.to_vec();
        ro.extend(SYS_RO.iter().map(PathBuf::from).filter(|p| p.exists()));
        let st = Ruleset::default()
            .handle_access(AccessFs::from_all(abi))
            .map_err(|e| e.to_string())?
            .create()
            .map_err(|e| e.to_string())?
            .add_rules(path_beneath_rules(&ro, AccessFs::from_read(abi)))
            .map_err(|e| e.to_string())?
            .add_rules(path_beneath_rules(rw, AccessFs::from_all(abi)))
            .map_err(|e| e.to_string())?
            .add_rules(path_beneath_rules(["/dev/null", "/dev/urandom", "/dev/zero"], AccessFs::ReadFile | AccessFs::WriteFile))
            .map_err(|e| e.to_string())?
            .restrict_self()
            .map_err(|e| e.to_string())?;
        Ok(st.ruleset == RulesetStatus::FullyEnforced)
    }

    #[repr(C)]
    struct Filter {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }
    #[repr(C)]
    struct Prog {
        len: u16,
        filter: *const Filter,
    }

    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 0xc000_00b7;

    fn denied() -> Vec<libc::c_long> {
        use libc::*;
        vec![
            SYS_socket, SYS_ptrace, SYS_mount, SYS_umount2, SYS_pivot_root, SYS_unshare, SYS_setns, SYS_bpf, SYS_keyctl, SYS_add_key, SYS_request_key,
            SYS_init_module, SYS_finit_module, SYS_delete_module, SYS_kexec_load, SYS_reboot, SYS_swapon, SYS_swapoff, SYS_perf_event_open, SYS_process_vm_writev,
        ]
    }

    fn seccomp() -> Result<(), String> {
        let d = denied();
        let mut f = vec![Filter { code: 0x20, jt: 0, jf: 0, k: 4 }, Filter { code: 0x15, jt: 1, jf: 0, k: ARCH }, Filter { code: 0x06, jt: 0, jf: 0, k: 0x8000_0000 }, Filter { code: 0x20, jt: 0, jf: 0, k: 0 }];
        for nr in &d {
            f.push(Filter { code: 0x15, jt: 0, jf: 1, k: *nr as u32 });
            f.push(Filter { code: 0x06, jt: 0, jf: 0, k: 0x0005_0000 | libc::EPERM as u32 });
        }
        f.push(Filter { code: 0x06, jt: 0, jf: 0, k: 0x7fff_0000 });
        let prog = Prog { len: f.len() as u16, filter: f.as_ptr() };
        unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err("no_new_privs".into());
            }
            if libc::prctl(libc::PR_SET_SECCOMP, 2, &prog as *const Prog as libc::c_ulong, 0, 0) != 0 {
                return Err("seccomp".into());
            }
        }
        Ok(())
    }

    fn ns() -> bool {
        unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWNET | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS) == 0 }
    }

    fn rlimit(res: libc::__rlimit_resource_t, v: u64) {
        let l = libc::rlimit { rlim_cur: v, rlim_max: v };
        unsafe {
            libc::setrlimit(res, &l);
        }
    }

    /// Fork a child, try each layer, report the class it reached.
    pub fn measure() -> String {
        unsafe {
            let pid = libc::fork();
            if pid == 0 {
                let mut code = 0;
                if ns() {
                    code |= 1;
                }
                if landlock(&[], &[]).unwrap_or(false) {
                    code |= 2;
                }
                if seccomp().is_ok() {
                    code |= 4;
                }
                libc::_exit(code);
            }
            let mut st = 0;
            libc::waitpid(pid, &mut st, 0);
            let c = libc::WEXITSTATUS(st);
            match (c & 1 != 0, c & 2 != 0, c & 4 != 0) {
                (true, true, true) => "ns+landlock+seccomp",
                (_, true, true) => "landlock+seccomp",
                _ => "none",
            }
            .into()
        }
    }

    pub fn apply(cmd: &mut Command, s: Spec) -> Result<(), String> {
        let want_ns = s.class == "ns+landlock+seccomp" && std::env::var("WS_BOX_DIAG").map_or(true, |v| v != "no-ns");
        let want = s.class != "none";
        let want_ll = want && std::env::var("WS_BOX_DIAG").map_or(true, |v| v != "no-landlock");
        let want_sc = want && std::env::var("WS_BOX_DIAG").map_or(true, |v| v != "no-seccomp");
        unsafe {
            cmd.pre_exec(move || {
                if want_ns && !ns() {
                    return Err(std::io::Error::other("namespaces"));
                }
                rlimit(libc::RLIMIT_CPU, s.secs);
                rlimit(libc::RLIMIT_FSIZE, 512 << 20);
                rlimit(libc::RLIMIT_AS, (s.memory_mb.max(512) * 4) << 20);
                if want_ll && !landlock(&s.ro, &s.rw).map_err(std::io::Error::other)? {
                    return Err(std::io::Error::other("landlock not enforced"));
                }
                if want_sc {
                    seccomp().map_err(std::io::Error::other)?;
                }
                Ok(())
            });
        }
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
pub mod sandbox {
    use std::path::PathBuf;
    use std::process::Command;
    pub struct Spec {
        pub ro: Vec<PathBuf>,
        pub rw: Vec<PathBuf>,
        pub class: String,
        pub memory_mb: u64,
        pub secs: u64,
    }
    pub fn measure() -> String {
        "none".into()
    }
    pub fn apply(_: &mut Command, _: Spec) -> Result<(), String> {
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod t {
    use super::*;
    use std::process::Command;

    /// Inside the box: no network, no writes outside scratch.
    #[test]
    fn box_denies_network_and_writes() {
        let class = sandbox::measure();
        if class == "none" {
            eprintln!("host gives no sandbox class; skipped");
            return;
        }
        let tmp = std::env::temp_dir().join(format!("ws-box-test-{}", std::process::id()));
        let scratch = tmp.join("scratch");
        std::fs::create_dir_all(&scratch).unwrap();
        let outside = tmp.join("outside.txt");
        let script = format!(
            "echo hi > {s}/ok.txt && echo ok-write; echo x > {o} 2>/dev/null && echo BAD-write; (exec 3<>/dev/tcp/1.1.1.1/53) 2>/dev/null && echo BAD-net; echo done",
            s = scratch.display(),
            o = outside.display()
        );
        let mut c = Command::new("/bin/bash");
        c.arg("-c").arg(script).env_clear().env("PATH", "/usr/bin:/bin");
        sandbox::apply(&mut c, sandbox::Spec { ro: vec![], rw: vec![scratch.clone()], class: class.clone(), memory_mb: 256, secs: 10 }).unwrap();
        let out = c.output().unwrap();
        let s = String::from_utf8_lossy(&out.stdout);
        assert!(s.contains("ok-write") && s.contains("done"), "{s} / {}", String::from_utf8_lossy(&out.stderr));
        assert!(!s.contains("BAD"), "{s}");
        assert!(!outside.exists());
        std::fs::remove_dir_all(&tmp).ok();
    }
}

#[cfg(all(test, target_os = "linux"))]
mod diag {
    use super::*;
    #[test]
    fn rustc_inside_box() {
        let Some((rustc, sys)) = find_rustc() else { return };
        for mode in ["full", "no-seccomp", "no-landlock", "no-ns"] {
            std::env::set_var("WS_BOX_DIAG", mode);
            let tmp = std::env::temp_dir().join(format!("ws-box-diag-{}-{mode}", std::process::id()));
            std::fs::create_dir_all(&tmp).unwrap();
            std::fs::write(tmp.join("a.rs"), "#[test] fn t() {}").unwrap();
            let mut c = Command::new(&rustc);
            c.args(["--edition", "2021", "--test", "a.rs", "-o", "a"]).current_dir(&tmp).env_clear().env("PATH", "/usr/bin:/bin").env("TMPDIR", &tmp).env("HOME", &tmp);
            sandbox::apply(&mut c, sandbox::Spec { ro: vec![sys.clone()], rw: vec![tmp.clone()], class: "ns+landlock+seccomp".into(), memory_mb: 1024, secs: 60 }).unwrap();
            let o = c.output().unwrap();
            eprintln!("DIAG {mode}: exit {:?} {}", o.status.code(), String::from_utf8_lossy(&o.stderr).lines().take(3).collect::<Vec<_>>().join(" / "));
        }
        std::env::remove_var("WS_BOX_DIAG");
    }
}
