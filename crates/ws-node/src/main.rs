//! ws-node: one binary for a node of the workspace and the tools around it.
//!
//!   ws-node proof --net sim [--out DIR]              the 14-step proof, three nodes in one process
//!   ws-node init --out DIR --nodes N1=http://h:p,... a tenant: node configs and the proof identities
//!   ws-node serve CONFIG                             a real node: its cells, its peers, the gateway page
//!   ws-node proof --net real --dir DIR [--out DIR]   the same proof against real nodes
//!   ws-node verify FILE                              offline check of an exported receipt log
//!   ws-node mcp --node URL --identity FILE           the agent door (MCP over stdio); no exec, no shell
//!   ws-node contract                                 print the generated contract

mod http;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use ws_core::audit::{verify_log, Receipt};
use ws_core::gate::{Chain, Envelope, Key};
use ws_core::node::{Answer, Directory, NoRunner, Node, Remote, Runner};
use ws_core::proof::{self, People};
use ws_core::sim::{Client, Mesh, Net, Tenant};

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

fn arg(args: &[String], k: &str) -> Option<String> {
    args.iter().position(|a| a == k).and_then(|i| args.get(i + 1).cloned())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(|s| s.as_str()) {
        Some("proof") => cmd_proof(&args),
        Some("init") => cmd_init(&args),
        Some("serve") => cmd_serve(&args),
        Some("verify") => cmd_verify(&args),
        Some("mcp") => cmd_mcp(&args),
        Some("contract") => {
            println!("{}", serde_json::to_string_pretty(&ws_core::contract::contract_json()).unwrap());
            0
        }
        _ => {
            eprintln!("usage: ws-node proof|init|serve|verify|mcp|contract (see the source header)");
            2
        }
    };
    std::process::exit(code);
}

fn worker_runner(dir: &Path, tools: bool) -> Box<dyn Runner> {
    Box::new(ws_box::BoxRunner::detect(dir, tools))
}

fn write_report(r: &proof::Report, out: Option<String>, stem: &str) {
    for s in &r.steps {
        println!("{:>2} {} {:<62} {:>6} ms", s.n, if s.holds { "ok  " } else { "FAIL" }, s.title, s.ms);
    }
    println!("{} of {} steps hold on --net {}; {} receipts, log verifies: {}", r.passed, r.total, r.net, r.receipts.len(), r.verify.as_ref().map(|v| v.ok).unwrap_or(false));
    if let Some(o) = out {
        std::fs::create_dir_all(&o).ok();
        let p = Path::new(&o).join(format!("{stem}.json"));
        std::fs::write(&p, serde_json::to_string_pretty(r).unwrap()).unwrap();
        println!("wrote {}", p.display());
    }
}

fn cmd_proof(args: &[String]) -> i32 {
    let net = arg(args, "--net").unwrap_or("sim".into());
    let out = arg(args, "--out");
    let t0 = std::time::Instant::now();
    let clock = move || t0.elapsed().as_millis() as u64;
    if net == "sim" {
        let start = 1_800_000_000_000u64;
        let mut t = Tenant::new(b"live-devenv/sim/root", &[("N1", b"sim/N1".to_vec()), ("N2", b"sim/N2".to_vec()), ("N3", b"sim/N3".to_vec())], start);
        let mut p = proof::people(&mut t, start);
        let work = std::env::temp_dir().join(format!("ws-sim-{}", std::process::id()));
        let mut nodes = vec![t.node(0, Box::new(NoRunner)), t.node(1, Box::new(NoRunner)), t.node(2, worker_runner(&work, true))];
        let class = nodes[2].runner.isolation();
        let min = std::env::var("WS_MIN_CLASS").unwrap_or("ns+landlock+seccomp".into());
        for n in nodes.iter_mut() {
            n.min_class = min.clone();
        }
        println!("sim: worker N3 measured isolation class {class}; workspace minimum {min}");
        let mut mesh = Mesh::new(nodes, start);
        let keys = t.dir.nodes.iter().map(|n| n.1.clone()).collect();
        let r = proof::run(&mut mesh, &mut p, keys, &clock);
        if let Some(o) = &out {
            // what the browser replays: run results keyed by the source snapshot, artifacts left out
            let replay: Vec<Value> = r.runs.iter().map(|x| x.clone()).collect();
            std::fs::create_dir_all(o).ok();
            std::fs::write(Path::new(o).join("sim-runs.json"), serde_json::to_string_pretty(&replay_table(&mesh)).unwrap()).ok();
            let _ = replay;
        }
        write_report(&r, out, "sim");
        std::fs::remove_dir_all(&work).ok();
        return if r.passed == r.total { 0 } else { 1 };
    }
    let dir = PathBuf::from(arg(args, "--dir").unwrap_or("tenant".into()));
    let nodes: Vec<(String, String, String)> = serde_json::from_str(&std::fs::read_to_string(dir.join("nodes.json")).expect("nodes.json")).unwrap();
    let mut p = load_people(&dir);
    let mut real = RealNet { urls: nodes.iter().map(|n| n.1.clone()).collect() };
    let keys = nodes.iter().map(|n| n.2.clone()).collect();
    let r = proof::run(&mut real, &mut p, keys, &clock);
    write_report(&r, out, &format!("real-{}", now_ms()));
    if r.passed == r.total {
        0
    } else {
        1
    }
}

/// Every run the worker made, keyed by (tool, source files), with stdout and exit. The page replays these.
fn replay_table(mesh: &Mesh) -> Value {
    let n = mesh.node(2);
    let mut rows = vec![];
    for (rcpt, man) in n.cache.values() {
        let src: Vec<&(String, String)> = man.iter().filter(|(p, _)| !p.starts_with("out/")).collect();
        let log = n.fs.blobs.get(&rcpt.log).map(|b| String::from_utf8_lossy(b).into_owned()).unwrap_or_default();
        rows.push(json!({"tool": rcpt.tool, "source": ws_core::hj(&src), "exit": rcpt.exit, "stdout": log, "isolation": rcpt.isolation}));
    }
    json!(rows)
}

// ---------------------------------------------------------------- tenant files

#[derive(Serialize, Deserialize)]
struct NodeConfig {
    idx: usize,
    name: String,
    listen: String,
    peers: Vec<String>,
    secret: String,
    chain: Chain,
    dir: Directory,
    worker: bool,
    #[serde(default)]
    site: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default = "default_class")]
    min_class: String,
    #[serde(default)]
    sync_ms: u64,
    /// The keys node of a signed-in deployment: the tenant root (kept here only) and who may sign in.
    #[serde(default)]
    root_secret: Option<String>,
    #[serde(default)]
    people: std::collections::BTreeMap<String, String>,
    /// The gate's person key on this host (HMAC-SHA256 over the signed person header), read at start.
    #[serde(default)]
    person_key_file: Option<String>,
    /// The index of the node that holds ws.keys.
    #[serde(default)]
    keys_node: usize,
    /// /tick and /cut, for the proof driver only; off on a deployed node.
    #[serde(default)]
    test_controls: bool,
}

fn default_class() -> String {
    "ns+landlock+seccomp".into()
}

#[derive(Serialize, Deserialize)]
struct Identity {
    name: String,
    secret: String,
    chain: Chain,
}

fn os_seed() -> [u8; 32] {
    let mut b = [0u8; 32];
    use std::io::Read;
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).expect("/dev/urandom");
    b
}

fn cmd_init(args: &[String]) -> i32 {
    let out = PathBuf::from(arg(args, "--out").unwrap_or("tenant".into()));
    let spec = arg(args, "--nodes").expect("--nodes N1=http://host:port,N2=...,N3=...");
    let worker = arg(args, "--worker").unwrap_or("N3".into());
    // --private: a deployed workspace (root kept in N1's ws.keys for sign-in sessions, anti-entropy every 2 s,
    // no test controls); without it, a proof tenant
    let private = args.iter().any(|a| a == "--private");
    let keep_root = private || args.iter().any(|a| a == "--keep-root");
    let listen_port = |u: &str| u.rsplit(':').next().unwrap_or("7480").trim_end_matches('/').to_string();
    let list: Vec<(String, String)> = spec.split(',').map(|kv| kv.split_once('=').map(|(a, b)| (a.to_string(), b.to_string())).expect("N=url")).collect();
    let now = now_ms();
    let seeds: Vec<(&str, Vec<u8>)> = list.iter().map(|(n, _)| (n.as_str(), os_seed().to_vec())).collect();
    let mut t = Tenant::new(&os_seed(), &seeds, now);
    let p = proof::people(&mut t, now);
    std::fs::create_dir_all(&out).unwrap();
    let mut nodes = vec![];
    for (i, (name, url)) in list.iter().enumerate() {
        let cfg = NodeConfig {
            idx: i,
            name: name.clone(),
            listen: if private { url.trim_start_matches("http://").trim_end_matches('/').to_string() } else { format!("0.0.0.0:{}", listen_port(url)) },
            peers: list.iter().map(|x| x.1.clone()).collect(),
            secret: ws_core::hex(&t.node_keys[i].seed_bytes()),
            chain: t.node_chains[i].clone(),
            dir: t.dir.clone(),
            worker: *name == worker,
            site: None,
            state: None,
            min_class: default_class(),
            sync_ms: if private { 2000 } else { 0 },
            root_secret: if i == 0 && keep_root { Some(ws_core::hex(&t.root.seed_bytes())) } else { None },
            people: std::collections::BTreeMap::new(),
            person_key_file: None,
            keys_node: 0,
            test_controls: !private,
        };
        std::fs::write(out.join(format!("{name}.json")), serde_json::to_string_pretty(&cfg).unwrap()).unwrap();
        nodes.push((name.clone(), url.clone(), t.node_keys[i].pk()));
    }
    std::fs::write(out.join("nodes.json"), serde_json::to_string_pretty(&nodes).unwrap()).unwrap();
    for c in [&p.h1, &p.h2, &p.a1, &p.a2] {
        let id = Identity { name: c.name.clone(), secret: ws_core::hex(&c.key.seed_bytes()), chain: c.chain.clone() };
        std::fs::write(out.join(format!("id-{}.json", c.name)), serde_json::to_string_pretty(&id).unwrap()).unwrap();
    }
    // without --keep-root the tenant root is not written anywhere: nothing can mint a new chain from it.
    // with it, the root goes only into N1's file, the node that runs ws.keys and issues sign-in sessions.
    println!("tenant {} with {} nodes in {}; root {}", &t.dir.root[..16], nodes.len(), out.display(), if keep_root { "kept in N1's ws.keys only" } else { "discarded after issuing" });
    0
}

fn load_identity(path: &Path) -> Client {
    let id: Identity = serde_json::from_str(&std::fs::read_to_string(path).expect("identity file")).unwrap();
    let b: [u8; 32] = ws_core::unhex(&id.secret).unwrap().try_into().unwrap();
    Client::from_parts(&id.name, Key::from_secret(b), id.chain)
}

fn load_people(dir: &Path) -> People {
    let l = |n: &str| load_identity(&dir.join(format!("id-{n}.json")));
    People { h1: l("H1"), h2: l("H2"), a1: l("A1"), a2: l("A2") }
}

// ---------------------------------------------------------------- real network

struct RealNet {
    urls: Vec<String>,
}

fn post(url: &str, path: &str, body: &Value, secs: u64) -> Result<Value, String> {
    http::request("POST", url, path, &body.to_string(), secs).and_then(|s| serde_json::from_str(&s).map_err(|e| e.to_string()))
}

impl Net for RealNet {
    fn call(&mut self, node: usize, env: &Envelope) -> Answer {
        match post(&self.urls[node], "/call", &json!(env), 600) {
            Ok(v) => serde_json::from_value(v).unwrap_or(Answer::Error("bad answer".into())),
            Err(e) => Answer::Error(e),
        }
    }
    fn tick(&mut self, rounds: usize) {
        for _ in 0..rounds {
            for u in &self.urls {
                post(u, "/tick", &json!({}), 60).ok();
            }
        }
    }
    fn cut(&mut self, node: usize, cut: bool) {
        for u in &self.urls {
            post(u, "/cut", &json!({"node": node, "cut": cut}), 30).ok();
        }
    }
    fn status(&mut self, node: usize) -> Value {
        http::request("GET", &self.urls[node], "/status", "", 30).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(Value::Null)
    }
    fn advance(&mut self, _: u64) {}
    fn now(&self) -> u64 {
        now_ms()
    }
    fn label(&self) -> String {
        "real".into()
    }
}

/// A node's view of its peers over HTTP. Calls to a cut-off peer fail like a partition would.
struct Peers {
    me: usize,
    urls: Vec<String>,
    cut: Arc<Mutex<BTreeSet<usize>>>,
}

impl Remote for Peers {
    fn call(&mut self, node: usize, env: &Envelope) -> Answer {
        let cut = self.cut.lock().unwrap();
        if cut.contains(&node) || cut.contains(&self.me) {
            return Answer::Error("unreachable".into());
        }
        drop(cut);
        match post(&self.urls[node], "/peer", &json!(env), 300) {
            Ok(v) => serde_json::from_value(v).unwrap_or(Answer::Error("bad answer".into())),
            Err(e) => Answer::Error(e),
        }
    }
}

#[derive(Serialize, Deserialize, Default)]
struct State {
    fs: ws_core::fs::Replica,
    audit: ws_core::audit::Log,
    revoked: BTreeSet<String>,
    tools: std::collections::BTreeMap<String, ws_core::cells::Tool>,
    changes: std::collections::BTreeMap<String, ws_core::cells::ChangeSet>,
    commits: Vec<ws_core::cells::Commit>,
    derived: std::collections::BTreeMap<String, String>,
}

fn save(n: &Node, path: &Option<String>) {
    let Some(p) = path else { return };
    let st = State { fs: n.fs.clone(), audit: n.audit.clone(), revoked: n.revoked.clone(), tools: n.tools.clone(), changes: n.changes.clone(), commits: n.commits.clone(), derived: n.derived.clone() };
    let tmp = format!("{p}.tmp");
    if std::fs::write(&tmp, serde_json::to_vec(&st).unwrap()).is_ok() {
        std::fs::rename(tmp, p).ok();
    }
}

fn cmd_serve(args: &[String]) -> i32 {
    let path = args.get(1).expect("serve CONFIG");
    let cfg: NodeConfig = serde_json::from_str(&std::fs::read_to_string(path).expect("config")).expect("config json");
    let b: [u8; 32] = ws_core::unhex(&cfg.secret).unwrap().try_into().unwrap();
    let work = std::env::temp_dir().join(format!("ws-node-{}", cfg.name));
    let runner: Box<dyn Runner> = if cfg.worker { worker_runner(&work, true) } else { Box::new(NoRunner) };
    let mut node = Node::new(cfg.idx, &cfg.name, Key::from_secret(b), cfg.chain.clone(), cfg.dir.clone(), runner);
    node.min_class = cfg.min_class.clone();
    if let Some(r) = &cfg.root_secret {
        node.root_key = Some(Key::from_secret(ws_core::unhex(r).unwrap().try_into().unwrap()));
        node.people = cfg.people.clone();
    }
    let person_key: Option<Vec<u8>> = cfg.person_key_file.as_ref().and_then(|p| std::fs::read_to_string(p).ok()).and_then(|s| ws_core::unhex(s.trim()));
    if let Some(sp) = &cfg.state {
        if let Ok(s) = std::fs::read(sp) {
            if let Ok(st) = serde_json::from_slice::<State>(&s) {
                node.fs = st.fs;
                node.audit = st.audit;
                node.revoked = st.revoked;
                node.tools = st.tools;
                node.changes = st.changes;
                node.commits = st.commits;
                node.derived = st.derived;
            }
        }
    }
    eprintln!("{} listening on {} (isolation {}, tools {:?})", cfg.name, cfg.listen, node.runner.isolation(), node.runner.tools().keys().collect::<Vec<_>>());
    let node = Arc::new(Mutex::new(node));
    let cut = Arc::new(Mutex::new(BTreeSet::new()));
    let peers = cfg.peers.clone();
    if cfg.sync_ms > 0 {
        let (node, cut, peers, me, state) = (node.clone(), cut.clone(), peers.clone(), cfg.idx, cfg.state.clone());
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_millis(cfg.sync_ms));
            for j in 0..peers.len() {
                if j == me {
                    continue;
                }
                let mut net = Peers { me, urls: peers.clone(), cut: cut.clone() };
                if let Ok(mut n) = node.try_lock() {
                    n.now = now_ms();
                    n.sync_with(j, &mut net);
                    save(&n, &state);
                }
            }
        });
    }
    let site = cfg.site.clone();
    let state = cfg.state.clone();
    http::serve(&cfg.listen, move |req: &http::Req| {
        let (method, path, body) = (req.method.as_str(), req.path.as_str(), req.body.as_str());
        let mk = || Peers { me: cfg.idx, urls: peers.clone(), cut: cut.clone() };
        match (method, path) {
            ("POST", "/call") | ("POST", "/peer") => {
                let Ok(env) = serde_json::from_str::<Envelope>(body) else { return (400, "application/json", json!({"error": "not an envelope"}).to_string().into()) };
                if path == "/peer" && cut.lock().unwrap().contains(&cfg.idx) {
                    return (200, "application/json", json!(Answer::Error("unreachable".into())).to_string().into());
                }
                let mut net = mk();
                let a = {
                    let deadline = std::time::Instant::now() + Duration::from_secs(if path == "/peer" { 5 } else { 600 });
                    let mut g = loop {
                        if let Ok(g) = node.try_lock() {
                            break Some(g);
                        }
                        if std::time::Instant::now() > deadline {
                            break None;
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    };
                    match g.as_mut() {
                        Some(n) => {
                            n.now = now_ms();
                            let a = n.handle(&env, &mut net);
                            save(n, &state);
                            a
                        }
                        None => Answer::Error("busy".into()),
                    }
                };
                let a = match a {
                    Answer::Forward(t) => net.call_any(t, &env),
                    a => a,
                };
                (200, "application/json", json!(a).to_string().into())
            }
            ("POST", "/tick") | ("POST", "/cut") if !cfg.test_controls => (404, "text/plain", "not found".into()),
            ("POST", "/tick") => {
                let mut n = node.lock().unwrap();
                n.now = now_ms();
                let mut ok = vec![];
                for j in 0..peers.len() {
                    if j != cfg.idx {
                        let mut net = mk();
                        ok.push(n.sync_with(j, &mut net));
                    }
                }
                save(&n, &state);
                (200, "application/json", json!({"synced": ok}).to_string().into())
            }
            ("POST", "/cut") => {
                let v: Value = serde_json::from_str(body).unwrap_or_default();
                let i = v["node"].as_u64().unwrap_or(99) as usize;
                let mut c = cut.lock().unwrap();
                if v["cut"].as_bool().unwrap_or(false) {
                    c.insert(i);
                } else {
                    c.remove(&i);
                }
                (200, "application/json", json!({"cut": *c}).to_string().into())
            }
            ("GET", "/status") => {
                let n = node.lock().unwrap();
                (200, "application/json", json!({"name": n.name, "boxes_started": n.boxes_started, "content_hash": n.fs.content_hash(), "conflicts": n.fs.conflicts("").len(), "receipts": n.audit.len(), "isolation": n.runner.isolation(), "tools": n.runner.tools(), "rejected": n.rejected.len(), "key": n.pk()}).to_string().into())
            }
            ("GET", "/session") => {
                // a person signed in at the apps gate: the gate's signed person header, checked here, then ws.keys
                // issues an 8-hour chain to the browser's own key. The browser key never leaves the browser.
                let (Some(person), Some(at), Some(sig), Some(key)) = (req.header("X-Ce-Person"), req.header("X-Ce-Person-At"), req.header("X-Ce-Person-Sig"), person_key.as_ref()) else {
                    return (403, "application/json", json!({"error": "sign in at apps.ce-net.com first"}).to_string().into());
                };
                let fresh = at.parse::<u64>().map(|t| (now_ms() / 1000).abs_diff(t) < 300).unwrap_or(false);
                if !fresh || !person_sig_ok(key, person, at, sig) {
                    return (403, "application/json", json!({"error": "the signed person header does not verify"}).to_string().into());
                }
                let Some(pk) = req.q("pk").filter(|p| p.len() == 64 && ws_core::unhex(p).is_some()) else {
                    return (400, "application/json", json!({"error": "pk"}).to_string().into());
                };
                let mut net = mk();
                let env = node.lock().unwrap().sign(json!({"op": "KeysSession", "person": person, "pk": pk}));
                let a = if cfg.keys_node == cfg.idx {
                    let mut n = node.lock().unwrap();
                    n.now = now_ms();
                    n.handle(&env, &mut net)
                } else {
                    net.call(cfg.keys_node, &env)
                };
                (200, "application/json", json!(a).to_string().into())
            }
            ("GET", "/directory") => {
                let n = node.lock().unwrap();
                (200, "application/json", json!(n.dir).to_string().into())
            }
            ("GET", p) => match &site {
                Some(dir) => http::static_file(dir, p),
                None => (404, "text/plain", "no page on this node".into()),
            },
            _ => (404, "text/plain", "not found".into()),
        }
    });
    0
}

impl Peers {
    /// Forward a client's own envelope to the node that holds a single cell.
    fn call_any(&mut self, node: usize, env: &Envelope) -> Answer {
        match post(&self.urls[node], "/call", &json!(env), 600) {
            Ok(v) => serde_json::from_value(v).unwrap_or(Answer::Error("bad answer".into())),
            Err(e) => Answer::Error(e),
        }
    }
}

fn person_sig_ok(key: &[u8], person: &str, at: &str, sig: &str) -> bool {
    use hmac::{Hmac, Mac};
    let Ok(mut m) = Hmac::<sha2::Sha256>::new_from_slice(key) else { return false };
    m.update(format!("ce-person\n{person}\n{at}").as_bytes());
    ws_core::unhex(sig).map(|s| m.verify_slice(&s).is_ok()).unwrap_or(false)
}

fn cmd_verify(args: &[String]) -> i32 {
    let path = args.get(1).expect("verify FILE");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).expect("file")).expect("json");
    let receipts: Vec<Receipt> = serde_json::from_value(v["receipts"].clone()).expect("receipts");
    let keys: Vec<String> = serde_json::from_value(v["node_keys"].clone()).expect("node_keys");
    let r = verify_log(&receipts, &keys);
    println!("{} receipts in {} chains, {} refusals: {}", r.receipts, r.chains, r.refused, if r.ok { "every link and signature valid" } else { "INVALID" });
    for e in &r.errors {
        println!("  {e}");
    }
    if r.ok {
        0
    } else {
        1
    }
}

/// MCP over stdio. The session is bound to one identity's chain; the tool list is filtered by it.
fn cmd_mcp(args: &[String]) -> i32 {
    use std::io::{BufRead, Write};
    let url = arg(args, "--node").expect("--node URL");
    let mut me = load_identity(Path::new(&arg(args, "--identity").expect("--identity FILE")));
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let Ok(req) = serde_json::from_str::<Value>(&line) else { continue };
        let id = req.get("id").cloned();
        let method = req["method"].as_str().unwrap_or("");
        let result = match method {
            "initialize" => json!({"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "ws.mcp", "version": "1"}}),
            "tools/list" => json!({"tools": ws_core::contract::mcp_tools(&|r| me.chain.holds(r))}),
            "tools/call" => {
                let name = req["params"]["name"].as_str().unwrap_or("");
                match ws_core::contract::mcp_to_op(name, &req["params"]["arguments"]) {
                    None => json!({"isError": true, "content": [{"type": "text", "text": format!("no tool {name}; there is no exec or shell tool")}]}),
                    Some(op) => {
                        let env = me.env(op);
                        let a = post(&url, "/call", &json!(env), 600).unwrap_or_else(|e| json!({"error": e}));
                        let err = a.get("ok").is_none();
                        json!({"isError": err, "content": [{"type": "text", "text": a.to_string()}]})
                    }
                }
            }
            _ => {
                if id.is_none() {
                    continue;
                }
                json!({})
            }
        };
        if let Some(id) = id {
            writeln!(out, "{}", json!({"jsonrpc": "2.0", "id": id, "result": result})).ok();
            out.flush().ok();
        }
    }
    0
}
