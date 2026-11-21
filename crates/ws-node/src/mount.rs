//! `ws-node mount`: a plain directory kept in step with a workspace, for programs that want files on disk (a wrapped
//! editor such as T3 Code). Not FUSE: a poll loop over the same signed ops the page and `ws.mcp` use, under one
//! identity's chain.
//!
//! - Remote to disk: a file the chain may read is written to the directory; a file it may not read is never listed,
//!   so it is never written. A remote change replaces the local copy only while the local copy is unchanged.
//! - Disk to remote: a local change goes out as `FsPatch` range edits against the version it was based on. With
//!   `ws.fs:write` on the path it lands in the shared tree (merged with concurrent edits); with only
//!   `ws.fs:propose` it lands in the identity's own change set and goes through review. A refusal is counted and
//!   not retried until the file changes again.
//! - `.git/` and dot-directories of the program stay local; nothing is deleted remotely in this slice.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use ws_core::text::Doc;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Track {
    /// The shared text last written to (or found equal on) disk, and its version and hash.
    pub remote: String,
    pub version: Value,
    pub hash: String,
    /// The text sent into our own change set, when the chain may only propose.
    pub pushed: Option<String>,
    /// Local text that was refused; not sent again until it changes.
    pub refused: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct MountState {
    pub files: BTreeMap<String, Track>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub pulled: usize,
    pub shared: usize,
    pub proposed: usize,
    pub refused: usize,
    pub created: usize,
    pub removed: usize,
}

fn skip(rel: &str) -> bool {
    rel.split('/').any(|c| c == ".git" || c == ".ws-mount" || c == "node_modules" || c == "target") || rel.ends_with(".ws-tmp")
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let Ok(ft) = e.file_type() else { continue };
        let p = e.path();
        let rel = p.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
        if skip(&rel) || ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            walk(root, &p, out);
        } else if ft.is_file() {
            out.push(rel);
        }
    }
}

fn write_file(root: &Path, rel: &str, text: &str) -> std::io::Result<()> {
    let p = root.join(rel);
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = PathBuf::from(format!("{}.ws-tmp", p.display()));
    std::fs::write(&tmp, text)?;
    std::fs::rename(tmp, p)
}

fn safe(rel: &str) -> bool {
    !rel.is_empty() && !rel.starts_with('/') && !rel.split('/').any(|c| c == ".." || c.is_empty())
}

/// A cheap signature of the directory (paths, sizes, mtimes): a round runs only when it or the workspace changed,
/// so an idle mount writes no receipts.
pub fn local_sig(root: &Path) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut files = vec![];
    walk(root, root, &mut files);
    files.sort();
    let mut h = std::collections::hash_map::DefaultHasher::new();
    for f in files {
        f.hash(&mut h);
        if let Ok(m) = std::fs::metadata(root.join(&f)) {
            m.len().hash(&mut h);
            m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_nanos()).hash(&mut h);
        }
    }
    h.finish()
}

/// One round. `call` sends one op under the mount's identity and returns the node's answer as JSON.
pub fn once(call: &mut dyn FnMut(Value) -> Value, root: &Path, st: &mut MountState) -> Stats {
    let mut s = Stats::default();
    let listed = call(json!({"op": "FsList", "prefix": ""}));
    let Some(list) = listed.get("ok").and_then(|v| v.as_array()) else { return s };
    let mut seen = std::collections::BTreeSet::new();
    for l in list {
        let (Some(path), Some(hash)) = (l["path"].as_str(), l["hash"].as_str()) else { continue };
        if l["kind"] != "Text" || !safe(path) || skip(path) {
            continue;
        }
        seen.insert(path.to_string());
        let local = std::fs::read(root.join(path)).ok().and_then(|b| String::from_utf8(b).ok());
        let tr = st.files.get(path).cloned();
        // fetch the shared text when it is new to us or changed
        let fresh = match &tr {
            Some(t) if t.hash == hash => None,
            _ => {
                let r = call(json!({"op": "FsRead", "path": path}));
                match r.get("ok") {
                    Some(ok) => Some((ok["text"].as_str().unwrap_or("").to_string(), ok["version"].clone(), ok["hash"].as_str().unwrap_or(hash).to_string())),
                    None => continue,
                }
            }
        };
        let mut t = tr.unwrap_or_default();
        let first = !st.files.contains_key(path);
        let ours = t.pushed.clone().unwrap_or_else(|| t.remote.clone());
        let clean = match &local {
            None => true,
            Some(x) => (first && fresh.as_ref().map(|f| &f.0 == x).unwrap_or(false)) || (!first && *x == ours),
        };
        if let Some((text, version, h)) = fresh {
            if clean && t.pushed.is_none() {
                if local.as_deref() != Some(text.as_str()) && write_file(root, path, &text).is_ok() {
                    s.pulled += 1;
                }
                t = Track { remote: text, version, hash: h, pushed: None, refused: None };
                st.files.insert(path.into(), t);
                continue;
            }
            if first {
                // a local file that differs from the shared one at the first round: it is our edit on that base
                t.remote = text;
                t.version = version;
                t.hash = h;
            } else if t.pushed.is_none() {
                // both moved: keep the old base; our edits go against it and ws.fs maps them onto the present
                t.hash = h;
            }
        }
        let Some(local) = local else {
            st.files.insert(path.into(), t);
            continue;
        };
        let base_text = t.pushed.clone().unwrap_or_else(|| t.remote.clone());
        if local == base_text || t.refused.as_deref() == Some(local.as_str()) {
            st.files.insert(path.into(), t);
            continue;
        }
        let edits = Doc::diff(&base_text, &local);
        let a = call(json!({"op": "FsPatch", "path": path, "base": t.version, "edits": edits}));
        match a.get("ok") {
            Some(ok) if ok["shared"] == false => {
                t.pushed = Some(local);
                t.refused = None;
                s.proposed += 1;
            }
            Some(_) => {
                // shared: read the merged text back and write it if the file did not change meanwhile
                let r = call(json!({"op": "FsRead", "path": path}));
                if let Some(ok) = r.get("ok") {
                    let text = ok["text"].as_str().unwrap_or("").to_string();
                    if text != local {
                        write_file(root, path, &text).ok();
                    }
                    t = Track { remote: text, version: ok["version"].clone(), hash: ok["hash"].as_str().unwrap_or("").into(), pushed: None, refused: None };
                }
                s.shared += 1;
            }
            None => {
                t.refused = Some(local);
                s.refused += 1;
            }
        }
        st.files.insert(path.into(), t);
    }
    // gone remotely, or no longer readable: a clean local copy goes too
    let gone: Vec<String> = st.files.keys().filter(|p| !seen.contains(*p)).cloned().collect();
    for p in gone {
        let t = st.files.remove(&p).unwrap();
        let local = std::fs::read_to_string(root.join(&p)).ok();
        if t.hash.is_empty() {
            // a local file that was never shared: keep remembering its refusal while it is unchanged
            if local.is_some() && local == t.refused {
                st.files.insert(p, t);
            }
            continue;
        }
        if local.as_deref() == Some(t.pushed.as_deref().unwrap_or(&t.remote)) {
            std::fs::remove_file(root.join(&p)).ok();
            s.removed += 1;
        }
    }
    // new local files
    let mut files = vec![];
    walk(root, root, &mut files);
    for p in files {
        if st.files.contains_key(&p) || seen.contains(&p) || !safe(&p) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(root.join(&p)) else { continue };
        let a = call(json!({"op": "FsWrite", "path": p, "content": text}));
        if let Some(ok) = a.get("ok") {
            st.files.insert(p.clone(), Track { remote: text, version: ok["version"].clone(), hash: ok["hash"].as_str().unwrap_or("").into(), pushed: None, refused: None });
            s.created += 1;
        } else {
            // remembered as refused so it is not sent every round; a change to the file sends it again
            st.files.insert(p.clone(), Track { remote: String::new(), version: Value::Null, hash: String::new(), pushed: None, refused: Some(text) });
            s.refused += 1;
        }
    }
    s
}
