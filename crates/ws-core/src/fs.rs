//! `ws.fs` and `ws.snap`: one replica of the shared tree per node.
//!
//! Every accepted write becomes an `Update` with a unique (site, seq), the accepting replica's version
//! vector as its causal context, the actor's own signed request and the node's signature. Replicas exchange
//! updates by version vector; each replica re-checks the actor's chain against the update's paths before it
//! applies anything, so one bad replica cannot write as somebody else.
//!
//! The tree is derived from the update log: an entry's path is the last write by HLC; concurrent renames,
//! concurrent creates of one path, concurrent binary writes and an edit concurrent with a delete are all
//! kept as conflicts until someone with `resolve` picks. Nothing is dropped silently.

use crate::gate::{verify, Envelope, Key};
use crate::text::{vv_has, Doc, Edit, TOp, Vv};
use crate::{h, h64, hj, ref_of, Hlc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub type Uid = (u64, u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    Text,
    Bin,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "b")]
pub enum Body {
    Create { file: String, path: String, kind: Kind },
    Text { file: String, ops: Vec<TOp> },
    Bin { file: String, blob: String, data: String },
    Move { file: String, to: String },
    Delete { file: String, seen: Vv },
    Resolve { file: String, pick: String, covers: Vec<Uid> },
}

impl Body {
    pub fn file(&self) -> &str {
        match self {
            Body::Create { file, .. } | Body::Text { file, .. } | Body::Bin { file, .. } | Body::Move { file, .. } | Body::Delete { file, .. } | Body::Resolve { file, .. } => file,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Update {
    pub uid: Uid,
    pub node: String,
    pub hlc: Hlc,
    pub deps: Vv,
    pub right: String,
    pub paths: Vec<String>,
    pub env: Envelope,
    pub body: Body,
    pub nsig: String,
}

#[derive(Serialize)]
struct USig<'a> {
    uid: Uid,
    hlc: Hlc,
    deps: &'a Vv,
    right: &'a str,
    paths: &'a [String],
    env: String,
    body: &'a Body,
}

impl Update {
    fn sig_msg(&self) -> Vec<u8> {
        serde_json::to_vec(&USig { uid: self.uid, hlc: self.hlc, deps: &self.deps, right: &self.right, paths: &self.paths, env: self.env.hash(), body: &self.body }).unwrap()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Mv {
    uid: Uid,
    hlc: Hlc,
    deps: Vv,
    to: String,
    actor: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Entry {
    kind: Kind,
    created: Mv,
    moves: Vec<Mv>,
    deletes: Vec<(Uid, Vv)>,
    edits: Vec<Uid>,
    resolves: Vec<(Hlc, String, Vec<Uid>)>,
    bins: Vec<(Mv, String)>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Conflict {
    pub file: String,
    pub path: String,
    pub kind: String,
    pub sides: Vec<String>,
    pub covers: Vec<Uid>,
    /// The path the file was created at.
    pub origin: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Listed {
    pub path: String,
    pub file: String,
    pub kind: Kind,
    pub version: Vv,
    pub hash: String,
    pub conflicted: bool,
}

/// A snapshot manifest: sorted (path, blob hash).
pub type Manifest = Vec<(String, String)>;

pub fn tree_ref(m: &Manifest) -> String {
    ref_of("ws.snap", "tree", &hj(m))
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Replica {
    pub vv: Vv,
    pub log: Vec<Update>,
    pending: Vec<Update>,
    files: BTreeMap<String, Entry>,
    docs: BTreeMap<String, Doc>,
    doc_vv: BTreeMap<String, Vv>,
    pub blobs: BTreeMap<String, Vec<u8>>,
    pub snaps: BTreeMap<String, Manifest>,
    pub pins: BTreeMap<String, String>,
}

/// Why a remote update was not applied.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Rejected {
    pub uid: Uid,
    pub why: String,
}

pub struct Ctx<'a> {
    pub root: &'a str,
    pub nodes: &'a BTreeSet<String>,
}

impl Replica {
    pub fn site(actor: &str, node: &str) -> u64 {
        h64(format!("{actor}@{node}").as_bytes())
    }

    /// Accept a write that the gate already allowed on this node.
    pub fn accept(&mut self, key: &Key, hlc: Hlc, env: &Envelope, right: &str, paths: Vec<String>, body: Body) -> Update {
        let node = key.pk();
        let site = Self::site(&env.actor, &node);
        let seq = self.vv.get(&site).copied().unwrap_or(0) + 1;
        let mut u = Update { uid: (site, seq), node, hlc, deps: self.vv.clone(), right: right.into(), paths, env: env.clone(), body, nsig: String::new() };
        u.nsig = key.sign(&u.sig_msg());
        self.apply(u.clone());
        u
    }

    fn check(&self, u: &Update, cx: &Ctx) -> Result<(), String> {
        if !cx.nodes.contains(&u.node) {
            return Err("unknown node".into());
        }
        if !verify(&u.node, &u.sig_msg(), &u.nsig) {
            return Err("bad node signature".into());
        }
        if !u.env.sig_ok() {
            return Err("bad actor signature".into());
        }
        if u.uid.0 != Self::site(&u.env.actor, &u.node) {
            return Err("site does not belong to this actor and node".into());
        }
        // revocation is decided where the write is accepted; here the chain must have allowed it then
        for p in &u.paths {
            u.env.chain.check(&u.env.actor, &u.right, Some(p), None, cx.root, u.hlc.ms, &BTreeSet::new()).map_err(|r| format!("{}: {}", r.need, r.why))?;
        }
        Ok(())
    }

    /// Apply updates from a peer: verify each, deliver in causal order, keep the rest pending.
    pub fn absorb(&mut self, ups: Vec<Update>, cx: &Ctx) -> (usize, Vec<Rejected>) {
        let mut rejected = vec![];
        for u in ups {
            if vv_has(&self.vv, u.uid.0, u.uid.1) || self.pending.iter().any(|p| p.uid == u.uid) {
                continue;
            }
            match self.check(&u, cx) {
                Ok(()) => self.pending.push(u),
                Err(why) => rejected.push(Rejected { uid: u.uid, why }),
            }
        }
        let mut n = 0;
        loop {
            let Some(i) = self.pending.iter().position(|u| {
                u.uid.1 == self.vv.get(&u.uid.0).copied().unwrap_or(0) + 1 && u.deps.iter().all(|(s, q)| vv_has(&self.vv, *s, *q))
            }) else {
                break;
            };
            let u = self.pending.remove(i);
            self.apply(u);
            n += 1;
        }
        (n, rejected)
    }

    fn apply(&mut self, u: Update) {
        let mv = |to: &str| Mv { uid: u.uid, hlc: u.hlc, deps: u.deps.clone(), to: to.into(), actor: u.env.actor.clone() };
        match &u.body {
            Body::Create { file, path, kind } => {
                self.files.entry(file.clone()).or_insert(Entry { kind: *kind, created: mv(path), moves: vec![], deletes: vec![], edits: vec![], resolves: vec![], bins: vec![] });
            }
            Body::Text { file, ops } => {
                let d = self.docs.entry(file.clone()).or_default();
                for op in ops {
                    if d.ready(op) || matches!(op, TOp::Del { .. }) {
                        d.apply(u.uid, op);
                    }
                }
                let v = self.doc_vv.entry(file.clone()).or_default();
                v.insert(u.uid.0, u.uid.1);
                if let Some(e) = self.files.get_mut(file) {
                    e.edits.push(u.uid);
                }
            }
            Body::Bin { file, blob, data } => {
                if let Some(bytes) = crate::unhex(data) {
                    self.blobs.insert(blob.clone(), bytes);
                }
                let m = mv(blob);
                if let Some(e) = self.files.get_mut(file) {
                    e.bins.push((m, blob.clone()));
                }
            }
            Body::Move { file, to } => {
                let m = mv(to);
                if let Some(e) = self.files.get_mut(file) {
                    e.moves.push(m);
                }
            }
            Body::Delete { file, seen } => {
                if let Some(e) = self.files.get_mut(file) {
                    e.deletes.push((u.uid, seen.clone()));
                }
            }
            Body::Resolve { file, pick, covers } => {
                if let Some(e) = self.files.get_mut(file) {
                    e.resolves.push((u.hlc, pick.clone(), covers.clone()));
                }
            }
        }
        self.vv.insert(u.uid.0, u.uid.1);
        self.log.push(u);
    }

    pub fn missing_for(&self, vv: &Vv) -> Vec<Update> {
        self.log.iter().filter(|u| !vv_has(vv, u.uid.0, u.uid.1)).cloned().collect()
    }

    fn raw_path(e: &Entry) -> String {
        let mut best = (e.created.hlc, e.created.to.clone());
        for m in &e.moves {
            if m.hlc > best.0 {
                best = (m.hlc, m.to.clone());
            }
        }
        for (t, p, _) in &e.resolves {
            if *t > best.0 {
                best = (*t, p.clone());
            }
        }
        best.1
    }

    fn deleted(e: &Entry) -> bool {
        e.deletes.iter().any(|(_, seen)| e.edits.iter().all(|u| vv_has(seen, u.0, u.1)))
    }

    fn concurrent(a: &Mv, b: &Mv) -> bool {
        !vv_has(&b.deps, a.uid.0, a.uid.1) && !vv_has(&a.deps, b.uid.0, b.uid.1)
    }

    /// Live entries with their displayed path (a second concurrent create of one path gets `~<site>`).
    fn live(&self) -> Vec<(String, String)> {
        let mut by_path: BTreeMap<String, Vec<(Hlc, String)>> = BTreeMap::new();
        for (id, e) in &self.files {
            if !Self::deleted(e) {
                by_path.entry(Self::raw_path(e)).or_default().push((e.created.hlc, id.clone()));
            }
        }
        let mut out = vec![];
        for (p, mut v) in by_path {
            v.sort();
            for (i, (_, id)) in v.into_iter().enumerate() {
                let shown = if i == 0 { p.clone() } else { format!("{p}~{}", &id[..6]) };
                out.push((shown, id));
            }
        }
        out.sort();
        out
    }

    pub fn file_at(&self, path: &str) -> Option<String> {
        self.live().into_iter().find(|(p, _)| p == path).map(|x| x.1)
    }

    pub fn path_of(&self, file: &str) -> Option<String> {
        self.live().into_iter().find(|(_, f)| f == file).map(|x| x.0)
    }

    pub fn kind(&self, file: &str) -> Option<Kind> {
        self.files.get(file).map(|e| e.kind)
    }

    pub fn doc(&self, file: &str) -> Doc {
        self.docs.get(file).cloned().unwrap_or_default()
    }

    pub fn version(&self, file: &str) -> Vv {
        self.doc_vv.get(file).cloned().unwrap_or_default()
    }

    pub fn content(&self, file: &str) -> Vec<u8> {
        match self.kind(file) {
            Some(Kind::Bin) => {
                let e = &self.files[file];
                e.bins.iter().max_by_key(|(m, _)| m.hlc).and_then(|(_, b)| self.blobs.get(b).cloned()).unwrap_or_default()
            }
            _ => self.docs.get(file).map(|d| d.text().into_bytes()).unwrap_or_default(),
        }
    }

    pub fn text(&self, file: &str) -> String {
        String::from_utf8_lossy(&self.content(file)).into_owned()
    }

    pub fn list(&self, prefix: &str) -> Vec<Listed> {
        let conflicted: BTreeSet<String> = self.conflicts("").into_iter().map(|c| c.file).collect();
        self.live()
            .into_iter()
            .filter(|(p, _)| p.starts_with(prefix))
            .map(|(path, file)| Listed { hash: h(&self.content(&file)), kind: self.files[&file].kind, version: self.version(&file), conflicted: conflicted.contains(&file), path, file })
            .collect()
    }

    pub fn conflicts(&self, prefix: &str) -> Vec<Conflict> {
        let mut out = vec![];
        let live = self.live();
        for (id, e) in &self.files {
            let path = live.iter().find(|(_, f)| f == id).map(|x| x.0.clone()).unwrap_or_else(|| Self::raw_path(e));
            if !path.starts_with(prefix) {
                continue;
            }
            let resolved = |a: Uid, b: Uid| e.resolves.iter().any(|(_, _, c)| c.contains(&a) && c.contains(&b));
            let mut all = vec![e.created.clone()];
            all.extend(e.moves.iter().cloned());
            for i in 0..all.len() {
                for j in i + 1..all.len() {
                    let (a, b) = (&all[i], &all[j]);
                    if i > 0 && Self::concurrent(a, b) && !resolved(a.uid, b.uid) {
                        out.push(Conflict { file: id.clone(), path: path.clone(), kind: "rename".into(), sides: vec![a.to.clone(), b.to.clone()], covers: vec![a.uid, b.uid], origin: e.created.to.clone() });
                    }
                }
            }
            for i in 0..e.bins.len() {
                for j in i + 1..e.bins.len() {
                    let (a, b) = (&e.bins[i].0, &e.bins[j].0);
                    if Self::concurrent(a, b) && !resolved(a.uid, b.uid) {
                        out.push(Conflict { file: id.clone(), path: path.clone(), kind: "binary".into(), sides: vec![a.to.clone(), b.to.clone()], covers: vec![a.uid, b.uid], origin: e.created.to.clone() });
                    }
                }
            }
            for (d, seen) in &e.deletes {
                if let Some(u) = e.edits.iter().find(|u| !vv_has(seen, u.0, u.1)) {
                    if !resolved(*d, *u) {
                        out.push(Conflict { file: id.clone(), path: path.clone(), kind: "edit-vs-delete".into(), sides: vec!["deleted".into(), "edited".into()], covers: vec![*d, *u], origin: e.created.to.clone() });
                    }
                }
            }
        }
        for (p, f) in &live {
            if let Some((_, base)) = p.split_once('~').filter(|_| p.starts_with(prefix)) {
                let _ = base;
                out.push(Conflict { file: f.clone(), path: p.clone(), kind: "same-path".into(), sides: vec![p.split('~').next().unwrap().into(), p.clone()], covers: vec![], origin: p.clone() });
            }
        }
        out
    }

    /// Freeze every live file under `prefix` (with an optional overlay of path -> text) into a snapshot.
    pub fn snapshot(&mut self, prefix: &str, overlay: &BTreeMap<String, String>) -> String {
        let mut m: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for (p, f) in self.live() {
            if p.starts_with(prefix) {
                m.insert(p, self.content(&f));
            }
        }
        for (p, t) in overlay {
            m.insert(p.clone(), t.clone().into_bytes());
        }
        let mut man = Manifest::new();
        for (p, b) in m {
            let bh = h(&b);
            self.blobs.insert(bh.clone(), b);
            man.push((p, bh));
        }
        self.put_snap(man)
    }

    pub fn put_snap(&mut self, man: Manifest) -> String {
        let r = tree_ref(&man);
        self.snaps.insert(r.clone(), man);
        r
    }

    pub fn snap_files(&self, r: &str) -> Option<Vec<(String, Vec<u8>)>> {
        let m = self.snaps.get(r)?;
        m.iter().map(|(p, b)| Some((p.clone(), self.blobs.get(b)?.clone()))).collect()
    }

    pub fn content_hash(&self) -> String {
        hj(&self.list("").into_iter().map(|l| (l.path, l.hash)).collect::<Vec<_>>())
    }

    pub fn new_file_id(site: u64, seq: u64, path: &str) -> String {
        h(format!("{site}:{seq}:{path}").as_bytes())[..16].to_string()
    }

    pub fn ops_for(&self, file: &str, base: &Vv, edits: &[Edit], uid_hint: (u64, u64)) -> Result<Vec<TOp>, String> {
        self.doc(file).ops_for(base, edits, uid_hint)
    }

    pub fn next_uid(&self, actor: &str, node: &str) -> Uid {
        let s = Self::site(actor, node);
        (s, self.vv.get(&s).copied().unwrap_or(0) + 1)
    }
}

/// Line-level edits from `old` to `new` (LCS), in character offsets of `old`. Used to replay a change set
/// onto the shared document so lines typed meanwhile survive.
pub fn line_edits(old: &str, new: &str) -> Vec<Edit> {
    let a: Vec<&str> = old.split_inclusive('\n').collect();
    let b: Vec<&str> = new.split_inclusive('\n').collect();
    let (n, m) = (a.len(), b.len());
    let mut l = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            l[i][j] = if a[i] == b[j] { l[i + 1][j + 1] + 1 } else { l[i + 1][j].max(l[i][j + 1]) };
        }
    }
    let off: Vec<usize> = std::iter::once(0).chain(a.iter().scan(0, |s, x| {
        *s += x.chars().count();
        Some(*s)
    })).collect();
    let (mut i, mut j) = (0, 0);
    let mut edits: Vec<Edit> = vec![];
    let mut cur: Option<Edit> = None;
    while i < n || j < m {
        if i < n && j < m && a[i] == b[j] {
            if let Some(e) = cur.take() {
                edits.push(e);
            }
            i += 1;
            j += 1;
        } else if j < m && (i == n || l[i][j + 1] >= l[i + 1][j]) {
            cur.get_or_insert(Edit { start: off[i], end: off[i], text: String::new() }).text.push_str(b[j]);
            j += 1;
        } else {
            let e = cur.get_or_insert(Edit { start: off[i], end: off[i], text: String::new() });
            e.end = off[i + 1];
            i += 1;
        }
    }
    if let Some(e) = cur {
        edits.push(e);
    }
    edits
}

#[cfg(test)]
mod t {
    use super::*;
    #[test]
    fn line_edits_apply() {
        let old = "a\nb\nc\nd\n";
        let new = "a\nB\nc\nd\ne\n";
        let es = line_edits(old, new);
        let mut s: Vec<char> = old.chars().collect();
        for e in es.iter().rev() {
            s.splice(e.start..e.end, e.text.chars());
        }
        assert_eq!(s.iter().collect::<String>(), new);
        assert_eq!(es.len(), 2);
    }
}
