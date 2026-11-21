//! One node: a replica of `ws.fs`, `ws.snap`, `ws.presence`, `ws.run`, `ws.cache`, `ws.audit`, `ws.search`;
//! on the first node also the single cells `ws.keys`, `ws.tools`, `ws.place`, `ws.build`, `ws.test`,
//! `ws.review`, `ws.vcs`, `ws.ui`. Every client op arrives as a signed envelope, is checked by the gate and
//! leaves a receipt, allowed or refused.

use crate::audit::{Draft, Log, Outcome};
use crate::cells::*;
use crate::contract::{cell_of, right_of, VIEWS};
use crate::fs::{line_edits, Body, Ctx, Kind, Manifest, Replica, Update};
use crate::gate::{need_label, Chain, Envelope, Key, Link, Refused};
use crate::text::{Doc, Edit, Vv};
use crate::{h, hex, hj, unhex, Clock, Hlc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Answer {
    Ok(Value),
    Refused(Refused),
    Error(String),
    Forward(usize),
}

impl Answer {
    pub fn ok(&self) -> Option<&Value> {
        if let Answer::Ok(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub fn is_refused(&self) -> bool {
        matches!(self, Answer::Refused(_))
    }
}

pub trait Remote {
    fn call(&mut self, node: usize, env: &Envelope) -> Answer;
}

/// Runs one tool in a box. Native nodes use `ws-box`; the browser replays recorded runs and says so.
pub trait Runner: Send {
    fn isolation(&self) -> String;
    fn tools(&self) -> BTreeMap<String, String>;
    fn run(&mut self, req: &RunReq, files: &[(String, Vec<u8>)]) -> Result<RunOut, String>;
}

pub struct NoRunner;
impl Runner for NoRunner {
    fn isolation(&self) -> String {
        "none".into()
    }
    fn tools(&self) -> BTreeMap<String, String> {
        BTreeMap::new()
    }
    fn run(&mut self, _: &RunReq, _: &[(String, Vec<u8>)]) -> Result<RunOut, String> {
        Err("this node runs no tools".into())
    }
}

/// Who is who: the tenant root's public key, the nodes and the named identities.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Directory {
    pub root: String,
    pub nodes: Vec<(String, String)>,
    pub names: BTreeMap<String, String>,
}

/// Ops arrive as `{"op": "<Name>", ...fields}` and are read as `{"<Name>": {...fields}}`: serde's internally
/// tagged form buffers its content and then cannot read maps with integer keys (version vectors).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Op {
    FsList { #[serde(default)] prefix: String },
    FsOpen { path: String },
    FsRead { path: String },
    FsWrite { path: String, content: String, #[serde(default)] base_hash: Option<String>, #[serde(default)] change: Option<String> },
    FsPatch { path: String, base: Vv, edits: Vec<Edit>, #[serde(default)] change: Option<String> },
    FsMove { path: String, to: String },
    FsDelete { path: String },
    FsConflicts { #[serde(default)] prefix: String },
    FsResolve { path: String, pick: String },
    FsSnapshot { #[serde(default)] prefix: String },
    SnapPin { snapshot: String, label: String },
    SnapPins {},
    PresenceAnnounce { path: String, offset: usize },
    PresenceWatch { #[serde(default)] prefix: String },
    ReviewOpen { title: String },
    ReviewList {},
    ReviewDiff { change: String },
    ReviewSnapshot { change: String },
    ReviewComment { change: String, text: String },
    ReviewApprove { change: String, snapshot: String },
    ReviewMerge { change: String },
    ToolsFind { capability: String },
    ToolsRegister { tool: Tool },
    BuildStart { input: String, target: String, #[serde(default)] network: bool },
    TestStart { input: String, bin: String },
    RunStart { req: RunReq },
    CacheGet { key: String },
    KeysRevoke { link: Link },
    KeysSession { person: String, pk: String },
    KeysWhoami {},
    VcsCommit { snapshot: String, message: String },
    VcsLog {},
    SearchText { query: String, #[serde(default)] glob: String },
    AuditRead { #[serde(default)] since: usize },
    UiLayout {},
    PeerHave { vv: Vv, heads: BTreeMap<String, u64>, revoked: BTreeSet<String>, presence: Vec<Presence>, info: NodeInfo },
    PeerPush { updates: Vec<Update>, receipts: Vec<crate::audit::Receipt> },
    SnapGet { snapshot: String },
}

const SINGLE: &[&str] = &["ws.keys", "ws.tools", "ws.place", "ws.build", "ws.test", "ws.review", "ws.vcs", "ws.ui"];

pub struct Node {
    pub idx: usize,
    pub name: String,
    key: Key,
    pub chain: Chain,
    pub dir: Directory,
    pub clock: Clock,
    pub now: u64,
    pub fs: Replica,
    pub audit: Log,
    pub revoked: BTreeSet<String>,
    pub presence: BTreeMap<String, Presence>,
    pub cache: BTreeMap<String, (RunReceipt, Manifest)>,
    pub boxes_started: u32,
    pub runner: Box<dyn Runner>,
    pub infos: BTreeMap<usize, NodeInfo>,
    pub device: bool,
    pub tools: BTreeMap<String, Tool>,
    pub changes: BTreeMap<String, ChangeSet>,
    pub commits: Vec<Commit>,
    pub derived: BTreeMap<String, String>,
    pub min_class: String,
    pub rejected: Vec<crate::fs::Rejected>,
    /// Only on the node that holds `ws.keys` in a deployment where people sign in: the tenant root and who may.
    pub root_key: Option<Key>,
    pub people: BTreeMap<String, String>,
    nonce: u64,
}

fn s(v: impl Into<String>) -> String {
    v.into()
}

impl Node {
    pub fn new(idx: usize, name: &str, key: Key, chain: Chain, dir: Directory, runner: Box<dyn Runner>) -> Node {
        Node {
            idx,
            name: name.into(),
            key,
            chain,
            dir,
            clock: Clock::default(),
            now: 0,
            fs: Replica::default(),
            audit: Log::default(),
            revoked: BTreeSet::new(),
            presence: BTreeMap::new(),
            cache: BTreeMap::new(),
            boxes_started: 0,
            runner,
            infos: BTreeMap::new(),
            device: false,
            tools: BTreeMap::new(),
            changes: BTreeMap::new(),
            commits: vec![],
            derived: BTreeMap::new(),
            min_class: "ns+landlock+seccomp".into(),
            rejected: vec![],
            root_key: None,
            people: BTreeMap::new(),
            nonce: 0,
        }
    }

    pub fn pk(&self) -> String {
        self.key.pk()
    }

    fn hlc(&mut self) -> Hlc {
        self.clock.tick(self.now, self.idx as u32)
    }

    fn name_of(&self, pk: &str) -> String {
        self.dir.names.get(pk).cloned().unwrap_or_else(|| pk[..8.min(pk.len())].to_string())
    }

    fn node_keys(&self) -> BTreeSet<String> {
        self.dir.nodes.iter().map(|n| n.1.clone()).collect()
    }

    fn receipt(&mut self, env: &Envelope, cell: &str, op: &str, target: &str, outcome: Outcome) {
        let t = self.hlc();
        let actor = self.name_of(&env.actor);
        let args = h(env.op.to_string().as_bytes());
        let chain = env.chain.id();
        self.audit.append(&self.key, t, Draft { cell, op, actor: &actor, chain: &chain, target, args: &args, outcome });
    }

    pub fn sign(&mut self, op: Value) -> Envelope {
        self.nonce += 1;
        Envelope::sign(&self.key, &self.chain, op, self.nonce)
    }

    pub fn info(&self) -> NodeInfo {
        NodeInfo {
            name: self.name.clone(),
            key: self.pk(),
            tools: self.runner.tools(),
            isolation: self.runner.isolation(),
            cores: 1,
            running: 0,
            cache_keys: self.cache.keys().cloned().collect(),
            snaps: self.fs.snaps.keys().cloned().collect(),
            device: self.device,
        }
    }

    fn check(&self, env: &Envelope, right: &str, path: Option<&str>, tool: Option<&str>) -> Result<(), Refused> {
        env.chain.check(&env.actor, right, path, tool, &self.dir.root, self.now, &self.revoked)
    }

    fn may_read(&self, env: &Envelope, path: &str) -> bool {
        self.check(env, "ws.fs:read", Some(path), None).is_ok()
    }

    /// The single entry point for a request.
    pub fn handle(&mut self, env: &Envelope, net: &mut dyn Remote) -> Answer {
        let opname = env.op.get("op").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if !env.sig_ok() {
            let r = Refused { need: s("a valid signature by the actor"), have: vec![], why: s("bad signature") };
            self.receipt(env, "ws.gate", &opname, "", Outcome::Refused { need: r.need.clone() });
            return Answer::Refused(r);
        }
        let mut fields = env.op.as_object().cloned().unwrap_or_default();
        fields.remove("op");
        let op: Op = match serde_json::from_value(json!({ opname.clone(): fields })) {
            Ok(o) => o,
            Err(e) => return Answer::Error(format!("not an op of live-devenv@1: {e}")),
        };
        if matches!(op, Op::PeerHave { .. } | Op::PeerPush { .. } | Op::SnapGet { .. }) {
            return self.peer(env, op);
        }
        let cell = cell_of(&opname).unwrap_or("ws.fs");
        if SINGLE.contains(&cell) && self.idx != 0 {
            return Answer::Forward(0);
        }
        let target = op_target(&op);
        let res = self.exec(env, op, net);
        let outcome = match &res {
            Answer::Ok(v) => Some(Outcome::Ok { result: h(v.to_string().as_bytes()) }),
            Answer::Refused(r) => Some(Outcome::Refused { need: r.need.clone() }),
            Answer::Error(e) => Some(Outcome::Refused { need: format!("error: {e}") }),
            Answer::Forward(_) => None,
        };
        if let Some(o) = outcome {
            self.receipt(env, cell, &opname, &target, o);
        }
        res
    }

    fn exec(&mut self, env: &Envelope, op: Op, net: &mut dyn Remote) -> Answer {
        let opname = env.op["op"].as_str().unwrap_or("").to_string();
        let right = right_of(&opname).unwrap_or_default();
        macro_rules! gate {
            ($path:expr, $tool:expr) => {
                if let Err(r) = self.check(env, &right, $path, $tool) {
                    return Answer::Refused(r);
                }
            };
        }
        match op {
            Op::FsList { prefix } => {
                gate!(None, None);
                let l: Vec<_> = self.fs.list(&prefix).into_iter().filter(|l| self.may_read(env, &l.path)).collect();
                Answer::Ok(json!(l))
            }
            Op::FsOpen { path } | Op::FsRead { path } => {
                gate!(Some(&path), None);
                let Some(f) = self.fs.file_at(&path) else { return Answer::Error(format!("no file {path}")) };
                Answer::Ok(json!({"path": path, "file": f, "text": self.fs.text(&f), "version": self.fs.version(&f), "hash": h(&self.fs.content(&f)), "kind": self.fs.kind(&f)}))
            }
            Op::FsWrite { path, content, base_hash, change } => {
                let cur = self.fs.file_at(&path);
                let edits = match &cur {
                    Some(f) => {
                        if let Some(b) = &base_hash {
                            if *b != h(&self.fs.content(f)) {
                                return Answer::Error(s("Stale: the file changed since base_hash"));
                            }
                        }
                        Doc::diff(&self.fs.text(f), &content)
                    }
                    None => vec![Edit { start: 0, end: 0, text: content.clone() }],
                };
                let base = cur.as_ref().map(|f| self.fs.version(f)).unwrap_or_default();
                self.write(env, &path, base, edits, change, net)
            }
            Op::FsPatch { path, base, edits, change } => self.write(env, &path, base, edits, change, net),
            Op::FsMove { path, to } => {
                gate!(Some(&path), None);
                gate!(Some(&to), None);
                let Some(f) = self.fs.file_at(&path) else { return Answer::Error(format!("no file {path}")) };
                let t = self.hlc();
                self.fs.accept(&self.key, t, env, "ws.fs:write", vec![path, to.clone()], Body::Move { file: f, to });
                Answer::Ok(json!({"moved": true}))
            }
            Op::FsDelete { path } => {
                gate!(Some(&path), None);
                let Some(f) = self.fs.file_at(&path) else { return Answer::Error(format!("no file {path}")) };
                let t = self.hlc();
                let seen = self.fs.version(&f);
                self.fs.accept(&self.key, t, env, "ws.fs:write", vec![path], Body::Delete { file: f, seen });
                Answer::Ok(json!({"deleted": true}))
            }
            Op::FsConflicts { prefix } => {
                gate!(None, None);
                let c: Vec<_> = self.fs.conflicts(&prefix).into_iter().filter(|c| self.may_read(env, &c.path)).collect();
                Answer::Ok(json!(c))
            }
            Op::FsResolve { path, pick } => {
                gate!(Some(&pick), None);
                let Some(c) = self.fs.conflicts("").into_iter().find(|c| c.path == path || c.origin == path || c.sides.contains(&path)) else {
                    return Answer::Error(format!("no conflict on {path}"));
                };
                let t = self.hlc();
                self.fs.accept(&self.key, t, env, "ws.fs:resolve", vec![pick.clone()], Body::Resolve { file: c.file, pick, covers: c.covers });
                Answer::Ok(json!({"resolved": true}))
            }
            Op::FsSnapshot { prefix } => {
                gate!(Some(if prefix.is_empty() { "**" } else { &prefix }), None);
                let r = self.fs.snapshot(&prefix, &BTreeMap::new());
                Answer::Ok(json!({"snapshot": r}))
            }
            Op::SnapPin { snapshot, label } => {
                gate!(None, None);
                if !self.fs.snaps.contains_key(&snapshot) {
                    return Answer::Error(s("unknown snapshot"));
                }
                self.fs.pins.insert(snapshot.clone(), label);
                Answer::Ok(json!({"pinned": snapshot}))
            }
            Op::SnapPins {} => {
                gate!(None, None);
                Answer::Ok(json!(self.fs.pins))
            }
            Op::PresenceAnnounce { path, offset } => {
                gate!(Some(&path), None);
                let Some(f) = self.fs.file_at(&path) else { return Answer::Error(format!("no file {path}")) };
                let at = self.hlc();
                let p = Presence { actor: env.actor.clone(), name: self.name_of(&env.actor), path, anchor: self.fs.doc(&f).anchor(offset), file: f, at };
                self.presence.insert(env.actor.clone(), p);
                Answer::Ok(json!({"ok": true}))
            }
            Op::PresenceWatch { prefix } => {
                gate!(None, None);
                let rows: Vec<Value> = self
                    .presence
                    .values()
                    .filter(|p| p.path.starts_with(&prefix) && self.may_read(env, &p.path))
                    .map(|p| json!({"name": p.name, "path": self.fs.path_of(&p.file).unwrap_or(p.path.clone()), "offset": self.fs.doc(&p.file).offset(p.anchor)}))
                    .collect();
                Answer::Ok(json!(rows))
            }
            Op::ReviewOpen { title } => {
                gate!(None, None);
                Answer::Ok(json!({"change": self.open_change(&env.actor, &title)}))
            }
            Op::ReviewList {} => {
                gate!(None, None);
                Answer::Ok(json!(self.changes.values().map(|c| json!({"id": c.id, "title": c.title, "owner": self.name_of(&c.owner), "files": c.files.keys().collect::<Vec<_>>(), "approvals": c.approvals.len(), "merged": c.merged})).collect::<Vec<_>>()))
            }
            Op::ReviewDiff { change } => {
                gate!(None, None);
                let Some(c) = self.changes.get(&change) else { return Answer::Error(s("no such change set")) };
                Answer::Ok(json!(c.files.iter().map(|(p, f)| json!({"path": p, "base": f.base_text, "text": f.text})).collect::<Vec<_>>()))
            }
            Op::ReviewSnapshot { change } => {
                gate!(None, None);
                match self.change_snapshot(&change) {
                    Some(r) => Answer::Ok(json!({"snapshot": r})),
                    None => Answer::Error(s("no such change set")),
                }
            }
            Op::ReviewComment { change, text } => {
                gate!(None, None);
                let n = self.name_of(&env.actor);
                let Some(c) = self.changes.get_mut(&change) else { return Answer::Error(s("no such change set")) };
                c.comments.push((n, text));
                Answer::Ok(json!({"ok": true}))
            }
            Op::ReviewApprove { change, snapshot } => {
                gate!(None, None);
                let Some(cur) = self.change_snapshot(&change) else { return Answer::Error(s("no such change set")) };
                let c = self.changes.get_mut(&change).unwrap();
                if c.owner == env.actor {
                    return Answer::Refused(Refused { need: s("ws.review:approve by someone other than the proposer"), have: env.chain.have(), why: s("the proposer's own approval does not count") });
                }
                if snapshot != cur {
                    return Answer::Error(s("Stale: the change set changed; approve its current snapshot"));
                }
                c.approvals.push(Approval { by: env.actor.clone(), snapshot, env_hash: env.hash(), sig: env.sig.clone() });
                Answer::Ok(json!({"approved": cur}))
            }
            Op::ReviewMerge { change } => {
                gate!(None, None);
                self.merge(env, &change)
            }
            Op::ToolsFind { capability } => {
                gate!(None, None);
                let v: Vec<&Tool> = self.tools.values().filter(|t| t.provides.contains(&capability) && self.check(env, "ws.tools:invoke", None, Some(&t.name)).is_ok()).collect();
                Answer::Ok(json!(v))
            }
            Op::ToolsRegister { tool } => {
                gate!(None, None);
                if !(tool.artifact.starts_with("ref:ws.tools/bin/") || tool.artifact.starts_with("input:")) {
                    return Answer::Error(s("a tool names its program by hash"));
                }
                let r = format!("ref:ws.tools/tool/{}", hj(&tool));
                self.tools.insert(tool.name.clone(), tool);
                Answer::Ok(json!({"tool": r}))
            }
            Op::BuildStart { input, target, network } => {
                gate!(None, None);
                let args = json!({"root": format!("{target}/src/lib.rs"), "out": "out/test"});
                self.job(env, "compile:rust", input, args, network, net)
            }
            Op::TestStart { input, bin } => {
                gate!(None, None);
                let a = self.job(env, "test:rust", input.clone(), json!({"bin": bin}), false, net);
                let Answer::Ok(mut v) = a else { return a };
                let cases = parse_cases(v["stdout"].as_str().unwrap_or(""));
                let green = !cases.is_empty() && cases.iter().all(|c| c.status != "fail") && v["receipt"]["exit"] == 0;
                let src = self.derived.get(&input).cloned().unwrap_or(input);
                if green {
                    for c in self.changes.values_mut() {
                        c.green.push(src.clone());
                    }
                }
                v["cases"] = json!(cases);
                v["green"] = json!(green);
                v["source"] = json!(src);
                Answer::Ok(v)
            }
            Op::RunStart { req } => {
                gate!(None, None);
                self.run_start(env, req)
            }
            Op::CacheGet { key } => {
                gate!(None, None);
                Answer::Ok(json!(self.cache.get(&key).map(|c| &c.0)))
            }
            Op::KeysRevoke { link } => {
                gate!(None, None);
                if link.issuer != env.actor && env.chain.links.len() != 1 {
                    return Answer::Refused(Refused { need: s("ws.keys:revoke by the issuer of the link"), have: env.chain.have(), why: s("only the issuer or a person granted by the root may revoke") });
                }
                self.revoked.insert(link.id());
                Answer::Ok(json!({"revoked": link.id()}))
            }
            Op::KeysSession { person, pk } => {
                gate!(None, None);
                let Some(role) = self.people.get(&person).cloned() else {
                    return Answer::Refused(Refused { need: format!("{person} in this workspace's people"), have: vec![], why: s("not a person of this workspace") });
                };
                let Some(root) = &self.root_key else { return Answer::Error(s("this node does not hold ws.keys")) };
                let chain = Chain::default().extend(root, &pk, crate::sim::person_grants(role == "owner"), self.now + crate::sim::HOUR * 8);
                self.dir.names.insert(pk.clone(), person);
                Answer::Ok(json!({"chain": chain, "directory": self.dir}))
            }
            Op::KeysWhoami {} => {
                gate!(None, None);
                Answer::Ok(json!({"identity": self.name_of(&env.actor), "key": env.actor, "chain": env.chain.id(), "rights": env.chain.have(), "expiry": env.chain.links.last().map(|l| l.expiry)}))
            }
            Op::VcsCommit { snapshot, message } => {
                gate!(None, None);
                if !self.fs.snaps.contains_key(&snapshot) && !self.fetch_snap(&snapshot, net) {
                    return Answer::Error(s("unknown snapshot"));
                }
                let time = self.hlc();
                let parent = self.commits.last().map(|c| c.id.clone()).unwrap_or_default();
                let author = self.name_of(&env.actor);
                let id = hj(&(&parent, &snapshot, &message, &author, time));
                let c = Commit { id, parent, snapshot, message, author, time };
                self.commits.push(c.clone());
                Answer::Ok(json!(c))
            }
            Op::VcsLog {} => {
                gate!(None, None);
                Answer::Ok(json!(self.commits))
            }
            Op::SearchText { query, glob } => {
                gate!(None, None);
                let mut hits = vec![];
                for l in self.fs.list("") {
                    if !self.may_read(env, &l.path) || (!glob.is_empty() && !crate::gate::glob(&glob, &l.path)) || l.kind != Kind::Text {
                        continue;
                    }
                    for (i, line) in self.fs.text(&l.file).lines().enumerate() {
                        if line.contains(&query) {
                            hits.push(json!({"path": l.path, "line": i + 1, "text": line}));
                        }
                    }
                }
                Answer::Ok(json!(hits))
            }
            Op::AuditRead { since } => {
                gate!(None, None);
                Answer::Ok(json!(self.audit.all().into_iter().skip(since).collect::<Vec<_>>()))
            }
            Op::UiLayout {} => {
                gate!(None, None);
                let v: Vec<Value> = VIEWS.iter().filter(|v| env.chain.holds(v.2)).map(|v| json!({"view": v.0, "cell": v.1, "title": v.3})).collect();
                Answer::Ok(json!(v))
            }
            Op::PeerHave { .. } | Op::PeerPush { .. } | Op::SnapGet { .. } => unreachable!(),
        }
    }

    /// `FsWrite`/`FsPatch`: into the shared tree with `write`, else into the caller's change set with `propose`.
    fn write(&mut self, env: &Envelope, path: &str, base: Vv, edits: Vec<Edit>, change: Option<String>, net: &mut dyn Remote) -> Answer {
        let _ = net;
        let can_write = self.check(env, "ws.fs:write", Some(path), None);
        let can_propose = self.check(env, "ws.fs:propose", Some(path), None).is_ok();
        if change.is_some() || can_write.is_err() {
            if !can_propose {
                return Answer::Refused(can_write.err().unwrap_or(Refused { need: need_label("ws.fs:propose", Some(path), None), have: env.chain.have(), why: s("no grant covers this op") }));
            }
            if self.idx != 0 {
                return Answer::Forward(0);
            }
            return self.propose(env, path, base, edits, change);
        }
        let t = self.hlc();
        let me = self.pk();
        let file = match self.fs.file_at(path) {
            Some(f) => f,
            None => {
                let (site, seq) = self.fs.next_uid(&env.actor, &me);
                let f = Replica::new_file_id(site, seq, path);
                self.fs.accept(&self.key, t, env, "ws.fs:write", vec![path.into()], Body::Create { file: f.clone(), path: path.into(), kind: Kind::Text });
                f
            }
        };
        let uid = self.fs.next_uid(&env.actor, &me);
        let ops = match self.fs.ops_for(&file, &base, &edits, uid) {
            Ok(o) => o,
            Err(e) => return Answer::Error(e),
        };
        let t = self.hlc();
        let u = self.fs.accept(&self.key, t, env, "ws.fs:write", vec![path.into()], Body::Text { file: file.clone(), ops });
        Answer::Ok(json!({"path": path, "file": file, "version": self.fs.version(&file), "update": [u.uid.0, u.uid.1], "hash": h(&self.fs.content(&file))}))
    }

    fn open_change(&mut self, owner: &str, title: &str) -> String {
        let base = self.fs.snapshot("", &BTreeMap::new());
        let id = h(format!("{owner}{title}{}", self.changes.len()).as_bytes())[..12].to_string();
        self.changes.insert(id.clone(), ChangeSet { id: id.clone(), title: title.into(), owner: owner.into(), base, files: BTreeMap::new(), approvals: vec![], comments: vec![], green: vec![], merged: false });
        id
    }

    fn propose(&mut self, env: &Envelope, path: &str, base: Vv, edits: Vec<Edit>, change: Option<String>) -> Answer {
        let id = match change {
            Some(c) => c,
            None => match self.changes.values().find(|c| c.owner == env.actor && !c.merged) {
                Some(c) => c.id.clone(),
                None => {
                    let t = format!("proposal by {}", self.name_of(&env.actor));
                    self.open_change(&env.actor, &t)
                }
            },
        };
        let Some(file) = self.fs.file_at(path) else { return Answer::Error(format!("no file {path}")) };
        let (bt, bv) = (self.fs.text(&file), self.fs.version(&file));
        let doc = self.fs.doc(&file);
        let Some(c) = self.changes.get_mut(&id) else { return Answer::Error(s("no such change set")) };
        if c.owner != env.actor || c.merged {
            return Answer::Refused(Refused { need: s("a change set of your own"), have: env.chain.have(), why: s("a change set takes edits only from its proposer") });
        }
        let f = c.files.entry(path.into()).or_insert(crate::cells::CsFile { file: file.clone(), base_vv: bv, base_text: bt, text: String::new() });
        if f.text.is_empty() {
            f.text = f.base_text.clone();
        }
        // edits are against the version the caller read; as of that version, then replayed on the set's text
        let read = doc.text_at(&base);
        let mut chars: Vec<char> = if read == f.base_text { f.text.chars().collect() } else { read.chars().collect() };
        let mut es = edits.clone();
        es.sort_by_key(|e| std::cmp::Reverse(e.start));
        for e in es {
            if e.end > chars.len() || e.start > e.end {
                return Answer::Error(s("edit range does not fit"));
            }
            chars.splice(e.start..e.end, e.text.chars());
        }
        f.text = chars.into_iter().collect();
        let snap = self.change_snapshot(&id).unwrap();
        Answer::Ok(json!({"change": id, "path": path, "snapshot": snap, "shared": false}))
    }

    fn change_snapshot(&mut self, id: &str) -> Option<String> {
        let c = self.changes.get(id)?;
        let mut man: BTreeMap<String, String> = self.fs.snaps.get(&c.base)?.iter().cloned().collect();
        for (p, f) in &c.files {
            let b = h(f.text.as_bytes());
            self.fs.blobs.insert(b.clone(), f.text.clone().into_bytes());
            man.insert(p.clone(), b);
        }
        Some(self.fs.put_snap(man.into_iter().collect()))
    }

    fn merge(&mut self, env: &Envelope, id: &str) -> Answer {
        let Some(snap) = self.change_snapshot(id) else { return Answer::Error(s("no such change set")) };
        let c = self.changes[id].clone();
        if c.merged {
            return Answer::Error(s("already merged"));
        }
        let ok = c.approvals.iter().filter(|a| a.snapshot == snap && a.by != c.owner).count();
        if ok < 1 {
            return Answer::Refused(Refused { need: s("one approval of this exact snapshot by someone other than the proposer"), have: vec![], why: s("policy: approvals required") });
        }
        if !c.green.contains(&snap) {
            return Answer::Refused(Refused { need: s("a green test receipt for this exact snapshot"), have: vec![], why: s("policy: tests required") });
        }
        let me = self.pk();
        for (p, f) in &c.files {
            let edits = line_edits(&f.base_text, &f.text);
            let uid = self.fs.next_uid(&env.actor, &me);
            let ops = match self.fs.ops_for(&f.file, &f.base_vv, &edits, uid) {
                Ok(o) => o,
                Err(e) => return Answer::Error(e),
            };
            let t = self.hlc();
            self.fs.accept(&self.key, t, env, "ws.review:merge", vec![p.clone()], Body::Text { file: f.file.clone(), ops });
        }
        self.changes.get_mut(id).unwrap().merged = true;
        Answer::Ok(json!({"merged": id, "snapshot": snap}))
    }

    fn fetch_snap(&mut self, r: &str, net: &mut dyn Remote) -> bool {
        for n in 0..self.dir.nodes.len() {
            if n == self.idx {
                continue;
            }
            let e = self.sign(json!({"op": "SnapGet", "snapshot": r}));
            if let Answer::Ok(v) = net.call(n, &e) {
                if v.is_null() {
                    continue;
                }
                let man: Manifest = serde_json::from_value(v["manifest"].clone()).unwrap_or_default();
                let blobs: BTreeMap<String, String> = serde_json::from_value(v["blobs"].clone()).unwrap_or_default();
                for (k, b) in blobs {
                    if let Some(bytes) = unhex(&b).filter(|x| h(x) == k) {
                        self.fs.blobs.insert(k, bytes);
                    }
                }
                if crate::fs::tree_ref(&man) == r {
                    self.fs.put_snap(man);
                    return true;
                }
            }
        }
        false
    }

    /// `ws.build`/`ws.test`: resolve the tool, place the run, call `ws.run` on that node.
    fn job(&mut self, env: &Envelope, capability: &str, input: String, args: Value, network: bool, net: &mut dyn Remote) -> Answer {
        let cands: Vec<Tool> = self.tools.values().filter(|t| t.provides.iter().any(|p| p == capability)).cloned().collect();
        let Some(tool) = cands.iter().find(|t| self.check(env, "ws.tools:invoke", None, Some(&t.name)).is_ok()).cloned() else {
            let name = cands.first().map(|t| t.name.clone()).unwrap_or(capability.into());
            return Answer::Refused(self.check(env, "ws.tools:invoke", None, Some(&name)).err().unwrap_or(Refused { need: format!("a tool for {capability}"), have: vec![], why: s("none registered") }));
        };
        if network && !tool.network {
            return Answer::Refused(Refused { need: s("network inside a run box"), have: env.chain.have(), why: format!("tool record {} says network: none", tool.name) });
        }
        if !self.fs.snaps.contains_key(&input) && !self.fetch_snap(&input, net) {
            return Answer::Error(s("unknown snapshot"));
        }
        let man = self.fs.snaps[&input].clone();
        let key = h(format!("{}|{}|{}", tool.artifact, hj(&args), input).as_bytes());
        let mut infos: Vec<(usize, NodeInfo)> = self.infos.iter().map(|(k, v)| (*k, v.clone())).collect();
        infos.retain(|(k, _)| *k != self.idx);
        infos.push((self.idx, self.info()));
        let Some(at) = place(&infos, &tool, &self.min_class, &key, &input) else {
            return Answer::Error(format!("no node holds {} at class {}", tool.name, self.min_class));
        };
        let blobs = man.iter().filter_map(|(_, b)| Some((b.clone(), hex(self.fs.blobs.get(b)?)))).collect();
        let req = RunReq { tool, args, input: input.clone(), manifest: man, blobs, network, actor: self.name_of(&env.actor), min_class: self.min_class.clone() };
        let e = self.sign(json!({"op": "RunStart", "req": req}));
        let ans = if at == self.idx { self.handle(&e, net) } else { net.call(at, &e) };
        let Answer::Ok(v) = ans else { return ans };
        let out: Manifest = serde_json::from_value(v["manifest"].clone()).unwrap_or_default();
        let blobs: BTreeMap<String, String> = serde_json::from_value(v["blobs"].clone()).unwrap_or_default();
        for (k, b) in blobs {
            if let Some(bytes) = unhex(&b).filter(|x| h(x) == k) {
                self.fs.blobs.insert(k, bytes);
            }
        }
        let oref = self.fs.put_snap(out);
        let src = self.derived.get(&input).cloned().unwrap_or(input);
        self.derived.insert(oref.clone(), src);
        Answer::Ok(json!({"receipt": v["receipt"], "output": oref, "stdout": v["stdout"], "stderr": v["stderr"], "node": self.dir.nodes.get(at).map(|n| n.0.clone())}))
    }

    fn run_start(&mut self, env: &Envelope, req: RunReq) -> Answer {
        let args_hash = hj(&req.args);
        let key = h(format!("{}|{}|{}", req.tool.artifact, args_hash, req.input).as_bytes());
        if let Some((r, man)) = self.cache.get(&key).cloned() {
            let mut r = r;
            r.cache = s("hit");
            return Answer::Ok(json!({"receipt": r, "manifest": man, "blobs": {}, "stdout": ""}));
        }
        if req.network && !req.tool.network {
            return Answer::Refused(Refused { need: s("network inside a run box"), have: env.chain.have(), why: s("the tool record says network: none") });
        }
        let iso = self.runner.isolation();
        if class_rank(&iso) < class_rank(&req.min_class) {
            return Answer::Refused(Refused { need: format!("isolation {}", req.min_class), have: vec![iso], why: s("this node cannot give the class the workspace asks for") });
        }
        if !req.tool.artifact.starts_with("input:") && self.runner.tools().get(&req.tool.name) != Some(&req.tool.artifact) {
            return Answer::Refused(Refused { need: format!("program {} with hash {}", req.tool.name, req.tool.artifact), have: vec![], why: s("the local program does not match the registered hash") });
        }
        let mut files = vec![];
        for (p, b) in &req.manifest {
            let bytes = match self.fs.blobs.get(b).cloned().or_else(|| req.blobs.get(b).and_then(|x| unhex(x))) {
                Some(x) if h(&x) == *b => x,
                _ => return Answer::Error(format!("missing blob for {p}")),
            };
            self.fs.blobs.insert(b.clone(), bytes.clone());
            files.push((p.clone(), bytes));
        }
        self.fs.put_snap(req.manifest.clone());
        self.boxes_started += 1;
        let out = match self.runner.run(&req, &files) {
            Ok(o) => o,
            Err(e) => return Answer::Error(e),
        };
        let mut man: BTreeMap<String, String> = req.manifest.iter().cloned().collect();
        let mut oblobs = BTreeMap::new();
        for (p, b) in &out.outputs {
            let bh = h(b);
            self.fs.blobs.insert(bh.clone(), b.clone());
            oblobs.insert(bh.clone(), hex(b));
            man.insert(p.clone(), bh);
        }
        let man: Manifest = man.into_iter().collect();
        let oref = self.fs.put_snap(man.clone());
        let logb = format!("{}\n{}", out.stdout, out.stderr);
        let log = h(logb.as_bytes());
        self.fs.blobs.insert(log.clone(), logb.into_bytes());
        let t = self.hlc();
        let r = RunReceipt {
            run: h(format!("{key}{t:?}").as_bytes())[..16].to_string(),
            actor: req.actor.clone(),
            tool: req.tool.name.clone(),
            tool_artifact: req.tool.artifact.clone(),
            args_hash,
            input: req.input.clone(),
            output: oref,
            exit: out.exit,
            isolation: out.isolation.clone(),
            node: self.name.clone(),
            cache: s("miss"),
            log,
            replayed: out.replayed,
        };
        if out.exit == 0 || req.tool.provides.iter().any(|p| p.starts_with("test:")) {
            self.cache.insert(key, (r.clone(), man.clone()));
        }
        Answer::Ok(json!({"receipt": r, "manifest": man, "blobs": oblobs, "stdout": out.stdout, "stderr": out.stderr.chars().take(4000).collect::<String>()}))
    }

    fn peer(&mut self, env: &Envelope, op: Op) -> Answer {
        if !self.node_keys().contains(&env.actor) {
            return Answer::Refused(Refused { need: s("a node of this workspace"), have: vec![], why: s("peer ops are for nodes") });
        }
        if let Err(r) = env.chain.check(&env.actor, "ws.peer:sync", None, None, &self.dir.root, self.now, &self.revoked) {
            return Answer::Refused(r);
        }
        match op {
            Op::PeerHave { vv, heads, revoked, presence, info } => {
                self.merge_soft(revoked, presence);
                if let Some(i) = self.dir.nodes.iter().position(|n| n.1 == env.actor) {
                    self.infos.insert(i, info);
                }
                let pres: Vec<Presence> = self.presence.values().cloned().collect();
                Answer::Ok(json!({
                    "updates": self.fs.missing_for(&vv), "receipts": self.audit.missing_for(&heads),
                    "vv": self.fs.vv, "heads": self.audit.heads(), "revoked": self.revoked, "presence": pres, "info": self.info(),
                }))
            }
            Op::PeerPush { updates, receipts } => {
                self.absorb(updates, receipts);
                Answer::Ok(json!({"ok": true}))
            }
            Op::SnapGet { snapshot } => match self.fs.snaps.get(&snapshot) {
                Some(m) => {
                    let blobs: BTreeMap<String, String> = m.iter().filter_map(|(_, b)| Some((b.clone(), hex(self.fs.blobs.get(b)?)))).collect();
                    Answer::Ok(json!({"manifest": m, "blobs": blobs}))
                }
                None => Answer::Ok(Value::Null),
            },
            _ => unreachable!(),
        }
    }

    fn merge_soft(&mut self, revoked: BTreeSet<String>, presence: Vec<Presence>) {
        self.revoked.extend(revoked);
        for p in presence {
            if self.presence.get(&p.actor).map_or(true, |q| q.at < p.at) {
                self.clock.see(p.at);
                self.presence.insert(p.actor.clone(), p);
            }
        }
    }

    fn absorb(&mut self, updates: Vec<Update>, receipts: Vec<crate::audit::Receipt>) {
        for u in &updates {
            self.clock.see(u.hlc);
        }
        let keys = self.node_keys();
        let root = self.dir.root.clone();
        let (_, rej) = self.fs.absorb(updates, &Ctx { root: &root, nodes: &keys });
        self.rejected.extend(rej);
        self.audit.absorb(receipts);
    }

    /// One anti-entropy exchange with `peer`.
    pub fn sync_with(&mut self, peer: usize, net: &mut dyn Remote) -> bool {
        let pres: Vec<Presence> = self.presence.values().cloned().collect();
        let have = json!({"op": "PeerHave", "vv": self.fs.vv, "heads": self.audit.heads(), "revoked": self.revoked, "presence": pres, "info": self.info()});
        let e = self.sign(have);
        let Answer::Ok(v) = net.call(peer, &e) else { return false };
        let updates: Vec<Update> = serde_json::from_value(v["updates"].clone()).unwrap_or_default();
        let receipts = serde_json::from_value(v["receipts"].clone()).unwrap_or_default();
        let revoked: BTreeSet<String> = serde_json::from_value(v["revoked"].clone()).unwrap_or_default();
        let presence: Vec<Presence> = serde_json::from_value(v["presence"].clone()).unwrap_or_default();
        if let Ok(i) = serde_json::from_value::<NodeInfo>(v["info"].clone()) {
            self.infos.insert(peer, i);
        }
        self.merge_soft(revoked, presence);
        self.absorb(updates, receipts);
        let pvv: Vv = serde_json::from_value(v["vv"].clone()).unwrap_or_default();
        let pheads: BTreeMap<String, u64> = serde_json::from_value(v["heads"].clone()).unwrap_or_default();
        let push = json!({"op": "PeerPush", "updates": self.fs.missing_for(&pvv), "receipts": self.audit.missing_for(&pheads)});
        let e = self.sign(push);
        net.call(peer, &e).ok().is_some()
    }
}

fn op_target(op: &Op) -> String {
    match op {
        Op::FsOpen { path } | Op::FsRead { path } | Op::FsWrite { path, .. } | Op::FsPatch { path, .. } | Op::FsDelete { path } | Op::FsResolve { path, .. } | Op::PresenceAnnounce { path, .. } => path.clone(),
        Op::FsMove { path, to } => format!("{path} -> {to}"),
        Op::FsList { prefix } | Op::FsConflicts { prefix } | Op::FsSnapshot { prefix } | Op::PresenceWatch { prefix } => prefix.clone(),
        Op::ReviewDiff { change } | Op::ReviewSnapshot { change } | Op::ReviewComment { change, .. } | Op::ReviewMerge { change } => change.clone(),
        Op::ReviewApprove { change, snapshot } => format!("{change} @ {snapshot}"),
        Op::BuildStart { input, .. } | Op::TestStart { input, .. } => input.clone(),
        Op::RunStart { req } => format!("{} on {}", req.tool.name, req.input),
        Op::VcsCommit { snapshot, .. } | Op::SnapPin { snapshot, .. } => snapshot.clone(),
        Op::KeysRevoke { link } => link.id(),
        Op::ToolsRegister { tool } => tool.name.clone(),
        Op::ToolsFind { capability } => capability.clone(),
        _ => String::new(),
    }
}
