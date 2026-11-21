//! The tenant set-up and the in-process mesh (`--net sim`): three nodes in one process, with partitions.

use crate::gate::{Chain, Envelope, Grant, Key};
use crate::node::{Answer, Directory, Node, Remote, Runner};
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub const HOUR: u64 = 3_600_000;

/// A person device or an agent: its own key and its own chain. Nobody else signs for it.
pub struct Client {
    pub name: String,
    pub key: Key,
    pub chain: Chain,
    n: u64,
}

impl Client {
    pub fn env(&mut self, op: Value) -> Envelope {
        self.n += 1;
        Envelope::sign(&self.key, &self.chain, op, self.n)
    }
    pub fn pk(&self) -> String {
        self.key.pk()
    }
    pub fn from_parts(name: &str, key: Key, chain: Chain) -> Client {
        Client { name: name.into(), key, chain, n: 0 }
    }
}

/// What the tenant root (inside `ws.keys`) issues at set-up: node chains and person chains. Agents get
/// their chains from a person, by a narrowing grant bundle.
pub struct Tenant {
    pub root: Key,
    pub dir: Directory,
    pub node_keys: Vec<Key>,
    pub node_chains: Vec<Chain>,
}

pub fn node_grants() -> Vec<Grant> {
    vec![Grant::new("ws.peer:sync"), Grant::new("ws.run:start"), Grant::new("ws.cache:get"), Grant::new("ws.snap:read"), Grant::new("ws.keys:session")]
}

pub fn person_grants(resolve: bool) -> Vec<Grant> {
    let mut g: Vec<Grant> = [
        "ws.fs:read", "ws.fs:write", "ws.fs:propose", "ws.fs:snapshot", "ws.snap:*", "ws.presence:*", "ws.review:*", "ws.tools:find", "ws.tools:invoke",
        "ws.build:start", "ws.test:start", "ws.keys:revoke", "ws.keys:whoami", "ws.vcs:*", "ws.search:query", "ws.audit:read", "ws.ui:render",
    ]
    .iter()
    .map(|r| Grant::new(r))
    .collect();
    if resolve {
        g.push(Grant::new("ws.fs:resolve"));
        g.push(Grant::new("ws.tools:register"));
    }
    g
}

impl Tenant {
    /// `seeds`: (node name, key seed). In the sim seeds are names; real nodes use OS randomness.
    pub fn new(root_seed: &[u8], nodes: &[(&str, Vec<u8>)], now: u64) -> Tenant {
        let root = Key::from_seed(root_seed);
        let node_keys: Vec<Key> = nodes.iter().map(|(_, s)| Key::from_seed(s)).collect();
        let node_chains = node_keys.iter().map(|k| Chain::default().extend(&root, &k.pk(), node_grants(), now + 24 * 365 * HOUR)).collect();
        let mut dir = Directory { root: root.pk(), ..Default::default() };
        for ((n, _), k) in nodes.iter().zip(&node_keys) {
            dir.nodes.push((n.to_string(), k.pk()));
            dir.names.insert(k.pk(), n.to_string());
        }
        Tenant { root, dir, node_keys, node_chains }
    }
    /// A person: chain from the root, at most 8 hours.
    pub fn person(&mut self, name: &str, seed: &[u8], grants: Vec<Grant>, now: u64) -> Client {
        let key = Key::from_seed(seed);
        self.dir.names.insert(key.pk(), name.into());
        let chain = Chain::default().extend(&self.root, &key.pk(), grants, now + 8 * HOUR);
        Client { name: name.into(), key, chain, n: 0 }
    }
    /// An agent: chain delegated by a person, narrowed.
    pub fn agent(&mut self, by: &Client, name: &str, seed: &[u8], grants: Vec<Grant>, now: u64) -> Client {
        let key = Key::from_seed(seed);
        self.dir.names.insert(key.pk(), name.into());
        let chain = by.chain.extend(&by.key, &key.pk(), grants, now + 4 * HOUR);
        Client { name: name.into(), key, chain, n: 0 }
    }
    pub fn node(&self, i: usize, runner: Box<dyn Runner>) -> Node {
        Node::new(i, &self.dir.nodes[i].0, self.node_keys[i].dup(), self.node_chains[i].clone(), self.dir.clone(), runner)
    }
}

/// What the proof needs from a network, sim or real.
pub trait Net {
    fn call(&mut self, node: usize, env: &Envelope) -> Answer;
    fn tick(&mut self, rounds: usize);
    fn cut(&mut self, node: usize, cut: bool);
    fn status(&mut self, node: usize) -> Value;
    fn advance(&mut self, ms: u64);
    fn now(&self) -> u64;
    fn label(&self) -> String;
}

pub struct Mesh {
    pub nodes: Vec<Option<Node>>,
    pub cut: BTreeSet<usize>,
    pub now: u64,
    current: Option<usize>,
}

impl Mesh {
    pub fn new(nodes: Vec<Node>, now: u64) -> Mesh {
        let mut m = Mesh { nodes: nodes.into_iter().map(Some).collect(), cut: BTreeSet::new(), now, current: None };
        m.set_now();
        m
    }
    fn set_now(&mut self) {
        for n in self.nodes.iter_mut().flatten() {
            n.now = self.now;
        }
    }
    pub fn node(&self, i: usize) -> &Node {
        self.nodes[i].as_ref().expect("node present")
    }
    pub fn node_mut(&mut self, i: usize) -> &mut Node {
        self.nodes[i].as_mut().expect("node present")
    }
    fn reach(&self, from: Option<usize>, to: usize) -> bool {
        match from {
            Some(f) => f == to || (!self.cut.contains(&f) && !self.cut.contains(&to)),
            None => true,
        }
    }
    fn deliver(&mut self, from: Option<usize>, to: usize, env: &Envelope) -> Answer {
        if !self.reach(from, to) {
            return Answer::Error("unreachable".into());
        }
        let Some(mut n) = self.nodes[to].take() else { return Answer::Error("busy".into()) };
        let prev = self.current.replace(to);
        let a = n.handle(env, self);
        self.current = prev;
        self.nodes[to] = Some(n);
        match a {
            Answer::Forward(t) if t != to => self.deliver(Some(to), t, env),
            a => a,
        }
    }
}

impl Remote for Mesh {
    fn call(&mut self, node: usize, env: &Envelope) -> Answer {
        let from = self.current;
        self.deliver(from, node, env)
    }
}

impl Net for Mesh {
    fn call(&mut self, node: usize, env: &Envelope) -> Answer {
        self.deliver(None, node, env)
    }
    fn tick(&mut self, rounds: usize) {
        for _ in 0..rounds {
            self.now += 50;
            self.set_now();
            let n = self.nodes.len();
            for i in 0..n {
                for j in 0..n {
                    if i != j && self.reach(Some(i), j) {
                        let mut me = self.nodes[i].take().unwrap();
                        self.current = Some(i);
                        me.sync_with(j, self);
                        self.current = None;
                        self.nodes[i] = Some(me);
                    }
                }
            }
        }
    }
    fn cut(&mut self, node: usize, cut: bool) {
        if cut {
            self.cut.insert(node);
        } else {
            self.cut.remove(&node);
        }
    }
    fn status(&mut self, i: usize) -> Value {
        let n = self.node(i);
        json!({"name": n.name, "boxes_started": n.boxes_started, "content_hash": n.fs.content_hash(), "conflicts": n.fs.conflicts("").len(), "receipts": n.audit.len(), "isolation": n.runner.isolation(), "tools": n.runner.tools(), "rejected": n.rejected.len()})
    }
    fn advance(&mut self, ms: u64) {
        self.now += ms;
        self.set_now();
    }
    fn now(&self) -> u64 {
        self.now
    }
    fn label(&self) -> String {
        "sim".into()
    }
}
