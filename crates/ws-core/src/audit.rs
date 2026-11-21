//! `ws.audit`: the receipt log. Every op, allowed or refused, leaves one receipt, signed by the node whose
//! cell decided and linked by hash to that node's previous receipt. Each node's chain is replicated to every
//! other node, so the exported log is the union of all chains and can be verified offline.

use crate::gate::{verify, Key};
use crate::{hj, Hlc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Outcome {
    Ok { result: String },
    Refused { need: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub node: String,
    pub seq: u64,
    pub prev: String,
    pub time: Hlc,
    pub cell: String,
    pub op: String,
    pub actor: String,
    pub chain: String,
    pub target: String,
    pub args: String,
    pub outcome: Outcome,
    pub sig: String,
}

#[derive(Serialize)]
struct Body<'a> {
    node: &'a str,
    seq: u64,
    prev: &'a str,
    time: Hlc,
    cell: &'a str,
    op: &'a str,
    actor: &'a str,
    chain: &'a str,
    target: &'a str,
    args: &'a str,
    outcome: &'a Outcome,
}

impl Receipt {
    fn body(&self) -> Vec<u8> {
        serde_json::to_vec(&Body {
            node: &self.node,
            seq: self.seq,
            prev: &self.prev,
            time: self.time,
            cell: &self.cell,
            op: &self.op,
            actor: &self.actor,
            chain: &self.chain,
            target: &self.target,
            args: &self.args,
            outcome: &self.outcome,
        })
        .unwrap()
    }
    pub fn hash(&self) -> String {
        hj(self)
    }
    pub fn refused(&self) -> bool {
        matches!(self.outcome, Outcome::Refused { .. })
    }
}

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// All chains this node holds, by node public key.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Log {
    pub chains: BTreeMap<String, Vec<Receipt>>,
}

pub struct Draft<'a> {
    pub cell: &'a str,
    pub op: &'a str,
    pub actor: &'a str,
    pub chain: &'a str,
    pub target: &'a str,
    pub args: &'a str,
    pub outcome: Outcome,
}

impl Log {
    pub fn append(&mut self, key: &Key, time: Hlc, d: Draft) -> Receipt {
        let node = key.pk();
        let mine = self.chains.entry(node.clone()).or_default();
        let (seq, prev) = mine.last().map(|r| (r.seq + 1, r.hash())).unwrap_or((1, GENESIS.into()));
        let mut r = Receipt {
            node,
            seq,
            prev,
            time,
            cell: d.cell.into(),
            op: d.op.into(),
            actor: d.actor.into(),
            chain: d.chain.into(),
            target: d.target.into(),
            args: d.args.into(),
            outcome: d.outcome,
            sig: String::new(),
        };
        r.sig = key.sign(&r.body());
        mine.push(r.clone());
        r
    }
    pub fn heads(&self) -> BTreeMap<String, u64> {
        self.chains.iter().map(|(k, v)| (k.clone(), v.len() as u64)).collect()
    }
    pub fn missing_for(&self, heads: &BTreeMap<String, u64>) -> Vec<Receipt> {
        let mut out = vec![];
        for (k, v) in &self.chains {
            let have = heads.get(k).copied().unwrap_or(0) as usize;
            out.extend(v.iter().skip(have).cloned());
        }
        out
    }
    /// Accept receipts from a peer; each must extend its chain exactly and carry a valid signature.
    pub fn absorb(&mut self, rs: Vec<Receipt>) -> usize {
        let mut n = 0;
        for r in rs {
            let c = self.chains.entry(r.node.clone()).or_default();
            let (seq, prev) = c.last().map(|x| (x.seq + 1, x.hash())).unwrap_or((1, GENESIS.into()));
            if r.seq == seq && r.prev == prev && verify(&r.node, &r.body(), &r.sig) {
                c.push(r);
                n += 1;
            }
        }
        n
    }
    pub fn all(&self) -> Vec<Receipt> {
        let mut v: Vec<Receipt> = self.chains.values().flatten().cloned().collect();
        v.sort_by(|a, b| a.time.cmp(&b.time).then(a.node.cmp(&b.node)).then(a.seq.cmp(&b.seq)));
        v
    }
    pub fn len(&self) -> usize {
        self.chains.values().map(|v| v.len()).sum()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifyReport {
    pub receipts: usize,
    pub chains: usize,
    pub refused: usize,
    pub ok: bool,
    pub errors: Vec<String>,
}

/// Offline check of an exported log: every chain starts at genesis, every `prev` is the hash of the one
/// before, every signature is valid for a published node key.
pub fn verify_log(receipts: &[Receipt], node_keys: &[String]) -> VerifyReport {
    let mut by: BTreeMap<&str, Vec<&Receipt>> = BTreeMap::new();
    for r in receipts {
        by.entry(&r.node).or_default().push(r);
    }
    let mut errors = vec![];
    for (node, rs) in by.iter_mut() {
        if !node_keys.iter().any(|k| k == node) {
            errors.push(format!("chain of unknown node {}", &node[..12.min(node.len())]));
        }
        rs.sort_by_key(|r| r.seq);
        let mut prev = GENESIS.to_string();
        for (i, r) in rs.iter().enumerate() {
            if r.seq != i as u64 + 1 {
                errors.push(format!("{}: gap before seq {}", &node[..12], r.seq));
                break;
            }
            if r.prev != prev {
                errors.push(format!("{}: seq {} does not link to seq {}", &node[..12], r.seq, r.seq - 1));
            }
            if !verify(&r.node, &r.body(), &r.sig) {
                errors.push(format!("{}: seq {} bad signature", &node[..12], r.seq));
            }
            prev = r.hash();
        }
    }
    VerifyReport { receipts: receipts.len(), chains: by.len(), refused: receipts.iter().filter(|r| r.refused()).count(), ok: errors.is_empty(), errors }
}
