//! The cells of live-devenv. Everything in this crate is plain logic with no clock, no socket and no
//! process of its own, so the same code runs in a node, in the in-process mesh and in the browser.

pub mod audit;
pub mod cells;
pub mod contract;
pub mod fs;
pub mod gate;
pub mod node;
pub mod proof;
pub mod sim;
pub mod text;

use serde::{Deserialize, Serialize};

pub fn hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

/// BLAKE3 of bytes, as hex.
pub fn h(b: &[u8]) -> String {
    hex(blake3::hash(b).as_bytes())
}

/// BLAKE3 of the canonical JSON of a value (struct fields in declaration order, maps sorted).
pub fn hj<T: Serialize>(v: &T) -> String {
    h(&serde_json::to_vec(v).expect("serializable"))
}

/// A short stable number for a name (sites, file ids).
pub fn h64(b: &[u8]) -> u64 {
    let d = blake3::hash(b);
    u64::from_le_bytes(d.as_bytes()[..8].try_into().unwrap())
}

/// Typed reference `ref:<cell>/<kind>/<hash>`.
pub fn ref_of(cell: &str, kind: &str, hash: &str) -> String {
    format!("ref:{cell}/{kind}/{hash}")
}

pub fn ref_hash(r: &str) -> Option<&str> {
    r.rsplit('/').next().filter(|x| x.len() == 64)
}

/// Hybrid logical clock stamp: wall milliseconds, counter, node.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Hlc {
    pub ms: u64,
    pub c: u32,
    pub node: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Clock {
    pub last: Hlc,
}

impl Clock {
    pub fn tick(&mut self, now_ms: u64, node: u32) -> Hlc {
        let t = if now_ms > self.last.ms { Hlc { ms: now_ms, c: 0, node } } else { Hlc { ms: self.last.ms, c: self.last.c + 1, node } };
        self.last = t;
        t
    }
    pub fn see(&mut self, o: Hlc) {
        if o > self.last {
            self.last = Hlc { node: self.last.node, ..o };
        }
    }
}
