//! One text document as a sequence CRDT (RGA with Lamport order). Every character is an item with a stable
//! id; deletes leave tombstones. Items carry the update (site, seq) that made them, so the document can be
//! read "as of" any version vector: that is how a `Patch` written against an old version is mapped onto the
//! present while others type.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub type Vv = BTreeMap<u64, u64>;

pub fn vv_has(vv: &Vv, site: u64, seq: u64) -> bool {
    vv.get(&site).map_or(false, |&s| s >= seq)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Id {
    pub site: u64,
    pub seq: u64,
    pub i: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum TOp {
    Ins { id: Id, lam: u64, after: Option<Id>, ch: char },
    Del { target: Id },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Item {
    id: Id,
    lam: u64,
    ch: char,
    del: Option<(u64, u64)>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Doc {
    items: Vec<Item>,
    max_lam: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Edit {
    pub start: usize,
    pub end: usize,
    pub text: String,
}

impl Doc {
    fn pos(&self, id: Id) -> Option<usize> {
        self.items.iter().position(|x| x.id == id)
    }
    pub fn has(&self, id: Id) -> bool {
        self.pos(id).is_some()
    }
    /// Can `op` be applied now (its dependency is present)?
    pub fn ready(&self, op: &TOp) -> bool {
        match op {
            TOp::Ins { id, after, .. } => !self.has(*id) && after.map_or(true, |a| self.has(a)),
            TOp::Del { target } => self.has(*target),
        }
    }
    /// Apply one op made by update `uid`. Idempotent.
    pub fn apply(&mut self, uid: (u64, u64), op: &TOp) {
        match *op {
            TOp::Ins { id, lam, after, ch } => {
                if self.has(id) {
                    return;
                }
                let mut i = match after {
                    None => 0,
                    Some(a) => self.pos(a).expect("dependency checked") + 1,
                };
                while i < self.items.len() && (self.items[i].lam, self.items[i].id) > (lam, id) {
                    i += 1;
                }
                self.items.insert(i, Item { id, lam, ch, del: None });
                self.max_lam = self.max_lam.max(lam);
            }
            TOp::Del { target } => {
                if let Some(p) = self.pos(target) {
                    let it = &mut self.items[p];
                    // keep the smallest deleter so every replica records the same one
                    if it.del.map_or(true, |d| uid < d) {
                        it.del = Some(uid);
                    }
                }
            }
        }
    }
    pub fn text(&self) -> String {
        self.items.iter().filter(|x| x.del.is_none()).map(|x| x.ch).collect()
    }
    fn visible_at(&self, vv: &Vv) -> Vec<Id> {
        self.items
            .iter()
            .filter(|x| vv_has(vv, x.id.site, x.id.seq) && x.del.map_or(true, |(s, q)| !vv_has(vv, s, q)))
            .map(|x| x.id)
            .collect()
    }
    pub fn text_at(&self, vv: &Vv) -> String {
        let ids = self.visible_at(vv);
        ids.iter().map(|id| self.items[self.pos(*id).unwrap()].ch).collect()
    }
    /// Turn range edits against the text as of `base` into ops for update `uid`. Ranges are in characters
    /// of the base text and must not overlap.
    pub fn ops_for(&self, base: &Vv, edits: &[Edit], uid: (u64, u64)) -> Result<Vec<TOp>, String> {
        let ids = self.visible_at(base);
        let mut ops = vec![];
        let mut lam = self.max_lam;
        let mut i = 0u32;
        let mut sorted: Vec<&Edit> = edits.iter().collect();
        sorted.sort_by_key(|e| e.start);
        let mut last_end = 0;
        for e in sorted {
            if e.start > e.end || e.end > ids.len() || e.start < last_end {
                return Err(format!("edit range {}..{} does not fit the base text of {} characters", e.start, e.end, ids.len()));
            }
            last_end = e.end;
            for t in &ids[e.start..e.end] {
                if self.items[self.pos(*t).unwrap()].del.is_none() {
                    ops.push(TOp::Del { target: *t });
                }
            }
            let mut after = if e.start == 0 { None } else { Some(ids[e.start - 1]) };
            for ch in e.text.chars() {
                lam += 1;
                let id = Id { site: uid.0, seq: uid.1, i };
                i += 1;
                ops.push(TOp::Ins { id, lam, after, ch });
                after = Some(id);
            }
        }
        Ok(ops)
    }
    /// Edits that turn the current text into `new` (one replaced middle range).
    pub fn diff(old: &str, new: &str) -> Vec<Edit> {
        let a: Vec<char> = old.chars().collect();
        let b: Vec<char> = new.chars().collect();
        let mut p = 0;
        while p < a.len() && p < b.len() && a[p] == b[p] {
            p += 1;
        }
        let mut s = 0;
        while s < a.len() - p && s < b.len() - p && a[a.len() - 1 - s] == b[b.len() - 1 - s] {
            s += 1;
        }
        if p == a.len() && p == b.len() {
            return vec![];
        }
        vec![Edit { start: p, end: a.len() - s, text: b[p..b.len() - s].iter().collect() }]
    }
    /// A cursor that stays on its character: the id of the character before it.
    pub fn anchor(&self, offset: usize) -> Option<Id> {
        if offset == 0 {
            return None;
        }
        self.items.iter().filter(|x| x.del.is_none()).nth(offset - 1).map(|x| x.id)
    }
    pub fn offset(&self, anchor: Option<Id>) -> usize {
        let Some(a) = anchor else { return 0 };
        let Some(p) = self.pos(a) else { return 0 };
        self.items[..=p].iter().filter(|x| x.del.is_none()).count()
    }
}

#[cfg(test)]
mod t {
    use super::*;
    fn e(start: usize, end: usize, text: &str) -> Edit {
        Edit { start, end, text: text.into() }
    }
    fn vv(p: &[(u64, u64)]) -> Vv {
        p.iter().cloned().collect()
    }
    #[test]
    fn concurrent_same_place_converges() {
        let mut a = Doc::default();
        for op in a.clone().ops_for(&Vv::new(), &[e(0, 0, "hello")], (1, 1)).unwrap() {
            a.apply((1, 1), &op);
        }
        let mut b = a.clone();
        let base = vv(&[(1, 1)]);
        let oa = a.ops_for(&base, &[e(5, 5, " A")], (2, 1)).unwrap();
        let ob = b.ops_for(&base, &[e(5, 5, " B")], (3, 1)).unwrap();
        for o in &oa {
            a.apply((2, 1), o);
        }
        for o in &ob {
            b.apply((3, 1), o);
        }
        for o in &ob {
            a.apply((3, 1), o);
        }
        for o in &oa {
            b.apply((2, 1), o);
        }
        assert_eq!(a.text(), b.text());
        assert!(a.text().contains(" A") && a.text().contains(" B"));
    }
    #[test]
    fn stale_patch_lands_in_place() {
        let mut d = Doc::default();
        for op in d.clone().ops_for(&Vv::new(), &[e(0, 0, "fn a() {}\nfn b() {}\n")], (1, 1)).unwrap() {
            d.apply((1, 1), &op);
        }
        let base = vv(&[(1, 1)]);
        // someone inserts a line at the top
        for op in d.clone().ops_for(&base, &[e(0, 0, "// head\n")], (2, 1)).unwrap() {
            d.apply((2, 1), &op);
        }
        // a patch against the old base replaces `b` with `c`
        for op in d.clone().ops_for(&base, &[e(13, 14, "c")], (3, 1)).unwrap() {
            d.apply((3, 1), &op);
        }
        assert_eq!(d.text(), "// head\nfn a() {}\nfn c() {}\n");
        let cur = d.anchor(11);
        for op in d.clone().ops_for(&vv(&[(1, 1), (2, 1), (3, 1)]), &[e(0, 0, "x")], (4, 1)).unwrap() {
            d.apply((4, 1), &op);
        }
        assert_eq!(d.offset(cur), 12);
    }
    #[test]
    fn diff_roundtrip() {
        let d = Doc::diff("abcdef", "abXYef");
        assert_eq!(d.len(), 1);
        assert_eq!((d[0].start, d[0].end, d[0].text.as_str()), (2, 4, "XY"));
    }
}
