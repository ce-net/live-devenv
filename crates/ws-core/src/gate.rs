//! `ws-gate`: identities, capability chains and the check on every op (stands in for ce-gate, cap v3, CAL).
//!
//! A chain starts at the tenant root and narrows at every hop. A grant is one right (`cell:right`, or
//! `cell:*`) plus caveats: the paths it covers, the paths it never covers and, for `ws.tools:invoke`, the
//! tools. A request is signed by the actor's own key, and the actor must be the chain's last subject, so
//! nobody acts with another identity's chain.

use crate::{h, hex, hj, unhex};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub struct Key {
    sk: SigningKey,
}

impl Key {
    /// A key from 32 bytes of seed material (hashed first). Nodes seed from the OS; the sim from names.
    pub fn from_seed(seed: &[u8]) -> Key {
        let d = blake3::hash(seed);
        Key { sk: SigningKey::from_bytes(d.as_bytes()) }
    }
    /// A second handle on the same key, for handing a node its own key once at start.
    pub fn dup(&self) -> Key {
        Key { sk: SigningKey::from_bytes(&self.sk.to_bytes()) }
    }
    pub fn seed_bytes(&self) -> [u8; 32] {
        self.sk.to_bytes()
    }
    pub fn from_secret(b: [u8; 32]) -> Key {
        Key { sk: SigningKey::from_bytes(&b) }
    }
    pub fn pk(&self) -> String {
        hex(self.sk.verifying_key().as_bytes())
    }
    pub fn sign(&self, msg: &[u8]) -> String {
        hex(&self.sk.sign(msg).to_bytes())
    }
}

pub fn verify(pk: &str, msg: &[u8], sig: &str) -> bool {
    let (Some(p), Some(s)) = (unhex(pk), unhex(sig)) else { return false };
    let (Ok(p), Ok(s)) = (<[u8; 32]>::try_from(p.as_slice()), <[u8; 64]>::try_from(s.as_slice())) else { return false };
    let Ok(vk) = VerifyingKey::from_bytes(&p) else { return false };
    vk.verify(msg, &Signature::from_bytes(&s)).is_ok()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub right: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<String>,
}

impl Grant {
    pub fn new(right: &str) -> Grant {
        Grant { right: right.into(), paths: vec!["**".into()], not: vec![], tools: vec![] }
    }
    pub fn paths(mut self, p: &[&str]) -> Grant {
        self.paths = p.iter().map(|s| s.to_string()).collect();
        self
    }
    pub fn not(mut self, p: &[&str]) -> Grant {
        self.not = p.iter().map(|s| s.to_string()).collect();
        self
    }
    pub fn tools(mut self, t: &[&str]) -> Grant {
        self.tools = t.iter().map(|s| s.to_string()).collect();
        self
    }
    pub fn label(&self) -> String {
        let mut s = self.right.clone();
        if self.paths != ["**"] && !self.paths.is_empty() {
            s += &format!(" path in {:?}", self.paths);
        }
        if !self.not.is_empty() {
            s += &format!(" path not in {:?}", self.not);
        }
        if !self.tools.is_empty() {
            s += &format!(" tool in {:?}", self.tools);
        }
        s
    }
    fn right_covers(&self, right: &str) -> bool {
        self.right == right || self.right == "*" || (self.right.ends_with(":*") && right.starts_with(&self.right[..self.right.len() - 1]))
    }
    pub fn allows_path(&self, path: &str) -> bool {
        self.paths.iter().any(|g| glob(g, path)) && !self.not.iter().any(|g| glob(g, path))
    }
    /// Does this grant cover `c` entirely (used to check that delegation only narrows)?
    pub fn covers(&self, c: &Grant) -> bool {
        let right = self.right_covers(&c.right) || (self.right.ends_with(":*") && c.right == self.right);
        let paths = c.paths.iter().all(|cp| self.paths.iter().any(|pp| glob_covers(pp, cp)));
        let not = self.not.iter().all(|n| c.not.contains(n));
        let tools = self.tools.is_empty() || (!c.tools.is_empty() && c.tools.iter().all(|t| self.tools.contains(t)));
        right && paths && not && tools
    }
}

/// `**` any number of segments, `*` within a segment, else literal.
pub fn glob(pat: &str, path: &str) -> bool {
    fn m(p: &[u8], s: &[u8]) -> bool {
        if p.is_empty() {
            return s.is_empty();
        }
        if p.starts_with(b"**") {
            let rest = p[2..].strip_prefix(b"/").unwrap_or(&p[2..]);
            if rest.is_empty() {
                return true;
            }
            return (0..=s.len()).any(|i| (i == 0 || s[i - 1] == b'/') && m(rest, &s[i..])) || m(rest, s);
        }
        if p[0] == b'*' {
            return (0..=s.len()).take_while(|&i| i == 0 || s[i - 1] != b'/').any(|i| m(&p[1..], &s[i..]));
        }
        !s.is_empty() && p[0] == s[0] && m(&p[1..], &s[1..])
    }
    m(pat.as_bytes(), path.as_bytes())
}

fn glob_covers(parent: &str, child: &str) -> bool {
    parent == child || parent == "**" || (parent.ends_with("/**") && child.starts_with(&parent[..parent.len() - 2])) || (!child.contains('*') && glob(parent, child))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Link {
    pub issuer: String,
    pub subject: String,
    pub grants: Vec<Grant>,
    pub expiry: u64,
    pub sig: String,
}

#[derive(Serialize)]
struct LinkBody<'a> {
    issuer: &'a str,
    subject: &'a str,
    grants: &'a [Grant],
    expiry: u64,
}

impl Link {
    pub fn issue(by: &Key, subject: &str, grants: Vec<Grant>, expiry: u64) -> Link {
        let issuer = by.pk();
        let body = serde_json::to_vec(&LinkBody { issuer: &issuer, subject, grants: &grants, expiry }).unwrap();
        Link { sig: by.sign(&body), issuer, subject: subject.into(), grants, expiry }
    }
    pub fn id(&self) -> String {
        hj(self)
    }
    fn sig_ok(&self) -> bool {
        let body = serde_json::to_vec(&LinkBody { issuer: &self.issuer, subject: &self.subject, grants: &self.grants, expiry: self.expiry }).unwrap();
        verify(&self.issuer, &body, &self.sig)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chain {
    pub links: Vec<Link>,
}

/// The typed refusal every cell answers with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refused {
    pub need: String,
    pub have: Vec<String>,
    pub why: String,
}

impl Chain {
    pub fn id(&self) -> String {
        self.links.last().map(|l| l.id()).unwrap_or_default()
    }
    pub fn subject(&self) -> &str {
        self.links.last().map(|l| l.subject.as_str()).unwrap_or("")
    }
    pub fn grants(&self) -> &[Grant] {
        self.links.last().map(|l| l.grants.as_slice()).unwrap_or(&[])
    }
    pub fn extend(&self, by: &Key, subject: &str, grants: Vec<Grant>, expiry: u64) -> Chain {
        let mut c = self.clone();
        c.links.push(Link::issue(by, subject, grants, expiry));
        c
    }
    /// Structural check: starts at `root`, every signature, every hop narrows, nothing expired or revoked.
    pub fn verify(&self, root: &str, now: u64, revoked: &BTreeSet<String>) -> Result<(), String> {
        if self.links.is_empty() {
            return Err("empty chain".into());
        }
        if self.links[0].issuer != root {
            return Err("chain does not start at the tenant root".into());
        }
        for (i, l) in self.links.iter().enumerate() {
            if !l.sig_ok() {
                return Err(format!("link {i}: bad signature"));
            }
            if l.expiry <= now {
                return Err(format!("link {i}: expired"));
            }
            if revoked.contains(&l.id()) {
                return Err(format!("link {i}: revoked"));
            }
            if i > 0 {
                let p = &self.links[i - 1];
                if l.issuer != p.subject {
                    return Err(format!("link {i}: issuer is not the previous subject"));
                }
                if l.expiry > p.expiry {
                    return Err(format!("link {i}: outlives its parent"));
                }
                if let Some(g) = l.grants.iter().find(|g| !p.grants.iter().any(|pg| pg.covers(g))) {
                    return Err(format!("link {i}: widens: {}", g.label()));
                }
            }
        }
        Ok(())
    }
    pub fn have(&self) -> Vec<String> {
        self.grants().iter().map(|g| g.label()).collect()
    }
    /// The right check. `path` and `tool` are the caveat targets of this op.
    pub fn check(&self, actor: &str, right: &str, path: Option<&str>, tool: Option<&str>, root: &str, now: u64, revoked: &BTreeSet<String>) -> Result<(), Refused> {
        let refuse = |why: String| Refused { need: need_label(right, path, tool), have: self.have(), why };
        if self.subject() != actor {
            return Err(refuse("the chain belongs to another identity".into()));
        }
        self.verify(root, now, revoked).map_err(refuse)?;
        let ok = self.grants().iter().any(|g| g.right_covers(right) && path.map_or(true, |p| g.allows_path(p)) && tool.map_or(true, |t| g.tools.is_empty() || g.tools.iter().any(|x| x == t)));
        if ok {
            Ok(())
        } else {
            Err(refuse("no grant covers this op".into()))
        }
    }
    pub fn holds(&self, right: &str) -> bool {
        self.grants().iter().any(|g| g.right_covers(right))
    }
}

pub fn need_label(right: &str, path: Option<&str>, tool: Option<&str>) -> String {
    let mut s = right.to_string();
    if let Some(p) = path {
        s += &format!(" path {p}");
    }
    if let Some(t) = tool {
        s += &format!(" tool {t}");
    }
    s
}

/// A signed request: the op, the actor's chain, a nonce, the actor's signature over all three.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Envelope {
    pub actor: String,
    pub chain: Chain,
    pub op: serde_json::Value,
    pub n: u64,
    pub sig: String,
}

impl Envelope {
    pub fn sign(key: &Key, chain: &Chain, op: serde_json::Value, n: u64) -> Envelope {
        let msg = Self::msg(&chain.id(), &op, n);
        Envelope { actor: key.pk(), chain: chain.clone(), op, n, sig: key.sign(msg.as_bytes()) }
    }
    fn msg(chain: &str, op: &serde_json::Value, n: u64) -> String {
        format!("ws.env\n{chain}\n{n}\n{}", h(op.to_string().as_bytes()))
    }
    pub fn sig_ok(&self) -> bool {
        verify(&self.actor, Self::msg(&self.chain.id(), &self.op, self.n).as_bytes(), &self.sig)
    }
    pub fn hash(&self) -> String {
        hj(self)
    }
}

#[cfg(test)]
mod t {
    use super::*;
    #[test]
    fn globs() {
        assert!(glob("**", "a/b/c.rs"));
        assert!(glob("crates/parser/**", "crates/parser/src/lib.rs"));
        assert!(!glob("crates/parser/**", "crates/other/x"));
        assert!(glob("**/.env*", "a/.env.local"));
        assert!(glob("**/.env*", ".env"));
        assert!(glob("docs/*.md", "docs/a.md"));
        assert!(!glob("docs/*.md", "docs/x/a.md"));
    }
    #[test]
    fn narrowing_and_forgery() {
        let root = Key::from_seed(b"root");
        let a = Key::from_seed(b"a");
        let c = Chain::default().extend(&root, &a.pk(), vec![Grant::new("ws.fs:write").paths(&["crates/parser/**"])], 100);
        let rv = BTreeSet::new();
        assert!(c.check(&a.pk(), "ws.fs:write", Some("crates/parser/src/lib.rs"), None, &root.pk(), 1, &rv).is_ok());
        assert!(c.check(&a.pk(), "ws.fs:write", Some(".github/workflows/ci.yml"), None, &root.pk(), 1, &rv).is_err());
        // a self-signed widening link is refused
        let forged = c.extend(&a, &a.pk(), vec![Grant::new("ws.fs:write")], 100);
        let e = forged.check(&a.pk(), "ws.fs:write", Some(".github/workflows/ci.yml"), None, &root.pk(), 1, &rv).unwrap_err();
        assert!(e.why.contains("widens"), "{e:?}");
        // revocation
        let mut rv2 = BTreeSet::new();
        rv2.insert(c.id());
        assert!(c.check(&a.pk(), "ws.fs:write", Some("crates/parser/a"), None, &root.pk(), 1, &rv2).is_err());
        // another identity's chain
        let b = Key::from_seed(b"b");
        assert!(c.check(&b.pk(), "ws.fs:write", Some("crates/parser/a"), None, &root.pk(), 1, &rv).is_err());
    }
}
