//! The page's sim mode: the real cells (`ws.fs`, `ws.presence`, `ws.review`, `ws.audit`, the gate) running as
//! three nodes inside the browser tab. Builds and tests cannot run in a tab, so the worker replays runs that
//! were recorded on a real worker, matched by tool and source files; every replayed receipt says so.

use serde_json::{json, Value};
use std::collections::BTreeMap;
use wasm_bindgen::prelude::*;
use ws_core::cells::{RunOut, RunReq};
use ws_core::node::{Answer, NoRunner, Runner};
use ws_core::proof::{self, People};
use ws_core::sim::{Client, Mesh, Net, Tenant};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = Date)]
    fn now() -> f64;
}

struct Replay {
    rows: Vec<Value>,
}

impl Runner for Replay {
    fn isolation(&self) -> String {
        self.rows.first().and_then(|r| r["isolation"].as_str()).unwrap_or("ns+landlock+seccomp").to_string()
    }
    fn tools(&self) -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert("rustc-test".to_string(), ws_core::ref_of("ws.tools", "bin", &ws_core::h(b"recorded rustc")));
        m
    }
    fn run(&mut self, req: &RunReq, files: &[(String, Vec<u8>)]) -> Result<RunOut, String> {
        let src: Vec<(String, String)> = files.iter().filter(|(p, _)| !p.starts_with("out/")).map(|(p, b)| (p.clone(), ws_core::h(b))).collect();
        let key = ws_core::hj(&src);
        let row = self.rows.iter().find(|r| r["tool"] == req.tool.name.as_str() && r["source"] == key.as_str()).ok_or("no recorded run for these files: builds in the browser replay runs recorded on a real worker")?;
        let outputs = if req.tool.name == "rustc-test" { vec![("out/test".to_string(), format!("replayed build of {key}").into_bytes())] } else { vec![] };
        Ok(RunOut { exit: row["exit"].as_i64().unwrap_or(1) as i32, stdout: row["stdout"].as_str().unwrap_or("").into(), stderr: String::new(), outputs, isolation: self.isolation(), replayed: true })
    }
}

const START: u64 = 1_800_000_000_000;

#[wasm_bindgen]
pub struct Sim {
    mesh: Mesh,
    people: People,
    keys: Vec<String>,
}

fn build(replay: &str) -> Sim {
    let rows: Vec<Value> = serde_json::from_str(replay).unwrap_or_default();
    let mut t = Tenant::new(b"live-devenv/sim/root", &[("N1", b"sim/N1".to_vec()), ("N2", b"sim/N2".to_vec()), ("N3", b"sim/N3".to_vec())], START);
    let people = proof::people(&mut t, START);
    let nodes = vec![t.node(0, Box::new(NoRunner)), t.node(1, Box::new(NoRunner)), t.node(2, Box::new(Replay { rows }))];
    let keys = t.dir.nodes.iter().map(|n| n.1.clone()).collect();
    Sim { mesh: Mesh::new(nodes, START), people, keys }
}

#[wasm_bindgen]
impl Sim {
    /// A fresh workspace, seeded by H1 through N1.
    #[wasm_bindgen(constructor)]
    pub fn new(replay: &str) -> Sim {
        let mut s = build(replay);
        proof::seed(&mut s.mesh, &mut s.people.h1, 2);
        s
    }

    /// Run the 14 steps on a fresh mesh and answer the report.
    pub fn run_proof(replay: &str) -> String {
        let mut s = build(replay);
        let t0 = now();
        let clock = move || (now() - t0) as u64;
        let r = proof::run(&mut s.mesh, &mut s.people, s.keys.clone(), &clock);
        serde_json::to_string(&r).unwrap()
    }

    fn who(&mut self, name: &str) -> &mut Client {
        match name {
            "H2" => &mut self.people.h2,
            "A1" => &mut self.people.a1,
            "A2" => &mut self.people.a2,
            _ => &mut self.people.h1,
        }
    }

    /// Any op as any of the four identities, at any node. Answers the typed result or refusal.
    pub fn call(&mut self, who: &str, node: usize, op: &str) -> String {
        let op: Value = serde_json::from_str(op).unwrap_or(json!({}));
        let e = self.who(who).env(op);
        let a: Answer = self.mesh.call(node, &e);
        serde_json::to_string(&a).unwrap()
    }

    /// Replace a file's text as `who` at `node` (the editor sends a diff against the version it shows).
    pub fn edit(&mut self, who: &str, node: usize, path: &str, text: &str) -> String {
        self.call(who, node, &json!({"op": "FsWrite", "path": path, "content": text}).to_string())
    }

    pub fn cut(&mut self, node: usize, cut: bool) {
        self.mesh.cut(node, cut);
    }

    pub fn tick(&mut self) {
        self.mesh.tick(1);
    }

    /// Per node: reachability, files with hashes, the text of one file, conflicts, receipts.
    pub fn state(&mut self, path: &str) -> String {
        let mut out = vec![];
        for i in 0..3 {
            let n = self.mesh.node(i);
            let file = n.fs.file_at(path);
            out.push(json!({
                "name": n.name, "cut": self.mesh.cut.contains(&i),
                "files": n.fs.list("").into_iter().map(|l| json!({"path": l.path, "hash": &l.hash[..8], "conflicted": l.conflicted})).collect::<Vec<_>>(),
                "text": file.as_ref().map(|f| n.fs.text(f)).unwrap_or_default(),
                "content_hash": &n.fs.content_hash()[..12],
                "conflicts": n.fs.conflicts(""),
                "receipts": n.audit.len(),
            }));
        }
        json!(out).to_string()
    }

    pub fn receipts(&self, node: usize) -> String {
        serde_json::to_string(&self.mesh.node(node).audit.all()).unwrap()
    }
}

/// Verify an exported receipt log (a proof report) in the browser.
#[wasm_bindgen]
pub fn verify(report: &str) -> String {
    let v: Value = serde_json::from_str(report).unwrap_or(json!({}));
    let receipts: Vec<ws_core::audit::Receipt> = serde_json::from_value(v["receipts"].clone()).unwrap_or_default();
    let keys: Vec<String> = serde_json::from_value(v["node_keys"].clone()).unwrap_or_default();
    serde_json::to_string(&ws_core::audit::verify_log(&receipts, &keys)).unwrap()
}

#[wasm_bindgen]
pub fn contract() -> String {
    ws_core::contract::contract_json().to_string()
}

/// The browser's own key (32 random bytes from crypto.getRandomValues, as hex): its public key.
#[wasm_bindgen]
pub fn public_key(secret: &str) -> String {
    let b: [u8; 32] = ws_core::unhex(secret).and_then(|v| v.try_into().ok()).unwrap_or([0; 32]);
    ws_core::gate::Key::from_secret(b).pk()
}

/// Sign one op with the browser's key and the session chain the gateway issued to it.
#[wasm_bindgen]
pub fn sign(secret: &str, chain: &str, op: &str, n: f64) -> String {
    let b: [u8; 32] = ws_core::unhex(secret).and_then(|v| v.try_into().ok()).unwrap_or([0; 32]);
    let chain: ws_core::gate::Chain = serde_json::from_str(chain).unwrap_or_default();
    let op: Value = serde_json::from_str(op).unwrap_or(json!({}));
    serde_json::to_string(&ws_core::gate::Envelope::sign(&ws_core::gate::Key::from_secret(b), &chain, op, n as u64)).unwrap()
}
