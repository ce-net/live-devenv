//! The 14-step proof (DESIGN.md section 10), against any `Net`: the in-process mesh, the browser, or real
//! nodes over TCP. Two people and two agents, three nodes. Every step records what must hold and whether it did.

use crate::audit::{verify_log, Receipt, VerifyReport};
use crate::cells::Tool;
use crate::gate::Grant;
use crate::node::Answer;
use crate::sim::{person_grants, Client, Net, Tenant};
use crate::text::{Edit, Vv};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const SAMPLE: &[(&str, &str)] = &[
    ("crates/parser/src/lib.rs", include_str!("../../../sample/crates/parser/src/lib.rs")),
    ("crates/parser/src/util.rs", include_str!("../../../sample/crates/parser/src/util.rs")),
    ("docs/README.md", include_str!("../../../sample/docs/README.md")),
    ("ws.toml", include_str!("../../../sample/ws.toml")),
    (".github/workflows/ci.yml", include_str!("../../../sample/.github/workflows/ci.yml")),
];

pub const LIB: &str = "crates/parser/src/lib.rs";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StepResult {
    pub n: u32,
    pub title: String,
    pub must: String,
    pub holds: bool,
    pub detail: Value,
    pub ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    pub net: String,
    pub nodes: Vec<Value>,
    pub identities: Vec<Value>,
    pub steps: Vec<StepResult>,
    pub passed: usize,
    pub total: usize,
    pub receipts: Vec<Receipt>,
    pub node_keys: Vec<String>,
    pub verify: Option<VerifyReport>,
    pub tamper_detected: bool,
    pub runs: Vec<Value>,
}

pub struct People {
    pub h1: Client,
    pub h2: Client,
    pub a1: Client,
    pub a2: Client,
}

/// The four identities of the proof. H1 delegates to both agents with narrowing grant bundles.
pub fn people(t: &mut Tenant, now: u64) -> People {
    let h1 = t.person("H1", b"proof/H1/device-A", person_grants(true), now);
    let h2 = t.person("H2", b"proof/H2/device-B", person_grants(false), now);
    let a1 = t.agent(
        &h1,
        "A1",
        b"proof/A1",
        vec![
            Grant::new("ws.fs:read"),
            Grant::new("ws.fs:write").paths(&["crates/parser/**"]),
            Grant::new("ws.fs:propose"),
            Grant::new("ws.fs:snapshot"),
            Grant::new("ws.build:start"),
            Grant::new("ws.test:start"),
            Grant::new("ws.tools:find"),
            Grant::new("ws.tools:invoke").tools(&["rustc-test", "run-test"]),
            Grant::new("ws.review:open"),
            Grant::new("ws.review:comment"),
            Grant::new("ws.review:approve"),
            Grant::new("ws.presence:*"),
            Grant::new("ws.search:query"),
            Grant::new("ws.keys:whoami"),
            Grant::new("ws.audit:read"),
        ],
        now,
    );
    let a2 = t.agent(
        &h1,
        "A2",
        b"proof/A2",
        vec![
            Grant::new("ws.fs:read"),
            Grant::new("ws.fs:write").paths(&["docs/**"]),
            Grant::new("ws.fs:propose").paths(&["crates/**"]),
            Grant::new("ws.build:start"),
            Grant::new("ws.tools:invoke").tools(&["run-test"]),
            Grant::new("ws.presence:*"),
            Grant::new("ws.keys:whoami"),
        ],
        now,
    );
    People { h1, h2, a1, a2 }
}

/// Agents call through `ws.mcp`: the tool name and arguments become the cell op.
fn mcp(tool: &str, args: Value) -> Value {
    crate::contract::mcp_to_op(tool, &args).unwrap_or_else(|| panic!("{tool} is not an agent tool"))
}

fn ok(a: &Answer) -> Value {
    a.ok().cloned().unwrap_or_else(|| json!({"not_ok": a}))
}

fn read(net: &mut dyn Net, c: &mut Client, node: usize, path: &str) -> (String, Vv) {
    let e = c.env(json!({"op": "FsRead", "path": path}));
    let v = ok(&net.call(node, &e));
    (v["text"].as_str().unwrap_or("").to_string(), serde_json::from_value(v["version"].clone()).unwrap_or_default())
}

fn insert_before(text: &str, needle: &str, ins: &str) -> Edit {
    let byte = text.find(needle).unwrap_or(0);
    let at = text[..byte].chars().count();
    Edit { start: at, end: at, text: ins.into() }
}

fn hashes(net: &mut dyn Net) -> Vec<String> {
    (0..3).map(|i| net.status(i)["content_hash"].as_str().unwrap_or("").to_string()).collect()
}

fn same(v: &[String]) -> bool {
    v.windows(2).all(|w| w[0] == w[1]) && !v[0].is_empty()
}

/// H1 seeds the workspace through N1 and registers the tool records it approves.
pub fn seed(net: &mut dyn Net, h1: &mut Client) {
    for (path, text) in SAMPLE {
        let e = h1.env(json!({"op": "FsWrite", "path": path, "content": text}));
        net.call(0, &e);
    }
    let worker_tools = net.status(2)["tools"].clone();
    let rustc = worker_tools.get("rustc-test").and_then(|v| v.as_str()).unwrap_or("ref:ws.tools/bin/0000000000000000000000000000000000000000000000000000000000000000").to_string();
    let tools = [
        Tool { name: "rustc-test".into(), version: "1".into(), artifact: rustc, provides: vec!["compile:rust".into()], args: vec!["root".into(), "out".into()], network: false, secs: 300, memory_mb: 1024, wraps: "rustc (MIT OR Apache-2.0)".into() },
        Tool { name: "run-test".into(), version: "1".into(), artifact: "input:bin".into(), provides: vec!["test:rust".into()], args: vec!["bin".into()], network: false, secs: 120, memory_mb: 256, wraps: String::new() },
    ];
    for t in tools {
        let e = h1.env(json!({"op": "ToolsRegister", "tool": t}));
        net.call(0, &e);
    }
    net.tick(2);

}

pub fn run(net: &mut dyn Net, p: &mut People, node_keys: Vec<String>, clock: &dyn Fn() -> u64) -> Report {
    let mut steps: Vec<StepResult> = vec![];
    let mut runs: Vec<Value> = vec![];
    let (h1, h2, a1, a2) = (&mut p.h1, &mut p.h2, &mut p.a1, &mut p.a2);
    let mut push = |n: u32, title: &str, must: &str, holds: bool, detail: Value, t0: u64| {
        steps.push(StepResult { n, title: title.into(), must: must.into(), holds, detail, ms: clock().saturating_sub(t0) });
    };

    seed(net, h1);

    // 1. three writers, three functions, one second, through N1, N2, N2
    let t0 = clock();
    let (text, base) = read(net, h1, 0, LIB);
    let e1 = h1.env(json!({"op": "FsPatch", "path": LIB, "base": base, "edits": [insert_before(&text, "pub fn parse_line", "/// Splits at the first `=`.\n")]}));
    let e2 = h2.env(json!({"op": "FsPatch", "path": LIB, "base": base, "edits": [insert_before(&text, "pub fn count_pairs", "/// Lines that hold a pair.\n")]}));
    let op3 = mcp("fs_patch", json!({"path": LIB, "base": base, "edits": [insert_before(&text, "pub fn keys", "/// Keys in order.\n")]}));
    let e3 = a1.env(op3);
    let r = [net.call(0, &e1), net.call(1, &e2), net.call(1, &e3)];
    net.tick(2);
    let hs = hashes(net);
    let (t1, _) = read(net, h2, 2, LIB);
    let all = ["Splits at the first", "Lines that hold a pair", "Keys in order"].iter().all(|s| t1.contains(s));
    push(1, "three writers edit different functions within one second", "all three replicas reach one content hash; no edit lost", r.iter().all(|a| a.ok().is_some()) && same(&hs) && all, json!({"hashes": hs, "all_edits_present": all}), t0);

    // 2. same line, same moment
    let t0 = clock();
    let (text, base) = read(net, h1, 0, LIB);
    let at = text.find('\n').map(|b| text[..b].chars().count()).unwrap_or(0);
    let e1 = h1.env(json!({"op": "FsPatch", "path": LIB, "base": base, "edits": [{"start": at, "end": at, "text": " Fast."}]}));
    let e2 = h2.env(json!({"op": "FsPatch", "path": LIB, "base": base, "edits": [{"start": at, "end": at, "text": " Small."}]}));
    let (x, y) = (net.call(0, &e1), net.call(1, &e2));
    net.tick(2);
    let hs = hashes(net);
    let (t2, _) = read(net, h1, 2, LIB);
    let first = t2.lines().next().unwrap_or("").to_string();
    push(2, "two people type in the same line at once", "converges on every replica; both insertions present", x.ok().is_some() && y.ok().is_some() && same(&hs) && first.contains(" Fast.") && first.contains(" Small."), json!({"hashes": hs, "line": first}), t0);

    // 3. presence with cursors that stay on their character
    let t0 = clock();
    let (text, _) = read(net, h1, 0, LIB);
    let targets = [("H1", "pub fn parse_line"), ("H2", "pub fn count_pairs"), ("A1", "pub fn keys"), ("A2", "pub fn is_comment")];
    let offs: Vec<usize> = targets.iter().map(|(_, n)| text[..text.find(n).unwrap()].chars().count()).collect();
    let calls = [(0usize, 0usize), (1, 1), (1, 2), (2, 3)];
    for (node, who) in calls {
        let c: &mut Client = match who {
            0 => &mut *h1,
            1 => &mut *h2,
            2 => &mut *a1,
            _ => &mut *a2,
        };
        let e = c.env(json!({"op": "PresenceAnnounce", "path": LIB, "offset": offs[who]}));
        net.call(node, &e);
    }
    net.tick(1);
    let (_, base) = read(net, h1, 0, LIB);
    let e = h1.env(json!({"op": "FsPatch", "path": LIB, "base": base, "edits": [{"start": 0, "end": 0, "text": "// shared workspace\n"}]}));
    net.call(0, &e);
    net.tick(2);
    let mut seen_ok = true;
    let mut views = vec![];
    for (node, c) in [(0usize, &mut *h1), (1, &mut *h2), (1, &mut *a1)] {
        let e = c.env(json!({"op": "PresenceWatch", "prefix": ""}));
        let rows = ok(&net.call(node, &e));
        let (now_text, _) = read(net, c, node, LIB);
        let rows = rows.as_array().cloned().unwrap_or_default();
        let mut ok_here = rows.len() == 4;
        for (name, needle) in targets {
            let off = rows.iter().find(|r| r["name"] == name).and_then(|r| r["offset"].as_u64()).unwrap_or(0) as usize;
            let at: String = now_text.chars().skip(off).take(needle.len()).collect();
            ok_here &= at == needle;
        }
        seen_ok &= ok_here;
        views.push(json!({"viewer": c.name, "node": node, "sees": rows.len(), "cursors_on_their_characters": ok_here}));
    }
    push(3, "presence", "each sees the other three, with cursors on the right characters after edits above them", seen_ok, json!(views), t0);

    // 4. an agent with propose only: the patch lands in its change set
    let t0 = clock();
    let before = hashes(net);
    let (text, base) = read(net, a2, 2, LIB);
    let op = mcp("fs_patch", json!({"path": LIB, "base": base, "edits": [insert_before(&text, "pub fn is_comment", "/// True for a line that starts with `#`.\n")]}));
    let e = a2.env(op);
    let a = ok(&net.call(2, &e));
    net.tick(2);
    let after = hashes(net);
    push(4, "A2 patches a file outside its write paths", "lands in A2's change set; shared tree unchanged", a["shared"] == false && a["change"].is_string() && before == after, json!({"answer": a, "hash_before": before[0], "hash_after": after[0]}), t0);

    // 5. forged claim and out-of-scope write
    let t0 = clock();
    let honest = a1.chain.clone();
    a1.chain = a1.chain.extend(&a1.key, &a1.key.pk(), vec![Grant::new("ws.fs:write")], net.now() + 3_600_000);
    let op = mcp("fs_write", json!({"path": ".github/workflows/ci.yml", "content": "pwned\n"}));
    let e = a1.env(op);
    let r1 = net.call(1, &e);
    a1.chain = honest;
    let op = mcp("fs_write", json!({"path": "ws.toml", "content": "[workspace]\n"}));
    let e = a2.env(op);
    let r2 = net.call(2, &e);
    net.tick(2);
    let unchanged = hashes(net) == after;
    let (ci, _) = read(net, h1, 0, ".github/workflows/ci.yml");
    push(5, "forged write claim and an out-of-scope write", "both Refused, tree unchanged, two signed refusal receipts", r1.is_refused() && r2.is_refused() && unchanged && !ci.contains("pwned"), json!({"a1": r1, "a2": r2}), t0);

    // 6. concurrent renames across a partition
    let t0 = clock();
    net.cut(1, true);
    let e1 = h1.env(json!({"op": "FsMove", "path": "crates/parser/src/util.rs", "to": "crates/parser/src/text.rs"}));
    let e2 = h2.env(json!({"op": "FsMove", "path": "crates/parser/src/util.rs", "to": "crates/parser/src/strings.rs"}));
    let (x, y) = (net.call(0, &e1), net.call(1, &e2));
    net.tick(1);
    net.cut(1, false);
    net.tick(2);
    let conflicts: Vec<u64> = (0..3).map(|i| net.status(i)["conflicts"].as_u64().unwrap_or(0)).collect();
    let e = h1.env(json!({"op": "FsResolve", "path": "crates/parser/src/util.rs", "pick": "crates/parser/src/text.rs"}));
    let res = net.call(0, &e);
    net.tick(2);
    let after_c: Vec<u64> = (0..3).map(|i| net.status(i)["conflicts"].as_u64().unwrap_or(0)).collect();
    let mut names = vec![];
    for (i, c) in [(0usize, &mut *h1), (1, &mut *h2), (2, &mut *a1)] {
        let e = c.env(json!({"op": "FsList", "prefix": "crates/parser/src/"}));
        let l = ok(&net.call(i, &e));
        names.push(l.as_array().map(|a| a.iter().map(|x| x["path"].as_str().unwrap_or("").to_string()).collect::<Vec<_>>()).unwrap_or_default());
    }
    let one = names.iter().all(|n| n.contains(&"crates/parser/src/text.rs".to_string()) && !n.iter().any(|p| p.contains("strings") || p.contains("util")));
    push(6, "two renames of one file on a partitioned node, then heal", "one tree conflict on all replicas; H1 resolves; one name everywhere; receipt", x.ok().is_some() && y.ok().is_some() && conflicts == [1, 1, 1] && res.ok().is_some() && after_c == [0, 0, 0] && one, json!({"conflicts_after_heal": conflicts, "after_resolve": after_c, "names": names[0]}), t0);

    // 7. build and test placed on the worker
    let t0 = clock();
    let op = mcp("fs_snapshot", json!({"prefix": ""}));
    let e = a1.env(op);
    let snap = ok(&net.call(1, &e))["snapshot"].as_str().unwrap_or("").to_string();
    let op = mcp("build_start", json!({"input": snap, "target": "crates/parser"}));
    let e = a1.env(op);
    let b = ok(&net.call(1, &e));
    let out = b["output"].as_str().unwrap_or("").to_string();
    let op = mcp("test_start", json!({"input": out, "bin": "out/test"}));
    let e = a1.env(op);
    let t = ok(&net.call(1, &e));
    let failed = t["cases"].as_array().map(|c| c.iter().filter(|x| x["status"] == "fail").count()).unwrap_or(9);
    let worker = net.status(2)["name"].clone();
    runs.push(b["receipt"].clone());
    runs.push(t["receipt"].clone());
    let iso = b["receipt"]["isolation"].clone();
    push(7, "A1 builds and tests a snapshot, entering at N2", "placed on N3; run receipts name N3 and the isolation class; cases typed; one fails",
        b["receipt"]["node"] == worker && t["receipt"]["node"] == worker && b["receipt"]["exit"] == 0 && failed == 1 && iso.is_string(),
        json!({"build": b["receipt"], "test": t["receipt"], "cases": t["cases"]}), t0);
    let first_build = (snap.clone(), b["receipt"].clone());

    // 8. the fix in a change set, tested there
    let t0 = clock();
    let op = mcp("review_open", json!({"title": "indented comments"}));
    let e = a1.env(op);
    let ch = ok(&net.call(1, &e))["change"].as_str().unwrap_or("").to_string();
    let (text, base) = read(net, a1, 1, LIB);
    let bad = "line.starts_with('#')";
    let at = text[..text.find(bad).unwrap_or(0)].chars().count();
    let op = mcp("fs_patch", json!({"path": LIB, "base": base, "change": ch, "edits": [{"start": at, "end": at + bad.len(), "text": "line.trim_start().starts_with('#')"}]}));
    let e = a1.env(op);
    let pa = ok(&net.call(1, &e));
    let cs_snap = pa["snapshot"].as_str().unwrap_or("").to_string();
    let op = mcp("build_start", json!({"input": cs_snap, "target": "crates/parser"}));
    let e = a1.env(op);
    let b2 = ok(&net.call(1, &e));
    let op = mcp("test_start", json!({"input": b2["output"], "bin": "out/test"}));
    let e = a1.env(op);
    let t2 = ok(&net.call(1, &e));
    runs.push(b2["receipt"].clone());
    runs.push(t2["receipt"].clone());
    push(8, "A1 patches the fix into a change set; tests on the change set", "green; receipt bound to the change set's snapshot", t2["green"] == true && t2["source"] == cs_snap && pa["shared"] == false, json!({"change": ch, "snapshot": cs_snap, "cases": t2["cases"], "test": t2["receipt"]}), t0);

    // 9. self-approval refused, a person approves, merge keeps a line typed meanwhile
    let t0 = clock();
    let (text, base) = read(net, h1, 0, LIB);
    let end = text.chars().count();
    let e = h1.env(json!({"op": "FsPatch", "path": LIB, "base": base, "edits": [{"start": end, "end": end, "text": "// typed by H1 during the review\n"}]}));
    net.call(0, &e);
    let op = mcp("review_approve", json!({"change": ch, "snapshot": cs_snap}));
    let e = a1.env(op);
    let self_ap = net.call(1, &e);
    let e = h2.env(json!({"op": "ReviewApprove", "change": ch, "snapshot": cs_snap}));
    let ap = net.call(1, &e);
    let e = h2.env(json!({"op": "ReviewMerge", "change": ch}));
    let mg = net.call(1, &e);
    net.tick(2);
    let hs = hashes(net);
    let (merged, _) = read(net, h2, 2, LIB);
    let keeps = merged.contains("trim_start().starts_with('#')") && merged.contains("typed by H1 during the review");
    push(9, "A1 approves its own change; H2 approves; merge", "first Refused; second accepted with H2's device signature; merge keeps a line H1 typed meanwhile", self_ap.is_refused() && ap.ok().is_some() && mg.ok().is_some() && keeps && same(&hs), json!({"self_approval": self_ap, "approval": ap, "merge": mg, "kept_h1_line": keeps}), t0);

    // 10. the same build again, from N1
    let t0 = clock();
    let boxes_before = net.status(2)["boxes_started"].as_u64().unwrap_or(0);
    let e = h1.env(json!({"op": "BuildStart", "input": first_build.0, "target": "crates/parser"}));
    let b3 = ok(&net.call(0, &e));
    let boxes_after = net.status(2)["boxes_started"].as_u64().unwrap_or(0);
    push(10, "the same build again from N1", "cache: hit, no box started", b3["receipt"]["cache"] == "hit" && boxes_before == boxes_after && b3["receipt"]["output"] == first_build.1["output"], json!({"receipt": b3["receipt"], "boxes_before": boxes_before, "boxes_after": boxes_after}), t0);

    // 11. network in a box; a tool outside the grant
    let t0 = clock();
    let e = h1.env(json!({"op": "BuildStart", "input": first_build.0, "target": "crates/parser", "network": true}));
    let n1 = net.call(0, &e);
    let op = mcp("build_start", json!({"input": first_build.0, "target": "crates/parser"}));
    let e = a2.env(op);
    let n2 = net.call(2, &e);
    push(11, "a run asks for network; a tool not in A2's grant", "both Refused", n1.is_refused() && n2.is_refused(), json!({"network": n1, "tool": n2}), t0);

    // 12. revoke
    let t0 = clock();
    let link = a2.chain.links.last().unwrap().clone();
    let e = h1.env(json!({"op": "KeysRevoke", "link": link}));
    let rv = net.call(0, &e);
    net.tick(1);
    let mut refused = vec![];
    for n in 0..3 {
        let e = a2.env(json!({"op": "FsRead", "path": LIB}));
        refused.push(net.call(n, &e).is_refused());
    }
    push(12, "H1 revokes A2", "A2's next call Refused on all three nodes within one round", rv.ok().is_some() && refused == [true, true, true], json!({"refused_at": refused}), t0);

    // 13. commit and pin
    let t0 = clock();
    let e = h1.env(json!({"op": "FsSnapshot", "prefix": ""}));
    let s = ok(&net.call(0, &e))["snapshot"].as_str().unwrap_or("").to_string();
    let e = h1.env(json!({"op": "VcsCommit", "snapshot": s, "message": "parser: indented comments are comments"}));
    let c = ok(&net.call(0, &e));
    let e = h1.env(json!({"op": "SnapPin", "snapshot": s, "label": "release-1"}));
    net.call(0, &e);
    let e = h1.env(json!({"op": "SnapPins"}));
    let pins = ok(&net.call(0, &e));
    push(13, "commit of the merged snapshot; pin", "commit names the snapshot ref; pin listed", c["snapshot"] == s && pins.get(&s).is_some(), json!({"commit": c, "pins": pins}), t0);

    // 14. offline verification of the exported log
    let t0 = clock();
    net.tick(3);
    let e = h1.env(json!({"op": "AuditRead", "since": 0}));
    let receipts: Vec<Receipt> = serde_json::from_value(ok(&net.call(0, &e))).unwrap_or_default();
    let v = verify_log(&receipts, &node_keys);
    let mut bad = receipts.clone();
    let tamper = if let Some(r) = bad.iter_mut().find(|r| r.refused()) {
        r.outcome = crate::audit::Outcome::Ok { result: "0".repeat(64) };
        !verify_log(&bad, &node_keys).ok
    } else {
        false
    };
    let refusals = receipts.iter().filter(|r| r.refused()).count();
    push(14, "verify the exported receipt log offline", "every link and signature valid; a copy with one receipt altered fails", v.ok && tamper && refusals >= 2, json!({"receipts": v.receipts, "chains": v.chains, "refused": v.refused, "errors": v.errors, "tampered_copy_fails": tamper}), t0);

    let nodes = (0..3).map(|i| net.status(i)).collect();
    let passed = steps.iter().filter(|s| s.holds).count();
    let identities = [&p.h1, &p.h2, &p.a1, &p.a2].iter().map(|c| json!({"name": c.name, "key": c.pk(), "rights": c.chain.have(), "chain": c.chain.id()})).collect();
    Report { net: net.label(), nodes, identities, total: steps.len(), passed, steps, receipts, node_keys, verify: Some(v), tamper_detected: tamper, runs }
}
