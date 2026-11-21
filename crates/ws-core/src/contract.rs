//! The one declaration of every op: its cell, the right it needs, its agent tool name and its views.
//! The JSON contract served to the page (`site/contract.json`) and the MCP tool list are generated from
//! this table; a test fails when the committed file differs.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// (op, cell, right, MCP tool name or "" for none, one line, argument names)
pub const OPS: &[(&str, &str, &str, &str, &str, &[&str])] = &[
    ("FsList", "ws.fs", "read", "fs_list", "List the files under a prefix that you may read.", &["prefix"]),
    ("FsOpen", "ws.fs", "read", "fs_open", "Open a file: its id, version and state.", &["path"]),
    ("FsRead", "ws.fs", "read", "fs_read", "Read a file's text and version.", &["path"]),
    ("FsWrite", "ws.fs", "write", "fs_write", "Replace or create a whole file; with base_hash it is compare-and-set.", &["path", "content", "base_hash", "change"]),
    ("FsPatch", "ws.fs", "write", "fs_patch", "Range edits against a version you read; the cell maps them onto the present.", &["path", "base", "edits", "change"]),
    ("FsMove", "ws.fs", "write", "fs_move", "Rename a file.", &["path", "to"]),
    ("FsDelete", "ws.fs", "write", "fs_delete", "Delete a file.", &["path"]),
    ("FsConflicts", "ws.fs", "read", "fs_conflicts", "Unsettled pairs under a prefix.", &["prefix"]),
    ("FsResolve", "ws.fs", "resolve", "", "Pick one side of a conflict.", &["path", "pick"]),
    ("FsSnapshot", "ws.fs", "snapshot", "fs_snapshot", "Freeze a prefix into an immutable snapshot reference.", &["prefix"]),
    ("SnapPin", "ws.snap", "pin", "", "Keep a snapshot from collection.", &["snapshot", "label"]),
    ("SnapPins", "ws.snap", "read", "", "Pinned snapshots.", &[]),
    ("PresenceAnnounce", "ws.presence", "announce", "presence_announce", "Say where your cursor is.", &["path", "offset"]),
    ("PresenceWatch", "ws.presence", "see", "", "Who is here and where.", &["prefix"]),
    ("ReviewOpen", "ws.review", "open", "review_open", "Open a change set on the current tree.", &["title"]),
    ("ReviewList", "ws.review", "open", "", "Change sets.", &[]),
    ("ReviewDiff", "ws.review", "open", "review_diff", "A change set's files against its base.", &["change"]),
    ("ReviewSnapshot", "ws.review", "open", "", "The snapshot of a change set (its base with its files).", &["change"]),
    ("ReviewComment", "ws.review", "comment", "review_comment", "Comment on a change set.", &["change", "text"]),
    ("ReviewApprove", "ws.review", "approve", "review_approve", "Approve the exact snapshot of a change set.", &["change", "snapshot"]),
    ("ReviewMerge", "ws.review", "merge", "", "Merge an approved change set into the shared tree.", &["change"]),
    ("ToolsFind", "ws.tools", "find", "tools_find", "Tools you may invoke for a capability.", &["capability"]),
    ("ToolsRegister", "ws.tools", "register", "", "Register a tool record (artifact by hash).", &["tool"]),
    ("BuildStart", "ws.build", "start", "build_start", "Build a snapshot; placed on the node that fits.", &["input", "target", "network"]),
    ("TestStart", "ws.test", "start", "test_start", "Run the tests of a built snapshot; typed cases.", &["input", "bin"]),
    ("RunStart", "ws.run", "start", "", "One boxed run of one tool (node to node).", &["req"]),
    ("CacheGet", "ws.cache", "get", "", "A step result by key (node to node).", &["key"]),
    ("KeysRevoke", "ws.keys", "revoke", "", "End a chain everywhere.", &["link"]),
    ("KeysSession", "ws.keys", "session", "", "Issue an 8-hour session chain to a signed-in person's browser key (gateway to keys).", &["person", "pk"]),
    ("KeysWhoami", "ws.keys", "whoami", "whoami", "Your identity, rights and paths.", &[]),
    ("VcsCommit", "ws.vcs", "commit", "vcs_commit", "Commit a snapshot.", &["snapshot", "message"]),
    ("VcsLog", "ws.vcs", "read", "vcs_log", "Commits.", &[]),
    ("SearchText", "ws.search", "query", "search_text", "Text search over files you may read.", &["query", "glob"]),
    ("AuditRead", "ws.audit", "read", "audit_read", "The receipt log.", &["since"]),
    ("UiLayout", "ws.ui", "render", "", "The views this viewer may render.", &[]),
];

/// (view, cell, right that shows it, title)
pub const VIEWS: &[(&str, &str, &str, &str)] = &[
    ("render:tree", "ws.fs", "ws.fs:read", "Files"),
    ("render:editor", "ws.fs", "ws.fs:read", "Editor"),
    ("render:conflicts", "ws.fs", "ws.fs:read", "Conflicts"),
    ("render:people", "ws.presence", "ws.presence:see", "People"),
    ("render:changes", "ws.review", "ws.review:open", "Changes"),
    ("render:runs", "ws.build", "ws.build:start", "Runs"),
    ("render:tests", "ws.test", "ws.test:start", "Tests"),
    ("render:tools", "ws.tools", "ws.tools:find", "Tools"),
    ("render:search", "ws.search", "ws.search:query", "Search"),
    ("render:history", "ws.vcs", "ws.vcs:read", "History"),
    ("render:receipts", "ws.audit", "ws.audit:read", "Receipts"),
    ("render:grants", "ws.keys", "ws.keys:whoami", "Grants"),
];

pub fn right_of(op: &str) -> Option<String> {
    OPS.iter().find(|o| o.0 == op).map(|o| format!("{}:{}", o.1, o.2))
}

pub fn cell_of(op: &str) -> Option<&'static str> {
    OPS.iter().find(|o| o.0 == op).map(|o| o.1)
}

pub fn contract_json() -> Value {
    json!({
        "contract": "live-devenv@1",
        "ops": OPS.iter().map(|o| json!({"op": o.0, "cell": o.1, "needs": format!("{}:{}", o.1, o.2), "tool": o.3, "doc": o.4, "args": o.5})).collect::<Vec<_>>(),
        "views": VIEWS.iter().map(|v| json!({"view": v.0, "cell": v.1, "needs": v.2, "title": v.3})).collect::<Vec<_>>(),
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpTool {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

/// The agent tool list for a chain: only ops whose right the chain holds. There is no exec and no shell.
pub fn mcp_tools(holds: &dyn Fn(&str) -> bool) -> Vec<McpTool> {
    OPS.iter()
        .filter(|o| !o.3.is_empty())
        .filter(|o| holds(&format!("{}:{}", o.1, o.2)) || (o.1 == "ws.fs" && o.2 == "write" && holds("ws.fs:propose")))
        .map(|o| McpTool {
            name: o.3.into(),
            description: format!("{} Needs {}:{}.", o.4, o.1, o.2),
            input_schema: json!({"type": "object", "properties": o.5.iter().map(|a| (a.to_string(), json!({}))).collect::<serde_json::Map<_, _>>()}),
        })
        .collect()
}

/// An MCP tool call as a cell op.
pub fn mcp_to_op(name: &str, args: &Value) -> Option<Value> {
    let o = OPS.iter().find(|o| o.3 == name && !name.is_empty())?;
    let mut v = args.as_object().cloned().unwrap_or_default();
    v.insert("op".into(), json!(o.0));
    Some(Value::Object(v))
}

#[cfg(test)]
mod t {
    #[test]
    fn generated_contract_is_committed() {
        let want = serde_json::to_string_pretty(&super::contract_json()).unwrap() + "\n";
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../site/contract.json");
        if std::env::var("WS_BLESS").is_ok() {
            std::fs::write(path, &want).unwrap();
        }
        let have = std::fs::read_to_string(path).unwrap_or_default();
        assert_eq!(have, want, "site/contract.json differs from the contracts; run with WS_BLESS=1");
    }
}
