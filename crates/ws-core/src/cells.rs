//! Records of the smaller cells: `ws.tools`, `ws.place`, `ws.run`, `ws.cache`, `ws.build`, `ws.test`,
//! `ws.review`, `ws.presence`, `ws.vcs`.

use crate::fs::Manifest;
use crate::text::{Id, Vv};
use crate::Hlc;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A tool is a record, not a path.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Tool {
    pub name: String,
    pub version: String,
    /// `ref:ws.tools/bin/<hash>` of the program, or `input:<arg>` when the program is an artifact of the input.
    pub artifact: String,
    pub provides: Vec<String>,
    pub args: Vec<String>,
    pub network: bool,
    pub secs: u64,
    pub memory_mb: u64,
    #[serde(default)]
    pub wraps: String,
}

pub const CLASSES: &[&str] = &["none", "landlock+seccomp", "ns+landlock+seccomp"];

pub fn class_rank(c: &str) -> usize {
    CLASSES.iter().position(|x| *x == c).unwrap_or(0)
}

/// What a node's `ws.run` announces to `ws.place`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NodeInfo {
    pub name: String,
    pub key: String,
    pub tools: BTreeMap<String, String>,
    pub isolation: String,
    pub cores: u32,
    pub running: u32,
    pub cache_keys: Vec<String>,
    pub snaps: Vec<String>,
    pub device: bool,
}

/// `ws.place`: the node that has the tool, meets the class, is not a device, holds the most cache; ties to the
/// least loaded, then the most cores.
pub fn place(infos: &[(usize, NodeInfo)], tool: &Tool, min_class: &str, key: &str, input: &str) -> Option<usize> {
    infos
        .iter()
        .filter(|(_, i)| !i.device && class_rank(&i.isolation) >= class_rank(min_class))
        .filter(|(_, i)| tool.artifact.starts_with("input:") || i.tools.get(&tool.name).map(|a| *a == tool.artifact).unwrap_or(false))
        .max_by_key(|(n, i)| {
            let warm = i.cache_keys.iter().any(|k| k == key) as u32 * 2 + i.snaps.iter().any(|s| s == input) as u32;
            (warm, u32::MAX - i.running, i.cores, u32::MAX - *n as u32)
        })
        .map(|x| x.0)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunReq {
    pub tool: Tool,
    pub args: serde_json::Value,
    pub input: String,
    pub manifest: Manifest,
    pub blobs: BTreeMap<String, String>,
    pub network: bool,
    pub actor: String,
    pub min_class: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RunOut {
    pub exit: i32,
    pub stdout: String,
    pub stderr: String,
    pub outputs: Vec<(String, Vec<u8>)>,
    pub isolation: String,
    pub replayed: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RunReceipt {
    pub run: String,
    pub actor: String,
    pub tool: String,
    pub tool_artifact: String,
    pub args_hash: String,
    pub input: String,
    pub output: String,
    pub exit: i32,
    pub isolation: String,
    pub node: String,
    pub cache: String,
    pub log: String,
    pub replayed: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Case {
    pub name: String,
    pub status: String,
    pub message: String,
}

/// Parse libtest's plain output into typed cases.
pub fn parse_cases(stdout: &str) -> Vec<Case> {
    let mut cases: Vec<Case> = stdout
        .lines()
        .filter_map(|l| {
            let rest = l.strip_prefix("test ")?;
            let (name, st) = rest.rsplit_once(" ... ")?;
            let status = match st.trim() {
                "ok" => "pass",
                "FAILED" => "fail",
                "ignored" => "skip",
                _ => return None,
            };
            Some(Case { name: name.into(), status: status.into(), message: String::new() })
        })
        .collect();
    for c in cases.iter_mut().filter(|c| c.status == "fail") {
        let marker = format!("---- {} stdout ----", c.name);
        if let Some(i) = stdout.find(&marker) {
            c.message = stdout[i + marker.len()..].lines().map(str::trim).filter(|l| !l.is_empty()).take(3).collect::<Vec<_>>().join(" ");
        }
    }
    cases
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CsFile {
    pub file: String,
    pub base_vv: Vv,
    pub base_text: String,
    pub text: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Approval {
    pub by: String,
    pub snapshot: String,
    pub env_hash: String,
    pub sig: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChangeSet {
    pub id: String,
    pub title: String,
    pub owner: String,
    pub base: String,
    pub files: BTreeMap<String, CsFile>,
    pub approvals: Vec<Approval>,
    pub comments: Vec<(String, String)>,
    pub green: Vec<String>,
    pub merged: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Presence {
    pub actor: String,
    pub name: String,
    pub path: String,
    pub file: String,
    pub anchor: Option<Id>,
    pub at: Hlc,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Commit {
    pub id: String,
    pub parent: String,
    pub snapshot: String,
    pub message: String,
    pub author: String,
    pub time: Hlc,
}

#[cfg(test)]
mod t {
    use super::*;
    #[test]
    fn cases_parse() {
        let out = "running 2 tests\ntest t::a ... ok\ntest t::b ... FAILED\n\nfailures:\n\n---- t::b stdout ----\nassertion failed: x\n\n";
        let c = parse_cases(out);
        assert_eq!(c.len(), 2);
        assert_eq!(c[1].status, "fail");
        assert!(c[1].message.contains("assertion"));
    }
}
