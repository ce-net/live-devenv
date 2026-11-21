# live-devenv

A development workspace shared by people and agents on several nodes. The files, builds, tests, tools, reviews,
the page and the record of who did what are cells with typed contracts. No op takes a command line. A run names
a registered tool plus typed arguments, runs in a box with no network and a read-only checkout, and leaves a signed,
hash-linked receipt, whether it was allowed or refused.

This is a live system on ce-net. The repository builds from a fresh clone with public dependencies only.

- Page: <https://ce-net.github.io/live-devenv/>. It has two modes. The recorded run shows the real three-node run
  step by step and checks every receipt in your browser. Sim mode runs the real cells as WebAssembly, three nodes
  inside the tab. You type as H1 and can cut a node off.
- Design: [docs/DESIGN.md](docs/DESIGN.md). Recorded runs: [proof/](proof/).

## Quickstart (fresh clone)

Needs Rust (stable). The box needs Linux with Landlock. Unprivileged user namespaces give the strongest class.

```sh
git clone https://github.com/ce-net/live-devenv && cd live-devenv
cargo test --workspace --release                       # unit, replica, sandbox; generated contract matches
cargo run --release -p ws-node -- proof --net sim --out out
cargo run --release -p ws-node -- verify out/sim.json  # offline check of every receipt
```

`proof --net sim` runs the 14 steps of DESIGN.md section 10 with three nodes in one process. The worker node runs
real boxed `rustc` builds and tests. `WS_MIN_CLASS=landlock+seccomp` lowers the workspace minimum on hosts that
refuse user namespaces, such as GitHub's runners.

Real nodes:

```sh
ws-node init --out tenant --nodes N1=http://10.0.0.1:7480,N2=http://10.0.0.2:7480,N3=http://10.0.0.3:7480
ws-node serve tenant/N1.json         # on each node, its own file; N3 is the worker
ws-node proof --net real --dir tenant --out proof
ws-node mcp --node http://10.0.0.2:7480 --identity tenant/id-A1.json   # an agent harness joins over MCP
```

`init` issues the node chains and the person chains from a fresh tenant root, then discards the root. Nothing can
mint a new chain from it afterwards. People delegate to agents themselves, and each hop can only narrow.

## What the proof shows

| # | Step | Must hold |
|---|---|---|
| 1 | H1, H2 and A1 edit three functions of one file within one second through N1, N2, N2 | one content hash on all replicas; no edit lost |
| 2 | H1 and H2 type in the same line at once | converges; both insertions present |
| 3 | Presence | each sees the other three; cursors stay on their characters after edits above them |
| 4 | A2 patches a file outside its write paths | lands in A2's change set; shared tree unchanged |
| 5 | A1 writes CI config with a self-signed widening link; A2 writes `ws.toml` | both refused; signed refusal receipts |
| 6 | Two renames of one file, one on a partitioned node; heal | one conflict everywhere; H1 resolves; one name |
| 7 | A1 builds and tests a snapshot, entering at N2 | placed on N3; receipts name N3 and the isolation class; one test fails |
| 8 | A1 puts the fix in a change set and tests it there | green, bound to the change set's snapshot |
| 9 | A1 approves its own change; H2 approves; merge | first refused; merge keeps a line H1 typed meanwhile |
| 10 | The same build again from N1 | `cache: hit`, no box started |
| 11 | A build asks for network; A2 uses a tool outside its grant | both refused |
| 12 | H1 revokes A2 | A2 refused on all three nodes within one round |
| 13 | Commit of the merged snapshot; pin | the commit names the snapshot ref; the pin is listed |
| 14 | Verify the exported log offline | every link and signature valid; a copy with one receipt changed fails |

## Layout

| Crate | What it holds | Stands in for, on the ce-net mesh |
|---|---|---|
| `ws-core::gate` | identities, capability chains with path and tool caveats, signed envelopes | `ce-gate`, cap v3, CAL |
| `ws-core::text` | the text CRDT (RGA, per-character ids, reads as of any version vector) | `yrs`/`yjs` in DESIGN 3.1 |
| `ws-core::fs` | `ws.fs` and `ws.snap`: signed updates, re-checked rights on every replica, conflicts, Merkle snapshots | `state.store@2`, `ce-ref`, `ref.pin` |
| `ws-core::audit` | `ws.audit`: per-node hash-linked, signed receipt chains, offline verify | `cr.audit` |
| `ws-core::node` | every cell's ops on one node, the gate on every op, anti-entropy | cells on `cell.install` |
| `ws-core::cells` | `ws.tools`, `ws.place`, `ws.run`, `ws.cache`, `ws.build`, `ws.test`, `ws.review`, `ws.presence`, `ws.vcs` records | `cell.build`, `artifact.index`, `net.find`, `grant.bundle` |
| `ws-core::contract` | the single op, right and view table; generates `site/contract.json` and the MCP tool list | `ce-wire`, `ce-wire-gen` |
| `ws-box` | namespaces, Landlock, seccomp, rlimits; measures its class | `agent.box` |
| `ws-node` | a node over HTTP, the gateway page, the proof driver, the MCP door, `verify` | `wire.ws-door`, `site.gateway` |
| `ws-wasm` | the cells in the browser for sim mode | `ui-cells` |

## Where this differs from DESIGN.md

- The text CRDT is a small RGA in `ws-core::text`, not `yrs`. The browser runs the same Rust as WebAssembly, so both
  sides use one implementation, and `Patch` maps old ranges through per-update version vectors.
- One `ws-core` crate holds every cell's logic instead of one crate pair per cell. The ops, rights and views are
  still declared once, in `contract.rs`.
- Receipts form one hash-linked chain per node, replicated to every node. A quorum-append log is not built.
- The sim page edits a plain text area that sends whole-file writes, which the cell turns into minimal patches.
  CodeMirror and `Sync` over a socket are not built.
- A2's grant is `write docs/**`, `propose crates/**`. The table in DESIGN section 10 gives propose on `docs/**`, which
  would make step 4 a refusal.
- `ws.lsp`, `ws.pkg`, `ws.vcs Push`, `ws-mount`, wrapped editors and the swap to the mesh cells (slices 5 to 8 in
  part) are not built yet. `ws.vcs` keeps commit objects that name snapshot refs. It does not write git objects.
- Box limits use rlimits plus a wall-clock kill, not cgroups.

Apache-2.0.
