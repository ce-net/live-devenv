# live-devenv: a development environment where every part is a cell (design, 2026-11-21)

One workspace, shared by people and agents on many devices at once. The files, the builds, the tests, the
tools, the reviews, the editor page and the record of who did what are all cells with typed contracts. Nothing
in it is a shell: every edit and every run is one typed op, checked against the caller's capability chain,
limited to granted paths, executed in a sandbox, and written to a hash-linked receipt log.

This is a live system on ce-net. The repository builds from a fresh clone with public dependencies only.

## 0. What is reused

The public repository carries a small runtime of its own (as `live-shop` does) so that a fresh clone needs
nothing private. Each piece of it has the shape of the ce-net cell that does the same job on the real mesh, and
the mapping is one table so the real deployment swaps pieces without changing a contract.

| Need | In this repository | On the ce-net mesh |
|---|---|---|
| Contract, server, client, TS types | `ws-wire` (`api!`, schema hash, TS generation) | `ce-wire`, `ce-wire-gen` |
| Right on every op | `ws-gate` (`needs "<cell>:<right>"`, caveats) | `ce-gate`, cap v3, CAL |
| Identities, grants, secrets | `ws.keys` | `keys`, `cap.mint`, `person.grant`, `grant.bundle` |
| Rows and change streams | `ws-store` (HLC, version vectors, `Watch`) | `state.store@2` |
| Typed references, pins | `ws-ref` (`ref:<cell>/<kind>/<hash>`) | `ce-ref`, `ref.pin` |
| Sandbox for every run | `ws-box` | `agent.box` |
| Run on the node that fits | `ws.place` | `net.find`, `node-run` |
| Build and artifacts by hash | `ws.build`, `ws.cache` | `cell.build`, `artifact.index`, sccache |
| Receipts | `ws.audit` | `cr.audit` |
| Views, manifest, page host | `ui/` halves, `ws.ui`, `ws.gateway` | `ui-cells`, `site.gateway`, `control-room` |
| Browser transport | one socket, grant in the URL fragment | `wire.ws-door` v2 |
| Deploy, verify, sim | `ws-net plan/apply/verify --net sim|real` | `cell.install`, `orch`, `deploy.ship`, `sim-mesh` |
| Wrapped existing programs | tool records (section 5) | `ce-wrap` |

Existing editors are onboarded, not rebuilt, where they fit the rules (section 7.3).

## 1. Rules

1. **Everything is a cell and a capability.** A feature is an op of a cell; using it needs a right. The page is
   made of `render:*` capabilities of the backend cells, composed by one aggregator cell and served by one
   http-serve cell. There is no application server and no backend-for-frontend.
2. **No shell.** There is no op that takes a command line. A run names a registered tool by reference and gives
   typed arguments; the tool record fixes the program, its argument schema and its sandbox profile.
3. **Paths are rights.** Every file op carries the caller's chain; the chain's path caveats decide. What a caller
   may not read is not sent, not listed and not searchable.
4. **Runs happen in a box.** No network, a read-only checkout of one snapshot, a private scratch directory, only
   the tools the run names. The isolation class is written into the receipt; a run is refused when the node
   cannot give the class the workspace policy asks for.
5. **Every op leaves a receipt**, allowed or refused, signed by the cell that decided, linked to the one before.
6. **People and agents are peers.** Each has its own key and its own narrow grant. Nobody acts with another
   identity's chain, and no session ever holds the tenant root.
7. **Secrets live in `ws.keys` only.** No file in the workspace tree, no receipt and no log line holds one; a
   box gets a secret only by a named, granted, single-run handle.
8. **Declared once.** Types, ops, rights, views and tool schemas are declared in Rust contracts; TS types, the
   page bindings and the tool list for agent harnesses are generated. A second declaration fails the build.
9. **A device is a window.** A laptop or phone runs the page and nothing else. Agents and builds run on Linux
   nodes of the mesh.

## 2. Cells

| Cell | Instances | What it decides | Rights |
|---|---|---|---|
| `ws.keys` | 1 | tenant root, identities, grants, secret handles | `identity`, `grant`, `revoke`, `secret.use` |
| `ws.fs` | 3 (one per node) | the tree and the content of every file, merged without loss | `read`, `write`, `propose`, `resolve`, `snapshot` |
| `ws.snap` | 3 | immutable snapshots by hash, pins | `read`, `pin` |
| `ws.presence` | 3 | who is here, where their cursor is | `see`, `announce` |
| `ws.review` | 1 (leader lease) | change sets, comments, approvals, merges | `open`, `comment`, `approve`, `merge` |
| `ws.tools` | 1 | the tool registry | `find`, `register`, `invoke` |
| `ws.place` | 1 | which node runs a job | `place` |
| `ws.run` | 3 | one boxed run of one tool | `start`, `stop`, `watch` |
| `ws.build` | 1 | build jobs: plan, cache, steps, result | `start`, `watch` |
| `ws.test` | 1 | test jobs: selection, results per case | `start`, `watch` |
| `ws.cache` | 3 | step results and compiler cache by hash | `get`, `put` |
| `ws.lsp` | per node, on use | language-server sessions as typed ops | `query` |
| `ws.search` | 3 | text and symbol search, filtered by path rights | `query` |
| `ws.vcs` | 1 | commits, history, push | `read`, `commit`, `push` |
| `ws.pkg` | 1 | fetch of locked packages by checksum | `fetch` |
| `ws.audit` | 3 (quorum append) | the receipt log | `read`, `verify` |
| `ws.ui` | 1 | the page layout per viewer (aggregator) | `render` |
| `ws.gateway` | 1 per edge node | the only listener: sessions to chains, page, socket | none (public door) |
| `ws.mcp` | 1 | the same ops as tools for agent harnesses | the caller's own |

Each cell has `crates/<cell>-api` (contract), `crates/<cell>` (program, `cell.toml`), and `ui/` when it
shows something. Cells call each other only through contracts and never link each other's code.

## 3. The shared file system: `ws.fs` and `ws.snap`

### 3.1 Model

- A workspace is a tree of entries. Each entry has a stable `FileId`; the path is a property of the entry, so a
  rename does not lose concurrent edits.
- **Text files** are one sequence CRDT document per file (`yrs`, the Rust implementation of Yjs, MIT; the
  browser uses `yjs` with the same update format). Concurrent edits from any number of devices and nodes
  converge without a lock and without a leader.
- **Binary files** are a register with a version vector. Concurrent writes are both kept; the read answers
  the HLC winner flagged `conflicted` until someone with `resolve` picks.
- **The tree** (create, rename, delete) is a map CRDT keyed by `FileId`. Rules: an edit beats a concurrent
  delete (the file returns, flagged); two concurrent renames of one file keep the HLC winner and record the
  other as a conflict; two creates of one path become `name` and `name~<actor>` and a conflict.
- Nothing is dropped silently: every unsettled pair is a row in `ws.fs conflicts` with both sides.

### 3.2 Contract (`ws.fs@1`)

```
List     { dir, depth }                       -> entries the chain may read              needs ws.fs:read
Open     { path }                             -> { file, version, kind, state }          needs ws.fs:read
Read     { file, at: Option<Version>, range } -> bytes or text                           needs ws.fs:read
Write    { path, content, base: Option<Version> } -> { version, receipt }                needs ws.fs:write
Patch    { file, base: Version, edits: [ { range, text } ] } -> { version, receipt }     needs ws.fs:write
Sync     { file, update, have: StateVector }  -> { missing_update, version }             needs ws.fs:write
Move     { file, to }   Delete { file }       -> { receipt }                             needs ws.fs:write
Watch    { prefix, since }                    -> stream of Change { file, version, actor, kind, delta }
Conflicts{ prefix }                           -> [ Conflict ]                            needs ws.fs:read
Resolve  { conflict, pick | merged }          -> { receipt }                             needs ws.fs:resolve
Snapshot { prefix, label }                    -> SnapRef                                 needs ws.fs:snapshot
```

- `Patch` is the op for agents and scripts. It takes plain range edits against a version the caller has read.
  The cell maps the ranges through the CRDT from `base` to the present, so a patch written against an older
  version still lands in the right place while others type. No CRDT library is needed on the caller's side.
- `Sync` is the op for editors: opaque CRDT updates plus a state vector, used by the page for keystrokes.
- `Write` replaces a whole file; with `base` it is compare-and-set and answers `Stale` instead of overwriting.
- `propose` instead of `write`: the same three ops are accepted but land in the caller's change set
  (section 6.2), not in the shared tree. The caller does not choose; its grant does.
- Path check: every op resolves the target path (after `Move`, both paths) against the chain's caveats, for
  example `path in ["crates/parser/**"]`, `path not in [".git/**", "**/.env*"]`. A refusal is an answer of type
  `Refused { need, have, receipt }` and a signed receipt; nothing about the hidden path leaks beyond its name
  as the caller wrote it.
- Limits are part of the contract: file size, update size, ops per second per identity. Over the limit is
  `Refused`, not a slow node.

### 3.3 Replication

One `ws.fs` per node holds a full replica. Replicas exchange CRDT updates and tree ops over `ws.fs.peer@1`
(`Have { vector }`, `Pull`, `Push`), eagerly on change and by anti-entropy every few seconds. A node that was
away catches up by state vector. Writes are accepted on any replica; rights are checked on the replica that
accepts and checked again on every replica that applies (the update carries the actor's chain id and
signature, so one bad replica cannot inject edits as someone else).

### 3.4 Snapshots as references

`Snapshot` freezes a prefix into a Merkle tree of blobs (BLAKE3) and answers
`ref:ws.snap/tree/<hash>`. A snapshot is immutable, content-addressed and the only input a build, a test, a
review or a commit ever names. `ws.snap Pin { ref, label, until }` keeps it from collection; unpinned
snapshots are collected after a declared age. Blobs are shared between snapshots and replicated on demand
(`ws.snap.peer Get { hash }`), so a job on another node pulls only what it lacks.

## 4. Build and test as cells

### 4.1 One run: `ws.run@1`

```
Start { tool: ToolRef, args: <typed by the tool record>, input: SnapRef, paths: [glob],
        cache: [CacheVolume], limits: { cpu, memory, secs, output_bytes }, secret_handles: [] }
      -> RunId                                                   needs ws.run:start + ws.tools:invoke(tool)
Watch { run } -> stream of Event { stdout | stderr | status }    needs ws.run:watch
Stop  { run }                                                    needs ws.run:stop
```

`ws.run` checks out `input` read-only (only `paths`, only what the chain may read), mounts the tool by its
artifact hash, and starts it in `ws-box`: new user, mount, pid and network namespaces, no network device,
Landlock on everything but the checkout (read) and scratch (write), a seccomp filter, cgroup limits.
Isolation classes are `ns+landlock+seccomp`, `landlock+seccomp` and `none`; the workspace policy names the
minimum (default: the first) and `none` exists only so the refusal can be shown. On the mesh the same op is
answered by `agent.box`.

Outputs are collected from scratch into a new snapshot. The answer is a **run receipt**:

```
RunReceipt { run, actor, chain, tool: ToolRef, args_hash, input: SnapRef, output: SnapRef,
             exit, isolation, node, started, ended, cache: hit|miss, log: BlobRef, prev, sig(node key) }
```

### 4.2 `ws.build@1` and `ws.test@1`

- `ws.build Start { input: SnapRef, target, profile }` reads the workspace's build declaration
  (`ws.toml`: steps, each a tool capability such as `compile:rust` plus typed arguments), resolves each step
  to a tool through `ws.tools`, asks `ws.place` for a node and calls `ws.run` there. One job is a small graph
  of runs; its result is a `BuildReceipt` naming every run receipt and the artifact references.
- `ws.test Start { input, select }` does the same for tests and parses the tool's machine-readable output
  into `Case { name, status, secs, message }` rows, so the page and an agent get typed results, not a log.
- Both are **keyed by snapshot**: the same snapshot, tool and arguments is the same job. A second caller
  joins the running job or gets the stored receipt.
- Both can be asked for a change set (`input` is the change set's snapshot), which is how a proposed change
  is built and tested before anyone approves it.

### 4.3 Placement: `ws.place@1`

Each node's `ws.run` announces `{ tools present, cores, memory free, cache keys held, isolation class,
running jobs }`. `Place { tool, limits, cache_keys }` answers the node that has the tool, meets the class,
has room, and holds the most cache; ties go to the least loaded. A workspace policy can pin job kinds to
nodes and cap concurrent jobs per node (the default is one heavy job per node). The caller's device is never
a candidate.

### 4.4 Cache: `ws.cache@1`

- **Step cache.** Key = hash(tool artifact, argument hash, input subtree hash, declared environment). A hit
  answers the stored output snapshot and receipt with `cache: hit`; no box starts.
- **Compiler cache.** A tool record may declare cache volumes (for Rust: an sccache directory and the
  registry of fetched crates). Volumes are content-addressed stores mounted into the box; `ws.cache.peer`
  moves entries between nodes on demand, so a build on one node warms the next build on another.
- Cache entries are written only by `ws.run` after a run whose inputs were all pinned by hash. A caller
  cannot put an entry under a key of its choosing.

## 5. One tool registry: `ws.tools@1`

A tool is a record, not a path:

```
Tool { name, version, artifact: ref:ws.tools/bin/<hash>, provides: [Capability],
       args: Schema, outputs: Schema, box: { network: none | pkg, cache: [..], limits },
       nodes: [..], wraps: Option<upstream name and license> }
```

`provides` uses one vocabulary: `compile:<lang>`, `test:<lang>`, `format:<lang>`, `lint:<lang>`,
`lsp:<lang>`, `search:text`, `search:symbol`, `vcs:commit`, `pkg:fetch:<registry>`.

```
Find     { capability, lang, node }  -> [Tool the chain may invoke]     needs ws.tools:find
Describe { tool }                    -> Tool                            needs ws.tools:find
Register { tool }                    -> ToolRef                         needs ws.tools:register
```

- Registration is an owner-approved act: the record names an artifact by hash, and the registry verifies the
  hash before the tool can run anywhere. `rustc`, `cargo`, `clippy`, `rustfmt`, `rust-analyzer`, `tsc`,
  `prettier`, `ripgrep` and `git` ship as records in `tools/`; adding one is a file and a `Register`.
- A grant can narrow by tool: `ws.tools:invoke` with `tool in ["rustfmt", "cargo-test"]`.
- **Language servers** (`ws.lsp@1`): a long-lived boxed run per (snapshot stream, language), fed by `ws.fs
  Watch`. Callers use typed ops (`Diagnostics`, `Hover`, `Complete`, `Definition`, `References`, `Rename`
  which answers a `Patch`, never writes). The raw protocol does not leave the cell.
- **Search** (`ws.search@1`): `Text { query, glob }`, `Symbol { name }` over the live tree or a snapshot; hits
  outside the chain's paths are not produced.
- **Version control** (`ws.vcs@1`): `Status`, `Diff { a, b }`, `Log`, `Commit { snapshot, message }`
  (the author is the caller's identity, mapped by `ws.keys`), `Push { remote }`. `Push` needs its own right
  and, by default policy, a merged review. The remote's credential is a secret handle; the box that pushes
  gets egress to that one host and nothing else.
- **Packages** (`ws.pkg@1`): `Fetch { registry, name, version, checksum }` only for entries present in a
  lock file of the snapshot, verified by checksum, stored by hash. Build boxes never have a network; they
  mount what `ws.pkg` fetched.

## 6. People and agents as peers

### 6.1 Identity and grants

- Every person device and every agent has its own key. `ws.keys Identity` registers it; a grant is a cap
  chain from the tenant root, narrowed at each hop, with an expiry.
- A person signs in on the gateway; the session becomes a chain for that person, narrowed to the workspace,
  at most 8 hours. The tenant root signs only inside `ws.keys`; no session, page or agent ever holds it.
- A person delegates to an agent by a **grant bundle**: `{ identity, grants[], expiry, issued_by }`, each
  grant a right plus caveats, for example
  `ws.fs:write path in ["crates/parser/**"]`, `ws.fs:propose path in ["**"]`, `ws.fs:read`,
  `ws.build:start`, `ws.test:start`, `ws.tools:invoke tool in [..]`. Delegation can only narrow.
- `ws.keys Revoke` ends a chain everywhere within one anti-entropy round; open sockets and streams of that
  chain close, and its panels leave the page.

### 6.2 Review: `ws.review@1`

- A caller holding `propose` writes into a **change set**: an overlay on a base snapshot, with its own CRDT
  documents, visible in the page beside the shared tree.
- `Open { title, base }`, `Diff { change }`, `Comment`, `Build`/`Test` (section 4.2 on the overlay),
  `Approve { change, snapshot }`, `Reject`, `Merge { change }`.
- `Approve` is signed by the approver's device key over the exact snapshot hash. The proposer's own approval
  does not count. Policy per path: how many approvals, from whom (`person` by default), whether a green test
  receipt for that snapshot is required. A later edit to the change set voids earlier approvals.
- `Merge` replays the change set's edits onto the shared documents as CRDT ops, so work typed meanwhile is
  kept; if the merge raises tree conflicts they go to `ws.fs conflicts` like any other.

### 6.3 Presence: `ws.presence@1`

`Announce { file, cursor, selection }` and `Watch { prefix }`. State is per identity and device, kept in
memory with a short time to live, gossiped between nodes, never written to the receipt log (joins and leaves
are). Cursors are CRDT-relative positions, so they stay on the right character while others type. A viewer
sees presence only for paths it may read.

## 7. The page

### 7.1 Views

Each backend cell exposes its own views as capabilities and serves its own data to them:

| Capability | Cell | Shows |
|---|---|---|
| `render:tree`, `render:editor`, `render:conflicts` | `ws.fs` | files, the text editor (CodeMirror 6 bound to `Sync`), unsettled pairs |
| `render:people` | `ws.presence` | who is here; cursors are drawn inside the editor through a typed slot |
| `render:changes` | `ws.review` | change sets, diffs, approvals |
| `render:runs`, `render:tests` | `ws.build`, `ws.test` | jobs, nodes, live output, cases |
| `render:tools` | `ws.tools` | the registry |
| `render:search` | `ws.search` | hits |
| `render:history` | `ws.vcs` | commits |
| `render:receipts` | `ws.audit` | the log, with a verify button |
| `render:grants` | `ws.keys` | identities and what each may do |

### 7.2 Composition

`ws.ui` (aggregator) answers `Layout { chain }`: the views this viewer's chain may render, their slots and
order. `ws.gateway` (http-serve) is the one listener: it serves the host page, the bundles by hash, and one
socket through which every view calls its own cell with the viewer's chain. **Tabs are emergent**: a tab
exists because the viewer holds the `render:*` right and the cell answers; the page has no list of tabs. A
viewer without `ws.review:*` receives neither the tab, the bundle nor the name. When a grant ends, its panel
leaves.

### 7.3 Existing editors, wrapped

The built-in editor is the default because it is made of views. Existing editors join as optional cells
on Linux nodes and are reached from a device only through the browser:

- **code-server** (MIT) as `ws.editor.code-server`: runs in a box, sees the workspace only through
  `ws-mount`, a mount that speaks `ws.fs` with the viewer's chain (so path rights and receipts hold), with
  task running mapped to `ws.build` and `ws.test`. Its integrated terminal is inside the same box: no network,
  no files but the mount.
- **T3 Code** (MIT) and **opencode** as agent workbenches: each agent session they start is a box with its
  own identity and grant bundle, joined through `ws.mcp` (section 8). They get no path into the workspace
  other than the typed ops.

These are later slices (section 11); they add cells and tool records and change no contract.

## 8. The cell API for agents

- The contracts are the API. `ws-wire` generates Rust and TypeScript clients, a JSON description of every op
  and, from the same source, **MCP tools**.
- `ws.mcp` serves them over stdio and over streamable HTTP behind the gateway. A session is bound at start to
  one identity's chain; every tool call is the cell op with that chain, so the gate, path rights, the box and
  the receipts apply unchanged. The tool list a harness sees is filtered by the chain.
- Tool set (names stable, arguments typed): `fs_list`, `fs_open`, `fs_read`, `fs_patch`, `fs_write`,
  `fs_move`, `fs_delete`, `fs_watch`, `search_text`, `search_symbol`, `lsp_diagnostics`, `lsp_definition`,
  `lsp_references`, `tools_find`, `tools_describe`, `build_start`, `build_watch`, `test_start`,
  `test_watch`, `review_open`, `review_diff`, `review_comment`, `vcs_status`, `vcs_diff`, `vcs_commit`,
  `presence_announce`, `audit_read`, `whoami` (identity, rights, paths: an agent can ask what it may do).
- There is no `exec`, no `shell`, no `eval`. A harness that needs a new program asks for a tool record.
- Refusals are typed (`Refused { need, have }`), so a harness can ask for the right through
  `ws.keys Request { need, why }`, which a person approves or declines in the page.

## 9. Receipts: `ws.audit@1`

```
Receipt { seq, prev: Hash, time: Hlc, node, cell, op, actor, chain, target, args_hash,
          outcome: Ok { result_hash } | Refused { need }, sig(cell key) }
```

- Appended by the cell that decided, to a 3-replica log with quorum append; `prev` links each to the one
  before, so removing or changing one breaks every later hash.
- Keystroke-level `Sync` ops are batched: one receipt per (actor, file, short window) with the hash of the
  merged update, so the log stays readable and still covers every byte.
- `Read { since, filter }`, `Head`, `Verify { from, to }`. `ws-audit verify <file>` checks a whole exported
  log offline: links, signatures against the published cell keys, and that every run receipt's input and
  output snapshots exist.
- No secret, file content or token appears in a receipt: hashes and references only.

## 10. The proof

`ws-net apply --net real` on three Linux nodes (N1 edge and replicas, N2 edge and replicas, N3 worker), then
`ws-proof run` drives four identities against a small Rust workspace and records everything.

| Identity | Kind | Enters at | Grant |
|---|---|---|---|
| H1 | person, device A | N1 | read, write `**`, approve, resolve |
| H2 | person, device B | N2 | read, write `**`, approve |
| A1 | agent, boxed on N2 | `ws.mcp` | read; write `crates/parser/**`; propose `**`; build, test |
| A2 | agent, boxed on N3 | `ws.mcp` | read; propose `docs/**` |

| # | Step | Must hold |
|---|---|---|
| 1 | All four open `crates/parser/src/lib.rs`; H1, H2 and A1 edit different functions within the same second through N1, N2, N2 | all three replicas reach one content hash; no edit lost |
| 2 | H1 and H2 type in the **same line** at once | converges on every replica; both insertions present |
| 3 | Presence | each sees the other three, with cursors on the right characters after step 2 |
| 4 | A2 `fs_patch` on `crates/parser/src/lib.rs` (outside `docs/**`) | lands in A2's change set, shared tree unchanged |
| 5 | A1 `fs_write` on `.github/workflows/ci.yml` with a forged `write` claim, and A2 `fs_write` on `ws.toml` | both `Refused`, tree unchanged, two signed refusal receipts |
| 6 | H1 renames `util.rs` to `text.rs` while H2 renames it to `strings.rs` on a partitioned N2; heal | one tree conflict on all replicas; H1 `Resolve`; one name everywhere; receipt |
| 7 | A1 `build_start` then `test_start` on a snapshot, entering at N2 | job placed on **N3**; run receipts name N3 and the isolation class; test cases typed; one test fails |
| 8 | A1 patches the fix into a change set; `ws.test` on the change set | green; receipt bound to the change set's snapshot |
| 9 | A1 tries `review_approve` on its own change; H2 approves; merge | first `Refused`; second accepted with H2's device signature; merge keeps a line H1 typed meanwhile |
| 10 | Same build again from N1 | `cache: hit`, no box started |
| 11 | A run asks for network; a tool not in A2's grant | both `Refused` |
| 12 | H1 revokes A2 | A2's next call `Refused` on all three nodes within one round |
| 13 | `ws.vcs Commit` of the merged snapshot by H1; snapshot pinned | commit names the snapshot ref; pin listed |
| 14 | `ws-audit verify` on the exported log | every link and signature valid; a copy with one receipt altered fails |

The recorded run (`docs/runs/<date>/`: receipts, snapshots' hashes, the node list, timings) is committed and
replayed by the public page. `--net sim` runs the same script with three simulated nodes on one machine and is
what CI runs on every push, including the partition in step 6 and seeded fault runs (a replica killed
mid-edit, a worker killed mid-build: the job is placed again and the receipt says so).

**The public page** (GitHub Pages) has two modes. *Sim*: the real `ws.fs`, `ws.presence`, `ws.review`,
`ws.audit` and gate logic compiled to WebAssembly, three nodes and four identities inside the tab, the visitor
types as H1 and can cut a node off; builds and tests in this mode replay stored receipts and say so. *Recorded
run*: the real three-node run, step by step, with every receipt verifiable in the browser.

## 11. Repository and slices

```
crates/ws-wire ws-gate ws-store ws-ref ws-box            shared runtime (public)
crates/<cell>-api, crates/<cell>                         one pair per cell in section 2
crates/ws-net ws-proof ws-audit-verify xtask             deploy, proof, offline verify, drift checks
tools/*.toml                                             tool records
ui/                                                      view halves, host, generated bindings
site/                                                    the public page (sim + recorded run)
docs/DESIGN.md docs/runs/
```

Apache-2.0. CI: build, tests, `xtask check` (generated clients match contracts, `tsc` clean), `ws-net apply
--net sim` plus `ws-proof run --net sim`, and the page build.

| Slice | Contents | Done when |
|---|---|---|
| 1 | runtime crates; `ws.keys`, `ws.audit`, `ws.fs` (text CRDT, tree, rights, `Patch`/`Sync`/`Watch`, replication), `ws.snap`; `ws-net --net sim` | proof steps 1, 2, 5, 6, 14 pass in sim in CI |
| 2 | `ws-box`, `ws.tools`, `ws.run`, `ws.place`, `ws.cache`, `ws.build`, `ws.test`, `ws.pkg` | steps 7, 10, 11 |
| 3 | `ws.presence`, `ws.review`, revoke | steps 3, 4, 8, 9, 12 |
| 4 | `ws.ui`, `ws.gateway`, views, generated TS; the page in sim mode | page drives steps 1 to 6 in the browser |
| 5 | `ws.mcp`, `ws.search`, `ws.lsp`, `ws.vcs` | step 13; a harness joins over MCP with only its bundle |
| 6 | real three-node run, recorded; page shows it; listed in the ce-net live systems index | steps 1 to 14 on three nodes |
| 7 | mesh swap: `agent.box`, `cell.build`, `state.store`, `cr.audit`, `wire.ws-door`, `ui-cells` behind the same contracts | same proof on the mesh cells |
| 8 | wrapped editors: `ws-mount`, code-server, then agent workbenches | a wrapped editor edits beside the built-in one under the same rights |

## 12. Open points

1. Unprivileged user namespaces are restricted on some hosts and CI runners. The class falls to
   `landlock+seccomp` there; whether CI may run step 7 at that class or must use a self-hosted runner is to be
   settled in slice 2.
2. CRDT history grows. Compaction at pinned snapshots (keep state, drop tombstones older than the oldest
   live state vector) needs a rule for replicas that were away longer than that.
3. `Patch` against a very old `base` is well-defined but may surprise; a maximum age and a `Stale` answer are
   likely right.
4. Language servers assume a real directory. `ws.lsp` feeds a checkout kept current from `Watch`; the cost
   for large trees is not measured.
5. Receipts for batched `Sync` trade detail for volume; the window (default 2 s) is a guess.
6. A wrapped editor's extensions can run arbitrary code inside its box. The box bounds the damage to the
   mount and the viewer's own rights; whether extensions are allowed at all is a workspace policy.
