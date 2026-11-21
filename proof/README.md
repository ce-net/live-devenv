# Recorded runs

| File | What |
|---|---|
| `real-2026-11-21.json` | The 14 steps on three real Linux nodes over the mesh, 2026-11-21. N1 and N2 (x86_64) are edges with replicas; N3 (aarch64) is the worker and the only node with a compile tool. 14 of 14 hold. |
| `sim-2026-11-21.json` | The same script on the in-process mesh, with real boxed builds on the worker. |
| `sim-runs.json` | The worker's runs from the sim run (tool, source files hash, exit, output), which the page's sim mode replays. |
| `index.json` | Which run the page shows. |

Numbers from the real run:

- 14 of 14 steps hold. 70 receipts in 3 node chains, 8 of them refusals. `ws-node verify real-2026-11-21.json`
  reports every link and signature valid. Changing one refusal into a success breaks the chain.
- Step 7: the build and the test were placed on N3 at isolation class `ns+landlock+seccomp`. The test cases were
  typed: pass, fail, pass.
- Step 10: the same build from N1 answered `cache: hit`, and the worker started no box (4 boxes over the whole run).
- Step 12: after one anti-entropy round, A2 was refused on all three nodes.
- Wall time per step: 0.3 to 7.3 s. Steps that wait for anti-entropy rounds take longest. Each round is a full
  exchange between every pair of nodes over the mesh.

Every receipt names its node key, the cell that decided, the actor, the chain id and the outcome. To check a file:

```sh
cargo run --release -p ws-node -- verify proof/real-2026-11-21.json
```
