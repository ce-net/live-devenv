// The page: a recorded real run, and a sim mode that runs the real cells as WebAssembly in this tab.
import init, { Sim, verify } from "./pkg/ws_wasm.js";

const $ = (s) => document.querySelector(s);
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const LIB = "crates/parser/src/lib.rs";

function stepsTable(tbody, steps) {
  tbody.innerHTML = steps.map((s) => `<tr><td class="num">${s.n}</td><td>${esc(s.title)}<details><summary>detail</summary><pre>${esc(JSON.stringify(s.detail, null, 1))}</pre></details></td><td>${esc(s.must)}</td><td class="${s.holds ? "ok" : "bad"}">${s.holds ? "holds" : "fails"}</td><td class="num">${s.ms}</td></tr>`).join("");
}

// ---- mode switch
for (const b of document.querySelectorAll(".modes button")) {
  b.onclick = () => {
    for (const x of document.querySelectorAll(".modes button")) x.setAttribute("aria-selected", x === b);
    for (const m of document.querySelectorAll(".mode")) m.hidden = m.id !== b.dataset.mode;
    if (b.dataset.mode === "sim") startSim();
    try { localStorage.setItem("devenv-mode", b.dataset.mode); } catch (e) {}
  };
}

let ready = init();
let recorded = null;

// ---- recorded run
(async () => {
  try {
    const idx = await (await fetch("proof/index.json")).json();
    recorded = await (await fetch("proof/" + idx.latest)).json();
    $("#rec-json").href = "proof/" + idx.latest;
    const nodes = recorded.nodes.map((n, i) => `N${i + 1} ${n.name}: ${n.isolation}${n.boxes_started ? `, ${n.boxes_started} boxes` : ""}`);
    $("#rec-meta").textContent = `${idx.when}. ${recorded.passed} of ${recorded.total} steps hold. ${recorded.receipts.length} receipts from ${recorded.verify?.chains ?? "?"} nodes.`;
    $("#rec-nodes").innerHTML = nodes.map((n) => `<span class="pill">${esc(n)}</span>`).join("") + (idx.hosts || []).map((h) => `<span class="pill">${esc(h)}</span>`).join("");
    stepsTable($("#rec-steps"), recorded.steps);
  } catch (e) {
    $("#rec-meta").textContent = "No recorded run is published yet.";
  }
})();

$("#rec-verify").onclick = async () => {
  if (!recorded) return;
  await ready;
  const v = JSON.parse(verify(JSON.stringify(recorded)));
  const tampered = structuredClone(recorded);
  const r = tampered.receipts.find((x) => x.outcome.kind === "Refused");
  if (r) r.outcome = { kind: "Ok", result: "0".repeat(64) };
  const t = JSON.parse(verify(JSON.stringify(tampered)));
  const el = $("#rec-verdict");
  el.hidden = false;
  el.className = "verdict " + (v.ok && !t.ok ? "ok" : "bad");
  el.textContent = `${v.receipts} receipts in ${v.chains} node chains: ${v.ok ? "every link and signature is valid" : "INVALID: " + v.errors.join("; ")}. A copy with one refusal turned into a success: ${t.ok ? "passes (wrong)" : "fails, as it must (" + t.errors[0] + ")"}.`;
};

// ---- sim
let sim = null, replay = "[]", viewer = "H1", timer = null;

async function startSim() {
  if (sim) return;
  await ready;
  try { replay = await (await fetch("sim-runs.json")).text(); } catch (e) {}
  sim = new Sim(replay);
  render(true);
  timer = setInterval(() => { if ($("#auto").checked) { sim.tick(); render(false); } }, 800);
}

function render(full) {
  const st = JSON.parse(sim.state(LIB));
  const host = $("#sim-nodes");
  if (full || host.children.length !== 3) {
    host.innerHTML = st.map((n, i) => `<div class="node" data-i="${i}"><header><b>${n.name}</b><button class="btn ghost cutb">Cut off</button></header><div class="meta"></div><textarea spellcheck="false" aria-label="${LIB} on ${n.name}, typing as H1"></textarea><div class="conf"></div></div>`).join("");
    for (const el of host.children) {
      const i = +el.dataset.i;
      el.querySelector(".cutb").onclick = () => { const c = !el.classList.contains("cut"); sim.cut(i, c); render(false); };
      const ta = el.querySelector("textarea");
      ta.oninput = () => { sim.edit("H1", i, LIB, ta.value); render(false); };
    }
  }
  st.forEach((n, i) => {
    const el = host.children[i];
    el.classList.toggle("cut", n.cut);
    el.querySelector(".cutb").textContent = n.cut ? "Reconnect" : "Cut off";
    el.querySelector(".meta").innerHTML = `<span>tree ${n.content_hash}</span><span>${n.files.length} files</span><span>${n.receipts} receipts</span>`;
    const ta = el.querySelector("textarea");
    if (document.activeElement !== ta && ta.value !== n.text) ta.value = n.text;
    el.querySelector(".conf").textContent = n.conflicts.map((c) => `${c.kind} conflict: ${c.sides.join(" / ")}`).join("\n");
  });
  layout();
  const rs = JSON.parse(sim.receipts(0)).slice(-40).reverse();
  $("#receipts").innerHTML = rs.map((r) => `<li class="${r.outcome.kind === "Refused" ? "r" : ""}"><span>#${r.seq}</span><span>${esc(r.actor)} ${esc(r.cell)} ${esc(r.op)} ${esc(r.target)}${r.outcome.kind === "Refused" ? " refused: " + esc(r.outcome.need) : ""}</span></li>`).join("");
}

function layout() {
  const a = JSON.parse(sim.call(viewer, 0, JSON.stringify({ op: "UiLayout" })));
  $("#layout").innerHTML = a.ok ? a.ok.map((v) => `<li title="${esc(v.view)} from ${esc(v.cell)}">${esc(v.title)}</li>`).join("") : `<li>${esc(JSON.stringify(a))}</li>`;
}

for (const b of document.querySelectorAll(".viewas [data-who]")) {
  b.onclick = () => { viewer = b.dataset.who; for (const x of document.querySelectorAll(".viewas [data-who]")) x.classList.toggle("on", x === b); layout(); };
}
$("#sync").onclick = () => { sim.tick(); render(false); };
$("#try-ci").onclick = () => { $("#try-out").textContent = JSON.stringify(JSON.parse(sim.call("A1", 1, JSON.stringify({ op: "FsWrite", path: ".github/workflows/ci.yml", content: "x\n" }))), null, 1); render(false); };
$("#try-toml").onclick = () => { $("#try-out").textContent = JSON.stringify(JSON.parse(sim.call("A2", 2, JSON.stringify({ op: "FsWrite", path: "ws.toml", content: "x\n" }))), null, 1); render(false); };
$("#run14").onclick = async () => {
  await ready;
  $("#run14").textContent = "Running";
  setTimeout(() => {
    const r = JSON.parse(Sim.run_proof(replay));
    $("#sim-steps-t").hidden = false;
    stepsTable($("#sim-steps"), r.steps);
    $("#run14").textContent = `${r.passed} of ${r.total} hold. Run again`;
  }, 30);
};

// #sim opens sim mode; #sim-run also runs the 14 steps
let wantSim = location.hash.startsWith("#sim");
try { wantSim ||= localStorage.getItem("devenv-mode") === "sim"; } catch (e) {}
if (wantSim) document.querySelector('[data-mode="sim"]').click();
if (location.hash === "#sim-run") $("#run14").click();
