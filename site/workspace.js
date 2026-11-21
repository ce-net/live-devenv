// The signed-in workspace page. Tabs come from ws.ui Layout: only views whose right this chain holds.
import init, { public_key, sign } from "./pkg/ws_wasm.js";
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
let secret, chain, n = 0, file = null, base = null;

function newSecret() { const b = new Uint8Array(32); crypto.getRandomValues(b); return [...b].map((x) => x.toString(16).padStart(2, "0")).join(""); }
async function call(op) {
  const env = sign(secret, JSON.stringify(chain), JSON.stringify(op), ++n + Date.now() * 1000);
  const r = await fetch("call", { method: "POST", body: env });
  return r.json();
}
const show = (a) => `<pre class="answer">${esc(JSON.stringify(a, null, 1))}</pre>`;

const panels = {
  "render:tree": async (el) => {
    const a = await call({ op: "FsList", prefix: "" });
    el.innerHTML = `<div class="split"><div><h3>Files</h3><ul class="receipts">${(a.ok || []).map((f) => `<li><span>${f.conflicted ? "!" : ""}</span><a href="#" data-p="${esc(f.path)}">${esc(f.path)}</a></li>`).join("")}</ul>
      <h3>New file</h3><div class="viewas"><input id="np" placeholder="path/to/file.rs" aria-label="new file path"><button class="btn ghost" id="nb">Create</button></div></div>
      <div><h3 id="fp">Editor</h3><textarea id="ed" style="width:100%;min-height:420px" spellcheck="false" aria-label="file text"></textarea>
      <div class="viewas"><button class="btn" id="sv">Save</button><button class="btn ghost" id="sn">Snapshot and build</button></div><div id="out"></div></div></div>`;
    el.querySelectorAll("[data-p]").forEach((x) => (x.onclick = async (e) => { e.preventDefault(); const r = await call({ op: "FsRead", path: x.dataset.p }); file = x.dataset.p; base = r.ok?.hash; $("#fp").textContent = file; $("#ed").value = r.ok?.text ?? ""; }));
    $("#nb").onclick = async () => { $("#out").innerHTML = show(await call({ op: "FsWrite", path: $("#np").value, content: "" })); render(); };
    $("#sv").onclick = async () => { if (!file) return; const r = await call({ op: "FsWrite", path: file, content: $("#ed").value, base_hash: base }); base = r.ok?.hash ?? base; $("#out").innerHTML = show(r); };
    $("#sn").onclick = async () => {
      const s = await call({ op: "FsSnapshot", prefix: "" });
      const target = prompt("Crate directory to build (holds src/lib.rs)", "crates/parser");
      const b = await call({ op: "BuildStart", input: s.ok?.snapshot, target });
      const t = b.ok ? await call({ op: "TestStart", input: b.ok.output, bin: "out/test" }) : null;
      $("#out").innerHTML = show({ build: b.ok?.receipt ?? b, cases: t?.ok?.cases, test: t?.ok?.receipt ?? t });
    };
  },
  "render:conflicts": async (el) => { el.innerHTML = `<h3>Conflicts</h3>` + show(await call({ op: "FsConflicts", prefix: "" })); },
  "render:people": async (el) => { el.innerHTML = `<h3>People</h3>` + show(await call({ op: "PresenceWatch", prefix: "" })); },
  "render:changes": async (el) => { el.innerHTML = `<h3>Change sets</h3>` + show(await call({ op: "ReviewList" })); },
  "render:tools": async (el) => { el.innerHTML = `<h3>Tools</h3>` + show(await call({ op: "ToolsFind", capability: "compile:rust" })) + show(await call({ op: "ToolsFind", capability: "test:rust" })); },
  "render:search": async (el) => { el.innerHTML = `<h3>Search</h3><div class="viewas"><input id="q" aria-label="search"><button class="btn ghost" id="qs">Search</button></div><div id="qo"></div>`; $("#qs").onclick = async () => ($("#qo").innerHTML = show(await call({ op: "SearchText", query: $("#q").value }))); },
  "render:history": async (el) => { el.innerHTML = `<h3>Commits</h3>` + show(await call({ op: "VcsLog" })); },
  "render:receipts": async (el) => {
    const a = await call({ op: "AuditRead", since: 0 });
    el.innerHTML = `<h3>Receipts</h3><ol class="receipts">${(a.ok || []).slice(-200).reverse().map((r) => `<li class="${r.outcome.kind === "Refused" ? "r" : ""}"><span>#${r.seq}</span><span>${esc(r.actor)} ${esc(r.cell)} ${esc(r.op)} ${esc(r.target)} ${r.outcome.kind === "Refused" ? "refused: " + esc(r.outcome.need) : ""}</span></li>`).join("")}</ol>`;
  },
  "render:grants": async (el) => { el.innerHTML = `<h3>This session</h3>` + show(await call({ op: "KeysWhoami" })); },
};
let views = [], current = "render:tree";
async function render() {
  $("#tabs").innerHTML = views.filter((v) => panels[v.view] && v.view !== "render:editor").map((v) => `<button role="tab" aria-selected="${v.view === current}" data-v="${v.view}">${esc(v.title)}</button>`).join("");
  $("#tabs").querySelectorAll("button").forEach((b) => (b.onclick = () => { current = b.dataset.v; render(); }));
  await panels[current]?.($("#panel"));
}
(async () => {
  await init();
  try { secret = sessionStorage.getItem("ws-secret"); } catch (e) {}
  if (!secret) { secret = newSecret(); try { sessionStorage.setItem("ws-secret", secret); } catch (e) {} }
  const s = await (await fetch("session?pk=" + public_key(secret))).json().catch(() => ({}));
  if (!s.ok) { $("#who").textContent = "Not signed in: " + (s.error || JSON.stringify(s.refused || s)); return; }
  chain = s.ok.chain;
  const me = await call({ op: "KeysWhoami" });
  $("#who").textContent = `${me.ok?.identity}: ${me.ok?.rights?.length} rights until ${new Date(me.ok?.expiry).toLocaleTimeString()}`;
  views = (await call({ op: "UiLayout" })).ok || [];
  render();
})();
