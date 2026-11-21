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

// Live editing: the open file is read every 1.5 s; local typing goes out as FsPatch range edits against the version
// last read, so two people typing in one line both land (ws.fs maps the edits onto the present).
let pushT = null, pollT = null, seen = "", version = null, busy = false;
const ws = () => new URLSearchParams(location.hash.slice(1)).get("ws") || "main";
const link = (p) => `#ws=${encodeURIComponent(ws())}&path=${encodeURIComponent(p)}`;
function diff(a, b) {
  const A = [...a], B = [...b];
  let p = 0; while (p < A.length && p < B.length && A[p] === B[p]) p++;
  let s = 0; while (s < A.length - p && s < B.length - p && A[A.length - 1 - s] === B[B.length - 1 - s]) s++;
  if (p === A.length && p === B.length) return [];
  return [{ start: p, end: A.length - s, text: B.slice(p, B.length - s).join("") }];
}
async function open(p) {
  const r = await call({ op: "FsRead", path: p });
  if (!r.ok) { $("#live").textContent = "Cannot open " + p + ": " + (r.refused?.need || r.error || "refused"); return; }
  file = p; seen = r.ok.text ?? ""; version = r.ok.version; base = r.ok.hash;
  history.replaceState(null, "", link(p));
  $("#fp").textContent = p; const ed = $("#ed"); ed.disabled = false; ed.value = seen;
  $("#live").textContent = "Live. Edits are saved as you type.";
  clearInterval(pollT); pollT = setInterval(poll, 1500);
}
async function push() {
  if (!file || busy) return;
  const now = $("#ed").value, edits = diff(seen, now);
  if (!edits.length) return;
  busy = true;
  const r = await call({ op: "FsPatch", path: file, base: version, edits });
  busy = false;
  if (r.ok) { seen = now; $("#live").textContent = "Saved " + new Date().toLocaleTimeString() + (r.ok.change ? " to your change set " + r.ok.change : ""); await poll(); }
  else $("#live").textContent = "Not saved: " + (r.refused?.need || r.error);
}
async function poll() {
  if (!file || busy || document.hidden) return;
  const ed = $("#ed"); if (!ed) { clearInterval(pollT); return; }
  const r = await call({ op: "FsRead", path: file });
  if (!r.ok || r.ok.text === seen) { if (r.ok) version = r.ok.version; return; }
  const mine = diff(seen, ed.value);
  // rebase what is typed but not sent yet onto the new text
  let t = r.ok.text;
  if (mine.length) { const e = mine[0], c = [...t]; t = c.slice(0, e.start).join("") + e.text + c.slice(Math.min(e.end, c.length)).join(""); }
  const theirs = diff(seen, r.ok.text)[0];
  let at = ed.selectionStart;
  if (theirs && theirs.start < at) at = Math.max(theirs.start, at + [...theirs.text].length - (theirs.end - theirs.start));
  seen = r.ok.text; version = r.ok.version; base = r.ok.hash; ed.value = t;
  ed.selectionStart = ed.selectionEnd = Math.min(at, t.length);
  if (mine.length) push();
}
window.addEventListener("hashchange", () => { const p = new URLSearchParams(location.hash.slice(1)).get("path"); if (p && p !== file && $("#ed")) open(p); });

const panels = {
  "render:tree": async (el) => {
    const a = await call({ op: "FsList", prefix: "" });
    el.innerHTML = `<div class="split"><div><h3>Files</h3><ul class="receipts files">${(a.ok || []).map((f) => `<li><span>${f.conflicted ? "!" : ""}</span><a href="${link(f.path)}" data-p="${esc(f.path)}">${esc(f.path)}</a></li>`).join("")}</ul>
      <h3>New file</h3><div class="viewas"><input id="np" placeholder="path/to/file.rs" aria-label="new file path"><button class="btn ghost" id="nb">Create</button></div></div>
      <div><h3 id="fp">Editor</h3><p class="dim small" id="live">Pick a file. Typing is saved as you go and merged with everyone else's edits.</p>
      <textarea id="ed" class="editor" spellcheck="false" aria-label="file text" disabled></textarea>
      <div class="viewas"><button class="btn ghost" id="sn">Snapshot and build</button></div><div id="out"></div></div></div>`;
    el.querySelectorAll("[data-p]").forEach((x) => (x.onclick = (e) => { e.preventDefault(); open(x.dataset.p); }));
    $("#nb").onclick = async () => { const p = $("#np").value.trim(); if (!p) return; $("#out").innerHTML = show(await call({ op: "FsWrite", path: p, content: "" })); await render(); open(p); };
    $("#ed").oninput = () => { clearTimeout(pushT); pushT = setTimeout(push, 400); };
    $("#sn").onclick = async () => {
      const s = await call({ op: "FsSnapshot", prefix: "" });
      const target = prompt("Crate directory to build (holds src/lib.rs)", "crates/parser");
      if (!target) return;
      const b = await call({ op: "BuildStart", input: s.ok?.snapshot, target });
      const t = b.ok ? await call({ op: "TestStart", input: b.ok.output, bin: "out/test" }) : null;
      $("#out").innerHTML = show({ build: b.ok?.receipt ?? b, cases: t?.ok?.cases, test: t?.ok?.receipt ?? t });
    };
    const want = new URLSearchParams(location.hash.slice(1)).get("path");
    if (want) open(want);
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
