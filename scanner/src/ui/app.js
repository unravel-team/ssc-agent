"use strict";
// Supply-chain scanner UI. Talks only to this local app (/api/...), which sends scans to the company server.
const TOKEN = document.querySelector('meta[name="ssc-token"]').content;
const $ = (id) => document.getElementById(id);
const INTERVALS = [15, 30, 60, 120, 240, 480, 1440];
let STATE = null, SELECTED = null, SCAN = null, POLL = null;
const RESULTS = {};                                  // label -> last loaded result

async function api(path, body) {
  const opts = { headers: { "X-SSC-Token": TOKEN } };
  if (body !== undefined) { opts.method = "POST"; opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
  const r = await fetch(path, opts);
  const j = await r.json().catch(() => ({ error: "bad response" }));
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}

// ---------------------------------------------------------------- safe DOM + markdown
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function el(tag, attrs, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") n.className = v; else if (k === "text") n.textContent = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v); else n.setAttribute(k, v === true ? "" : v);
  }
  for (const k of kids.flat()) if (k != null && k !== false) n.append(k);
  return n;
}
// Markdown from the agents, rendered safely: everything is escaped first; only http(s) links become links.
function inline(s) {
  const codes = [];
  s = esc(s).replace(/`([^`]+)`/g, (_, c) => { codes.push(c); return "\u0000" + (codes.length - 1) + "\u0000"; });
  s = s.replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, (_, t, u) => `<a href="${u}" target="_blank" rel="noopener noreferrer">${t}</a>`);
  s = s.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>").replace(/(^|[\s(])_([^_]+)_(?=[\s).,;:]|$)/g, "$1<em>$2</em>");
  return s.replace(/\u0000(\d+)\u0000/g, (_, i) => `<code>${codes[+i]}</code>`);
}
function md(src) {
  const lines = String(src || "").replace(/\r/g, "").split("\n");
  let html = "", i = 0;
  const isSep = (l) => /^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$/.test(l);
  const cells = (l) => l.trim().replace(/^\||\|$/g, "").split("|").map((c) => c.trim());
  while (i < lines.length) {
    const l = lines[i];
    if (/^```/.test(l)) { const b = []; i++; while (i < lines.length && !/^```/.test(lines[i])) b.push(lines[i++]); i++; html += `<pre><code>${esc(b.join("\n"))}</code></pre>`; continue; }
    const h = l.match(/^(#{1,6})\s+(.*)$/);
    if (h) { const n = Math.min(h[1].length + 1, 6); html += `<h${n}>${inline(h[2])}</h${n}>`; i++; continue; }
    if (/^\s*\|/.test(l) && i + 1 < lines.length && isSep(lines[i + 1])) {
      html += "<div class='tablewrap'><table><thead><tr>" + cells(l).map((c) => `<th>${inline(c)}</th>`).join("") + "</tr></thead><tbody>";
      i += 2;
      while (i < lines.length && /^\s*\|/.test(lines[i])) html += "<tr>" + cells(lines[i++]).map((c) => `<td>${inline(c)}</td>`).join("") + "</tr>";
      html += "</tbody></table></div>"; continue;
    }
    if (/^\s*([-*]|\d+\.)\s+/.test(l)) {
      const ordered = /^\s*\d+\./.test(l), items = [];
      while (i < lines.length && /^\s*([-*]|\d+\.)\s+/.test(lines[i])) {
        let item = lines[i++].replace(/^\s*([-*]|\d+\.)\s+/, "");
        while (i < lines.length && /^\s{2,}\S/.test(lines[i]) && !/^\s*([-*]|\d+\.)\s+/.test(lines[i])) item += " " + lines[i++].trim();
        items.push(`<li>${inline(item)}</li>`);
      }
      html += ordered ? `<ol>${items.join("")}</ol>` : `<ul>${items.join("")}</ul>`; continue;
    }
    if (/^\s*$/.test(l)) { i++; continue; }
    if (/^-{3,}\s*$/.test(l)) { html += "<hr>"; i++; continue; }
    const p = [];
    while (i < lines.length && !/^\s*$/.test(lines[i]) && !/^(#{1,6}\s|```|\s*\||\s*([-*]|\d+\.)\s)/.test(lines[i])) p.push(lines[i++]);
    html += `<p>${inline(p.join(" "))}</p>`;
  }
  return html;
}

// ---------------------------------------------------------------- small helpers
function ago(iso) {
  if (!iso) return "";
  const s = Math.max(0, (Date.now() - Date.parse(iso)) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}
const every = (m) => m < 60 ? `every ${m} min` : m === 60 ? "every hour" : m === 1440 ? "daily" : `every ${m / 60} h`;
const tail = (label) => label.replace(/\/+$/, "").split("/").pop() || label;
function level(summary) {
  const s = summary || {};
  return (s.BLOCK || 0) > 0 ? "block" : (s.HOLD || 0) > 0 ? "hold" : "ok";
}
const scanningThis = (f) => SCAN && SCAN.running && SCAN.folder === f.path;

// ---------------------------------------------------------------- top bar + sidebar
function renderTop() {
  const s = STATE, srv = $("server");
  const up = s.server === "up";
  srv.hidden = up;  // connected: nothing to show; a problem is shown with a red dot and text
  srv.querySelector(".dot").className = "dot " + (up ? "up" : s.api ? "down" : "");
  // connected: just the green dot (hover for the address); a problem is spelled out
  srv.querySelector(".label").textContent = up ? "" : s.api ? "Server unreachable" : "No server set";
  srv.title = up ? `Server connected: ${s.api}` : (s.server || "Set SSC_API_URL in scanner/.env");
  const auto = $("auto"), sel = $("interval");
  auto.checked = s.background === "installed";
  auto.disabled = !(s.api && s.key_saved && s.folders.length);
  if (!sel.options.length) for (const m of INTERVALS) sel.append(el("option", { value: String(m), text: every(m) }));
  sel.value = String(s.interval_minutes);
}

function renderSidebar() {
  const list = $("folders");
  list.replaceChildren();
  for (const f of STATE.folders) {
    // the badge counts open action items, the same rows as the table (an older result without them: its verdicts)
    const last = f.last, o = f.open;
    const lv = !last ? null : o ? (o.block ? "block" : o.total ? "hold" : "ok") : level(last.summary);
    const n = o ? o.total : lv === "block" ? (last.summary || {}).BLOCK : lv === "hold" ? (last.summary || {}).HOLD : 0;
    const dot = scanningThis(f) ? "busy" : !f.exists ? "" : lv || "";
    const sub = scanningThis(f) ? "Scanning…" : !f.exists ? "Folder not found" : last ? `Scanned ${ago(last.at)}` : "Not scanned yet";
    const count = n ? el("span", { class: "count" + (lv === "block" ? "" : " hold"), text: String(n),
      title: o ? `${plural(n, "open action item", "open action items")}${o.block ? `, ${o.block} to fix now` : ""}` : "" }) : null;
    list.append(el("button", { type: "button", class: "folder" + (SELECTED === f.label ? " sel" : ""), onclick: () => select(f.label), title: f.path },
      el("span", { class: "dot " + dot }),
      el("span", {}, el("div", { class: "name", text: tail(f.label) }), el("div", { class: "sub", text: sub })),
      count || el("span")));
  }
  $("scan-all").disabled = !(STATE.api && STATE.key_saved && STATE.folders.length) || !!(SCAN && SCAN.running);
}

// ---------------------------------------------------------------- main pane
const STEPS = ["Scan the folder's files", "Check every package with the server", "Write the advisory"];
function stepOf(log) {
  const t = (log || []).join("\n");
  if (/done:/.test(t)) return 3;
  if (/agents are writing/.test(t)) return 2;
  if (/sending|checking every package|waiting for the server/.test(t)) return 1;
  return 0;
}

function progressView(s) {
  const at = stepOf(s.log);
  const failed = !s.running && s.error;
  return el("section", { class: "card progress" },
    el("h2", { text: failed ? "The scan didn't finish" : s.running ? "Scanning…" : "Scan finished" }),
    el("ol", { class: "steps" }, STEPS.map((label, i) => el("li", { class: i < at ? "done" : i === at && s.running ? "now" : "" },
      el("span", { class: "ic", text: i < at ? "✓" : "" }), el("span", { text: label })))),
    failed ? el("div", { class: "err", text: s.error }) : null);
}

const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
const isLink = (u) => /^https?:\/\//.test(u || "");
const DONE_DAYS = 30;                                 // fixed items stay listed (ticked) this long
const HOW = { ticked: "Marked done", applied: "Applied by Claude", resolved: "Fixed: no longer found", skipped: "Skipped" };
const stateOf = (d) => (!d ? "pending" : d.how === "skipped" ? "skipped" : "done");

// every row of the table: open items from the latest scan, then done ones (ticked here, or gone since)
function rowsOf(r) {
  const actions = r.result?.actions || [], done = r.done || {};
  const open = actions.filter((a) => !done[a.key]);
  const ticked = actions.filter((a) => done[a.key]).map((a) => ({ ...a, done: done[a.key] }));
  const keys = new Set(actions.map((a) => a.key)), cut = Date.now() - DONE_DAYS * 864e5;
  const gone = Object.entries(done).filter(([k, d]) => !keys.has(k) && Date.parse(d.at) > cut)
    .map(([k, d]) => ({ ...(d.row || {}), key: k, done: d, gone: true, sources: d.row?.sources || [] }));
  return { open, done: [...ticked, ...gone.sort((x, y) => (y.done.at || "").localeCompare(x.done.at || ""))] };
}

function verdictView(r) {
  const { open, done } = rowsOf(r);
  const now = open.filter((a) => a.priority === "block").length, review = open.length - now;
  const lv = now ? "block" : review ? "hold" : "ok";
  const title = { block: "Action needed", hold: "Review recommended", ok: "All clear" }[lv];
  // the written summary is from the scan; once something is ticked after it, say what is still open instead
  const written = r.result?.updated_at || "", ticks = Object.values(r.done || {}).map((d) => d.at || "");
  const stale = ticks.some((t) => t > written);
  const summary = el("div", { class: "md summary" });
  if (stale) {
    const by = {}; open.forEach((a) => { by[a.criticality || "Medium"] = (by[a.criticality || "Medium"] || 0) + 1; });
    const counts = ["Critical", "High", "Medium", "Low"].filter((c) => by[c]).map((c) => `${by[c]} ${c}`).join(", ");
    const next = open[0];
    summary.append(open.length
      ? el("ul", {}, el("li", { text: `${plural(open.length, "item", "items")} still open (${counts})` }),
          ...open.slice(0, 2).map((a) => el("li", { text: `${a.item}: ${a.action}` })))
      : el("p", { text: "Everything on the list is done." }),
      el("p", { class: "hint", text: "Updated from your ticks; the next scan writes a fresh summary." }));
  } else summary.innerHTML = md(r.result?.advice_summary || "");          // escaped by md()
  const s = r.result?.summary || {};
  return el("section", { class: "card verdict " + lv },
    el("div", { class: "badge", text: lv === "ok" ? "✓" : "!" }),
    el("div", {}, el("h2", { text: title }), summary,
      el("div", { class: "stats" },
        el("span", { class: "stat block" }, el("b", { text: String(now) }), "to fix now"),
        el("span", { class: "stat hold" }, el("b", { text: String(review) }), "to review"),
        el("span", { class: "stat ok" }, el("b", { text: String(done.filter((a) => stateOf(a.done) === "done").length) }), "done"),
        el("span", { class: "stat muted" }, el("b", { text: String(done.filter((a) => stateOf(a.done) === "skipped").length) }), "skipped"),
        el("span", { class: "stat muted" }, el("b", { text: String((s.BLOCK || 0) + (s.HOLD || 0) + (s.ALLOW || 0)) }), "packages checked"))));
}

function sourcesCell(items, kind, max = 2) {
  const seen = new Set(), list = (items || []).filter((x) => isLink(x.url) && !seen.has(x.url) && seen.add(x.url));
  if (!list.length) return el("td", { class: "src none", text: kind === "secret" ? "Found in your file" : "-" });
  const link = (x) => el("a", { href: x.url, target: "_blank", rel: "noopener noreferrer", title: x.title || x.url, text: x.text || x.url });
  const rest = list.slice(max);
  return el("td", { class: "src" }, list.slice(0, max).map(link),
    rest.length ? el("details", {}, el("summary", { text: `+${rest.length} more` }), rest.map(link)) : null);
}

let FLASH = null;                                     // the row just changed: shown where it moved to
async function setState(label, key, state) {
  let why = "";
  if (state === "skipped") {                          // the reason helps the server rank such items lower
    const answer = window.prompt("Why doesn't this apply to you? (optional, e.g. \"we don't use Docker Hub\")", "");
    if (answer === null) return;                      // cancelled
    why = answer;
  }
  FLASH = key;
  try {
    const r = await api("/api/done", { label, key, state, why });
    RESULTS[label].done = r.done;
    const f = STATE.folders.find((x) => x.label === label), open = rowsOf(RESULTS[label]).open;
    if (f) f.open = { total: open.length, block: open.filter((a) => a.priority === "block").length };
    renderSidebar();
  } catch (e) { $("side-msg").textContent = e.message; }
  renderMain();
  const tr = document.querySelector(`tr[data-key="${CSS.escape(key)}"]`);
  if (tr) tr.scrollIntoView({ block: "center", behavior: "smooth" });
  setTimeout(() => { FLASH = null; tr && tr.classList.remove("flash"); }, 1600);
}

function actionsView(r, label) {
  const { open, done } = rowsOf(r);
  if (!open.length && !done.length) return el("section", { class: "card panel" }, el("p", { class: "hint", text: "Nothing to do: no problems found." }));
  const row = (a) => {
    const state = stateOf(a.done), isDone = state !== "pending";
    const auto = !isDone && (a.edits || []).length;
    // a row the latest scan no longer lists has nothing to go back to: its state can't be changed
    const locked = !!a.gone;
    const choice = (st, text, hint) => el("button", { type: "button", class: "st " + st + (state === st ? " on" : ""),
      "aria-pressed": String(state === st), disabled: locked || state === st || undefined, title: locked ?
        "The latest scan no longer finds this, so there is nothing to change" : hint, text,
      onclick: () => setState(label, a.key, st) });
    return el("tr", { class: (isDone ? "done " + state : "") + (FLASH === a.key ? " flash" : ""), "data-key": a.key },
      el("td", { class: "tick" }, el("div", { class: "states", role: "group", "aria-label": "State" },
        choice("pending", "Open", "Mark as still to do"),
        choice("done", "Done", "Mark as done: you did it"),
        choice("skipped", "Skip", "Not relevant to you, or you won't do it"))),
      el("td", {}, el("span", { class: "tag " + (state === "done" ? "ok" : state === "skipped" ? "skip" : a.priority),
        text: state === "done" ? "Done" : state === "skipped" ? "Skipped" : a.priority === "block" ? "Fix now" : "Review" })),
      el("td", {}, a.criticality ? el("span", { class: "crit " + a.criticality.toLowerCase(), text: a.criticality }) : "-"),
      el("td", { class: "proj", text: a.project || "" }),
      el("td", { class: "item" }, el("div", { class: "pkg", text: a.item || "" }), a.problem ? el("div", { class: "more", text: a.problem }) : null),
      el("td", { class: "where", text: (a.where || []).join("\n") || "-" }),
      el("td", { class: "why" }, a.action || "",
        isDone ? el("div", { class: "more", text: `${HOW[a.done.how] || "Done"}${a.done.why ? `: ${a.done.why}` : ""} · ${ago(a.done.at)}` })
          : auto ? el("div", { class: "more", text: "Claude plugin can apply this" }) : null),
      sourcesCell(a.sources, a.kind));
  };
  return el("section", { class: "card panel" },
    el("h3", { class: "group-head" }, "Action items", el("span", { class: "n", text:
      ` ${open.length} open · ${done.filter((a) => stateOf(a.done) === "done").length} done · ${done.filter((a) => stateOf(a.done) === "skipped").length} skipped` })),
    el("div", { class: "tablewrap" }, el("table", { class: "actions-table" },
      el("thead", {}, el("tr", {}, ["State", "Priority", "Criticality", "Project", "Item", "Where", "Action", "Sources"].map((h) => el("th", { text: h })))),
      el("tbody", {}, [...open, ...done].map(row)))));
}

function resultView(r, label) {
  return [verdictView(r), actionsView(r, label)];
}

function renderMain() {
  const main = $("main"), s = STATE;
  main.replaceChildren();
  if (!s.api) {
    main.append(el("div", { class: "empty" }, el("h2", { text: "No server set" }),
      el("p", {}, "This copy of the app has no server address. Ask whoever gave it to you for the right build.")));
    return;
  }
  if (!s.key_saved) {
    const msg = el("p", { class: "key-msg", role: "status" });
    const form = el("form", { class: "key-form", autocomplete: "off", onsubmit: async (e) => {
      e.preventDefault();
      msg.textContent = "Checking with the server…";
      try { await api("/api/key", { key: e.target.key.value }); refresh(); } catch (err) { msg.textContent = err.message; }
    } }, el("input", { name: "key", type: "password", placeholder: "Paste your scan key", "aria-label": "Scan key", required: true }),
       el("button", { class: "btn", type: "submit" }, "Continue"));
    main.append(el("div", { class: "empty welcome" }, el("h2", { text: "Welcome" }),
      el("p", { text: "This server does not hand out keys by itself: paste the scan key you were given. You only do this once; it stays on this computer." }), form, msg));
    return;
  }
  const f = s.folders.find((x) => x.label === SELECTED);
  if (!f) {
    main.append(el("div", { class: "empty" }, el("h2", { text: s.folders.length ? "Pick a folder" : "Add a folder to scan" }),
      el("p", { text: s.folders.length ? "Choose a folder on the left to see its advisory."
        : "Add a folder that holds your projects (for example ~/code). Each project in it is checked; nothing is installed or run." })));
    return;
  }
  const last = f.last, busy = !!(SCAN && SCAN.running);
  main.append(el("div", { class: "page-head" },
    el("div", {}, el("h1", { text: tail(f.label) }),
      el("div", { class: "meta" }, el("span", { text: f.label }),
        last ? el("span", { text: `Scanned ${ago(last.at)}` }) : null,
        last ? el("button", { class: "link", type: "button", onclick: () => api("/api/open", { label: f.label }).catch(() => {}) }, "Open results folder") : null,
        el("button", { class: "link", type: "button", onclick: () => removeFolder(f) }, "Remove"))),
    el("button", { class: "btn", type: "button", disabled: busy || !f.exists, onclick: () => scan(f.path) }, scanningThis(f) ? "Scanning…" : "Scan now")));
  if (SCAN && SCAN.folder === f.path && (SCAN.running || SCAN.error)) main.append(progressView(SCAN));
  if (!f.exists) main.append(el("section", { class: "card notice", text: "This folder no longer exists on this computer." }));
  const r = RESULTS[f.label];
  if (r) main.append(...resultView(r, f.label));
  else if (!last && !scanningThis(f)) main.append(el("div", { class: "empty" }, el("h2", { text: "Not scanned yet" }),
    el("p", { text: "Scan this folder to see what's wrong and how to fix it." })));
}

async function render() {
  renderTop(); renderSidebar(); renderMain();
}

// ---------------------------------------------------------------- data + actions
async function refresh() {
  STATE = await api("/api/state");
  if (!SELECTED || !STATE.folders.some((f) => f.label === SELECTED)) SELECTED = STATE.folders[0] && STATE.folders[0].label;
  const f = STATE.folders.find((x) => x.label === SELECTED);
  if (f && f.last && (!RESULTS[f.label] || RESULTS[f.label].result?.id !== f.last.scan_id)) {
    RESULTS[f.label] = await api("/api/result?label=" + encodeURIComponent(f.label)).catch(() => undefined);
  }
  render();
}

function select(label) { SELECTED = label; refresh(); }

async function scan(path) {
  $("side-msg").textContent = "";
  try { await api("/api/scan", path ? { folder: path } : {}); } catch (e) { $("side-msg").textContent = e.message; return; }
  if (path) { const f = STATE.folders.find((x) => x.path === path); if (f) SELECTED = f.label; }
  watchScan();
}

function watchScan() {
  if (POLL) return;
  const tick = async () => {
    SCAN = await api("/api/scan").catch(() => SCAN);
    if (SCAN && !SCAN.running) {
      clearInterval(POLL); POLL = null;
      const f = STATE.folders.find((x) => x.path === SCAN.folder);
      if (f) delete RESULTS[f.label];
      if (!SCAN.error) SCAN = null;                     // success: the result replaces the progress view
      await refresh(); return;
    }
    renderSidebar(); renderMain();
  };
  POLL = setInterval(tick, 1200); tick();
}

async function removeFolder(f) {
  if (!confirm(`Stop scanning ${f.label}? Its past results are kept.`)) return;
  try { await api("/api/folders", { action: "remove", path: f.path }); SELECTED = null; refresh(); }
  catch (e) { $("side-msg").textContent = e.message; }
}

$("add-folder").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("side-msg").textContent = "";
  try {
    const r = await api("/api/folders", { action: "add", path: e.target.path.value });
    e.target.reset();
    await refresh();
    const added = STATE.folders[STATE.folders.length - 1];
    if (added) select(added.label);
    void r;
  } catch (err) { $("side-msg").textContent = err.message; }
});
$("scan-all").addEventListener("click", () => scan());
$("auto").addEventListener("change", async (e) => {
  try { await api("/api/background", { action: e.target.checked ? "install" : "uninstall" }); }
  catch (err) { $("side-msg").textContent = err.message; }
  refresh();
});
$("interval").addEventListener("change", async (e) => {
  try { await api("/api/interval", { minutes: Number(e.target.value) }); } catch (err) { $("side-msg").textContent = err.message; }
  refresh();
});
setInterval(() => { if (!POLL) refresh().catch(() => {}); }, 60_000);   // keep "scanned N min ago" and server status fresh

refresh().then(async () => { SCAN = await api("/api/scan").catch(() => null); if (SCAN && SCAN.running) watchScan(); else SCAN = null; render(); });
