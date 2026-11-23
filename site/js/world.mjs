// SPDX-License-Identifier: Apache-2.0 OR MIT
// AINRA World. The test network as a world you can turn, replay, walk through and check.
//
// Real: every node, count, status-list bit, log position and verdict.
//   nodes, counts      net/index.json, net/directory.json, net/epochs.json, net/registry.json
//   dust               each registrar's signed status list (status/current.json), one point per bit
//   replay             each registrar's log positions, then its status changes in order (status/deltas.json)
//   checks             vendor/ainra-sdk.js in this tab, against the published directory and roots, at the record's time
// Drawn (and the About panel says so): positions in space, the turning, the travelling threads.
//
// Motion: respond on press; drag 1:1; release velocity becomes momentum; the camera and the
// sheet move on springs (damping 1.0 by default, 0.8 only after a flick), always from their current value, so anything
// can be grabbed mid-flight; soft resistance past every limit; under reduced motion nothing travels or turns by itself.

import { icon } from "./icons.mjs";
const $ = (s) => document.querySelector(s);
const cv = $("#world"), ctx = cv.getContext("2d");
// Motion follows the site's one switch (js/motion.mjs, stored as "ainra-motion"), then the system's reduced-motion setting.
const RMQ = matchMedia("(prefers-reduced-motion: reduce)");
const RM = { get matches() { let pref = null; try { pref = localStorage.getItem("ainra-motion"); } catch { /* storage unavailable */ } return pref === "off" || (pref !== "on" && RMQ.matches); } };
const MONO = '"Noto Sans Mono", ui-monospace, monospace';
const TAU = Math.PI * 2;

// ---------- small tools ----------
async function getJSON(url) {
  const c = new AbortController(), t = setTimeout(() => c.abort(), 10000);
  try { const r = await fetch(url, { signal: c.signal, cache: "no-cache" }); if (!r.ok) throw new Error(`${url} answered HTTP ${r.status}`); return await r.json(); }
  catch (e) { throw new Error(e.name === "AbortError" ? `${url} did not answer within 10 seconds` : e.message); }
  finally { clearTimeout(t); }
}
const b64u = (s) => btoa(String.fromCharCode(...new TextEncoder().encode(s))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const cut = (s, n = 18) => (s && s.length > n ? s.slice(0, n) + "…" : s || "");
const short = (sub) => sub.split(":").slice(3).join(":") || sub;
const hash = (i) => { const x = Math.sin(i * 127.1 + 311.7) * 43758.5453; return x - Math.floor(x); };
const add = (a, b) => [a[0] + b[0], a[1] + b[1], a[2] + b[2]];
const mul = (a, k) => [a[0] * k, a[1] * k, a[2] * k];
const norm = (a) => { const l = Math.hypot(...a) || 1; return mul(a, 1 / l); };
const clamp = (x, a, b) => Math.max(a, Math.min(b, x));
const rubber = (over, dim, c = 0.55) => (over * dim * c) / (dim + c * Math.abs(over));       // resistance past a limit
const project = (v, d = 0.998) => (v / 1000) * d / (1 - d);                                  // where a flick comes to rest
async function bitsOf(st) {
  if (typeof DecompressionStream === "undefined") throw new Error("this browser cannot inflate the status list");
  const b = st.status_list_b64.replace(/-/g, "+").replace(/_/g, "/");
  const raw = Uint8Array.from(atob(b.padEnd(Math.ceil(b.length / 4) * 4, "=")), (c) => c.charCodeAt(0));
  const p = new Uint8Array(await new Response(new Blob([raw]).stream().pipeThrough(new DecompressionStream("deflate"))).arrayBuffer());
  const out = new Uint8Array(st.bit_len); for (let i = 0; i < st.bit_len; i++) out[i] = (p[i >> 3] >> (i & 7)) & 1; return out;
}

// A spring in two terms: response (seconds) and damping ratio (1 = no overshoot).
class Spring {
  constructor(x, response = 0.4, damping = 1) { this.x = x; this.v = 0; this.to = x; this.on = false; this.set(response, damping); }
  set(response, damping) { this.k = (TAU / response) ** 2; this.c = (4 * Math.PI * damping) / response; return this; }
  go(to, v) { this.to = to; this.on = true; if (v !== undefined) this.v = v; }
  stop() { this.on = false; this.v = 0; }
  step(dt) {
    if (!this.on) return;
    for (let t = dt; t > 0; t -= 1 / 240) { const h = Math.min(t, 1 / 240), a = -this.k * (this.x - this.to) - this.c * this.v; this.v += a * h; this.x += this.v * h; }
    if (Math.abs(this.x - this.to) < 1e-4 && Math.abs(this.v) < 1e-3) { this.x = this.to; this.on = false; }
  }
}

// ---------- icons: painted once, swapped by turning out and in ----------
function paintIcons() { for (const el of document.querySelectorAll("[data-icon]:not([data-painted])")) { el.dataset.painted = "1"; el.insertAdjacentHTML("afterbegin", icon(el.dataset.icon)); } }
function swapIcon(el, name) {
  const cur = el.querySelector(".ic:not(.out)"); if (cur && cur.dataset.n === name) return;
  el.insertAdjacentHTML("beforeend", icon(name, RM.matches || !cur ? "ic" : "ic in")); el.lastElementChild.dataset.n = name;
  if (cur) { if (RM.matches) cur.remove(); else { cur.classList.add("out"); setTimeout(() => cur.remove(), 200); } }
}

// ---------- appearance: follows the system ----------
let INK = "#0b0b0b", PAPER = "#f5f5f3", rgb = [11, 11, 11];
function readTheme() {
  const cs = getComputedStyle(document.documentElement);
  INK = cs.getPropertyValue("--ink").trim(); PAPER = cs.getPropertyValue("--paper").trim();
  const h = INK.replace("#", ""); rgb = [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16));
}
const ink = (a) => `rgba(${rgb[0]},${rgb[1]},${rgb[2]},${a})`;
matchMedia("(prefers-color-scheme: dark)").addEventListener("change", readTheme);

// ---------- loading: determinate, every step named ----------
const boot = $("#boot");
function stepOn(s, label, pct) { const li = boot.querySelector(`li[data-s="${s}"]`); if (li) li.className = "on"; $("#bootStep").textContent = label; progress(pct); }
function stepOk(s) { const li = boot.querySelector(`li[data-s="${s}"]`); if (li) li.className = "ok"; }
function progress(p) { $("#bootBar").style.width = `${p}%`; boot.setAttribute("aria-valuenow", String(Math.round(p))); bootP = p; paintArt(); }
// The loading mark, drawn in characters: the AINRA mark sampled into a small grid, each cell revealed as the real
// loading passes its place (the bar and the steps say the same in words). Decoration only: aria-hidden.
let bootP = 0, artCells = null;
function bootArt() {
  const g = document.getElementById("mark"); if (!g) return;
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 112 112" width="448" height="448"><rect width="112" height="112" fill="#fff"/><g fill="none" stroke="#000" stroke-linecap="round">${g.innerHTML.replace(/currentColor/g, "#000")}</g></svg>`;
  const im = new Image();
  im.onload = () => {
    const cols = 40, rows = 20, c = document.createElement("canvas"); c.width = cols; c.height = rows;
    const x = c.getContext("2d", { willReadFrequently: true }); x.imageSmoothingQuality = "high"; x.drawImage(im, 0, 0, cols, rows);
    const px = x.getImageData(0, 0, cols, rows).data, ramp = " .:-=+*#%@";
    artCells = []; for (let i = 0; i < cols * rows; i++) {
      const v = 1 - (px[i * 4] + px[i * 4 + 1] + px[i * 4 + 2]) / 765;
      artCells.push({ ch: v < 0.05 ? " " : ramp[Math.min(ramp.length - 1, 1 + Math.floor(Math.sqrt(v) * (ramp.length - 1)))], at: hash(i * 3.1) * 100, eol: (i + 1) % cols === 0 });
    }
    $("#bootArt").hidden = false; const m = $("#bootMark"); if (m) m.style.display = "none"; paintArt();
  };
  im.src = "data:image/svg+xml," + encodeURIComponent(svg);
}
function paintArt() {
  if (!artCells) return; let t = "";
  for (const c of artCells) { t += c.ch !== " " && (c.at <= bootP || RM.matches) ? c.ch : c.ch !== " " ? "·" : " "; if (c.eol) t += "\n"; }
  $("#bootArt").textContent = t;
}
function bootFail(msg) {
  const on = boot.querySelector("li.on"); if (on) on.className = "bad";
  $("#bootStep").textContent = "The world could not be built";
  const p = document.createElement("div"); p.className = "boot__err";
  p.innerHTML = `<b>What happened:</b> <span></span><br><b>What to do:</b> reload the page; if it happens again, the record is unreachable from here. The record itself is plain files: <a href="net/registry.json">net/registry.json</a>.`;
  p.querySelector("span").textContent = msg; $(".boot__in").append(p);
  boot.querySelector(".boot__mark").style.animation = "none";
}

// ---------- the world ----------
const nodes = [], edges = [], byId = {}, regs = [];
function N(id, kind, pos, r, label, info, extra = {}) { const n = { id, kind, pos, r, label, info, flash: 0, sx: 0, sy: 0, sr: 0, depth: 0, vis: false, ...extra }; nodes.push(n); byId[id] = n; return n; }
function E(a, b, kind = "base") { const e = { a: byId[a], b: byId[b], kind, lit: 0 }; edges.push(e); return e; }
const edgeOf = (a, b) => edges.find((e) => (e.a.id === a && e.b.id === b) || (e.a.id === b && e.b.id === a));
let CUR = 0;

function build({ roots, directory, epochs, registry, lists }) {
  CUR = directory.epoch;
  N("root", "root", [0, 0, 0], 22, "root", { k: "ROOT · TEST, BEFORE THE CEREMONY", t: "The root", rows: [["Ed25519", cut(roots.root_ed25519, 30)], ["SLH-DSA", cut(roots.root_slh, 30)], ["Signs", "one thing: the registrar directory"], ["Issues", "no passports, sees no traffic"]] });
  epochs.epochs.forEach((ep, i) => {
    const now = ep.epoch === CUR;
    N(`epoch${ep.epoch}`, "epoch", [0, 0, 0], 52 + i * 14, `epoch ${ep.epoch}`, { k: `DIRECTORY EPOCH ${ep.epoch}`, t: now ? `Directory, epoch ${ep.epoch} (current)` : `Directory, epoch ${ep.epoch} (replaced)`, rows: [["Digest", cut(ep.digest, 30)], ["Names", now ? `${directory.entries.length} registrars` : "kept in the directory log"], ["Signed by", "both root keys"]] }, { ring: true, faded: !now, tilt: 0.5 + i * 0.35 });
  });
  const anchors = [[-270, 30, -40], [275, -30, 50], [0, -40, -300], [0, 60, 300]];
  registry.registrars.forEach((R, ri) => {
    const id = R.registrar, recs = R.records.map((r) => r.record), L = lists[id];
    const pos = anchors[ri % anchors.length], out = norm(pos);
    const shell = 95 + Math.sqrt(recs.length) * 16, size = Math.max(...recs.map((r) => r.checkpoint_size || 0));
    const reg = N(id, "registrar", pos, 12 + Math.sqrt(recs.length) * 5, id, { k: "REGISTRAR · ACCREDITED IN THE DIRECTORY", t: id, rows: [
      ["Issuer key", `Ed25519 ${cut(R.accreditation.issuer_key.ed25519, 22)} + ML-DSA-65`], ["Log", `${R.accreditation.log_origin}, ${size} entries`],
      ["Status list", `${L.list.bit_len.toLocaleString("en")} bits, change ${R.status_seq}`], ["Passports", `${recs.length} issued, ${recs.filter((r) => L.bits[r.status_idx]).length} switched off`]] },
      { shell, out, size, recs });
    regs.push(reg); E(`epoch${CUR}`, id, "sign");
    const n = L.list.bit_len, dust = new Float32Array(n * 3);
    for (let i = 0; i < n; i++) {                                     // bit i always sits at the same place
      const y = 1 - ((i + 0.5) / n) * 2, rr = Math.sqrt(1 - y * y), th = i * 2.399963229728653, k = shell * (0.86 + hash(i + ri * 9973) * 0.28);
      dust[i * 3] = pos[0] + Math.cos(th) * rr * k; dust[i * 3 + 1] = pos[1] + y * k; dust[i * 3 + 2] = pos[2] + Math.sin(th) * rr * k;
    }
    Object.assign(reg, { dust, bitsFinal: L.bits, bits: new Uint8Array(L.bits), list: L.list, deltas: L.deltas, used: new Map(recs.map((r) => [r.status_idx, r.sub])) });
    const side = norm([out[2], 0.0001, -out[0]]); let mid = [0, 0, 0];
    for (let k = 0; k < size; k++) {
      const a = k * 0.85, base = add(pos, mul(out, 46));
      const p = add(add(add(base, mul(side, Math.cos(a) * 15)), [0, -56 + k * (112 / Math.max(1, size - 1)), 0]), mul(out, Math.sin(a) * 15));
      mid = add(mid, mul(p, 1 / size));
      const rec = recs.find((r) => r.leaf_index === k);
      N(`leaf:${id}:${k}`, "leaf", p, 2.7, "", { k: `LOG ENTRY ${k}`, t: rec ? short(rec.sub) : `Entry ${k}`, rows: [["Log", R.accreditation.log_origin], ["Entry", rec ? `the passport ${rec.sub}` : "another entry, not a passport in this record"]] }, { reg: id, leaf: k, rec });
      if (k) E(`leaf:${id}:${k - 1}`, `leaf:${id}:${k}`, "chain");
    }
    reg.logMid = mid;
    const ops = [...new Set(recs.map((r) => r.operator))];
    ops.forEach((op, oi) => {
      const a = (oi / ops.length) * TAU + ri, rad = shell * 0.55, op3 = add(pos, [Math.cos(a) * rad, (oi % 2 ? 1 : -1) * 22, Math.sin(a) * rad]);
      const oid = `op:${id}:${op}`, mine = recs.filter((r) => r.operator === op);
      N(oid, "operator", op3, 5.5, op, { k: "OPERATOR", t: op, rows: [["Registrar", id], ["Passports", String(mine.length)]] }, { reg: id });
      E(id, oid);
      mine.forEach((r, pi) => {
        const m = mine.length, y = m === 1 ? 0 : 1 - (pi / (m - 1)) * 2, rr = Math.sqrt(Math.max(0, 1 - y * y)), th = pi * 2.4 + oi, k = 20 + m * 2.2;
        const p3 = add(op3, [Math.cos(th) * rr * k, y * k * 0.8, Math.sin(th) * rr * k]);
        N(`pp:${r.sub}`, "passport", p3, 4.3, short(r.sub).replace(/^smoke-(\d{4})\d*-\d+/, "smoke-$1…"), { k: "PASSPORT", t: short(r.sub), rows: [
          ["Name", r.sub], ["Registrar", id], ["Operator", op], ["Class", `${r.auth_class}, tier ${r.tier ?? "–"}`], ["May", (r.capabilities || []).join(", ")],
          ["Log entry", String(r.leaf_index)], ["Status bit", String(r.status_idx)], ...((r.chain_keys || []).length ? [["Acts through", `a chain of ${r.chain_keys.length} earlier keys`]] : [])] },
          { rec: r, reg: id, op: oid, verdict: null });
        E(oid, `pp:${r.sub}`); E(`pp:${r.sub}`, `leaf:${id}:${r.leaf_index}`, "faint");
      });
    });
  });
  const w = registry.witnesses[0];
  N("wit", "witness", [0, 210, -10], 6, "witness", { k: "WITNESS · SELF-DECLARED", t: "The network's own witness", rows: [["Operator", w.operator], ["Ed25519", cut(w.ed25519, 30)], ["Does", "cosigns each log's checkpoints, so a log cannot show two histories"]] });
  N("wit-open", "open", [72, 232, 30], 6, "open seat", { k: "OPEN SEAT", t: "An independent witness", rows: [["Needed for", "fork resistance: witnesses run by others"], ["Who", "anyone; the software is published"]] });
  for (const r of regs) { E(`leaf:${r.id}:${r.size - 1}`, "wit", "sign"); E(`leaf:${r.id}:${r.size - 1}`, "wit-open", "dash"); }
  N("you", "you", [0, -175, 360], 9, "", { k: "YOU · THIS TAB", t: "You, the verifier", rows: [["Holds", "the directory, checked against the root's two keys"], ["And", "each registrar's signed status list"], ["Contacts", "nobody while it checks"]] });
}

// ---------- camera: an orbit around a target, every part a spring ----------
const HOME = { yaw: 0.12, pitch: 0.26, dist: 1050 };
const cam = { yaw: new Spring(-0.9, 0.9), pitch: new Spring(0.26, 0.5), dist: new Spring(2600, 0.9), tx: new Spring(0, 0.6), ty: new Spring(0, 0.6), tz: new Spring(0, 0.6), vyaw: 0, auto: 0 };
const SPR = [cam.yaw, cam.pitch, cam.dist, cam.tx, cam.ty, cam.tz];
const PITCH = [-1.2, 1.2], DIST = [300, 1900];
let W = 0, H = 0, S = 1, CX = 0, CY = 0, CY0 = 0, CX0 = 0; const lift = new Spring(0, 0.6, 1);
function resize() {
  const dpr = Math.min(2, window.devicePixelRatio || 1); W = innerWidth; H = innerHeight;
  cv.width = Math.round(W * dpr); cv.height = Math.round(H * dpr); ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  const wide = W > 900; S = (wide ? Math.min(W * 0.6, H) : Math.min(W * 0.8, H * 0.6)) * 1.55;
  CX0 = W * (wide ? 0.46 : 0.5); CY0 = H * (wide ? 0.45 : 0.4);
}
let cy_, sy_, cp_, sp_, tx_, ty_, tz_, D_;
function prep() { const wide = W > 900; CY = CY0 - (wide ? 0 : lift.x * H); CX = CX0 + (wide ? lift.x * 1.6 * W - (1 - clamp(sheetPos.x, 0, 1)) * Math.min(200, sheet.offsetWidth / 2) : 0); const y = cam.yaw.x, p = cam.pitch.x; cy_ = Math.cos(y); sy_ = Math.sin(y); cp_ = Math.cos(p); sp_ = Math.sin(p); tx_ = cam.tx.x; ty_ = cam.ty.x; tz_ = cam.tz.x; D_ = cam.dist.x; }
function proj(x, y, z, out) {
  x -= tx_; y -= ty_; z -= tz_;
  const x1 = x * cy_ - z * sy_, z1 = x * sy_ + z * cy_, y2 = y * cp_ - z1 * sp_, z2 = y * sp_ + z1 * cp_, d = z2 + D_;
  if (d < 30) return false; out[0] = CX + (x1 * S) / d; out[1] = CY - (y2 * S) / d; out[2] = d; return true;
}
const fog = (d) => clamp(1.35 - (d - D_ + 420) / 900, 0.12, 1);
function flyTo(pos, dist, { pitch } = {}) {                              // always from wherever the camera is now
  cam.vyaw = 0; cam.auto = 0; idleAt = performance.now() + 7000;
  const r = RM.matches;
  for (const [s, v] of [[cam.tx, pos[0]], [cam.ty, pos[1]], [cam.tz, pos[2]], [cam.dist, dist]]) r ? ((s.x = v), s.stop()) : s.set(0.75, 1).go(v);
  if (pitch !== undefined) r ? ((cam.pitch.x = pitch), cam.pitch.stop()) : cam.pitch.set(0.75, 1).go(pitch);
}
const resetView = () => flyTo([0, 0, 0], HOME.dist, { pitch: HOME.pitch });
const zoomBy = (f) => { const t = clamp((cam.dist.on ? cam.dist.to : cam.dist.x) * f, DIST[0], DIST[1]); RM.matches ? (cam.dist.x = t) : cam.dist.set(0.35, 1).go(t); idleAt = performance.now() + 6000; };

// ---------- timeline: the record's own order ----------
const events = []; let step = 0, playing = false, playT = 0;
function buildEvents() {
  const lv = [], ch = [];
  for (const r of regs) for (let k = 0; k < r.size; k++) lv.push({ type: "leaf", reg: r.id, leaf: k, key: k / r.size + regs.indexOf(r) * 1e-4 });
  for (const r of regs) for (const d of r.deltas) ch.push({ type: "change", reg: r.id, seq: d.seq, idx: d.idx, on: d.new_status, key: d.seq + regs.indexOf(r) * 1e-4 });
  lv.sort((a, b) => a.key - b.key); ch.sort((a, b) => a.key - b.key); events.push(...lv, ...ch); step = events.length;
}
const live = () => step === events.length;
function applyStep(s) {
  step = clamp(s, 0, events.length);
  for (const r of regs) r.bits = live() ? new Uint8Array(r.bitsFinal) : new Uint8Array(r.list.bit_len);
  const seen = new Set();
  for (let i = 0; i < step; i++) { const e = events[i]; if (e.type === "leaf") seen.add(`${e.reg}:${e.leaf}`); else if (!live()) for (const ix of e.idx) byId[e.reg].bits[ix] = e.on ? 1 : 0; }
  for (const n of nodes) {
    if (n.kind === "leaf") n.shown = seen.has(`${n.reg}:${n.leaf}`);
    if (n.kind === "passport") { n.shown = seen.has(`${n.reg}:${n.rec.leaf_index}`); n.off = byId[n.reg].bits[n.rec.status_idx] === 1; }
  }
  renderTrack(); sayNow(); stats();
  $("#feedNote").textContent = live() ? "Newest first. Each line is one passport checked in this tab, now." : "Checks pause while the record replays; they run on the record as it stands now.";
}
function sayNow() {
  const el = $("#now"); let txt;
  if (live()) txt = "<b>Now</b> · the record as published · checks running";
  else if (step === 0) txt = "<b>Before the first entry</b>";
  else {
    const e = events[step - 1];
    if (e.type === "leaf") { const rec = byId[e.reg].recs.find((r) => r.leaf_index === e.leaf); txt = `<b>${e.reg} logs entry ${e.leaf}</b> · ${rec ? short(rec.sub) : "another entry"}`; }
    else { const who = e.idx.map((i) => byId[e.reg].used.get(i)).filter(Boolean).map(short); txt = `<b>${e.reg}, change ${e.seq}</b> · bit ${e.idx.join(", ")} ${e.on ? "set" : "cleared"}${who.length ? " · " + who.join(", ") + (e.on ? " switched off" : " back in service") : ""}`; }
  }
  el.innerHTML = txt; $("#track").setAttribute("aria-valuetext", el.textContent);
}

// ---------- drawing ----------
const P = [0, 0, 0], threads = [], labels = [];
function sphere(x, y, r, a) {                                             // a shaded ink sphere, still monochrome
  const g = ctx.createRadialGradient(x - r * 0.35, y - r * 0.4, r * 0.1, x, y, r);
  g.addColorStop(0, ink(0.6 * a)); g.addColorStop(0.55, ink(0.92 * a)); g.addColorStop(1, ink(a));
  ctx.fillStyle = g; ctx.beginPath(); ctx.arc(x, y, r, 0, TAU); ctx.fill();
}
const hidden = (n) => (n.kind === "leaf" || n.kind === "passport") && !n.shown;
function draw(dt) {
  prep();
  ctx.fillStyle = PAPER; ctx.fillRect(0, 0, W, H);
  for (const r of regs) {                                                 // the status lists, bit by bit
    const dim = r.dim ? 0.12 : 1, d = r.dust, bits = r.bits;
    for (let i = 0, n = bits.length; i < n; i++) {
      if (!proj(d[i * 3], d[i * 3 + 1], d[i * 3 + 2], P)) continue;
      const f = fog(P[2]) * dim;
      if (bits[i]) { ctx.fillStyle = ink(0.95 * f); ctx.beginPath(); ctx.arc(P[0], P[1], Math.max(1.9, 2.5 * (S / P[2])), 0, TAU); ctx.fill(); }
      else { const u = r.used.has(i), s = u ? 1.9 : 1.15; ctx.fillStyle = ink((u ? 0.62 : 0.3) * f); ctx.fillRect(P[0] - s / 2, P[1] - s / 2, s, s); }
    }
  }
  for (const n of nodes) {
    n.vis = proj(n.pos[0], n.pos[1], n.pos[2], P); n.sx = P[0]; n.sy = P[1]; n.depth = P[2]; n.sr = (n.r * S) / P[2];
    n.flash = Math.max(0, n.flash - dt / 0.9); n.dimmed = !!((n.reg && byId[n.reg].dim) || (n.kind === "registrar" && n.dim));
  }
  for (const n of nodes) if (n.ring) {                                    // directory epochs
    ctx.beginPath(); let on = false;
    for (let i = 0; i <= 120; i++) {
      const a = (i / 120) * TAU, x = Math.cos(a) * n.r, z = Math.sin(a) * n.r;
      if (!proj(x, z * Math.sin(n.tilt), z * Math.cos(n.tilt), P)) { on = false; continue; }
      on ? ctx.lineTo(P[0], P[1]) : ctx.moveTo(P[0], P[1]); on = true;
    }
    ctx.strokeStyle = ink((n.faded ? 0.2 : 0.55) + n.flash * 0.4); ctx.lineWidth = 1 + n.flash; ctx.setLineDash(n.faded ? [2, 4] : []); ctx.stroke(); ctx.setLineDash([]);
  }
  for (const e of edges) {
    e.lit = Math.max(0, e.lit - dt / 1.6);
    if (!e.a.vis || !e.b.vis || hidden(e.a) || hidden(e.b)) continue;
    const base = { faint: 0.05, chain: 0.42, dash: 0.3, sign: 0.22 }[e.kind] ?? 0.16;
    const f = Math.min(fog(e.a.depth), fog(e.b.depth)) * (e.a.dimmed || e.b.dimmed ? 0.25 : 1);
    ctx.strokeStyle = ink(Math.min(1, (base + e.lit * 0.9) * f)); ctx.lineWidth = 0.8 + e.lit * 1.8;
    ctx.setLineDash(e.kind === "dash" ? [3, 4] : []); ctx.beginPath(); ctx.moveTo(e.a.sx, e.a.sy); ctx.lineTo(e.b.sx, e.b.sy); ctx.stroke();
  }
  ctx.setLineDash([]);
  for (let i = threads.length - 1; i >= 0; i--) {                         // a real check travelling from you
    const t = threads[i]; t.t += dt / 0.65; const a = byId.you, b = t.p;
    if (t.t >= 1) { threads.splice(i, 1); t.done(); continue; }
    const k = 1 - Math.pow(1 - t.t, 3), x = a.sx + (b.sx - a.sx) * k, y = a.sy + (b.sy - a.sy) * k;
    ctx.strokeStyle = ink(0.8); ctx.lineWidth = 1.3; ctx.beginPath(); ctx.moveTo(a.sx, a.sy); ctx.lineTo(x, y); ctx.stroke();
    ctx.fillStyle = ink(1); ctx.beginPath(); ctx.arc(x, y, 3.2, 0, TAU); ctx.fill();
  }
  const order = nodes.filter((n) => n.vis && !n.ring && !hidden(n)).sort((a, b) => b.depth - a.depth);
  for (const n of order) {
    const f = fog(n.depth) * (n.dimmed ? 0.3 : 1), r = Math.max(n.kind === "leaf" ? 1.5 : 2.4, n.sr);
    if (n.flash > 0.02) { ctx.strokeStyle = ink(n.flash * 0.75 * f); ctx.lineWidth = 1.2; ctx.beginPath(); ctx.arc(n.sx, n.sy, r + 3 + (1 - n.flash) * 18, 0, TAU); ctx.stroke(); }
    ctx.lineWidth = 1.3; ctx.strokeStyle = ink(f);
    if (n.kind === "root" || n.kind === "registrar") sphere(n.sx, n.sy, r, f);
    else if (n.kind === "you") { ctx.fillStyle = PAPER; ctx.beginPath(); ctx.arc(n.sx, n.sy, r + 3, 0, TAU); ctx.fill(); ctx.stroke(); ctx.fillStyle = ink(1); ctx.beginPath(); ctx.arc(n.sx, n.sy, Math.max(2.2, r * 0.45), 0, TAU); ctx.fill(); }
    else if (n.kind === "open") { ctx.setLineDash([2, 3]); ctx.fillStyle = PAPER; ctx.beginPath(); ctx.arc(n.sx, n.sy, r, 0, TAU); ctx.fill(); ctx.stroke(); ctx.setLineDash([]); }
    else if (n.kind === "passport") {
      ctx.fillStyle = PAPER; ctx.beginPath(); ctx.arc(n.sx, n.sy, r, 0, TAU); ctx.fill(); ctx.stroke();
      if (n.off) { ctx.beginPath(); ctx.moveTo(n.sx - r * 0.72, n.sy + r * 0.72); ctx.lineTo(n.sx + r * 0.72, n.sy - r * 0.72); ctx.stroke(); }
      else { ctx.fillStyle = ink(f); ctx.beginPath(); ctx.arc(n.sx, n.sy, Math.max(1, r - 1.7), 0, TAU); ctx.fill(); }
    } else if (n.kind === "leaf") { ctx.fillStyle = n.rec ? ink(f) : PAPER; ctx.beginPath(); ctx.arc(n.sx, n.sy, r, 0, TAU); ctx.fill(); ctx.stroke(); }
    else { ctx.fillStyle = PAPER; ctx.beginPath(); ctx.arc(n.sx, n.sy, r, 0, TAU); ctx.fill(); ctx.stroke(); }
    if (n === sheetN || n === focusN) { ctx.strokeStyle = ink(0.9); ctx.lineWidth = 1; ctx.beginPath(); ctx.arc(n.sx, n.sy, r + 6, 0, TAU); ctx.stroke(); }
    const pri = n === focusN || n === sheetN ? 0 : n === hoverN ? 1 : { root: 2, registrar: 2, witness: 3, open: 3, operator: 4, passport: 5 }[n.kind];
    if (pri !== undefined && n.label && (n.kind !== "passport" || pri < 2 || n.sr > 7)) labels.push({ n, r, f, pri });
  }
  if (VIEW !== "points") charPass();
  // labels: most important first; one that would overlap another is left out (the hover pill still names it)
  labels.sort((a, b) => a.pri - b.pri || a.n.depth - b.n.depth); const placed = [];
  ctx.textAlign = "left"; ctx.textBaseline = "middle";
  for (const L of labels) {
    const n = L.n, big = n.kind === "registrar" || n.kind === "root";
    ctx.font = `${big ? 12.5 : 12}px ${MONO}`;
    const w = ctx.measureText(n.label).width, x = n.sx + L.r + 8, y = n.sy, box = [x - 2, y - 8, x + w + 2, y + 8];
    if (placed.some((q) => box[0] < q[2] && box[2] > q[0] && box[1] < q[3] && box[3] > q[1])) continue;
    placed.push(box); ctx.fillStyle = ink((n.kind === "operator" ? 0.64 : 0.92) * L.f); ctx.fillText(n.label, x, y);
  }
  labels.length = 0;
  const you = byId.you, yp = $("#youPill"); yp.hidden = !you.vis || you.sx < -20 || you.sx > W + 20 || you.sy < 70 || you.sy > H - 150;
  yp.style.transform = `translate(${clamp(you.sx, 120, W - 120)}px, ${you.sy - Math.max(9, you.sr) - 8}px) translate(-50%,-100%)`;
  const hp = $("#hoverPill");
  if (hoverN && hoverN.vis && !drag) { hp.hidden = false; hp.style.transform = `translate(${hoverN.sx}px, ${hoverN.sy - Math.max(6, hoverN.sr) - 8}px) translate(-50%,-100%)`; }
  else hp.hidden = true;
}

// ---------- drawn in characters: the frame above, sampled into cells and redrawn as text, braille dots or 1-bit dither ----------
let VIEW = "points";
const small = document.createElement("canvas"), sctx = small.getContext("2d", { willReadFrequently: true });
const charCv = document.createElement("canvas"), cctx = charCv.getContext("2d");   // the character layer, kept between frames
const RAMP = " .,:;-~=+*o#%@";                                  // light to dense, for ink on paper
const BAYER = [0, 8, 2, 10, 12, 4, 14, 6, 3, 11, 1, 9, 15, 7, 13, 5].map((v) => (v + 0.5) / 16);
let glyphW = null, dens = new Float32Array(0), charAt = 0, charKey = "";
function sampleTo(sw, sh) {                                       // the live frame, averaged down to sw × sh: 0 paper … 1 ink
  if (small.width !== sw || small.height !== sh) { small.width = sw; small.height = sh; }
  if (dens.length !== sw * sh) dens = new Float32Array(sw * sh);
  sctx.imageSmoothingEnabled = true; sctx.imageSmoothingQuality = "high";
  sctx.drawImage(cv, 0, 0, cv.width, cv.height, 0, 0, sw, sh);
  const px = sctx.getImageData(0, 0, sw, sh).data;
  const pl = (parseInt(PAPER.slice(1, 3), 16) + parseInt(PAPER.slice(3, 5), 16) + parseInt(PAPER.slice(5, 7), 16)) / 3, il = (rgb[0] + rgb[1] + rgb[2]) / 3, k = 1 / (il - pl);
  for (let i = 0, n = sw * sh; i < n; i++) { const v = ((px[i * 4] + px[i * 4 + 1] + px[i * 4 + 2]) / 3 - pl) * k; dens[i] = v < 0 ? 0 : v > 1 ? 1 : v; }
  return dens;
}
// Redrawn about twenty times a second (the camera and the checks still move at full rate underneath); in between the
// kept layer is copied, which costs almost nothing. A change of view, size or appearance redraws it at once.
function charPass() {
  const now = performance.now(), key = `${VIEW}|${cv.width}x${cv.height}|${INK}|${PAPER}`;
  if (key !== charKey || now - charAt > 50) { charKey = key; charAt = now; renderChars(); }
  ctx.save(); ctx.setTransform(1, 0, 0, 1, 0, 0); ctx.drawImage(charCv, 0, 0); ctx.restore();
}
function renderChars() {
  if (charCv.width !== cv.width || charCv.height !== cv.height) { charCv.width = cv.width; charCv.height = cv.height; }
  const c = cctx, dpr = cv.width / Math.max(1, W); c.setTransform(dpr, 0, 0, dpr, 0, 0);
  c.fillStyle = PAPER; c.fillRect(0, 0, W, H);
  if (VIEW === "text") {
    const fs = W < 700 ? 10 : 12; c.font = `${fs}px ${MONO}`; if (!glyphW || glyphW.fs !== fs) glyphW = { fs, w: c.measureText("M").width };
    const cw = glyphW.w, ch = Math.round(fs * 1.08), cols = Math.floor(W / cw), rows = Math.floor(H / ch), d = sampleTo(cols, rows);
    c.fillStyle = ink(0.92); c.textBaseline = "top"; c.textAlign = "left";
    for (let y = 0; y < rows; y++) {
      let line = ""; for (let x = 0; x < cols; x++) { const v = d[y * cols + x]; line += RAMP[Math.min(RAMP.length - 1, Math.floor(Math.pow(v, 0.7) * RAMP.length * 1.15))]; }
      c.fillText(line, 0, y * ch);
    }
  } else if (VIEW === "braille") {
    const dx = W < 700 ? 2.6 : 3, cols = Math.floor(W / dx), rows = Math.floor(H / dx), d = sampleTo(cols, rows), dot = dx * 0.62;
    c.fillStyle = ink(0.95); c.beginPath();
    for (let y = 0; y < rows; y++) for (let x = 0; x < cols; x++) {
      if (d[y * cols + x] <= BAYER[(y & 3) * 4 + (x & 3)] * 0.9) continue;
      c.rect(x * dx + (x % 2 ? 0.6 : 0), y * dx + (y % 4 === 3 ? 0.6 : 0), dot, dot);   // 2 × 4 cells, a hair apart
    }
    c.fill();
  } else if (VIEW === "dither") {
    const k = W < 700 ? 2 : 2.5, sw = Math.floor(W / k), sh = Math.floor(H / k), d = sampleTo(sw, sh);
    const img = sctx.createImageData(sw, sh), P2 = [parseInt(PAPER.slice(1, 3), 16), parseInt(PAPER.slice(3, 5), 16), parseInt(PAPER.slice(5, 7), 16)];
    for (let y = 0; y < sh; y++) for (let x = 0; x < sw; x++) {
      const i = y * sw + x, col = d[i] > BAYER[(y & 3) * 4 + (x & 3)] ? rgb : P2;
      img.data[i * 4] = col[0]; img.data[i * 4 + 1] = col[1]; img.data[i * 4 + 2] = col[2]; img.data[i * 4 + 3] = 255;
    }
    sctx.putImageData(img, 0, 0); c.imageSmoothingEnabled = false; c.drawImage(small, 0, 0, sw, sh, 0, 0, W, H); c.imageSmoothingEnabled = true;
  }
}

// ---------- checks (real) ----------
let verifier = null, NOW = 0, cursor = 0, order = [];
const times = []; let nValid = 0, nRefused = 0;
function bundle(rec, st) {
  return {
    claims: b64u(rec.claims), issuer_sig: { ed25519: rec.issuer_sig_ed25519, mldsa65: rec.issuer_sig_mldsa65 }, chain_keys: rec.chain_keys, hop_proofs: rec.hop_proofs,
    status_uri: st.uri, status_list: st.status_list_b64, status_len: st.bit_len, status_issued_at: st.issued_at, status_sig_ed25519: st.sig_ed25519, status_sig_mldsa65: st.sig_mldsa65,
    checkpoint: { origin: rec.log_origin, size: rec.checkpoint_size, root: rec.checkpoint_root }, checkpoint_sig: rec.checkpoint_sig, leaf_index: rec.leaf_index, inclusion_proof: rec.inclusion_proof,
    mandate_revocations: [], revoked_delegates: [],
    ...(rec.chain_parties?.length ? { chain_parties: rec.chain_parties } : {}),           // a chain its registrar bound (D-113)
  };
}
const median = (a) => { const s = [...a].sort((x, y) => x - y); return s.length ? s[Math.floor(s.length / 2)] : 0; };
function check(p, then) {
  if (!verifier || !live() || byId[p.reg].dim) return false;
  const t0 = performance.now(); let v;
  try { v = verifier.verify(bundle(p.rec, byId[p.reg].list), NOW); } catch { v = { verdict: "invalid", reason: "error" }; }
  const ms = performance.now() - t0;
  const reveal = () => {
    const ok = v.verdict === "valid"; p.verdict = ok ? "valid" : v.reason; p.flash = 1; byId.you.flash = 0.8; byId.root.flash = 0.6; byId[`epoch${CUR}`].flash = 0.7;
    for (const [a, b] of [[p.id, p.op], [p.op, p.reg], [`epoch${CUR}`, p.reg], [p.id, `leaf:${p.reg}:${p.rec.leaf_index}`]]) { const e = edgeOf(a, b); if (e) { e.lit = 1; e.a.flash = Math.max(e.a.flash, 0.5); e.b.flash = Math.max(e.b.flash, 0.5); } }
    times.push(ms); if (times.length > 300) times.shift(); ok ? nValid++ : nRefused++;
    const li = document.createElement("li"); if (!ok) li.className = "no";
    li.innerHTML = `<span class="n"></span><span class="v"></span><span class="t"></span>`;
    li.querySelector(".n").textContent = short(p.rec.sub);
    const vb = li.querySelector(".v"); vb.innerHTML = icon(ok ? "valid" : "revoked"); vb.append(ok ? "valid" : v.reason === "revoked" ? "switched off" : v.reason || "refused");
    li.querySelector(".t").textContent = `${p.reg} · ${new Date().toTimeString().slice(0, 8)} · ${ms < 10 ? ms.toFixed(1) : Math.round(ms)} ms`;
    const ol = $("#checks"); ol.prepend(li); while (ol.children.length > 5) ol.lastChild.remove();
    stats(); if (sheetN === p) fillSheet(p, true); then && then(v, ms);
  };
  RM.matches ? reveal() : threads.push({ p, t: 0, done: reveal });
  return true;
}
function stats() {
  const pps = nodes.filter((n) => n.kind === "passport" && n.shown && !byId[n.reg].dim);
  $("#sIn").textContent = pps.filter((n) => !n.off).length; $("#sOff").textContent = pps.filter((n) => n.off).length;
  $("#sChk").textContent = nValid + nRefused; $("#sMs").textContent = times.length ? `${median(times).toFixed(1)} ms` : "–";
}

// ---------- pointer: respond on press, 1:1 drag, momentum, rubber-band ----------
let hoverN = null, focusN = null, sheetN = null, drag = null, idleAt = 0;
const pointers = new Map();
function pick(x, y) {
  let best = null, bd = Infinity;
  for (const n of nodes) {
    if (!n.vis || n.ring || hidden(n)) continue;
    const d = (n.sx - x) ** 2 + (n.sy - y) ** 2, reach = Math.max(16, n.sr + 6) ** 2;
    if (d < reach && d < bd) { bd = d; best = n; }
  }
  return best;
}
const outOfPitch = () => cam.pitch.x < PITCH[0] || cam.pitch.x > PITCH[1];
cv.addEventListener("pointerdown", (e) => {
  try { cv.setPointerCapture(e.pointerId); } catch {} pointers.set(e.pointerId, [e.clientX, e.clientY]);
  for (const s of SPR) s.stop();                                           // grab it mid-flight: it stays where it is
  cam.vyaw = 0; cam.auto = 0; idleAt = performance.now() + 5000;
  if (pointers.size === 1) { drag = { x: e.clientX, y: e.clientY, t: performance.now(), moved: 0, vx: 0, vy: 0, raw: cam.pitch.x }; cv.classList.add("grabbing"); }
  else drag = null;
});
cv.addEventListener("pointermove", (e) => {
  if (pointers.has(e.pointerId)) {
    const prev = [...pointers.values()]; pointers.set(e.pointerId, [e.clientX, e.clientY]);
    if (pointers.size === 2) {                                               // pinch, 1:1, soft past the limits
      const now = [...pointers.values()], d0 = Math.hypot(prev[0][0] - prev[1][0], prev[0][1] - prev[1][1]), d1 = Math.hypot(now[0][0] - now[1][0], now[0][1] - now[1][1]);
      if (d0 && d1) { const t = cam.dist.x * (d0 / d1); cam.dist.x = t < DIST[0] ? DIST[0] - rubber(DIST[0] - t, 200) : t > DIST[1] ? DIST[1] + rubber(t - DIST[1], 400) : t; }
      return;
    }
  }
  if (drag) {
    const now = performance.now(), dx = e.clientX - drag.x, dy = e.clientY - drag.y, dt = Math.max(1, now - drag.t), k = 0.0052;
    drag.moved += Math.abs(dx) + Math.abs(dy);
    if (drag.moved < 6) return;                                              // a little hysteresis before it counts as a drag
    cam.yaw.x += dx * k; drag.raw += dy * k;
    cam.pitch.x = drag.raw < PITCH[0] ? PITCH[0] - rubber(PITCH[0] - drag.raw, 1) : drag.raw > PITCH[1] ? PITCH[1] + rubber(drag.raw - PITCH[1], 1) : drag.raw;
    drag.vx = 0.75 * ((dx * k) / dt) * 1000 + 0.25 * drag.vx; drag.vy = 0.75 * ((dy * k) / dt) * 1000 + 0.25 * drag.vy;
    drag.x = e.clientX; drag.y = e.clientY; drag.t = now; hoverN = null; cv.classList.remove("point");
  } else {
    const n = pick(e.clientX, e.clientY); hoverN = n; cv.classList.toggle("point", !!n);
    if (n) $("#hoverTxt").textContent = n.kind === "passport" ? `${n.label}${n.off ? " · switched off" : ""}` : n.info.t;
  }
});
function release(e) {
  pointers.delete(e.pointerId);
  if (!drag) { if (cam.dist.x < DIST[0] || cam.dist.x > DIST[1]) cam.dist.set(0.4, 1).go(clamp(cam.dist.x, DIST[0], DIST[1])); return; }
  cv.classList.remove("grabbing");
  if (drag.moved < 6) { const n = pick(e.clientX, e.clientY); if (n) select(n); else if (sheetN) closeSheet(); }
  else {
    const still = performance.now() - drag.t > 80;                           // a finger that stopped hands over no velocity
    if (!RM.matches && !still) cam.vyaw = drag.vx / 1000;                    // rad per ms, decays like a flick
    if (outOfPitch()) RM.matches ? (cam.pitch.x = clamp(cam.pitch.x, PITCH[0], PITCH[1])) : cam.pitch.set(0.4, 1).go(clamp(cam.pitch.x, PITCH[0], PITCH[1]), still ? 0 : drag.vy);
    else if (!RM.matches && !still && Math.abs(drag.vy) > 0.3) cam.pitch.set(0.5, 0.8).go(clamp(cam.pitch.x + project(drag.vy, 0.99) * 0.06, PITCH[0], PITCH[1]), drag.vy);
  }
  drag = null; idleAt = performance.now() + 5000;
}
cv.addEventListener("pointerup", release); cv.addEventListener("pointercancel", release);
cv.addEventListener("pointerleave", () => { if (!drag) hoverN = null; });
cv.addEventListener("wheel", (e) => { e.preventDefault(); zoomBy(Math.exp(e.deltaY * 0.0012)); }, { passive: false });
function physics(dt) {
  for (const s of SPR) s.step(dt);
  if (!drag && !cam.yaw.on) {
    cam.yaw.x += cam.vyaw * dt * 1000; cam.vyaw *= Math.pow(0.995, dt * 1000);         // momentum, decaying like a scroll
    if (!RM.matches && !tour.on && !sheetN && performance.now() > idleAt) { cam.auto = Math.min(1, cam.auto + dt / 2.5); cam.yaw.x += 0.06 * dt * cam.auto; }
  }
}

// ---------- details sheet: on a spring, and thrown away like a card ----------
const sheet = $("#sheet"), sheetPos = new Spring(1, 0.42, 1);              // 0 = open, 1 = away
const phone = () => matchMedia("(max-width: 760px)").matches;
function placeSheet() {
  const size = phone() ? sheet.offsetHeight + 24 : sheet.offsetWidth + 24;
  sheet.style.transform = phone() ? `translateY(${sheetPos.x * size}px)` : `translateX(${sheetPos.x * size}px)`;
  sheet.setAttribute("aria-hidden", String(sheetPos.x > 0.98));
}
function openSheet() { RM.matches ? ((sheetPos.x = 0), sheetPos.stop()) : sheetPos.set(0.42, 1).go(0); }
function closeSheet(v) { RM.matches ? ((sheetPos.x = 1), sheetPos.stop()) : sheetPos.set(0.42, 1).go(1, v); sheetN = null; focusN = null; }
const KIND_ICON = { root: "root", epoch: "epoch", registrar: "registrar", operator: "operator", leaf: "log", witness: "witness", open: "seat", you: "you" };
function fillSheet(n, keepAction) {
  $("#shK").textContent = n.info.k; $("#shT").textContent = n.info.t;
  $("#shIc").innerHTML = icon(n.kind === "passport" ? (n.off ? "revoked" : "valid") : KIND_ICON[n.kind] || "info");
  $("#shCopy").hidden = n.kind !== "passport"; if (n.kind === "passport") $("#shCopyTxt").textContent = n.rec.sub;
  if (!keepAction) setAct("idle");
  const dl = $("#shD"); dl.innerHTML = "";
  for (const [k, v] of n.info.rows) { const dt = document.createElement("dt"), dd = document.createElement("dd"); dt.textContent = k; dd.textContent = v; dl.append(dt, dd); }
  const vbox = $("#shV"); vbox.innerHTML = "";
  if (n.kind === "passport") {
    const d = document.createElement("div"); d.className = "verdict" + (n.verdict && n.verdict !== "valid" ? " no" : "");
    d.textContent = !n.verdict ? (live() ? "Not checked in this tab yet." : "Checks run on the record as it stands now: move the timeline to Now.")
      : n.verdict === "valid" ? "Checked in this tab: valid. A service would let this agent in."
      : n.verdict === "revoked" ? "Checked in this tab: switched off by its registrar. A service would refuse this agent." : `Checked in this tab: refused (${n.verdict}).`;
    vbox.append(d);
  }
  $("#shCheck").hidden = n.kind !== "passport";
}
function select(n) { sheetN = n; focusN = n; fillSheet(n); openSheet(); if (n.kind === "passport") check(n); }
$("#sheetX").addEventListener("click", () => closeSheet());
// the action button: idle → checking (held at least 450 ms, so it never flickers) → the verifier's own verdict → idle
const act = $("#shCheck"); let actTimer = 0;
function setAct(state, ok) { act.dataset.state = state; if (ok !== undefined) act.dataset.ok = String(ok); for (const el of act.querySelectorAll(".act__s")) el.setAttribute("aria-hidden", String(el.dataset.s !== state)); }
act.addEventListener("click", () => {
  if (!sheetN || act.dataset.state === "busy") return;
  const p = sheetN, until = performance.now() + (RM.matches ? 0 : 450); clearTimeout(actTimer); setAct("busy");
  const show = (ok, ic, txt) => { $("#actIc").innerHTML = icon(ic); $("#actTxt").textContent = txt; setAct("done", ok); $("#actLive").textContent = txt; actTimer = setTimeout(() => sheetN === p && setAct("idle"), 2800); };
  const ran = check(p, (v, ms) => setTimeout(() => {
    if (sheetN !== p) return;
    const t = `${ms < 10 ? ms.toFixed(1) : Math.round(ms)} ms`;
    v.verdict === "valid" ? show(true, "valid", `Valid · let in · ${t}`) : show(false, "revoked", `${v.reason === "revoked" ? "Switched off" : "Refused (" + (v.reason || "invalid") + ")"} · ${t}`);
  }, Math.max(0, until - performance.now())));
  if (!ran) show(false, "alert", live() ? "This registrar is hidden: show it first" : "Checks run at Now: move the timeline");
});
// the copy field: the copy icon turns into a check, and back
$("#shCopyBtn").addEventListener("click", async () => {
  const txt = $("#shCopyTxt").textContent; let ok = false;
  try { await navigator.clipboard.writeText(txt); ok = true; } catch { const r = document.createRange(); r.selectNodeContents($("#shCopyTxt")); const sl = getSelection(); sl.removeAllRanges(); sl.addRange(r); ok = document.execCommand?.("copy") ?? false; sl.removeAllRanges(); }
  swapIcon($("#shCopyIc"), ok ? "check" : "alert"); $("#shCopyLive").textContent = ok ? "Copied" : "Could not copy; select the name instead";
  setTimeout(() => { swapIcon($("#shCopyIc"), "copy"); $("#shCopyLive").textContent = ""; }, 1600);
});
$("#shFocus").addEventListener("click", () => sheetN && flyTo(sheetN.kind === "registrar" && sheetN.logMid ? sheetN.pos : sheetN.pos, ["passport", "leaf", "operator"].includes(sheetN.kind) ? 360 : 640));
let sd = null;
sheet.addEventListener("pointerdown", (e) => {
  if (e.target.closest("button,a,input")) return;
  if (phone() && sheet.scrollTop > 0) return;
  const p = phone() ? e.clientY : e.clientX;
  sd = { id: e.pointerId, s: p, x0: sheetPos.x, t: performance.now(), v: 0, last: p, moved: 0 };
  sheetPos.stop(); try { sheet.setPointerCapture(e.pointerId); } catch {}
});
sheet.addEventListener("pointermove", (e) => {
  if (!sd || e.pointerId !== sd.id) return;
  const p = phone() ? e.clientY : e.clientX, size = phone() ? sheet.offsetHeight + 24 : sheet.offsetWidth + 24, now = performance.now();
  sd.moved += Math.abs(p - sd.last);
  let x = sd.x0 + (p - sd.s) / size; if (x < 0) x = -rubber(-x, 1, 0.3);                    // resists past fully open
  sd.v = 0.7 * ((p - sd.last) / size / Math.max(1, now - sd.t)) * 1000 + 0.3 * sd.v; sd.last = p; sd.t = now;
  sheetPos.x = x;
});
const sheetUp = (e) => {
  if (!sd || e.pointerId !== sd.id) return;
  const rest = sheetPos.x + project(sd.v * 1000, 0.99) / 1000;                              // where the throw would land
  if (sd.moved < 4) { RM.matches ? (sheetPos.x = 0) : sheetPos.set(0.42, 1).go(0); }
  else if (rest > 0.45) closeSheet(sd.v);
  else RM.matches ? (sheetPos.x = 0) : sheetPos.set(0.42, Math.abs(sd.v) > 0.5 ? 0.8 : 1).go(0, sd.v);
  sd = null;
};
sheet.addEventListener("pointerup", sheetUp); sheet.addEventListener("pointercancel", sheetUp);

// ---------- the walk-through ----------
const tour = { on: false, i: 0, stops: [], timer: 0 };
function makeTour() {
  const r0 = regs[0], recs = r0.recs;
  const off = nodes.find((n) => n.kind === "passport" && n.reg === r0.id && r0.bitsFinal[n.rec.status_idx]);
  const good = nodes.find((n) => n.kind === "passport" && n.reg === r0.id && !r0.bitsFinal[n.rec.status_idx] && !(n.rec.chain_keys || []).length);
  const offAll = nodes.filter((n) => n.kind === "passport" && byId[n.reg].bitsFinal[n.rec.status_idx]).length;
  const later = (fn) => { clearTimeout(tour.timer); tour.timer = setTimeout(() => tour.on && fn(), RM.matches ? 0 : 950); };
  tour.stops = [
    { t: "The root", p: "A root signs one thing: the list of accredited registrars. It issues no passports and sees no traffic. This is the test root; the real one is made at the founding ceremony.", at: () => flyTo(byId.root.pos, 560, { pitch: 0.3 }), hl: "root" },
    { t: "The directory", p: `The directory names ${regs.length} registrars and is signed with both root keys. Epoch ${CUR} is current; the replaced epoch stays in the directory log. Your tab checks it against the root before it trusts anything else.`, at: () => flyTo(byId.root.pos, 780, { pitch: 0.55 }), hl: `epoch${CUR}` },
    { t: "A registrar", p: `${r0.id} is accredited in the directory. It onboards operators and issues their agents' passports: ${recs.length} here, from ${new Set(recs.map((r) => r.operator)).size} operators.`, at: () => flyTo(r0.pos, 640, { pitch: 0.25 }), hl: r0.id },
    { t: "Its log", p: `Every passport is appended to the registrar's log before it counts. These ${r0.size} beads are its entries; a filled bead is a passport in the record.`, at: () => flyTo(r0.logMid, 400, { pitch: 0.15 }), hl: `leaf:${r0.id}:${r0.size - 1}` },
    { t: "Its status list", p: `${r0.list.bit_len.toLocaleString("en")} points, one for each bit of the list the registrar signs. The dark points are set: those passports are switched off. Verifiers keep a copy and read it offline.`, at: () => flyTo(r0.pos, 840, { pitch: 0.7 }), hl: r0.id },
    { t: "You, the verifier", p: "This tab holds the directory and the signed lists. Watch: it checks a passport now, here, without contacting anyone.", at: () => { focusN = good; flyTo(good.pos, 520, { pitch: 0.2 }); later(() => check(good)); }, hl: "you" },
    { t: "The off switch", p: `This agent's registrar set its bit. Every verifier that holds the list now refuses it, everywhere, without asking anyone. ${offAll} passports in this record are switched off.`, at: () => { focusN = off; flyTo(off.pos, 420, { pitch: 0.2 }); later(() => check(off)); }, hl: null },
  ];
}
function makeLadder() {
  const box = $("#ladder"); box.innerHTML = "";
  tour.stops.forEach((s, i) => { const b = document.createElement("button"); b.type = "button"; b.setAttribute("aria-label", `Stop ${i + 1}: ${s.t}`); b.innerHTML = "<i></i><span></span>"; b.querySelector("span").textContent = s.t; b.addEventListener("click", () => tourShow(i)); box.append(b); });
}
function tourShow(i) {
  tour.i = clamp(i, 0, tour.stops.length - 1); const s = tour.stops[tour.i];
  [...$("#ladder").children].forEach((b, j) => (j === tour.i ? b.setAttribute("aria-current", "step") : b.removeAttribute("aria-current")));
  $("#capN").textContent = `${tour.i + 1} / ${tour.stops.length}`; $("#capT").textContent = s.t; $("#capP").textContent = s.p;
  $("#capBack").disabled = tour.i === 0; $("#capNext").textContent = tour.i === tour.stops.length - 1 ? "Finish" : "Next";
  focusN = null; if (!live()) applyStep(events.length);
  s.at(); if (s.hl && byId[s.hl]) byId[s.hl].flash = 1;
}
function tourStart() { tour.on = true; RM.matches ? (lift.x = 0.1) : lift.go(0.1); $("#caption").hidden = false; $("#tourBtn").setAttribute("aria-pressed", "true"); closeSheet(); setPlaying(false); tourShow(0); $("#capNext").focus({ preventScroll: true }); }
function tourEnd() { tour.on = false; RM.matches ? (lift.x = 0) : lift.go(0); clearTimeout(tour.timer); $("#caption").hidden = true; $("#tourBtn").setAttribute("aria-pressed", "false"); focusN = null; resetView(); $("#tourBtn").focus({ preventScroll: true }); }
$("#tourBtn").addEventListener("click", () => (tour.on ? tourEnd() : tourStart()));
$("#capNext").addEventListener("click", () => (tour.i === tour.stops.length - 1 ? tourEnd() : tourShow(tour.i + 1)));
$("#capBack").addEventListener("click", () => tourShow(tour.i - 1));
$("#capExit").addEventListener("click", tourEnd);

// ---------- controls ----------
$("#aboutBtn").addEventListener("click", () => { const a = $("#about"), on = a.hidden; a.hidden = !on; $("#aboutBtn").setAttribute("aria-expanded", String(on)); });
$("#feedToggle").addEventListener("click", () => { const f = $("#feed"), closed = !f.classList.contains("closed"); f.classList.toggle("closed", closed); $("#feedToggle").textContent = closed ? "Show" : "Hide"; $("#feedToggle").setAttribute("aria-expanded", String(!closed)); });
$("#zIn").addEventListener("click", () => zoomBy(0.78)); $("#zOut").addEventListener("click", () => zoomBy(1.28)); $("#zReset").addEventListener("click", resetView);
document.addEventListener("pointerdown", (e) => { const b = e.target.closest(".btn,.chip,.play"); if (b) b.classList.add("is-down"); });   // the press shows on the press
addEventListener("pointerup", () => document.querySelectorAll(".is-down").forEach((b) => b.classList.remove("is-down")));
addEventListener("pointercancel", () => document.querySelectorAll(".is-down").forEach((b) => b.classList.remove("is-down")));
const findIn = $("#find"), findList = $("#findList"); let hits = [], sel = -1;
function renderHits() {
  findList.innerHTML = "";
  hits.forEach((n, i) => { const li = document.createElement("li"), b = document.createElement("button"); b.type = "button"; b.setAttribute("role", "option"); b.setAttribute("aria-selected", String(i === sel)); b.textContent = n.rec.sub; b.addEventListener("click", () => choose(n)); li.append(b); findList.append(li); });
  findList.classList.toggle("on", hits.length > 0);
}
function choose(n) { findList.classList.remove("on"); findIn.value = ""; hits = []; findIn.blur(); if (!live()) applyStep(events.length); flyTo(n.pos, 360, { pitch: 0.2 }); select(n); }
findIn.addEventListener("input", () => { const q = findIn.value.trim().toLowerCase(); hits = q ? nodes.filter((n) => n.kind === "passport" && n.rec.sub.toLowerCase().includes(q)).slice(0, 12) : []; sel = hits.length ? 0 : -1; renderHits(); });
findIn.addEventListener("keydown", (e) => {
  if (e.key === "ArrowDown") { sel = Math.min(hits.length - 1, sel + 1); renderHits(); e.preventDefault(); }
  if (e.key === "ArrowUp") { sel = Math.max(0, sel - 1); renderHits(); e.preventDefault(); }
  if (e.key === "Enter" && hits[sel]) choose(hits[sel]);
  if (e.key === "Escape") { findIn.value = ""; hits = []; renderHits(); findIn.blur(); }
});
findIn.addEventListener("blur", () => setTimeout(() => findList.classList.remove("on"), 150));
addEventListener("keydown", (e) => {
  if (e.target.closest("input")) return;
  const k = e.key;
  if (k === "Escape") { if (!$("#about").hidden) $("#aboutBtn").click(); else if (tour.on) tourEnd(); else if (sheetN) closeSheet(); return; }
  if (e.target.closest("#track") || e.target.closest("button")) { if (k !== " ") return; if (e.target.closest("button")) return; }
  if (k === "ArrowLeft" || k === "ArrowRight") { const d = k === "ArrowLeft" ? -0.35 : 0.35; RM.matches ? (cam.yaw.x += d) : cam.yaw.set(0.4, 1).go((cam.yaw.on ? cam.yaw.to : cam.yaw.x) + d); idleAt = performance.now() + 6000; e.preventDefault(); }
  if (k === "ArrowUp" || k === "ArrowDown") { const t = clamp((cam.pitch.on ? cam.pitch.to : cam.pitch.x) + (k === "ArrowUp" ? 0.2 : -0.2), PITCH[0], PITCH[1]); RM.matches ? (cam.pitch.x = t) : cam.pitch.set(0.4, 1).go(t); e.preventDefault(); }
  if (k === "+" || k === "=") zoomBy(0.8); if (k === "-" || k === "_") zoomBy(1.25); if (k === "0") resetView();
  if (k === " ") { setPlaying(!playing); e.preventDefault(); }
});
// segmented controls: a pill slides under the choice on a spring, from where it is (arrow keys move the choice)
const segs = [];
function makeSeg(box, opts, start, onChoose) {
  const sg = { box, pill: box.querySelector(".seg__pill"), x: new Spring(0, 0.35, 0.85), w: new Spring(0, 0.35, 0.85), opts: [], i: start };
  sg.opts = opts.map((o, i) => {
    const b = document.createElement("button"); b.type = "button"; b.setAttribute("role", "radio"); b.setAttribute("aria-label", o.label);
    b.innerHTML = `<span class="seg__l"></span><span class="seg__s" aria-hidden="true"></span>`; b.querySelector(".seg__l").textContent = o.label; b.querySelector(".seg__s").textContent = o.short || o.label;
    b.setAttribute("aria-checked", String(i === start)); b.tabIndex = i === start ? 0 : -1;
    b.addEventListener("click", () => sg.choose(i, true));
    b.addEventListener("keydown", (e) => { const d = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 }[e.key]; if (!d) return; e.preventDefault(); const j = (i + d + opts.length) % opts.length; sg.choose(j, true); sg.opts[j].b.focus(); });
    box.append(b); return { ...o, b };
  });
  sg.choose = (i, user) => {
    sg.i = i; sg.opts.forEach((o, j) => { o.b.setAttribute("aria-checked", String(i === j)); o.b.tabIndex = i === j ? 0 : -1; });
    const b = sg.opts[i].b; RM.matches ? ((sg.x.x = b.offsetLeft), (sg.w.x = b.offsetWidth)) : (sg.x.go(b.offsetLeft), sg.w.go(b.offsetWidth));
    onChoose(sg.opts[i], user);
  };
  sg.sync = () => { const b = sg.opts[sg.i].b; sg.x.x = sg.x.to = b.offsetLeft; sg.w.x = sg.w.to = b.offsetWidth; sg.x.on = sg.w.on = false; sg.place(); };
  sg.place = () => { sg.pill.style.transform = `translateX(${sg.x.x}px)`; sg.pill.style.width = `${Math.max(0, sg.w.x)}px`; };
  sg.step = (dt) => { sg.x.step(dt); sg.w.step(dt); sg.place(); };
  requestAnimationFrame(sg.sync); segs.push(sg); return sg;
}
function filters() {
  const opts = [{ id: null, label: "All registrars", short: "All" }, ...regs.map((r) => ({ id: r.id, label: `${r.id} · ${r.recs.length}`, short: `${r.id.replace("registrar-", "r-")} · ${r.recs.length}` }))];
  makeSeg($("#filters"), opts, 0, (o, user) => {
    for (const r of regs) r.dim = !!o.id && r.id !== o.id; stats();
    if (user) o.id ? flyTo(byId[o.id].pos, 760, { pitch: 0.3 }) : resetView();
  });
  const views = [{ id: "points", label: "Points" }, { id: "text", label: "Text" }, { id: "braille", label: "Braille" }, { id: "dither", label: "Dither" }];
  let saved = "points"; try { saved = localStorage.getItem("ainra-world-view") || "points"; } catch { /* storage unavailable */ }
  const start = Math.max(0, views.findIndex((v) => v.id === saved)); VIEW = views[start].id;
  makeSeg($("#viewSeg"), views, start, (o) => { VIEW = o.id; try { localStorage.setItem("ainra-world-view", o.id); } catch { /* not kept */ } });
}

// ---------- the timeline: the knob follows the finger and can be grabbed mid-replay ----------
const track = $("#track");
function renderTrack() { const f = events.length ? step / events.length : 1; $("#fill").style.width = `${f * 100}%`; $("#knob").style.left = `${f * 100}%`; track.setAttribute("aria-valuemax", String(events.length)); track.setAttribute("aria-valuenow", String(step)); }
function ticks() { const t = $("#ticks"); events.forEach((e, i) => { const d = document.createElement("i"); if (e.type === "change") d.className = "ch"; d.style.left = `${((i + 1) / events.length) * 100}%`; t.append(d); }); }
const stepAt = (x) => { const r = track.getBoundingClientRect(); return Math.round(clamp((x - r.left) / r.width, 0, 1) * events.length); };
track.addEventListener("pointerdown", (e) => { try { track.setPointerCapture(e.pointerId); } catch {} track.classList.add("drag"); setPlaying(false); applyStep(stepAt(e.clientX)); });
track.addEventListener("pointermove", (e) => { if (track.classList.contains("drag")) applyStep(stepAt(e.clientX)); });
const trackUp = () => track.classList.remove("drag"); track.addEventListener("pointerup", trackUp); track.addEventListener("pointercancel", trackUp);
track.addEventListener("keydown", (e) => {
  const m = { ArrowRight: 1, ArrowUp: 1, ArrowLeft: -1, ArrowDown: -1 }[e.key];
  if (m) { setPlaying(false); applyStep(step + m); e.preventDefault(); }
  if (e.key === "Home") { setPlaying(false); applyStep(0); e.preventDefault(); } if (e.key === "End") { applyStep(events.length); e.preventDefault(); }
});
function setPlaying(on) {
  playing = on; const b = $("#play"); b.setAttribute("aria-pressed", String(on)); b.setAttribute("aria-label", on ? "Pause the replay" : "Replay the record");
  swapIcon($("#playIc"), on ? "pause" : "play");
  if (on && live()) applyStep(0);
}
$("#play").addEventListener("click", () => setPlaying(!playing));

// ---------- boot ----------
async function bootUp() {
  readTheme(); bootArt(); paintIcons(); swapIcon($("#playIc"), "play"); swapIcon($("#shCopyIc"), "copy");
  stepOn("record", "Reading the published record", 6);
  let done = 0; const tick = (x) => { done++; progress(6 + (done / 6) * 34); return x; };
  const sdkP = import("../vendor/ainra-sdk.js").then(tick);
  const [index, roots, directory, epochs, registry] = await Promise.all(["index", "roots", "directory", "epochs", "registry"].map((f) => getJSON(`net/${f}.json`).then(tick)));
  stepOk("record");
  stepOn("lists", `Reading ${registry.registrars.length} signed status lists`, 42);
  const lists = {}; let li = 0;
  for (const R of registry.registrars) {
    const [list, deltas] = await Promise.all([getJSON(`net/registrars/${R.registrar}/status/current.json`), getJSON(`net/registrars/${R.registrar}/status/deltas.json`)]);
    lists[R.registrar] = { list, bits: await bitsOf(list), deltas: deltas.deltas };
    progress(42 + (++li / registry.registrars.length) * 20);
  }
  const bitsTotal = Object.values(lists).reduce((a, l) => a + l.list.bit_len, 0);
  boot.querySelector('li[data-s="lists"]').textContent = `${registry.registrars.length} signed status lists, ${bitsTotal.toLocaleString("en")} bits`;
  stepOk("lists");
  stepOn("verifier", "Checking the directory against the root's two keys", 66);
  const sdk = await sdkP;
  await new Promise((r) => setTimeout(r, 40));                                // let the step paint before the work
  verifier = sdk.Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh, "F1");
  if (!verifier) throw new Error("the published directory does not verify against the published root keys");
  NOW = registry.generated_window?.verified_at;
  if (!Number.isInteger(NOW)) throw new Error("the record does not state its time");
  stepOk("verifier");
  stepOn("world", "Placing every part", 86);
  build({ index, roots, directory, epochs, registry, lists }); buildEvents(); filters(); ticks(); makeTour(); makeLadder(); resize();
  applyStep(events.length);
  order = nodes.filter((n) => n.kind === "passport");
  for (let i = order.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [order[i], order[j]] = [order[j], order[i]]; }
  stepOk("world"); progress(100); $("#bootStep").textContent = "Ready";
  setTimeout(() => boot.classList.add("done"), RM.matches ? 0 : 260);
  // arrive: the world comes in from afar on a spring (only a cross-fade under reduced motion)
  if (RM.matches) { cam.yaw.x = HOME.yaw; cam.dist.x = HOME.dist; } else { cam.yaw.set(1.5, 1).go(HOME.yaw); cam.dist.set(1.3, 1).go(HOME.dist); }
  idleAt = performance.now() + 5000;
  let last = performance.now(), nextCheck = last + 1800;
  const frame = (now) => {
    const dt = Math.min(0.05, (now - last) / 1000); last = now;
    if (playing && !document.hidden) { playT += dt; if (playT > (RM.matches ? 0.9 : 0.42)) { playT = 0; applyStep(step + 1); if (live()) setPlaying(false); } }
    if (!document.hidden && now >= nextCheck && live() && !tour.on) { check(order[cursor++ % order.length]); nextCheck = now + (RM.matches ? 2600 : 1300); }
    physics(dt); lift.step(dt); sheetPos.step(dt); for (const sg of segs) sg.step(dt); placeSheet(); draw(dt);
    requestAnimationFrame(frame);
  };
  requestAnimationFrame(frame);
}
const narrowFind = () => { $("#find").placeholder = innerWidth <= 520 ? "Find" : "Find a passport"; };
narrowFind();
addEventListener("resize", () => { readTheme(); narrowFind(); if (nodes.length) { resize(); placeSheet(); for (const sg of segs) sg.sync(); } });
bootUp().catch((e) => { console.info("[world] did not start:", e); bootFail(e?.message || String(e)); });
