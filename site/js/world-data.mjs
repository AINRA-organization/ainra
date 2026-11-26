// SPDX-License-Identifier: Apache-2.0 OR MIT
// AINRA World, the record. Everything the page shows comes from here, and everything here comes from the published
// record under net/ and from the verifier the site ships. No drawing and no DOM in this file.
//
//   parts, counts      net/index.json, net/roots.json, net/directory.json, net/epochs.json, net/registry.json
//   status bits        each registrar's signed status list (status/current.json), inflated in the tab
//   the log's tree     the shape RFC 6962 gives a log of that size; a passport's path is its own inclusion proof
//   order and dates    each passport's log position and issue date, each status change's sequence and date, each
//                      directory epoch's date, all as the record states them
//   verdicts           vendor/ainra-sdk.js in this tab, against the published directory and roots, at the record's time

const fromB64u = (s) => { const b = s.replace(/-/g, "+").replace(/_/g, "/"); return Uint8Array.from(atob(b.padEnd(Math.ceil(b.length / 4) * 4, "=")), (c) => c.charCodeAt(0)); };
const toB64u = (s) => btoa(String.fromCharCode(...new TextEncoder().encode(s))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

export async function getJSON(url) {
  const c = new AbortController(), t = setTimeout(() => c.abort(), 20000);
  try { const r = await fetch(url, { signal: c.signal, cache: "no-cache" }); if (!r.ok) throw new Error(`${url} answered HTTP ${r.status}`); return await r.json(); }
  catch (e) { throw new Error(e.name === "AbortError" ? `${url} did not answer in 20 seconds` : e.message); }
  finally { clearTimeout(t); }
}

// A status list is a deflated bit string; bit i is byte i>>3, bit i&7.
export async function bitsOf(st) {
  if (typeof DecompressionStream === "undefined") throw new Error("this browser cannot inflate the status list");
  const p = new Uint8Array(await new Response(new Blob([fromB64u(st.status_list_b64)]).stream().pipeThrough(new DecompressionStream("deflate"))).arrayBuffer());
  const out = new Uint8Array(st.bit_len); for (let i = 0; i < st.bit_len; i++) out[i] = (p[i >> 3] >> (i & 7)) & 1; return out;
}

// ---------- the log's tree (RFC 6962, section 2.1) ----------
// A node is the range of leaves [lo, hi) it covers. A tree of n leaves splits at the largest power of two below n.
const splitAt = (n) => { let k = 1; while (k * 2 < n) k *= 2; return k; };
export const levelOf = (lo, hi) => Math.ceil(Math.log2(hi - lo));
export function treeNodes(n) {                                          // every node of a tree of n leaves, leaves included
  const out = []; const walk = (lo, hi) => { out.push([lo, hi]); if (hi - lo > 1) { const k = splitAt(hi - lo); walk(lo, lo + k); walk(lo + k, hi); } };
  if (n > 0) walk(0, n); return out;
}
export function auditPath(m, n) {                                       // the siblings a proof for leaf m carries, deepest first
  const path = []; const walk = (lo, hi) => { if (hi - lo <= 1) return; const k = splitAt(hi - lo), mid = lo + k; if (m < mid) { walk(lo, mid); path.push([mid, hi]); } else { walk(mid, hi); path.push([lo, mid]); } };
  walk(0, n); return path;
}
export function climb(m, n) {                                           // the nodes from leaf m up to the tree's head
  const up = []; const walk = (lo, hi) => { if (hi - lo > 1) { const k = splitAt(hi - lo), mid = lo + k; m < mid ? walk(lo, mid) : walk(mid, hi); } up.push([lo, hi]); };
  walk(0, n); return up;
}

// ---------- reading the record ----------
export async function loadRecord(base, step) {
  step("record", "Reading the published record", 4);
  let done = 0; const tick = (x) => { step(null, null, 4 + (++done / 7) * 32); return x; };
  const sdkP = import("../vendor/ainra-sdk.js").then(tick);
  const [index, roots, directory, epochs, registry, published] = await Promise.all(["index", "roots", "directory", "epochs", "registry", "published"].map((f) => getJSON(`${base}/${f}.json`).then(tick)));
  step("record", null, 38, true);
  step("lists", `Reading ${registry.registrars.length} signed status lists`, 40);
  const lists = {}; let li = 0;
  for (const R of registry.registrars) {
    const [list, deltas] = await Promise.all([getJSON(`${base}/registrars/${R.registrar}/status/current.json`), getJSON(`${base}/registrars/${R.registrar}/status/deltas.json`)]);
    lists[R.registrar] = { list, bits: await bitsOf(list), deltas: deltas.deltas };
    step(null, null, 40 + (++li / registry.registrars.length) * 22);
  }
  step("lists", null, 62, true);
  step("verifier", "Checking the directory against the root's two keys", 66);
  const sdk = await sdkP;
  await new Promise((r) => setTimeout(r, 30));                          // let the step paint before the work
  const verifier = sdk.Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh, "F1");
  if (!verifier) throw new Error("the published directory does not verify against the published root keys");
  const now = registry.generated_window?.verified_at;
  if (!Number.isInteger(now)) throw new Error("the record does not state its time");
  step("verifier", null, 84, true);
  return { index, roots, directory, epochs, registry, published, lists, verifier, now };
}

// What the verifier is handed for one passport: its record and its registrar's signed status list, nothing else.
function bundle(rec, st) {
  return {
    claims: toB64u(rec.claims), issuer_sig: { ed25519: rec.issuer_sig_ed25519, mldsa65: rec.issuer_sig_mldsa65 }, chain_keys: rec.chain_keys, hop_proofs: rec.hop_proofs,
    status_uri: st.uri, status_list: st.status_list_b64, status_len: st.bit_len, status_issued_at: st.issued_at, status_sig_ed25519: st.sig_ed25519, status_sig_mldsa65: st.sig_mldsa65,
    checkpoint: { origin: rec.log_origin, size: rec.checkpoint_size, root: rec.checkpoint_root }, checkpoint_sig: rec.checkpoint_sig, leaf_index: rec.leaf_index, inclusion_proof: rec.inclusion_proof,
    mandate_revocations: [], revoked_delegates: [],
    ...(rec.chain_parties?.length ? { chain_parties: rec.chain_parties } : {}),           // a chain its registrar bound (D-113)
  };
}
// One real check. Returns the verifier's own answer and how long it took here.
export function runCheck(R, rec, list) {
  const t0 = performance.now(); let v;
  try { v = R.verifier.verify(bundle(rec, list), R.now); } catch (e) { console.warn("the verifier threw:", e); v = { verdict: "invalid", reason: "error" }; }
  return { ok: v.verdict === "valid", reason: v.verdict === "valid" ? null : (v.reason || "refused"), ms: performance.now() - t0 };
}

// ---------- the world's parts, from the record ----------
export const short = (sub) => sub.split(":").slice(3).join(":") || sub;
const cut = (s, n = 26) => (s && s.length > n ? s.slice(0, n) + "…" : s || "");
const TAU = Math.PI * 2, GOLD = 2.399963229728653;
const day = (t) => new Date(t * 1000).toISOString().slice(0, 10);

// Layout, in world units, y up. The root is the centre. The current directory epoch is the ring the registrars stand
// on. Beyond each registrar lies its status list as a flat spiral of bits (bit 0 at the centre, later bits further
// out), and above that its log as a tree: leaves in log order, each pair joined upward to the signed head.
export function buildWorld(R) {
  const { roots, directory, epochs, registry, lists } = R;
  const parts = [], byId = {}, links = [], regs = [];
  const P = (id, kind, pos, r, label, info, extra = {}) => { const n = { id, kind, pos, r, label, info, flash: 0, shown: true, ...extra }; parts.push(n); byId[id] = n; return n; };
  const L = (a, b, kind = "base") => { const l = { a: byId[a], b: byId[b], kind, lit: 0 }; links.push(l); return l; };
  const CUR = directory.epoch, RING = 220;

  P("root", "root", [0, 0, 0], 15, "root", { k: "ROOT · TEST, BEFORE THE CEREMONY", t: "The root", rows: [["Ed25519", cut(roots.root_ed25519)], ["SLH-DSA", cut(roots.root_slh)], ["Signs", "one thing: the registrar directory"], ["Issues", "no passports, sees no traffic"]] });
  const eps = epochs.epochs;
  eps.forEach((ep, i) => {
    const cur = ep.epoch === CUR;
    P(`epoch${ep.epoch}`, "epoch", [0, 0, 0], cur ? RING : 70 + i * 36, `epoch ${ep.epoch}`, {
      k: `DIRECTORY EPOCH ${ep.epoch}`, t: cur ? `The directory, epoch ${ep.epoch} (current)` : `The directory, epoch ${ep.epoch} (replaced)`,
      rows: [["Signed", `${day(ep.issued_at)} by the root's two keys`], ["Digest", cut(ep.digest)], ["Names", cur ? `${directory.entries.length} registrars` : "kept in the directory's own log"]] }, { cur, date: ep.issued_at, epoch: ep.epoch, labelAt: [-(cur ? RING : 70 + i * 36) * 0.7071, 0, (cur ? RING : 70 + i * 36) * 0.7071] });
  });

  const nReg = registry.registrars.length;
  registry.registrars.forEach((G, ri) => {
    const id = G.registrar, recs = G.records.map((x) => x.record), Li = lists[id];
    const ang = (ri / nReg) * TAU + (nReg === 2 ? 0 : -Math.PI / 2), out = [Math.cos(ang), 0, Math.sin(ang)], side = [-out[2], 0, out[0]];
    const pos = [out[0] * RING, 0, out[2] * RING];
    const size = Math.max(...recs.map((r) => r.checkpoint_size || 0)), n = Li.list.bit_len;
    const discR = 132, c = discR / Math.sqrt(n), centre = [out[0] * (RING + 190), -70, out[2] * (RING + 190)];
    // the status list: bit i always sits at the same place on the spiral
    const bitPos = new Float32Array(n * 3);
    for (let i = 0; i < n; i++) { const rr = c * Math.sqrt(i + 0.5), th = i * GOLD; bitPos[i * 3] = centre[0] + Math.cos(th) * rr; bitPos[i * 3 + 1] = centre[1]; bitPos[i * 3 + 2] = centre[2] + Math.sin(th) * rr; }
    // the log: leaves in a row above the list, the tree rising from them
    const gap = Math.min(22, (discR * 1.9) / Math.max(1, size - 1)), y0 = 36, lift = 40;
    const leafX = (k) => (k - (size - 1) / 2) * gap;
    const at = (lo, hi) => { const x = (leafX(lo) + leafX(hi - 1)) / 2, lv = levelOf(lo, hi); return [centre[0] + out[0] * x, y0 + lv * lift, centre[2] + out[2] * x]; };   // the row runs outward, so it faces a reader standing in front
    const reg = P(id, "registrar", pos, 9, id, { k: "REGISTRAR · ACCREDITED IN THE DIRECTORY", t: id, rows: [
      ["Issuer key", `Ed25519 ${cut(G.accreditation.issuer_key.ed25519, 20)} + ML-DSA-65`], ["Log", `${G.accreditation.log_origin}, ${size} entries`],
      ["Status list", `${n.toLocaleString("en")} bits, change ${G.status_seq}`], ["Passports", `${recs.length} issued, ${recs.filter((r) => Li.bits[r.status_idx]).length} switched off`]] },
      { out, side, centre, discR, size, recs, at, bitPos, list: Li.list, deltas: Li.deltas, bitsFinal: Li.bits, bits: new Uint8Array(Li.bits), used: new Map(recs.map((r) => [r.status_idx, r])), dim: false });
    regs.push(reg); L("root", id, "sign");
    P(`list:${id}`, "list", centre, 7, "status list", { k: "STATUS LIST · SIGNED BY THE REGISTRAR", t: `${id}'s status list`, rows: [["Bits", n.toLocaleString("en")], ["Set now", `${Li.bits.reduce((a, b) => a + b, 0)} (each is a passport switched off)`], ["Issued", day(Li.list.issued_at)], ["Signed", "Ed25519 + ML-DSA-65"], ["Reads as", "bit 0 at the centre, later bits further out"]] }, { reg: id, labelAt: [centre[0], centre[1], centre[2] + discR + 14] });
    for (const [lo, hi] of treeNodes(size)) {
      const leaf = hi - lo === 1, rec = leaf ? recs.find((r) => r.leaf_index === lo) : null, nid = `t:${id}:${lo}:${hi}`, head = lo === 0 && hi === size;
      if (rec) {
        P(`pp:${rec.sub}`, "passport", at(lo, hi), 4.4, short(rec.sub).replace(/^smoke-(\d{4})\d*-\d+/, "smoke-$1…"), { k: "PASSPORT", t: short(rec.sub), rows: [
          ["Name", rec.sub], ["Registrar", id], ["Operator", rec.operator], ["Class", `${rec.auth_class}, tier ${rec.tier ?? "–"}`], ["May", (rec.capabilities || []).join(", ")],
          ["Issued", day(rec.issued_at)], ["Log entry", `${rec.leaf_index} of ${rec.checkpoint_size}`], ["Status bit", String(rec.status_idx)],
          ...((rec.chain_keys || []).length ? [["Acts through", `a chain of ${rec.chain_keys.length} earlier keys`]] : [])] },
          { rec, reg: id, leaf: lo, tid: nid, verdict: null, off: false, bit: [bitPos[rec.status_idx * 3], bitPos[rec.status_idx * 3 + 1], bitPos[rec.status_idx * 3 + 2]] });
        byId[nid] = byId[`pp:${rec.sub}`];
      } else {
        P(nid, leaf ? "leaf" : head ? "head" : "node", at(lo, hi), leaf ? 2.4 : head ? 5 : 2, head ? "log head" : "", leaf
          ? { k: `LOG ENTRY ${lo}`, t: `Entry ${lo}`, rows: [["Log", G.accreditation.log_origin], ["Holds", "another entry, not a passport in this record"]] }
          : head ? { k: "LOG HEAD · SIGNED CHECKPOINT", t: `${id}'s log, ${size} entries`, rows: [["Log", G.accreditation.log_origin], ["Size", `${size} entries`], ["Signed by", "the registrar's delegate, cosigned by the witness"], ["Means", "one hash stands for every entry below it; nothing can be changed or removed unseen"]] }
          : { k: "TREE NODE", t: `Entries ${lo} to ${hi - 1}`, rows: [["Is", "the hash of the two nodes below it"], ["Covers", `${hi - lo} entries`]] }, { reg: id, lo, hi });
      }
    }
    for (const [lo, hi] of treeNodes(size)) if (hi - lo > 1) { const k = splitAt(hi - lo); L(`t:${id}:${lo}:${hi}`, `t:${id}:${lo}:${lo + k}`, "tree"); L(`t:${id}:${lo}:${hi}`, `t:${id}:${lo + k}:${hi}`, "tree"); }
    reg.headId = `t:${id}:0:${size}`; L(id, reg.headId, "sign");
  });

  const w = registry.witnesses[0];
  P("wit", "witness", [0, 285, 0], 6, "witness", { k: "WITNESS · SELF-DECLARED", t: "The network's own witness", rows: [["Operator", w.operator], ["Ed25519", cut(w.ed25519)], ["Does", "cosigns each log's head, so a log cannot show two histories"]] });
  P("wit-open", "open", [64, 300, 40], 6, "open seat", { k: "OPEN SEAT", t: "An independent witness", rows: [["Needed for", "fork resistance: witnesses run by others"], ["Who", "anyone; the software is published"]] });
  for (const r of regs) { L(r.headId, "wit", "sign"); L(r.headId, "wit-open", "dash"); }
  P("you", "you", [0, -40, 440], 8, "", { k: "YOU · THIS TAB", t: "You, the verifier", rows: [["Holds", "the directory, checked against the root's two keys"], ["And", "each registrar's signed status list"], ["Contacts", "nobody while it checks"]] });

  // ---------- the record's own order, with its own dates ----------
  // Epochs by number; each log's entries by position; each status change by sequence. Dates are the record's:
  // an entry that is not a passport in this record has a position but no date here.
  const events = [];
  for (const e of eps) events.push({ type: "epoch", epoch: e.epoch, date: e.issued_at, sort: [e.issued_at, 0, e.epoch] });
  for (const r of regs) for (let k = 0; k < r.size; k++) { const rec = r.recs.find((x) => x.leaf_index === k); events.push({ type: "leaf", reg: r.id, leaf: k, rec, date: rec ? rec.issued_at : null, sort: [null, 1, k / r.size + regs.indexOf(r) * 1e-4] }); }
  for (const r of regs) for (const d of r.deltas) events.push({ type: "change", reg: r.id, seq: d.seq, idx: d.idx, on: d.new_status, date: d.ts, sort: [d.ts, 2, d.seq + regs.indexOf(r) * 1e-4] });
  const firstLeaf = Math.min(...events.filter((e) => e.type === "leaf" && e.date).map((e) => e.date));
  for (const e of events) if (e.type === "leaf") e.sort[0] = e.date ?? firstLeaf;
  events.sort((a, b) => a.sort[0] - b.sort[0] || a.sort[1] - b.sort[1] || a.sort[2] - b.sort[2]);

  // The path one check walks, in the order the verifier works: the passport's entry, up its inclusion proof to the
  // signed head, the registrar that signed it, the directory that names the registrar, the root that signed the
  // directory; and beside it the passport's bit in the status list.
  const pathOf = (p) => {
    const r = byId[p.reg], n = p.rec.checkpoint_size, m = p.rec.leaf_index;
    const up = climb(m, n).map(([lo, hi]) => r.at(lo, hi)), sib = auditPath(m, n).map(([lo, hi]) => ({ pos: r.at(lo, hi), lo, hi }));
    const proofOk = sib.length === p.rec.inclusion_proof.length;
    return { up, sib: proofOk ? sib.map((s, i) => ({ ...s, hash: p.rec.inclusion_proof[i] })) : [], bit: p.bit, reg: r.pos, root: byId.root.pos, head: byId[r.headId].pos };
  };
  return { parts, byId, links, regs, events, CUR, pathOf, RING };
}
