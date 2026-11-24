// SPDX-License-Identifier: Apache-2.0 OR MIT
// make counterfeit-drill — forged, lookalike, self-certified, unlogged and replayed passports, tried on real ones.
//
// This drill takes every passport in the published record (`site/net/`) and the verifier that ships
// (`packages/sdk-ts/dist`), and tries on each one the ways a counterfeit passes for the real thing:
//   · the real name from another issuer: forged signatures, a dropped post-quantum half, a registrar nobody accredited;
//   · lookalike names: a letter from another alphabet, capitals, an invisible character, a stray hyphen;
//   · a verdict the presenter writes itself: "verified", a wider capability, "valid" beside a revoked passport;
//   · a passport not (yet) in the log: no inclusion proof, a leaf past the signed checkpoint, an unsigned checkpoint;
//   · outside its time: after expiry, before validity, kept alive by an old, re-dated or edited status list;
//   · a counterfeit root: the directory checked against another root's halves, or with a registrar renamed.
// Each trick is pinned to the ONE reason its own defence gives, so a removed check cannot hide behind another one.
// It runs offline and changes nothing.
//
// WITNESS (the negative control): every genuine passport must first give its published verdict, so a verifier that
// refuses everything fails. `--witness` then runs the whole drill twice against deliberately broken verifiers and
// demands that the drill catch them on every trick: one that accepts everything (root checks included), and one that
// refuses with the wrong reason.
import { readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { inflateSync, deflateSync } from "node:zlib";
import { Verifier } from "../packages/sdk-ts/dist/index.js";

const NET = process.env.AINRA_NET_DIR || new URL("../site/net/", import.meta.url).pathname;
const read = (f) => JSON.parse(readFileSync(NET + f, "utf8"));
const directory = read("directory.json"), roots = read("roots.json"), registry = read("registry.json");
const NOW = registry.generated_window.verified_at;

const b64u = (buf) => Buffer.from(buf).toString("base64url");
const unb64 = (s) => Buffer.from(s, "base64url");
const forge = (s) => b64u(randomBytes(unb64(s).length));   // the right length, made by someone else

function bundle(rec, st) {
  return {
    claims: b64u(Buffer.from(rec.claims, "utf8")),
    issuer_sig: { ed25519: rec.issuer_sig_ed25519, mldsa65: rec.issuer_sig_mldsa65 },
    chain_keys: rec.chain_keys, hop_proofs: rec.hop_proofs,
    status_uri: st.uri, status_list: st.status_list_b64, status_len: st.bit_len, status_issued_at: st.issued_at,
    status_sig_ed25519: st.sig_ed25519, status_sig_mldsa65: st.sig_mldsa65,
    checkpoint: { origin: rec.log_origin, size: rec.checkpoint_size, root: rec.checkpoint_root },
    checkpoint_sig: rec.checkpoint_sig, leaf_index: rec.leaf_index, inclusion_proof: rec.inclusion_proof,
    mandate_revocations: [], revoked_delegates: [],
    ...(rec.chain_parties?.length ? { chain_parties: rec.chain_parties } : {}),
  };
}
const claimsText = (b) => unb64(b.claims).toString("utf8");
// Every trick must really change what it says it changes; one that changed nothing would pass for the wrong reason.
const withClaimsText = (b, edit) => {
  const before = claimsText(b), after = edit(before);
  if (after === before) throw new Error("drill bug: the trick changed nothing");
  return { ...b, claims: b64u(Buffer.from(after, "utf8")) };
};
const withClaims = (b, edit) => withClaimsText(b, (t) => { const c = JSON.parse(t); edit(c); return JSON.stringify(c); });
// The operator label, rewritten in every name that carries it (iss and sub), so only the name rule can refuse it.
const editOperator = (c, f) => {
  const op = c.iss.split(":")[3], to = f(op);
  c.iss = c.iss.split(":").map((p, i) => (i === 3 ? to : p)).join(":");
  c.sub = c.sub.split(":").map((p, i) => (i === 2 ? to : p)).join(":");
};
const LOOK = { a: 0x430, o: 0x43e, e: 0x435, c: 0x441, p: 0x440 }, ZWSP = String.fromCodePoint(0x200b);
// Clear one passport's bit inside the compressed status list (LSB-first), then compress again: the list now says the
// passport is not revoked, and only the registrar's signature over the list can tell.
const clearBit = (list64, idx) => {
  const bits = Buffer.from(inflateSync(unb64(list64))), byte = idx >> 3, mask = 1 << (idx & 7);
  if (!(bits[byte] & mask)) throw new Error(`drill bug: bit ${idx} is not set in the published list`);
  bits[byte] &= ~mask;
  return b64u(deflateSync(bits));
};

// The verifiers the drill runs against: the shipped one, and (for --witness) two that are broken on purpose.
const MODES = {
  shipped: { fromDirectory: (d, ed, slh) => Verifier.fromDirectoryB64(d, ed, slh, "F3"), wrap: (v) => v },
  "accepts everything": { fromDirectory: () => ({ verify: () => ({ verdict: "valid" }) }), wrap: (v) => v },
  "wrong reasons": {
    fromDirectory: (d, ed, slh) => Verifier.fromDirectoryB64(d, ed, slh, "F3"),
    wrap: (v) => v && { verify: (b, t) => { const r = v.verify(b, t); return r.verdict === "valid" ? r : { ...r, reason: r.reason === "expired" ? "revoked" : "expired" }; } },
  },
};

function drill(modeName) {
  const mode = MODES[modeName], quiet = modeName !== "shipped";
  const out = { genuineOk: 0, genuineFail: 0, tricks: 0, tricksRefused: 0, rootTricks: 0, valid: 0, revoked: 0, lines: [] };
  const log = (ok, line) => { if (!ok || process.env.VERBOSE) out.lines.push(`  ${ok ? "ok  " : "FAIL"} ${line}`); };
  const verifier = mode.wrap(mode.fromDirectory(directory, roots.root_ed25519, roots.root_slh));
  if (!verifier) { out.lines.push("  FAIL the published directory does not verify under the published roots"); out.genuineFail++; return out; }
  const run = (b, at = NOW) => { try { return verifier.verify(b, at); } catch (e) { return { verdict: "invalid", reason: `threw: ${e.message}` }; } };
  const trick = (name, f, want) => {
    out.tricks++;
    let v; try { v = f(); } catch (e) { log(false, `${name}: ${e.message}`); return; }
    const ok = v.verdict !== "valid" && v.reason === want;
    if (ok) out.tricksRefused++;
    log(ok, `${name} → ${v.verdict}${v.reason ? ` (${v.reason})` : ""}${ok ? "" : `, wanted ${want}`}`);
  };
  const rootTrick = (name, ed, slh, dir = directory) => {
    out.tricks++; out.rootTricks++;
    const ok = mode.fromDirectory(dir, ed, slh) === null;
    if (ok) out.tricksRefused++;
    log(ok, `${name} → ${ok ? "refused" : "ACCEPTED"}`);
  };

  // A counterfeit root: the directory checked against another root, half by half, or edited.
  rootTrick("the directory checked against another root's Ed25519 half", forge(roots.root_ed25519), roots.root_slh);
  rootTrick("the directory checked against another root's SLH-DSA half", roots.root_ed25519, forge(roots.root_slh));
  rootTrick("the directory checked against another root (both halves)", forge(roots.root_ed25519), forge(roots.root_slh));
  rootTrick("a directory with one registrar renamed", roots.root_ed25519, roots.root_slh,
    JSON.parse(JSON.stringify(directory).replace(/"registrar-07"/, '"registrar-7a"')));

  for (const reg of registry.registrars) {
    for (const { record: rec, verdict: pub } of reg.records) {
      const b = bundle(rec, reg.status_list), name = rec.sub.replace(/^ainra:/, "");
      const g = run(b);   // the control: the genuine passport gives exactly its published verdict
      const gok = g.verdict === pub.verdict && (pub.verdict === "valid" || g.reason === pub.reason);
      gok ? out.genuineOk++ : out.genuineFail++;
      log(gok, `genuine ${name} → ${g.verdict}${g.reason ? ` (${g.reason})` : ""} (published: ${pub.verdict}${pub.reason ? ` ${pub.reason}` : ""})`);
      pub.verdict === "valid" ? out.valid++ : out.revoked++;

      if (pub.verdict !== "valid") {
        trick(`${name}: revoked, its bit cleared inside the status list`, () => run({ ...b, status_list: clearBit(b.status_list, rec.status_idx) }), "stale_status");
        trick(`${name}: revoked, the presenter adds "revoked": false and "verdict": "valid"`, () => run({ ...b, revoked: false, verdict: "valid" }), "revoked");
        continue;
      }
      // The real name from another issuer.
      trick(`${name}: signed by another key (both halves)`, () => run({ ...b, issuer_sig: { ed25519: forge(b.issuer_sig.ed25519), mldsa65: forge(b.issuer_sig.mldsa65) } }), "sig_invalid");
      trick(`${name}: the Ed25519 half kept, the ML-DSA half forged`, () => run({ ...b, issuer_sig: { ...b.issuer_sig, mldsa65: forge(b.issuer_sig.mldsa65) } }), "sig_invalid");
      trick(`${name}: the ML-DSA half kept, the Ed25519 half forged`, () => run({ ...b, issuer_sig: { ...b.issuer_sig, ed25519: forge(b.issuer_sig.ed25519) } }), "sig_invalid");
      trick(`${name}: the post-quantum half dropped`, () => run({ ...b, issuer_sig: { ed25519: b.issuer_sig.ed25519 } }), "schema_violation");
      // The whole passport rewritten to a registrar the directory does not name, every mention of it.
      trick(`${name}: issued in the name of a registrar nobody accredited`, () => {
        const r = JSON.parse(claimsText(b)).iss.split(":")[2];
        return run(withClaimsText(b, (t) => t.split(r).join("registrar-99")));
      }, "unknown_registrar");
      // Lookalike names, in iss and sub alike, so only the name rule can refuse them.
      for (const [why, f] of [["one Latin letter swapped for its Cyrillic twin", (o) => o.replace(/[aoecp]/, (x) => String.fromCodePoint(LOOK[x]))],
                              ["capital letters", (o) => o.toUpperCase()],
                              ["a zero-width space inside", (o) => o.slice(0, 1) + ZWSP + o.slice(1)],
                              ["a trailing hyphen", (o) => o + "-"]]) {
        trick(`${name}: lookalike operator name (${why})`, () => run(withClaims(b, (c) => editOperator(c, f))), "name_malformed");
      }
      // A verdict the presenter writes itself.
      trick(`${name}: "verified": true written into the claims`, () => run(withClaims(b, (c) => { c.verified = true; })), "schema_violation");
      trick(`${name}: a wider capability written into the claims`, () => run(withClaims(b, (c) => { c.capabilities = [...(c.capabilities || []), "pay:any"]; })), "sig_invalid");
      // Not (yet) in the log.
      trick(`${name}: no inclusion proof`, () => run({ ...b, inclusion_proof: [] }), "not_logged");
      trick(`${name}: a leaf past the signed checkpoint (still pending)`, () => run({ ...b, leaf_index: b.checkpoint.size + 5 }), "not_logged");
      trick(`${name}: a checkpoint root the registrar never signed`, () => run({ ...b, checkpoint: { ...b.checkpoint, root: forge(b.checkpoint.root) } }), "checkpoint_invalid");
      // Outside its time.
      const c0 = JSON.parse(claimsText(b));
      trick(`${name}: shown one second after it expired`, () => run(b, c0.exp + 1), "expired");
      trick(`${name}: shown one second before it was valid`, () => run(b, c0.nbf - 1), "not_yet_valid");
      trick(`${name}: its status list replayed a day and a second later (F3)`, () => run(b, b.status_issued_at + 86400 + 1), "stale_status");
      trick(`${name}: its status list re-dated to look fresh`, () => run({ ...b, status_issued_at: NOW }), "stale_status");
    }
  }
  return out;
}

const report = (o) => { for (const l of o.lines) console.log(l); console.log(`\n  ${o.genuineOk} genuine passports as published (${o.valid} valid, ${o.revoked} revoked) · ${o.tricksRefused} of ${o.tricks} tricks refused with their own reason`); };

if (process.argv.includes("--witness")) {
  // Each broken verifier must be caught on every trick it can affect: the one that accepts everything on all of them
  // (root checks included); the one that gives wrong reasons on every trick that ends in a reason (a refused root
  // gives no reason, so those are the first broken verifier's to catch).
  let bad = 0;
  for (const m of ["accepts everything", "wrong reasons"]) {
    const o = drill(m), caught = o.tricks - o.tricksRefused, owed = m === "wrong reasons" ? o.tricks - o.rootTricks : o.tricks;
    const ok = owed > 0 && caught === owed;
    console.log(`  ${ok ? "ok  " : "FAIL"} a verifier that ${m === "accepts everything" ? "accepts everything" : "refuses with the wrong reason"}: caught on ${caught} of ${owed} tricks`);
    if (!ok) bad++;
  }
  if (bad) { console.log("WITNESS FAILED: the drill missed a broken verifier"); process.exit(1); }
  console.log("WITNESS OK: both broken verifiers were caught on every trick they could affect");
  process.exit(0);
}

console.log(`AINRA counterfeit drill · ${NET} · the shipped verifier\n`);
const o = drill("shipped");
report(o);
if (!o.valid || !o.revoked) { console.log("✗ the record must hold a valid and a revoked passport to test both"); process.exit(1); }
if (o.genuineFail || o.tricksRefused !== o.tricks) { console.log("COUNTERFEIT-DRILL FAILED: a trick got through or was refused for another reason, or a genuine passport lost its verdict"); process.exit(1); }
console.log("COUNTERFEIT-DRILL OK — every genuine passport gave its published verdict, and every trick was refused with the reason its own defence gives");
