// SPDX-License-Identifier: Apache-2.0 OR MIT
// make counterfeit-drill — the tricks of a counterfeit payment, tried on real passports.
//
// A fake token can carry the real token's name. A wallet can show a balance that never arrived. A transfer can sit
// "pending" and vanish. Each trick has a twin against an identity: a passport issued by someone else under the same
// name, a presenter that writes its own "verified", a passport never written to the log, a stale or replayed record.
// This drill takes every passport in the published record (`site/net/`) and the verifier that ships
// (`packages/sdk-ts/dist`), and tries each trick on each valid passport. Every attempt must be refused, and refused
// for its own reason. It runs offline and changes nothing.
//
// WITNESS (the negative control): every genuine passport must first give its published verdict, so a verifier that
// refuses everything fails this drill. `--witness` then swaps in a verifier that
// accepts everything and demands that the drill catch it: it must report every trick as getting through.
import { readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { Verifier } from "../packages/sdk-ts/dist/index.js";

const NET = process.env.AINRA_NET_DIR || new URL("../site/net/", import.meta.url).pathname;
const WITNESS = process.argv.includes("--witness");
const read = (f) => JSON.parse(readFileSync(NET + f, "utf8"));
const directory = read("directory.json"), roots = read("roots.json"), registry = read("registry.json");

const b64u = (buf) => Buffer.from(buf).toString("base64url");
const unb64 = (s) => Buffer.from(s, "base64url");
// A signature of the right length that the registrar never made: the "token someone else minted".
const forge = (s) => b64u(randomBytes(unb64(s).length));

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
const claimsOf = (b) => JSON.parse(unb64(b.claims).toString("utf8"));
// Every trick must really change the passport; a trick that changed nothing would "pass" for the wrong reason.
const withClaims = (b, edit) => {
  const before = JSON.stringify(claimsOf(b)), c = claimsOf(b); edit(c); const after = JSON.stringify(c);
  if (after === before) throw new Error("drill bug: the trick changed nothing");
  return { ...b, claims: b64u(Buffer.from(after, "utf8")) };
};
// The operator label of an issuer name (did:ainra:<registrar>:<operator>:<lineage>), rewritten by `f`.
const editOperator = (c, f) => { const p = c.iss.split(":"); p[3] = f(p[3]); c.iss = p.join(":"); };
// Cyrillic letters that look exactly like Latin ones, and an invisible character, written as code points.
const LOOK = { a: 0x430, o: 0x43e, e: 0x435, c: 0x441, p: 0x440 }, ZWSP = String.fromCodePoint(0x200b);
const setBit = (list64, idx, on) => {   // rewrite one bit of a status list (gzip/zlib inside is the registrar's business:
  const u = unb64(list64);              // the signature covers the list as published, so any rewrite must fail)
  const v = Buffer.from(u); const i = Math.min(v.length - 1, idx >> 3); v[i] = on ? v[i] | (1 << (idx & 7)) : v[i] & ~(1 << (idx & 7));
  if (Buffer.compare(v, u) === 0) v[v.length - 1] ^= 1;   // make sure the bytes really changed
  return b64u(v);
};

// The pinned roots are the "official contract address". A directory signed by any other root is refused.
const verifier = WITNESS ? { verify: () => ({ verdict: "valid" }) } : Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh, "F3");
if (!verifier) { console.error("✗ the published directory does not verify under the published roots"); process.exit(1); }
const NOW = registry.generated_window.verified_at;

let failed = 0, passed = 0;
const say = (ok, line) => { ok ? passed++ : failed++; if (!ok || process.env.VERBOSE) console.log(`  ${ok ? "ok  " : "FAIL"} ${line}`); };
const refused = (name, v, allowed) => {
  const ok = v.verdict !== "valid" && (!allowed || allowed.includes(v.reason));
  say(ok, `${name} → ${v.verdict}${v.reason ? ` (${v.reason})` : ""}${ok ? "" : allowed ? `, wanted one of ${allowed.join("/")}` : ""}`);
};
const run = (b, at = NOW) => { try { return verifier.verify(b, at); } catch (e) { return { verdict: "invalid", reason: `threw: ${e.message}` }; } };

console.log(`AINRA counterfeit drill · ${NET} · ${WITNESS ? "WITNESS RUN (a verifier that accepts everything)" : "the shipped verifier"}\n`);

// 1 · The pinned root is the contract address: anything signed under another root, or a tampered directory, is refused.
if (!WITNESS) {
  const fakeRoot = Verifier.fromDirectoryB64(directory, b64u(randomBytes(unb64(roots.root_ed25519).length)), roots.root_slh, "F3");
  say(fakeRoot === null, `the real directory checked against an attacker's root → ${fakeRoot === null ? "refused" : "ACCEPTED"}`);
  const tampered = structuredClone(directory); const s = JSON.stringify(tampered).replace(/"registrar-07"/, '"registrar-7a"');
  const t2 = Verifier.fromDirectoryB64(JSON.parse(s), roots.root_ed25519, roots.root_slh, "F3");
  say(t2 === null, `a directory with one registrar renamed → ${t2 === null ? "refused" : "ACCEPTED"}`);
}

let genuine = 0, published = { valid: 0, revoked: 0 };
for (const reg of registry.registrars) {
  for (const { record: rec, verdict: pub } of reg.records) {
    const b = bundle(rec, reg.status_list), name = rec.sub.replace(/^ainra:/, "");
    // The control: the genuine passport gives exactly its published verdict.
    if (!WITNESS) {
      const v = run(b);
      const ok = v.verdict === pub.verdict && (pub.verdict === "valid" || v.reason === pub.reason);
      say(ok, `genuine ${name} → ${v.verdict}${v.reason ? ` (${v.reason})` : ""} (published: ${pub.verdict}${pub.reason ? ` ${pub.reason}` : ""})`);
      genuine++; pub.verdict === "valid" ? published.valid++ : published.revoked++;
    }
    if (pub.verdict !== "valid") {
      // A revoked passport made to look clear: its bit unset in the list, the list's signature now false.
      const st = reg.status_list;
      refused(`${name}: revoked, its status bit cleared by hand`, run({ ...b, status_list: setBit(st.status_list_b64, rec.status_idx, false) }), ["sig_invalid", "stale_status"]);
      refused(`${name}: revoked, the presenter adds "revoked": false and "verdict": "valid"`, run({ ...b, revoked: false, verdict: "valid" }), ["revoked", "schema_violation"]);
      continue;
    }
    // 2 · The same name, minted by someone else.
    refused(`${name}: signed by another key (both halves)`, run({ ...b, issuer_sig: { ed25519: forge(b.issuer_sig.ed25519), mldsa65: forge(b.issuer_sig.mldsa65) } }), ["sig_invalid"]);
    refused(`${name}: the classical half kept, the post-quantum half forged`, run({ ...b, issuer_sig: { ...b.issuer_sig, mldsa65: forge(b.issuer_sig.mldsa65) } }), ["sig_invalid", "alg_downgrade"]);
    refused(`${name}: the post-quantum half dropped`, run({ ...b, issuer_sig: { ed25519: b.issuer_sig.ed25519 } }), ["alg_downgrade", "schema_violation", "sig_invalid"]);
    // The whole passport rewritten, consistently, to a registrar the directory does not name (every field that
    // carries the registrar: iss, sub, the log checkpoint, the status URI), as a counterfeit issuer would.
    const ghost = (b2) => withClaims(b2, (c) => {
      const r = c.iss.split(":")[2], to = (s) => s.split(r).join("registrar-99");
      c.iss = to(c.iss); c.sub = to(c.sub);
      if (c.log?.checkpoint) c.log.checkpoint = to(c.log.checkpoint);
      if (c.status?.status_list?.uri) c.status.status_list.uri = to(c.status.status_list.uri);
    });
    // A delegated passport's chain still names the real registrar's passports, so the rewrite is malformed before
    // the registrar is even looked up: refused either way.
    refused(`${name}: claimed by a registrar the directory does not name`, run(ghost(b)), rec.hops?.length ? ["unknown_registrar", "schema_violation"] : ["unknown_registrar"]);
    // 3 · Lookalike names, in the operator's own label: a letter from another alphabet, capitals, an invisible
    //     character, a stray hyphen.
    for (const [why, f] of [["one Latin letter swapped for its Cyrillic twin", (o) => o.replace(/[aoecp]/, (x) => String.fromCodePoint(LOOK[x]))],
                            ["capital letters", (o) => o.toUpperCase()],
                            ["a zero-width space inside", (o) => o.slice(0, 1) + ZWSP + o.slice(1)],
                            ["a trailing hyphen", (o) => o + "-"]]) {
      let t; try { t = run(withClaims(b, (c) => editOperator(c, f))); } catch (e) { say(false, `${name}: lookalike name (${why}): ${e.message}`); continue; }
      refused(`${name}: lookalike operator name (${why})`, t, ["name_malformed", "schema_violation", "sig_invalid"]);
    }
    // 4 · The display that lies: the presenter writes its own verdict or status into the passport.
    refused(`${name}: "verified": true written into the signed claims`, run(withClaims(b, (c) => { c.verified = true; })), ["schema_violation", "sig_invalid"]);
    refused(`${name}: a wider capability written into the claims`, run(withClaims(b, (c) => { c.capabilities = [...(c.capabilities || []), "pay:any"]; })), ["sig_invalid", "ceiling_exceeded", "schema_violation"]);
    // 5 · The transfer that never confirms: not in the log, or "in" a log the registrar never signed.
    refused(`${name}: no inclusion proof (never logged)`, run({ ...b, inclusion_proof: [] }), ["not_logged", "checkpoint_invalid"]);
    refused(`${name}: a leaf past the signed checkpoint (still pending)`, run({ ...b, leaf_index: b.checkpoint.size + 5 }), ["not_logged", "checkpoint_invalid", "schema_violation"]);
    refused(`${name}: a checkpoint root the registrar never signed`, run({ ...b, checkpoint: { ...b.checkpoint, root: forge(b.checkpoint.root) } }), ["checkpoint_invalid", "not_logged"]);
    // 6 · Money that vanishes: out of its window, or kept alive by an old status list.
    const exp = claimsOf(b).exp, nbf = claimsOf(b).nbf;
    refused(`${name}: shown one second after it expired`, run(b, exp + 1), ["expired", "stale_status"]);
    refused(`${name}: shown one second before it was valid`, run(b, nbf - 1), ["not_yet_valid", "stale_status"]);
    refused(`${name}: its status list replayed a day and a second later (F3)`, run(b, b.status_issued_at + 86400 + 1), ["stale_status"]);
    refused(`${name}: its status list re-dated to look fresh`, run({ ...b, status_issued_at: NOW }), ["sig_invalid", "stale_status"]);
  }
}

console.log(`\n  ${passed} ok · ${failed} failed`);
if (WITNESS) {
  // The witness run passes only if the drill caught the accept-everything verifier on every trick.
  if (failed > 0 && passed === 0) { console.log(`WITNESS OK: a verifier that accepts everything let all ${failed} tricks through, and the drill said so`); process.exit(0); }
  console.log("WITNESS FAILED: the drill did not catch a verifier that accepts everything"); process.exit(1);
}
if (!published.valid || !published.revoked) { console.log(`✗ the record must hold a valid and a revoked passport to test both; found ${published.valid} valid, ${published.revoked} revoked`); process.exit(1); }
console.log(`  ${genuine} published passports: ${published.valid} valid, ${published.revoked} revoked`);
if (failed) { console.log("COUNTERFEIT-DRILL FAILED: a trick got through, or a genuine passport lost its verdict"); process.exit(1); }
console.log("COUNTERFEIT-DRILL OK — every genuine passport gave its published verdict; every counterfeit, lookalike, self-written verdict, unlogged passport and stale or replayed record was refused");
