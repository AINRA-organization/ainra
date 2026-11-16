#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make issuer-link-e2e — an issuer link, live (D-110, PLAN-M55 step 2).
//
// Most agents do not sign their own requests. They carry a TOKEN from an identity system: a JWT that names the
// agent and is signed by the system's key. One link for that key, the ISSUER's, answers for every token it signs.
// This is the whole path against the running registrar, with a token issuer that contains no AINRA code
// (./issuer.mjs: a discovery document, a published key set, ES256 tokens):
//
//   1. the operator behind the issuer: a passport from the live registrar
//   2. the issuer, running as it always has
//   3. the issuer's key signs ONE statement: its consent to an issuer link under its own name. The registrar
//      refuses the wrong consent in both directions, and the open door refuses issuer links altogether.
//   4. a gate verifies an agent's token the ordinary way (the issuer's published keys), then asks AINRA who
//      answers for that issuer → the operator, by name
//   5. a second issuer nobody linked: its token verifies the ordinary way; AINRA: not linked
//   6. a token that NAMES the linked issuer but was signed with another key: the ordinary check refuses it, and a
//      gate careless enough to accept it still finds no link for that key
//   7. the link is consent to one use: the issuer key signing a request itself, or a token under another issuer
//      name, is refused
//   8. revoke the issuer link → the same token still verifies at the issuer; AINRA refuses it
//
// TEST-ROOT, loopback, http. The issuer is a stand-in that this drill starts: no outside identity system has linked
// a key. It proves the mechanism; it is not evidence that any issuer uses it.
//
// WITNESS: could this observe a failure? Yes. Step 4 is the positive control (a `valid` that names the operator and
// the issuer), steps 5 and 6 are negative controls (tokens that verify, or look as if they should, and must not be
// attributed), and step 8 needs the SAME token to pass the issuer's check and fail AINRA's. With a registrar built
// before D-110, step 3 already fails: it answers 400 "unknown field `issuer`".
import { readFileSync } from "node:fs";
import { Verifier, issuerLinkPopSigningBytes, jwkThumbprintEs256, linkFromIndex, linkPopSigningBytes } from "../../packages/sdk-ts/dist/index.js";
import { b64uEncode } from "../../packages/sdk-ts/dist/crypto.js";
import { startIssuer } from "./issuer.mjs";

const REG = process.env.AINRA_REGISTRAR ?? "http://127.0.0.1:4970";
const ART = process.env.AINRA_ARTIFACTS ?? "http://127.0.0.1:8093";
const AUD = "https://api.example";
const now = () => Math.floor(Date.now() / 1000);

let bad = 0;
const ok = (m) => console.log(`  ok    ${m}`);
const fail = (m) => { console.error(`  ✗     ${m}`); bad = 1; };
const step = (m) => console.log(`\n${m}`);
async function j(url, init) {
  const r = await fetch(url, init);
  const t = await r.text();
  let body; try { body = JSON.parse(t); } catch { body = t; }
  return { status: r.status, body };
}

try { await fetch(`${REG}/accreditation`, { signal: AbortSignal.timeout(3000) }); }
catch { console.error(`issuer-link-e2e: no live registrar at ${REG} — run \`make live-up\` first`); process.exit(2); }
// Linking and revoking are operator writes. The token goes into a request header only — never onto stdout.
let TOKEN;
try { TOKEN = readFileSync(new URL("../../live/.issue-token", import.meta.url), "utf8").trim(); }
catch { console.error("issuer-link-e2e: live/.issue-token missing — start the registrar with `make live-up`"); process.exit(2); }
const write = (path, body) => j(`${REG}${path}`, {
  method: "POST", headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" }, body: JSON.stringify(body),
});

// ── 1 · the operator behind the issuer ───────────────────────────────────────────────────────────────────────────
step("1 · the operator behind the issuer: a passport from the live registrar");
const issued = await j(`${REG}/demo/issue`, { method: "POST", body: JSON.stringify({ operator: "specimen", lineage: "issuer" }) });
if (issued.status !== 200) { fail(`issue failed: ${issued.status} ${JSON.stringify(issued.body)}`); process.exit(1); }
const passport = issued.body;
const directory = (await j(`${ART}/directory.json`)).body;
const roots = (await j(`${ART}/roots.json`)).body;
const gate = Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh, "F1");
if (!gate) { fail("could not build a verifier from the published directory"); process.exit(1); }
ok(`${passport.sub}`);

// ── 2 · the issuer ───────────────────────────────────────────────────────────────────────────────────────────────
step("2 · the issuer, running as it always has (no AINRA code in it)");
const IDP = await startIssuer(), STRANGER = await startIssuer();
const TP = jwkThumbprintEs256(IDP.publicKey);
IDP.publicKey.length === 65 && TP === IDP.kid ? ok(`${IDP.issuer} · ES256 · key ${TP.slice(0, 12)}… published at /jwks.json`) : fail("the issuer's key is not a P-256 key named by its thumbprint");

// ── 3 · one statement by the issuing key ─────────────────────────────────────────────────────────────────────────
step("3 · the issuing key signs its consent to an issuer link; the registrar takes that and nothing else");
// The platform returns either twin of an ECDSA signature; Link takes the low-S one (D-108).
const N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551n;
const lowS = (sig) => {
  const s = BigInt("0x" + Buffer.from(sig.slice(32)).toString("hex"));
  const low = s > N / 2n ? N - s : s;
  return Uint8Array.from([...sig.slice(0, 32), ...Buffer.from(low.toString(16).padStart(64, "0"), "hex")]);
};
const nbf = passport.nbf, exp = Math.min(passport.exp, now() + 3600);
const issuerConsent = lowS(await IDP.sign(issuerLinkPopSigningBytes(passport.registrar, passport.sub, TP, IDP.issuer, nbf)));
const keyConsent = lowS(await IDP.sign(linkPopSigningBytes(passport.registrar, passport.sub, TP, nbf)));
const body = (pop, issuer) => ({ passport: passport.sub, alg: "ES256", key: b64uEncode(IDP.publicKey), pop: b64uEncode(pop), nbf, exp, ...(issuer === undefined ? {} : { issuer }) });
const why = (r) => String(r.body?.error ?? r.body).split("(")[0].trim();
{
  const r = await write("/link", body(keyConsent, IDP.issuer));
  r.status === 400 ? ok(`an issuer link on the key's ORDINARY consent → refused: ${why(r)}`) : fail(`ordinary consent as issuer: ${r.status} ${JSON.stringify(r.body)}`);
}
{
  const r = await write("/link", body(issuerConsent, undefined));
  r.status === 400 ? ok(`an ordinary link on the key's ISSUER consent → refused: ${why(r)}`) : fail(`issuer consent as ordinary: ${r.status} ${JSON.stringify(r.body)}`);
}
{
  const r = await write("/link", body(issuerConsent, "https://someone-else.example"));
  r.status === 400 ? ok(`the consent under another issuer's name → refused: ${why(r)}`) : fail(`another name: ${r.status} ${JSON.stringify(r.body)}`);
}
{
  const r = await j(`${REG}/demo/link`, { method: "POST", body: JSON.stringify(body(issuerConsent, IDP.issuer)) });
  r.status === 403 ? ok(`the open demo door → refused: ${why(r)}`) : fail(`demo door: ${r.status} ${JSON.stringify(r.body)}`);
}
{
  const r = await write("/link", body(issuerConsent, IDP.issuer));
  r.status === 200 && r.body.thumbprint === TP ? ok(`linked as an issuer · log leaf ${r.body.leaf_index}`) : fail(`link: ${r.status} ${JSON.stringify(r.body)}`);
}

// ── the gate ─────────────────────────────────────────────────────────────────────────────────────────────────────
// (a) The ORDINARY check, as a service does it today: only issuers it has configured, their published keys, the
//     signature, the audience and the expiry. No AINRA code. Returns the key that verified the token and the issuer
//     name in it, or null.
const CONFIGURED = new Set([IDP.issuer, STRANGER.issuer]);
async function verifyTokenTheOrdinaryWay(jwt) {
  const [h, p, s] = jwt.split(".");
  let head, claims;
  try { head = JSON.parse(Buffer.from(h, "base64url")); claims = JSON.parse(Buffer.from(p, "base64url")); } catch { return null; }
  if (head.alg !== "ES256" || !CONFIGURED.has(claims.iss)) return null;
  const conf = (await j(`${claims.iss}/.well-known/openid-configuration`)).body;
  if (conf.issuer !== claims.iss) return null;
  const jwk = ((await j(conf.jwks_uri)).body.keys ?? []).find((k) => k.kid === head.kid && k.kty === "EC" && k.crv === "P-256");
  if (!jwk) return null;
  const key = await crypto.subtle.importKey("jwk", { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  const good = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, Buffer.from(s, "base64url"), Buffer.from(`${h}.${p}`));
  if (!good || claims.aud !== AUD || !(claims.exp > now())) return null;
  return { key: Uint8Array.from([4, ...Buffer.from(jwk.x, "base64url"), ...Buffer.from(jwk.y, "base64url")]), issuer: claims.iss, sub: claims.sub };
}
// (b) The next question, to AINRA: who answers for the issuer whose key verified this token? The link is found by
//     the KEY the gate verified with, never by the issuer's name; `issuer` is undefined when a key signed a request.
async function whoAnswersFor(key, issuer) {
  const [index, publication] = await Promise.all([j(`${REG}/links`).then((r) => r.body), j(`${REG}/status-list`).then((r) => r.body)]);
  const link = linkFromIndex(index, publication, jwkThumbprintEs256(key));
  if (!link) return { verdict: "not_linked" };
  return gate.verifyLink(link, key, now(), "demo:specimen", issuer);
}

step("4 · an agent's token: verified the ordinary way, then attributed");
const token = await IDP.mint({ sub: "agent-7", aud: AUD });
{
  const t = await verifyTokenTheOrdinaryWay(token);
  if (!t) { fail("the issuer's own token did not verify the ordinary way"); }
  else {
    const v = await whoAnswersFor(t.key, t.issuer);
    v.verdict === "valid" && v.operator === "specimen" && v.passport === passport.sub && v.issuer === IDP.issuer
      ? ok(`token for ${t.sub} verifies · issuer ${v.issuer} is answered for by operator ${v.operator} · ${v.passport}`)
      : fail(`linked issuer: ${JSON.stringify(v)}`);
  }
}
step("5 · a second issuer nobody linked");
{
  const t = await verifyTokenTheOrdinaryWay(await STRANGER.mint({ sub: "agent-9", aud: AUD }));
  const v = t ? await whoAnswersFor(t.key, t.issuer) : null;
  t && v.verdict === "not_linked" ? ok("its token verifies the ordinary way · AINRA: not linked — a token that verifies is not, by itself, an accountable issuer") : fail(`unlinked issuer: ${JSON.stringify({ verified: !!t, v })}`);
}
step("6 · a token that names the linked issuer, signed with another key");
{
  // The stranger's key signs a token whose `iss` is the linked issuer's name.
  const forged = await STRANGER.mint({ sub: "agent-7", aud: AUD }, { iss: IDP.issuer });
  (await verifyTokenTheOrdinaryWay(forged)) === null ? ok("the ordinary check refuses it: that key is not in the issuer's published set") : fail("the forged token verified the ordinary way");
  // A gate careless enough to accept the key that came with the token still asks AINRA about THAT key.
  const v = await whoAnswersFor(STRANGER.publicKey, IDP.issuer);
  v.verdict === "not_linked" ? ok("and a gate that skipped that check finds no link for the key it used: not linked") : fail(`forged token at a careless gate: ${JSON.stringify(v)}`);
}
step("7 · the link is consent to one use");
{
  const direct = await whoAnswersFor(IDP.publicKey, undefined);
  direct.verdict === "invalid" && direct.reason === "sig_invalid" ? ok("the issuing key signing a request itself → refused: sig_invalid") : fail(`issuer key as a request key: ${JSON.stringify(direct)}`);
  const other = await whoAnswersFor(IDP.publicKey, "https://someone-else.example");
  other.verdict === "invalid" && other.reason === "sig_invalid" ? ok("the same key under another issuer's name → refused: sig_invalid") : fail(`another issuer name: ${JSON.stringify(other)}`);
}
step("8 · revoke the issuer link");
{
  const rv = await write("/link/revoke", { thumbprint: TP, kind: "link" });
  rv.status === 200 ? ok(`revoked (kind link) · log leaf ${rv.body.leaf_index}`) : fail(`revoke: ${rv.status} ${JSON.stringify(rv.body)}`);
  const t = await verifyTokenTheOrdinaryWay(token);
  const v = t ? await whoAnswersFor(t.key, t.issuer) : null;
  t && v.verdict === "invalid" && v.reason === "revoked"
    ? ok("the SAME token still verifies at the issuer · AINRA refuses it: revoked — every token this key signs as this issuer")
    : fail(`after revocation: ${JSON.stringify({ verified: !!t, v })}`);
}

await IDP.close(); await STRANGER.close();
console.log(bad ? "\nISSUER LINK E2E FAILED" : "\nISSUER LINK E2E OK: an issuer's key linked once, its tokens attributed to the operator behind it, and all of them refused on one revocation — live");
process.exit(bad);
