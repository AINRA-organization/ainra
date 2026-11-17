#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make cert-link-e2e — an agent's own certificate, linked, attributed and switched off, live (PLAN-M55 step 4).
//
// The certificates are made by a standard tool (openssl), the way an operator already has them. For each kind of key a
// certificate can carry and Link takes (P-256, secp256k1, Ed25519, RSA as RS256 and as PS256):
//
//   1. the operator: a passport from the live registrar
//   2. the kit reads the key out of the certificate and has the agent's private key sign its consent, locally
//   3. the registrar links it; a gate that has checked a signature by that key asks who answers → the operator
//   4. revoke the link → the same gate refuses the same key
//
// and, once each: a certificate whose key nobody linked is "not linked"; a private key that is not the certificate's
// is refused by the kit before anything is sent; a certificate with a key Link does not take (P-384, RSA 1024) is
// refused by name.
//
// TEST-ROOT, loopback. It proves the mechanism; it is not evidence that any operator runs it.
//
// WITNESS: could this observe a failure? Yes — step 3 is the positive control (a `valid` that names the operator),
// the unlinked certificate the negative one, and step 4 must turn the same key from valid to revoked.
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { certificateKey, linkRequest } from "./link.mjs";

const { Verifier, linkFromIndex, presentedKeyThumbprint } = await import(
  new URL("../../packages/sdk-ts/dist/index.js", import.meta.url).href
);
const REG = process.env.AINRA_REGISTRAR ?? "http://127.0.0.1:4970";
const ART = process.env.AINRA_ARTIFACTS ?? "http://127.0.0.1:8093";
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
catch { console.error(`cert-link-e2e: no live registrar at ${REG} — run \`make live-up\` first`); process.exit(2); }
let TOKEN;
try { TOKEN = readFileSync(new URL("../../live/.issue-token", import.meta.url), "utf8").trim(); }
catch { console.error("cert-link-e2e: live/.issue-token missing — start the registrar with `make live-up`"); process.exit(2); }
// The live registrar allows 30 writes a minute, shared by every drill that runs before this one. A refusal for rate is
// the registrar working, not this drill failing: wait for its window and ask again, for up to about a minute and a half.
async function patiently(call) {
  for (let i = 0; ; i++) {
    const r = await call();
    if (r.status !== 429 && !/rate limited/.test(JSON.stringify(r.body)) || i >= 18) return r;
    await new Promise((res) => setTimeout(res, 5000));
  }
}
const write = (path, body) => patiently(() => j(`${REG}${path}`, {
  method: "POST", headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" }, body: JSON.stringify(body),
}));

// Certificates as an operator already has them, from openssl.
const dir = mkdtempSync(join(tmpdir(), "ainra-cert-link-"));
const openssl = (...a) => execFileSync("openssl", a, { stdio: ["ignore", "ignore", "pipe"] });
function makeCert(name, keyArgs) {
  const key = join(dir, `${name}.key`), crt = join(dir, `${name}.crt`);
  openssl("req", "-x509", "-nodes", ...keyArgs, "-keyout", key, "-out", crt, "-days", "2", "-subj", `/CN=agent-${name}.example`);
  return { cert: readFileSync(crt, "utf8"), key: readFileSync(key, "utf8") };
}
const ec = (curve) => ["-newkey", "ec", "-pkeyopt", `ec_paramgen_curve:${curve}`];
let certs;
try {
  certs = {
    p256: makeCert("p256", ec("P-256")),
    k256: makeCert("k256", ec("secp256k1")),
    ed25519: makeCert("ed25519", ["-newkey", "ed25519"]),
    rsa: makeCert("rsa", ["-newkey", "rsa:2048"]),
    rsapss: makeCert("rsapss", ["-newkey", "rsa:3072"]),
    p384: makeCert("p384", ec("P-384")),
    rsa1024: makeCert("rsa1024", ["-newkey", "rsa:1024"]),
    stranger: makeCert("stranger", ec("P-256")),
  };
} catch (e) {
  console.error(`cert-link-e2e: openssl could not make the certificates: ${e.stderr ?? e.message}`);
  process.exit(2);
}
ok(`openssl ${execFileSync("openssl", ["version"]).toString().trim().split(" ").slice(0, 2).join(" ")} made 8 certificates`);

const directory = (await j(`${ART}/directory.json`)).body;
const roots = (await j(`${ART}/roots.json`)).body;
const gate = Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh, "F1");
if (!gate) { fail("could not build a verifier from the published directory"); process.exit(1); }

// A gate that has ALREADY verified a signature with `key`, in whatever protocol the certificate serves, asks next.
async function whoAnswersFor(key) {
  const [index, publication] = await Promise.all([j(`${REG}/links`).then((r) => r.body), j(`${REG}/status-list`).then((r) => r.body)]);
  const link = linkFromIndex(index, publication, presentedKeyThumbprint(key));
  if (!link) return { verdict: "not_linked" };
  return gate.verifyLink(link, key, now(), "demo:specimen");
}

// One operator, one passport; each certificate's key is linked to it in turn.
const issued = await patiently(() => j(`${REG}/demo/issue`, { method: "POST", body: JSON.stringify({ operator: "specimen", lineage: "cert-agents" }) }));
if (issued.status !== 200) { fail(`issue failed: ${issued.status} ${JSON.stringify(issued.body)}`); process.exit(1); }
const p = issued.body;
ok(`the operator's passport: ${p.sub}`);
for (const [name, pss] of [["p256", false], ["k256", false], ["ed25519", false], ["rsa", false], ["rsapss", true]]) {
  step(`${name} · a certificate's key, linked and switched off`);
  const nbf = p.nbf, exp = Math.min(p.exp, now() + 3600);
  let req;
  try {
    req = linkRequest({ certPem: certs[name].cert, keyPem: certs[name].key, passport: p.sub, registrarId: p.registrar, nbf, exp, pss });
  } catch (e) { fail(`the kit: ${e.message}`); continue; }
  ok(`read from the certificate: ${req.key.alg} · ${req.key.key.length} bytes · ${req.key.thumbprint.slice(0, 12)}…`);
  const r = await write("/link", req.body);
  r.status === 200 && r.body.thumbprint === req.key.thumbprint ? ok(`linked to ${p.sub} · log leaf ${r.body.leaf_index}`) : fail(`link: ${r.status} ${JSON.stringify(r.body)}`);
  const v = await whoAnswersFor(req.key.key);
  v.verdict === "valid" && v.operator === "specimen" && v.passport === p.sub ? ok(`a gate asks who answers → valid · operator ${v.operator}`) : fail(`linked key: ${JSON.stringify(v)}`);
  const rv = await write("/link/revoke", { thumbprint: req.key.thumbprint, kind: "link" });
  rv.status === 200 ? ok("revoked") : fail(`revoke: ${rv.status} ${JSON.stringify(rv.body)}`);
  const after = await whoAnswersFor(req.key.key);
  after.verdict === "invalid" && after.reason === "revoked" ? ok("the same gate, the same key → refused: revoked") : fail(`after revocation: ${JSON.stringify(after)}`);
}

step("a certificate whose key nobody linked");
{
  const v = await whoAnswersFor(certificateKey(certs.stranger.cert).key);
  v.verdict === "not_linked" ? ok("not linked — a certificate that verifies is not, by itself, an accountable operator") : fail(`unlinked: ${JSON.stringify(v)}`);
}
step("what the kit refuses before sending anything");
for (const [what, thunk, expect] of [
  ["a private key that is not the certificate's", () => linkRequest({ certPem: certs.p256.cert, keyPem: certs.stranger.key, passport: "x", registrarId: "x", nbf: 1, exp: 2 }), "not the one in the certificate"],
  ["a P-384 key", () => certificateKey(certs.p384.cert), "secp384r1"],
  ["a 1024-bit RSA key", () => certificateKey(certs.rsa1024.cert), "1024 bits"],
]) {
  try { thunk(); fail(`${what}: accepted`); }
  catch (e) { String(e.message).includes(expect) ? ok(`${what} → ${e.message}`) : fail(`${what}: ${e.message}`); }
}

rmSync(dir, { recursive: true, force: true });
console.log(bad ? "\nCERT LINK E2E FAILED" : "\nCERT LINK E2E OK: five kinds of certificate key, read by the kit, linked, attributed and revoked — live");
process.exit(bad);
