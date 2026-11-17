#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// The certificate link kit (PLAN-M55 step 4). An agent that already has a certificate keeps it. This reads the key
// inside the certificate, has the agent's private key sign its consent, and asks a registrar to link that key to the
// operator's passport. Then any gate that has checked a signature by that key, in whatever protocol the certificate
// is used for, can ask who answers for it, and get "nobody" again after the link is revoked.
//
// It reads certificates. It issues none, and it never sends the private key anywhere: the key signs one consent,
// here, and the registrar receives the signature.
//
//   node kits/cert-link/link.mjs --cert agent.crt --key agent.key --passport SUB --registrar URL --token-file F
//        [--registrar-id ID] [--nbf T] [--exp T] [--pss]
//
// Keys it reads, as the certificate carries them: NIST P-256 (ES256), secp256k1 (ES256K), Ed25519, and RSA of 2048 to
// 4096 bits with exponent 65537 (RS256, or PS256 with --pss). Anything else is refused here, by name, before any
// request is sent (D-082, D-108, D-112).
import { X509Certificate, createPrivateKey, createPublicKey, sign as nodeSign, constants } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const SDK = new URL("../../packages/sdk-ts/dist/index.js", import.meta.url);
const { linkPopSigningBytes, presentedKeyThumbprint } = await import(SDK.href);

const P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551n;
const K256_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const b64u = (b) => Buffer.from(b).toString("base64url");
const fromB64u = (s) => new Uint8Array(Buffer.from(s, "base64url"));

/** The key a certificate carries, in the form a link presents it: `{ alg, key, thumbprint, kind }`. Throws a sentence
 *  that says why when the certificate's key cannot be linked. `pss` picks PS256 over RS256 for an RSA key. */
export function certificateKey(pem, { pss = false } = {}) {
  const cert = new X509Certificate(pem);
  const pub = cert.publicKey;
  const type = pub.asymmetricKeyType;
  let alg, key;
  if (type === "ed25519") {
    alg = "Ed25519";
    key = fromB64u(pub.export({ format: "jwk" }).x);
  } else if (type === "ec") {
    const curve = pub.asymmetricKeyDetails?.namedCurve;
    const jwk = pub.export({ format: "jwk" });
    const x = fromB64u(jwk.x), y = fromB64u(jwk.y);
    if (curve === "prime256v1") {
      alg = "ES256";
      key = Uint8Array.from([4, ...x, ...y]); // uncompressed: what Link takes for P-256 (D-108)
    } else if (curve === "secp256k1") {
      alg = "ES256K";
      key = Uint8Array.from([2 + (y[31] & 1), ...x]); // compressed: what Link takes for secp256k1 (D-082)
    } else {
      throw new Error(`the certificate's key is on ${curve}; Link takes P-256, secp256k1, Ed25519 and RSA keys`);
    }
  } else if (type === "rsa") {
    const d = pub.asymmetricKeyDetails;
    if (d.publicExponent !== 65537n) throw new Error(`the certificate's RSA key has exponent ${d.publicExponent}; Link takes 65537 only (D-112)`);
    if (d.modulusLength < 2048 || d.modulusLength > 4096) throw new Error(`the certificate's RSA key is ${d.modulusLength} bits; Link takes 2048 to 4096 (D-112)`);
    alg = pss ? "PS256" : "RS256";
    key = new Uint8Array(pub.export({ type: "spki", format: "der" }));
  } else {
    throw new Error(`the certificate's key is ${type}; Link takes P-256, secp256k1, Ed25519 and RSA keys`);
  }
  const thumbprint = presentedKeyThumbprint(key);
  if (!thumbprint) throw new Error("the certificate's key is not in a form Link reads");
  return { alg, key, thumbprint, subject: cert.subject, notAfter: cert.validTo };
}

/** The consent: the agent's private key signs the link's message, here. Returns the signature Link expects for `alg`:
 *  64 bytes `r || s` with the low S for ECDSA, 64 bytes for Ed25519, the modulus length for RSA. */
export function signConsent(privatePem, alg, message, publicKey) {
  const key = createPrivateKey(privatePem);
  // The private key must be the certificate's: a consent by another key is refused by the registrar, but saying so
  // here, before anything is sent, is the kinder answer.
  const mine = createPublicKey(key).export({ type: "spki", format: "der" });
  if (!Buffer.from(mine).equals(Buffer.from(publicKey.export({ type: "spki", format: "der" })))) {
    throw new Error("the private key is not the one in the certificate");
  }
  if (alg === "Ed25519") return new Uint8Array(nodeSign(null, message, key));
  if (alg === "ES256" || alg === "ES256K") {
    const sig = new Uint8Array(nodeSign("sha256", message, { key, dsaEncoding: "ieee-p1363" }));
    const n = alg === "ES256" ? P256_N : K256_N;
    const s = BigInt("0x" + Buffer.from(sig.slice(32)).toString("hex"));
    const low = s > n / 2n ? n - s : s; // Link takes the low-S twin (D-082, D-108)
    return Uint8Array.from([...sig.slice(0, 32), ...Buffer.from(low.toString(16).padStart(64, "0"), "hex")]);
  }
  if (alg === "RS256") return new Uint8Array(nodeSign("sha256", message, { key, padding: constants.RSA_PKCS1_PADDING }));
  if (alg === "PS256") {
    return new Uint8Array(nodeSign("sha256", message, { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }));
  }
  throw new Error(`no signer for ${alg}`);
}

/** The whole request body for `POST /link`: the certificate's key and the agent's consent to be linked to `passport`
 *  (its name, the registrar's id and its window) from `nbf` to `exp`. */
export function linkRequest({ certPem, keyPem, passport, registrarId, nbf, exp, pss = false }) {
  const k = certificateKey(certPem, { pss });
  const message = linkPopSigningBytes(registrarId, passport, k.thumbprint, nbf);
  const pop = signConsent(keyPem, k.alg, message, new X509Certificate(certPem).publicKey);
  return { body: { passport, alg: k.alg, key: b64u(k.key), pop: b64u(pop), nbf, exp }, key: k };
}

// ── the command ─────────────────────────────────────────────────────────────────────────────────────────────────
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const arg = (n) => { const i = process.argv.indexOf(`--${n}`); return i > 0 ? process.argv[i + 1] : undefined; };
  const need = ["cert", "key", "passport", "registrar", "token-file"].filter((n) => !arg(n));
  if (need.length) {
    console.error(`cert-link: missing --${need.join(", --")}\n  node kits/cert-link/link.mjs --cert agent.crt --key agent.key --passport SUB --registrar URL --token-file F`);
    process.exit(2);
  }
  const reg = arg("registrar").replace(/\/$/, "");
  try {
    const acc = await (await fetch(`${reg}/accreditation`)).json();
    const rec = await (await fetch(`${reg}/record?sub=${encodeURIComponent(arg("passport"))}`)).json();
    if (!rec.sub) throw new Error(`the registrar has no passport ${arg("passport")}`);
    const now = Math.floor(Date.now() / 1000);
    const nbf = Number(arg("nbf") ?? Math.max(rec.nbf, now));
    const exp = Number(arg("exp") ?? rec.exp);
    const { body, key } = linkRequest({
      certPem: readFileSync(arg("cert"), "utf8"), keyPem: readFileSync(arg("key"), "utf8"),
      passport: rec.sub, registrarId: arg("registrar-id") ?? acc.registrar, nbf, exp, pss: process.argv.includes("--pss"),
    });
    console.log(`certificate: ${key.subject} · ${key.alg} · thumbprint ${key.thumbprint}`);
    // The token goes into a request header only, never onto stdout.
    const token = readFileSync(arg("token-file"), "utf8").trim();
    const r = await fetch(`${reg}/link`, {
      method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: JSON.stringify(body),
    });
    const out = await r.json().catch(() => ({}));
    if (r.status !== 200) throw new Error(`the registrar refused the link: ${out.error ?? r.status}`);
    console.log(`linked to ${rec.sub} · log leaf ${out.leaf_index} · until ${new Date(exp * 1000).toISOString()}`);
  } catch (e) {
    console.error(`cert-link: ${e.message}`);
    process.exit(1);
  }
}
