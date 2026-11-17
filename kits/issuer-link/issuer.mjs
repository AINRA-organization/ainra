// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// A stand-in for any identity system that issues tokens to agents. It is an ordinary token issuer in the usual
// shape: a discovery document, a published key set, and ES256 tokens (JWTs) that name the issuer in `iss`. It uses
// the platform's own signer and NO AINRA code, on purpose: an issuer does not have to adopt anything to be linked
// except to sign one statement, once, with the key it already issues with (`sign` below).
//
//   const idp = await startIssuer();          // http://127.0.0.1:<port>, ES256
//   const rsa = await startIssuer({ alg: "RS256" });   // RSA 2048, as the large identity providers sign (D-112)
//   const jwt = await idp.mint({ sub: "agent-7", aud: "https://api.example" });
import http from "node:http";
import { createHash } from "node:crypto";

const b64u = (b) => Buffer.from(b).toString("base64url");

export async function startIssuer({ alg = "ES256" } = {}) {
  // The issuing key lives in the platform's keystore and cannot be exported, as a real issuer's would not be.
  const rsa = alg === "RS256";
  const algo = rsa ? { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }
    : { name: "ECDSA", namedCurve: "P-256" };
  const pair = await crypto.subtle.generateKey(algo, false, ["sign", "verify"]);
  const pub = await crypto.subtle.exportKey("jwk", pair.publicKey);
  // The key id is the key's RFC 7638 thumbprint, as many issuers choose.
  const kid = b64u(createHash("sha256").update(rsa ? `{"e":"${pub.e}","kty":"RSA","n":"${pub.n}"}` : `{"crv":"P-256","kty":"EC","x":"${pub.x}","y":"${pub.y}"}`).digest());
  const jwk = rsa ? { kty: "RSA", n: pub.n, e: pub.e, kid, alg, use: "sig" } : { kty: "EC", crv: "P-256", x: pub.x, y: pub.y, kid, alg, use: "sig" };

  let issuer = "";
  const server = http.createServer((req, res) => {
    const send = (body) => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(body)); };
    if (req.url === "/.well-known/openid-configuration") return send({ issuer, jwks_uri: `${issuer}/jwks.json`, id_token_signing_alg_values_supported: [alg] });
    if (req.url === "/jwks.json") return send({ keys: [jwk] });
    res.writeHead(404); res.end();
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  issuer = `http://127.0.0.1:${server.address().port}`;

  /** A raw signature by the issuing key over `bytes`: ES256 `r || s` (64 bytes), or RS256 as long as the modulus. */
  const sign = async (bytes) => new Uint8Array(await crypto.subtle.sign(rsa ? { name: "RSASSA-PKCS1-v1_5" } : { name: "ECDSA", hash: "SHA-256" }, pair.privateKey, bytes));
  /** A token for one agent: `{ sub, aud }` and anything else the issuer says about it. Five minutes. */
  const mint = async (claims, { iss = issuer, lifetime = 300 } = {}) => {
    const now = Math.floor(Date.now() / 1000);
    const head = b64u(JSON.stringify({ alg, typ: "JWT", kid }));
    const body = b64u(JSON.stringify({ iss, iat: now, exp: now + lifetime, ...claims }));
    return `${head}.${body}.${b64u(await sign(Buffer.from(`${head}.${body}`)))}`;
  };
  /** The issuing key as it travels: for ES256 65 bytes, uncompressed (0x04 || x || y); for RS256 its DER
   *  SubjectPublicKeyInfo, as WebCrypto exports it. */
  const publicKey = rsa ? new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey))
    : Uint8Array.from([4, ...Buffer.from(pub.x, "base64url"), ...Buffer.from(pub.y, "base64url")]);
  return { issuer, alg, kid, publicKey, sign, mint, close: () => new Promise((r) => server.close(r)) };
}
