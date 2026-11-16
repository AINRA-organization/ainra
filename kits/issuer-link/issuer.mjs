// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// A stand-in for any identity system that issues tokens to agents. It is an ordinary token issuer in the usual
// shape: a discovery document, a published key set, and ES256 tokens (JWTs) that name the issuer in `iss`. It uses
// the platform's own signer and NO AINRA code, on purpose: an issuer does not have to adopt anything to be linked
// except to sign one statement, once, with the key it already issues with (`sign` below).
//
//   const idp = await startIssuer();          // http://127.0.0.1:<port>
//   const jwt = await idp.mint({ sub: "agent-7", aud: "https://api.example" });
import http from "node:http";
import { createHash } from "node:crypto";

const b64u = (b) => Buffer.from(b).toString("base64url");

export async function startIssuer() {
  // The issuing key lives in the platform's keystore and cannot be exported, as a real issuer's would not be.
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const { x, y } = await crypto.subtle.exportKey("jwk", pair.publicKey);
  // The key id is the key's RFC 7638 thumbprint, as many issuers choose.
  const kid = b64u(createHash("sha256").update(`{"crv":"P-256","kty":"EC","x":"${x}","y":"${y}"}`).digest());
  const jwk = { kty: "EC", crv: "P-256", x, y, kid, alg: "ES256", use: "sig" };

  let issuer = "";
  const server = http.createServer((req, res) => {
    const send = (body) => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(body)); };
    if (req.url === "/.well-known/openid-configuration") return send({ issuer, jwks_uri: `${issuer}/jwks.json`, id_token_signing_alg_values_supported: ["ES256"] });
    if (req.url === "/jwks.json") return send({ keys: [jwk] });
    res.writeHead(404); res.end();
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  issuer = `http://127.0.0.1:${server.address().port}`;

  /** A raw ES256 signature (r || s, 64 bytes) by the issuing key over `bytes`. */
  const sign = async (bytes) => new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, bytes));
  /** A token for one agent: `{ sub, aud }` and anything else the issuer says about it. Five minutes. */
  const mint = async (claims, { iss = issuer, lifetime = 300 } = {}) => {
    const now = Math.floor(Date.now() / 1000);
    const head = b64u(JSON.stringify({ alg: "ES256", typ: "JWT", kid }));
    const body = b64u(JSON.stringify({ iss, iat: now, exp: now + lifetime, ...claims }));
    return `${head}.${body}.${b64u(await sign(Buffer.from(`${head}.${body}`)))}`;
  };
  /** The issuing key as it travels: 65 bytes, uncompressed (0x04 || x || y). */
  const publicKey = Uint8Array.from([4, ...Buffer.from(x, "base64url"), ...Buffer.from(y, "base64url")]);
  return { issuer, kid, publicKey, sign, mint, close: () => new Promise((r) => server.close(r)) };
}
