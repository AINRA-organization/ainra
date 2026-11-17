// SPDX-License-Identifier: Apache-2.0 OR MIT
// D-112: RS256 and PS256 VERIFICATION for Link, written here.
//
// This is the one exception to "audited libraries only" in this package, and D-112 records why: none of the audited
// libraries this SDK already uses does RSA, and the platform's own RSA (WebCrypto) is asynchronous, while every
// verify call here is synchronous and runs unchanged in a browser. The exception is kept as small as it can be:
// - verification only: no private key, no signing, no secret anywhere, so there is nothing to leak by timing;
// - one exponent (65537), 2048 to 4096 bits, one canonical key encoding, decided before any arithmetic;
// - RS256 is checked by building the one valid encoding and comparing bytes (RFC 8017 §8.2.2), never by parsing it;
// - PS256 follows RFC 8017 §9.1.2 step by step with the salt fixed at 32 bytes (RFC 7518 §3.5).
// It is held to `vectors/v1-link` beside the Rust core (RustCrypto `rsa`) and Python (OpenSSL through
// `cryptography`): a byte this code reads differently from either of them fails `make diff`.

import { sha256 } from "@noble/hashes/sha256";

export const RSA_MIN_BITS = 2048;
export const RSA_MAX_BITS = 4096;
export const RSA_EXPONENT = Uint8Array.of(0x01, 0x00, 0x01);
const RSA_MAX_BYTES = RSA_MAX_BITS / 8;
/** DER AlgorithmIdentifier for rsaEncryption (1.2.840.113549.1.1.1) with NULL parameters. */
const RSA_ALG_ID = Uint8Array.of(0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00);
/** DER DigestInfo prefix for SHA-256 (RFC 8017 §9.2, note 1). */
const SHA256_DIGEST_INFO = Uint8Array.of(0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20);

function cat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}
function derLen(n: number): Uint8Array {
  if (n < 0x80) return Uint8Array.of(n);
  if (n < 0x100) return Uint8Array.of(0x81, n);
  return Uint8Array.of(0x82, n >> 8, n & 0xff);
}
function tlv(tag: number, content: Uint8Array): Uint8Array {
  return cat(Uint8Array.of(tag), derLen(content.length), content);
}
function eq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

/** The one canonical DER SubjectPublicKeyInfo of an RSA key with modulus `n` (big-endian, no leading zero) and
 *  exponent 65537 — byte for byte what `ainra_core::link::rsa_spki` and openssl produce. */
export function rsaSpki(n: Uint8Array): Uint8Array {
  const nInt = n.length > 0 && (n[0] & 0x80) !== 0 ? cat(Uint8Array.of(0), n) : n;
  const rsaPk = tlv(0x30, cat(tlv(0x02, nInt), tlv(0x02, RSA_EXPONENT)));
  return tlv(0x30, cat(RSA_ALG_ID, tlv(0x03, cat(Uint8Array.of(0), rsaPk))));
}

/** The modulus of an RSA key given as DER SubjectPublicKeyInfo, if and only if the bytes are {@link rsaSpki} of that
 *  modulus and the modulus is odd and 2048 to 4096 bits long; `null` otherwise. Mirrors `rsa_spki_modulus`. */
export function rsaSpkiModulus(der: Uint8Array): Uint8Array | null {
  const header = (at: number): [number, number] | null => {
    if (at + 1 >= der.length) return null;
    const first = der[at + 1];
    if (first < 0x80) return [at + 2, first];
    const k = first & 0x7f;
    if (k === 0 || k > 2 || at + 2 + k > der.length) return null;
    let len = 0;
    for (let i = 0; i < k; i++) len = (len << 8) | der[at + 2 + i];
    return [at + 2 + k, len];
  };
  const body = header(0);
  if (!body) return null;
  const bits = header(body[0] + RSA_ALG_ID.length);
  if (!bits) return null;
  const seq = header(bits[0] + 1);
  if (!seq || der[seq[0]] !== 0x02) return null;
  const nh = header(seq[0]);
  if (!nh || nh[0] + nh[1] > der.length) return null;
  let n = der.subarray(nh[0], nh[0] + nh[1]);
  if (n.length > 0 && n[0] === 0) n = n.subarray(1);
  if (n.length === 0 || n[0] === 0 || n.length > RSA_MAX_BYTES || (n[n.length - 1] & 1) === 0) return null;
  const nBits = n.length * 8 - Math.clz32(n[0]) + 24;
  if (nBits < RSA_MIN_BITS || nBits > RSA_MAX_BITS) return null;
  return eq(rsaSpki(n), der) ? n.slice() : null;
}

function os2ip(b: Uint8Array): bigint {
  let x = 0n;
  for (const v of b) x = (x << 8n) | BigInt(v);
  return x;
}
function i2osp(x: bigint, len: number): Uint8Array | null {
  const out = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) { out[i] = Number(x & 0xffn); x >>= 8n; }
  return x === 0n ? out : null;
}
/** s^65537 mod n: sixteen squarings and one multiplication. */
function pow65537(s: bigint, n: bigint): bigint {
  let r = s;
  for (let i = 0; i < 16; i++) r = (r * r) % n;
  return (r * s) % n;
}
function mgf1(seed: Uint8Array, len: number): Uint8Array {
  const out = new Uint8Array(len);
  let at = 0;
  for (let c = 0; at < len; c++) {
    const h = sha256(cat(seed, Uint8Array.of(c >>> 24, (c >>> 16) & 0xff, (c >>> 8) & 0xff, c & 0xff)));
    out.set(h.subarray(0, Math.min(32, len - at)), at);
    at += 32;
  }
  return out;
}

/** RS256 (`pss` false) or PS256 (`pss` true) verification of `sig` over `msg` by the RSA key with modulus `n` and
 *  exponent 65537. The signature is exactly as long as the modulus. Never throws. */
export function rsaVerify(n: Uint8Array, pss: boolean, msg: Uint8Array, sig: Uint8Array): boolean {
  const k = n.length;
  if (k === 0 || sig.length !== k) return false;
  const nn = os2ip(n);
  const s = os2ip(sig);
  if (s >= nn) return false;
  const m = pow65537(s, nn);
  const mHash = sha256(msg);
  if (!pss) {
    // EMSA-PKCS1-v1_5: 00 01 FF…FF 00 DigestInfo(SHA-256) H, as long as the modulus; compared whole.
    const t = cat(SHA256_DIGEST_INFO, mHash);
    if (k < t.length + 11) return false;
    const em = new Uint8Array(k);
    em[1] = 0x01;
    em.fill(0xff, 2, k - t.length - 1);
    em.set(t, k - t.length);
    const got = i2osp(m, k);
    return got !== null && eq(got, em);
  }
  // EMSA-PSS-VERIFY (RFC 8017 §9.1.2), SHA-256 and MGF1-SHA-256, salt of exactly 32 bytes.
  const hLen = 32, sLen = 32;
  const modBits = k * 8 - Math.clz32(n[0]) + 24;
  const emBits = modBits - 1;
  const emLen = Math.ceil(emBits / 8);
  const em = i2osp(m, emLen);
  if (em === null) return false;
  if (emLen < hLen + sLen + 2) return false;
  if (em[emLen - 1] !== 0xbc) return false;
  const maskedDb = em.subarray(0, emLen - hLen - 1);
  const h = em.subarray(emLen - hLen - 1, emLen - 1);
  const topMask = 0xff >> (8 * emLen - emBits);
  if ((maskedDb[0] & ~topMask & 0xff) !== 0) return false;
  const db = mgf1(h, maskedDb.length);
  for (let i = 0; i < db.length; i++) db[i] ^= maskedDb[i];
  db[0] &= topMask;
  const ps = emLen - hLen - sLen - 2;
  for (let i = 0; i < ps; i++) if (db[i] !== 0) return false;
  if (db[ps] !== 0x01) return false;
  const salt = db.subarray(db.length - sLen);
  return eq(sha256(cat(new Uint8Array(8), mHash, salt)), h);
}
