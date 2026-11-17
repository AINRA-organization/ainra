// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AINRA Link (D-078): status and attribution for a credential the agent ALREADY has.
//!
//! An agent usually carries a key someone else issued or manages: a signature-agent key, a workload key. Its
//! issuer can withdraw it inside its own system, but nobody can tell a stranger's service that the key's agent has
//! been cut off, or who answers for it. A link record closes that gap without leaving the core:
//!
//! * an **accredited registrar** signs it with its hybrid key, exactly as it signs passports — both-or-invalid;
//! * it binds a key, named by its RFC 7638 thumbprint, to an **operator's passport** the same registrar issued;
//! * it carries **proof of control**: a signature by the linked key itself, so nobody can link a key they do not
//!   hold to a passport, and no key can be attributed to an operator without its holder's consent;
//! * it takes **two bits in the registrar's existing signed status list** — its own, and the passport's — so
//!   revoking the link, or the operator's whole lineage, refuses it everywhere;
//! * it is **logged before it is valid**, in the registrar's existing log, so the set of links can be audited.
//!
//! No new trust and no new list. The caller hands over the key it has ALREADY verified a signature with; this module
//! answers whether that key is linked, by whom, and whether it is still trusted.
//!
//! **Two kinds of link (D-110).** A `jwk` link is for a key that signs REQUESTS: the agent's own key. An `issuer`
//! link is for a key that signs TOKENS naming other agents: the key another identity system issues with, and the
//! one name (`iss`) it issues as. The key consents to one kind, in its own words, and a link presented for the
//! other use is refused. An issuer link says who answers for that key while it signs as that issuer. It does not
//! say the key belongs to the issuer: a gate learns that where it always has, from the keys the issuer publishes,
//! and looks a link up by the key it verified the token with, never by the issuer's name.
//!
//! Order (each step's failure reason in parentheses), fixed so every implementation reports the same first failure:
//!   1. schema                                   (`schema_violation`, `name_malformed`)
//!   2. the registrar is accredited              (`unknown_registrar`)
//!   3. validity window                          (`not_yet_valid`, then `expired`)
//!   4. registrar hybrid signature               (`alg_downgrade`, then `sig_invalid`)
//!   5. the presented key IS the linked key, used as the link says, and it consented to that (`sig_invalid`)
//!   6. scope                                    (`ceiling_exceeded`)
//!   7. status: freshness, then the link's bit, then the passport's bit (`stale_status`, then `revoked`)
//!   8. logged-before-valid                      (`checkpoint_invalid`, then `not_logged`, then `registrar_distrusted`)

extern crate alloc;
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::name::AinraName;
use crate::verdict::Reason;
use crate::verify::{prelog_leaf, TrustAnchors};
use crate::{b64, canon, checkpoint, crypto, status};

/// The link record's version tag. Frozen: it is inside what the registrar signs.
pub const LINK_V: &str = "ainra-link-1";
/// The purpose string the linked key signs over (proof of control). Frozen.
pub const LINK_POP_PURPOSE: &str = "ainra-link-pop-1";
/// A key that signs requests, named by its RFC 7638 thumbprint.
pub const SUBJECT_KIND_JWK: &str = "jwk";
/// A key that signs tokens naming other agents (D-110): the same thumbprint, and the one issuer name it signs as.
pub const SUBJECT_KIND_ISSUER: &str = "issuer";
/// The purpose string an issuer key signs over to consent to an issuer link. Frozen. Not [`LINK_POP_PURPOSE`]: a
/// key that agreed to be linked as itself has not agreed to answer for every token it signs, and the reverse.
pub const ISSUER_LINK_POP_PURPOSE: &str = "ainra-issuer-link-pop-1";
/// Longest issuer name a link may carry, in bytes.
pub const MAX_ISSUER_LEN: usize = 255;
/// Signature-agent keys and AINRA's own workload keys are Ed25519.
pub const SUBJECT_ALG_ED25519: &str = "Ed25519";
/// ES256K (RFC 8812): ECDSA over secp256k1 with SHA-256 — the keys agents that live on ledgers already hold (D-082).
/// Signatures are 64-byte `r || s` and must be low-S, so no signature can be re-encoded into a second valid one.
pub const SUBJECT_ALG_ES256K: &str = "ES256K";
/// ES256 (RFC 7518): ECDSA over NIST P-256 with SHA-256 — the keys most other identity systems issue: certificates,
/// signed agent cards, token issuers, hardware and platform keystores (D-108). Signatures are 64-byte `r || s` and
/// must be low-S, the one rule for both ECDSA algorithms here; a signer that returns the high-S twin sends `n - s`.
pub const SUBJECT_ALG_ES256: &str = "ES256";
/// RS256 (RFC 7518): RSASSA-PKCS1-v1_5 with SHA-256 — how the large identity providers sign their tokens (D-112).
pub const SUBJECT_ALG_RS256: &str = "RS256";
/// PS256 (RFC 7518): RSASSA-PSS with SHA-256, MGF1 with SHA-256 and a salt of exactly 32 bytes (D-112).
pub const SUBJECT_ALG_PS256: &str = "PS256";
/// The RSA key family's name, for messages; an RSA link names RS256 or PS256.
pub const KEY_FAMILY_RSA: &str = "RSA";
/// RSA moduli Link accepts, in bits, inclusive. Below 2048 is refused by name; above 4096 bounds a gate's work.
pub const RSA_MIN_BITS: usize = 2048;
pub const RSA_MAX_BITS: usize = 4096;
/// The one public exponent Link accepts. Every identity system checked publishes it, and one value means one
/// canonical encoding of each key.
pub const RSA_EXPONENT: [u8; 3] = [0x01, 0x00, 0x01];
const RSA_MAX_BYTES: usize = RSA_MAX_BITS / 8;
/// DER `AlgorithmIdentifier` for rsaEncryption (1.2.840.113549.1.1.1) with NULL parameters.
const RSA_ALG_ID: [u8; 15] = [
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
];
/// DER `DigestInfo` prefix for SHA-256 (RFC 8017 §9.2, note 1).
const SHA256_DIGEST_INFO: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// A key a caller has already verified a signature with, as Link names it. By length: 32 bytes is an Ed25519 key,
/// 33 a compressed SEC1 secp256k1 point, 65 an UNCOMPRESSED SEC1 P-256 point (`0x04 || x || y`, the form that key
/// has in a JWK, a COSE key and a certificate). Anything longer must be an RSA key (D-112) as DER
/// SubjectPublicKeyInfo — the form a certificate, `openssl rsa -pubout -outform DER` and WebCrypto's `spki` export
/// carry — in its one canonical encoding: so every caller that passes a 32-byte key keeps meaning Ed25519, and no
/// length means two things (the shortest RSA key Link accepts is 294 bytes).
// The RSA variant holds a 4096-bit modulus inline so the key stays `Copy` and allocation-free on the verify path; at
// about half a kilobyte it is still a small stack value, and the key is read once per check.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresentedKey {
    Ed25519([u8; 32]),
    Es256k([u8; 33]),
    Es256([u8; 65]),
    /// The modulus, big-endian with no leading zero, in the first `len` bytes; the exponent is [`RSA_EXPONENT`].
    Rsa {
        n: [u8; RSA_MAX_BYTES],
        len: u16,
    },
}

impl PresentedKey {
    /// `None` for any other length, and for 65 bytes that are not an uncompressed point on P-256: before D-108 no
    /// 65-byte key was a key at all (an uncompressed secp256k1 point is refused as malformed, vector l42), and that
    /// stays true of every 65-byte string except a P-256 key.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        match b.len() {
            32 => b.try_into().ok().map(PresentedKey::Ed25519),
            33 => b.try_into().ok().map(PresentedKey::Es256k),
            65 => {
                let k: [u8; 65] = b.try_into().ok()?;
                p256_affine(&k).map(|_| PresentedKey::Es256(k))
            }
            n if n > 65 => {
                let m = rsa_spki_modulus(b)?;
                let mut n = [0u8; RSA_MAX_BYTES];
                n[..m.len()].copy_from_slice(m);
                Some(PresentedKey::Rsa {
                    n,
                    len: m.len() as u16,
                })
            }
            _ => None,
        }
    }
    /// The key's algorithm, or for an RSA key its family ([`KEY_FAMILY_RSA`]): one RSA key may be linked as RS256 or
    /// as PS256. Use [`Self::fits`] to ask whether a link's `alg` can be this key's.
    pub fn alg(&self) -> &'static str {
        match self {
            PresentedKey::Ed25519(_) => SUBJECT_ALG_ED25519,
            PresentedKey::Es256k(_) => SUBJECT_ALG_ES256K,
            PresentedKey::Es256(_) => SUBJECT_ALG_ES256,
            PresentedKey::Rsa { .. } => KEY_FAMILY_RSA,
        }
    }
    /// Whether a link whose `subject.alg` is `alg` can be for this key.
    pub fn fits(&self, alg: &str) -> bool {
        match self {
            PresentedKey::Rsa { .. } => alg == SUBJECT_ALG_RS256 || alg == SUBJECT_ALG_PS256,
            k => k.alg() == alg,
        }
    }
    /// The RSA modulus, for an RSA key.
    fn modulus(&self) -> Option<&[u8]> {
        match self {
            PresentedKey::Rsa { n, len } => Some(&n[..*len as usize]),
            _ => None,
        }
    }
    /// The RFC 7638 thumbprint; `None` for bytes that are not a point on the key's curve.
    pub fn thumbprint(&self) -> Option<String> {
        match self {
            PresentedKey::Ed25519(k) => Some(jwk_thumbprint_ed25519(k)),
            PresentedKey::Es256k(k) => jwk_thumbprint_es256k(k),
            PresentedKey::Es256(k) => jwk_thumbprint_es256(k),
            PresentedKey::Rsa { .. } => self.modulus().map(jwk_thumbprint_rsa),
        }
    }
    /// Verify a signature by this key over `msg` in the link algorithm `alg` (which must [`Self::fits`] the key).
    /// Ed25519, ES256K and ES256 signatures are 64 bytes; an RSA signature is exactly as long as the modulus.
    pub fn verify(&self, alg: &str, msg: &[u8], sig: &[u8]) -> bool {
        if !self.fits(alg) {
            return false;
        }
        match self {
            PresentedKey::Rsa { .. } => {
                let n = self.modulus().unwrap_or_default();
                rsa_verify(n, alg == SUBJECT_ALG_PS256, msg, sig)
            }
            k => {
                let Ok(sig) = <&[u8; 64]>::try_from(sig) else {
                    return false;
                };
                match k {
                    PresentedKey::Ed25519(k) => crypto::ed25519_verify(k, msg, sig),
                    PresentedKey::Es256k(k) => es256k_verify(k, msg, sig),
                    PresentedKey::Es256(k) => es256_verify(k, msg, sig),
                    PresentedKey::Rsa { .. } => false,
                }
            }
        }
    }
}

/// DER length octets for `n` (definite, minimal form).
fn der_len(n: usize, out: &mut Vec<u8>) {
    if n < 0x80 {
        out.push(n as u8);
    } else if n < 0x100 {
        out.extend_from_slice(&[0x81, n as u8]);
    } else {
        out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
    }
}

fn der_tlv(tag: u8, content: &[u8], out: &mut Vec<u8>) {
    out.push(tag);
    der_len(content.len(), out);
    out.extend_from_slice(content);
}

/// The one canonical DER SubjectPublicKeyInfo of an RSA key with modulus `n` (big-endian, no leading zero) and
/// exponent 65537: rsaEncryption with NULL parameters, then the RSAPublicKey in a BIT STRING with no unused bits.
/// Every implementation builds the same bytes, so "is this a key" has one answer everywhere (D-112).
pub fn rsa_spki(n: &[u8]) -> Vec<u8> {
    let mut n_int = Vec::with_capacity(n.len() + 1);
    if n.first().is_some_and(|b| b & 0x80 != 0) {
        n_int.push(0);
    }
    n_int.extend_from_slice(n);
    let mut rsa_pk = Vec::new();
    der_tlv(0x02, &n_int, &mut rsa_pk);
    der_tlv(0x02, &RSA_EXPONENT, &mut rsa_pk);
    let mut seq = Vec::new();
    der_tlv(0x30, &rsa_pk, &mut seq);
    let mut bits = alloc::vec![0u8];
    bits.extend_from_slice(&seq);
    let mut body = RSA_ALG_ID.to_vec();
    der_tlv(0x03, &bits, &mut body);
    let mut out = Vec::new();
    der_tlv(0x30, &body, &mut out);
    out
}

/// The modulus of an RSA key given as DER SubjectPublicKeyInfo, if and only if the bytes are [`rsa_spki`] of that
/// modulus (so non-minimal lengths, another exponent, absent parameters or trailing bytes are not a key), and the
/// modulus is odd and between [`RSA_MIN_BITS`] and [`RSA_MAX_BITS`] bits long.
pub fn rsa_spki_modulus(der: &[u8]) -> Option<&[u8]> {
    // Find the modulus INTEGER: it follows SEQUENCE{ algid, BIT STRING{ 00, SEQUENCE{ INTEGER n … } } }. Read the
    // lengths loosely here; the byte-for-byte comparison with the canonical encoding below is the real check.
    fn skip_header(b: &[u8], at: usize) -> Option<(usize, usize)> {
        let first = *b.get(at + 1)?;
        if first < 0x80 {
            return Some((at + 2, first as usize));
        }
        let k = (first & 0x7f) as usize;
        if k == 0 || k > 2 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..k {
            len = (len << 8) | *b.get(at + 2 + i)? as usize;
        }
        Some((at + 2 + k, len))
    }
    let (body, _) = skip_header(der, 0)?;
    let bit = body + RSA_ALG_ID.len();
    let (bits, _) = skip_header(der, bit)?;
    let (seq, _) = skip_header(der, bits + 1)?;
    if der.get(seq) != Some(&0x02) {
        return None;
    }
    let (n_at, n_len) = skip_header(der, seq)?;
    let mut n = der.get(n_at..n_at.checked_add(n_len)?)?;
    if n.first() == Some(&0) {
        n = &n[1..];
    }
    if n.is_empty() || n[0] == 0 || n.len() > RSA_MAX_BYTES || n[n.len() - 1] & 1 == 0 {
        return None;
    }
    let bits = n.len() * 8 - n[0].leading_zeros() as usize;
    if !(RSA_MIN_BITS..=RSA_MAX_BITS).contains(&bits) {
        return None;
    }
    (rsa_spki(n) == der).then_some(n)
}

/// RFC 7638 thumbprint of an RSA key: base64url(SHA-256(`{"e":"AQAB","kty":"RSA","n":"…"}`)), `n` the modulus
/// big-endian with no leading zero, the member names RFC 7518 registers.
pub fn jwk_thumbprint_rsa(n: &[u8]) -> String {
    #[derive(Serialize)]
    struct Jwk<'a> {
        e: String,
        kty: &'a str,
        n: String,
    }
    use sha2::{Digest, Sha256};
    let j = Jwk {
        e: b64::encode(&RSA_EXPONENT),
        kty: "RSA",
        n: b64::encode(n),
    };
    let s = canon::canonicalize(&j).unwrap_or_default();
    b64::encode(&Sha256::digest(s.as_bytes()))
}

/// RS256 or PS256 verification of `sig` over `msg` by the RSA key with modulus `n` and exponent 65537. The signature
/// is exactly as long as the modulus (RFC 8017 §8.2.2, §8.1.2 step 1). PS256 is RSASSA-PSS with SHA-256, MGF1 with
/// SHA-256 and a salt of exactly 32 bytes (RFC 7518 §3.5): any other salt length is refused.
pub fn rsa_verify(n: &[u8], pss: bool, msg: &[u8], sig: &[u8]) -> bool {
    use rsa::traits::SignatureScheme as _;
    use sha2::{Digest, Sha256};
    if sig.len() != n.len() || n.is_empty() {
        return false;
    }
    let bits = (n.len() * 8) as u32;
    let (Ok(nn), Ok(ee)) = (
        rsa::BoxedUint::from_be_slice(n, bits),
        rsa::BoxedUint::from_be_slice(&RSA_EXPONENT, 32),
    ) else {
        return false;
    };
    let Ok(key) = rsa::PublicKey::new_with_size_limits(nn, ee, RSA_MIN_BITS..=RSA_MAX_BITS) else {
        return false;
    };
    let hashed = Sha256::digest(msg);
    if pss {
        rsa::pss::Pss::<rsa::sha2::Sha256>::new_with_salt(32)
            .verify(&key, &hashed, sig)
            .is_ok()
    } else {
        rsa::pkcs1v15::Pkcs1v15Sign {
            hash_len: Some(32),
            prefix: SHA256_DIGEST_INFO.to_vec().into_boxed_slice(),
        }
        .verify(&key, &hashed, sig)
        .is_ok()
    }
}

impl From<[u8; 32]> for PresentedKey {
    fn from(k: [u8; 32]) -> Self {
        PresentedKey::Ed25519(k)
    }
}
/// Most capabilities a link may name (the same bound as an instance credential, D-053).
pub const MAX_LINK_SCOPE: usize = crate::instance::MAX_CAPABILITIES;

/// Which key the link is for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkSubject {
    pub kind: String,
    pub alg: String,
    /// base64url(SHA-256(canonical JWK)), RFC 7638.
    pub thumbprint: String,
    /// Kind `issuer` only: the name the key issues as, compared byte for byte with the one in what it signed (a
    /// token's `iss`). Absent on a `jwk` link; an explicit `null` is not canonical and is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
}

/// An issuer name a link may carry: 1 to [`MAX_ISSUER_LEN`] bytes of visible ASCII (0x21 to 0x7E). No space, no
/// control character and nothing outside ASCII, so two names that look the same are the same bytes.
pub fn issuer_name_ok(iss: &str) -> bool {
    !iss.is_empty()
        && iss.len() <= MAX_ISSUER_LEN
        && iss.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// A status-list position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusRef {
    pub uri: String,
    pub idx: u64,
}

/// The log back-reference, as on a passport: it points INTO the log, so it is not part of what was logged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkLog {
    pub leaf: String,
}

/// The signed link claims. Field names are frozen: they are what the registrar signs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkClaims {
    pub v: String,
    pub registrar: String,
    /// The operator's passport this key acts under (an AINRA name, e.g. `ainra:registrar-07:acme:invoicing@1.0.0`).
    pub passport: String,
    pub subject: LinkSubject,
    /// Capabilities the linked key may exercise. Empty means: whatever the passport allows.
    pub scope: Vec<String>,
    pub nbf: u64,
    pub exp: u64,
    pub status: StatusRef,
    pub passport_status: StatusRef,
    /// base64url Ed25519 signature by the linked key over [`pop_signing_bytes`].
    pub pop: String,
    pub log: LinkLog,
}

impl LinkClaims {
    /// Parse the exact signed bytes, refusing anything that is not a well-formed version-1 link.
    pub fn parse_checked(bytes: &[u8]) -> core::result::Result<Self, Reason> {
        let c: LinkClaims = serde_json::from_slice(bytes).map_err(|_| Reason::SchemaViolation)?;
        // The signed bytes must already be canonical: one record, one byte string, everywhere (D-029).
        let again = canon::canonicalize(&c).map_err(|_| Reason::SchemaViolation)?;
        if again.as_bytes() != bytes {
            return Err(Reason::SchemaViolation);
        }
        let rsa = c.subject.alg == SUBJECT_ALG_RS256 || c.subject.alg == SUBJECT_ALG_PS256;
        if c.v != LINK_V
            || !(rsa
                || c.subject.alg == SUBJECT_ALG_ED25519
                || c.subject.alg == SUBJECT_ALG_ES256K
                || c.subject.alg == SUBJECT_ALG_ES256)
        {
            return Err(Reason::SchemaViolation);
        }
        // A `jwk` link names no issuer; an `issuer` link names exactly one, well-formed (D-110).
        let kind_ok = match (c.subject.kind.as_str(), c.subject.iss.as_deref()) {
            (SUBJECT_KIND_JWK, None) => true,
            (SUBJECT_KIND_ISSUER, Some(iss)) => issuer_name_ok(iss),
            _ => false,
        };
        if !kind_ok {
            return Err(Reason::SchemaViolation);
        }
        b64::decode_array::<32>(&c.subject.thumbprint).map_err(|_| Reason::SchemaViolation)?;
        // The consent: 64 bytes for Ed25519 and the ECDSA algorithms; for RSA as long as a 2048- to 4096-bit modulus
        // (its exact length is checked against the key in step 5).
        let pop = b64::decode(&c.pop).map_err(|_| Reason::SchemaViolation)?;
        let pop_ok = if rsa {
            (RSA_MIN_BITS / 8..=RSA_MAX_BYTES).contains(&pop.len())
        } else {
            pop.len() == 64
        };
        if !pop_ok {
            return Err(Reason::SchemaViolation);
        }
        b64::decode_array::<32>(&c.log.leaf).map_err(|_| Reason::SchemaViolation)?;
        if c.scope.len() > MAX_LINK_SCOPE || c.scope.iter().any(|s| s.is_empty() || s.len() > 128) {
            return Err(Reason::SchemaViolation);
        }
        // Both bits live in the one list the registrar signs; a link pointing at two lists cannot be checked whole.
        if c.status.uri != c.passport_status.uri || c.status.idx == c.passport_status.idx {
            return Err(Reason::SchemaViolation);
        }
        if c.nbf >= c.exp {
            return Err(Reason::SchemaViolation);
        }
        let name = AinraName::parse(&c.passport).map_err(|_| Reason::NameMalformed)?;
        // A registrar links only passports it issued itself.
        if name.registrar() != c.registrar {
            return Err(Reason::SchemaViolation);
        }
        Ok(c)
    }
}

/// RFC 7638 thumbprint of an Ed25519 public key: base64url(SHA-256(`{"crv":"Ed25519","kty":"OKP","x":"…"}`)).
/// The core's canonical encoder sorts keys and drops whitespace, which is exactly the RFC's required form.
pub fn jwk_thumbprint_ed25519(pk: &[u8; 32]) -> String {
    #[derive(Serialize)]
    struct Jwk<'a> {
        crv: &'a str,
        kty: &'a str,
        x: String,
    }
    use sha2::{Digest, Sha256};
    let j = Jwk {
        crv: "Ed25519",
        kty: "OKP",
        x: b64::encode(pk),
    };
    // canonicalize cannot fail on three ASCII strings; an empty input would only ever fail a later comparison.
    let s = canon::canonicalize(&j).unwrap_or_default();
    b64::encode(&Sha256::digest(s.as_bytes()))
}

/// RFC 7638 thumbprint of a secp256k1 key given as a compressed SEC1 point: base64url(SHA-256(
/// `{"crv":"secp256k1","kty":"EC","x":"…","y":"…"}`)), the member names and curve name RFC 8812 registers. `None`
/// when the bytes are not a compressed point on the curve.
pub fn jwk_thumbprint_es256k(sec1: &[u8; 33]) -> Option<String> {
    use k256::elliptic_curve::sec1::ToSec1Point;
    #[derive(Serialize)]
    struct Jwk<'a> {
        crv: &'a str,
        kty: &'a str,
        x: String,
        y: String,
    }
    use sha2::{Digest, Sha256};
    if !matches!(sec1[0], 0x02 | 0x03) {
        return None;
    }
    let pk = k256::PublicKey::from_sec1_bytes(sec1).ok()?;
    let p = pk.to_sec1_point(false);
    let j = Jwk {
        crv: "secp256k1",
        kty: "EC",
        x: b64::encode(p.x()?),
        y: b64::encode(p.y()?),
    };
    let s = canon::canonicalize(&j).ok()?;
    Some(b64::encode(&Sha256::digest(s.as_bytes())))
}

/// ES256K verification (RFC 8812): ECDSA over secp256k1 with SHA-256 of `msg`, the signature as 64-byte `r || s`.
/// A high-S signature is refused even though the curve math accepts it: its low-S twin is the canonical form, and
/// accepting both would give every consent two valid encodings.
pub fn es256k_verify(sec1: &[u8; 33], msg: &[u8], sig: &[u8; 64]) -> bool {
    use k256::ecdsa::signature::Verifier as _;
    use k256::ecdsa::{Signature, VerifyingKey};
    if !matches!(sec1[0], 0x02 | 0x03) {
        return false;
    }
    let (Ok(vk), Ok(s)) = (
        VerifyingKey::from_sec1_bytes(sec1),
        Signature::from_slice(sig),
    ) else {
        return false;
    };
    // High-S when normalising changes it: the same test on every k256 line (0.13 returned an Option here, 0.14 the
    // signature itself).
    if s.normalize_s() != s {
        return false;
    }
    vk.verify(msg, &s).is_ok()
}

/// The affine `x` and `y` of an uncompressed SEC1 P-256 point (`0x04 || x || y`); `None` when the bytes are not one.
fn p256_affine(sec1: &[u8; 65]) -> Option<([u8; 32], [u8; 32])> {
    use p256::elliptic_curve::sec1::ToSec1Point;
    if sec1[0] != 0x04 {
        return None;
    }
    let pk = p256::PublicKey::from_sec1_bytes(sec1).ok()?;
    let p = pk.to_sec1_point(false);
    Some((
        p.x()?.as_slice().try_into().ok()?,
        p.y()?.as_slice().try_into().ok()?,
    ))
}

/// RFC 7638 thumbprint of a P-256 key given as an uncompressed SEC1 point: base64url(SHA-256(
/// `{"crv":"P-256","kty":"EC","x":"…","y":"…"}`)), the member names and curve name RFC 7518 registers. `None` when
/// the bytes are not an uncompressed point on the curve.
pub fn jwk_thumbprint_es256(sec1: &[u8; 65]) -> Option<String> {
    #[derive(Serialize)]
    struct Jwk<'a> {
        crv: &'a str,
        kty: &'a str,
        x: String,
        y: String,
    }
    use sha2::{Digest, Sha256};
    let (x, y) = p256_affine(sec1)?;
    let j = Jwk {
        crv: "P-256",
        kty: "EC",
        x: b64::encode(&x),
        y: b64::encode(&y),
    };
    let s = canon::canonicalize(&j).ok()?;
    Some(b64::encode(&Sha256::digest(s.as_bytes())))
}

/// ES256 verification (RFC 7518): ECDSA over P-256 with SHA-256 of `msg`, the signature as 64-byte `r || s`.
/// A high-S signature is refused, as for ES256K and for the same reason: its low-S twin is the canonical form, and
/// accepting both would give every consent two valid encodings. (RFC 7518 itself accepts both; a P-256 signer that
/// returns high-S replaces `s` with `n - s`, which anyone can do and which is the same statement by the same key.)
pub fn es256_verify(sec1: &[u8; 65], msg: &[u8], sig: &[u8; 64]) -> bool {
    use p256::ecdsa::signature::Verifier as _;
    use p256::ecdsa::{Signature, VerifyingKey};
    if sec1[0] != 0x04 {
        return false;
    }
    let (Ok(vk), Ok(s)) = (
        VerifyingKey::from_sec1_bytes(sec1),
        Signature::from_slice(sig),
    ) else {
        return false;
    };
    if s.normalize_s() != s {
        return false;
    }
    vk.verify(msg, &s).is_ok()
}

/// What the linked key signs to consent to the link. Frozen.
pub fn pop_signing_bytes(registrar: &str, passport: &str, thumbprint: &str, nbf: u64) -> Vec<u8> {
    #[derive(Serialize)]
    struct Pop<'a> {
        purpose: &'a str,
        registrar: &'a str,
        passport: &'a str,
        thumbprint: &'a str,
        nbf: u64,
    }
    canon::canonicalize(&Pop {
        purpose: LINK_POP_PURPOSE,
        registrar,
        passport,
        thumbprint,
        nbf,
    })
    .unwrap_or_default()
    .into_bytes()
}

/// What an issuer key signs to consent to an issuer link (D-110). Frozen. It names the issuer, so a consent given
/// for one name is not a consent for another.
pub fn issuer_pop_signing_bytes(
    registrar: &str,
    passport: &str,
    thumbprint: &str,
    iss: &str,
    nbf: u64,
) -> Vec<u8> {
    #[derive(Serialize)]
    struct Pop<'a> {
        purpose: &'a str,
        registrar: &'a str,
        passport: &'a str,
        thumbprint: &'a str,
        iss: &'a str,
        nbf: u64,
    }
    canon::canonicalize(&Pop {
        purpose: ISSUER_LINK_POP_PURPOSE,
        registrar,
        passport,
        thumbprint,
        iss,
        nbf,
    })
    .unwrap_or_default()
    .into_bytes()
}

/// Everything a verifier hands over to check one link. Like [`crate::verify::Presentation`], the core has no clock
/// and no network: the caller supplies `now` and every fetched artefact, and the status list it supplies must
/// already be AUTHENTICATED against the registrar's status key (D-072) — this module trusts the bits it is given.
pub struct LinkCheck<'a> {
    /// The exact signed link claims.
    pub claims: &'a [u8],
    pub registrar_sig: crypto::HybridSig,
    /// The key the caller ALREADY verified the request's signature with, in its algorithm.
    pub presented_key: PresentedKey,
    pub now: u64,
    pub status_list: &'a status::StatusList,
    pub status_issued_at: u64,
    pub freshness: status::Freshness,
    pub checkpoint: &'a checkpoint::Checkpoint,
    pub checkpoint_sig: &'a checkpoint::CheckpointSig,
    pub leaf_index: u64,
    pub inclusion_proof: &'a [[u8; 32]],
    pub revoked_delegates: &'a BTreeSet<[u8; 32]>,
    /// The capability the request exercises, if the verifier checks one.
    pub capability: Option<&'a str>,
    /// How the caller used `presented_key` (D-110). `None`: it verified the REQUEST's signature with it. `Some`:
    /// it verified a TOKEN with it, and this is the issuer name written in that token (its `iss`), which the
    /// caller has already matched to the key in the ordinary way, from the keys that issuer publishes.
    pub issuer: Option<&'a str>,
}

/// Who a valid link attributes the key to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribution {
    pub registrar: String,
    pub operator: String,
    pub passport: String,
    pub scope: Vec<String>,
    /// For an issuer link: the issuer name the link is for. The operator answers for the ISSUER; nothing here
    /// vouches for the agent a token names.
    pub issuer: Option<String>,
}

/// Check one link. Never panics. `Ok` carries the attribution; `Err` the first failing reason in the fixed order.
pub fn verify_link(
    chk: &LinkCheck,
    anchors: &TrustAnchors,
) -> core::result::Result<Attribution, Reason> {
    // 1. schema
    let c = LinkClaims::parse_checked(chk.claims)?;
    let name = AinraName::parse(&c.passport).map_err(|_| Reason::NameMalformed)?;

    // 2. the registrar is accredited
    let reg = anchors
        .registrars
        .get(&c.registrar)
        .ok_or(Reason::UnknownRegistrar)?;

    // 3. validity window, exact (ADR-017)
    if chk.now < c.nbf {
        return Err(Reason::NotYetValid);
    }
    if chk.now >= c.exp {
        return Err(Reason::Expired);
    }

    // 4. the registrar signed exactly these bytes, with both halves of its key
    crypto::verify_hybrid(&reg.issuer_key, chk.claims, &chk.registrar_sig)?;

    // 5. the key the caller verified is the linked key — same algorithm, same thumbprint — it was used as the link
    //    says (a request's key for a `jwk` link; a token's issuer key, under this issuer name, for an `issuer`
    //    link), and that key consented to exactly that
    if !chk.presented_key.fits(&c.subject.alg)
        || chk.presented_key.thumbprint().as_deref() != Some(c.subject.thumbprint.as_str())
    {
        return Err(Reason::SigInvalid);
    }
    let msg = match (c.subject.iss.as_deref(), chk.issuer) {
        (None, None) => pop_signing_bytes(&c.registrar, &c.passport, &c.subject.thumbprint, c.nbf),
        (Some(named), Some(used)) if named == used => issuer_pop_signing_bytes(
            &c.registrar,
            &c.passport,
            &c.subject.thumbprint,
            named,
            c.nbf,
        ),
        _ => return Err(Reason::SigInvalid),
    };
    let pop = b64::decode(&c.pop).map_err(|_| Reason::SchemaViolation)?;
    if !chk.presented_key.verify(&c.subject.alg, &msg, &pop) {
        return Err(Reason::SigInvalid);
    }

    // 6. scope: a narrowed link refuses anything it does not name
    if let Some(cap) = chk.capability {
        if !c.scope.is_empty() && !c.scope.iter().any(|s| s == cap) {
            return Err(Reason::CeilingExceeded);
        }
    }

    // 7. status: fresh first, then the link's own bit, then the operator's lineage
    chk.freshness.check(chk.now, chk.status_issued_at)?;
    if chk.status_list.status_of(c.status.idx) == status::LineageStatus::Revoked {
        return Err(Reason::Revoked);
    }
    if chk.status_list.status_of(c.passport_status.idx) == status::LineageStatus::Revoked {
        return Err(Reason::Revoked);
    }

    // 8. logged before valid — the same machinery, and the same order, as a passport (verify.rs step 9),
    //    including D-111: a distrusted registrar with a pinned head is proven against that head and no other.
    if !crate::verify::pinned_head_holds(reg, chk.checkpoint)? {
        chk.checkpoint
            .verify_sig_mode(&reg.log_root_key, chk.checkpoint_sig, chk.now)?;
        if let checkpoint::CheckpointSig::Delegate { cert, .. } = chk.checkpoint_sig {
            if chk.revoked_delegates.contains(&cert.fingerprint()) {
                return Err(Reason::CheckpointInvalid);
            }
        }
    }
    let expected_leaf = prelog_leaf(chk.claims)?;
    let claimed_leaf: [u8; 32] = b64::decode_array(&c.log.leaf).map_err(|_| Reason::NotLogged)?;
    if claimed_leaf != expected_leaf {
        return Err(Reason::NotLogged);
    }
    checkpoint::verify_logged(
        &claimed_leaf,
        chk.leaf_index,
        chk.checkpoint,
        chk.inclusion_proof,
    )?;
    if let Some(cut) = reg.distrust_from_leaf {
        if chk.leaf_index >= cut {
            return Err(Reason::RegistrarDistrusted);
        }
    }

    Ok(Attribution {
        registrar: c.registrar,
        operator: String::from(name.operator()),
        passport: c.passport,
        scope: c.scope,
        issuer: c.subject.iss,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle;
    use crate::verify::RegistrarInfo;
    use alloc::collections::BTreeMap;
    use alloc::string::ToString;
    use rand_core::SeedableRng;
    use serde_json::json;

    // A genuinely valid link — real registrar signature, real proof of control, a real Merkle log — plus knobs, so
    // each test flips exactly one thing and asserts the verdict. Nothing is mocked.
    struct Fx {
        anchors: TrustAnchors,
        claims: Vec<u8>,
        sig: crypto::HybridSig,
        key: [u8; 32],
        cp: checkpoint::Checkpoint,
        cp_sig: checkpoint::CheckpointSig,
        proof: Vec<[u8; 32]>,
        leaf_index: u64,
        list: status::StatusList,
        issuer: crypto::HybridKeypair,
        agent: ed25519_dalek::SigningKey,
        /// A genuine inclusion proof for a DIFFERENT leaf of the same log (index 0, the first filler).
        other_proof: Vec<[u8; 32]>,
    }

    const REG: &str = "registrar-01";
    const PASSPORT: &str = "ainra:registrar-01:acme:invoicing@1.0.0";

    const ISS: &str = "https://issuer.example";

    fn body(thumb: &str, pop: &str, scope: &[&str], iss: Option<&str>) -> serde_json::Value {
        let subject = match iss {
            None => json!({ "kind": "jwk", "alg": "Ed25519", "thumbprint": thumb }),
            Some(i) => json!({ "kind": "issuer", "alg": "Ed25519", "thumbprint": thumb, "iss": i }),
        };
        json!({
            "v": LINK_V, "registrar": REG, "passport": PASSPORT,
            "subject": subject,
            "scope": scope, "nbf": 1_000u64, "exp": 2_000u64,
            "status": { "uri": "status://registrar-01/1", "idx": 5u64 },
            "passport_status": { "uri": "status://registrar-01/1", "idx": 0u64 },
            "pop": pop,
        })
    }

    fn build_scoped(scope: &[&str]) -> Fx {
        build_with(scope, None)
    }
    /// The same fixture as an ISSUER link (D-110) when `iss` is given: the subject names it and the key signs the
    /// issuer consent.
    fn build_with(scope: &[&str], iss: Option<&str>) -> Fx {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0x11_4E_00_78);
        let issuer = crypto::HybridKeypair::generate(&mut rng);
        let root = crypto::TestRootSlh::generate(&mut rng);
        let agent = ed25519_dalek::SigningKey::generate(&mut rng);
        let key = agent.verifying_key().to_bytes();
        let thumb = jwk_thumbprint_ed25519(&key);
        use ed25519_dalek::Signer as _;
        let consent = match iss {
            None => pop_signing_bytes(REG, PASSPORT, &thumb, 1_000),
            Some(i) => issuer_pop_signing_bytes(REG, PASSPORT, &thumb, i, 1_000),
        };
        let pop = agent.sign(&consent).to_bytes();

        let pre = body(&thumb, &b64::encode(&pop), scope, iss);
        let pre_bytes = canon::canonicalize(&pre).unwrap().into_bytes();
        let leaf = merkle::hash_leaf(&pre_bytes);
        let mut log = merkle::TestLog::new();
        log.append(&[9u8]);
        let leaf_index = log.append(&pre_bytes);
        log.append(&[8u8]);
        let cp = checkpoint::Checkpoint {
            origin: "ainra-log/registrar-01".to_string(),
            tree_size: log.size(),
            root: log.root(),
        };
        let cp_sig = checkpoint::CheckpointSig::Root {
            slh: cp.sign_test_root(&root).unwrap(),
        };
        let proof = log.inclusion_proof(leaf_index).unwrap();
        let other_proof = log.inclusion_proof(0).unwrap();

        let mut full = pre;
        full["log"] = json!({ "leaf": b64::encode(&leaf) });
        let claims = canon::canonicalize(&full).unwrap().into_bytes();
        assert_eq!(prelog_leaf(&claims).unwrap(), leaf);
        let sig = issuer.sign(&claims).unwrap();

        let mut registrars = BTreeMap::new();
        registrars.insert(
            REG.to_string(),
            RegistrarInfo {
                issuer_key: issuer.public(),
                log_root_key: root.public(),
                distrust_from_leaf: None,
                distrust_root: None,
            },
        );
        Fx {
            anchors: TrustAnchors { registrars },
            claims,
            sig,
            key,
            cp,
            cp_sig,
            proof,
            leaf_index,
            list: status::StatusList::from_bits(alloc::vec![false; 16]),
            issuer,
            agent,
            other_proof,
        }
    }
    fn build() -> Fx {
        build_scoped(&[])
    }

    fn run(
        f: &Fx,
        now: u64,
        issued_at: u64,
        cap: Option<&str>,
    ) -> core::result::Result<Attribution, Reason> {
        run_as(f, now, issued_at, cap, None)
    }
    /// `issuer`: `None` when the gate verified the request with the key, `Some(name)` when it verified a token.
    fn run_as(
        f: &Fx,
        now: u64,
        issued_at: u64,
        cap: Option<&str>,
        issuer: Option<&str>,
    ) -> core::result::Result<Attribution, Reason> {
        let none = BTreeSet::new();
        verify_link(
            &LinkCheck {
                claims: &f.claims,
                registrar_sig: f.sig.clone(),
                presented_key: f.key.into(),
                now,
                status_list: &f.list,
                status_issued_at: issued_at,
                freshness: status::Freshness::F1,
                checkpoint: &f.cp,
                checkpoint_sig: &f.cp_sig,
                leaf_index: f.leaf_index,
                inclusion_proof: &f.proof,
                revoked_delegates: &none,
                capability: cap,
                issuer,
            },
            &f.anchors,
        )
    }

    #[test]
    fn a_genuine_link_attributes_the_key_to_its_operator() {
        let f = build();
        let a = run(&f, 1_500, 1_495, None).unwrap();
        assert_eq!(a.operator, "acme");
        assert_eq!(a.passport, PASSPORT);
        assert_eq!(a.registrar, REG);
    }

    #[test]
    fn the_thumbprint_is_rfc_7638() {
        // RFC 8037 §A.3: the JWK thumbprint of the RFC's example Ed25519 key.
        let x = b64::decode_array::<32>("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo").unwrap();
        assert_eq!(
            jwk_thumbprint_ed25519(&x),
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
    }

    #[test]
    fn revoking_the_link_or_the_operators_lineage_refuses_it() {
        let mut f = build();
        let mut bits = alloc::vec![false; 16];
        bits[5] = true;
        f.list = status::StatusList::from_bits(bits);
        assert_eq!(
            run(&f, 1_500, 1_495, None),
            Err(Reason::Revoked),
            "the link's own bit"
        );
        let mut bits = alloc::vec![false; 16];
        bits[0] = true;
        f.list = status::StatusList::from_bits(bits);
        assert_eq!(
            run(&f, 1_500, 1_495, None),
            Err(Reason::Revoked),
            "the passport's bit: every link of it flips"
        );
    }

    #[test]
    fn stale_status_fails_closed() {
        let f = build();
        assert_eq!(run(&f, 1_500, 1_400, None), Err(Reason::StaleStatus));
    }

    #[test]
    fn another_key_is_not_this_link() {
        let mut f = build();
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(7);
        f.key = ed25519_dalek::SigningKey::generate(&mut rng)
            .verifying_key()
            .to_bytes();
        assert_eq!(run(&f, 1_500, 1_495, None), Err(Reason::SigInvalid));
    }

    #[test]
    fn a_link_without_the_keys_consent_is_refused() {
        // The registrar signs a record whose proof of control was made by a DIFFERENT key for the same thumbprint
        // claim: the record is genuinely registrar-signed, and still refused.
        let mut f = build();
        let mut v: serde_json::Value = serde_json::from_slice(&f.claims).unwrap();
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(8);
        let other = ed25519_dalek::SigningKey::generate(&mut rng);
        use ed25519_dalek::Signer as _;
        let thumb = v["subject"]["thumbprint"].as_str().unwrap().to_string();
        v["pop"] = json!(b64::encode(
            &other
                .sign(&pop_signing_bytes(REG, PASSPORT, &thumb, 1_000))
                .to_bytes()
        ));
        f.claims = canon::canonicalize(&v).unwrap().into_bytes();
        f.sig = f.issuer.sign(&f.claims).unwrap();
        assert_eq!(run(&f, 1_500, 1_495, None), Err(Reason::SigInvalid));
        let _ = &f.agent;
    }

    #[test]
    fn a_forged_or_half_signed_record_is_refused() {
        let mut f = build();
        let mut s = f.sig.clone();
        s.ed25519[0] ^= 1;
        f.sig = s;
        assert_eq!(run(&f, 1_500, 1_495, None), Err(Reason::SigInvalid));
        let mut f = build();
        f.sig.mldsa65.clear();
        assert_eq!(run(&f, 1_500, 1_495, None), Err(Reason::AlgDowngrade));
    }

    #[test]
    fn the_window_is_exact() {
        let f = build();
        assert_eq!(run(&f, 999, 995, None), Err(Reason::NotYetValid));
        assert_eq!(run(&f, 2_000, 1_995, None), Err(Reason::Expired));
    }

    #[test]
    fn a_narrowed_link_refuses_what_it_does_not_name() {
        let f = build_scoped(&["read:invoices"]);
        assert!(run(&f, 1_500, 1_495, Some("read:invoices")).is_ok());
        assert_eq!(
            run(&f, 1_500, 1_495, Some("pay:invoices")),
            Err(Reason::CeilingExceeded)
        );
        let open = build();
        assert!(
            run(&open, 1_500, 1_495, Some("pay:invoices")).is_ok(),
            "an unscoped link defers to the passport"
        );
    }

    #[test]
    fn an_unlogged_or_unaccredited_link_is_refused() {
        let mut f = build();
        f.leaf_index += 1;
        assert_eq!(run(&f, 1_500, 1_495, None), Err(Reason::NotLogged));
        let mut f = build();
        f.anchors.registrars.clear();
        assert_eq!(run(&f, 1_500, 1_495, None), Err(Reason::UnknownRegistrar));
        let mut f = build();
        f.anchors
            .registrars
            .get_mut(REG)
            .unwrap()
            .distrust_from_leaf = Some(0);
        assert_eq!(
            run(&f, 1_500, 1_495, None),
            Err(Reason::RegistrarDistrusted)
        );
    }

    #[test]
    fn a_registrar_cannot_link_another_registrars_passport() {
        let mut f = build();
        let mut v: serde_json::Value = serde_json::from_slice(&f.claims).unwrap();
        v["passport"] = json!("ainra:registrar-02:acme:invoicing@1.0.0");
        f.claims = canon::canonicalize(&v).unwrap().into_bytes();
        f.sig = f.issuer.sign(&f.claims).unwrap();
        assert_eq!(run(&f, 1_500, 1_495, None), Err(Reason::SchemaViolation));
    }

    #[test]
    fn non_canonical_bytes_are_not_a_link() {
        let mut f = build();
        let mut s = String::from_utf8(f.claims.clone()).unwrap();
        s.insert(1, ' ');
        f.claims = s.into_bytes();
        f.sig = f.issuer.sign(&f.claims).unwrap();
        assert_eq!(run(&f, 1_500, 1_495, None), Err(Reason::SchemaViolation));
    }

    #[test]
    fn a_record_naming_someone_elses_key_is_refused_even_with_a_valid_consent() {
        // The attack the thumbprint check alone stops: a record (genuinely registrar-signed) names victim key A,
        // but its consent signature was made by attacker key B — and B is the key the attacker presents. The
        // consent verifies under B; only binding the presented key to the record's thumbprint refuses it.
        let mut f = build();
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(9);
        let attacker = ed25519_dalek::SigningKey::generate(&mut rng);
        use ed25519_dalek::Signer as _;
        let mut v: serde_json::Value = serde_json::from_slice(&f.claims).unwrap();
        let victim_thumb = v["subject"]["thumbprint"].as_str().unwrap().to_string();
        v["pop"] = json!(b64::encode(
            &attacker
                .sign(&pop_signing_bytes(REG, PASSPORT, &victim_thumb, 1_000))
                .to_bytes()
        ));
        f.claims = canon::canonicalize(&v).unwrap().into_bytes();
        f.sig = f.issuer.sign(&f.claims).unwrap();
        f.key = attacker.verifying_key().to_bytes();
        assert_eq!(run(&f, 1_500, 1_495, None), Err(Reason::SigInvalid));
    }

    #[test]
    fn a_record_pointing_at_another_logged_leaf_is_not_logged() {
        // The attack the leaf binding alone stops: the record's `log.leaf` names a leaf that really IS in the log
        // (a different entry), with that entry's genuine index and proof. Inclusion verifies; binding refuses.
        let mut f = build();
        let mut v: serde_json::Value = serde_json::from_slice(&f.claims).unwrap();
        v["log"]["leaf"] = json!(b64::encode(&merkle::hash_leaf(&[9u8])));
        f.claims = canon::canonicalize(&v).unwrap().into_bytes();
        f.sig = f.issuer.sign(&f.claims).unwrap();
        f.leaf_index = 0;
        f.proof = f.other_proof.clone();
        assert_eq!(run(&f, 1_500, 1_495, None), Err(Reason::NotLogged));
    }

    // ── D-110 issuer links ───────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn an_issuer_link_answers_for_tokens_naming_its_issuer_and_for_nothing_else() {
        let f = build_with(&[], Some(ISS));
        let a = run_as(&f, 1_500, 1_495, None, Some(ISS)).unwrap();
        assert_eq!(
            (a.operator.as_str(), a.issuer.as_deref()),
            ("acme", Some(ISS))
        );
        // The key signed the request itself: it agreed to answer for its tokens, not to act.
        assert_eq!(run(&f, 1_500, 1_495, None), Err(Reason::SigInvalid));
        // A token naming another issuer, signed by the same key.
        assert_eq!(
            run_as(&f, 1_500, 1_495, None, Some("https://other.example")),
            Err(Reason::SigInvalid)
        );
        // Revoking it refuses everything the key signs as that issuer.
        let mut f = f;
        let mut bits = alloc::vec![false; 16];
        bits[5] = true;
        f.list = status::StatusList::from_bits(bits);
        assert_eq!(
            run_as(&f, 1_500, 1_495, None, Some(ISS)),
            Err(Reason::Revoked)
        );
    }

    #[test]
    fn an_ordinary_link_does_not_answer_for_tokens_its_key_signs() {
        let f = build();
        assert!(run(&f, 1_500, 1_495, None).unwrap().issuer.is_none());
        assert_eq!(
            run_as(&f, 1_500, 1_495, None, Some(ISS)),
            Err(Reason::SigInvalid)
        );
        // An empty issuer name is still a token, not a request.
        assert_eq!(
            run_as(&f, 1_500, 1_495, None, Some("")),
            Err(Reason::SigInvalid)
        );
    }

    #[test]
    fn a_registrar_cannot_turn_a_key_consent_into_an_issuer_link() {
        // The record says issuer; the key signed the ORDINARY consent. Genuinely registrar-signed, and refused.
        let mut f = build_with(&[], Some(ISS));
        let mut v: serde_json::Value = serde_json::from_slice(&f.claims).unwrap();
        let thumb = v["subject"]["thumbprint"].as_str().unwrap().to_string();
        use ed25519_dalek::Signer as _;
        v["pop"] = json!(b64::encode(
            &f.agent
                .sign(&pop_signing_bytes(REG, PASSPORT, &thumb, 1_000))
                .to_bytes()
        ));
        f.claims = canon::canonicalize(&v).unwrap().into_bytes();
        f.sig = f.issuer.sign(&f.claims).unwrap();
        assert_eq!(
            run_as(&f, 1_500, 1_495, None, Some(ISS)),
            Err(Reason::SigInvalid)
        );
        // The two consents are different statements, and an issuer consent names its issuer.
        assert_ne!(
            pop_signing_bytes(REG, PASSPORT, &thumb, 1_000),
            issuer_pop_signing_bytes(REG, PASSPORT, &thumb, ISS, 1_000)
        );
        assert_ne!(
            issuer_pop_signing_bytes(REG, PASSPORT, &thumb, ISS, 1_000),
            issuer_pop_signing_bytes(REG, PASSPORT, &thumb, "https://other.example", 1_000)
        );
    }

    #[test]
    fn the_kind_and_the_issuer_name_go_together() {
        let reparse = |edit: &dyn Fn(&mut serde_json::Value)| {
            let f = build_with(&[], Some(ISS));
            let mut v: serde_json::Value = serde_json::from_slice(&f.claims).unwrap();
            edit(&mut v);
            LinkClaims::parse_checked(canon::canonicalize(&v).unwrap().as_bytes()).map(|_| ())
        };
        assert_eq!(reparse(&|_| {}), Ok(()));
        assert_eq!(
            reparse(&|v| {
                v["subject"].as_object_mut().unwrap().remove("iss");
            }),
            Err(Reason::SchemaViolation),
            "kind issuer with no name"
        );
        assert_eq!(
            reparse(&|v| v["subject"]["kind"] = json!("jwk")),
            Err(Reason::SchemaViolation),
            "kind jwk with a name"
        );
        assert_eq!(
            reparse(&|v| v["subject"]["iss"] = serde_json::Value::Null),
            Err(Reason::SchemaViolation),
            "a null name is not canonical"
        );
        assert_eq!(
            reparse(&|v| v["subject"]["kind"] = json!("x509")),
            Err(Reason::SchemaViolation)
        );
        for (name, ok) in [
            ("https://issuer.example", true),
            ("urn:example:issuer", true),
            ("", false),
            ("https://issuer.example/a b", false),
            ("https://issu\u{e9}r.example", false),
            ("tab\there", false),
        ] {
            assert_eq!(issuer_name_ok(name), ok, "{name:?}");
        }
        assert!(issuer_name_ok(&"a".repeat(MAX_ISSUER_LEN)));
        assert!(!issuer_name_ok(&"a".repeat(MAX_ISSUER_LEN + 1)));
    }

    // ── D-082 ES256K ───────────────────────────────────────────────────────────────────────────────────────────────

    fn k1(seed: u8) -> (k256::ecdsa::SigningKey, [u8; 33]) {
        let sk = k256::ecdsa::SigningKey::from_bytes(&[seed; 32].into()).unwrap();
        let pk: [u8; 33] = sk
            .verifying_key()
            .to_sec1_point(true)
            .as_bytes()
            .try_into()
            .unwrap();
        (sk, pk)
    }

    fn k1_sign(sk: &k256::ecdsa::SigningKey, msg: &[u8]) -> [u8; 64] {
        use k256::ecdsa::signature::Signer as _;
        let s: k256::ecdsa::Signature = sk.sign(msg);
        s.to_bytes().into()
    }

    #[test]
    fn an_es256k_signature_verifies_and_its_high_s_twin_does_not() {
        let (sk, pk) = k1(7);
        let msg = b"consent";
        let sig = k1_sign(&sk, msg);
        assert!(es256k_verify(&pk, msg, &sig));
        assert!(!es256k_verify(&pk, b"something else", &sig));
        // The same (r, s) with s replaced by n - s: valid curve math, refused as non-canonical.
        let parsed = k256::ecdsa::Signature::from_slice(&sig).unwrap();
        let (r, s_) = parsed.split_scalars();
        let high = k256::ecdsa::Signature::from_scalars(r, -*s_).unwrap();
        let high: [u8; 64] = high.to_bytes().into();
        assert_ne!(high, sig);
        assert!(!es256k_verify(&pk, msg, &high));
        let (_, other) = k1(8);
        assert!(!es256k_verify(&other, msg, &sig));
    }

    #[test]
    fn an_es256k_key_is_a_compressed_point_on_the_curve() {
        let (_, pk) = k1(7);
        let tp = jwk_thumbprint_es256k(&pk).unwrap();
        assert_eq!(b64::decode_array::<32>(&tp).unwrap().len(), 32);
        assert_eq!(
            PresentedKey::from_bytes(&pk).unwrap().thumbprint(),
            Some(tp)
        );
        let mut not_compressed = pk;
        not_compressed[0] = 0x04;
        assert_eq!(jwk_thumbprint_es256k(&not_compressed), None);
        let mut off_curve = pk;
        off_curve[32] ^= 1;
        off_curve[1] ^= 0xff;
        let maybe = jwk_thumbprint_es256k(&off_curve);
        // Flipping bits either leaves a point (another key, another thumbprint) or not a point at all.
        assert_ne!(maybe, jwk_thumbprint_es256k(&pk));
        assert_eq!(PresentedKey::from_bytes(&[0u8; 65]), None);
        assert_eq!(PresentedKey::from_bytes(&[0u8; 31]), None);
        assert_eq!(
            PresentedKey::from_bytes(&[1u8; 32]).unwrap().alg(),
            SUBJECT_ALG_ED25519
        );
    }

    #[test]
    fn an_ed25519_key_never_answers_for_an_es256k_link_or_the_reverse() {
        let f = build();
        let (_, k1pk) = k1(7);
        let none = BTreeSet::new();
        // An ES256K key presented for this (Ed25519) link: refused on the algorithm before the thumbprint.
        let r = verify_link(
            &LinkCheck {
                claims: &f.claims,
                registrar_sig: f.sig.clone(),
                presented_key: PresentedKey::Es256k(k1pk),
                now: 1_500,
                status_list: &f.list,
                status_issued_at: 1_495,
                freshness: status::Freshness::F1,
                checkpoint: &f.cp,
                checkpoint_sig: &f.cp_sig,
                leaf_index: f.leaf_index,
                inclusion_proof: &f.proof,
                revoked_delegates: &none,
                capability: None,
                issuer: None,
            },
            &f.anchors,
        );
        assert_eq!(r, Err(Reason::SigInvalid));
    }

    // ── D-108 ES256 (P-256) ────────────────────────────────────────────────────────────────────────────────────────

    fn r1(seed: u8) -> (p256::ecdsa::SigningKey, [u8; 65]) {
        let sk = p256::ecdsa::SigningKey::from_bytes(&[seed; 32].into()).unwrap();
        let pk: [u8; 65] = sk
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .try_into()
            .unwrap();
        (sk, pk)
    }

    fn r1_sign(sk: &p256::ecdsa::SigningKey, msg: &[u8]) -> [u8; 64] {
        use p256::ecdsa::signature::Signer as _;
        let s: p256::ecdsa::Signature = sk.sign(msg);
        let s = s.normalize_s();
        s.to_bytes().into()
    }

    #[test]
    fn an_es256_signature_verifies_and_its_high_s_twin_does_not() {
        let (sk, pk) = r1(7);
        let msg = b"consent";
        let sig = r1_sign(&sk, msg);
        assert!(es256_verify(&pk, msg, &sig));
        assert!(!es256_verify(&pk, b"something else", &sig));
        // The same (r, s) with s replaced by n - s: RFC 7518 accepts it, Link does not — one consent, one encoding.
        let parsed = p256::ecdsa::Signature::from_slice(&sig).unwrap();
        let (r, s_) = parsed.split_scalars();
        let high = p256::ecdsa::Signature::from_scalars(r, -*s_).unwrap();
        let high: [u8; 64] = high.to_bytes().into();
        assert_ne!(high, sig);
        assert!(!es256_verify(&pk, msg, &high));
        let (_, other) = r1(8);
        assert!(!es256_verify(&other, msg, &sig));
    }

    #[test]
    fn an_es256_key_is_an_uncompressed_point_on_p256_and_nothing_else_is_65_bytes() {
        let (sk, pk) = r1(7);
        let tp = jwk_thumbprint_es256(&pk).unwrap();
        assert_eq!(b64::decode_array::<32>(&tp).unwrap().len(), 32);
        let held = PresentedKey::from_bytes(&pk).unwrap();
        assert_eq!(
            (held.alg(), held.thumbprint()),
            (SUBJECT_ALG_ES256, Some(tp.clone()))
        );
        // The compressed form of the same key is 33 bytes, which names secp256k1: never this key.
        let compressed: [u8; 33] = sk
            .verifying_key()
            .to_sec1_point(true)
            .as_bytes()
            .try_into()
            .unwrap();
        let as_k1 = PresentedKey::from_bytes(&compressed).unwrap();
        assert_eq!(as_k1.alg(), SUBJECT_ALG_ES256K);
        assert_ne!(as_k1.thumbprint(), Some(tp.clone()));
        // 65 bytes that are not a P-256 point are not a key at all: a wrong prefix, an off-curve point, and an
        // uncompressed secp256k1 point (what vector l42 presents).
        let mut wrong_prefix = pk;
        wrong_prefix[0] = 0x02;
        assert_eq!(PresentedKey::from_bytes(&wrong_prefix), None);
        assert_eq!(jwk_thumbprint_es256(&wrong_prefix), None);
        let mut off_curve = pk;
        off_curve[64] ^= 1;
        assert_eq!(PresentedKey::from_bytes(&off_curve), None);
        let (k1sk, _) = k1(7);
        let k1_uncompressed: [u8; 65] = k1sk
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .try_into()
            .unwrap();
        assert_eq!(PresentedKey::from_bytes(&k1_uncompressed), None);
        // The thumbprint names the curve: the same x and y under "secp256k1" would hash differently.
        assert_ne!(Some(tp), jwk_thumbprint_es256k(&compressed));
    }

    #[test]
    fn a_p256_key_never_answers_for_an_ed25519_link() {
        let f = build();
        let (_, r1pk) = r1(7);
        let none = BTreeSet::new();
        let r = verify_link(
            &LinkCheck {
                claims: &f.claims,
                registrar_sig: f.sig.clone(),
                presented_key: PresentedKey::Es256(r1pk),
                now: 1_500,
                status_list: &f.list,
                status_issued_at: 1_495,
                freshness: status::Freshness::F1,
                checkpoint: &f.cp,
                checkpoint_sig: &f.cp_sig,
                leaf_index: f.leaf_index,
                inclusion_proof: &f.proof,
                revoked_delegates: &none,
                capability: None,
                issuer: None,
            },
            &f.anchors,
        );
        assert_eq!(r, Err(Reason::SigInvalid));
    }
}
