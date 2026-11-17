# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Cryptographic primitives — shared audited libraries, fail-closed wrappers.

Independence note (see the package README and decision D-041): the verification
*logic* in this package is written independently from the specification and the
conformance vectors. The primitives themselves are deliberately NOT reimplemented
— reimplementing a signature scheme would be less safe, not more independent:

* **Ed25519** (32-byte key, 64-byte signature) and **ML-DSA-65 / FIPS 204**
  (1952-byte key, 3309-byte signature) come from ``cryptography`` (pyca), which
  wraps OpenSSL 3.5+.
* **SLH-DSA-SHA2-128s / FIPS 205** (32-byte key, 7856-byte signature) is not yet
  surfaced by ``cryptography``, so it is bound directly from the same OpenSSL
  ``libcrypto`` via ``ctypes`` (EVP raw-public-key verify) — an established C
  implementation used for that primitive only.
* **SHA-256** is the Python standard library ``hashlib``.

The differential (the fourth column of ``make diff``) exercises the *logic*, not
the primitives; agreement with the Rust core, the TS SDK, and the JS CLI is the
independent confirmation. Every wrapper returns ``bool`` and never raises: a
verifier fails closed, so any error, wrong size, or exception is ``False``.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mldsa, padding
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

# Exact FIPS / RFC 8032 sizes — asserted as a conformance gate, matching the
# Rust core's size asserts (a deviation means a broken dependency, not a code
# change).
ED25519_PUB_LEN = 32
ED25519_SIG_LEN = 64
MLDSA65_PUB_LEN = 1952
MLDSA65_SIG_LEN = 3309
SLH_DSA_SHA2_128S_PUB_LEN = 32
SLH_DSA_SHA2_128S_SIG_LEN = 7856


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def ed25519_verify(pub: bytes, sig: bytes, msg: bytes) -> bool:
    """Verify an Ed25519 signature; fail closed on any anomaly."""
    if len(pub) != ED25519_PUB_LEN or len(sig) != ED25519_SIG_LEN:
        return False
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        return True
    except Exception:
        return False


# The order of the secp256k1 group: a signature's s must be at most half of it (low-S, D-082).
_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def secp256k1_point(pub: bytes) -> tuple[bytes, bytes] | None:
    """The affine x and y (32 bytes each) of a 33-byte compressed secp256k1 point, or None if it is not one."""
    if len(pub) != 33 or pub[0] not in (2, 3):
        return None
    try:
        n = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pub).public_numbers()
    except Exception:
        return None
    return n.x.to_bytes(32, "big"), n.y.to_bytes(32, "big")


def es256k_verify(pub: bytes, sig: bytes, msg: bytes) -> bool:
    """ES256K (RFC 8812): ECDSA over secp256k1 with SHA-256 of ``msg``; ``sig`` is 64-byte ``r || s``. A high-S
    signature is refused — its low-S twin is the canonical form — and so is anything that is not a compressed point
    on the curve. Fail closed on any anomaly."""
    if len(pub) != 33 or pub[0] not in (2, 3) or len(sig) != 64:
        return False
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if not (0 < r < _SECP256K1_N and 0 < s <= _SECP256K1_N // 2):
        return False
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pub)
        key.verify(encode_dss_signature(r, s), msg, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False
    except Exception:
        return False


# The order of the NIST P-256 group: a signature's s must be at most half of it (low-S, D-108).
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def p256_point(pub: bytes) -> tuple[bytes, bytes] | None:
    """The affine x and y (32 bytes each) of a 65-byte UNCOMPRESSED P-256 point (``0x04 || x || y``), or None if it
    is not one."""
    if len(pub) != 65 or pub[0] != 4:
        return None
    try:
        n = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub).public_numbers()
    except Exception:
        return None
    return n.x.to_bytes(32, "big"), n.y.to_bytes(32, "big")


# ── D-112: RSA keys for Link (RS256, PS256) ─────────────────────────────────────────────────────────────────────
RSA_MIN_BITS, RSA_MAX_BITS = 2048, 4096
RSA_EXPONENT = b"\x01\x00\x01"
_RSA_ALG_ID = bytes.fromhex("300d06092a864886f70d0101010500")


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    return bytes([0x82, n >> 8, n & 0xFF])


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def rsa_spki(n: bytes) -> bytes:
    """The one canonical DER SubjectPublicKeyInfo of an RSA key with modulus ``n`` (big-endian, no leading zero) and
    exponent 65537: byte for byte what ``ainra_core::link::rsa_spki``, the TypeScript SDK and openssl produce."""
    n_int = (b"\x00" + n) if n and n[0] & 0x80 else n
    rsa_pk = _tlv(0x30, _tlv(0x02, n_int) + _tlv(0x02, RSA_EXPONENT))
    return _tlv(0x30, _RSA_ALG_ID + _tlv(0x03, b"\x00" + rsa_pk))


def rsa_spki_modulus(der: bytes) -> bytes | None:
    """The modulus of an RSA key given as DER SubjectPublicKeyInfo, if and only if the bytes are ``rsa_spki`` of that
    modulus and the modulus is odd and 2048 to 4096 bits long; None otherwise. Mirrors ``rsa_spki_modulus`` in Rust."""
    def header(at: int):
        if at + 1 >= len(der):
            return None
        first = der[at + 1]
        if first < 0x80:
            return at + 2, first
        k = first & 0x7F
        if k == 0 or k > 2 or at + 2 + k > len(der):
            return None
        return at + 2 + k, int.from_bytes(der[at + 2:at + 2 + k], "big")
    body = header(0)
    if body is None:
        return None
    bits = header(body[0] + len(_RSA_ALG_ID))
    if bits is None:
        return None
    seq = header(bits[0] + 1)
    if seq is None or seq[0] >= len(der) or der[seq[0]] != 0x02:
        return None
    nh = header(seq[0])
    if nh is None or nh[0] + nh[1] > len(der):
        return None
    n = der[nh[0]:nh[0] + nh[1]]
    if n[:1] == b"\x00":
        n = n[1:]
    if not n or n[0] == 0 or len(n) > RSA_MAX_BITS // 8 or n[-1] & 1 == 0:
        return None
    if not RSA_MIN_BITS <= int.from_bytes(n, "big").bit_length() <= RSA_MAX_BITS:
        return None
    return bytes(n) if rsa_spki(n) == der else None


def rsa_verify(n: bytes, pss: bool, msg: bytes, sig: bytes) -> bool:
    """RS256 (``pss`` False: RSASSA-PKCS1-v1_5, SHA-256) or PS256 (``pss`` True: RSASSA-PSS, SHA-256, MGF1-SHA-256, a
    salt of exactly 32 bytes) by the RSA key with modulus ``n`` and exponent 65537. The signature is exactly as long as
    the modulus. Fail closed on any anomaly."""
    if not n or len(sig) != len(n):
        return False
    try:
        key = _rsa.RSAPublicNumbers(65537, int.from_bytes(n, "big")).public_key()
        if pss:
            key.verify(sig, msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
        else:
            key.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
        return True
    except (InvalidSignature, ValueError):
        return False


def es256_verify(pub: bytes, sig: bytes, msg: bytes) -> bool:
    """ES256 (RFC 7518): ECDSA over NIST P-256 with SHA-256 of ``msg``; ``sig`` is 64-byte ``r || s``. A high-S
    signature is refused, as for ES256K — RFC 7518 accepts both twins, Link takes the low-S one — and so is anything
    that is not an uncompressed point on the curve. Fail closed on any anomaly."""
    if len(pub) != 65 or pub[0] != 4 or len(sig) != 64:
        return False
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if not (0 < r < _P256_N and 0 < s <= _P256_N // 2):
        return False
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub)
        key.verify(encode_dss_signature(r, s), msg, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False
    except Exception:
        return False


def mldsa65_verify(pub: bytes, sig: bytes, msg: bytes) -> bool:
    """Verify an ML-DSA-65 (FIPS 204) signature; fail closed on any anomaly."""
    if len(pub) != MLDSA65_PUB_LEN or len(sig) != MLDSA65_SIG_LEN:
        return False
    try:
        mldsa.MLDSA65PublicKey.from_public_bytes(pub).verify(sig, msg)
        return True
    except Exception:
        return False


# ── SLH-DSA-SHA2-128s via OpenSSL libcrypto (ctypes) ────────────────────────
class _SlhBackend:
    """Lazy, process-wide binding to OpenSSL's SLH-DSA-SHA2-128s verify."""

    _ALG = b"SLH-DSA-SHA2-128s"

    def __init__(self) -> None:
        self._lib = None

    def _load(self):
        if self._lib is not None:
            return self._lib
        name = ctypes.util.find_library("crypto") or "libcrypto.so.3"
        lib = ctypes.CDLL(name)

        lib.EVP_PKEY_new_raw_public_key_ex.restype = ctypes.c_void_p
        lib.EVP_PKEY_new_raw_public_key_ex.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p,
            ctypes.c_char_p, ctypes.c_size_t,
        ]
        lib.EVP_PKEY_free.restype = None
        lib.EVP_PKEY_free.argtypes = [ctypes.c_void_p]
        lib.EVP_MD_CTX_new.restype = ctypes.c_void_p
        lib.EVP_MD_CTX_new.argtypes = []
        lib.EVP_MD_CTX_free.restype = None
        lib.EVP_MD_CTX_free.argtypes = [ctypes.c_void_p]
        lib.EVP_DigestVerifyInit_ex.restype = ctypes.c_int
        lib.EVP_DigestVerifyInit_ex.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p,
            ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p,
        ]
        lib.EVP_DigestVerify.restype = ctypes.c_int
        lib.EVP_DigestVerify.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_size_t,
        ]
        self._lib = lib
        return lib

    def verify(self, pub: bytes, sig: bytes, msg: bytes) -> bool:
        if len(pub) != SLH_DSA_SHA2_128S_PUB_LEN or len(sig) != SLH_DSA_SHA2_128S_SIG_LEN:
            return False
        try:
            lib = self._load()
        except Exception:
            return False
        pkey = None
        ctx = None
        try:
            pkey = lib.EVP_PKEY_new_raw_public_key_ex(
                None, self._ALG, None, pub, len(pub)
            )
            if not pkey:
                return False
            ctx = lib.EVP_MD_CTX_new()
            if not ctx:
                return False
            if lib.EVP_DigestVerifyInit_ex(ctx, None, None, None, None, pkey, None) != 1:
                return False
            return lib.EVP_DigestVerify(ctx, sig, len(sig), msg, len(msg)) == 1
        except Exception:
            return False
        finally:
            if ctx:
                lib.EVP_MD_CTX_free(ctx)
            if pkey:
                lib.EVP_PKEY_free(pkey)


_slh = _SlhBackend()


def slh_dsa_sha2_128s_verify(pub: bytes, sig: bytes, msg: bytes) -> bool:
    """Verify an SLH-DSA-SHA2-128s (FIPS 205) signature; fail closed."""
    return _slh.verify(pub, sig, msg)


def slh_available() -> bool:
    """True iff the OpenSSL SLH-DSA verify path is usable in this environment."""
    try:
        _slh._load()
        return True
    except Exception:
        return False
