// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RS256 and PS256 signing for the D-112 link vectors, by hand: RFC 8017's encodings and one modular exponentiation.
//! The salt of a PS256 signature is derived from the message, so the corpus regenerates byte for byte. Test use only.

use num_bigint::BigUint;
use sha2::{Digest, Sha256};

/// A test RSA key: modulus and private exponent (big-endian), public exponent.
pub struct TestRsa {
    pub n: Vec<u8>,
    d: BigUint,
}

impl TestRsa {
    pub fn from_hex(k: (&str, &str, u32)) -> Self {
        let n = BigUint::parse_bytes(k.0.as_bytes(), 16)
            .expect("modulus hex")
            .to_bytes_be();
        let d = BigUint::parse_bytes(k.1.as_bytes(), 16).expect("exponent hex");
        assert_eq!(k.2, 65537, "Link's test keys use exponent 65537");
        TestRsa { n, d }
    }
    fn k(&self) -> usize {
        self.n.len()
    }
    fn raw(&self, em: &[u8]) -> Vec<u8> {
        let s = BigUint::from_bytes_be(em)
            .modpow(&self.d, &BigUint::from_bytes_be(&self.n))
            .to_bytes_be();
        let mut out = vec![0u8; self.k() - s.len()];
        out.extend_from_slice(&s);
        out
    }
    /// RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017 §8.2.1, EMSA-PKCS1-v1_5 §9.2).
    pub fn sign_rs256(&self, msg: &[u8]) -> Vec<u8> {
        const PREFIX: [u8; 19] = [
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ];
        let mut t = PREFIX.to_vec();
        t.extend_from_slice(&Sha256::digest(msg));
        let mut em = vec![0x00, 0x01];
        em.extend(std::iter::repeat_n(0xff, self.k() - t.len() - 3));
        em.push(0x00);
        em.extend_from_slice(&t);
        self.raw(&em)
    }
    /// RSASSA-PSS with SHA-256 and MGF1-SHA-256 (RFC 8017 §8.1.1, EMSA-PSS-ENCODE §9.1.1), with a salt of
    /// `salt_len` bytes derived from the message.
    pub fn sign_ps256(&self, msg: &[u8], salt_len: usize) -> Vec<u8> {
        let m_hash = Sha256::digest(msg);
        let mut salt = Vec::new();
        let mut ctr = 0u32;
        while salt.len() < salt_len {
            let mut h = Sha256::new();
            h.update(b"ainra-test-pss-salt");
            h.update(ctr.to_be_bytes());
            h.update(msg);
            salt.extend_from_slice(&h.finalize());
            ctr += 1;
        }
        salt.truncate(salt_len);
        let mod_bits = self.n.len() * 8 - self.n[0].leading_zeros() as usize;
        let em_bits = mod_bits - 1;
        let em_len = em_bits.div_ceil(8);
        let mut mp = vec![0u8; 8];
        mp.extend_from_slice(&m_hash);
        mp.extend_from_slice(&salt);
        let h = Sha256::digest(&mp);
        let mut db = vec![0u8; em_len - salt_len - 32 - 2];
        db.push(0x01);
        db.extend_from_slice(&salt);
        let mask = mgf1(&h, db.len());
        for (b, m) in db.iter_mut().zip(mask) {
            *b ^= m;
        }
        db[0] &= 0xff >> (8 * em_len - em_bits);
        let mut em = db;
        em.extend_from_slice(&h);
        em.push(0xbc);
        self.raw(&em)
    }
}

fn mgf1(seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 32);
    let mut c = 0u32;
    while out.len() < len {
        let mut h = Sha256::new();
        h.update(seed);
        h.update(c.to_be_bytes());
        out.extend_from_slice(&h.finalize());
        c += 1;
    }
    out.truncate(len);
    out
}
