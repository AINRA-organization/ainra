// SPDX-License-Identifier: Apache-2.0 OR MIT
//! C2SP signed notes for a registrar's checkpoints, so that any public witness can cosign its log (D-121).
//!
//! The witnesses the transparency ecosystem runs speak one protocol (c2sp.org/tlog-witness): a log submits its
//! checkpoint as a signed note (c2sp.org/tlog-checkpoint, c2sp.org/signed-note) with a consistency proof, and the
//! witness answers with a timestamped cosignature (c2sp.org/tlog-cosignature). A witness trusts one fixed Ed25519 key
//! per log origin and never re-keys, so a registrar keeps a permanent **note key** for this, apart from the keys its
//! checkpoints are otherwise signed with (the SLH-DSA log root and its short-lived delegates, which rotate).
//!
//! This module formats and verifies; it holds no state. Everything here follows those four documents as read on
//! 18 November 2026:
//!   - a note is text ending in a newline, a blank line, then signature lines `— <name> <base64(key id || sig)>`;
//!   - a key id is the first four bytes of SHA-256(name || 0x0A || type || public key);
//!   - a verifier key (vkey) is `<name>+<8 hex key id>+<base64(type || public key)>`;
//!   - type 0x01 is a log's Ed25519 signature over the note text; type 0x04 a witness's Ed25519 cosignature over
//!     `cosignature/v1\ntime <t>\n` followed by the note text, its line carrying an 8-byte big-endian timestamp
//!     before the signature;
//!   - base64 is standard (RFC 4648) with padding, canonical only.
//!
//! ML-DSA-44 cosignatures (type 0x06), which the cosignature document recommends for new witnesses, are recognised
//! and reported as such, not verified here yet.

use base64ct::{Base64, Encoding};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// A log's own Ed25519 signature over the note text.
pub const TYPE_ED25519: u8 = 0x01;
/// A cosigner's timestamped Ed25519 checkpoint cosignature (`cosignature/v1`).
pub const TYPE_COSIG_ED25519: u8 = 0x04;
/// A cosigner's timestamped ML-DSA-44 checkpoint cosignature (recognised, not verified here).
pub const TYPE_COSIG_MLDSA44: u8 = 0x06;

/// The 4-byte key id of a key named `name`, of signature type `typ`, with encoded public key `pk`.
pub fn key_id(name: &str, typ: u8, pk: &[u8]) -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    h.update([0x0A, typ]);
    h.update(pk);
    let d = h.finalize();
    [d[0], d[1], d[2], d[3]]
}

/// A key name as the signed-note document requires: not empty, no space of any kind, no `+`.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty() && !name.chars().any(|c| c.is_whitespace() || c == '+')
}

/// The verifier key string for (`name`, `typ`, `pk`).
pub fn vkey(name: &str, typ: u8, pk: &[u8]) -> String {
    let id = key_id(name, typ, pk);
    let mut tp = Vec::with_capacity(1 + pk.len());
    tp.push(typ);
    tp.extend_from_slice(pk);
    format!(
        "{name}+{:02x}{:02x}{:02x}{:02x}+{}",
        id[0],
        id[1],
        id[2],
        id[3],
        Base64::encode_string(&tp)
    )
}

/// A parsed verifier key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vkey {
    pub name: String,
    pub id: [u8; 4],
    pub typ: u8,
    pub pk: Vec<u8>,
}

/// Parse a verifier key, refusing one whose id is not the id its name, type and key give.
pub fn parse_vkey(s: &str) -> Result<Vkey, String> {
    let mut parts = s.splitn(3, '+');
    let (Some(name), Some(hex), Some(b64)) = (parts.next(), parts.next(), parts.next()) else {
        return Err("a verifier key is <name>+<id>+<key>".into());
    };
    if !valid_name(name) {
        return Err(format!("not a key name: {name:?}"));
    }
    if hex.len() != 8
        || !hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("the key id is 8 lowercase hex digits".into());
    }
    let tp = Base64::decode_vec(b64).map_err(|_| "the key is not canonical base64".to_string())?;
    let (&typ, pk) = tp.split_first().ok_or("an empty key")?;
    let id = key_id(name, typ, pk);
    let want = format!("{:02x}{:02x}{:02x}{:02x}", id[0], id[1], id[2], id[3]);
    if want != hex {
        return Err(format!(
            "the key id {hex} is not the id of this name and key ({want})"
        ));
    }
    Ok(Vkey {
        name: name.to_string(),
        id,
        typ,
        pk: pk.to_vec(),
    })
}

/// The checkpoint note text: origin, tree size, base64 root, each line ending in a newline.
pub fn checkpoint_text(origin: &str, size: u64, root: &[u8; 32]) -> String {
    format!("{origin}\n{size}\n{}\n", Base64::encode_string(root))
}

/// The log's permanent note key: an Ed25519 key named by the log's origin.
pub struct NoteKey {
    name: String,
    sk: SigningKey,
}

impl NoteKey {
    /// A note key from 32 secret bytes, named `name` (the log origin).
    pub fn from_seed(name: &str, seed: &[u8; 32]) -> Result<Self, String> {
        if !valid_name(name) {
            return Err(format!("{name:?} cannot name a note key"));
        }
        Ok(NoteKey {
            name: name.to_string(),
            sk: SigningKey::from_bytes(seed),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn public(&self) -> [u8; 32] {
        self.sk.verifying_key().to_bytes()
    }

    /// The verifier key a witness is configured with for this log.
    pub fn vkey(&self) -> String {
        vkey(&self.name, TYPE_ED25519, &self.public())
    }

    /// The checkpoint as a signed note, signed by this key.
    pub fn sign_checkpoint(&self, size: u64, root: &[u8; 32]) -> String {
        let text = checkpoint_text(&self.name, size, root);
        let sig = self.sk.sign(text.as_bytes()).to_bytes();
        let id = key_id(&self.name, TYPE_ED25519, &self.public());
        let mut line = Vec::with_capacity(68);
        line.extend_from_slice(&id);
        line.extend_from_slice(&sig);
        format!(
            "{text}\n\u{2014} {} {}\n",
            self.name,
            Base64::encode_string(&line)
        )
    }
}

/// A note split into its text and its signature lines (name, decoded bytes).
pub struct Note {
    pub text: String,
    pub sigs: Vec<(String, Vec<u8>)>,
}

/// Split a note at its last blank line; refuse anything malformed.
pub fn parse_note(note: &str) -> Result<Note, String> {
    if !note.ends_with('\n') {
        return Err("a note ends with a newline".into());
    }
    if note.chars().any(|c| c.is_control() && c != '\n') {
        return Err("a note holds no control character but newline".into());
    }
    let sep = note
        .rfind("\n\n")
        .ok_or("a note has a blank line before its signatures")?;
    let text = &note[..sep + 1];
    let mut sigs = Vec::new();
    for line in note[sep + 2..].lines() {
        let rest = line
            .strip_prefix("\u{2014} ")
            .ok_or_else(|| format!("not a signature line: {line:?}"))?;
        let (name, b64) = rest
            .rsplit_once(' ')
            .ok_or_else(|| format!("not a signature line: {line:?}"))?;
        if !valid_name(name) {
            return Err(format!("not a key name: {name:?}"));
        }
        let bytes =
            Base64::decode_vec(b64).map_err(|_| format!("not canonical base64: {line:?}"))?;
        if bytes.len() < 5 {
            return Err(format!("a signature too short to hold a key id: {line:?}"));
        }
        sigs.push((name.to_string(), bytes));
    }
    if sigs.is_empty() {
        return Err("a note carries at least one signature".into());
    }
    Ok(Note {
        text: text.to_string(),
        sigs,
    })
}

/// The origin, size and root of a checkpoint note's text (extension lines are allowed and ignored here).
pub fn parse_checkpoint_text(text: &str) -> Result<(String, u64, [u8; 32]), String> {
    let mut lines = text.lines();
    let origin = lines
        .next()
        .filter(|l| !l.is_empty())
        .ok_or("no origin line")?;
    let size_s = lines.next().ok_or("no size line")?;
    if size_s.is_empty()
        || (size_s.len() > 1 && size_s.starts_with('0'))
        || !size_s.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(format!("not a tree size: {size_s:?}"));
    }
    let size: u64 = size_s
        .parse()
        .map_err(|_| format!("not a tree size: {size_s:?}"))?;
    let root_v = Base64::decode_vec(lines.next().ok_or("no root line")?)
        .map_err(|_| "the root is not canonical base64")?;
    let root: [u8; 32] = root_v
        .try_into()
        .map_err(|_| "the root is not 32 bytes".to_string())?;
    Ok((origin.to_string(), size, root))
}

/// Verify a log's Ed25519 signature (type 0x01) on a note, by the key `vk`. `Ok(false)` when no signature line is
/// from that key (by name AND id); `Err` when one is and does not verify.
pub fn verify_log_signature(note: &Note, vk: &Vkey) -> Result<bool, String> {
    if vk.typ != TYPE_ED25519 {
        return Err("a log signature key is type 0x01 (Ed25519)".into());
    }
    let pk: [u8; 32] = vk
        .pk
        .clone()
        .try_into()
        .map_err(|_| "an Ed25519 key is 32 bytes".to_string())?;
    let vkey =
        VerifyingKey::from_bytes(&pk).map_err(|_| "not an Ed25519 public key".to_string())?;
    for (name, bytes) in &note.sigs {
        if name == &vk.name && bytes[..4] == vk.id {
            let sig: [u8; 64] = bytes[4..]
                .try_into()
                .map_err(|_| "an Ed25519 signature is 64 bytes".to_string())?;
            return vkey
                .verify(note.text.as_bytes(), &Signature::from_bytes(&sig))
                .map(|_| true)
                .map_err(|_| format!("the signature by {} does not verify", vk.name));
        }
    }
    Ok(false)
}

/// The outcome of checking one cosignature line against a cosigner's key.
#[derive(Debug, PartialEq, Eq)]
pub enum Cosig {
    /// An Ed25519 cosignature that verifies, made at this POSIX time.
    Verified(u64),
    /// An ML-DSA-44 cosignature from this key: recognised, not verified here.
    MlDsa44Unverified(u64),
}

/// Check the cosignature lines a witness returned (each `— <name> <base64>`) against the witness's verifier key, over
/// the checkpoint note text `text`. At least one line must come from that key, and every line from it must verify.
pub fn verify_cosignatures(text: &str, lines: &str, vk: &Vkey) -> Result<Vec<Cosig>, String> {
    let mut out = Vec::new();
    for line in lines.lines().filter(|l| !l.is_empty()) {
        let rest = line
            .strip_prefix("\u{2014} ")
            .ok_or_else(|| format!("not a signature line: {line:?}"))?;
        let (name, b64) = rest
            .rsplit_once(' ')
            .ok_or_else(|| format!("not a signature line: {line:?}"))?;
        let bytes =
            Base64::decode_vec(b64).map_err(|_| format!("not canonical base64: {line:?}"))?;
        if name != vk.name || bytes.len() < 12 || bytes[..4] != vk.id {
            continue; // another key's line: ignored, as the signed-note document requires
        }
        let t = u64::from_be_bytes(bytes[4..12].try_into().expect("8 bytes"));
        match vk.typ {
            TYPE_COSIG_ED25519 => {
                let pk: [u8; 32] = vk
                    .pk
                    .clone()
                    .try_into()
                    .map_err(|_| "an Ed25519 key is 32 bytes".to_string())?;
                let vkey = VerifyingKey::from_bytes(&pk)
                    .map_err(|_| "not an Ed25519 public key".to_string())?;
                let sig: [u8; 64] = bytes[12..]
                    .try_into()
                    .map_err(|_| "an Ed25519 signature is 64 bytes".to_string())?;
                let msg = format!("cosignature/v1\ntime {t}\n{text}");
                vkey.verify(msg.as_bytes(), &Signature::from_bytes(&sig))
                    .map_err(|_| format!("the cosignature by {} does not verify", vk.name))?;
                out.push(Cosig::Verified(t));
            }
            TYPE_COSIG_MLDSA44 => out.push(Cosig::MlDsa44Unverified(t)),
            other => {
                return Err(format!(
                    "a cosigner key of type {other:#04x} is not a checkpoint cosignature"
                ))
            }
        }
    }
    if out.is_empty() {
        return Err(format!("no cosignature from {}", vk.name));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signed_checkpoint_parses_and_verifies_under_its_vkey_and_no_other() {
        let k = NoteKey::from_seed("ainra-log/registrar-07", &[7u8; 32]).unwrap();
        let note = k.sign_checkpoint(14, &[9u8; 32]);
        assert!(note.starts_with("ainra-log/registrar-07\n14\n"));
        let n = parse_note(&note).unwrap();
        let (o, s, r) = parse_checkpoint_text(&n.text).unwrap();
        assert_eq!(
            (o.as_str(), s, r),
            ("ainra-log/registrar-07", 14, [9u8; 32])
        );
        let vk = parse_vkey(&k.vkey()).unwrap();
        assert_eq!(verify_log_signature(&n, &vk), Ok(true));
        // the same name with another key: no line from it, so not verified (and not an error)
        let other = NoteKey::from_seed("ainra-log/registrar-07", &[8u8; 32]).unwrap();
        assert_eq!(
            verify_log_signature(&n, &parse_vkey(&other.vkey()).unwrap()),
            Ok(false)
        );
        // a changed size breaks the signature
        let forged = note.replacen("\n14\n", "\n15\n", 1);
        assert!(verify_log_signature(&parse_note(&forged).unwrap(), &vk).is_err());
    }

    #[test]
    fn a_vkey_whose_id_does_not_match_is_refused() {
        let k = NoteKey::from_seed("example.org/log", &[1u8; 32]).unwrap();
        let v = k.vkey();
        let bad = format!(
            "{}+00000000+{}",
            "example.org/log",
            v.rsplit('+').next().unwrap()
        );
        assert!(parse_vkey(&bad).is_err());
        assert!(parse_vkey(&v).is_ok());
        assert!(NoteKey::from_seed("has space", &[1u8; 32]).is_err());
    }

    #[test]
    fn an_ed25519_cosignature_verifies_over_the_v1_message_and_fails_when_moved() {
        let w = SigningKey::from_bytes(&[3u8; 32]);
        let name = "example.org/witness";
        let vk = parse_vkey(&vkey(
            name,
            TYPE_COSIG_ED25519,
            &w.verifying_key().to_bytes(),
        ))
        .unwrap();
        let text = checkpoint_text("ainra-log/registrar-07", 14, &[9u8; 32]);
        let t: u64 = 1_776_729_600;
        let sig = w
            .sign(format!("cosignature/v1\ntime {t}\n{text}").as_bytes())
            .to_bytes();
        let mut b = vk.id.to_vec();
        b.extend_from_slice(&t.to_be_bytes());
        b.extend_from_slice(&sig);
        let line = format!("\u{2014} {name} {}\n", Base64::encode_string(&b));
        assert_eq!(
            verify_cosignatures(&text, &line, &vk),
            Ok(vec![Cosig::Verified(t)])
        );
        let other_text = checkpoint_text("ainra-log/registrar-07", 15, &[9u8; 32]);
        assert!(verify_cosignatures(&other_text, &line, &vk).is_err());
        assert!(verify_cosignatures(&text, "", &vk).is_err());
    }
}
