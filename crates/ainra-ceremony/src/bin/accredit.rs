// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `accredit` — build a dual-root-signed AINRA directory over LIVE registrars. Reads each registrar's published
//! `/accreditation` JSON (public keys only — no secrets leave the registrar), DKGs a FROST 5-of-9 + SLH-DSA dual
//! root, dual-signs the directory, and writes `directory.json` + `roots.json`. The M5 testbed uses this to compose
//! the real registrar-box daemon with the real ceremony so a stranger's `sdk-ts` Verifier trust-anchors the result.
//!
//! Usage: `accredit <out-dir> <accreditation.json>...`  (each accreditation is a registrar-box `/accreditation`).

use std::path::Path;

use ainra_ceremony::ceremony::Genesis;
use ainra_core::directory::DirectoryEntry;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

const NOW: u64 = 1_775_865_600 - 3600; // ceremony time, just before the demo window opens

/// Read a 32-byte root seed: raw, or 64 hex characters with optional trailing whitespace. Refused when anyone but
/// the owner can read it, and never echoed.
fn root_seed(path: &Path) -> Result<[u8; 32], String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map_err(|e| format!("cannot read ({e})"))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(format!(
                "others can read it (mode {:o}); chmod 600 it",
                mode & 0o777
            ));
        }
    }
    let raw = std::fs::read(path).map_err(|e| format!("cannot read ({e})"))?;
    if raw.len() == 32 {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&raw);
        return Ok(seed);
    }
    let text = String::from_utf8_lossy(&raw);
    let hex = text.trim();
    if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        let mut seed = [0u8; 32];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).map_err(|e| e.to_string())?;
        }
        return Ok(seed);
    }
    Err("it must hold exactly 32 bytes, raw or as 64 hex characters".to_string())
}

fn main() {
    let mut args = std::env::args().skip(1);
    let out = args.next().unwrap_or_else(|| {
        eprintln!("usage: accredit <out-dir> <accreditation.json>...");
        std::process::exit(2);
    });
    let dir = Path::new(&out);
    std::fs::create_dir_all(dir).expect("mkdir");

    // Read each registrar's published accreditation → a directory entry (public keys only).
    let mut entries = Vec::new();
    for path in args {
        let raw = std::fs::read(&path).unwrap_or_else(|e| {
            eprintln!("cannot read {path}: {e}");
            std::process::exit(1);
        });
        let acc: serde_json::Value = serde_json::from_slice(&raw).expect("parse accreditation");
        entries.push(DirectoryEntry {
            registrar: acc["registrar"].as_str().expect("registrar").to_string(),
            issuer_ed25519: acc["issuer_key"]["ed25519"]
                .as_str()
                .expect("issuer ed")
                .to_string(),
            issuer_mldsa65: acc["issuer_key"]["mldsa65"]
                .as_str()
                .expect("issuer ml")
                .to_string(),
            log_root_slh: acc["log_root_key"].as_str().expect("log root").to_string(),
            // Status-signing key (D-020) — published in the registrar's accreditation so a verifier authenticates
            // presented status lists against it. A registrar that omits it is trust-anchored but its passports fail
            // closed in the GA Verifier (no way to authenticate revocation).
            status_ed25519: acc["status_key"]["ed25519"]
                .as_str()
                .expect("status ed")
                .to_string(),
            status_mldsa65: acc["status_key"]["mldsa65"]
                .as_str()
                .expect("status ml")
                .to_string(),
            status_uri: acc["status_uri"].as_str().unwrap_or("").to_string(),
            distrust_from_leaf: None,
        });
    }
    if entries.is_empty() {
        eprintln!("no accreditations given");
        std::process::exit(2);
    }

    // Where the root comes from. By default a PUBLIC fixed seed, so a hermetic testbed is reproducible: anyone can
    // recompute that root and sign a directory under it, which is right for a drill and wrong for a network whose
    // record is published (D-109). `AINRA_ROOT_SEED_FILE` names a file of 32 bytes from the OS instead (raw, or 64
    // hex characters), readable by its owner only; the same file gives the same root at every epoch. It is still a
    // TEST root: one machine holds the whole of it, where a real ceremony leaves no party with more than a share.
    let mut rng = match std::env::var("AINRA_ROOT_SEED_FILE") {
        Err(_) => {
            eprintln!("accredit: TEST root from the public fixed seed (anyone can recompute it)");
            ChaCha20Rng::seed_from_u64(0x0ACC_ED17_E5ED)
        }
        Ok(path) => match root_seed(Path::new(&path)) {
            Ok(seed) => ChaCha20Rng::from_seed(seed),
            Err(why) => {
                eprintln!("accredit: AINRA_ROOT_SEED_FILE {path}: {why}");
                std::process::exit(2);
            }
        },
    };
    let n = entries.len();
    // The epoch this directory is signed at. A network that changed its registrars' keys publishes the NEXT epoch;
    // it does not put a second directory at one it already published (D-107). Stated by the caller, never guessed.
    let epoch = match std::env::var("AINRA_DIRECTORY_EPOCH") {
        Err(_) => 1,
        Ok(v) => match v.parse::<u64>() {
            Ok(e) if e >= 1 => e,
            _ => {
                eprintln!("AINRA_DIRECTORY_EPOCH must be a whole number from 1 up, not {v:?}");
                std::process::exit(2);
            }
        },
    };
    let (directory, root_ed, root_slh) =
        Genesis::accredit_external_at(entries, vec![], epoch, NOW, &mut rng).expect("accredit");

    // Self-verify the way a stranger would, before writing anything.
    match directory.accredit(&root_ed, &root_slh) {
        Ok(acc) => {
            assert_eq!(acc.anchors.registrars.len(), n);
        }
        Err(r) => {
            eprintln!("accredit produced an unverifiable directory: {r}");
            std::process::exit(1);
        }
    }

    std::fs::write(
        dir.join("directory.json"),
        serde_json::to_string_pretty(&directory).unwrap(),
    )
    .expect("write directory");
    std::fs::write(
        dir.join("roots.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "root_ed25519": ainra_core::b64::encode(&root_ed),
            "root_slh": ainra_core::b64::encode(&root_slh),
        }))
        .unwrap(),
    )
    .expect("write roots");
    println!(
        "accredited {n} registrar(s) at epoch {epoch} → {out}/directory.json + roots.json (dual-root-signed, self-verified)"
    );
}
