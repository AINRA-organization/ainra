// SPDX-License-Identifier: Apache-2.0 OR MIT
//! D-109: `accredit` takes its root from a private seed file when it is given one.
//!
//! The default root comes from a public fixed seed, which is right for a hermetic drill and wrong for a network
//! whose record is published: anyone can recompute it and sign a directory under it. These tests run the real
//! binary and hold three things: a seed file gives a root that is not the public one, and the same root at every
//! epoch; two files give two roots; and a file other people can read, or of the wrong size, is refused with nothing
//! written and nothing of the seed on the screen.

use std::path::{Path, PathBuf};
use std::process::Command;

use ainra_ceremony::ceremony::Genesis;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn scratch(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("ainra-accredit-seed-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// One registrar's accreditation, as its daemon would publish it (public keys only).
fn accreditation(dir: &Path) -> PathBuf {
    let g = Genesis::run(
        &["registrar-07"],
        1_775_865_600,
        vec![],
        &mut ChaCha20Rng::seed_from_u64(1),
    )
    .expect("genesis");
    let e = &g.directory.entries[0];
    let acc = serde_json::json!({
        "registrar": e.registrar,
        "issuer_key": { "ed25519": e.issuer_ed25519, "mldsa65": e.issuer_mldsa65 },
        "log_root_key": e.log_root_slh,
        "status_key": { "ed25519": e.status_ed25519, "mldsa65": e.status_mldsa65 },
        "status_uri": e.status_uri,
    });
    let path = dir.join("acc.json");
    std::fs::write(&path, acc.to_string()).unwrap();
    path
}

fn seed_file(dir: &Path, name: &str, bytes: &[u8], mode: u32) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}

struct Run {
    code: i32,
    stderr: String,
    roots: Option<String>,
    epoch: Option<u64>,
    issued_at: Option<u64>,
    directory: Option<String>,
}

fn run(out: &Path, acc: &Path, seed: Option<&Path>, epoch: Option<u64>) -> Run {
    run_at(out, acc, seed, epoch, None)
}

fn run_at(
    out: &Path,
    acc: &Path,
    seed: Option<&Path>,
    epoch: Option<u64>,
    issued_at: Option<&str>,
) -> Run {
    let _ = std::fs::remove_dir_all(out);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_accredit"));
    cmd.arg(out).arg(acc);
    cmd.env_remove("AINRA_ROOT_SEED_FILE")
        .env_remove("AINRA_DIRECTORY_EPOCH")
        .env_remove("AINRA_DIRECTORY_ISSUED_AT");
    if let Some(t) = issued_at {
        cmd.env("AINRA_DIRECTORY_ISSUED_AT", t);
    }
    if let Some(s) = seed {
        cmd.env("AINRA_ROOT_SEED_FILE", s);
    }
    if let Some(e) = epoch {
        cmd.env("AINRA_DIRECTORY_EPOCH", e.to_string());
    }
    let o = cmd.output().expect("run accredit");
    let roots = std::fs::read_to_string(out.join("roots.json")).ok();
    let directory = std::fs::read_to_string(out.join("directory.json")).ok();
    let parsed = directory
        .as_deref()
        .and_then(|d| serde_json::from_str::<serde_json::Value>(d).ok());
    let epoch = parsed.as_ref().and_then(|d| d["epoch"].as_u64());
    let issued_at = parsed.as_ref().and_then(|d| d["issued_at"].as_u64());
    Run {
        code: o.status.code().unwrap_or(-1),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        roots,
        epoch,
        issued_at,
        directory,
    }
}

/// A network that keeps real time states when its directory was issued (D-064). Unset, the directory carries the
/// fixed ceremony instant it always carried, so the pinned reference network and every hermetic drill are unchanged.
/// Stated, that instant is under both signatures, one instant gives one directory, the root does not move, and a
/// value that is not a time signs nothing.
#[test]
fn the_issue_time_is_the_fixed_ceremony_instant_unless_the_caller_states_one() {
    const PINNED: u64 = 1_775_865_600 - 3600;
    const WALL: u64 = 1_795_000_000;
    let dir = scratch("issued-at");
    let acc = accreditation(&dir);
    let seed = seed_file(&dir, "a.seed", &[0xA1; 32], 0o600);
    let wall = WALL.to_string();

    let unset = run(&dir.join("unset"), &acc, Some(&seed), None);
    assert_eq!(unset.code, 0, "{}", unset.stderr);
    assert_eq!(unset.issued_at, Some(PINNED), "unset: as before");

    let stated = run_at(&dir.join("stated"), &acc, Some(&seed), None, Some(&wall));
    assert_eq!(stated.code, 0, "{}", stated.stderr);
    assert_eq!(stated.issued_at, Some(WALL), "stated: the caller's instant");
    assert_eq!(stated.roots, unset.roots, "the root does not move");
    assert_ne!(
        stated.directory, unset.directory,
        "the issue time is under the signatures"
    );

    let again = run_at(&dir.join("again"), &acc, Some(&seed), None, Some(&wall));
    assert_eq!(
        again.directory, stated.directory,
        "one instant, one directory"
    );

    for bad in ["", "0", "now", "-5", "1795000000.5"] {
        let r = run_at(&dir.join("bad"), &acc, Some(&seed), None, Some(bad));
        assert_eq!(r.code, 2, "{bad:?}: {}", r.stderr);
        assert!(
            r.stderr.contains("AINRA_DIRECTORY_ISSUED_AT"),
            "{bad:?}: {}",
            r.stderr
        );
        assert!(r.directory.is_none(), "{bad:?}: nothing is signed");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_seed_file_gives_a_root_that_is_not_the_public_one_and_the_same_root_at_every_epoch() {
    let dir = scratch("roots");
    let acc = accreditation(&dir);
    let a = seed_file(&dir, "a.seed", &[0xA1; 32], 0o600);
    let b = seed_file(&dir, "b.seed", &[0xB2; 32], 0o600);
    let hex: String = [0xA1u8; 32].iter().map(|x| format!("{x:02x}")).collect();
    let a_hex = seed_file(&dir, "a-hex.seed", format!("{hex}\n").as_bytes(), 0o600);

    let public = run(&dir.join("public"), &acc, None, None);
    assert_eq!(public.code, 0, "{}", public.stderr);
    assert!(public.stderr.contains("public fixed seed"));

    let a1 = run(&dir.join("a1"), &acc, Some(&a), None);
    let a2 = run(&dir.join("a2"), &acc, Some(&a), Some(2));
    let ah = run(&dir.join("ah"), &acc, Some(&a_hex), None);
    let b1 = run(&dir.join("b1"), &acc, Some(&b), None);
    for r in [&a1, &a2, &ah, &b1] {
        assert_eq!(r.code, 0, "{}", r.stderr);
        assert!(!r.stderr.contains("public fixed seed"));
        assert!(!r.stderr.contains(&hex), "the seed is never echoed");
    }
    assert_ne!(
        a1.roots, public.roots,
        "a private seed is not the public root"
    );
    assert_eq!(a1.roots, a2.roots, "one seed, one root, at every epoch");
    assert_eq!((a1.epoch, a2.epoch), (Some(1), Some(2)));
    assert_eq!(a1.roots, ah.roots, "raw and hex forms of one seed agree");
    assert_ne!(a1.roots, b1.roots, "two seeds, two roots");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_seed_others_can_read_or_of_the_wrong_size_is_refused_and_nothing_is_written() {
    let dir = scratch("refused");
    let acc = accreditation(&dir);
    let loose = seed_file(&dir, "loose.seed", &[7; 32], 0o644);
    let short = seed_file(&dir, "short.seed", &[7; 31], 0o600);
    let missing = dir.join("no-such.seed");
    for (seed, needle) in [
        (&loose, "others can read it"),
        (&short, "exactly 32 bytes"),
        (&missing, "cannot read"),
    ] {
        let out = dir.join("out");
        let r = run(&out, &acc, Some(seed), None);
        assert_eq!(r.code, 2, "{}", r.stderr);
        assert!(r.stderr.contains(needle), "{}", r.stderr);
        assert!(r.roots.is_none(), "a refused seed signs nothing");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
