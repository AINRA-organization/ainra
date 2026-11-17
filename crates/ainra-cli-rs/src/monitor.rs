// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `ainra monitor` — watch a registrar's log for issuance nobody expected (PLAN-M53 step 11, D-116).
//!
//! The Standard lets anyone monitor a registrar. This is the tool for it, run by an operator who wants to know whether
//! a passport was ever issued in its name without its knowing, or by a competitor paid to keep a registrar honest
//! (the "funded competitor monitor" of the accreditation prerequisites). Each run:
//!
//! 1. authenticates the directory against the pinned roots and takes the registrar's log key from it, never from the
//!    registrar;
//! 2. takes the registrar's current checkpoint (`/witness-feed`) and checks its signature under that key;
//! 3. if it has watched this log before, checks the consistency proof from the size it saw last: the log only grew,
//!    and nothing it saw was rewritten;
//! 4. downloads every entry (`/log/entries`) and rebuilds the tree: the root must be the signed root, so no entry is
//!    hidden behind the checkpoint, and none is shown that the log does not hold;
//! 5. reads every passport in the log and names each one, under a watched operator, that is not on the operator's
//!    own list.
//!
//! It holds no key and changes nothing. Exit status: 0 nothing found, 3 an alarm, 2 it could not check.
//!
//! WITNESS: `make monitor-e2e` runs it against a live registrar: a passport the operator expected passes, one it did
//! not is named, a feed that drops an entry is refused because the entries no longer rebuild the signed root, and a
//! log that shrank since the last run raises the rollback alarm.

use std::path::Path;

use ainra_core::{b64, checkpoint, merkle};
use serde_json::{json, Value};

use crate::ctl::{fetch, fetch_json};
use crate::{opt, opt_multi};

const PAGE: u64 = 256;

pub fn cmd_monitor(a: &[String]) -> i32 {
    let (Some(reg), Some(net)) = (opt(a, "registrar"), opt(a, "net")) else {
        eprintln!(
            "usage: ainra monitor --registrar <url> --net <url|dir> [--roots <pinned roots.json>] [--watch <operator>]… \
             [--expect <file of passport names>] [--state <file>] [--now <unix s>] [--json]"
        );
        return 2;
    };
    match run(a, reg, net) {
        Ok(report) => {
            let alarms = report["alarms"].as_array().map(|a| a.len()).unwrap_or(0);
            if a.iter().any(|x| x == "--json") {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).unwrap_or_default()
                );
            } else {
                print_report(&report);
            }
            if alarms > 0 {
                3
            } else {
                0
            }
        }
        Err(e) => {
            eprintln!("monitor: {e}");
            2
        }
    }
}

fn print_report(r: &Value) {
    println!(
        "monitor · {} · log {} at size {}",
        r["registrar"].as_str().unwrap_or(""),
        r["origin"].as_str().unwrap_or(""),
        r["size"]
    );
    for c in r["checks"].as_array().into_iter().flatten() {
        println!("  ok    {}", c.as_str().unwrap_or(""));
    }
    if let Some(kinds) = r["entries_by_kind"].as_object() {
        let parts: Vec<String> = kinds.iter().map(|(k, v)| format!("{v} {k}")).collect();
        println!("        entries: {}", parts.join(" · "));
    }
    for a in r["alarms"].as_array().into_iter().flatten() {
        println!("  ALARM {}", a.as_str().unwrap_or(""));
    }
    let n = r["alarms"].as_array().map(|a| a.len()).unwrap_or(0);
    if n == 0 {
        println!("MONITOR OK — the log is consistent, hides nothing, and holds no passport nobody expected");
    } else {
        println!("MONITOR ALARM — {n} finding(s) above");
    }
}

fn run(a: &[String], reg: &str, net: &str) -> Result<Value, String> {
    let now: u64 = opt(a, "now")
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        });
    let mut checks: Vec<String> = Vec::new();
    let mut alarms: Vec<String> = Vec::new();

    // 1. the directory, authenticated against roots this monitor trusts, gives the registrar's log key.
    let directory = fetch(net, "directory.json")?;
    let (roots, pinned) = match opt(a, "roots") {
        Some(p) => (std::fs::read(p).map_err(|e| format!("{p}: {e}"))?, true),
        None => (fetch(net, "roots.json")?, false),
    };
    let droots: Value = serde_json::from_slice(&roots).map_err(|e| format!("roots: {e}"))?;
    let d: ainra_core::directory::Directory =
        serde_json::from_slice(&directory).map_err(|e| format!("directory: {e}"))?;
    let (Some(ed), Some(slh)) = (droots["root_ed25519"].as_str(), droots["root_slh"].as_str())
    else {
        return Err("roots.json has no root_ed25519 / root_slh".into());
    };
    let ed = b64::decode_array::<32>(ed).map_err(|_| "roots: root_ed25519".to_string())?;
    let slh = b64::decode(slh).map_err(|_| "roots: root_slh".to_string())?;
    let anchors = d
        .accredit(&ed, &slh)
        .map_err(|_| "the directory does not verify under these roots".to_string())?;
    checks.push(format!(
        "directory epoch {} verifies under {} roots",
        d.epoch,
        if pinned {
            "the pinned"
        } else {
            "the published (not pinned: pass --roots to pin them)"
        }
    ));
    let acc = fetch_json(reg, "accreditation")?;
    let id = acc["registrar"]
        .as_str()
        .ok_or("the registrar's accreditation names no registrar")?
        .to_string();
    let anchor = anchors
        .anchors
        .registrars
        .get(&id)
        .ok_or_else(|| format!("{id} is not accredited in directory epoch {}", d.epoch))?;

    // 2. the checkpoint, signed under the directory's log key; 3. consistency with what this monitor saw last.
    let state_path = opt(a, "state");
    let last: Option<Value> = state_path
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|b| serde_json::from_slice(&b).ok());
    let last_size = last.as_ref().and_then(|v| v["size"].as_u64());
    let feed = fetch_json(
        reg,
        &match last_size {
            Some(n) => format!("witness-feed?from={n}"),
            None => "witness-feed".into(),
        },
    )
    .or_else(|e| {
        // A feed refuses a `from` beyond its size: that is a log that shrank, the alarm below.
        if last_size.is_some() {
            fetch_json(reg, "witness-feed")
        } else {
            Err(e)
        }
    })?;
    let cp = checkpoint::Checkpoint {
        origin: feed["checkpoint"]["origin"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        tree_size: feed["checkpoint"]["size"]
            .as_u64()
            .ok_or("checkpoint has no size")?,
        root: b64::decode_array::<32>(feed["checkpoint"]["root"].as_str().unwrap_or(""))
            .map_err(|_| "checkpoint root".to_string())?,
    };
    if cp.origin != format!("ainra-log/{id}") {
        alarms.push(format!(
            "the checkpoint is for log {:?}, not {id}'s",
            cp.origin
        ));
    }
    let wsig: ainra_adapter::WireCheckpointSig =
        serde_json::from_value(feed["checkpoint_sig"].clone())
            .map_err(|e| format!("checkpoint signature: {e}"))?;
    let sig =
        ainra_adapter::decode_cp_sig(&wsig).map_err(|r| format!("checkpoint signature: {r:?}"))?;
    match cp.verify_sig_mode(&anchor.log_root_key, &sig, now) {
        Ok(()) => checks.push(format!(
            "checkpoint at size {} is signed under {id}'s log key from the directory",
            cp.tree_size
        )),
        Err(r) => alarms.push(format!(
            "the checkpoint's signature does not verify under {id}'s log key ({r:?})"
        )),
    }
    if let (Some(prev), Some(n)) = (&last, last_size) {
        let prev_root = b64::decode_array::<32>(prev["root"].as_str().unwrap_or(""))
            .map_err(|_| "state: root".to_string())?;
        if cp.tree_size < n {
            alarms.push(format!(
                "ROLLBACK: the log was at size {n} when last seen and is at {} now",
                cp.tree_size
            ));
        } else {
            let proof: Vec<[u8; 32]> = feed["consistency_proof"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|h| h.as_str().and_then(|s| b64::decode_array::<32>(s).ok()))
                .collect();
            if merkle::verify_consistency(n, cp.tree_size, &prev_root, &cp.root, &proof) {
                checks.push(format!(
                    "the log grew from {n} to {} and rewrote nothing it had",
                    cp.tree_size
                ));
            } else {
                alarms.push(format!(
                    "FORK: the log at size {} is not an extension of the log seen at size {n}",
                    cp.tree_size
                ));
            }
        }
    }

    // 4. every entry, rebuilt into the signed root.
    let mut tree = ainra_services::tree::IncrementalTree::new();
    let mut entries: Vec<Vec<u8>> = Vec::new();
    while (entries.len() as u64) < cp.tree_size {
        let start = entries.len() as u64;
        let page = fetch_json(
            reg,
            &format!(
                "log/entries?start={start}&end={}",
                (start + PAGE).min(cp.tree_size)
            ),
        )?;
        let got: Vec<Vec<u8>> = page["entries"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|e| e.as_str().and_then(|s| b64::decode(s).ok()))
            .collect();
        if got.is_empty() {
            break;
        }
        entries.extend(got);
    }
    entries.truncate(cp.tree_size as usize);
    for e in &entries {
        tree.append(e);
    }
    if entries.len() as u64 != cp.tree_size || tree.root() != cp.root {
        alarms.push(format!(
            "the {} entries the registrar serves do not rebuild the signed root at size {}: an entry is hidden, \
             altered or extra",
            entries.len(),
            cp.tree_size
        ));
    } else {
        checks.push(format!(
            "all {} entries rebuild the signed root: nothing is hidden",
            cp.tree_size
        ));
    }

    // 5. every passport in the log, held to each watched operator's own list.
    let watch = opt_multi(a, "watch");
    let expected: Vec<String> = match opt(a, "expect") {
        Some(p) => std::fs::read_to_string(p)
            .map_err(|e| format!("{p}: {e}"))?
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect(),
        None => Vec::new(),
    };
    let mut kinds: std::collections::BTreeMap<&str, u64> = Default::default();
    let mut passports = Vec::new();
    for e in &entries {
        let kind = match serde_json::from_slice::<Value>(e) {
            Ok(v) if v.get("vct").is_some() && v.get("sub").is_some() => {
                passports.push(v["sub"].as_str().unwrap_or("").to_string());
                "passports"
            }
            Ok(v)
                if v.get("from").is_some()
                    && v.get("to").is_some()
                    && v.get("granted").is_some() =>
            {
                "delegation hops"
            }
            Ok(_) => "other records",
            Err(_) => "non-JSON entries",
        };
        *kinds.entry(kind).or_default() += 1;
    }
    for op in &watch {
        let mine: Vec<&String> = passports
            .iter()
            .filter(|s| s.split(':').nth(2) == Some(op.as_str()))
            .collect();
        let unexpected: Vec<&&String> = mine
            .iter()
            .filter(|s| !expected.iter().any(|x| x == **s))
            .collect();
        if unexpected.is_empty() {
            checks.push(format!(
                "{} passport(s) under operator {op}, every one on its list",
                mine.len()
            ));
        }
        for s in unexpected {
            alarms.push(format!(
                "UNEXPECTED ISSUANCE: {s} is in {id}'s log and not on {op}'s list"
            ));
        }
    }

    // Remember what was seen, but never past an alarm: a monitor that accepted a fork would stop seeing it.
    if let Some(p) = state_path {
        if alarms
            .iter()
            .all(|a| !a.starts_with("FORK") && !a.starts_with("ROLLBACK") && !a.contains("rebuild"))
        {
            let st = json!({ "registrar": id, "origin": cp.origin, "size": cp.tree_size, "root": b64::encode(&cp.root), "at": now });
            std::fs::write(
                Path::new(p),
                serde_json::to_string_pretty(&st).unwrap_or_default(),
            )
            .map_err(|e| format!("{p}: {e}"))?;
        }
    }
    Ok(json!({
        "registrar": id, "origin": cp.origin, "size": cp.tree_size,
        "checks": checks, "alarms": alarms, "entries_by_kind": kinds,
    }))
}
