// SPDX-License-Identifier: Apache-2.0 OR MIT
//! A registrar that keeps real time exports records a third party can verify as they stand.
//!
//! `/export` is what the published read contract is built from, and everything that re-verifies that contract
//! rebuilds a presentation from the exported record. The record used to go out as stored: with the checkpoint signed
//! on the day of issuance, by that day's delegate, whose certificate lives at most 92 days. So a registrar keeping
//! real time published good passports that every reader called `checkpoint_invalid`, while its own verdict beside
//! each record said `valid`. Found on 22 November 2026 by restarting a network seeded on the pinned clock on the real
//! one (tools/stage-wallclock-drill.sh): eight of nine good passports read `checkpoint_invalid`.
//!
//! This runs the real binary over one data directory twice: pinned (April 2026), then on the wall clock. Pinned, the
//! export is the stored record, as it always was. On the wall clock, every exported record verifies offline at the
//! export's own time and agrees with the verdict beside it, while the stored receipt of the same passport does not.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ainra_core::{status, Reason, Verdict};
use ainra_services::http::{http_get, http_post};
use ainra_services::registrar::{verify_record_offline, IssuedRecord, RegistrarBox};
use serde_json::Value;

struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// `AINRA_FRESH_KEYS=1` as the standing network sets it: keys from the OS, which a real clock insists on.
fn start(addr: &str, dir: &Path, clock: &str) -> Daemon {
    let child = Command::new(env!("CARGO_BIN_EXE_registrar-box"))
        .args([addr, "registrar-07", dir.to_str().unwrap()])
        .env("AINRA_CLOCK", clock)
        .env("AINRA_FRESH_KEYS", "1")
        .env("AINRA_OPEN_WRITES", "1")
        .env_remove("AINRA_STAGE_ISSUE_TOKEN")
        .env_remove("AINRA_TEST_DERIVED_KEYS")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn registrar-box");
    let d = Daemon(child);
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        if http_get(addr, "/health").is_ok_and(|b| b.contains("\"ok\":true")) {
            return d;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("registrar-box ({clock}) did not come up on {addr}");
}

fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ainra-export-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn json(body: String) -> Value {
    serde_json::from_str(&body).expect("json")
}

fn issue(addr: &str, lineage: &str) -> String {
    let spec = format!(
        r#"{{"operator":"globex","lineage":"{lineage}","version":"1.0.0","tier":"L2","auth_class":"A2",
"principal_proof":"deadbeef","capabilities":["read:invoices"],"scope_ceiling":["read:invoices"],"hops":[]}}"#
    );
    json(http_post(addr, "/issue", &spec).unwrap())["sub"]
        .as_str()
        .expect("issued")
        .to_string()
}

/// Every record of an export, verified offline the way a third party does it: the record as exported, the status
/// list that travels with it, the export's own time. Returns `(sub, offline verdict, the verdict beside it)`.
fn offline(export: &Value, rb: &RegistrarBox) -> Vec<(String, Verdict, Verdict)> {
    let now = export["verified_at"].as_u64().expect("verified_at");
    let sl = &export["status_list"];
    let compressed = ainra_core::b64::decode(sl["status_list_b64"].as_str().unwrap()).unwrap();
    let list =
        status::StatusList::decode(&compressed, sl["bit_len"].as_u64().unwrap() as usize).unwrap();
    export["records"]
        .as_array()
        .expect("records")
        .iter()
        .map(|e| {
            let rec: IssuedRecord = serde_json::from_value(e["record"].clone()).expect("record");
            let beside: Verdict = serde_json::from_value(e["verdict"].clone()).expect("verdict");
            let v = verify_record_offline(
                &rec,
                &rb.trust_anchors(),
                list.clone(),
                sl["issued_at"].as_u64().unwrap(),
                now,
                status::Freshness::F3,
            );
            (rec.sub, v, beside)
        })
        .collect()
}

#[test]
fn an_export_on_the_wall_clock_verifies_offline_though_the_issuance_day_delegate_has_lapsed() {
    const PINNED_NOW: u64 = 1_775_865_600 + 10 * 24 * 3600;
    let d = dir("wall");
    let addr = format!("127.0.0.1:{}", free_port());

    // 1 · the pinned world: two passports, one revoked. Its export is the stored record, as it always was.
    let (good, gone, pinned_export) = {
        let _rb = start(&addr, &d, "pinned");
        let good = issue(&addr, "billing");
        let gone = issue(&addr, "export");
        http_post(&addr, "/revoke", &format!(r#"{{"sub":"{gone}"}}"#)).unwrap();
        (good, gone, json(http_get(&addr, "/export").unwrap()))
    };
    let rb = RegistrarBox::load(&d).expect("the registrar's own state");
    assert_eq!(pinned_export["verified_at"], PINNED_NOW);
    for e in pinned_export["records"].as_array().unwrap() {
        let sub = e["record"]["sub"].as_str().unwrap();
        assert_eq!(
            e["record"],
            serde_json::to_value(rb.get(sub).expect("stored")).unwrap(),
            "pinned: {sub} is exported as stored"
        );
    }
    let pinned = offline(&pinned_export, &rb);
    assert_eq!(pinned.len(), 2);
    for (sub, v, beside) in &pinned {
        assert_eq!(v, beside, "pinned: {sub} reads as the registrar says");
    }

    // 2 · the same state on the wall clock: the delegate certified in April 2026 has lapsed, and is certified again.
    let wall_export = {
        let _rb = start(&addr, &d, "wall");
        json(http_get(&addr, "/export").unwrap())
    };
    let now = wall_export["verified_at"].as_u64().unwrap();
    assert!(
        now > PINNED_NOW + 92 * 24 * 3600,
        "the premise: this machine's clock is past the issuance-day delegate's life"
    );
    let wall = offline(&wall_export, &rb);
    assert_eq!(wall.len(), 2);
    for (sub, v, beside) in &wall {
        assert_eq!(
            v, beside,
            "wall clock: {sub}, verified from the export as it stands, agrees with the verdict beside it"
        );
    }
    let of = |sub: &str| wall.iter().find(|(s, ..)| s == sub).unwrap().1.clone();
    assert_eq!(of(&good), Verdict::Valid);
    assert_eq!(of(&gone), Verdict::invalid(Reason::Revoked));

    // The witness: the stored receipt of the good passport, at the same time against the same status list, is what
    // the export used to carry — and it does not verify. If `/export` goes back to it, the loop above fails.
    let mut receipts = wall_export.clone();
    for e in receipts["records"].as_array_mut().unwrap() {
        let sub = e["record"]["sub"].as_str().unwrap().to_string();
        e["record"] = serde_json::to_value(rb.get(&sub).expect("stored")).unwrap();
    }
    let stale = offline(&receipts, &rb);
    let receipt = stale.iter().find(|(s, ..)| s == &good).unwrap().1.clone();
    assert_eq!(
        receipt,
        Verdict::invalid(Reason::CheckpointInvalid),
        "the issuance receipt no longer verifies once its delegate has lapsed"
    );
    let _ = std::fs::remove_dir_all(&d);
}
