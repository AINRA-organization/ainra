// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `ainra witness-submit` — have a public witness cosign a registrar's log (c2sp.org/tlog-witness, D-121).
//!
//! Each run:
//! 1. fetches the registrar's checkpoint as a C2SP signed note (`GET /checkpoint`), and checks the log's own signature
//!    on it when `--log-vkey` is given;
//! 2. takes the size this witness last cosigned from `--state` (0 the first time) and the consistency proof from it
//!    (`GET /witness-feed?from=N`), and requires the feed's head to be the note's head;
//! 3. sends `POST <witness>/add-checkpoint` with `old N`, the proof in standard base64, a blank line and the note;
//! 4. on 409 (the witness last cosigned another size) starts again once from the size it names;
//! 5. on 200 checks the returned cosignature under `--witness-vkey`, then records the size, root and cosignature.
//!
//! It holds no key and changes nothing at the registrar. Exit status: 0 cosigned, 3 refused for a reason that may be
//! an alarm (403: the witness does not trust this log key; 422: the witness found the log inconsistent), 2 could not
//! run.

use std::io::Write;
use std::process::{Command, Stdio};

use ainra_core::b64;
use ainra_services::note;
use base64ct::{Base64, Encoding};
use serde_json::{json, Value};

use crate::ctl::{fetch, fetch_json};
use crate::opt;

const USAGE: &str = "usage: ainra witness-submit --registrar <url> --witness <url> --state <file> \
[--witness-vkey <vkey>] [--log-vkey <vkey>]";

pub fn cmd_witness_submit(a: &[String]) -> i32 {
    let (Some(reg), Some(wit), Some(state)) =
        (opt(a, "registrar"), opt(a, "witness"), opt(a, "state"))
    else {
        eprintln!("{USAGE}");
        return 2;
    };
    match run(a, reg, wit, state) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("witness-submit: {e}");
            2
        }
    }
}

/// POST `body` to `url`; the status code and the body of the answer.
fn post(url: &str, body: &str) -> Result<(u16, String), String> {
    let mut child = Command::new("curl")
        .args([
            "-sS",
            "--max-time",
            "30",
            "-X",
            "POST",
            "--data-binary",
            "@-",
            "-w",
            "\n%{http_code}",
            url,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("curl is needed to reach {url}: {e}"))?;
    child
        .stdin
        .take()
        .ok_or("curl stdin")?
        .write_all(body.as_bytes())
        .map_err(|e| format!("{url}: {e}"))?;
    let out = child
        .wait_with_output()
        .map_err(|e| format!("{url}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{url}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let (resp, code) = text.rsplit_once('\n').ok_or("curl gave no status")?;
    Ok((
        code.trim().parse().map_err(|_| "curl gave no status")?,
        resp.to_string(),
    ))
}

/// The registrar's checkpoint note and the consistency proof from `old`, for one and the same head.
fn note_and_proof(reg: &str, old: u64) -> Result<(String, u64, [u8; 32], Vec<String>), String> {
    for _ in 0..3 {
        let note_text = String::from_utf8(fetch(reg, "checkpoint")?)
            .map_err(|_| "the checkpoint is not text")?;
        let n = note::parse_note(&note_text)?;
        let (_, size, root) = note::parse_checkpoint_text(&n.text)?;
        if old > size {
            return Err(format!(
                "this witness last cosigned size {old}, the log is at {size}: a ROLLBACK"
            ));
        }
        let feed = fetch_json(reg, &format!("witness-feed?from={old}"))?;
        let fsize = feed["checkpoint"]["size"]
            .as_u64()
            .ok_or("the feed has no size")?;
        let froot = b64::decode_array::<32>(feed["checkpoint"]["root"].as_str().unwrap_or(""))
            .map_err(|_| "the feed's root".to_string())?;
        if fsize != size || froot != root {
            continue; // the log grew between the two reads: read both again
        }
        let mut proof = Vec::new();
        for h in feed["consistency_proof"].as_array().into_iter().flatten() {
            let raw = b64::decode_array::<32>(h.as_str().unwrap_or(""))
                .map_err(|_| "a proof hash".to_string())?;
            proof.push(Base64::encode_string(&raw));
        }
        if proof.len() > 63 {
            return Err("the consistency proof is longer than a witness accepts (63)".into());
        }
        return Ok((note_text, size, root, proof));
    }
    Err("the log kept growing between reading its checkpoint and its proof".into())
}

fn run(a: &[String], reg: &str, wit: &str, state_path: &str) -> Result<i32, String> {
    let wvk = opt(a, "witness-vkey").map(note::parse_vkey).transpose()?;
    let lvk = opt(a, "log-vkey").map(note::parse_vkey).transpose()?;
    let last: Value = std::fs::read(state_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(json!({}));
    let mut old = last["size"].as_u64().unwrap_or(0);
    let url = format!("{}/add-checkpoint", wit.trim_end_matches('/'));
    for attempt in 0..2 {
        let (note_text, size, root, proof) = note_and_proof(reg, old)?;
        if let Some(vk) = &lvk {
            if !note::verify_log_signature(&note::parse_note(&note_text)?, vk)? {
                return Err(format!(
                    "the checkpoint carries no signature by {}",
                    vk.name
                ));
            }
        }
        let mut body = format!("old {old}\n");
        for p in &proof {
            body.push_str(p);
            body.push('\n');
        }
        body.push('\n');
        body.push_str(&note_text);
        let (code, resp) = post(&url, &body)?;
        match code {
            200 => {
                let text = note::parse_note(&note_text)?.text;
                let mut seen = String::from("not checked (no --witness-vkey)");
                if let Some(vk) = &wvk {
                    let got = note::verify_cosignatures(&text, &resp, vk)?;
                    let note::Cosig::Verified(t) = got[0];
                    seen = format!("verified, made at {t}");
                }
                let st = json!({ "witness": wit, "size": size, "root": Base64::encode_string(&root),
                    "cosignatures": resp.lines().filter(|l| !l.is_empty()).collect::<Vec<_>>() });
                std::fs::write(
                    state_path,
                    serde_json::to_string_pretty(&st).unwrap_or_default(),
                )
                .map_err(|e| format!("{state_path}: {e}"))?;
                println!(
                    "COSIGNED: {} at size {size} (from {old}) — the cosignature is {seen}",
                    text.lines().next().unwrap_or("")
                );
                return Ok(0);
            }
            409 if attempt == 0 => {
                let n: u64 = resp
                    .trim()
                    .parse()
                    .map_err(|_| format!("409 without a size: {resp:?}"))?;
                eprintln!("witness-submit: the witness last cosigned size {n}, not {old}: starting again from {n}");
                old = n;
            }
            403 => {
                println!("REFUSED 403: the witness does not trust this log's note key for its origin (or the signature failed)");
                return Ok(3);
            }
            404 => return Err(
                "404: the witness does not know this log's origin — it has not been added there"
                    .into(),
            ),
            422 => {
                println!("REFUSED 422: the witness found the log INCONSISTENT with what it cosigned before: {}", resp.trim());
                return Ok(3);
            }
            c => return Err(format!("the witness answered {c}: {}", resp.trim())),
        }
    }
    Err("the witness answered 409 twice".into())
}
