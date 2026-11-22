#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# make stage-wallclock-drill — the test network on the wall clock instead of its pinned April 2026 clock (D-064),
# rehearsed on a whole throwaway network.
#
# The published test network is pinned: its directory is dated 10 April 2026, and `ainra ctl status` read at the
# real clock says so ("stale directory: issued N day(s) ago, the published quarterly cadence allows 92"). This drill
# runs what moving it would take, beside the real network and touching none of it: its own folder under the cache
# directory, its own root seeds (made for the drill), and spare addresses (5947, 5951, 5981, 9097). In two parts:
#
#   A · a network BORN on the wall clock (AINRA_STAGE_CLOCK=wall): seeded, accredited and published at the real time;
#       a passport issued and one revoked; `ainra ctl status` with no --now ends without an alarm; both passports get
#       the right answer from the SDK at the real clock; signing again is a new epoch, made only when asked for.
#   B · a network born on the PINNED clock (the switch unset, as today), then MOVED: the same registrars restarted
#       keeping real time over the same keys, logs and passports, and the directory signed again by the same root.
#
# WITNESS: six negative controls, each of which must fail in its own way or the drill fails.
#   A2  the revoked passport is refused as `revoked`, by the verifier that accepts the other one.
#   A4  the same `ctl status`, its clock set 100 days ahead, raises exactly the stale-directory alarm.
#   A6  a pinned publish and a pinned signing over the wall-clock network are refused, and change nothing.
#   B1  with the switch unset the network is the pinned one it has always been: dated April 2026, and read at the
#       real clock it raises the stale-directory alarm and a stale fresh head for each registrar.
#   B2  a pinned publish over registrars already restarted on the real clock is refused, and changes nothing.
#   B3  restarting the registrars on the real clock does not date the directory: without a new signing it is still
#       epoch 1 and still stale.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
# The verdicts below come from the SDK this checkout builds.
{ [ -f packages/sdk-ts/dist/index.js ] && [ -f packages/sdk-ts/dist/conformance.js ]; } || make -s sdk-build >/dev/null

# Nothing a caller's shell happens to export may steer the throwaway networks.
unset AINRA_STAGE_CLOCK AINRA_STAGE_RESIGN AINRA_STAGE_NEW_ROOT AINRA_STAGE_TAKE_BACK AINRA_CLOCK
R1=127.0.0.1:5947 ; R2=127.0.0.1:5951
PORTS=(5947 5951 5981 9097)
PINNED_SIGNED=$((1775865600 - 3600)) ; PINNED_NOW=$((1775865600 + 10*24*3600))
bad=0; ok(){ echo "  ok    $1"; }; fail(){ echo "  ✗     $1"; bad=1; }
taken(){ (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
for p in "${PORTS[@]}"; do
  taken "$p" && { echo "stage-wallclock-drill: something already listens on :$p — not starting"; exit 2; }
done
T="$(mktemp -d -p "${XDG_CACHE_HOME:-$HOME/.cache}" ainra-wallclock-drill-XXXXXX)" || exit 2
export AINRA_STAGE_REG1="$R1" AINRA_STAGE_REG2="$R2" AINRA_STAGE_WIT=127.0.0.1:5981 AINRA_STAGE_ART=9097
# net <born|moved> <wall|pinned> <stage.sh arguments…> — every call names its own folder and its own root seed.
net(){
  local name="$1" clock="$2"; shift 2
  if [ "$clock" = wall ]; then
    AINRA_STAGE_DIR="$T/$name" AINRA_STAGE_ROOT_SEED="$T/$name-root.seed" AINRA_STAGE_CLOCK=wall bash tools/stage.sh "$@"
  else
    AINRA_STAGE_DIR="$T/$name" AINRA_STAGE_ROOT_SEED="$T/$name-root.seed" bash tools/stage.sh "$@"
  fi
}
pids=()
# shellcheck disable=SC2329  # run by the EXIT trap
cleanup(){
  for p in "${pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
  net born wall down >/dev/null 2>&1
  net moved pinned down >/dev/null 2>&1
  rm -rf "$T"
}
trap cleanup EXIT
started=$(date +%s)

enc(){ node -e 'process.stdout.write(encodeURIComponent(process.argv[1]))' "$1"; }
token(){ cat "$T/$1/.issue-token"; }
issue(){ # issue <net> <addr> <lineage> — prints the new passport's name
  curl -s -m 10 -H 'Content-Type: application/json' -H "Authorization: Bearer $(token "$1")" \
    -d "{\"operator\":\"drill\",\"lineage\":\"$3\",\"version\":\"1.0.0\",\"tier\":\"L1\",\"auth_class\":\"A2\",\"principal_proof\":\"deadbeefdrill\",\"capabilities\":[\"read:x\"],\"scope_ceiling\":[\"read:x\"],\"hops\":[]}" \
    "http://$2/issue" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{process.stdout.write(JSON.parse(s).sub||"")}catch{}})'
}
# sdk <public dir> <addr> <passport> — the registrar presents it, and the SDK verifies the bundle against the
# published directory and roots at THIS machine's clock (no --now). Prints the verifier's one line; returns its exit.
sdk(){
  curl -s -m 10 "http://$2/present?sub=$(enc "$3")" -o "$T/bundle.json" || return 9
  node tools/ainra-verify.mjs --directory "$1/directory.json" --roots "$1/roots.json" --bundle "$T/bundle.json" 2>&1
}
# record <public dir> — every passport in the published record through the SDK, as the smoke test, the explorer and
# the site read it: a presentation rebuilt from the exported record, at the record's own verified_at. Prints
# "valid revoked other disagreeing verified_at": other = any verdict but valid or revoked; disagreeing = the SDK's
# verdict is not the one the registrar published beside the record.
record(){
  node --input-type=module -e '
import { runVector } from "./packages/sdk-ts/dist/conformance.js";
import fs from "node:fs";
const enc=(u)=>Buffer.from(u).toString("base64").replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
const reg=JSON.parse(fs.readFileSync(process.argv[1]+"/registry.json","utf8")); const now=reg.generated_window.verified_at;
const wire=(rec,R)=>({name:rec.sub,expect:{},anchors:{[R.registrar]:{issuer_key:R.accreditation.issuer_key,log_root_key:R.accreditation.log_root_key}},presentation:{claims:enc(new TextEncoder().encode(rec.claims)),issuer_sig:{ed25519:rec.issuer_sig_ed25519,mldsa65:rec.issuer_sig_mldsa65},now,chain_keys:rec.chain_keys,hop_proofs:rec.hop_proofs,status_list:R.status_list.status_list_b64,status_len:R.status_list.bit_len,status_issued_at:R.status_list.issued_at,freshness:"F3",checkpoint:{origin:rec.log_origin,size:rec.checkpoint_size,root:rec.checkpoint_root},checkpoint_sig:rec.checkpoint_sig,leaf_index:rec.leaf_index,inclusion_proof:rec.inclusion_proof,mandate_revocations:[],revoked_delegates:[]}});
const say=(v)=>v.verdict==="valid"?"valid":String(v.reason);
let valid=0,revoked=0,other=0,differ=0;
for(const R of reg.registrars) for(const e of R.records){const v=say(runVector(wire(e.record,R)));
  if(v==="valid")valid++;else if(v==="revoked")revoked++;else{other++;console.error("        "+e.record.sub+": "+v);}
  if(v!==say(e.verdict))differ++;}
console.log(valid,revoked,other,differ,now);' "$1" 2>"$T/record.err"
}
signed_at(){ ./target/release/ainra directory digest "$1" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const j=JSON.parse(s);process.stdout.write(j.epoch+" "+j.issued_at)}catch{}})'; }
day(){ node -e 'process.stdout.write(new Date(process.argv[1]*1000).toISOString().slice(0,10))' "$1"; }
sum(){ sha256sum "$1" 2>/dev/null | cut -c1-64; }

echo "A · a network born on the wall clock (AINRA_STAGE_CLOCK=wall)"
PUB="$T/born/public"
net born wall up > "$T/born-up.log" 2>&1
if [ -s "$PUB/directory.json" ] && [ -s "$PUB/roots.json" ] && [ -s "$PUB/registry.json" ]; then
  ok "up: two registrars keeping real time, seeded, accredited and published, with a root of its own"
else fail "the wall-clock network did not come up:"; tail -15 "$T/born-up.log"; echo "STAGE WALLCLOCK DRILL FAILED"; exit 1; fi
read -r epoch at <<< "$(signed_at "$PUB/directory.json")"
age=$(( $(date +%s) - ${at:-0} ))
if [ "${epoch:-0}" = 1 ] && [ "$age" -ge 0 ] && [ "$age" -lt 900 ]; then
  ok "A1 the directory is epoch 1, dated the moment it was signed (${age}s ago, $(day "$at")), not April 2026"
else fail "A1 the directory is not dated now: epoch ${epoch:-?}, issued_at ${at:-?}"; fi

keep="$(issue born "$R1" courier)"; gone="$(issue born "$R1" runaway)"
revoked="$(curl -s -m 10 -H 'Content-Type: application/json' -H "Authorization: Bearer $(token born)" -d "{\"sub\":\"$gone\"}" "http://$R1/revoke")"
if [ -n "$keep" ] && [ -n "$gone" ] && echo "$revoked" | grep -q '"seq"' && net born wall publish > "$T/born-publish.log" 2>&1; then
  ok "A2 issued $keep, issued and revoked $gone, published"
else fail "A2 could not issue, revoke and publish:"; echo "$revoked" | cut -c1-200; tail -5 "$T/born-publish.log" 2>/dev/null; fi
v="$(sdk "$PUB" "$R1" "$keep")"; rc=$?
if [ "$rc" = 0 ] && [ "$v" = "ainra-verify: VALID" ]; then
  ok "A2 the SDK at the real clock, against the published directory and roots: $keep is VALID"
else fail "A2 the passport issued here does not verify at the real clock: $v (exit $rc)"; fi
window="$(node -e 'const c=JSON.parse(Buffer.from(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).claims,"base64url").toString());process.stdout.write(c.nbf+" "+c.exp)' "$T/bundle.json" 2>/dev/null)"
v="$(sdk "$PUB" "$R1" "$gone")"; rc=$?
if [ "$rc" = 1 ] && [ "$v" = "ainra-verify: INVALID (revoked)" ]; then
  ok "A2 the revoked one is refused: $v"
else fail "A2 the revoked passport was not refused as revoked: $v (exit $rc)"; fi

ctl="$(./target/release/ainra ctl status --net "$PUB" --roots "$PUB/roots.json" --state "$T/born-ctl.json" --fresh-max 600 2>&1)"; rc=$?
if [ "$rc" = 0 ] && echo "$ctl" | grep -q "^CTL OK" && echo "$ctl" | grep -q "directory issued 0 day(s) ago" \
   && ! echo "$ctl" | grep -q "ALARM" && [ "$(echo "$ctl" | grep -c "fresh head [0-9]*s old")" = 2 ]; then
  ok "A3 ainra ctl status, no --now: no alarm — the directory is fresh and both registrars' heads are under ten minutes old"
else fail "A3 ainra ctl status alarms on the wall-clock network (exit $rc):"; echo "$ctl" | tail -8; fi
read -r nv nr no nd vat <<< "$(record "$PUB")"
if [ "${no:-1}" = 0 ] && [ "${nd:-1}" = 0 ] && [ "${nv:-0}" -ge 1 ] && [ "${nr:-0}" -ge 1 ] && [ $(( $(date +%s) - ${vat:-0} )) -lt 900 ]; then
  ok "A3 the whole published record through the SDK at its own verified_at (the real time): $nv valid, $nr revoked, none otherwise"
else fail "A3 the published record does not read as the registrars say: ${nv:-?} valid, ${nr:-?} revoked, ${no:-?} otherwise, ${nd:-?} disagreeing, verified_at ${vat:-?}"; cat "$T/record.err"; fi

ahead=$(( $(date +%s) + 100*86400 ))
ctl="$(./target/release/ainra ctl status --net "$PUB" --roots "$PUB/roots.json" --state "$T/born-ctl.json" --now "$ahead" 2>&1)"; rc=$?
if [ "$rc" = 1 ] && echo "$ctl" | grep -q "ALARM  stale directory: issued 100 day(s) ago, the published quarterly cadence allows 92" \
   && echo "$ctl" | grep -q "^CTL ALARM — 1 alarm(s)"; then
  ok "A4 the same check 100 days ahead: exactly one alarm, the stale directory (a directory must be signed again within 92 days)"
else fail "A4 a directory 100 days old did not raise exactly the stale-directory alarm (exit $rc):"; echo "$ctl" | tail -6; fi

before="$(sum "$PUB/directory.json")"
if net born wall accredit > "$T/born-accredit.log" 2>&1 && grep -q "accredited at epoch 1 " "$T/born-accredit.log" && [ "$(sum "$PUB/directory.json")" = "$before" ]; then
  ok "A5 accredited again with nothing changed: still epoch 1, the same bytes (a restart signs nothing new)"
else fail "A5 a second accreditation changed the directory:"; tail -4 "$T/born-accredit.log"; fi
roots="$(sum "$PUB/roots.json")"
AINRA_STAGE_RESIGN=1 net born wall accredit > "$T/born-resign.log" 2>&1
read -r epoch at2 <<< "$(signed_at "$PUB/directory.json")"
ctl="$(./target/release/ainra ctl status --net "$PUB" --roots "$PUB/roots.json" --state "$T/born-ctl.json" 2>&1)"; rc=$?
if [ "${epoch:-0}" = 2 ] && [ "${at2:-0}" -ge "${at:-1}" ] && [ "$(sum "$PUB/roots.json")" = "$roots" ] && [ "$rc" = 0 ] \
   && echo "$ctl" | grep -q "epoch history: 2 epoch(s)" && echo "$ctl" | grep -q "^CTL OK"; then
  ok "A5 asked to sign again (AINRA_STAGE_RESIGN=1): epoch 2 under the same root, epoch 1 kept in the history, no alarm"
else fail "A5 signing again did not give a clean epoch 2 (epoch ${epoch:-?}, ctl exit $rc):"; tail -3 "$T/born-resign.log"; echo "$ctl" | tail -6; fi

# What the watchdog, or the node's own publish, would do after a move if nobody told them the clock had changed.
rsum="$(sum "$PUB/registry.json")"; dsum="$(sum "$PUB/directory.json")"; esum="$(sum "$PUB/epochs.json")"
net born pinned publish > "$T/born-pinned-publish.log" 2>&1; prc=$?
net born pinned accredit > "$T/born-pinned-accredit.log" 2>&1; arc=$?
if [ "$prc" != 0 ] && grep -q "dated at the real time and this publish is pinned" "$T/born-pinned-publish.log" \
   && [ "$arc" != 0 ] && grep -q "dated at the real time and this signing is pinned" "$T/born-pinned-accredit.log" \
   && [ "$(sum "$PUB/registry.json")" = "$rsum" ] && [ "$(sum "$PUB/directory.json")" = "$dsum" ] && [ "$(sum "$PUB/epochs.json")" = "$esum" ]; then
  ok "A6 a pinned publish and a pinned signing over this network are each refused by name; record, directory and history unchanged"
else fail "A6 a pinned run was let loose on a wall-clock network (publish exit $prc, accredit exit $arc):"; tail -2 "$T/born-pinned-publish.log" "$T/born-pinned-accredit.log"; fi
net born wall down >/dev/null 2>&1
if [ -n "$window" ]; then
  read -r nbf exp <<< "$window"
  echo "  note  $keep, issued today, is valid $(day "$nbf") to $(day "$exp"): registrar-box gives a first issuance a"
  echo "        fixed window on either clock. $(( (exp - $(date +%s)) / 86400 )) day(s) are left of it; after that this drill fails at A2."
fi

echo "B · a network born on the pinned clock (the switch unset), then moved to the wall clock"
for _ in $(seq 1 40); do busy=0; for p in "${PORTS[@]}"; do taken "$p" && busy=1; done; [ "$busy" = 0 ] && break; sleep 0.25; done
PUB="$T/moved/public"
net moved pinned up > "$T/moved-up.log" 2>&1
read -r epoch at <<< "$(signed_at "$PUB/directory.json")"
vat="$(node -e 'process.stdout.write(String(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).generated_window.verified_at))' "$PUB/registry.json" 2>/dev/null)"
ctl="$(./target/release/ainra ctl status --net "$PUB" --roots "$PUB/roots.json" --state "$T/moved-ctl.json" --fresh-max 600 2>&1)"; rc=$?
if [ "${epoch:-0}" = 1 ] && [ "${at:-0}" = "$PINNED_SIGNED" ] && [ "$vat" = "$PINNED_NOW" ] && [ "$rc" = 1 ] \
   && echo "$ctl" | grep -q "ALARM  stale directory: issued [0-9]* day(s) ago, the published quarterly cadence allows 92" \
   && [ "$(echo "$ctl" | grep -c "ALARM  registrar-[0-9]*: fresh head is [0-9]*s old")" = 2 ]; then
  ok "B1 unset, it is the pinned network: dated $(day "$at"), verified_at $(day "$vat"); read at the real clock it alarms ($(echo "$ctl" | grep -o "issued [0-9]* day(s) ago"), both heads stale)"
else fail "B1 the pinned default is not what it was (epoch ${epoch:-?}, issued_at ${at:-?}, verified_at ${vat:-?}, ctl exit $rc):"; tail -5 "$T/moved-up.log"; echo "$ctl" | tail -6; fi
ctl="$(./target/release/ainra ctl status --net "$PUB" --roots "$PUB/roots.json" --state "$T/moved-ctl.json" --now "$PINNED_NOW" 2>&1)"; rc=$?
if [ "$rc" = 0 ] && echo "$ctl" | grep -q "^CTL OK"; then
  ok "B1 read at its own pinned instant (--now $PINNED_NOW) it has no alarm, as today; that look is remembered"
else fail "B1 the pinned network alarms at its own instant (exit $rc):"; echo "$ctl" | tail -6; fi
april="ainra:registrar-07:acme:invoicing@4.2.1" ; april_gone="ainra:registrar-07:acme:data-export@2.0.0"

net moved pinned down >/dev/null 2>&1
for _ in $(seq 1 40); do busy=0; for p in "${PORTS[@]}"; do taken "$p" && busy=1; done; [ "$busy" = 0 ] && break; sleep 0.25; done
for pair in "$R1 registrar-07" "$R2 registrar-11"; do
  read -r addr id <<< "$pair"
  AINRA_STAGE=1 AINRA_CLOCK=wall AINRA_FRESH_KEYS=1 AINRA_STAGE_ISSUE_TOKEN="$(token moved)" \
    ./target/release/registrar-box "$addr" "$id" "$T/moved/$id" > "$T/moved/$id.wall.log" 2>&1 & pids+=($!)
done
for _ in $(seq 1 80); do
  curl -s -m 1 -o /dev/null "http://$R1/accreditation" && curl -s -m 1 -o /dev/null "http://$R2/accreditation" && break; sleep 0.25
done
if grep -q "RELOADED" "$T/moved/registrar-07.wall.log" && grep -q "delegates re-certified at the wall clock" "$T/moved/registrar-07.wall.log" \
   && grep -q "RELOADED" "$T/moved/registrar-11.wall.log" && grep -q "delegates re-certified at the wall clock" "$T/moved/registrar-11.wall.log"; then
  ok "B2 the same two registrars restarted keeping real time: state reloaded, the same keys, delegates certified again"
else fail "B2 the registrars did not restart on the wall clock over their pinned state:"; tail -4 "$T/moved/registrar-07.wall.log" "$T/moved/registrar-11.wall.log"; fi
# The moment a watchdog could meet: registrars already on the real clock, the directory still dated April.
rsum="$(sum "$PUB/registry.json")"
net moved pinned publish > "$T/moved-pinned-publish.log" 2>&1; prc=$?
if [ "$prc" != 0 ] && grep -q "keeps real time and this publish is pinned" "$T/moved-pinned-publish.log" && [ "$(sum "$PUB/registry.json")" = "$rsum" ]; then
  ok "B2 a pinned publish over them is refused by name, and the published record is left as it was"
else fail "B2 a pinned publish ran over registrars that keep real time (exit $prc):"; tail -2 "$T/moved-pinned-publish.log"; fi

roots="$(sum "$PUB/roots.json")"
net moved wall accredit > "$T/moved-accredit.log" 2>&1; arc=$?
ctl="$(./target/release/ainra ctl status --net "$PUB" --roots "$PUB/roots.json" --state "$T/moved-ctl.json" 2>&1)"; rc=$?
if [ "$arc" = 0 ] && grep -q "accredited at epoch 1 " "$T/moved-accredit.log" && [ "$rc" = 1 ] && echo "$ctl" | grep -q "ALARM  stale directory"; then
  ok "B3 accredited with nothing changed: still epoch 1, still dated April — restarting the registrars does not cure the directory"
else fail "B3 expected the unchanged epoch 1 and the stale alarm (accredit exit $arc, ctl exit $rc):"; tail -3 "$T/moved-accredit.log"; echo "$ctl" | tail -5; fi
AINRA_STAGE_RESIGN=1 net moved wall accredit > "$T/moved-resign.log" 2>&1
read -r epoch at <<< "$(signed_at "$PUB/directory.json")"
ctl="$(./target/release/ainra ctl status --net "$PUB" --roots "$PUB/roots.json" --state "$T/moved-ctl.json" --fresh-max 600 2>&1)"; rc=$?
if [ "${epoch:-0}" = 2 ] && [ $(( $(date +%s) - ${at:-0} )) -lt 900 ] && [ "$(sum "$PUB/roots.json")" = "$roots" ] && [ "$rc" = 0 ] \
   && echo "$ctl" | grep -q "epoch history: 2 epoch(s)" && echo "$ctl" | grep -q "^CTL OK" && ! echo "$ctl" | grep -q "ALARM"; then
  ok "B4 signed again by the same root: epoch 2 dated today; ctl, remembering the pinned look, has no alarm at the real clock"
else fail "B4 the moved network is not clean at the real clock (epoch ${epoch:-?}, ctl exit $rc):"; tail -3 "$T/moved-resign.log"; echo "$ctl" | tail -8; fi

v="$(sdk "$PUB" "$R1" "$april")"; rc=$?
v2="$(sdk "$PUB" "$R1" "$april_gone")"; rc2=$?
if [ "$rc" = 0 ] && [ "$v" = "ainra-verify: VALID" ] && [ "$rc2" = 1 ] && [ "$v2" = "ainra-verify: INVALID (revoked)" ]; then
  ok "B5 passports issued in the pinned world, presented now, at the real clock: invoicing VALID, data-export revoked"
else fail "B5 the pinned world's passports do not carry over: invoicing → $v (exit $rc), data-export → $v2 (exit $rc2)"; fi
read -r nv nr no nd vat <<< "$(record "$PUB")"
if [ "${no:-1}" = 0 ] && [ "${nd:-1}" = 0 ] && [ "${nv:-0}" -ge 1 ] && [ "${nr:-0}" -ge 1 ] && [ $(( $(date +%s) - ${vat:-0} )) -lt 900 ]; then
  ok "B5 the whole published record through the SDK at the real time: $nv valid, $nr revoked, none otherwise"
else fail "B5 the moved network's published record does not read as its registrars say: ${nv:-?} valid, ${nr:-?} revoked, ${no:-?} otherwise, ${nd:-?} disagreeing"; cat "$T/record.err"; fi

took=$(( $(date +%s) - started ))
if [ $bad = 0 ]; then
  echo "STAGE WALLCLOCK DRILL OK: born on the wall clock and moved to it, no alarm at the real clock, valid and revoked read right, stale 100 days ahead, the pinned default unchanged (${took}s)"
else echo "STAGE WALLCLOCK DRILL FAILED (${took}s)"; fi
exit $bad
