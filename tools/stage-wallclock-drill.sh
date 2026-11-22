#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# make stage-wallclock-drill — the test network on the wall clock instead of its pinned April 2026 clock (D-064),
# rehearsed on a whole throwaway network, with everything that surrounds the network reading its clock from it.
#
# The published test network is pinned: its directory is dated 10 April 2026, and `ainra ctl status` read at the
# real clock says so ("stale directory: issued N day(s) ago, the published quarterly cadence allows 92"). This drill
# runs what moving it would take, beside the real network and touching none of it: its own folder under the cache
# directory, its own root seeds (made for the drill), and spare addresses (5947, 5951, 5981, 9097). In two parts:
#
#   A · a network BORN on the wall clock, from the statement in its own folder alone (the file CLOCK says `wall`; no
#       variable): seeded, accredited and published at the real time; a passport issued and one revoked; `ainra ctl
#       status` with no --now ends without an alarm; both passports get the right answer from the SDK at the real
#       clock; signing again is a new epoch, made only when asked for.
#   B · a network born on the PINNED clock (no file, no variable, as today), then MOVED: the same registrars restarted
#       keeping real time over the same keys, logs and passports, the file written, and the directory signed again by
#       the same root with no variable.
#
# On both networks, what surrounds a network is run against it and must read the network's own clock: the record's
# statement (tools/net-clock.mjs), the installer's unit settings (printed, never installed), the home watch, a copy of
# the record as the site keeps one (in a temporary folder, never site/net/) with `site-net-check` and `record-agrees`,
# and the four drills that talk to a running network (stage-smoke, genesis-verify, demo-walkthrough, three-clients).
#
# WITNESS: negative controls, each of which must fail in its own way or the drill fails.
#   A2  the revoked passport is refused as `revoked`, by the verifier that accepts the other one.
#   A4  the same `ctl status`, its clock set 100 days ahead, raises exactly the stale-directory alarm.
#   A6  with the folder's statement lost, a publish and a signing over the wall-clock network are refused (the guards
#       that came before the file still stand), and change nothing.
#   M2  a variable that disagrees with the folder is refused by name, both ways round, and so is a file that says
#       neither word; a variable that agrees is accepted, so the guard does not refuse everything.
#   I1  the installer prints `pinned` for a folder that says nothing and refuses a file that says neither word.
#   W1  a copy of the record with its statement removed, shown to the watch that saw the statement, is an alarm.
#   S3  a copy with a tampered directory is refused; S4 a copy behind a new epoch; S6 a copy that still shows a
#       passport the network has since revoked (and `record-agrees` refuses that one too).
#   D2  demo-walkthrough told to use the April instant on the wall-clock network fails at exactly its two write steps.
#   B1  with nothing said the network is the pinned one it has always been: dated April 2026, no clock in its record,
#       and read at the real clock it raises the stale-directory alarm and a stale fresh head for each registrar.
#   B1  the pinned copy is byte for byte the network, and a tampered directory in it is refused.
#   B1  a publish and a signing that keep real time, over registrars that are still pinned (the move begun in the
#       wrong order), are refused by name and change nothing.
#   B2  a pinned publish over registrars already restarted on the real clock is refused, and changes nothing.
#   B3  restarting the registrars on the real clock does not date the directory: without a new signing it is still
#       epoch 1 and still stale. With the file written, a run that still names the pinned clock is refused.
#   B4  the copy taken while the network was pinned is refused against the network after its move.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
# The verdicts below come from the SDK this checkout builds.
{ [ -f packages/sdk-ts/dist/index.js ] && [ -f packages/sdk-ts/dist/conformance.js ]; } || make -s sdk-build >/dev/null

# Nothing a caller's shell happens to export may steer the throwaway networks or what reads them.
unset AINRA_STAGE_CLOCK AINRA_STAGE_RESIGN AINRA_STAGE_NEW_ROOT AINRA_STAGE_TAKE_BACK AINRA_CLOCK AINRA_STAGE_DIR \
      AINRA_HOME_NOW AINRA_HOME_NET AINRA_HOME_REGISTRARS AINRA_HOME_ROOTS AINRA_HOME_STATE AINRA_HOME_ALERT \
      AINRA_HOME_WATCH AINRA_HOME_EXPECT AINRA_CONTRACT AINRA_SITE_NET_DEST AINRA_SITE_NEW_ROOT AINRA_REG AINRA_REGID \
      AINRA_ART AINRA_ARTIFACTS AINRA_NOW AINRA_SUB AINRA_RECORD AINRA_DOORS AINRA_EVIDENCE_DIR
R1=127.0.0.1:5947 ; R2=127.0.0.1:5951 ; ART=http://127.0.0.1:9097
PORTS=(5947 5951 5981 9097)
PINNED_SIGNED=$((1775865600 - 3600)) ; PINNED_NOW=$((1775865600 + 10*24*3600))
bad=0; ok(){ echo "  ok    $1"; }; fail(){ echo "  ✗     $1"; bad=1; }
taken(){ (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
for p in "${PORTS[@]}"; do
  taken "$p" && { echo "stage-wallclock-drill: something already listens on :$p — not starting"; exit 2; }
done
T="$(mktemp -d -p "${XDG_CACHE_HOME:-$HOME/.cache}" ainra-wallclock-drill-XXXXXX)" || exit 2
export AINRA_STAGE_REG1="$R1" AINRA_STAGE_REG2="$R2" AINRA_STAGE_WIT=127.0.0.1:5981 AINRA_STAGE_ART=9097
# net <folder> <own|wall|pinned> <stage.sh arguments…> — every call names its own folder and its own root seed.
#   own      no variable at all: the network's clock is whatever its own folder says (a CLOCK file, or nothing)
#   wall     AINRA_STAGE_CLOCK=wall for this run       pinned   AINRA_STAGE_CLOCK=pinned for this run
net(){
  local name="$1" clock="$2"; shift 2
  if [ "$clock" = own ]; then
    AINRA_STAGE_DIR="$T/$name" AINRA_STAGE_ROOT_SEED="$T/$name-root.seed" bash tools/stage.sh "$@"
  else
    AINRA_STAGE_DIR="$T/$name" AINRA_STAGE_ROOT_SEED="$T/$name-root.seed" AINRA_STAGE_CLOCK="$clock" bash tools/stage.sh "$@"
  fi
}
pids=()
# shellcheck disable=SC2329  # run by the EXIT trap
cleanup(){
  for p in "${pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
  net born own down >/dev/null 2>&1
  net moved own down >/dev/null 2>&1
  rm -rf "$T"
}
trap cleanup EXIT
started=$(date +%s)
touch "$T/started"

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
field(){ node -e 'const v=process.argv[2].split(".").reduce((o,k)=>o?.[k],JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")));process.stdout.write(v===undefined?"-":String(v))' "$1" "$2"; }
free_ports(){ for _ in $(seq 1 40); do busy=0; for p in "${PORTS[@]}"; do taken "$p" && busy=1; done; [ "$busy" = 0 ] && break; sleep 0.25; done; }

# ── what surrounds a network, pointed at a throwaway one ──
# watch <public record: a URL or a folder> <state name> [AINRA_HOME_NOW] — one round of the home watch. It is given a
# clock only when the caller passes one; otherwise it must find the network's own. Output in $T/watch.out.
watch(){
  AINRA_HOME_NET="$1" AINRA_HOME_REGISTRARS="http://$R1 http://$R2" AINRA_HOME_ROOTS="$T/$2-roots.json" \
  AINRA_HOME_STATE="$T/$2-state" AINRA_HOME_NOW="${3:-}" bash tools/home-watch.sh > "$T/watch.out" 2>&1
}
# copy <folder> <publish|check> — tools/site-net.sh against the throwaway network and a copy in a temporary folder.
# Both addresses are always named: unset, the tool would read the standing network and write site/net/.
copy(){ AINRA_CONTRACT="$ART" AINRA_SITE_NET_DEST="$T/$1" AINRA_REG="http://$R1" bash tools/site-net.sh "$2" > "$T/copy.out" 2>&1; }
agrees(){ AINRA_RECORD="$T/$1" AINRA_DOORS="registrar-07=http://$R1,registrar-11=http://$R2" node tools/record-agrees.mjs > "$T/agrees.out" 2>&1; }
tamper(){ node -e 'const fs=require("fs"),p=process.argv[1],j=JSON.parse(fs.readFileSync(p,"utf8"));j.issued_at+=1;fs.writeFileSync(p,JSON.stringify(j))' "$1"; }
envs(){ bash tools/stage-install.sh show-env "$1" 2>"$T/envs.err"; }
count(){ grep -c "$1" <<< "$2"; }
# drills <folder> <label> — the four drills that talk to a running network, each told only where the network is.
drills(){
  local out c n=0
  out="$(AINRA_STAGE_DIR="$T/$1" bash tools/stage-smoke.sh 2>&1)"; c=$?
  if [ $c = 0 ] && grep -q "^STAGE-SMOKE OK" <<< "$out"; then n=$((n+1)); else fail "$2 stage-smoke did not pass (exit $c):"; tail -n 4 <<< "$out"; fi
  out="$(AINRA_ART="$ART" AINRA_REG="http://$R1" node tools/genesis-verify.mjs 2>&1)"; c=$?
  if [ $c = 0 ] && grep -q "verifies ROOT-DARK → VALID" <<< "$out"; then n=$((n+1)); else fail "$2 genesis-verify did not pass (exit $c):"; tail -n 4 <<< "$out"; fi
  out="$(AINRA_ART="$ART" node tools/demo-walkthrough.mjs "http://$R1" registrar-07 2>&1)"; c=$?
  if [ $c = 0 ] && grep -q "/demo lifecycle GREEN" <<< "$out"; then n=$((n+1)); else fail "$2 demo-walkthrough did not pass (exit $c):"; tail -n 7 <<< "$out" | cut -c1-200; fi
  if [ -d packages/mcp/node_modules/@ainra ]; then
    out="$(AINRA_REG="http://$R1" AINRA_ARTIFACTS="$ART" AINRA_EVIDENCE_DIR="$T/evidence" node tools/three-clients.mjs 2>&1)"; c=$?
    if [ $c = 0 ] && grep -q "3/3 independent clients green" <<< "$out"; then n=$((n+1)); else fail "$2 three-clients did not pass (exit $c):"; tail -n 5 <<< "$out"; fi
  else fail "$2 three-clients cannot run: packages/mcp is not installed (make stage-wallclock-drill installs it; or make mcp-test)"; fi
  [ "$n" = 4 ]
}

echo "A · a network born on the wall clock, by the statement in its own folder (CLOCK says wall; no variable)"
PUB="$T/born/public"
mkdir -p "$T/born"; echo wall > "$T/born/CLOCK"
net born own up > "$T/born-up.log" 2>&1
if [ -s "$PUB/directory.json" ] && [ -s "$PUB/roots.json" ] && [ -s "$PUB/registry.json" ]; then
  ok "up: two registrars keeping real time, seeded, accredited and published, with a root of its own"
else fail "the wall-clock network did not come up:"; tail -n 15 "$T/born-up.log"; echo "STAGE WALLCLOCK DRILL FAILED"; exit 1; fi
read -r epoch at <<< "$(signed_at "$PUB/directory.json")"
age=$(( $(date +%s) - ${at:-0} ))
if [ "${epoch:-0}" = 1 ] && [ "$age" -ge 0 ] && [ "$age" -lt 900 ]; then
  ok "A1 the directory is epoch 1, dated the moment it was signed (${age}s ago, $(day "$at")), not April 2026"
else fail "A1 the directory is not dated now: epoch ${epoch:-?}, issued_at ${at:-?}"; fi

keep="$(issue born "$R1" courier)"; gone="$(issue born "$R1" runaway)"
revoked="$(curl -s -m 10 -H 'Content-Type: application/json' -H "Authorization: Bearer $(token born)" -d "{\"sub\":\"$gone\"}" "http://$R1/revoke")"
if [ -n "$keep" ] && [ -n "$gone" ] && echo "$revoked" | grep -q '"seq"' && net born own publish > "$T/born-publish.log" 2>&1; then
  ok "A2 issued $keep, issued and revoked $gone, published"
else fail "A2 could not issue, revoke and publish:"; echo "$revoked" | cut -c1-200; tail -n 5 "$T/born-publish.log" 2>/dev/null; fi
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

# The folder's statement was all this network was given. What it published says the same, and everything below reads that.
said="$(node tools/net-clock.mjs "$ART" 2>&1)"
if [ "$(field "$PUB/index.json" clock)" = wall ] && [ "$(field "$PUB/registry.json" clock)" = wall ] && [ "$said" = wall ]; then
  ok "M1 no variable was set: the folder's CLOCK file alone made this network, and its record states it (\"clock\": \"wall\" in index.json and registry.json)"
else fail "M1 the record does not state the wall clock: index $(field "$PUB/index.json" clock), registry $(field "$PUB/registry.json" clock), net-clock '$said'"; fi
# What the watchdog's republish carries: no clock variable of the network's, and the units' own setting in its shell.
AINRA_CLOCK=pinned net born own publish > "$T/born-watchdog-publish.log" 2>&1; rc=$?
if [ "$rc" = 0 ] && [ "$(field "$PUB/index.json" clock)" = wall ] && [ $(( $(date +%s) - $(field "$PUB/registry.json" generated_window.verified_at) )) -lt 900 ]; then
  ok "M1 a publish told nothing, as the watchdog's is (even with AINRA_CLOCK=pinned left in its shell), runs on the network's clock"
else fail "M1 a publish with no variable did not follow the folder (exit $rc):"; tail -n 3 "$T/born-watchdog-publish.log"; fi
rsum="$(sum "$PUB/registry.json")"
net born pinned publish > "$T/born-disagree.log" 2>&1; prc=$?
mkdir -p "$T/says-pinned" "$T/says-neither"; echo pinned > "$T/says-pinned/CLOCK"; echo walll > "$T/says-neither/CLOCK"
net says-pinned wall status > "$T/disagree2.log" 2>&1; wrc=$?
net says-neither own status > "$T/neither.log" 2>&1; nrc=$?
net born wall status > "$T/agree.log" 2>&1; arc=$?
if [ "$prc" = 2 ] && grep -q "AINRA_STAGE_CLOCK=pinned, and this network's own folder says wall" "$T/born-disagree.log" && [ "$(sum "$PUB/registry.json")" = "$rsum" ] \
   && [ "$wrc" = 2 ] && grep -q "AINRA_STAGE_CLOCK=wall, and this network's own folder says pinned" "$T/disagree2.log" \
   && [ "$nrc" = 2 ] && grep -q "must hold 'wall' or 'pinned', not 'walll'" "$T/neither.log" && [ "$arc" = 0 ]; then
  ok "M2 a variable against the folder is refused by name both ways round, and a file that says neither word; one that agrees is accepted; the record unchanged"
else fail "M2 a disagreement was not refused as it should be (pinned over wall exit $prc, wall over pinned exit $wrc, neither word exit $nrc, agreeing exit $arc):"; tail -n 2 "$T/born-disagree.log" "$T/disagree2.log" "$T/neither.log" "$T/agree.log"; fi

# The installer's unit settings, printed and not installed: nothing is written and systemd is not asked for anything.
touch "$T/before-envs"
e_wall="$(envs "$T/born")"; e_none="$(envs "$T/no-such-network")"; e_bad="$(envs "$T/says-neither")"; brc=$?
touched="$(find deploy/systemd "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user" -newer "$T/before-envs" 2>/dev/null | head -1)"
if [ "$(count '^AINRA_CLOCK=wall$' "$e_wall")" = 4 ] && [ "$(count 'AINRA_CLOCK=pinned' "$e_wall")" = 0 ] \
   && [ "$(count '^AINRA_CLOCK=pinned$' "$e_none")" = 4 ] && [ "$(count 'AINRA_CLOCK=wall' "$e_none")" = 0 ] \
   && [ "$brc" != 0 ] && [ "$(count 'AINRA_CLOCK=' "$e_bad")" = 0 ] && grep -q "must hold 'wall' or 'pinned'" "$T/envs.err" \
   && ! grep -qF "$(token born)" <<< "$e_wall" && [ -z "$touched" ]; then
  ok "I1 the installer would write AINRA_CLOCK=wall into all four unit settings for this network, pinned for a folder that says nothing, and refuses a file that says neither; nothing written, no token shown"
else fail "I1 the installer's settings do not follow the folder (wall $(count '^AINRA_CLOCK=wall$' "$e_wall")/4, pinned $(count '^AINRA_CLOCK=pinned$' "$e_none")/4, bad file exit $brc, touched '${touched:-nothing}')"; fi

# The home watch, given no clock.
cp "$PUB/roots.json" "$T/born-watch-roots.json"
watch "$ART" born-watch; rc=$?
if [ "$rc" = 0 ] && grep -q "the record states real time; read at this machine's clock" "$T/watch.out" && grep -q "^HOME WATCH OK" "$T/watch.out" \
   && grep -q "^CTL OK" "$T/watch.out" && [ "$(grep -c "^MONITOR OK" "$T/watch.out")" = 2 ]; then
  ok "W1 the home watch, told no clock: it reads the record's, checks at this machine's clock, and ends without an alarm (ctl and both logs)"
else fail "W1 the home watch did not pass on the wall-clock network (exit $rc):"; tail -n 12 "$T/watch.out"; fi
cp -r "$PUB" "$T/born-relabelled"
node -e 'const fs=require("fs"),p=process.argv[1]+"/index.json",j=JSON.parse(fs.readFileSync(p,"utf8"));delete j.clock;fs.writeFileSync(p,JSON.stringify(j))' "$T/born-relabelled"
watch "$T/born-relabelled" born-watch; rc=$?
if [ "$rc" = 3 ] && grep -q "ALARM  this network stated real time before and its record now states the pinned clock" "$T/watch.out"; then
  ok "W1 the same record with its statement removed, shown to that watch: exit 3, and the alarm names it"
else fail "W1 a record relabelled as pinned was accepted by a watch that had seen it keep real time (exit $rc):"; tail -n 8 "$T/watch.out"; fi

# A copy of the record as the site keeps one, in a temporary folder, and what `make site-net-check` means for it.
copy site-born publish; rc=$?
if [ "$rc" = 0 ] && [ "$(field "$T/site-born/published.json" clock)" = wall ] && grep -q "The network keeps real time" "$T/site-born/published.json"; then
  ok "S1 a copy of the record taken into a temporary folder: its stamp says \"clock\": \"wall\", and its note says what verified_at is there"
else fail "S1 the copy was not taken, or its stamp does not state the clock (exit $rc):"; tail -n 4 "$T/copy.out"; fi
sleep 1
net born own publish > "$T/born-publish2.log" 2>&1
differ=0; for f in registry.json registrars/registrar-07/fresh-head.json registrars/registrar-07/status/current.json; do cmp -s "$T/site-born/$f" "$PUB/$f" || differ=$((differ+1)); done
copy site-born check; rc=$?
agrees site-born; arc=$?
if [ "$differ" = 3 ] && [ "$rc" = 0 ] && grep -q "^site-net OK: the published record agrees with the running network, which keeps real time" "$T/copy.out" \
   && [ "$arc" = 0 ] && grep -q "^record-agrees OK" "$T/agrees.out"; then
  ok "S2 the network published again (heads and status signed anew: the copy is no longer byte for byte): site-net-check accepts it, and record-agrees agrees on every passport"
else fail "S2 the check does not accept a copy that differs only in fresh heads and status ($differ/3 files differ, check exit $rc, record-agrees exit $arc):"; tail -n 5 "$T/copy.out" "$T/agrees.out"; fi
cp "$T/site-born/directory.json" "$T/directory.kept"; tamper "$T/site-born/directory.json"
copy site-born check; rc=$?
cp "$T/directory.kept" "$T/site-born/directory.json"
if [ "$rc" = 1 ] && grep -q "DRIFT — .*directory.json differs from what" "$T/copy.out"; then
  ok "S3 the copy's directory tampered with: refused, by name"
else fail "S3 a tampered directory in the copy was not refused (exit $rc):"; tail -n 4 "$T/copy.out"; fi

before="$(sum "$PUB/directory.json")"
if net born own accredit > "$T/born-accredit.log" 2>&1 && grep -q "accredited at epoch 1 " "$T/born-accredit.log" && [ "$(sum "$PUB/directory.json")" = "$before" ]; then
  ok "A5 accredited again with nothing changed: still epoch 1, the same bytes (a restart signs nothing new)"
else fail "A5 a second accreditation changed the directory:"; tail -n 4 "$T/born-accredit.log"; fi
roots="$(sum "$PUB/roots.json")"
AINRA_STAGE_RESIGN=1 net born wall accredit > "$T/born-resign.log" 2>&1
read -r epoch at2 <<< "$(signed_at "$PUB/directory.json")"
ctl="$(./target/release/ainra ctl status --net "$PUB" --roots "$PUB/roots.json" --state "$T/born-ctl.json" 2>&1)"; rc=$?
if [ "${epoch:-0}" = 2 ] && [ "${at2:-0}" -ge "${at:-1}" ] && [ "$(sum "$PUB/roots.json")" = "$roots" ] && [ "$rc" = 0 ] \
   && echo "$ctl" | grep -q "epoch history: 2 epoch(s)" && echo "$ctl" | grep -q "^CTL OK"; then
  ok "A5 asked to sign again (AINRA_STAGE_RESIGN=1): epoch 2 under the same root, epoch 1 kept in the history, no alarm"
else fail "A5 signing again did not give a clean epoch 2 (epoch ${epoch:-?}, ctl exit $rc):"; tail -n 3 "$T/born-resign.log"; echo "$ctl" | tail -6; fi

copy site-born check; rc=$?
if [ "$rc" = 1 ] && grep -q "DRIFT — .*directory.json differs" "$T/copy.out" && grep -q "DRIFT — the epoch history differs" "$T/copy.out"; then
  ok "S4 the copy is now an epoch behind: refused (the directory and the epoch history differ) until the site publishes again"
else fail "S4 a copy behind a new epoch was accepted (exit $rc):"; tail -n 4 "$T/copy.out"; fi
copy site-born publish; prc=$?
copy site-born check; rc=$?
if [ "$prc" = 0 ] && [ "$rc" = 0 ] && [ -s "$T/site-born/epochs/2.json" ] && [ -s "$T/site-born/epochs/1.json" ]; then
  ok "S4 published into the copy again: both epochs are in its history, and the check passes"
else fail "S4 the copy did not catch up with the new epoch (publish exit $prc, check exit $rc):"; tail -n 4 "$T/copy.out"; fi
late="$(issue born "$R1" latecomer)"
net born own publish > "$T/born-publish3.log" 2>&1
copy site-born check; rc=$?
if [ -n "$late" ] && [ "$rc" = 0 ] && grep -q "note — the network has 1 passport issued after this copy was taken" "$T/copy.out"; then
  ok "S5 a passport issued after the copy was taken: the log only grew, so the check passes and says there is one to publish"
else fail "S5 a log that only grew was not accepted with a note (exit $rc):"; tail -n 4 "$T/copy.out"; fi
curl -s -m 10 -H 'Content-Type: application/json' -H "Authorization: Bearer $(token born)" -d "{\"sub\":\"$keep\"}" "http://$R1/revoke" > /dev/null
net born own publish > "$T/born-publish4.log" 2>&1
copy site-born check; rc=$?
agrees site-born; arc=$?
if [ "$rc" = 1 ] && grep -qF "DRIFT — $keep: the copy shows it not revoked, the network revoked" "$T/copy.out" \
   && [ "$arc" = 1 ] && grep -qF "$keep: the record shows VALID" "$T/agrees.out"; then
  ok "S6 a passport the copy shows as good, revoked on the network since: refused by name, by site-net-check and by record-agrees"
else fail "S6 a copy still showing a revoked passport as good was accepted (check exit $rc, record-agrees exit $arc):"; tail -n 4 "$T/copy.out" "$T/agrees.out"; fi

if drills born "D1"; then
  ok "D1 stage-smoke, genesis-verify, demo-walkthrough and three-clients, each told only where the network is: all pass, naming no instant"
fi
out="$(AINRA_NOW="$PINNED_NOW" node tools/demo-walkthrough.mjs "http://$R1" registrar-07 2>&1)"; rc=$?
if [ "$rc" = 1 ] && [ "$(grep -c '^  ✗ [45]\. ' <<< "$out")" = 2 ] && [ "$(grep -c '^  ✓ [123]\. ' <<< "$out")" = 3 ] && grep -q "outside the delegate window" <<< "$out"; then
  ok "D2 demo-walkthrough told to use the April instant here: fails at exactly its revoke and re-verify (the registrar will not sign in April)"
else fail "D2 the April instant was accepted on a network that keeps real time (exit $rc):"; tail -n 7 <<< "$out" | cut -c1-200; fi

# The guards that came before the file still stand: a copy of this network's state that lost its CLOCK file.
rsum="$(sum "$PUB/registry.json")"; dsum="$(sum "$PUB/directory.json")"; esum="$(sum "$PUB/epochs.json")"
mv "$T/born/CLOCK" "$T/born-CLOCK.kept"
net born own publish > "$T/born-pinned-publish.log" 2>&1; prc=$?
net born own accredit > "$T/born-pinned-accredit.log" 2>&1; arc=$?
mv "$T/born-CLOCK.kept" "$T/born/CLOCK"
if [ "$prc" != 0 ] && grep -q "dated at the real time and this publish is pinned" "$T/born-pinned-publish.log" \
   && [ "$arc" != 0 ] && grep -q "dated at the real time and this signing is pinned" "$T/born-pinned-accredit.log" \
   && [ "$(sum "$PUB/registry.json")" = "$rsum" ] && [ "$(sum "$PUB/directory.json")" = "$dsum" ] && [ "$(sum "$PUB/epochs.json")" = "$esum" ]; then
  ok "A6 with the folder's statement lost, a pinned publish and a pinned signing over this network are each refused by name; record, directory and history unchanged"
else fail "A6 a pinned run was let loose on a wall-clock network (publish exit $prc, accredit exit $arc):"; tail -n 2 "$T/born-pinned-publish.log" "$T/born-pinned-accredit.log"; fi
net born own down >/dev/null 2>&1
if [ -n "$window" ]; then
  read -r nbf exp <<< "$window"
  echo "  note  $keep, issued today, is valid $(day "$nbf") to $(day "$exp"): registrar-box gives a first issuance a"
  echo "        fixed window on either clock. $(( (exp - $(date +%s)) / 86400 )) day(s) are left of it; after that this drill fails at A2."
fi

echo "B · a network born on the pinned clock (nothing said), then moved to the wall clock"
free_ports
PUB="$T/moved/public"
net moved own up > "$T/moved-up.log" 2>&1
read -r epoch at <<< "$(signed_at "$PUB/directory.json")"
vat="$(node -e 'process.stdout.write(String(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).generated_window.verified_at))' "$PUB/registry.json" 2>/dev/null)"
ctl="$(./target/release/ainra ctl status --net "$PUB" --roots "$PUB/roots.json" --state "$T/moved-ctl.json" --fresh-max 600 2>&1)"; rc=$?
if [ "${epoch:-0}" = 1 ] && [ "${at:-0}" = "$PINNED_SIGNED" ] && [ "$vat" = "$PINNED_NOW" ] && [ "$rc" = 1 ] \
   && echo "$ctl" | grep -q "ALARM  stale directory: issued [0-9]* day(s) ago, the published quarterly cadence allows 92" \
   && [ "$(echo "$ctl" | grep -c "ALARM  registrar-[0-9]*: fresh head is [0-9]*s old")" = 2 ]; then
  ok "B1 unset, it is the pinned network: dated $(day "$at"), verified_at $(day "$vat"); read at the real clock it alarms ($(echo "$ctl" | grep -o "issued [0-9]* day(s) ago"), both heads stale)"
else fail "B1 the pinned default is not what it was (epoch ${epoch:-?}, issued_at ${at:-?}, verified_at ${vat:-?}, ctl exit $rc):"; tail -n 5 "$T/moved-up.log"; echo "$ctl" | tail -6; fi
ctl="$(./target/release/ainra ctl status --net "$PUB" --roots "$PUB/roots.json" --state "$T/moved-ctl.json" --now "$PINNED_NOW" 2>&1)"; rc=$?
if [ "$rc" = 0 ] && echo "$ctl" | grep -q "^CTL OK"; then
  ok "B1 read at its own pinned instant (--now $PINNED_NOW) it has no alarm, as today; that look is remembered"
else fail "B1 the pinned network alarms at its own instant (exit $rc):"; echo "$ctl" | tail -6; fi
april="ainra:registrar-07:acme:invoicing@4.2.1" ; april_gone="ainra:registrar-07:acme:data-export@2.0.0"

# The same surroundings, on the pinned network: each must do what it has always done.
said="$(node tools/net-clock.mjs "$ART" 2>&1)"; e_pin="$(envs "$T/moved")"
if ! grep -q '"clock"' "$PUB/index.json" "$PUB/registry.json" && [ "$said" = "pinned $PINNED_NOW" ] \
   && [ "$(count '^AINRA_CLOCK=pinned$' "$e_pin")" = 4 ] && [ "$(count 'AINRA_CLOCK=wall' "$e_pin")" = 0 ]; then
  ok "B1 its record carries no clock field (read as pinned, at its verified_at $PINNED_NOW), and the installer would write AINRA_CLOCK=pinned for it, as it always has"
else fail "B1 the pinned network does not read as pinned (net-clock '$said', installer pinned $(count '^AINRA_CLOCK=pinned$' "$e_pin")/4):"; fi
cp "$PUB/roots.json" "$T/moved-watch-roots.json"
watch "$ART" moved-watch; rc=$?
if [ "$rc" = 0 ] && grep -q "the record states the pinned clock; read at its instant $PINNED_NOW" "$T/watch.out" && grep -q "^HOME WATCH OK" "$T/watch.out"; then
  ok "B1 the home watch, told no clock: it reads the record's pinned instant and ends without an alarm (at the real clock this record alarms, above)"
else fail "B1 the home watch did not pass on the pinned network (exit $rc):"; tail -n 12 "$T/watch.out"; fi
copy site-moved publish; prc=$?
net moved own publish > "$T/moved-publish2.log" 2>&1
copy site-moved check; rc=$?
if [ "$prc" = 0 ] && [ "$(field "$T/site-moved/published.json" clock)" = pinned ] && grep -q "a pinned staging constant" "$T/site-moved/published.json" \
   && [ "$rc" = 0 ] && grep -q "^site-net OK: the published record is byte-identical to the running network" "$T/copy.out"; then
  ok "B1 a copy of the pinned record: its stamp says \"clock\": \"pinned\" with the note it always had, and after another publish it is still byte for byte the network"
else fail "B1 the pinned copy is not byte for byte the network (publish exit $prc, check exit $rc):"; tail -n 4 "$T/copy.out"; fi
cp "$T/site-moved/directory.json" "$T/directory.kept"; tamper "$T/site-moved/directory.json"
copy site-moved check; rc=$?
cp "$T/directory.kept" "$T/site-moved/directory.json"
if [ "$rc" = 1 ] && grep -q "DRIFT — .*directory.json differs from what" "$T/copy.out"; then
  ok "B1 the pinned copy's directory tampered with: refused, as it always was"
else fail "B1 a tampered directory in the pinned copy was not refused (exit $rc):"; tail -n 4 "$T/copy.out"; fi
if drills moved "B1"; then
  ok "B1 stage-smoke, genesis-verify, demo-walkthrough and three-clients against the pinned network: all pass, at its April instant"
fi
# The move begun in the wrong order: a run that keeps real time while the registrars are still pinned (the folder's
# file changed, or the variable set, before they were restarted). It must sign nothing and publish nothing.
rsum="$(sum "$PUB/registry.json")"; dsum="$(sum "$PUB/directory.json")"; esum="$(sum "$PUB/epochs.json")"
net moved wall publish > "$T/moved-early-publish.log" 2>&1; prc=$?
AINRA_STAGE_RESIGN=1 net moved wall accredit > "$T/moved-early-accredit.log" 2>&1; arc=$?
if [ "$prc" != 0 ] && grep -q "registrar-07 still runs on the pinned clock and this publish keeps real time" "$T/moved-early-publish.log" \
   && [ "$arc" != 0 ] && grep -q "registrar-07 still runs on the pinned clock and this signing keeps real time" "$T/moved-early-accredit.log" \
   && [ "$(sum "$PUB/registry.json")" = "$rsum" ] && [ "$(sum "$PUB/directory.json")" = "$dsum" ] && [ "$(sum "$PUB/epochs.json")" = "$esum" ]; then
  ok "B1 a publish and a signing that keep real time, over registrars not yet restarted, are each refused by name; record, directory and history unchanged"
else fail "B1 a wall-clock run was let loose on registrars that are still pinned (publish exit $prc, accredit exit $arc):"; tail -n 2 "$T/moved-early-publish.log" "$T/moved-early-accredit.log"; fi

net moved own down >/dev/null 2>&1
free_ports
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
else fail "B2 the registrars did not restart on the wall clock over their pinned state:"; tail -n 4 "$T/moved/registrar-07.wall.log" "$T/moved/registrar-11.wall.log"; fi
# The moment a watchdog could meet: registrars already on the real clock, the folder not yet saying so, the directory
# still dated April.
rsum="$(sum "$PUB/registry.json")"
net moved own publish > "$T/moved-pinned-publish.log" 2>&1; prc=$?
if [ "$prc" != 0 ] && grep -q "keeps real time and this publish is pinned" "$T/moved-pinned-publish.log" && [ "$(sum "$PUB/registry.json")" = "$rsum" ]; then
  ok "B2 a pinned publish over them is refused by name, and the published record is left as it was"
else fail "B2 a pinned publish ran over registrars that keep real time (exit $prc):"; tail -n 2 "$T/moved-pinned-publish.log"; fi

roots="$(sum "$PUB/roots.json")"
net moved wall accredit > "$T/moved-accredit.log" 2>&1; arc=$?
ctl="$(./target/release/ainra ctl status --net "$PUB" --roots "$PUB/roots.json" --state "$T/moved-ctl.json" 2>&1)"; rc=$?
if [ "$arc" = 0 ] && grep -q "accredited at epoch 1 " "$T/moved-accredit.log" && [ "$rc" = 1 ] && echo "$ctl" | grep -q "ALARM  stale directory"; then
  ok "B3 accredited with nothing changed: still epoch 1, still dated April — restarting the registrars does not cure the directory"
else fail "B3 expected the unchanged epoch 1 and the stale alarm (accredit exit $arc, ctl exit $rc):"; tail -n 3 "$T/moved-accredit.log"; echo "$ctl" | tail -5; fi
# The move itself: the folder now says so. From here nothing names a clock.
echo wall > "$T/moved/CLOCK"
rsum="$(sum "$PUB/registry.json")"
net moved pinned publish > "$T/moved-disagree.log" 2>&1; prc=$?
e_moved="$(envs "$T/moved")"
if [ "$prc" = 2 ] && grep -q "AINRA_STAGE_CLOCK=pinned, and this network's own folder says wall" "$T/moved-disagree.log" && [ "$(sum "$PUB/registry.json")" = "$rsum" ] \
   && [ "$(count '^AINRA_CLOCK=wall$' "$e_moved")" = 4 ] && [ "$(count 'AINRA_CLOCK=pinned' "$e_moved")" = 0 ]; then
  ok "B3 the folder now says wall: a run that still names the pinned clock is refused by name, and an install over it would write AINRA_CLOCK=wall, not re-pin the registrars"
else fail "B3 the moved network's folder is not followed (pinned run exit $prc, installer wall $(count '^AINRA_CLOCK=wall$' "$e_moved")/4):"; tail -n 2 "$T/moved-disagree.log"; fi
AINRA_STAGE_RESIGN=1 net moved own accredit > "$T/moved-resign.log" 2>&1
read -r epoch at <<< "$(signed_at "$PUB/directory.json")"
ctl="$(./target/release/ainra ctl status --net "$PUB" --roots "$PUB/roots.json" --state "$T/moved-ctl.json" --fresh-max 600 2>&1)"; rc=$?
if [ "${epoch:-0}" = 2 ] && [ $(( $(date +%s) - ${at:-0} )) -lt 900 ] && [ "$(sum "$PUB/roots.json")" = "$roots" ] && [ "$rc" = 0 ] \
   && echo "$ctl" | grep -q "epoch history: 2 epoch(s)" && echo "$ctl" | grep -q "^CTL OK" && ! echo "$ctl" | grep -q "ALARM" \
   && [ "$(field "$PUB/index.json" clock)" = wall ]; then
  ok "B4 signed again by the same root, no variable but AINRA_STAGE_RESIGN: epoch 2 dated today, the record now states the wall clock; ctl, remembering the pinned look, has no alarm at the real clock"
else fail "B4 the moved network is not clean at the real clock (epoch ${epoch:-?}, ctl exit $rc, record clock $(field "$PUB/index.json" clock)):"; tail -n 3 "$T/moved-resign.log"; echo "$ctl" | tail -8; fi
# The artifact server went down with the pinned network; what reads a record over HTTP needs one over the moved record.
AINRA_STAGE=1 node tools/artifact-server.mjs "$PUB" 9097 > "$T/moved/artifact.wall.log" 2>&1 & pids+=($!)
for _ in $(seq 1 40); do curl -s -m 1 -o /dev/null "$ART/index.json" && break; sleep 0.25; done
watch "$ART" moved-watch; rc=$?
copy site-moved check; crc=$?
if [ "$rc" = 0 ] && grep -q "the record states real time; read at this machine's clock" "$T/watch.out" && grep -q "^HOME WATCH OK" "$T/watch.out" \
   && [ "$crc" = 1 ] && grep -q "the copy was taken when the network was pinned, and the network now keeps real time" "$T/copy.out"; then
  ok "B4 the same home watch, its settings untouched, follows the move (real time now, no alarm); the copy taken while pinned is refused by name until the site publishes again"
else fail "B4 the surroundings did not follow the move (watch exit $rc, copy check exit $crc):"; tail -n 6 "$T/watch.out"; tail -n 4 "$T/copy.out"; fi

v="$(sdk "$PUB" "$R1" "$april")"; rc=$?
v2="$(sdk "$PUB" "$R1" "$april_gone")"; rc2=$?
if [ "$rc" = 0 ] && [ "$v" = "ainra-verify: VALID" ] && [ "$rc2" = 1 ] && [ "$v2" = "ainra-verify: INVALID (revoked)" ]; then
  ok "B5 passports issued in the pinned world, presented now, at the real clock: invoicing VALID, data-export revoked"
else fail "B5 the pinned world's passports do not carry over: invoicing → $v (exit $rc), data-export → $v2 (exit $rc2)"; fi
read -r nv nr no nd vat <<< "$(record "$PUB")"
if [ "${no:-1}" = 0 ] && [ "${nd:-1}" = 0 ] && [ "${nv:-0}" -ge 1 ] && [ "${nr:-0}" -ge 1 ] && [ $(( $(date +%s) - ${vat:-0} )) -lt 900 ]; then
  ok "B5 the whole published record through the SDK at the real time: $nv valid, $nr revoked, none otherwise"
else fail "B5 the moved network's published record does not read as its registrars say: ${nv:-?} valid, ${nr:-?} revoked, ${no:-?} otherwise, ${nd:-?} disagreeing"; cat "$T/record.err"; fi

# Nothing above may have reached the site's own copy of the record.
if [ -n "$(find site/net -newer "$T/started" 2>/dev/null | head -1)" ]; then fail "site/net/ was written to during this drill"; fi

took=$(( $(date +%s) - started ))
if [ $bad = 0 ]; then
  echo "STAGE WALLCLOCK DRILL OK: born on the wall clock and moved to it, no alarm at the real clock, valid and revoked read right, stale 100 days ahead, the pinned default unchanged (${took}s)"
else echo "STAGE WALLCLOCK DRILL FAILED (${took}s)"; fi
exit $bad
