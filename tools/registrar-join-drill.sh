#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# make registrar-join-drill — a registrar the network does not run joins it (D-120), on a whole throwaway network.
#
# Beside the real network and touching none of it: its own folder, its own root (made for the drill), and spare
# addresses (5907, 5911, 5991, 9091; the outside registrar on 5922). In order:
#   1. the network comes up with its two registrars and signs its first directory
#   2. an outside registrar starts on its own, with its own keys, and issues a passport
#   3. listed with a WRONG fingerprint: refused, and the signed directory is unchanged
#   4. listed with its own fingerprint: signed into the directory at the next epoch; `ainra ctl` reads three registrars
#      and `ainra monitor` checks the outside registrar's log under the key the root's directory gives it
#   5. the outside registrar stops: publishing goes on, and its last published copy is kept
#
# WITNESS: step 3 is the negative control (a wrong fingerprint must be refused with the directory unchanged); step 4
# the positive one. If step 3 passes quietly, or step 4 is refused, the drill fails.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
T="$(mktemp -d -p "${XDG_CACHE_HOME:-$HOME/.cache}" ainra-join-drill-XXXXXX)"
export AINRA_STAGE_DIR="$T/stage" AINRA_STAGE_REG1=127.0.0.1:5907 AINRA_STAGE_REG2=127.0.0.1:5911 \
       AINRA_STAGE_WIT=127.0.0.1:5991 AINRA_STAGE_ART=9091
OUT=127.0.0.1:5922
NOW=1776729600
bad=0; ok(){ echo "  ok    $1"; }; fail(){ echo "  ✗     $1"; bad=1; }
opid=""
cleanup(){
  [ -n "$opid" ] && kill "$opid" 2>/dev/null
  bash tools/stage.sh down >/dev/null 2>&1
  rm -rf "$T"
}
trap cleanup EXIT
for p in 5907 5911 5991 9091 5922; do
  curl -s -m 1 -o /dev/null "http://127.0.0.1:$p/" && { echo "registrar-join-drill: something already answers on :$p — not starting"; exit 2; }
done
dirsum(){ sha256sum "$AINRA_STAGE_DIR/public/directory.json" 2>/dev/null | cut -c1-64; }

echo "1 · a throwaway network, its own root"
bash tools/stage.sh up > "$T/up.log" 2>&1
if [ -s "$AINRA_STAGE_DIR/public/directory.json" ] && [ -s "$AINRA_STAGE_DIR/public/roots.json" ]; then
  ok "up: two registrars, a signed directory, its own root ($(grep -o 'the directory is epoch [0-9]*' "$T/up.log"))"
else fail "the throwaway network did not come up:"; tail -15 "$T/up.log"; exit 1; fi

echo "2 · a registrar the network does not run"
mkdir -p "$T/reg22"
AINRA_STAGE=1 AINRA_CLOCK=pinned AINRA_FRESH_KEYS=1 AINRA_STAGE_ISSUE_TOKEN="$(cat "$AINRA_STAGE_DIR/.issue-token")" \
  ./target/release/registrar-box "$OUT" registrar-22 "$T/reg22/data" > "$T/reg22/log" 2>&1 & opid=$!
for _ in $(seq 1 40); do curl -s -m 1 -o /dev/null "http://$OUT/accreditation" && break; sleep 0.25; done
sub="$(curl -s -m 10 -H 'Content-Type: application/json' -H "Authorization: Bearer $(cat "$AINRA_STAGE_DIR/.issue-token")" \
  -d '{"operator":"outside-op","lineage":"courier","version":"1.0.0","tier":"L1","auth_class":"A2","principal_proof":"deadbeefjoin","capabilities":["read:x"],"scope_ceiling":["read:x"],"hops":[]}' \
  "http://$OUT/issue" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{process.stdout.write(JSON.parse(s).sub||"")}catch{}})')"
[ -n "$sub" ] && ok "registrar-22 issued $sub, with keys of its own" || fail "registrar-22 did not issue"
fp="$(node tools/registrar-fingerprint.mjs "http://$OUT")"
[ -n "$fp" ] && ok "its operator's fingerprint: ${fp#* }" || { fail "no fingerprint"; exit 1; }

echo "2b · its formal request: proof of possession of every key, the prerequisites named (the production path)"
for f in agreement independence monitor audit; do echo "drill placeholder: $f" > "$T/reg22/$f.txt"; done
node -e 'const fs=require("fs"),c=require("crypto"),d=process.argv[1];const a=(f,date)=>Object.assign({file:f,sha256:c.createHash("sha256").update(fs.readFileSync(d+"/"+f)).digest("hex")},date?{date}:{});
  fs.writeFileSync(d+"/evidence.json",JSON.stringify({prerequisites:{agreement:a("agreement.txt"),independence_attestation:a("independence.txt"),competitor_monitor:a("monitor.txt"),audit:a("audit.txt","2026-11-18")}}))' "$T/reg22"
curl -s -m 10 "http://$OUT/accreditation" > "$T/reg22/accreditation.json"
if ./target/release/ainra directory request ACCREDIT --registrar "$T/reg22/data" --filed-at "$NOW" --test-root \
     --evidence "$T/reg22/evidence.json" --out "$T/reg22/request.json" > "$T/req.log" 2>&1 \
   && ./target/release/ainra directory check-request "$T/reg22/request.json" --directory "$AINRA_STAGE_DIR/public/directory.json" \
     --roots "$AINRA_STAGE_DIR/public/roots.json" --accreditation "$T/reg22/accreditation.json" > "$T/check.log" 2>&1; then
  ok "ainra directory request + check-request: the request is signed by its keys and matches what it serves"
else fail "the formal request was not accepted:"; tail -6 "$T/req.log" "$T/check.log"; fi

echo "3 · listed with a wrong fingerprint"
before="$(dirsum)"
printf '[{"id":"registrar-22","url":"http://%s","fingerprint":"sha256:%s"}]\n' "$OUT" "$(printf '0%.0s' $(seq 1 64))" \
  > "$AINRA_STAGE_DIR/genesis/outside-registrars.json"
if bash tools/stage.sh accredit > "$T/acc-wrong.log" 2>&1; then fail "accredited under a wrong fingerprint"
elif grep -q "not the one registrar-22's operator fingerprinted" "$T/acc-wrong.log" && [ "$(dirsum)" = "$before" ]; then
  ok "refused by name, and the signed directory is unchanged"
else fail "refused, but not for the fingerprint, or the directory changed:"; tail -5 "$T/acc-wrong.log"; fi

echo "4 · listed with its own fingerprint"
printf '[{"id":"registrar-22","url":"http://%s","fingerprint":"%s"}]\n' "$OUT" "${fp#* }" > "$AINRA_STAGE_DIR/genesis/outside-registrars.json"
if bash tools/stage.sh accredit > "$T/acc-right.log" 2>&1; then
  ok "accredited: $(tail -1 "$T/acc-right.log")"
else fail "refused with the right fingerprint:"; tail -8 "$T/acc-right.log"; fi
ctl="$(./target/release/ainra ctl status --net "$AINRA_STAGE_DIR/public" --roots "$AINRA_STAGE_DIR/public/roots.json" \
  --state "$T/ctl.json" --now "$NOW" 2>&1)"
echo "$ctl" | grep -q "3 registrar(s)" && echo "$ctl" | grep -q "^CTL OK" \
  && ok "ainra ctl: the directory verifies under the root and names three registrars" \
  || { fail "ainra ctl does not read three registrars under the root:"; echo "$ctl" | tail -6; }
mon="$(./target/release/ainra monitor --registrar "http://$OUT" --net "$AINRA_STAGE_DIR/public" \
  --roots "$AINRA_STAGE_DIR/public/roots.json" --state "$T/mon.json" --now "$NOW" 2>&1)"
echo "$mon" | grep -q "^MONITOR OK" \
  && ok "ainra monitor: registrar-22's log checks out under the key the root's directory gives it" \
  || { fail "the monitor cannot check registrar-22 under the directory:"; echo "$mon" | tail -6; }
grep -q '"registrar-22"' "$AINRA_STAGE_DIR/public/registry.json" && ok "the published record carries registrar-22's passports" \
  || fail "registry.json has no registrar-22"

echo "5 · the outside registrar stops"
kill "$opid" 2>/dev/null; wait "$opid" 2>/dev/null; opid=""
if bash tools/stage.sh publish > "$T/pub-down.log" 2>&1 && grep -q "last published copy is kept" "$T/pub-down.log" \
   && grep -q '"registrar-22"' "$AINRA_STAGE_DIR/public/registry.json"; then
  ok "publishing goes on; registrar-22's last published copy is kept"
else fail "publishing stopped, or lost registrar-22:"; tail -5 "$T/pub-down.log"; fi

[ $bad = 0 ] && echo "REGISTRAR JOIN DRILL OK: a wrong fingerprint refused, the right one signed in and checked under the root, an outage survived" \
             || echo "REGISTRAR JOIN DRILL FAILED"
exit $bad
