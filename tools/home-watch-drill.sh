#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# make home-watch-drill — the home node's watcher (D-117) against the running test network (`make stage-up` or the
# installed units). WITNESS: round 1 is the positive control (exit 0, no alert). Round 2 plants a fork in what the
# watcher remembers: it must alarm and alert once; round 3 must not alert again; round 4 must say the alarm cleared.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
curl -s -m 3 -o /dev/null http://127.0.0.1:8091/roots.json || { echo "home-watch-drill: no test network on :8091 — make stage-up first"; exit 2; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
curl -s -m 5 http://127.0.0.1:8091/roots.json > "$T/pinned-roots.json"
export AINRA_HOME_ROOTS="$T/pinned-roots.json" AINRA_HOME_NOW=1776729600 AINRA_HOME_STATE="$T/state" AINRA_HOME_ALERT="cat >> $T/alerts.txt"
bad=0; ok(){ echo "  ok    $1"; }; fail(){ echo "  ✗     $1"; bad=1; }
alerts(){ grep -c '^AINRA home watch' "$T/alerts.txt" 2>/dev/null || echo 0; }

echo "1 · a network that is as it says"
bash tools/home-watch.sh > "$T/out" 2>&1; c=$?
[ $c = 0 ] && [ "$(alerts)" = 0 ] && ok "exit 0, no alert" || { fail "expected exit 0 and no alert: exit $c"; tail -20 "$T/out"; }

echo "2 · a fork planted in what the watcher saw last"
f="$(ls "$T"/state/monitor-*4907*.json)"; cp "$f" "$T/good.json"
node -e 'const fs=require("fs"),p=process.argv[1],j=JSON.parse(fs.readFileSync(p));j.root=Buffer.alloc(32,7).toString("base64url");fs.writeFileSync(p,JSON.stringify(j))' "$f"
bash tools/home-watch.sh > "$T/out" 2>&1; c=$?
[ $c = 3 ] && [ "$(alerts)" = 1 ] && grep -q "FORK" "$T/alerts.txt" && ok "exit 3, one alert naming the FORK" || fail "expected exit 3 and one FORK alert: exit $c, $(alerts) alert(s)"

echo "3 · the same alarm, the next round"
bash tools/home-watch.sh > "$T/out" 2>&1; c=$?
[ $c = 3 ] && [ "$(alerts)" = 1 ] && ok "still exit 3, not alerted again" || fail "expected exit 3 and no second alert: exit $c, $(alerts) alert(s)"

echo "4 · the watcher's memory put right"
cp "$T/good.json" "$f"
bash tools/home-watch.sh > "$T/out" 2>&1; c=$?
[ $c = 0 ] && [ "$(alerts)" = 2 ] && grep -q "has cleared" "$T/alerts.txt" && ok "exit 0, one 'cleared' message" || fail "expected exit 0 and a cleared message: exit $c"

[ $bad = 0 ] && echo "HOME WATCH DRILL OK: a fork alarmed once, was not repeated, and its clearing was reported" || echo "HOME WATCH DRILL FAILED"
exit $bad
