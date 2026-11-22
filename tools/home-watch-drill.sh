#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# make home-watch-drill — the home node's watcher (D-117), on throwaway networks: one on the pinned clock, one that
# keeps real time. It never touches the standing network (until 22 November 2026 it ran against it, on :8091).
#
# Beside the real network and touching none of it: its own folder under the cache directory, a root seed made for each
# network, and spare addresses (5967, 5971, 5985, 9099). On each network the watcher is given no clock at all
# (AINRA_HOME_NOW is unset): it must take the network's own from the record (tools/net-clock.mjs).
#
# WITNESS, per network: round 1 is the positive control (exit 0, no alert, and the round says which clock it read at).
# Round 2 plants a fork in what the watcher remembers: it must alarm and alert once; round 3 must not alert again;
# round 4 must say the alarm cleared. Then the clock itself:
#   pinned     the same record read at this machine's clock alarms (so round 1 passing shows the instant was used).
#   real time  a fixed instant left in the watcher's settings (AINRA_HOME_NOW) is not used, shown with one that would
#              alarm if it were; and a copy of the record with its statement removed, shown to the watcher that saw the
#              statement, is an alarm.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
unset AINRA_STAGE_CLOCK AINRA_STAGE_RESIGN AINRA_STAGE_NEW_ROOT AINRA_STAGE_TAKE_BACK AINRA_CLOCK \
      AINRA_HOME_NOW AINRA_HOME_NET AINRA_HOME_REGISTRARS AINRA_HOME_WATCH AINRA_HOME_EXPECT
R1=127.0.0.1:5967 ; R2=127.0.0.1:5971 ; ART=9099
PORTS=(5967 5971 5985 9099)
taken(){ (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
for p in "${PORTS[@]}"; do
  taken "$p" && { echo "home-watch-drill: something already listens on :$p — not starting"; exit 2; }
done
T="$(mktemp -d -p "${XDG_CACHE_HOME:-$HOME/.cache}" ainra-home-watch-drill-XXXXXX)" || exit 2
export AINRA_STAGE_REG1="$R1" AINRA_STAGE_REG2="$R2" AINRA_STAGE_WIT=127.0.0.1:5985 AINRA_STAGE_ART="$ART"
# net <pinned|wall> <stage.sh arguments…> — every call names its own folder and its own root seed; the clock is the
# folder's own (a CLOCK file for the network that keeps real time), never a variable.
net(){ local name="$1"; shift; AINRA_STAGE_DIR="$T/$name" AINRA_STAGE_ROOT_SEED="$T/$name-root.seed" bash tools/stage.sh "$@"; }
# shellcheck disable=SC2329  # run by the EXIT trap
cleanup(){ net pinned down >/dev/null 2>&1; net wall down >/dev/null 2>&1; rm -rf "$T"; }
trap cleanup EXIT
bad=0; ok(){ echo "  ok    $1"; }; fail(){ echo "  ✗     $1"; bad=1; }

for clock in pinned wall; do
  if [ "$clock" = wall ]; then echo "B · a network that keeps real time"; mkdir -p "$T/wall"; echo wall > "$T/wall/CLOCK"
  else echo "A · a network on the pinned clock"; fi
  for _ in $(seq 1 40); do busy=0; for p in "${PORTS[@]}"; do taken "$p" && busy=1; done; [ "$busy" = 0 ] && break; sleep 0.25; done
  net "$clock" up > "$T/$clock-up.log" 2>&1
  PUB="$T/$clock/public"
  [ -s "$PUB/roots.json" ] && [ -s "$PUB/index.json" ] || { fail "the $clock network did not come up:"; tail -12 "$T/$clock-up.log"; echo "HOME WATCH DRILL FAILED"; exit 1; }
  cp "$PUB/roots.json" "$T/$clock-pinned-roots.json"
  export AINRA_HOME_NET="http://127.0.0.1:$ART" AINRA_HOME_REGISTRARS="http://$R1 http://$R2" \
         AINRA_HOME_ROOTS="$T/$clock-pinned-roots.json" AINRA_HOME_STATE="$T/$clock-state" AINRA_HOME_ALERT="cat >> $T/$clock-alerts.txt"
  alerts(){ grep -c '^AINRA home watch' "$T/$clock-alerts.txt" 2>/dev/null || echo 0; }
  said="the record states the pinned clock; read at its instant 1776729600"
  [ "$clock" = wall ] && said="the record states real time; read at this machine's clock"

  echo "1 · a network that is as it says, and a watcher told no clock"
  bash tools/home-watch.sh > "$T/out" 2>&1; c=$?
  if [ $c = 0 ] && [ "$(alerts)" = 0 ] && grep -q "$said" "$T/out"; then ok "exit 0, no alert; $said"
  else fail "expected exit 0, no alert and '$said': exit $c"; tail -20 "$T/out"; fi

  echo "2 · a fork planted in what the watcher saw last"
  f="$(find "$T/$clock-state" -name 'monitor-*5967*.json' | head -1)"; cp "$f" "$T/good.json"
  node -e 'const fs=require("fs"),p=process.argv[1],j=JSON.parse(fs.readFileSync(p));j.root=Buffer.alloc(32,7).toString("base64url");fs.writeFileSync(p,JSON.stringify(j))' "$f"
  bash tools/home-watch.sh > "$T/out" 2>&1; c=$?
  if [ $c = 3 ] && [ "$(alerts)" = 1 ] && grep -q "FORK" "$T/$clock-alerts.txt"; then ok "exit 3, one alert naming the FORK"
  else fail "expected exit 3 and one FORK alert: exit $c, $(alerts) alert(s)"; fi

  echo "3 · the same alarm, the next round"
  bash tools/home-watch.sh > "$T/out" 2>&1; c=$?
  if [ $c = 3 ] && [ "$(alerts)" = 1 ]; then ok "still exit 3, not alerted again"
  else fail "expected exit 3 and no second alert: exit $c, $(alerts) alert(s)"; fi

  echo "4 · the watcher's memory put right"
  cp "$T/good.json" "$f"
  bash tools/home-watch.sh > "$T/out" 2>&1; c=$?
  if [ $c = 0 ] && [ "$(alerts)" = 2 ] && grep -q "has cleared" "$T/$clock-alerts.txt"; then ok "exit 0, one 'cleared' message"
  else fail "expected exit 0 and a cleared message: exit $c"; fi

  echo "5 · the clock"
  if [ "$clock" = pinned ]; then
    ctl="$(./target/release/ainra ctl status --net "$AINRA_HOME_NET" --roots "$AINRA_HOME_ROOTS" --state "$T/pinned-ctl.json" 2>&1)"; c=$?
    if [ $c = 1 ] && echo "$ctl" | grep -q "ALARM  stale directory"; then ok "WITNESS: the same record read at this machine's clock alarms (stale directory), so round 1 read at the record's instant"
    else fail "the pinned record did not alarm at the real clock (exit $c): round 1 proves nothing about the instant"; echo "$ctl" | tail -4; fi
  else
    # An instant 100 days ahead stands in for any fixed one: if the watcher used it, the directory would read as stale.
    # (The April instant itself would hide the opposite fault: read from the past, a directory never goes stale.)
    ahead=$(( $(date +%s) + 100*86400 ))
    AINRA_HOME_NOW="$ahead" bash tools/home-watch.sh > "$T/out" 2>&1; c=$?
    if [ $c = 0 ] && grep -q "AINRA_HOME_NOW is set and not used" "$T/out"; then ok "a fixed instant left in the watcher's settings (AINRA_HOME_NOW) is not used over this network: exit 0"
    else fail "a fixed instant steered a watch over a network that keeps real time: exit $c"; tail -12 "$T/out"; fi
    ctl="$(./target/release/ainra ctl status --net "$AINRA_HOME_NET" --roots "$AINRA_HOME_ROOTS" --state "$T/wall-ctl.json" --now "$ahead" 2>&1)"; c=$?
    if [ $c = 1 ] && echo "$ctl" | grep -q "ALARM  stale directory: issued 100 day(s) ago"; then ok "WITNESS: read at that instant by hand, the same record alarms (stale directory), so the watcher did not use it"
    else fail "the record passed at an instant 100 days ahead (exit $c), so the line above proves nothing"; echo "$ctl" | tail -4; fi
    cp -r "$PUB" "$T/wall-relabelled"
    node -e 'const fs=require("fs"),p=process.argv[1]+"/index.json",j=JSON.parse(fs.readFileSync(p,"utf8"));delete j.clock;fs.writeFileSync(p,JSON.stringify(j))' "$T/wall-relabelled"
    AINRA_HOME_NET="$T/wall-relabelled" bash tools/home-watch.sh > "$T/out" 2>&1; c=$?
    if [ $c = 3 ] && grep -q "ALARM  this network stated real time before and its record now states the pinned clock" "$T/out"; then ok "the record's statement removed, shown to the watcher that saw it: exit 3, the alarm names it"
    else fail "a record relabelled as pinned was accepted by a watcher that had seen it keep real time: exit $c"; tail -12 "$T/out"; fi
    bash tools/home-watch.sh > "$T/out" 2>&1; c=$?
    if [ $c = 0 ]; then ok "the true record again: exit 0"; else fail "the true record no longer passes: exit $c"; tail -12 "$T/out"; fi
  fi
  net "$clock" down >/dev/null 2>&1
done

if [ $bad = 0 ]; then echo "HOME WATCH DRILL OK: on both clocks a fork alarmed once, was not repeated, and its clearing was reported; the watcher took each network's own clock"
else echo "HOME WATCH DRILL FAILED"; fi
exit $bad
