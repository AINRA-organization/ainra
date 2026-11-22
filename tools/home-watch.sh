#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# tools/home-watch.sh — one round of watching the network from a home node (D-117). Run by ainra-home-watch.timer.
#
# Reads only. It checks the published record the way a stranger would (`ainra ctl status`: the directory verifies
# under the pinned roots, the epoch history is whole, nothing went stale) and every registrar's log the way a monitor
# would (`ainra monitor`, D-116: each new head consistent with the last one seen, the entries rebuild the signed root,
# no passport in a watched operator's name that is not on its list). It can sign nothing and write to no registrar.
#
# On an alarm it writes the report to the journal and to $STATE/alarm.txt, and runs AINRA_HOME_ALERT (a command of the
# operator's choosing; the report on its standard input) once per distinct alarm, not every round. When the alarm
# clears it says so once. Exit: 0 all well, 3 an alarm, 2 could not check.
#
# Configuration, from the environment (the unit reads ~/.config/ainra-home/home.env):
#   AINRA_HOME_NET         the published record: a URL or a directory      (default http://127.0.0.1:8091)
#   AINRA_HOME_ROOTS       the pinned roots.json, copied once out of band   (required: a watcher that trusts what it
#                                                                             is served would watch nothing)
#   AINRA_HOME_REGISTRARS  registrar URLs, space separated                  (default the two test registrars)
#   AINRA_HOME_WATCH       operators whose passports must all be expected  (optional, space separated)
#   AINRA_HOME_EXPECT      a file of the passports those operators asked for (required with AINRA_HOME_WATCH)
#   AINRA_HOME_NOW         leave empty: the watch reads the network at the clock the network states (below). Set, it
#                          is the instant used for a record that states the pinned clock, and for nothing else
#   AINRA_HOME_STATE       where the watcher remembers what it saw         (default ~/.local/state/ainra-home)
#   AINRA_HOME_ALERT       a command run on a new alarm or its clearing    (optional; e.g. a mail or push command)
#
# THE CLOCK is the network's own, read from the record it publishes (index.json, tools/net-clock.mjs), every round:
#   "clock": "wall"   the registrars keep real time, so the watch reads at this machine's clock and names no time
#   no such field     the pinned clock: the watch reads at the record's own fixed instant (its verified_at)
# So the watch cannot be on one clock while the registrars are on the other, and a network that moves to real time
# is followed without anyone editing this machine's settings. The statement is not signed, which matters in one
# direction only: a record that keeps real time and claimed to be pinned would be read at an instant of its own
# choosing and never go stale. So the watch remembers that a network stated the wall clock ($STATE/clock), and a
# later record of that network stating the pinned one is an alarm, read at the real clock.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

BIN="${AINRA_BIN:-./target/release/ainra}"
NET="${AINRA_HOME_NET:-http://127.0.0.1:8091}"
ROOTS="${AINRA_HOME_ROOTS:-}"
REGS="${AINRA_HOME_REGISTRARS:-http://127.0.0.1:4907 http://127.0.0.1:4911}"
STATE="${AINRA_HOME_STATE:-$HOME/.local/state/ainra-home}"
mkdir -p "$STATE"; chmod 700 "$STATE"

[ -x "$BIN" ] || { echo "home-watch: $BIN is not built (cargo build --release -p ainra-cli-rs --bin ainra)"; exit 2; }
[ -s "$ROOTS" ] || { echo "home-watch: AINRA_HOME_ROOTS must name the pinned roots.json (copied once, out of band)"; exit 2; }
if [ -n "${AINRA_HOME_WATCH:-}" ] && [ ! -s "${AINRA_HOME_EXPECT:-}" ]; then
  echo "home-watch: AINRA_HOME_WATCH is set, so AINRA_HOME_EXPECT must name the list of expected passports"; exit 2
fi

report="$STATE/round.txt"; : > "$report"
worst=0
note(){ # note CODE — keep the worst outcome: an alarm (3) outranks could-not-check (2), which outranks well (0)
  if [ "$1" = 3 ]; then worst=3; elif [ "$1" != 0 ] && [ "$worst" = 0 ]; then worst=2; fi
}

# The clock this round reads at (see THE CLOCK above). A record that cannot be read states nothing: the checks below
# then report that they could not check, at the instant this machine was given, if any.
stated="$(node tools/net-clock.mjs "$NET" 2>/dev/null)" || stated=""
seen="$(cat "$STATE/clock" 2>/dev/null)"
nowarg=(); [ "$seen" != wall ] && [ -n "${AINRA_HOME_NOW:-}" ] && nowarg=(--now "$AINRA_HOME_NOW")
case "$stated" in
  wall)
    nowarg=(); echo wall > "$STATE/clock"
    echo "== the clock: the record states real time; read at this machine's clock" >> "$report"
    [ -n "${AINRA_HOME_NOW:-}" ] && echo "   (AINRA_HOME_NOW is set and not used: it is for a record that states the pinned clock)" >> "$report"
    ;;
  pinned*)
    if [ "$seen" = wall ]; then
      echo "== the clock: ALARM  this network stated real time before and its record now states the pinned clock; read at this machine's clock" >> "$report"
      note 3
    elif [ -z "${AINRA_HOME_NOW:-}" ]; then
      at="${stated#pinned}"; at="${at# }"
      if [ -n "$at" ]; then nowarg=(--now "$at"); echo "== the clock: the record states the pinned clock; read at its instant $at" >> "$report"; fi
    fi   # with AINRA_HOME_NOW set, a pinned record is read at that instant, as this watch always did
    ;;
esac

echo "== the published record: $NET" >> "$report"
"$BIN" ctl status --net "$NET" --roots "$ROOTS" --state "$STATE/ctl-seen.json" "${nowarg[@]}" >> "$report" 2>&1
c=$?; [ "$c" = 0 ] || { [ "$c" = 1 ] && c=3; }; note "$c"

for reg in $REGS; do
  name="$(printf '%s' "$reg" | tr -c 'A-Za-z0-9' '_')"
  watch=(); for op in ${AINRA_HOME_WATCH:-}; do watch+=(--watch "$op"); done
  [ ${#watch[@]} -gt 0 ] && watch+=(--expect "$AINRA_HOME_EXPECT")
  echo "== registrar log: $reg" >> "$report"
  "$BIN" monitor --registrar "$reg" --net "$NET" --roots "$ROOTS" --state "$STATE/monitor-$name.json" \
    "${watch[@]}" "${nowarg[@]}" >> "$report" 2>&1
  note "$?"
done

cat "$report"
stamp="$(date -u +%FT%TZ)"
alarm_text(){ grep -E 'ALARM|FORK|ROLLBACK|UNEXPECTED|do not rebuild|could not|refused|✗' "$report" | sort -u; }
alert(){ [ -n "${AINRA_HOME_ALERT:-}" ] && { printf '%s\n' "$1"; cat "$report"; } | bash -c "$AINRA_HOME_ALERT" || true; }
if [ "$worst" = 0 ]; then
  if [ -f "$STATE/alarm.txt" ]; then
    rm -f "$STATE/alarm.txt" "$STATE/alarm.sum"
    echo "home-watch: the alarm has cleared ($stamp)"
    alert "AINRA home watch: the alarm has cleared ($stamp)"
  fi
  echo "HOME WATCH OK ($stamp)"
  exit 0
fi
sum="$(alarm_text | sha256sum | cut -c1-16)"
if [ "$(cat "$STATE/alarm.sum" 2>/dev/null)" != "$sum" ]; then
  { echo "$stamp"; alarm_text; } > "$STATE/alarm.txt"; echo "$sum" > "$STATE/alarm.sum"
  alert "AINRA home watch: $( [ "$worst" = 3 ] && echo ALARM || echo 'could not check' ) ($stamp)"
  echo "home-watch: a new alarm — alert sent${AINRA_HOME_ALERT:+ via AINRA_HOME_ALERT}"
else
  echo "home-watch: the same alarm as last round — not alerting again"
fi
[ "$worst" = 3 ] && echo "HOME WATCH ALARM ($stamp)" || echo "HOME WATCH COULD NOT CHECK ($stamp)"
exit "$worst"
