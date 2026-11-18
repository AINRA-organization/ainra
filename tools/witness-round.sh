#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# tools/witness-round.sh — one round of having outside witnesses cosign each registrar's log (D-121), run by
# ainra-home-witness.timer on a home node. Does nothing until witnesses are configured.
#
# For every registrar and every witness: submit the registrar's checkpoint with `ainra witness-submit`, but only when
# the log has grown since that witness last cosigned it, or once a day otherwise. That is the rate a log promises a
# witness network (at most one add-checkpoint per log per hour, and far fewer when nothing changes).
#
# Configuration, from the environment (the unit reads ~/.config/ainra-home/home.env):
#   AINRA_HOME_REGISTRARS   registrar URLs, space separated            (default the two test registrars)
#   AINRA_HOME_WITNESSES    one witness per line: "<submission URL> <cosigning vkey>"; empty = nothing to do
#   AINRA_HOME_STATE        where each (registrar, witness) record is kept   (default ~/.local/state/ainra-home)
#   AINRA_WITNESS_EVERY     seconds between submissions of an unchanged log (default 86400)
# Exit: 0 every submission cosigned or skipped, 3 a witness refused (403/422: may be an alarm), 2 could not run.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
BIN="${AINRA_BIN:-./target/release/ainra}"
REGS="${AINRA_HOME_REGISTRARS:-http://127.0.0.1:4907 http://127.0.0.1:4911}"
STATE="${AINRA_HOME_STATE:-$HOME/.local/state/ainra-home}"
EVERY="${AINRA_WITNESS_EVERY:-86400}"
mkdir -p "$STATE"; chmod 700 "$STATE"
if [ -z "${AINRA_HOME_WITNESSES:-}" ]; then echo "witness-round: no witnesses configured (AINRA_HOME_WITNESSES) — nothing to do"; exit 0; fi
[ -x "$BIN" ] || { echo "witness-round: $BIN is not built"; exit 2; }
now="$(date +%s)"; worst=0
while read -r wurl wvkey; do
  [ -n "$wurl" ] || continue
  for reg in $REGS; do
    key="$(printf '%s %s' "$reg" "$wurl" | sha256sum | cut -c1-16)"
    st="$STATE/witness-$key.json"
    size="$(curl -fsS -m 10 "$reg/checkpoint" 2>/dev/null | sed -n 2p)"
    [ -n "$size" ] || { echo "witness-round: $reg did not serve its checkpoint"; [ "$worst" = 0 ] && worst=2; continue; }
    last_size="$(node -e 'try{process.stdout.write(String(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).size))}catch{}' "$st" 2>/dev/null)"
    last_at="$(stat -c %Y "$st" 2>/dev/null || echo 0)"
    if [ "$size" = "$last_size" ] && [ $((now - last_at)) -lt "$EVERY" ]; then
      echo "witness-round: $reg at $size, unchanged since $wurl cosigned it — skipped"; continue
    fi
    "$BIN" witness-submit --registrar "$reg" --witness "$wurl" --witness-vkey "$wvkey" --state "$st"; c=$?
    if [ $c = 3 ]; then worst=3; elif [ $c != 0 ] && [ "$worst" = 0 ]; then worst=2; fi
  done
done <<< "$AINRA_HOME_WITNESSES"
exit "$worst"
