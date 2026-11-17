#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# deploy/home-node/install.sh — make this machine the test network's home node (D-117). Run it ON the node, from a
# clone of the repository at the same commit as the machine the network comes from.
#
#   bash deploy/home-node/install.sh install        the network's units (tools/stage-install.sh) + the home watch
#   bash deploy/home-node/install.sh install --watch-only   the home watch alone, over a network that runs elsewhere
#   bash deploy/home-node/install.sh status         units, the last watch round, any standing alarm
#   bash deploy/home-node/install.sh uninstall      the home watch units (the network's: make stage-uninstall)
#
# The network's state arrives by deploy/home-node/move-to-node.sh, never by seeding a new one here: a node that seeded
# its own network would hold a fresh root seed, in plain bytes, on a machine that is always on. This script refuses
# to install the network without moved state, unless --fresh says that a separate, new test network is the intent.
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 2
REPO="$(pwd)"
UNIT_DST="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
CONF="${XDG_CONFIG_HOME:-$HOME/.config}/ainra-home"
cmd="${1:-install}"; shift || true
watch_only=0; fresh=0
for a in "$@"; do case "$a" in --watch-only) watch_only=1;; --fresh) fresh=1;; *) echo "unknown option $a"; exit 2;; esac; done

case "$cmd" in
install)
  command -v systemctl >/dev/null && systemctl --user show-environment >/dev/null 2>&1 \
    || { echo "✗ no systemd user session here (this kit needs one: any systemd Linux)"; exit 1; }
  for t in cargo node curl; do command -v "$t" >/dev/null || { echo "✗ $t is missing (see README § the node)"; exit 1; }; done
  if [ "$watch_only" = 0 ]; then
    if [ ! -s stage/public/roots.json ] && [ "$fresh" = 0 ]; then
      echo "✗ no network state here. Move it from the machine that runs it now: deploy/home-node/move-to-node.sh"
      echo "  (or --fresh, for a separate new test network — with its own root, made here)"; exit 1
    fi
    [ -e stage/genesis/root.seed ] && echo "!! stage/genesis/root.seed is on this node: a root seed does not belong on an always-on machine"
    echo "== the network's units =="
    bash tools/stage-install.sh install || exit 1
  fi
  echo "== the home watch =="
  cargo build --release -q -p ainra-cli-rs --bin ainra || { echo "✗ build failed"; exit 1; }
  mkdir -p "$CONF"; chmod 700 "$CONF"
  if [ ! -s "$CONF/pinned-roots.json" ]; then
    src="${AINRA_HOME_PIN_FROM:-stage/public/roots.json}"
    [ -s "$src" ] || { echo "✗ nothing to pin: give AINRA_HOME_PIN_FROM=<a roots.json obtained out of band>"; exit 1; }
    cp "$src" "$CONF/pinned-roots.json"
    fp=$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).root_ed25519.slice(0,16))' "$CONF/pinned-roots.json")
    echo "   pinned the roots (genesis:$fp). Compare that fingerprint with the one the operator's own machine shows."
  fi
  if [ ! -s "$CONF/home.env" ]; then
    cat > "$CONF/home.env" <<ENV
# AINRA home watch (D-117). See deploy/home-node/README.md. Read by ainra-home-watch.service.
AINRA_HOME_NET=http://127.0.0.1:8091
AINRA_HOME_ROOTS=$CONF/pinned-roots.json
AINRA_HOME_REGISTRARS=http://127.0.0.1:4907 http://127.0.0.1:4911
# The test network runs on a pinned clock; a wall-clock network leaves this empty.
AINRA_HOME_NOW=1776729600
# Operators whose every passport must be on the list in AINRA_HOME_EXPECT (one passport name per line).
AINRA_HOME_WATCH=
AINRA_HOME_EXPECT=
AINRA_HOME_STATE=$HOME/.local/state/ainra-home
# A command run on a new alarm and on its clearing, the report on its standard input. Empty: the journal only.
AINRA_HOME_ALERT=
ENV
    chmod 600 "$CONF/home.env"
  fi
  mkdir -p "$UNIT_DST"
  sed "s|@REPO@|$REPO|" deploy/home-node/ainra-home-watch.service > "$UNIT_DST/ainra-home-watch.service"
  cp deploy/home-node/ainra-home-watch.timer "$UNIT_DST/"
  systemctl --user daemon-reload
  loginctl show-user "$USER" -p Linger 2>/dev/null | grep -q Linger=yes || loginctl enable-linger "$USER" 2>/dev/null \
    || echo "!! linger is off: the watch stops at logout. Run: sudo loginctl enable-linger $USER"
  systemctl --user enable --now ainra-home-watch.timer >/dev/null
  echo "== the first round =="
  systemctl --user start ainra-home-watch.service; c=$?
  journalctl --user -u ainra-home-watch -n 4 --no-pager -o cat
  [ $c = 0 ] && echo "home node ready: the watch runs every five minutes" || echo "!! the first round did not pass: bash $0 status"
  ;;
status)
  systemctl --user list-timers ainra-home-watch.timer --no-pager 2>/dev/null | head -3
  systemctl --user is-active ainra-stage.target >/dev/null 2>&1 && echo "network units: active" || echo "network units: not active here"
  st="$(sed -n 's/^AINRA_HOME_STATE=//p' "$CONF/home.env" 2>/dev/null)"; st="${st:-$HOME/.local/state/ainra-home}"
  [ -s "$st/round.txt" ] && { echo "-- the last round:"; grep -E '^(==|CTL|MONITOR)' "$st/round.txt"; }
  [ -s "$st/alarm.txt" ] && { echo "-- STANDING ALARM:"; cat "$st/alarm.txt"; } || echo "no standing alarm"
  ;;
uninstall)
  systemctl --user disable --now ainra-home-watch.timer >/dev/null 2>&1 || true
  rm -f "$UNIT_DST/ainra-home-watch.service" "$UNIT_DST/ainra-home-watch.timer"
  systemctl --user daemon-reload
  echo "home watch removed (its configuration in $CONF and its memory are kept). The network: make stage-uninstall."
  ;;
*) echo "usage: install.sh install [--watch-only] [--fresh] | status | uninstall"; exit 2 ;;
esac
