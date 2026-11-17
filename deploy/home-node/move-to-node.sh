#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# deploy/home-node/move-to-node.sh NODE [DIR] [--dry-run] — move the running test network from this machine to a home
# node (D-117). NODE is an ssh target (pi@ainra-node.local); DIR is the node's clone (default: ainra, in its home).
#
# The order is the safety: stop here first, copy, start there, check that there serves the same record, and only then
# mark this copy as moved. Two registrars running from one key and one log would each grow their own history, which is
# a fork signed by one key; so at no moment do both run. The root seed (sealed or plain) is never copied: it stays
# where it is, and directories are signed from here through deploy/home-node/sign-for-node.sh.
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 2
NODE="${1:?usage: move-to-node.sh NODE [DIR] [--dry-run]}"; DIR="ainra"; DRY=0
for a in "${@:2}"; do case "$a" in --dry-run) DRY=1;; *) DIR="$a";; esac; done
run(){ echo "+ $*"; [ $DRY = 1 ] || "$@"; }
rsh(){ echo "+ ssh $NODE: $*"; [ $DRY = 1 ] || ssh -o BatchMode=yes "$NODE" "cd $DIR && $*"; }

echo "== 0 · before anything stops"
[ -f stage/MOVED-TO-NODE ] && { echo "✗ already moved to $(head -1 stage/MOVED-TO-NODE)"; exit 1; }
[ -s stage/public/roots.json ] || { echo "✗ no network state here to move"; exit 1; }
here="$(git rev-parse HEAD)"
there="$(ssh -o BatchMode=yes -o ConnectTimeout=10 "$NODE" "git -C $DIR rev-parse HEAD" 2>/dev/null)" \
  || { echo "✗ cannot reach $NODE:$DIR by ssh with a key (README § the node)"; exit 1; }
[ "$here" = "$there" ] || { echo "✗ the node's clone is at ${there:0:12}, this one at ${here:0:12} — the same commit on both, please"; exit 1; }
ssh -o BatchMode=yes "$NODE" "test ! -e $DIR/stage/public/roots.json" || { echo "✗ the node already holds a network's state; refusing to mix two"; exit 1; }
want="$(sha256sum stage/public/roots.json | cut -c1-64)"
echo "   ok: same commit ${here:0:12}; the node holds no state; the record's roots are ${want:0:16}…"

echo "== 1 · build the node's programs here, so the node compiles nothing (D-119)"
if [ $DRY = 1 ]; then echo "+ bash deploy/home-node/build-for-node.sh $NODE $DIR"
else bash deploy/home-node/build-for-node.sh "$NODE" "$DIR" || { echo "✗ nothing was stopped"; exit 1; }; fi

echo "== 2 · stop the network here (nothing runs twice)"
run systemctl --user stop ainra-stage-watchdog.timer ainra-stage.target ainra-registrar@registrar-07.service \
  ainra-registrar@registrar-11.service ainra-witnessd.service ainra-artifacts.service

echo "== 3 · copy its state — never the root seed"
run rsync -a --exclude 'genesis/root.seed' --exclude 'genesis/root.seed.gpg' --exclude 'MOVED-TO-NODE' stage/ "$NODE:$DIR/stage/"

echo "== 4 · start it on the node"
if ! rsh bash deploy/home-node/install.sh install; then
  echo "✗ the node did not come up — starting the network here again, as it was"
  run bash tools/stage-install.sh install >/dev/null; exit 1
fi

echo "== 5 · the node serves the same record"
if [ $DRY = 0 ]; then
  got="$(ssh -o BatchMode=yes "$NODE" "curl -s -m 5 http://127.0.0.1:8091/roots.json | sha256sum | cut -c1-64")"
  if [ "$got" != "$want" ]; then
    echo "✗ the node serves different roots (${got:0:16}…) — stopping it there and starting it here again"
    ssh -o BatchMode=yes "$NODE" "systemctl --user stop ainra-stage.target ainra-stage-watchdog.timer"
    bash tools/stage-install.sh install >/dev/null; exit 1
  fi
  echo "   ok: the same roots, served by the node"
fi

echo "== 6 · this copy is now a backup"
if [ $DRY = 0 ]; then printf '%s:%s\n%s\n' "$NODE" "$DIR" "$(date -u +%F)" > stage/MOVED-TO-NODE; fi
run bash tools/stage-install.sh uninstall

echo "== 7 · the node, reachable here on the usual ports (so every local tool works unchanged)"
UD="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
if [ $DRY = 1 ]; then echo "+ install ainra-node-tunnel.service for $NODE"
else
  sed "s|@NODE@|$NODE|g" deploy/home-node/ainra-node-tunnel.service > "$UD/ainra-node-tunnel.service"
  systemctl --user daemon-reload; systemctl --user enable --now ainra-node-tunnel.service >/dev/null 2>&1
  sleep 3
  got="$(curl -s -m 5 http://127.0.0.1:8091/roots.json | sha256sum | cut -c1-64)"
  [ "$got" = "$want" ] && echo "   ok: http://127.0.0.1:8091 here serves the node's record" \
    || echo "!! the tunnel is not answering yet: journalctl --user -u ainra-node-tunnel"
fi
echo "moved. The network runs on $NODE; this machine keeps the sealed root seed and signs through sign-for-node.sh."
