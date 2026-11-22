#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# deploy/home-node/sign-for-node.sh NODE [DIR] [accredit|bind-chains] — sign the network's directory on the machine
# that keeps the root seed, for a network that runs on a home node (D-117).
#
# The node's registrars are reached through an ssh tunnel on their usual ports, so tools/stage.sh runs unchanged here:
# it asks them for their accreditation, opens the sealed seed in this machine's memory (you type the passphrase), signs,
# shreds the opened seed, and publishes. Then the signed directory goes to the node (never the seed), and the node
# republishes from its own registrars. The root seed never leaves this machine and never reaches the network.
#
# THE CLOCK is the node's network's own: the file stage/CLOCK in the node's clone (`wall`, or absent/`pinned`; see
# tools/stage.sh). It is read from the node before anything is signed and noted in this checkout, so the signing here
# and the node's own publish run on the same clock without a variable to remember. This checkout saying real time
# while the node says pinned is refused: one of the two is wrong, and the node is where the network runs.
#
# THE QUARTERLY SIGNING. A network that keeps real time must have its directory signed again within the published 92
# days, or every reader calls it stale. That is this script, asked by name to sign the same registrars under today's
# date:
#     AINRA_STAGE_RESIGN=1 bash deploy/home-node/sign-for-node.sh NODE [DIR]
# It makes the next epoch and keeps the earlier ones in the history. Without the variable a directory whose registrars
# have not changed is left exactly as it is. On a pinned network there is nothing to sign again, and the variable is
# ignored with a line saying so. Afterwards the site's copy is refreshed as after any signing: make site-net, make
# site, make site-net-check, deploy.
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 2
NODE="${1:?usage: sign-for-node.sh NODE [DIR] [accredit|bind-chains]}"; DIR="${2:-ainra}"; WHAT="${3:-accredit}"
case "$WHAT" in accredit|bind-chains) ;; *) echo "✗ accredit or bind-chains"; exit 2;; esac
[ -f stage/MOVED-TO-NODE ] || { echo "✗ this checkout's network has not moved to a node (stage/MOVED-TO-NODE)"; exit 1; }
if systemctl --user is-active -q ainra-node-tunnel.service 2>/dev/null; then
  echo "== the node's registrars, through the standing tunnel (ainra-node-tunnel)"
else
  for p in 4907 4911; do curl -s -m 1 -o /dev/null "http://127.0.0.1:$p/" && { echo "✗ something here answers on :$p — stop it first"; exit 1; }; done
  SOCK="$(mktemp -u "${XDG_RUNTIME_DIR:-/tmp}/ainra-tunnel-XXXXXX")"
  ssh -o BatchMode=yes -o ExitOnForwardFailure=yes -M -S "$SOCK" -f -N \
    -L 4907:127.0.0.1:4907 -L 4911:127.0.0.1:4911 "$NODE" || { echo "✗ no tunnel to $NODE"; exit 1; }
  trap 'ssh -S "$SOCK" -O exit "$NODE" >/dev/null 2>&1' EXIT
fi
echo "== the clock the node's network keeps"
theirs="$(ssh -o BatchMode=yes "$NODE" "cat $DIR/stage/CLOCK 2>/dev/null || echo pinned")" \
  || { echo "✗ could not ask $NODE which clock its network keeps; nothing signed"; exit 1; }
theirs="$(printf '%s' "$theirs" | tr -d ' \t\r\n')"
mine=pinned; [ -e stage/CLOCK ] && mine="$(tr -d ' \t\r\n' < stage/CLOCK)"
case "$theirs" in
  wall)
    [ "$mine" = wall ] || { echo wall > stage/CLOCK; echo "   real time on the node: noted in this checkout (stage/CLOCK)"; }
    echo "   real time: the directory is dated when it is signed${AINRA_STAGE_RESIGN:+ (AINRA_STAGE_RESIGN=$AINRA_STAGE_RESIGN)}" ;;
  pinned)
    if [ "$mine" = wall ]; then
      echo "✗ this checkout says the network keeps real time (stage/CLOCK), and the node says it is pinned."
      echo "  Put it right where the network runs (the node's stage/CLOCK, then restart its registrars), or remove the"
      echo "  file here if it was written by mistake. Nothing signed; the node is unchanged."
      exit 1
    fi
    echo "   pinned" ;;
  *) echo "✗ the node's stage/CLOCK holds '$theirs', which is neither wall nor pinned. Nothing signed."; exit 1 ;;
esac
echo "== the node's current record, so this signs on top of what it serves"
rsync -a "$NODE:$DIR/stage/public/" stage/public/ || exit 1
echo "== sign here (the seed opens in memory only)"
# AINRA_STAGE_RESIGN is handed on as the caller set it; unset, nothing is signed again that has not changed.
AINRA_STAGE_RESIGN="${AINRA_STAGE_RESIGN:-0}" bash tools/stage.sh "$WHAT" || { echo "✗ not signed; the node is unchanged"; exit 1; }
echo "== the signed directory to the node (the seed stays here), and the node republishes"
rsync -a --exclude 'root.seed' --exclude 'root.seed.gpg' stage/genesis/ "$NODE:$DIR/stage/genesis/" || exit 1
rsync -a stage/public/ "$NODE:$DIR/stage/public/" || exit 1
# The node publishes on its network's own clock (its stage/CLOCK): no variable is passed, and none is needed.
ssh -o BatchMode=yes "$NODE" "cd $DIR && bash tools/stage.sh publish" || { echo "✗ the node did not republish"; exit 1; }
echo "signed here, served there."
