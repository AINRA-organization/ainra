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
echo "== the node's current record, so this signs on top of what it serves"
rsync -a "$NODE:$DIR/stage/public/" stage/public/ || exit 1
echo "== sign here (the seed opens in memory only)"
bash tools/stage.sh "$WHAT" || { echo "✗ not signed; the node is unchanged"; exit 1; }
echo "== the signed directory to the node (the seed stays here), and the node republishes"
rsync -a --exclude 'root.seed' --exclude 'root.seed.gpg' stage/genesis/ "$NODE:$DIR/stage/genesis/" || exit 1
rsync -a stage/public/ "$NODE:$DIR/stage/public/" || exit 1
ssh -o BatchMode=yes "$NODE" "cd $DIR && bash tools/stage.sh publish" || { echo "✗ the node did not republish"; exit 1; }
echo "signed here, served there."
