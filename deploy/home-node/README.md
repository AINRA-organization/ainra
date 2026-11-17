<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# A home node for the test network

Until now one laptop was the whole test network: both registrars, the witness, the published record, and the test
root's seed. When the laptop slept, the network stopped answering, and the root's seed sat on a machine used every day.
D-117 splits those two things apart:

| What | Where | Why |
|---|---|---|
| Both registrars, the witness, the published record, the watchdog | **the home node** (a small single-board computer, always on) | the network answers while the laptop sleeps |
| The home watch (`ainra ctl status` + `ainra monitor` per registrar, every five minutes) | **the home node** | someone is always checking the record and the logs, and says so when they break |
| The test root's seed, **sealed** (`tools/root-seal.sh`) | **the operator's machine**, never the node | a root seed does not belong on an always-on, networked machine |
| Signing a new directory (rare: a key change, binding chains) | **the operator's machine**, through an ssh tunnel to the node | the seed opens in memory for that minute, then is shredded |

A second small computer that never touches a network, holding the seed, is the next step after this one
(directories in and out by USB or QR, the remote-ceremony kit, D-101). The production root is a different thing again:
born at the recorded genesis ceremony, from keys held by its custodians (D-094).

## Built here, run there: a node light enough for a small board (D-119)

Running the network is light: the registrar door, the witness and the `ainra` tool are static programs of 1 to 3 MB.
Compiling them is not: whole-program optimisation over post-quantum signature code takes long and more memory than a
small board has to spare. So the node never compiles. `build-for-node.sh` builds them on the operator's machine for the
node's 64-bit ARM processor (static: nothing needed from the node's system), runs each once under an emulator if one
is installed, copies them over, and marks them with their commit; the node's install scripts use them, and compile
nothing, only when the node's checkout is at that same commit. `move-to-node.sh` does this first.

The watch is light the same way: `ainra monitor` keeps the log's compact range between runs (at most 64 hashes, however
long the log), and each run reads only the entries added since, a page at a time. On the live test registrar's log of
304 entries it kept 4 hashes. A node's work grows with what is new, not with everything there has ever been.

On the operator's machine, once: `rustup target add aarch64-unknown-linux-musl`.

## The node

A small single-board computer with a 64-bit ARM processor and 4 GB of memory or more, a 32 GB+ card or better an SSD,
a wired network, and a 64-bit Debian-based system with systemd. On it, once:

```sh
sudo apt install -y git curl rsync nodejs        # no compiler: the programs are built on the operator's machine
git clone https://github.com/JacobJandon/ainra.git && cd ainra
git checkout <the same commit as the operator's machine>
```

Give the operator's machine ssh access to it with a key (`ssh-copy-id pi@ainra-node.local`).

## Move the network to it (on the operator's machine)

```sh
bash deploy/home-node/move-to-node.sh pi@ainra-node.local --dry-run   # what it will do
bash deploy/home-node/move-to-node.sh pi@ainra-node.local
```

In this order, so that at no moment two copies run: stop the network here; copy its state (never the root seed);
install it on the node (`install.sh`: the network's units and the home watch); check that the node serves the same
roots; only then mark this copy as moved (`stage/MOVED-TO-NODE`) and remove its units. If any step fails, the network is
started here again as it was. Afterwards `tools/stage.sh up` and `make stage-install` refuse to start a second copy
here: two registrars with one key and one log would fork it.

## Sign a directory (on the operator's machine)

```sh
bash deploy/home-node/sign-for-node.sh pi@ainra-node.local            # re-sign over the registrars as they are
bash deploy/home-node/sign-for-node.sh pi@ainra-node.local ainra bind-chains
```

It opens a tunnel to the node's registrars, signs here (the sealed seed asks for its passphrase), sends the signed
directory to the node, and the node republishes. A node that is asked to sign by itself refuses: the seed is not there.

## The home watch

`ainra-home-watch.timer` runs `tools/home-watch.sh` every five minutes. It reads only. Configuration in
`~/.config/ainra-home/home.env`; the roots it trusts are pinned once in `~/.config/ainra-home/pinned-roots.json` (compare
the fingerprint `install.sh` prints with the one on the operator's machine). On a new alarm it writes the journal and
runs `AINRA_HOME_ALERT` once, with the report on standard input; on the clearing, once more. For example, a phone
notification through a push service of your choosing that accepts a plain HTTP POST:
`AINRA_HOME_ALERT=curl -s --data-binary @- https://<your push service>/<a long random topic only you know>`.

```sh
bash deploy/home-node/install.sh status          # the last round, any standing alarm
journalctl --user -u ainra-home-watch -f         # every round
make home-watch-drill                            # a planted fork alarms once, is not repeated, then clears
```

`install.sh install --watch-only` installs the watch alone, to watch a network that runs elsewhere (a second home, a
friend's machine: watchers are worth most where the network is not).

## Taking it back

Stop it on the node (`make stage-uninstall` there), copy its `stage/` back (`rsync -a pi@ainra-node.local:ainra/stage/ stage/`,
keeping this machine's root seed), remove `stage/MOVED-TO-NODE`, and run `AINRA_STAGE_TAKE_BACK=1 make stage-install`.

## What is honest to say

The network answers while the node is powered and online. It binds `127.0.0.1` on the node, so it is still not
reachable by a stranger; the public site still serves a copy of its record. A home node removes the laptop as the single
point of failure and the root seed from the always-on path; it does not make the network independent. Independence
comes from witnesses and monitors run by other people, in other places (deploy/witness-quickstart.md, kits/monitor).
