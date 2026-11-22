<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# kits/registrar: run a registrar the network does not run

For an organisation that already verifies businesses or people (a KYB or KYC provider, an identity provider, a cloud
or domain registrar) and wants to issue AINRA passports to the operators of AI agents. You keep the fees; the network
charges nothing per passport. Decision: [D-120](../../docs/DECISIONS.md).

**Today this is the test network,** signed by a TEST root. Nothing accredited here moves to the production root, which
is born at its own public ceremony; the same steps, with the formal request below, are how a registrar joins it.

## What you take on

- **Verify the operator** behind every passport under rules you publish, and keep the evidence; the passport itself
  carries none of it.
- **Issue, renew and revoke** through your registrar, and keep its transparency log and its signed status list
  served. A passport is valid only once it is in your log; a revocation reaches every verifier through your list.
- **Stay checkable.** Anyone can watch your log for passports nobody asked for (`ainra monitor`, `kits/monitor`), and
  the compliance probe (`kits/probe`) measures your registrar from outside.
- What the network may do if you stop: [docs/ACCREDITATION-CHECKS.md](../../docs/ACCREDITATION-CHECKS.md) lists every
  rule a directory change is held to, including notice, cure windows and distrust from a log position.

## Managed start

If you want to issue before you have learned to run the registrar, the network's operator can run one for you and hand
it over later. It joins the network by the same steps as any registrar the network does not run (below); the
difference is whose machine it is on.

**What we run for you.** One registrar under the id `registrar-<your-name>` (after `registrar-`: up to 40 lower-case
letters, digits and hyphens), in a folder of its own on the operator's machine, at its own address. Its keys are made
by that machine when it first starts. We keep it running, keep its log and its status list served, and hold its write
token; how you ask for a passport to be issued or revoked is agreed with the operator.

**What is yours from the first day.** The decisions: whom you verify, under which published rules, what is issued and
what is revoked, and the evidence you keep. The name: every passport reads `ainra:registrar-<your-name>:…`, and that id
never changes. The record: your log and your status list are public, so you, or anyone you ask, can check with
`ainra monitor` that nothing was issued under your name that you did not ask for.

**What is not yours yet.** The keys. While we run the registrar we are able to issue or revoke under your name; the log
would show it, and nothing but our word prevents it. The fingerprint the root's holder checks is computed on our
machine, so where the operator and the root's holder are the same party, the second channel guards against a changed
address and not against us.

**A hand-over.** When you are ready, the operator stops the registrar and seals its whole state (keys, log, status
list, the log's note key) into one file with a passphrase, which reaches you by another channel than the file. You
open it on your machine with one command: your registrar starts with the same keys, the same log and the same id, and
a new write token of your own. The operator checks that your address serves the same keys and the same log, grown and
not rewritten, then destroys its copy of the keys, the old token and the package, and keeps a record of the hand-over.
The network's directory does not change: no new epoch, no passport issued again, nothing for a verifier to do.

```sh
bash tools/managed-registrar.sh create <your-name> --name "Your Organisation" --addr 127.0.0.1:4922 \
  --net <the network's record> --roots roots.json                                         # the operator
bash tools/managed-registrar.sh status
bash tools/managed-registrar.sh handover registrar-<your-name> --out <folder>             # the operator
bash tools/managed-registrar.sh receive  registrar-<your-name> <package> --addr 127.0.0.1:4922   # you
bash tools/managed-registrar.sh confirm  registrar-<your-name> --at https://registrar.example.org   # the operator
make managed-registrar-drill   # all of it on throwaway networks, with every refusal
```

**The limit.** After a hand-over your keys are the keys that were made on our machine and were there until that day.
We destroy our copy; you have our word and our record of it, not a proof. Today an existing registrar cannot be given
new keys and keep its passports and its log: a directory entry holds one set of keys, a request to roll them is
refused until its rule exists, and the id is bound to its log. What exists is a second registrar. You start one
yourself (`create` on your own machine, or step 1 below), it is accredited under an id of its own, and each agent's
operator moves its lineage there through the transfer doors: the operator's own signature, a five-day public window,
the history kept. There is no command-line client for the operator's side of a move yet, and a passport's name changes
with the registrar's id. If keys that were never on another machine matter to you from the start, begin at step 1
instead.

A managed registrar keeps real time. The published test network is still pinned at April 2026: there its passports
verify at the real clock, and a reader standing at the pinned instant sees their status as stale.

## 1. Run the registrar

The registrar is one program, `registrar-box`, with its state in one folder:

```sh
cargo build --release -p ainra-services --bin registrar-box -p ainra-cli-rs --bin ainra   # or the services image: deploy/Dockerfile.services
AINRA_FRESH_KEYS=1 AINRA_STAGE_ISSUE_TOKEN=<a long random secret> \
  ./target/release/registrar-box 127.0.0.1:4922 registrar-<your-name> /var/lib/ainra/registrar
```

- `AINRA_FRESH_KEYS=1` makes its keys from the operating system's randomness on first start (D-107). The folder holds
  them: back it up, keep it private, never copy it to a second running registrar.
- The issue token guards the write endpoints (`/issue`, `/revoke`, `/link`, …). Keep it secret.
- Put it behind HTTPS at a stable address, for example `https://registrar.example.org`, with the read endpoints public:
  `/accreditation`, `/export`, `/status-list`, `/fresh-head`, `/deltas`, `/log/entries`, `/witness-feed`, `/links`.

## 2. Send two things, by two different channels

```sh
node tools/registrar-fingerprint.mjs https://registrar.example.org
# registrar-<your-name> sha256:<64 hex>
```

- **The address**, by email to info@ainra.org.
- **The fingerprint**, by a different channel: read it out on a call, or send it signed from an address the root's
  holder already knows. The fingerprint covers your registrar id, your issuer, log and status keys, your log origin
  and your status-list address.

The root's holder fetches your accreditation from the address and signs you in only if it has that fingerprint, so
whoever could tamper with one channel cannot also change the other.

## 3. File the formal request

The production path, and on the test network a stronger check than the fingerprint alone: a request signed by every
one of your keys, naming the Standard's prerequisites by their SHA-256.

```sh
ainra directory request ACCREDIT --registrar /var/lib/ainra/registrar --filed-at "$(date +%s)" --test-root \
  --evidence evidence.json --out accredit-request.json
```

`evidence.json` names four files you keep: the signed agreement, an independence attestation, a funded competitor
monitor, and an audit with its date:

```json
{"prerequisites": {"agreement": {"file": "agreement.pdf", "sha256": "…"},
  "independence_attestation": {"file": "independence.pdf", "sha256": "…"},
  "competitor_monitor": {"file": "monitor.pdf", "sha256": "…"},
  "audit": {"file": "audit.pdf", "sha256": "…", "date": "2026-11-18"}}}
```

The root's holder checks it with `ainra directory check-request accredit-request.json --directory … --roots …
--accreditation <what your address serves>`.

## For the root's holder

1. Check the request (above) and compare the fingerprint that came by the second channel.
2. Add the registrar to `stage/genesis/outside-registrars.json` on the machine that keeps the sealed root seed:
   ```json
   [{"id": "registrar-<name>", "url": "https://registrar.example.org", "fingerprint": "sha256:<hex>"}]
   ```
3. Sign the next directory epoch: `bash deploy/home-node/sign-for-node.sh <node>` (or `bash tools/stage.sh accredit`
   where the network runs on the same machine). A wrong fingerprint, or an address that does not answer, stops it with
   nothing signed. The list travels to the node with the signed directory.
4. From then on, every verifier that trusts the root accepts the new registrar's passports, and anyone can check its
   log under the key the directory gives it.

A registrar that stops answering does not stop the network's record: its last published copy is kept, and verifiers
refuse its passports once its signed status grows stale, as they must.

## Prove it works

```sh
make registrar-join-drill   # a whole throwaway network on spare ports, with its own root; touches nothing else
```

A wrong fingerprint is refused with the directory unchanged; the formal request is accepted; the right fingerprint
signs the registrar in at the next epoch, `ainra ctl` reads three registrars under the root and `ainra monitor` checks
the new registrar's log under the key the root gave it; when the registrar stops, publishing goes on with its last
copy.
