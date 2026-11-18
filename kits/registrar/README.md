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
