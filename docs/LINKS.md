<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# AINRA Link: attribution and revocation for keys agents already have

An agent usually already signs its requests with a key: a signature-agent key, a workload key. That key can be revoked
only inside the system that issued it, and it says nothing about who is accountable for it. A **link** is a
registrar's signed, logged statement that one such key acts for one AINRA passport, with a bit in the registrar's
status list that anyone can check offline. Decision: [D-078](DECISIONS.md). Plan: [PLAN-M47](PLAN-M47.md).

**What a link does not do.** It does not make a request genuine. Your gate verifies the request's signature first,
with whatever protocol it already speaks; a link answers the next question: *who stands behind this key, and is that
still true?*

**Two kinds.** A link is for a key that signs requests. An **issuer link** ([below](#issuer-links), D-110) is for a
key that signs *tokens* naming other agents: the key an identity system issues with. One issuer link answers for
every token that key signs.

## The record

```json
{
  "v": "ainra-link-1",
  "registrar": "registrar-07",
  "passport": "ainra:registrar-07:acme:invoicing@1.0.0",
  "subject": { "kind": "jwk", "alg": "Ed25519 | ES256K | ES256", "thumbprint": "<RFC 7638 thumbprint, base64url>" },
  "scope": [],
  "nbf": 1775865600,
  "exp": 1778457600,
  "status": { "uri": "status://registrar-07/1", "idx": 5 },
  "passport_status": { "uri": "status://registrar-07/1", "idx": 3 },
  "pop": "<64-byte signature by the linked key, in its own algorithm>",
  "log": { "leaf": "<RFC 6962 leaf of the record without `log`>" }
}
```

- The registrar signs these exact canonical bytes with its hybrid key (Ed25519 and ML-DSA-65, both or invalid).
- `pop` is the linked key's own consent, signed in its own algorithm over the canonical
  `{"nbf", "passport", "purpose": "ainra-link-pop-1", "registrar", "thumbprint"}`. Nobody can link a key they do not
  hold.
- **Four key types (D-082, D-108, D-112).** `Ed25519`: the 32-byte key, thumbprint over `{"crv":"Ed25519","kty":"OKP","x"}`.
  `ES256K` (RFC 8812), for agents on ledgers: the 33-byte compressed secp256k1 point, thumbprint over
  `{"crv":"secp256k1","kty":"EC","x","y"}`, consent by ECDSA with SHA-256 as 64-byte `r || s`, **low-S only** — the
  high-S twin of a valid signature is refused, so a consent has exactly one valid encoding. secp256k1 comes from
  RustCrypto `k256` 0.14 (the successor of the 0.13 line NCC Group reviewed in 2023, chosen because 0.13 carries
  RUSTSEC-2026-0387 through `crypto-bigint`; the crate still says "use at your own risk"), `@noble/curves` and Python
  `cryptography`.
  `ES256` (RFC 7518), for keys other identity systems already issue — certificates, signed agent cards, token
  issuers, hardware and platform keystores: the 65-byte **uncompressed** P-256 point (`0x04 || x || y`, the form the
  key has in a JWK and in a certificate), thumbprint over `{"crv":"P-256","kty":"EC","x","y"}`, consent by ECDSA with
  SHA-256 as 64-byte `r || s`, **low-S only**, the same rule. RFC 7518 accepts both twins and many P-256 signers
  return either: if yours returns the high one, send `n - s` in its place (the same statement by the same key; our
  own tools do this for you). P-256 comes from RustCrypto `p256` 0.14 (the same maintainers and the same `ecdsa` code
  as `k256`; no advisory names it; it too says "use at your own risk"), `@noble/curves` and Python `cryptography`.
  `RS256` and `PS256` (RFC 7518, D-112), for the keys the large identity providers sign with: an RSA key of 2048 to
  4096 bits with public exponent 65537, presented as its DER SubjectPublicKeyInfo in its one canonical encoding (what
  a certificate, `openssl rsa -pubout -outform DER` and WebCrypto's `spki` export carry), thumbprint over
  `{"e":"AQAB","kty":"RSA","n"}`. The consent is RSASSA-PKCS1-v1_5 (RS256) or RSASSA-PSS with MGF1 and a salt of
  exactly 32 bytes (PS256), with SHA-256, as long as the modulus. One key is linked under one of the two. RSA comes
  from RustCrypto `rsa` 0.10 (verify only), Python `cryptography` (OpenSSL), and in the TypeScript SDK from a small
  verify-only implementation of its own, the one exception to "audited libraries only" there (D-112 says why).
  A verifier tells them apart by the key it holds: 32 bytes is Ed25519, 33 is ES256K, 65 is ES256, and anything
  longer must be an RSA key. No length means two things, 65 bytes that are not a point on P-256 are not a key at all,
  and neither is any other RSA encoding, size or exponent.
- `scope` empty means "whatever the passport allows"; otherwise the link refuses any capability it does not name.
- Two bits: the link's own, and the passport's. Revoking the operator refuses every link it has.

## At the registrar

| Route | What it does |
|---|---|
| `POST /link` | Body `{passport, alg?, key, pop, scope?, nbf, exp, issuer?}` (`alg` is `Ed25519`, the default, `ES256K` or `ES256`; `key` the base64url public key in that algorithm's form; `issuer` makes it an [issuer link](#issuer-links)). Refused unless the key signed its consent, the passport is this registrar's and not revoked, and the link fits inside it: window inside the passport's, scope inside its capabilities. Bearer token, rate limited. |
| `GET /links` | The whole index. Each entry is registrar-signed and proven under one delegate-signed checkpoint. There is no lookup by key: you download the index, so nobody learns which key you asked about. |
| `POST /link/revoke` | Body `{thumbprint, kind, suspect_since?}`. `kind` is `link` (this key is retired), `operator` (the passport's lineage is suspended, so every link flips) or `compromise` (the key was stolen; `suspect_since` marks when its actions stopped being the operator's). Bearer token, rate limited. |
| `POST /demo/link`, `POST /demo/link/revoke` | The public demo door, for trying Link without a token: the same bodies, the same proof of control, but staging only, on the demo door's own rate limit, and only for demo specimens (passports from `POST /demo/issue`). A key cannot be linked to, and a link cannot be revoked from, any other passport through it. It refuses issuer links. |

Three rules:

- **One link per key, ever.** A revoked key stays revoked; to rotate, link a new key and revoke the old one.
- **A `link` revocation can later become a `compromise`.** A compromise is never downgraded.
- **Everything is logged.** Each link and each revocation is appended to the registrar's transparency log, so the log
  alone says which keys were ever attributable and when that ended.

## At a gate

A gate holds a dual-root-signed directory, as it does for passports. For each request whose signature it has verified
with an Ed25519 key, it builds a `WireLink` from the index entry for that key, the index's checkpoint, and the
registrar's current signed status publication:

```js
import { Verifier } from "@ainra/sdk";
const gate = Verifier.fromDirectoryB64(directory, rootEd25519, rootSlh, "F1");
const r = gate.verifyLink(link, presentedKey, nowSecs, "read:invoices");
// { verdict: "valid", registrar, operator, passport, scope }  or  { verdict: "invalid", reason }
```

```python
from ainra import Verifier
gate = Verifier.from_directory(directory, root_ed25519, root_slh, freshness="F1")
r = gate.verify_link(link, presented_key, now, "read:invoices")
```

The order is fixed and the first failure wins:

1. schema (`schema_violation`, `name_malformed`);
2. the registrar is accredited (`unknown_registrar`);
3. the status publication is the registrar's: signed, under the directory's status URI, before anything is
   decompressed (`stale_status`);
4. the window, exactly (`not_yet_valid`, `expired`);
5. the registrar's hybrid signature (`alg_downgrade`, `sig_invalid`);
6. the key the gate verified is the linked key, it was used as the link says (a request's key, or a token's issuer
   key under the link's issuer name), and that key signed its consent to exactly that (`sig_invalid`);
7. scope (`ceiling_exceeded`);
8. freshness, then the link's bit, then the passport's (`stale_status`, `revoked`);
9. logged before valid (`checkpoint_invalid`, `not_logged`, `registrar_distrusted`).

A key with no link at all is **not linked**: an outcome for the gate to act on, not a reason. A gate in link mode
refuses it.

### Ready-made gates and tools

| Where | What |
|---|---|
| Node (Express/Connect) | `ainraLinkGate(verifier, { verifiedKey, source, capability?, decisions? })` from `@ainra/middleware`; `verifiedToken` in place of `verifiedKey` for tokens |
| Python (ASGI) | `AinraLinkGate(app, verifier, verified_key, source, capability=..., decisions=...)`; `verified_token=` in place of `verified_key` for tokens |
| Edge (WebAssembly) | `createAinraLinkCheck({ directory, roots, freshness })` from `@ainra/edge`, plus `linkFromIndex`; the check takes `issuer` as its fourth argument |
| Command line | `ainra verify-link --link L --directory D --roots R --key K [--issuer NAME]` prints ACCEPT with the operator, or REFUSE with the reason; `ainra link` (`--issuer NAME` for an issuer link), `ainra link-revoke` and `ainra links` run a local registrar's side |
| MCP | `ainra_verify_link`, read-only; takes a link, or the registrar's index and status publication, and `issuer` when the key signed a token |
| Hosted verifier | `POST /v1/verify` with `{link, key, capability?, issuer?}`; a key of any link algorithm |

`verifiedKey` (Python: `verified_key`) is yours: whatever already checks the request's signature hands over the key
it verified. `source` returns the registrar's index and signed status publication; cache them inside your freshness
class. Each gate records `link` decisions when given a decision log.

`make link-parity` serves every link vector to the Node, edge and Python gates as a registrar would, and requires the
same status, reason, operator and issuer from all three. CI runs it.

## Issuer links

Most agents do not sign their own requests. They carry a token from an identity system: a JWT that names the agent,
signed with the system's key. An **issuer link** ([D-110](DECISIONS.md)) is one link for that key. It is the same
record with two differences:

```json
"subject": { "kind": "issuer", "alg": "ES256", "thumbprint": "<RFC 7638 thumbprint>", "iss": "https://issuer.example" }
```

- `iss` is the one name the key issues as: 1 to 255 bytes of visible ASCII, compared byte for byte with the issuer
  name in the token.
- The consent is a different statement, so that neither kind can be made from the other: the canonical
  `{"iss", "nbf", "passport", "purpose": "ainra-issuer-link-pop-1", "registrar", "thumbprint"}`.

A gate does its ordinary check first, and then tells the link check how it used the key:

```js
// 1. The ordinary check, unchanged: the token's signature against the keys its issuer publishes, audience, expiry.
const { key, issuer } = await yourTokenCheck(req);       // the issuer key that verified it, and the token's `iss`
// 2. Who answers for that issuer? The link is found by the KEY, never by the issuer's name.
const link = linkFromIndex(index, statusPublication, presentedKeyThumbprint(key));
const r = link ? gate.verifyLink(link, key, nowSecs, "read:invoices", issuer) : { verdict: "invalid", reason: "not_linked" };
// { verdict: "valid", registrar, operator, passport, scope, issuer }  or  { verdict: "invalid", reason }
```

```python
r = gate.verify_link(link, key, now, "read:invoices", issuer)
```

Leave `issuer` out when the key signed the request itself. A link is consent to one use: an issuer link presented
for a request, an ordinary link presented for a token, and a token naming another issuer are each `sig_invalid`.

**What a valid answer means.** The named operator answers for tokens this key signs as this issuer, and has not been
withdrawn. Revoking the link refuses every such token at every gate.

**What it does not mean.**

- It does not say the key *belongs* to that issuer. A gate learns an issuer's keys from the issuer, as it always has.
  Take the key from there and never from a link, and look the link up by the key and never by the name. A gate that
  does otherwise can be shown a link someone made for their own key under another system's name.
- It does not vouch for the agent the token names. That is the issuer's word, as before.
- It does not make a token genuine, fresh or meant for you. That is your ordinary check.

**Limits today.** No outside system has linked a key. One name per key, so a key shared by several issuer names can
be linked for one of them. Each new signing key needs its own consent. An RSA key can be linked since D-112, with SHA-256 only. A gate's
decision record names the issuer's key, not the agent.

`make issuer-link-e2e` ([`kits/issuer-link`](../kits/issuer-link)) runs it against a live registrar with a token
issuer that has no AINRA code in it:

| Step | The issuer's own check | AINRA |
|---|---|---|
| A token from the linked issuer | verifies | valid, names the operator and the issuer |
| A token from an issuer nobody linked | verifies | refused: not linked |
| A token naming the linked issuer, signed with another key | refused | no link for that key |
| The issuing key signing a request itself | (not a token) | refused: `sig_invalid` |
| After the issuer link is revoked, the same token | verifies | refused: `revoked` |

## Held to one corpus

[`vectors/v1-link`](../vectors/v1-link) holds every link vector in gate form: the directory and roots, the link as a gate
receives it, the key the gate verified, and the gate's own clock, freshness class and capability; from `l54` a vector
may also carry `issuer`, the issuer name in the token the gate verified with that key. A valid answer names
the registrar, operator, passport and scope (and the issuer, for an issuer link), so accepting for the wrong operator
counts as a disagreement. The Rust
core, the TypeScript SDK and the Python package must agree on every one in `make diff`. Each check was removed once from
each implementation to confirm a vector goes red; the leaf-binding attack (`l22`) was rewritten after that exercise
showed its first version could not tell a verifier with the check from one without it.

## Live

`make link-p256-e2e` (also in `make live-drills`) is the same path for a **P-256 key made and used by the platform's
own signer**, the way a keystore or a certificate's key behaves: the private key cannot be exported, and its
signatures come back as either twin. The registrar refuses the high-S twin, the compressed form of the key and a
consent by another key, then links the low-S consent; a gate attributes the key to its operator; an unlinked P-256
key is "not linked"; after a revocation the same gate refuses the same key.

`make link-e2e` (in `make live-drills`, which CI runs) does it at the real clock against a running registrar. An
operator's agents sign as signature agents with keys in its published directory. Two of three keys are linked, each
with its own consent. An origin reads every request twice: an independent open-source signature-agent verifier, then
AINRA Link from the downloaded index and signed status list.

| Step | Signature-agent reader | AINRA Link |
|---|---|---|
| Signed by a linked key | valid | valid, names the operator |
| Signed by the key nobody linked | valid | refused: not linked |
| Key A revoked | valid | A refused `revoked`; B still valid |
| A upgraded to `compromise` | valid | refused; downgrading back is refused |
| Operator suspended | valid | every key refused; the passport itself reads `revoked` |

The signature-agent reader accepts throughout because its profile has no revocation: its remedy is removing the key
from the directory, which reaches a verifier at its next cache refresh. That is the gap Link fills.

## A key in a certificate

An agent named by a certificate already has a key, and the certificate already says which. `kits/cert-link` reads
that key, has the agent's private key sign the consent on the operator's machine, and links it like any other: the
certificate and its issuer stay as they are, and a gate that has checked a signature by the key can ask who answers
for it. The kit reads certificates and issues none. `make cert-link-e2e` runs it against certificates made by openssl
for every key type Link takes (PLAN-M55 step 4).
