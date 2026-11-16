<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Issuer link kit

An agent that carries a token from an identity system (a JWT signed with the system's key) can be attributed and
switched off without the agent or the token changing. The system links the key it issues with, once. Decision:
[D-110](../../docs/DECISIONS.md). Guide: [docs/LINKS.md](../../docs/LINKS.md#issuer-links).

| File | What it is |
|---|---|
| `issuer.mjs` | A token issuer in the usual shape: a discovery document, a published key set, ES256 tokens. The platform's own signer, **no AINRA code**. It stands in for any identity system. |
| `e2e.mjs` | The whole path against a running registrar, with every answer asserted. |

```
make live-up            # a registrar on the wall clock, TEST root, loopback
make issuer-link-e2e
```

What the issuer does that it did not do before: its issuing key signs one statement, its consent to the link, under
its own issuer name. Nothing else about it changes.

What a gate does that it did not do before: after its ordinary check of the token, it looks up the key that verified
the token in the registrar's link index (downloaded whole) and asks who answers for it, saying which issuer the
token named.

```js
const r = gate.verifyLink(link, issuerKey, now, capability, issuerNameFromTheToken);
```

Two rules for a gate, and the drill shows why each matters (step 6):

1. Take the issuer's key from the issuer's published keys, never from a link.
2. Find the link by the key you verified with, never by the issuer's name.

**What this is not.** The issuer here is a stand-in that the drill starts on loopback. No outside identity system has
linked a key. A valid answer says who answers for the issuer; it does not vouch for the agent a token names. The
network is under a TEST root.
