<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Certificate link kit

An agent that already has a certificate keeps it. This kit reads the key inside the certificate, has the agent's
private key sign its consent on your machine, and asks a registrar to link that key to the operator's passport. A
gate that has checked a signature by that key, in whatever protocol the certificate is used for, can then ask who
answers for it, offline, and is told "nobody" again once the link is revoked. Plan:
[PLAN-M55 step 4](../../docs/PLAN-M55.md). Guide: [docs/LINKS.md](../../docs/LINKS.md).

It reads certificates. It issues none, and the private key never leaves the machine it runs on.

| File | What it is |
|---|---|
| `link.mjs` | The kit: `certificateKey(pem)` reads the key, `linkRequest(...)` builds the signed request, and run as a command it sends it. |
| `e2e.mjs` | The whole path against a running registrar, with certificates made by `openssl`, every answer asserted. |

```
node kits/cert-link/link.mjs --cert agent.crt --key agent.key \
     --passport ainra:registrar-07:acme:assistant@1.0.0 --registrar https://registrar.example --token-file token
```

The keys a certificate may carry, and how each is linked:

| Key in the certificate | Linked as | Presented as |
|---|---|---|
| NIST P-256 | ES256 | 65 bytes, uncompressed point (D-108) |
| secp256k1 | ES256K | 33 bytes, compressed point (D-082) |
| Ed25519 | Ed25519 | 32 bytes |
| RSA, 2048 to 4096 bits, exponent 65537 | RS256, or PS256 with `--pss` | its DER SubjectPublicKeyInfo (D-112) |

Anything else (P-384, a 1024-bit RSA key, another exponent) is refused by the kit, by name, before a request is sent.
So is a private key that is not the certificate's.

```
make live-up          # a registrar on the wall clock, TEST root, loopback
make cert-link-e2e
```

What the link does not mean: it does not say the certificate's issuer did its checks well, and it does not replace
the certificate. It says who answers for the key, and whether that is still true.
