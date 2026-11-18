---
title: "Status and Attribution for Externally Issued Agent Keys"
abbrev: "Agent Key Status"
docname: draft-georgiev-agent-key-status-00
category: info
submissiontype: IETF
ipr: trust200902
area: Security
keyword: [AI agents, revocation, status list, attribution, transparency log]
stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
  - fullname: Mihail Georgiev
    organization: AINRA
    email: info@ainra.org

normative:
  RFC5280:
  RFC7518:
  RFC7519:
  RFC7638:
  RFC8017:
  RFC8032:
  RFC8037:
  RFC8812:
  RFC6962:
  I-D.ietf-oauth-status-list:

informative:
  RFC9421:
  RFC7942:
  I-D.ietf-webbotauth-httpsig-protocol:
  I-D.meunier-webbotauth-httpsig-directory:
  SEC1:
    title: "SEC 1: Elliptic Curve Cryptography, Version 2.0"
    target: https://www.secg.org/sec1-v2.pdf
    author:
      - org: Standards for Efficient Cryptography Group
    date: 2009-05
  FIPS204:
    title: "Module-Lattice-Based Digital Signature Standard"
    target: https://doi.org/10.6028/NIST.FIPS.204
    author:
      - org: National Institute of Standards and Technology
    date: 2024-08

--- abstract

Software agents increasingly sign their requests with keys issued inside one system: a signature directory, a
workload identity domain, a platform's own key store, a certificate authority. Many carry tokens signed by an identity
system's key instead. A relying party in another organisation can verify such a signature, but cannot learn who is
accountable for the key or whether it has since been revoked, because revocation exists only inside the system that
issued it. This document specifies a link record: a signed, logged statement by an accountable registrar that one
existing key acts for one operator, carrying a status entry in a list any relying party can check offline. A link
covers either a key that signs requests or a key that signs tokens under one issuer name, in Ed25519, secp256k1
(ES256K), P-256 (ES256) or RSA (RS256, PS256). The document defines proof of control by the linked key, three kinds of
revocation, a fixed verification procedure, and reuse of the Token Status List format for the status itself.

--- middle

# Introduction

A relying party that receives a signed request from an agent (for example one signed with HTTP Message Signatures
{{RFC9421}}, as profiled for automated traffic in {{I-D.ietf-webbotauth-httpsig-protocol}}) typically answers one
question: did this key sign this request? It cannot answer two others that matter once agents act across
organisations: which accountable party stands behind the key, and whether that is still true. Short-lived credentials
bound the damage of a stolen key by their lifetime inside one provider; they do not tell a party outside that
provider that a key has been withdrawn. Key directories such as {{I-D.meunier-webbotauth-httpsig-directory}} let a
relying party find a key; their remedy for a withdrawn key is to remove it from the directory, which reaches a relying
party only at its next refresh, and says nothing about who answered for the key while it was there.

This document specifies a minimal layer for those two questions, for keys the agent or its identity system already
has:

- A **registrar** that has established the identity of an operator links an existing key to that operator, after the
  key itself has signed its consent.
- The link carries an entry in a status list in the format of {{I-D.ietf-oauth-status-list}}, together with an entry for
  the operator, so suspending the operator refuses every key linked to it.
- Every link and every revocation is appended to an append-only log {{RFC6962}}, so the log alone states which keys were
  ever attributable and when that ended.
- A relying party checks a link offline, in a fixed order, after it has verified the request's or the token's
  signature by whatever means it already uses.

The layer issues no new key to the agent and changes nothing in how requests or tokens are signed. It is
complementary to short-lived credentials and to key directories: those bound risk and distribute keys inside one
provider; a link carries attribution and revocation across providers.

## Requirements Language

{::boilerplate bcp14-tagged}

# Terminology

Operator:
: The organisation or person accountable for an agent.

Registrar:
: A party that has established an operator's identity under published rules, and signs link records. A relying party
  decides which registrars it trusts.

Linked key:
: A public key of one of the algorithms in {{algs}}, named in a link record by its JWK thumbprint {{RFC7638}}.

Link record:
: The signed statement defined in {{record}}.

Request link:
: A link record for a key that signs requests itself (`subject.kind` = `jwk`).

Issuer link:
: A link record for a key that signs tokens naming other agents, under one issuer name (`subject.kind` = `issuer`,
  {{issuer}}).

# The link record {#record}

A link record is a JSON object, serialised in a canonical form (sorted member names, no insignificant whitespace,
integers only, each member name once), and signed by the registrar over exactly those bytes. Its members are:

| Member | Content |
|---|---|
| `v` | the string `ainra-link-1` |
| `registrar` | the registrar's identifier |
| `passport` | the operator's identifier at that registrar |
| `subject` | `{kind: "jwk", alg, thumbprint}` for a request link, or `{kind: "issuer", alg, thumbprint, iss}` for an issuer link: the key's algorithm ({{algs}}), its RFC 7638 thumbprint in base64url and, for an issuer link, the one issuer name ({{issuer}}) |
| `scope` | an array of capability strings, at most 256; empty means no narrowing |
| `nbf`, `exp` | the validity window, seconds since the epoch, `nbf < exp` |
| `status` | `{uri, idx}`: the link's own entry in the registrar's status list |
| `passport_status` | `{uri, idx}`: the operator's entry, in the same list, at a different index |
| `pop` | the linked key's signature over the consent bytes ({{pop}}), base64url |
| `log` | `{leaf}`: the log leaf hash of the record without its `log` member, base64url |

A record with any other member, a missing member, a member of the wrong type, or bytes that are not in canonical form
MUST be rejected. In particular, a relying party MUST compare the signed bytes with the canonical encoding of what it
parsed: JSON parsers disagree about a member name that appears twice (some keep the first value, some the last), and
only the canonical form guarantees that every relying party reads the same record under one signature. The `passport`
identifier MUST name the same registrar as `registrar`. A `subject.kind` other than `jwk` or `issuer` MUST be rejected.

## Key algorithms {#algs}

| `alg` | Key, as presented | Thumbprint JWK | Signature over the consent bytes |
|---|---|---|---|
| `Ed25519` | the 32-byte public key {{RFC8032}} | `{crv: "Ed25519", kty: "OKP", x}` {{RFC8037}} | Ed25519, 64 bytes |
| `ES256K` | the 33-byte compressed point {{SEC1}} on secp256k1 | `{crv: "secp256k1", kty: "EC", x, y}` {{RFC8812}} | ECDSA with SHA-256, 64-byte `r` &#124;&#124; `s` with `s` at most half the group order |
| `ES256` | the 65-byte uncompressed point {{SEC1}} on P-256 | `{crv: "P-256", kty: "EC", x, y}` {{RFC7518}} | ECDSA with SHA-256, 64-byte `r` &#124;&#124; `s` with `s` at most half the group order |
| `RS256` | the DER SubjectPublicKeyInfo {{RFC5280}} of an RSA key of 2048 to 4096 bits with public exponent 65537, in its one canonical encoding | `{e: "AQAB", kty: "RSA", n}` {{RFC7518}} | RSASSA-PKCS1-v1_5 with SHA-256 {{RFC8017}}, as long as the modulus |
| `PS256` | as for `RS256` | as for `RS256` | RSASSA-PSS with SHA-256, MGF1 with SHA-256 and a salt of exactly 32 bytes {{RFC8017}}, as long as the modulus |

A verifier MUST refuse an ES256K or ES256 signature whose `s` is greater than half the group order, even though the
curve equation accepts it: each consent then has exactly one valid encoding. {{RFC7518}} itself accepts both; a P-256
signer that returns the larger `s` replaces it with the group order minus `s` before sending, which is the same
statement by the same key.

A verifier tells the algorithms apart by the presented key: 32 bytes is Ed25519, 33 bytes ES256K, 65 bytes ES256, and
a longer key MUST be an RSA SubjectPublicKeyInfo as described above. A 65-byte value that is not a point on P-256 is
not a key, and neither is any other RSA encoding, size or exponent. One RSA key is linked under RS256 or under PS256,
never both; a key presented in one algorithm never verifies a link that names another.

ES256K is the standard, ledger-neutral form for agents that hold keys on public ledgers; message formats specific to
one ledger would be further `alg` values. ES256 and the RSA algorithms are the algorithms of most certificates,
signed agent descriptions, hardware and platform key stores, and token issuers, so a key one of those systems already
issued can be linked as it is.

## Proof of control {#pop}

Before issuing a link, the registrar MUST verify, and every relying party MUST verify again, a signature by the linked
key over a canonical consent object. For a request link the object is
`{nbf, passport, purpose: "ainra-link-pop-1", registrar, thumbprint}`. For an issuer link it is
`{iss, nbf, passport, purpose: "ainra-issuer-link-pop-1", registrar, thumbprint}`. The two purposes differ so that
neither kind of consent can be presented as the other. Without proof of control, anyone could attribute a key they do
not hold to an operator, or an operator to a key it does not control.

## Registrar signature

The registrar signs the canonical record bytes. The reference implementation signs with Ed25519 and ML-DSA-65
{{FIPS204}} together and requires both to verify; a deployment that profiles this document MUST state its signature
algorithms and MUST NOT accept a record whose required signatures are incomplete.

# Issuer links {#issuer}

Most agents do not sign their own requests: they carry a token, for example a JWT {{RFC7519}}, that names the agent and
is signed with an identity system's key. An issuer link is one link for that key, under one issuer name.

`subject.iss` is the one name under which the key issues: 1 to 255 bytes of visible ASCII, compared byte for byte with
the issuer name in the token (the `iss` claim of a JWT). A relying party verifies the token by its ordinary means
first, takes the verifying key from the issuer as it always has, and then checks the link **found by that key's
thumbprint, never by the issuer's name**, passing the token's issuer name to step 6 of {{verification}}.

A valid issuer link means: the named operator answers for tokens this key signs as this issuer, and has not been
withdrawn. Revoking the link refuses every such token at every relying party that checks it. It does not mean that
the key belongs to that issuer (a relying party learns an issuer's keys from the issuer), it does not vouch for the
agent the token names (that remains the issuer's statement), and it does not make a token genuine, fresh or addressed
to the relying party (that remains the ordinary token check).

A link is consent to one use. A request link presented for a token, an issuer link presented for a request, and a
token naming another issuer than `subject.iss` each fail step 6.

## Keys in certificates

A key named in an X.509 certificate {{RFC5280}} is linked as itself: its SubjectPublicKeyInfo gives the presented key
and the thumbprint, and the holder of its private key signs the consent. The certificate and its issuer are neither
replaced nor validated by the link; a relying party that has verified a signature by the certified key, by whatever
means it trusts, can additionally ask who answers for that key and whether that is still true.

# Registrar operations

Issue:
: The registrar verifies proof of control, checks that the window lies inside the operator's own and that the scope is
  within what the operator may do, appends the record without its `log` member to its log, sets `log.leaf`, signs, and
  publishes. A key is linked at most once; a revoked key is never linked again. To rotate, the operator links the new
  key and revokes the old one.

Index:
: The registrar publishes all of its link records, with inclusion proofs under one signed checkpoint, as a single
  document fetched whole. It MUST NOT offer lookup by key: a relying party that asks about one key would reveal which
  agent it is dealing with.

Revoke:
: Three kinds. `link`: the linked key is no longer attributable; its entry is set. `operator`: the operator is
  suspended; the operator's entry is set, refusing every link to it. `compromise`: the key was stolen; its entry is set,
  and the revocation records `suspect_since`, the time from which the key's actions are not the operator's. A `link`
  revocation MAY later become a `compromise`; a compromise is never downgraded. Every revocation is appended to the
  log.

# Verification {#verification}

A relying party has already verified a request's signature, or a token's signature, with a key of one of the
algorithms in {{algs}}, and holds a trusted set of registrars with their signature keys, status keys, status list URIs
and log keys. It checks a link in this order; the first failure is the answer:

1. The record is well formed ({{record}}), including the canonical-bytes comparison.
2. The registrar is trusted.
3. The status list is authenticated: signed by the registrar's status key, published under the URI the trusted set
   names, and that URI equals the record's `status.uri`. Nothing in the list is read before this holds.
4. The current time is within `[nbf, exp)`.
5. The registrar's signature over the record verifies.
6. The key that verified the request or token is of the algorithm `subject.alg` names, its thumbprint equals
   `subject.thumbprint`, it was used as the link's kind says (a request link for a request; an issuer link for a token
   whose issuer name equals `subject.iss`), and `pop` verifies under that key, in that algorithm, over the consent
   object of that kind ({{pop}}).
7. If the request exercises a capability and `scope` is not empty, the capability is in `scope`.
8. The status list is fresh enough for the relying party's own policy; the link's entry is not set; the operator's
   entry is not set. An index at or beyond the end of the list is treated as set.
9. The checkpoint signature verifies, `log.leaf` is the leaf hash of the record without `log`, and the inclusion proof
   leads to the checkpoint's root.

A key with no link at all is "not linked": an outcome for the relying party's policy, typically refusal.

# Status

The status list uses the format of {{I-D.ietf-oauth-status-list}}: one bit per entry, least significant bit first,
compressed with DEFLATE in the ZLIB format. A registrar MAY publish additional signed forms of the same bits; a relying
party MUST check whichever form it trusts as authoritative. The reference implementation publishes a hybrid-signed
form as authoritative and the same bits as a `statuslist+jwt` for libraries that implement the Token Status List
draft. Reusing that format lets other credential formats for agents that name it as their revocation mechanism read
the same bits.

## Actions in flight

Revocation takes effect at a relying party's next check of a fresh status list. An action that a relying party
accepted before that check, such as a payment already authorised or a long-running task already started, is not
undone by the status bit. Three properties bound the gap:

- The relying party's freshness policy bounds how long a revoked key can still be accepted; a relying party that
  starts a long or costly action can re-check the status immediately before committing it.
- A `compromise` revocation's `suspect_since` states from when the key's actions are not the operator's, so actions
  accepted in the gap can be identified afterwards and handled under whatever dispute rules apply between the parties.
- The log records when each revocation was made, so the order of acceptance and revocation can be shown to a third
  party.

This document does not define who bears the loss of an action accepted in the gap; that is a matter for the rules
between operators, registrars and relying parties.

# Implementation Status

(This section is to be removed before publication, per {{RFC7942}}.)

A reference implementation with three independently written verifiers (Rust, TypeScript, Python) and a shared corpus of
92 conformance vectors for link verification, covering all five key algorithms and both subject kinds, is available
under open-source licences. It includes a registrar, gates for HTTP servers and edge runtimes, a tool that links the
key in an existing certificate, and interoperability tests in which an independent HTTP Message Signatures verifier, an
independent token issuer with no code from this implementation, and independent Token Status List and JOSE libraries
take part. It runs on a test network under a test root; no production deployment exists, and no key issued by an
outside system has yet been linked.

# Security Considerations

Stolen keys:
: `compromise` with `suspect_since` lets a relying party, an auditor or an insurer separate actions taken before the
  theft from those after. A relying party that keeps signed records of its decisions can later re-examine them.

Spliced status:
: A presenter could offer another registrar's list, or an old one. Step 3 binds the list to the registrar's status key
  and URI before any bit is read; freshness then bounds how long a superseded but genuine list can be replayed.

Consent forgery:
: Step 6 checks the thumbprint, the kind of use and the proof of control. Checking only some of them lets an attacker
  obtain a record naming a victim's key with the attacker's consent, the reverse, or a consent given for one use
  presented for another.

Issuer names:
: A link is found by the key, never by the issuer name. A relying party that looked a link up by name, or took an
  issuer's key from a link instead of from the issuer, could be shown a link someone made for their own key under
  another system's name.

Parser differentials:
: A record that repeats a member name could be read two ways by two relying parties under one signature. The
  canonical-bytes comparison in step 1 removes the ambiguity. The reference implementation has required it for link
  records from the start; its verifiers were found to disagree on another signed record type that lacked it, which
  is why the requirement is stated explicitly here.

Signature malleability and encodings:
: The low-`s` rule for ECDSA, the one canonical RSA key encoding, the fixed exponent and the fixed PSS salt length give
  each consent and each key exactly one valid form, so no two distinct byte strings carry the same statement.

Log binding:
: Step 9 binds `log.leaf` to the record's own bytes before checking inclusion; a record that points at another logged
  leaf is refused.

Registrar compromise:
: A registrar can link keys falsely. The append-only log makes every link visible to monitors; a relying party's trusted
  set may withdraw a registrar, and may limit trust to links logged before a given leaf.

Quantum:
: Link records live as long as their windows. A deployment that needs assurance beyond the life of classical signatures
  should require a post-quantum signature alongside Ed25519, as the reference implementation does. The linked keys
  themselves are classical; a link does not make them quantum-safe.

# Privacy Considerations

A link names a key, an operator and, for an issuer link, an issuer name; it holds no personal data. Relying parties
fetch whole indexes and whole status lists, so no request reveals which agent is being checked. Registrars hold
whatever evidence they used to establish the operator's identity; none of it appears in the link.

# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgments
{:numbered="false"}

This work builds on the Token Status List draft of the IETF OAuth working group, on Certificate Transparency, on the
Web Bot Auth working group, and on the other groups exploring agent identity and agent payments, whose drafts made the
cross-provider revocation gap visible.
