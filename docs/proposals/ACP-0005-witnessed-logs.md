<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# ACP-0005 — Logs any public witness can cosign, with their keys in the directory

```
Number:   ACP-0005
Title:    Logs any public witness can cosign, with their keys in the directory
Kind:     soft
Status:   Draft
Created:  2026-11-18
Author:   the operator
Decision: (none yet)
```

## What it proposes

Each registrar's transparency log can already be cosigned by the witnesses the wider ecosystem runs (D-121): it keeps
a permanent Ed25519 **note key**, serves its checkpoint as a C2SP signed note (`GET /checkpoint`), and
`ainra witness-submit` takes it to any c2sp.org/tlog-witness witness with a consistency proof. An independent witness
(`litewitness`) has cosigned a registrar's log in a drill, and refused a bad proof and an untrusted key.

What is not yet settled is how anyone learns which note key belongs to which log, and what a verifier may do with the
cosignatures. This proposal settles both:

1. **The note key in the directory.** A registrar's accreditation gains one member, `note_key`: the verifier-key
   string of its note key (`<origin>+<id>+<key>`). The root signs it with the rest of the entry, so a witness operator
   and a verifier take a log's key from the root-signed directory and from nowhere else. It is covered by the
   fingerprint of D-120 and by the formal ACCREDIT request's proof of possession (a signature by the note key over the
   request message).
2. **Permanent origins.** A witness never re-keys a log or changes its origin. A production log's origin is a
   schema-less URL that will not change (`log.ainra.org/<registrar>`); a note key changes only with a new origin, that
   is, a new log, announced in a new directory epoch. The test network keeps its origins (`ainra-log/<registrar>`).
3. **Cosignatures travel with the checkpoint.** The registrar serves, at `GET /checkpoint`, the note with the
   cosignature lines its witnesses returned, and a presentation may carry them.
4. **A verifier's own witness policy.** A verifier MAY require, before it accepts a checkpoint, `k` cosignatures from
   a witness list it chooses, and MUST then check them under those witnesses' keys over exactly the note's text. The
   network publishes a recommended list (distinct organisations, more than one jurisdiction, no organisation above a
   fixed share: ACP-0004's independence rule), signed into the directory as a separate member. A verifier that asks
   for none checks as it does today.
5. **Order of release.** As with D-113: verifiers that accept (and ignore) the new members ship in a release first;
   only then does a directory carry them. A verifier released before that refuses such a directory as malformed in
   the Rust core and ignores the members in the TypeScript and Python SDKs, so no directory carries them until the
   supported lines (D-114) all accept them.

## Why

A transparency log is as honest as the parties who would notice it lying. Today every AINRA log is cosigned only by
a witness the project runs, which proves nothing to someone who does not trust the project. The public witness
network already cosigns many logs, and every serious agent-identity effort found by the research of 17 and 18
November either has no independent witness or says so in writing. A log key a witness can only learn from an email is
a log key anyone could swap; the root-signed directory is where the network already says which keys belong to whom.

## What changes, and what does not

- **Changes:** the accreditation and directory gain optional members; verifiers gain an optional policy.
- **Does not change:** any existing verdict; any existing record; the checkpoint signatures verifiers check today
  (the SLH-DSA log root and its delegates stay as they are, the note key is added beside them).
- **Kind:** soft. No directory member is required, and a verifier that requires no cosignature checks as before.

## What waits

The release of verifiers that accept the new members (the next minor release), then a directory epoch that carries
`note_key` for both test registrars, then the recommended witness list once independent witnesses have agreed to
cosign. The request to the public witness network is the operator's own, written by a person.

## Objections and answers

(Draft: comments welcome.)
