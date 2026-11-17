<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# ACP-0004 — Proof of service: how the network rewards the people who run it

```
Number:   ACP-0004
Title:    Proof of service: how the network rewards the people who run it
Kind:     process
Status:   Draft
Created:  2026-11-17
Author:   the operator
Decision: (none yet)
```

## What it proposes

**The nodes carry passports too.** Every party that keeps the network honest holds a *service passport*: the same
format as an agent's passport, a service class, naming an accountable organisation, not transferable, revocable.

- **Witnesses** that co-sign checkpoints and epochs, on time and never two heads for one size.
- **Monitors** that prove a registrar broke a rule, with a signed record it served (the alarms of D-116), and that
  catch the misbehaviour the network plants on a test registrar to check the checkers.
- **Registrars** in good standing.
- **Independent implementations** that pass the whole public test corpus, and keep passing.
- **Finders** of flaws, with a reproducible proof: a failing test vector or a signed bad record.

Standing is **computed from the log**, not voted on, so anyone checks it offline as they check an agent. It earns, in
order:

1. **Standing**: a public list with written states (applied, qualified, trusted, retired) and written entry and exit
   rules.
2. **A seat** in the technical chamber after genesis: not transferable, re-qualified yearly, lost when service stops.
3. **Money, outside the protocol**: a published budget funded by registrars' flat yearly fees and grants, paid by bank
   transfer in fixed tiers against what the log proves, under a yearly cap, with no funder above a fixed share. Never
   per co-signature and never in-band (charter, prohibition 3).

A checkpoint counts as witnessed only when co-signed by distinct named organisations in more than one jurisdiction.

**No token.** An operator tied to an unofficial token scheme in AINRA's name may be delisted.

## Why

Networks that paid for a measurable proxy with a token saw the proxy farmed and their operators concentrate; tokens
whose value came from an organisation's work have been held to be securities; the Tor network refused to pay relays
for the same reasons. Networks like this one, a few dozen accountable operators, run on standing, self-interest and
pooled grants. This design rewards service the network's own log can prove, with the network's own credential.

## What waits

The service passport class and standing from the log can be built after this proposal is decided. Money and seats wait
for a legal entity and the chambers (D-094).

## Objections and answers

(Draft: comments welcome.)
