<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Drill — two issuers, one verifier, and the verifier cut off from both

Run it: `make crossed-withdrawal` (about fifteen seconds, loopback only, nothing to set up first). The tool is
`tools/crossed-withdrawal.mjs`; this page says what it shows and what it does not.

**Question.** A platform relies on agents that two other organisations issued. One of them withdraws an agent. Does
the platform refuse that agent, and only that agent, with no account at either issuer, no call to their API, and no
network path to them at all?

**Answer.** Yes, from files. And when the files stop arriving, the platform's own freshness class says for how
long it goes on trusting the old ones.

## What runs

- **Two issuers**: two registrars, each with its own keys and its own log, in one directory under one TEST root
  made for the run.
- **Two agents**, one from each. Each keeps the bundle its own issuer gave it and presents the same bytes every time.
- **A courier and a mirror**: `tools/publish-static.mjs` copies both issuers' signed status into plain files. Neither
  issuer runs the place the files land.
- **One verifier**, started in a new network namespace. It has no interface, and each run it tries to connect to
  both issuers and records the kernel's answer (`ENETUNREACH`). It holds the directory, the two root keys, what the
  agents presented, and the mirror's files. It applies **one rule to both issuers** and signs a
  [decision record](../DECISION-RECORDS.md) for every answer.

## What it shows

| Round | Status the verifier holds | Issuer A's agent | Issuer B's agent |
|---|---|---|---|
| 1 | fresh, from the courier | allowed | allowed |
| 2, after A revokes and the courier runs | fresh | **refused: `revoked`** | allowed |
| 3, the courier never came: the files from before the withdrawal, exactly one class old | old | **still allowed** | allowed |
| 3, one second later | old | refused: `stale_status` | refused: `stale_status` |

Round 3 is the cost of checking offline, stated as a number: a verifier the courier cannot reach keeps a withdrawn
agent for at most its class (F1 30 seconds, F2 5 minutes, F3 one day) and then refuses everyone from that issuer
until fresh status arrives. The verifier chooses the class; nobody else can lengthen it.

Two controls close the round: a mirror that changes one bit of a list, and a mirror that hands issuer B's list over
for issuer A's agent. Both are refused. A mirror extends reach; it cannot sign.

The run ends by checking its own record: the four decisions of rounds 1 and 2 verify under the verifier's key in
order, an edited one is found, and the egress log shows no connection to an issuer.

**Witness.** `node tools/crossed-withdrawal.mjs --witness-open` runs the verifier without the namespace. Its own
test then reaches an issuer and reports the cut as absent, so "no network" in the normal run is observed, not
assumed. `make crossed-withdrawal` runs the witness first.

## What it does not show

- **That two organisations run this.** Both issuers are processes on one machine, started by the run. No outside
  registrar can be accredited on the published test network yet ([quickstarts/registrar.md](../quickstarts/registrar.md)).
- **A real root.** The root is a TEST root made from the public fixed seed, for this run only.
- **How often a real mirror is refreshed.** Here the courier runs when the script says. In a deployment that
  interval, plus the class, is the time from an issuer's revoke to the last verifier's refusal.
- **A kernel cut everywhere.** Where unprivileged network namespaces are switched off, the run says so and the
  verifier only records that it made no connection of its own. That is weaker, and the output is labelled.
- **A request.** The verifier decides on a presented passport. Whether a given HTTP request is that agent's own is
  the request signature's job ([SIGNATURE-AGENTS.md](../SIGNATURE-AGENTS.md), `make live-drills`).
