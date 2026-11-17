<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# What we mean by Web4

The web changed what it does three times. First people read it. Then they wrote to it and bought from it. Then they
held keys of their own. It is changing a fourth time: **software acts on people's behalf**. Agents browse, buy, sign
and call other agents for the people and companies behind them. We call that era **Web4**. In European policy
documents it is written **Web 4.0**; the two spellings mean the same here.

AINRA is the identity layer of the internet for AI agents: a global network for Web4, in which registrars issue
passports and anyone checks them offline. It is the one shared root that era needs, the way the internet shares one
root for its names. Non-profit, open standard.

## Where the word stops

- **No token, no coin.** AINRA issues no token, no coin and no transferable unit of any kind, and none carries a say
  in its governance ([ACP-0002](proposals/ACP-0002-no-governance-token.md)).
- **Agents are not owners or persons.** Web4 here means software that acts *for* people and organisations who answer
  for it. Every passport names who stands behind the agent, and every agent can be switched off.
- **Nobody owns the word.** AINRA will never claim "Web4" or "Web 4.0" as a trade mark, and will oppose anyone's claim
  to own it.

## Web4-ready

A service, a platform or an agent is Web4-ready when all three are true. Each is testable with the open tools in this
repository; nobody pays to be called Web4-ready, and no one certifies it but the test.

| Criterion | What it means | How to test it |
|---|---|---|
| **Every acting agent can be identified** | Before an agent is let in, the service checks a passport, or a key linked to an accountable operator. | the pilot kit in watch mode beside one route ([kits/pilot](../kits/pilot)) |
| **A switched-off agent is refused in a stated time** | The service names its freshness class and refuses a revoked agent within it. | the gate's freshness class (F1, F2 or F3) in its own configuration; `make identity-e2e` shows a revocation refused end to end |
| **Decisions leave a record** | Each admit or refuse is written to a signed, hash-chained decision record. | [DECISION-RECORDS.md](DECISION-RECORDS.md), `ainra verify-decisions` |

## How AINRA stays one root without becoming a monopoly

One shared root is what makes the era work, the way one root for names made the internet work. A root that behaved
like a monopolist would be resisted by every platform and regulator, and it should be. So AINRA:

- **issues nothing itself.** Registrars issue and compete; the root only accredits them (charter, prohibition 1).
- **keeps checking free and offline, forever.** Nobody pays to verify, and nothing reaches us when they do.
- **never sets or recommends what registrars charge,** and never changes its own terms backwards.
- **accredits on published, objective criteria,** never exclusively; a registrar may also join any other root.
- **earns its place as a default in open code,** never by paying for placement or asking for exclusivity.
- **can be left.** The test corpus is CC0, the formats are open, and anyone may run another root
  ([CHANGE-PROPOSALS.md](CHANGE-PROPOSALS.md)).

These commitments are proposed as [ACP-0003](proposals/ACP-0003-neutrality-commitments.md), open for comment until
1 December 2026. Decision: [D-115](DECISIONS.md).
