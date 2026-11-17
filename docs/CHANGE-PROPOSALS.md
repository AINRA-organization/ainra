<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# How AINRA changes

No company can press an update button on a root that other people rely on. Open networks learned this first: anyone
writes an improvement proposal, the code is reviewed in public, and the people who run the software choose to run the
new version or not. AINRA changes the same way, with one difference that is its own. Its rules take effect at
**positions in its transparency log**, not on dates, so anyone can replay which rule applied to which passport,
offline. Decision: [D-114](DECISIONS.md). The register is [`docs/proposals/`](proposals/).

## Anyone proposes

A change starts as an **AINRA Change Proposal** (ACP): a numbered Markdown file in `docs/proposals/`, written by
anyone, sent as a pull request. The people who keep the register are clerks, not judges: they give it the next number,
check its form (`make proposals-check`), and do not decide whether it is a good idea.

| Status | Means |
|---|---|
| Draft | written, still being shaped |
| Open | ready for comment; open for **at least 14 days** |
| Accepted | decided; a decision record (D-xxx) says so and why |
| Rejected / Withdrawn | not going ahead; the file stays, with the reason |
| Active | in force (a process) or shipped (a change) |

A proposal is decided only when **every substantiated objection has a written answer** in the proposal itself.
Answered does not mean agreed with. Nobody counts heads; nobody can buy weight.

Who decides depends on the era. Today one operator decides, in public, and the decision record names the operator's
words. At genesis the custodians and then the constituencies take over, as
[GOVERNANCE-AMENDMENT.md](../GOVERNANCE-AMENDMENT.md) sets out. The proposal process stays the same across eras; only
the deciders change.

## Three kinds of change

| Kind | What it does to people who do not upgrade | AINRA's way |
|---|---|---|
| **Soft change** (a soft fork) | Nothing breaks. Old software keeps working; it just checks less. | A new rule that a registrar's directory entry turns on **from a log position**. Everything logged before it keeps its verdict, and every earlier test vector stays byte-identical. Examples: the distrust cutoff (D-044), the pinned log head (D-111), bound delegation chains (D-113). |
| **Hard change** (a hard fork) | Old software can no longer check new credentials, or refuses the new directory. | A new **edition** of the Standard, with its own test corpus. Verifiers support two editions at once; the old one ends at a published log position. An edition is never activated without a released verifier for it first. None has been needed yet. |
| **Maintenance and security release** | Nothing changes in the rules. | A patch release of each supported version line (see [SECURITY.md](../SECURITY.md#supported-versions)). A security fix ships with its post-mortem and its incident entry. |

## Switching a change on

1. **Verifiers first.** The release that can check a new rule is published before any directory turns the rule on.
   D-111 and D-113 learned why: verifiers released before a new field either refuse the whole directory or ignore the
   field.
2. **Then the log position.** The rule takes effect from a leaf index written into the root-signed directory. A log
   cannot be backdated, so nothing can slip under the line.
3. **Readiness, time-boxed** (planned). Registrars will say in their signed accreditation that they are ready, and a
   change switches on when enough of them have, inside a window, or fails cleanly when the window closes. Verifiers
   are never asked to report anything: they stay private.

## Leaving is a right

The test corpus is CC0, the formats are open, and anyone may run another root. A group that disagrees can leave with
its registrars and its history. That is what keeps the deciders honest.

## What this does not do

It does not create a token, a vote that can be bought, or anyone with power to change a passport after it was issued.
It adds a front door to the decision records that already exist.
