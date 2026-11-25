<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Moving the repository to an organization

**This is the maintainer's click, not the agent's.** Everything below is prepared so the move takes minutes and
nothing silently breaks afterwards.

## Why

Two reasons, one of them structural:

1. **A neutral root under a personal account undercuts its own claim.** The first thing a sceptical reader checks is
   whether the thing calling itself neutral is one person's project. Under a personal account the URL answered *yes*
   before they read a line of code. Moving cost nothing and removed the cheapest objection anyone could make.
2. **Fiscal hosting requires it.** Open Source Collective's acceptance criteria state the project must be *"hosted
   under an organizational repository, not a personal account"* — so the money path is gated on this, not on
   incorporating (see [`campaign/FREE-INFRASTRUCTURE.md`](../campaign/FREE-INFRASTRUCTURE.md)).

## The name — **`AINRA-organization`** (the maintainer's choice, 25 Nov 2026)

The August recommendation was `ainra-root`. On 25 Nov 2026 the maintainer created and chose `AINRA-organization`.
The bare `ainra` and `ainra-org` are taken (a dormant user account since 2015, an empty organization since 2017),
and so is `ainrahq` (2021). None of them is ours.

## The click-path

1. **Create the organization.** Done 25 Nov 2026: `AINRA-organization`, Free plan.
2. **Transfer each repository.** Done 25 Nov 2026, by the maintainer. The path: `github.com/JacobJandon/ainra` (and
   `ainra-website`) → **Settings** → *Danger Zone* → **Transfer ownership** → new owner `AINRA-organization` → type
   `JacobJandon/ainra` (or `JacobJandon/ainra-website`) to confirm.
3. **Immediately re-check the settings that do NOT survive a transfer** (see below), and reconnect the website's
   host to the new owner.
4. **Push the propagation** (below), prepared before the move so the references change the moment it is done.

### What the platform carries over, and what it does not

Carried over automatically: issues, pull requests, wiki, stars, watchers, **and redirects from every old URL** —
`git remote` keeps working, clone URLs keep working, and links in the wild keep resolving. Releases and tags come
with the repository, so published artifacts and their signatures are unaffected.

**Not carried over — re-check each after the move:**

- **Branch protection rules** — verify `main` still requires the checks it required before.
- **Actions secrets and variables**, and Actions being enabled at all.
- **Pages / deployment settings**, if any remain.
- **Trusted publishing configurations** — npm, PyPI, and crates.io each bind to an exact
  `owner/repo` **and** workflow path. All three must be re-pointed at the new owner or publishing breaks. If any
  package is already published, do this *before* the next release, not after.
- **The `repository` field in every package manifest** must match exactly, case-sensitively, or npm provenance
  fails — see the propagation command.
- **Codeowners, environments, rulesets**, and any org-level required workflows.

## Post-move propagation

Prepared before the move as one change: every **current** reference to the old owner in a tracked file is pointed at
`AINRA-organization`. That covers the site's pages and includes, the deploy units' `Documentation=` lines, the package
manifests, `SECURITY.md`, `security.txt` and its generator, the issue templates, the docs, and the tools that name the
repository.

`bash tools/org-rename.sh <new-owner>` moves the repository links for any later move: a dry run lists every file it
would change, then `--apply` writes them, adds the new owner to the link check (every earlier owner stays accepted,
because the records below still link to them), regenerates the site and the month's operator report (which carries
a digest of a package manifest), and runs the checks of both. It leaves alone everything in the list below. It
reads the current owner from the CI badge in `README.md`; `AINRA_OLD_OWNER` names another. One line is edited by
hand after it: `MAINTAINERS.md` names the organisation's account, a link with no repository in it, which the tool
does not touch.

### What keeps the old owner, and why

- **Historical records:** the entries of `CHANGELOG.md` before this move and the compare links of released versions
  (its `[Unreleased]` link moves), `docs/releases/*`, `docs/_archive/*`, and the published news entries (in
  `site/news.json`, `news.xml`, and inside the news block of `news.html`). A record that silently rewrites itself is
  not a record, and their old URLs still resolve through the redirect.
- **The maintainer's own handle** in `MAINTAINERS.md`: a person, not the repository's home.
- **The transfer source,** in the click-path above.
- **The trusted-publisher settings** described in `.github/workflows/publish.yml` and `docs/PUBLISHING.md`. They
  describe what npm and PyPI hold today; they change when the maintainer re-points them there.
- **The MCP registry name** `io.github.JacobJandon/ainra` (`packages/mcp/package.json`, `server.json`). It must match
  the namespace the publisher is authorised for, and it moves at the next release.
- **The link check** accepts every owner the repository has had, while their URLs redirect.

## After the move — the checklist

- [ ] `git remote -v` still resolves; `git ls-remote origin main` succeeds
- [ ] the prepared propagation pushed (after the transfer), CI green
- [ ] the website's host reconnected to `AINRA-organization`; a deploy goes through
- [ ] `make preflight` ALL GREEN from a **clean clone of the new URL** (not the old checkout)
- [ ] `make site && make site-check` green; the CI badge in `README.md` resolves
- [ ] branch protection on `main` restored
- [ ] Actions enabled; secrets present
- [ ] trusted-publishing configs re-pointed on **every** registry before the next publish
- [ ] `tools/export-site.sh` still pushes the website repo (it names the repo explicitly)
- [ ] the site's own GitHub links resolve (`make site-check` covers the internal ones; check the external one by hand)
