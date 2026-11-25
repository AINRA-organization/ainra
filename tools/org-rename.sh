#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Propagate a repository-owner change through every current repository link, then regenerate what is derived (the
# site and the month's operator report) and run their checks. One line stays for a hand edit: MAINTAINERS.md names the
# organisation's account (no repository in it). See docs/ORG-MOVE.md (used for the move to AINRA-organization, 25 Nov
# 2026).
#
#   bash tools/org-rename.sh <new-owner>            # DRY RUN: prints every file it would change, writes nothing
#   bash tools/org-rename.sh <new-owner> --apply    # writes, regenerates the site and the operator report, checks both
#
# It rewrites every `<old>/ainra…` form in tracked files (URLs, `gh -R <old>/ainra`, `<old>/ainra-website`) and the
# `[Unreleased]:` compare link of CHANGELOG.md, and with --apply it adds the new owner to the link check's accepted
# owners (every earlier owner stays accepted: the records it leaves alone still link to them). It leaves alone what
# "What keeps the old owner" in docs/ORG-MOVE.md lists: the historical records (and the published news entries inside
# site/news.html), the trusted-publisher settings, and the MCP registry name `io.github.<old>/…`. <old> is the current
# owner, read from the CI badge on README.md (which this tool moves, so it never goes stale); AINRA_OLD_OWNER overrides.
set -euo pipefail
cd "$(dirname "$0")/.."
BADGE_OWNER=$(sed -nE 's#.*\(https://github\.com/([A-Za-z0-9-]+)/ainra/actions/workflows/ci\.yml/badge\.svg\).*#\1#p' README.md | head -1)
OLD="${AINRA_OLD_OWNER:-$BADGE_OWNER}"
[ -n "$OLD" ] || { echo "cannot read the current owner from the CI badge in README.md; set AINRA_OLD_OWNER"; exit 2; }
NEW="${1:-}"; APPLY="${2:-}"
[ -n "$NEW" ] || { echo "usage: bash tools/org-rename.sh <new-owner> [--apply]"; exit 2; }
[ "$NEW" != "$OLD" ] || { echo "new owner is the same as the old one ($OLD): nothing to do"; exit 2; }
SKIP='^(docs/releases/|docs/_archive/|site/news\.(json|xml)$|docs/PUBLISHING\.md$|\.github/workflows/publish\.yml$|tools/org-rename\.sh$|tools/link-check\.mjs$|docs/ORG-MOVE\.md$)'
mapfile -t cand < <(git grep -lI -e "$OLD/ainra" | grep -Ev "$SKIP" || true)
echo "owner: $OLD → $NEW · $([ "$APPLY" = "--apply" ] && echo APPLY || echo 'DRY RUN (pass --apply to write)')"
OLD="$OLD" NEW="$NEW" APPLY="$APPLY" python3 - "${cand[@]}" <<'PY'
import os, re, sys
old, new, apply = os.environ["OLD"], os.environ["NEW"], os.environ["APPLY"] == "--apply"
pat = re.compile(r"(?<!io\.github\.)" + re.escape(old) + r"/ainra")   # the MCP registry name is not a URL to move
sub = lambda t: pat.sub(new + "/ainra", t)
total = 0
for f in sys.argv[1:]:
    s = open(f, encoding="utf-8").read()
    if f == "CHANGELOG.md":                 # entries are records; only the [Unreleased] compare link is current
        lines = s.split("\n")
        n = sum(1 for l in lines if l.startswith("[Unreleased]:") and pat.search(l))
        out = "\n".join(sub(l) if l.startswith("[Unreleased]:") else l for l in lines)
    elif f == "site/news.html":             # published news entries are records: only the page around them moves
        a, b = s.index("<!--news:start-->"), s.index("<!--news:end-->")
        n = len(pat.findall(s[:a])) + len(pat.findall(s[b:]))
        out = sub(s[:a]) + s[a:b] + sub(s[b:])
    else:
        n = len(pat.findall(s)); out = sub(s)
    if n:
        total += 1; print(f"  {f} ({n})")
        if apply: open(f, "w", encoding="utf-8").write(out)
print(f"  {total} file(s); historical records, the published news entries, trusted-publisher settings and the MCP registry name left alone")
PY
[ "$APPLY" = "--apply" ] || exit 0
# The link check accepts every owner the repository has had (their URLs redirect, and the records above keep them):
# put the new owner first in the owner group between `github\.com\/` and `\/ainra`, keeping all the others.
OLD="$OLD" NEW="$NEW" python3 - <<'PY'
import os
old, new = os.environ["OLD"], os.environ["NEW"]
p = "tools/link-check.mjs"; s = open(p).read()
key, tail = "github\\.com\\/", "\\/ainra"
i = s.index(key) + len(key); j = s.index(tail, i)
grp = s[i:j]
owners = grp[3:-1].split("|") if grp.startswith("(?:") and grp.endswith(")") else [grp]
owners = [new] + [o for o in [old] + owners if o != new]
owners = list(dict.fromkeys(owners))
s = s[:i] + "(?:" + "|".join(owners) + ")" + s[j:]
open(p, "w").write(s)
PY
# One command per line: under `set -e` a failure of any of them stops the tool with that failure.
make -s site >/dev/null
make -s site-check
# The month's operator report carries a digest of a package manifest this just rewrote: regenerate it and check it.
node tools/monthly-report.mjs >/dev/null
node tools/monthly-report.mjs --check
