#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# make site-net — publish the staging network's read contract into site/net/, and stamp WHEN.
#
# The site ships a copy of the contract so the record browses on any static host, not only next to a running
# network. That copy needs a publication date, and on a PINNED network it cannot borrow one from the data:
# `generated_window.verified_at` is then `seed.rs::VERIFY_NOW`, a pinned constant the staging network computes its
# validity window against. It is the same number in a record published today and one published a year ago — reading
# it as an age says "110 days old" about a file that is byte-identical to what the network is serving this second.
# So the stamp is written here, at the moment of copying, by the thing doing the copying.
#
# The stamp also says which clock the network keeps ("clock": "pinned" or "wall"), taken from the network's own
# statement (index.json, tools/net-clock.mjs). On a network that keeps real time verified_at is a real date: when
# the network last published its record. The copy's date is still the stamp's, because the copy is what ages.
#
#   make site-net          refresh site/net/ from a reachable contract and stamp site/net/published.json
#   make site-net-check    is the committed copy still what the network serves? (needs a running network)
#
# --check never writes and never guesses: no network, no verdict.
#
# WHAT THE CHECK MEANS, BY CLOCK
#   pinned   the copy is byte for byte what the network serves. A pinned registrar signs at the instant it is asked
#            for, so nothing in the record changes unless the record does.
#   wall     a network that keeps real time signs each registrar's head and status list again at every publish, at
#            the time it runs, so byte for byte holds only until its next publish. The check asks what a copy must
#            still share with its network:
#              identical     the roots; the directory; the epoch history; the index apart from verified_at; each
#                            registrar's accreditation; and every passport the copy lists: the same claims, the same
#                            issuer signatures, the same place in the log, the same answer (revoked or not, and the
#                            verdict published beside it)
#              only forward  verified_at; each log (the same size with the same root, or longer, and nothing inside
#                            the size the copy published that the copy does not list); each status sequence, status
#                            list date and fresh head; the status deltas (the copy's are the first of the network's)
#              may differ    the signatures over heads and status lists; the checkpoint a passport is proven under;
#                            passports issued after the copy was taken (named, not refused: `make site-net`
#                            publishes them)
#            Anything else is drift, named line by line. `make site-net-check` then runs tools/record-agrees.mjs,
#            which verifies every passport of the copy at its registrar.
#
# AINRA_CONTRACT names the network's read contract and AINRA_SITE_NET_DEST the copy (a drill points both at throwaway
# places); unset, they are the standing network and site/net/.
set -uo pipefail
cd "$(dirname "$0")/.."

MODE="${1:-publish}"
SRC="${AINRA_CONTRACT:-http://127.0.0.1:8091}"
DEST="${AINRA_SITE_NET_DEST:-site/net}"
FILES="index.json registry.json directory.json roots.json"

fetch_to() { curl -fsS -m 10 "$SRC/$1" -o "$2" 2>/dev/null; }

probe=$(curl -s -m 10 -o /dev/null -w '%{http_code}' "$SRC/index.json" 2>/dev/null)
[ -n "$probe" ] || probe=000
if [ "$probe" != "200" ]; then
  echo "site-net: no contract at $SRC (HTTP $probe) — run 'make stage-install' or 'make stage-all' first."
  echo "site-net: refusing to $MODE against a network that is not answering."
  exit 2
fi

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
for f in $FILES; do
  fetch_to "$f" "$TMP/$f" || { echo "site-net: contract answered but did not serve $f — aborting"; exit 2; }
done

# Each registrar's own tree travels with the record, and every file in it must be a JSON document the network
# actually served. Until 2026-11-04 only accreditation.json was refreshed here, so the published
# registrars/registrar-07/status/current.json stayed the 3 August list — revoking another passport than the
# 17 August registry.json beside it did — and ainra.org served the two together for months.
REG_FILES="accreditation.json export.json fresh-head.json status/current.json status/deltas.json"
json_ok() { [ -s "$1" ] && node -e 'JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"))' "$1" 2>/dev/null; }
for reg in $(node -e 'for (const r of JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).registrars||[]) console.log(r)' "$TMP/index.json"); do
  mkdir -p "$TMP/registrars/$reg/status" "$TMP/registrars/$reg/checkpoints"
  for f in $REG_FILES; do
    { fetch_to "registrars/$reg/$f" "$TMP/registrars/$reg/$f" && json_ok "$TMP/registrars/$reg/$f"; } \
      || { echo "site-net: $reg's $f is missing, empty or not JSON on the network — refusing to $MODE over it"; exit 2; }
  done
  cp_name=$(node -e 'const r=(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).records||[])[0]?.record;if(r)console.log(r.checkpoint_size)' "$TMP/registrars/$reg/export.json")
  if [ -n "$cp_name" ]; then
    { fetch_to "registrars/$reg/checkpoints/$cp_name.json" "$TMP/registrars/$reg/checkpoints/$cp_name.json" && json_ok "$TMP/registrars/$reg/checkpoints/$cp_name.json"; } \
      || { echo "site-net: $reg's checkpoints/$cp_name.json is not served — refusing to $MODE over it"; exit 2; }
  fi
done
TREE=$(cd "$TMP" && find registrars -type f | sort)

# The clock the network states (tools/net-clock.mjs): it decides what the check compares, the instant a probe names,
# and what the stamp says.
CLOCK_LINE="$(node tools/net-clock.mjs "$TMP" 2>/dev/null)" \
  || { echo "site-net: the network's index.json states a clock this cannot read — refusing to $MODE over it"; exit 2; }
CLOCK="${CLOCK_LINE%% *}"
case "$CLOCK" in wall|pinned) ;; *) echo "site-net: could not tell which clock the network keeps (tools/net-clock.mjs said '$CLOCK_LINE') — refusing to $MODE"; exit 2 ;; esac
NOWQ=""; [ "$CLOCK" = pinned ] && NOWQ="&now=1776729600"

if [ "$MODE" = "check" ]; then
  drift=0
  if [ "$CLOCK" = wall ]; then
    # The epoch history the network serves, when it serves one (a network under a signed directory does).
    if fetch_to "epochs.json" "$TMP/epochs.json" && json_ok "$TMP/epochs.json"; then
      mkdir -p "$TMP/epochs"
      for n in $(node -e 'for (const e of JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).epochs||[]) if (Number.isInteger(e.epoch)) console.log(e.epoch)' "$TMP/epochs.json"); do
        { fetch_to "epochs/$n.json" "$TMP/epochs/$n.json" && json_ok "$TMP/epochs/$n.json"; } \
          || { echo "site-net: the network lists epoch $n and does not serve it — refusing to check against it"; exit 2; }
      done
    else rm -f "$TMP/epochs.json"; fi
    node --input-type=module - "$TMP" "$DEST" "$SRC" <<'JS' || drift=1
import { readFileSync, existsSync, readdirSync } from "node:fs";
const [, net, copy, src] = process.argv.slice(1);
const text = (d, f) => readFileSync(`${d}/${f}`, "utf8");
const json = (d, f) => JSON.parse(text(d, f));
const has = (d, f) => existsSync(`${d}/${f}`);
const canon = (v) => JSON.stringify(v, (k, x) => (x && typeof x === "object" && !Array.isArray(x) ? Object.fromEntries(Object.keys(x).sort().map((y) => [y, x[y]])) : x));
let bad = 0; const drift = (m) => { console.log(`site-net: DRIFT — ${m}`); bad++; };
const notes = [];
const same = (f, what) => { if (!has(copy, f)) drift(`${copy}/${f} is missing, and the network serves it`); else if (text(net, f) !== text(copy, f)) drift(`${copy}/${f} differs from what ${src} serves now (${what})`); };
const forward = (what, was, is) => { if (!(Number.isFinite(was) && Number.isFinite(is)) || is < was) drift(`${what} went back: the copy has ${was}, the network ${is}`); };

same("roots.json", "the roots must be identical");
same("directory.json", "the directory must be identical: a newer epoch is published with make site-net");

// the index: everything but the time the network last published
if (!has(copy, "index.json")) drift(`${copy}/index.json is missing`);
else {
  const a = json(net, "index.json"), b = json(copy, "index.json");
  if ((b.clock ?? "pinned") !== "wall") drift(`the copy was taken when the network was pinned, and the network now keeps real time — make site-net`);
  forward("index.json verified_at", b.generated_window?.verified_at, a.generated_window?.verified_at);
  const strip = (x) => { const y = structuredClone(x); if (y.generated_window) delete y.generated_window.verified_at; return canon(y); };
  if (strip(a) !== strip(b)) drift(`${copy}/index.json differs from the network's in more than its verified_at`);
}

// the epoch history
if (has(net, "epochs.json")) {
  const list = (d) => (json(d, "epochs.json").epochs || []).map((e) => `${e.epoch}:${e.digest}`);
  if (!has(copy, "epochs.json")) drift(`the network serves an epoch history and the copy has none`);
  else {
    const a = list(net), b = list(copy);
    if (a.join() !== b.join()) drift(`the epoch history differs: the network lists epochs ${a.map((x) => x.split(":")[0]).join(", ") || "none"}, the copy ${b.map((x) => x.split(":")[0]).join(", ") || "none"} (or one of their digests differs)`);
    else for (const e of json(net, "epochs.json").epochs || []) {
      const f = `epochs/${e.epoch}.json`;
      if (!has(copy, f)) drift(`${copy}/${f} is missing`); else if (canon(json(net, f)) !== canon(json(copy, f))) drift(`${copy}/${f} is not the directory the network serves at epoch ${e.epoch}`);
    }
  }
} else notes.push("the network serves no epoch history, so none was compared");

// each registrar
const ids = json(net, "index.json").registrars || [];
let passports = 0, grown = 0;
for (const id of ids) {
  const at = `registrars/${id}`;
  if (!has(copy, `${at}/export.json`)) { drift(`${copy}/${at}/export.json is missing: the copy does not have this registrar`); continue; }
  same(`${at}/accreditation.json`, "a registrar's keys must be identical");
  const N = json(net, `${at}/export.json`), C = json(copy, `${at}/export.json`);
  const head = (x) => { let size = 0, root = ""; for (const e of x.records || []) if ((e.record.checkpoint_size || 0) >= size) { size = e.record.checkpoint_size || 0; root = e.record.checkpoint_root || ""; } return { size, root }; };
  const hn = head(N), hc = head(C);
  if (hn.size < hc.size) drift(`${id}: the log shrank: the copy published size ${hc.size}, the network is at ${hn.size}`);
  else if (hn.size === hc.size && hn.root !== hc.root) drift(`${id}: another log root at size ${hc.size} than the copy published — a forked log`);
  const byName = new Map((N.records || []).map((e) => [e.record.sub, e]));
  const listed = new Set();
  for (const e of C.records || []) {
    const r = e.record, n = byName.get(r.sub); passports++; listed.add(r.sub);
    if (!n) { drift(`${r.sub}: the copy lists it, and the network no longer does`); continue; }
    const q = n.record;
    if (q.claims !== r.claims || q.issuer_sig_ed25519 !== r.issuer_sig_ed25519 || q.issuer_sig_mldsa65 !== r.issuer_sig_mldsa65 || q.leaf_index !== r.leaf_index) {
      drift(`${r.sub}: the network lists another passport under this name (the claims, an issuer signature or the place in the log differ)`); continue; }
    if (!!q.revoked !== !!r.revoked) drift(`${r.sub}: the copy shows it ${r.revoked ? "revoked" : "not revoked"}, the network ${q.revoked ? "revoked" : "not revoked"} — make site-net`);
    else if (canon(n.verdict) !== canon(e.verdict)) drift(`${r.sub}: the copy shows ${canon(e.verdict)}, the network ${canon(n.verdict)} — make site-net`);
  }
  for (const e of N.records || []) {
    if (listed.has(e.record.sub)) continue;
    if (e.record.leaf_index < hc.size) drift(`${e.record.sub}: the network lists it at place ${e.record.leaf_index}, inside the log the copy published (size ${hc.size}), and the copy does not`);
    else grown++;
  }
  forward(`${id}: status sequence`, C.status_seq, N.status_seq);
  forward(`${id}: the status list's date`, C.status_list?.issued_at, N.status_list?.issued_at);
  const fh = (d) => (has(d, `${at}/fresh-head.json`) ? json(d, `${at}/fresh-head.json`) : null), fn = fh(net), fc = fh(copy);
  if (!fc) drift(`${copy}/${at}/fresh-head.json is missing`); else { forward(`${id}: fresh head sequence`, fc.seq, fn.seq); forward(`${id}: fresh head time`, fc.ts, fn.ts); }
  const cur = (d) => (has(d, `${at}/status/current.json`) ? json(d, `${at}/status/current.json`) : null), cn = cur(net), cc = cur(copy);
  if (!cc) drift(`${copy}/${at}/status/current.json is missing`); else forward(`${id}: the current status list's date`, cc.issued_at, cn.issued_at);
  const del = (d) => (has(d, `${at}/status/deltas.json`) ? json(d, `${at}/status/deltas.json`).deltas || [] : null), dn = del(net), dc = del(copy);
  const key = (x) => canon([x.seq, x.from_seq, x.idx, x.new_status, x.uri]);
  if (!dc) drift(`${copy}/${at}/status/deltas.json is missing`);
  else if (dc.length > dn.length || dc.some((x, i) => key(x) !== key(dn[i]))) drift(`${id}: the copy's status deltas are not the first ${dc.length} of the network's ${dn.length}`);
  // a checkpoint the copy published and the network still serves at the same height must be the same one
  if (has(copy, `${at}/checkpoints`)) for (const f of readdirSync(`${copy}/${at}/checkpoints`)) {
    if (has(net, `${at}/checkpoints/${f}`) && canon(json(net, `${at}/checkpoints/${f}`)) !== canon(json(copy, `${at}/checkpoints/${f}`))) drift(`${id}: checkpoints/${f} differs from the one the network serves at that height`);
  }
}
// a registrar tree the copy has and the network does not
if (has(copy, "registrars")) for (const id of readdirSync(`${copy}/registrars`)) if (!ids.includes(id)) drift(`${copy}/registrars/${id} is published, and the network no longer lists that registrar`);
if (grown) notes.push(`the network has ${grown} passport${grown === 1 ? "" : "s"} issued after this copy was taken; make site-net publishes ${grown === 1 ? "it" : "them"}`);
for (const n of notes) console.log(`site-net: note — ${n}`);
if (!bad) console.log(`site-net: on a network that keeps real time: roots, directory, epoch history and ${passports} passport${passports === 1 ? "" : "s"} identical; heads and status are the network's own, the same or newer`);
process.exit(bad ? 1 : 0);
JS
  else
  for f in $FILES $TREE; do
    if ! cmp -s "$TMP/$f" "$DEST/$f"; then echo "site-net: DRIFT — $DEST/$f differs from what $SRC serves now"; drift=1; fi
  done
  for f in $(cd "$DEST" && find registrars -type f 2>/dev/null | sort); do
    [ -f "$TMP/$f" ] || { echo "site-net: DRIFT — $DEST/$f is published but the network no longer serves it"; drift=1; }
  done
  fi
  # The byte-comparison above proves the published copy matches what the ARTIFACT SERVER serves. It does NOT prove
  # the REGISTRAR can still present the passports that record describes — and those are different machines with
  # different state. This gate said "byte-identical" for days while the registrar had regressed behind the record
  # after a restart and answered `unknown subject` for a passport the record listed. The artifact server serves
  # files from disk; the registrar serves from its own reloaded state. A record nobody can honour is not a record.
  reg_drift=0
  first_sub=$(curl -s -m 10 "$SRC/registry.json" 2>/dev/null \
    | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const r=JSON.parse(s);for(const R of r.registrars||[])for(const e of R.records||[]){const x=e.record?.sub||e.sub;if(x){console.log(x);process.exit(0)}}}catch{}})' 2>/dev/null)
  if [ -n "$first_sub" ]; then
    REG_URL="${AINRA_REG:-http://127.0.0.1:4907}"
    body=$(curl -s -m 10 "$REG_URL/present?sub=$(node -e 'process.stdout.write(encodeURIComponent(process.argv[1]))' "$first_sub")$NOWQ" 2>/dev/null)
    case "$body" in
      *'"claims"'*) echo "site-net: registrar can present a sampled subject from the record" ;;
      *) echo "site-net: DRIFT — the record lists a subject the registrar cannot present:"
         echo "site-net:   subject : $first_sub"
         echo "site-net:   answer  : $(printf '%s' "$body" | head -c 120)"
         echo "site-net: the registrar has regressed behind the published record (restart without its state?)."
         reg_drift=1 ;;
    esac
  fi
  if [ "$drift" -eq 0 ] && [ "$reg_drift" -ne 0 ]; then exit 1; fi
  if [ "$drift" -eq 0 ] && [ "$CLOCK" = wall ]; then
    echo "site-net OK: the published record agrees with the running network, which keeps real time ($(wc -w <<< "$FILES $TREE") files read)"
  elif [ "$drift" -eq 0 ]; then
    echo "site-net OK: the published record is byte-identical to the running network ($(echo $FILES $TREE | wc -w) files)"
  else
    echo "site-net: the published record no longer matches the network — run 'make site-net' to republish"
    exit 1
  fi
  exit 0
fi

# PLAN-M52 step 1: keep every epoch — before anything is copied, so a refusal leaves the published copy as it was.
# The archive refuses anything unsigned, an older epoch, and a second directory at an archived epoch, so a republish
# can only add to the history, never rewrite it.
[ -x target/release/ainra ] || cargo build --release -q -p ainra-cli-rs
mkdir -p "$DEST"
# A directory's epochs belong to one root. If the network's root is not the one the site has published, that is a
# change of root, and the site makes it only when someone says so (AINRA_SITE_NEW_ROOT=1, D-109). The history under
# the old root stays published, under its fingerprint, with the day it was retired; a new history starts beside it.
if [ -f "$DEST/roots.json" ] && [ -f "$DEST/epochs.json" ] \
   && ! node -e 'const fs=require("fs"),j=(p)=>JSON.stringify(JSON.parse(fs.readFileSync(p,"utf8")));process.exit(j(process.argv[1])===j(process.argv[2])?0:1)' "$TMP/roots.json" "$DEST/roots.json"; then
  OLDFP=$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).root_ed25519.slice(0,16))' "$DEST/roots.json")
  if [ "${AINRA_SITE_NEW_ROOT:-0}" != 1 ]; then
    echo "site-net: the network's root is not the root this site has published (genesis:$OLDFP)."
    echo "site-net: a change of root is deliberate — set AINRA_SITE_NEW_ROOT=1 to publish it. Nothing was changed."
    exit 1
  fi
  mkdir -p "$DEST/previous-root/$OLDFP"
  mv "$DEST/epochs" "$DEST/epochs.json" "$DEST/previous-root/$OLDFP/"
  [ -f "$DEST/epoch-log.json" ] && mv "$DEST/epoch-log.json" "$DEST/previous-root/$OLDFP/"
  cp "$DEST/roots.json" "$DEST/previous-root/$OLDFP/roots.json"
  printf '{\n  "retired_at_iso": "%s",\n  "note": "The root this network used until that day. Its epochs are kept here as they were published. The root in ../../roots.json replaced it; docs/DECISIONS.md says why."\n}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$DEST/previous-root/$OLDFP/retired.json"
  echo "site-net: NEW ROOT. The history under genesis:$OLDFP is kept at $DEST/previous-root/$OLDFP/."
fi
./target/release/ainra directory archive "$TMP/directory.json" --roots "$TMP/roots.json" --into "$DEST" \
  || { echo "site-net: the directory the network serves cannot join the epoch history — refusing to publish it"; exit 1; }
for f in $FILES; do cp "$TMP/$f" "$DEST/$f"; done
# The per-registrar trees, whole: a stamped index over stale leaves would be worse than no stamp at all.
rm -rf "$DEST/registrars"; cp -r "$TMP/registrars" "$DEST/registrars"

NOW=$(date -u +%s)
ROOT=$(curl -s -m 10 -D- -o /dev/null "$SRC/registry.json" 2>/dev/null | grep -i '^x-ainra-root:' | tr -d '\r' | awk '{print $2}')
NETW=$(curl -s -m 10 -D- -o /dev/null "$SRC/registry.json" 2>/dev/null | grep -i '^x-ainra-network:' | tr -d '\r' | awk '{print $2}')
{
  printf '{\n  "published_at": %s,\n  "published_at_iso": "%s",\n' "$NOW" "$(date -u -d "@$NOW" +%Y-%m-%dT%H:%M:%SZ)"
  printf '  "network": "%s",\n  "root": "%s",\n' "${NETW:-staging}" "${ROOT:-test-root}"
  # The clock the network states, so a reader of the copy knows how to read its times without asking the network.
  printf '  "clock": "%s",\n' "$CLOCK"
  if [ "$CLOCK" = wall ]; then
    printf '  "note": "When this copy of the read contract was taken from the network. The network keeps real time: generated_window.verified_at is when the network last published its record, at or before this.",\n'
  else
    printf '  "note": "When this copy of the read contract was taken from the network. NOT generated_window.verified_at, which is a pinned staging constant and says nothing about age.",\n'
  fi
  printf '  "sha256": {\n'
  i=0; n=$(echo $FILES | wc -w)
  for f in $FILES; do
    i=$((i+1)); h=$(sha256sum "$DEST/$f" | awk '{print $1}')
    printf '    "%s": "%s"%s\n' "$f" "$h" "$([ "$i" -lt "$n" ] && echo ,)"
  done
  printf '  }\n}\n'
} > "$DEST/published.json"

echo "site-net: published $(echo $FILES | wc -w) files from $SRC — stamped $(date -u -d "@$NOW" +%Y-%m-%dT%H:%M:%SZ)"
