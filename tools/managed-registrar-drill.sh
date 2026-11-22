#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# make managed-registrar-drill — "a registrar in a day": a registrar made and run for an organisation, signed into
# the network, and handed over to the organisation's own machine (tools/managed-registrar.sh), rehearsed end to end.
#
# Beside any real network and touching none of it: a folder of its own under the cache directory, root seeds made for
# the drill, its own GnuPG home, a hand-over passphrase made for the drill and kept in memory, and spare addresses
# (the network on 6107, 6111, 6181, 9217; the managed registrar on 6122; "their machine" on 6132 and 6142; 6152 for
# controls). The network keeps real time (AINRA_STAGE_CLOCK=wall), as a new registrar does. In order:
#
#   1  a throwaway network comes up with its two registrars and its own root
#   2  a managed registrar is created for Example Org: how long it took, what it printed, what it keeps secret
#   3  the root's holder signs it in: the formal request, a wrong fingerprint, the right one, `ainra ctl status`
#   4  it issues and revokes; the repo's own verifier reads both under the network's directory
#   5  the hand-over: packed and sealed, opened on "their machine" (another folder, another address), confirmed;
#      the copy here stopped and its keys destroyed
#   6  at its new home: the same log, grown and not rewritten; earlier passports still verify; new ones are issued
#      and a revocation made there is seen
#   7  no token and no passphrase in anything the tool or this drill wrote
#   8  keys the operator never held, with what exists today: a second registrar the organisation makes itself,
#      signed in under an id of its own, both started with the roots the lineage transfer doors (D-102) need
#   P  the same start on a network that is still pinned (as the published test network is)
#
# WITNESS: negative controls, each of which must fail in its own way or the drill fails.
#   2  keys recomputed from the id (a pinned registrar-box with the same id) are NOT the managed registrar's keys; a
#      write with no token is refused although the caller's shell exports AINRA_OPEN_WRITES=1; a pinned clock in the
#      caller's shell does not pin it; a second create with the same id, an id the directory already names, and an id
#      the grammar refuses are each refused and change nothing
#   3  a wrong fingerprint is refused by name, with the signed directory unchanged
#   4  the revoked passport is refused as `revoked` by the verifier that accepts the other
#   5  while the hand-over is open the copy here cannot be started; the package is not readable without the
#      passphrase, does not open with a wrong one, nor after one byte is changed, nor under another id, and each
#      refusal leaves nothing behind; the old write token is refused at the new home; a confirmation pointed at
#      another registrar, and one with the id mistyped, destroy nothing; afterwards the old folder cannot be started
#      as that registrar by the tool or by registrar-box itself, and its id cannot be created again; a hand-over
#      whose output is cut off after one line still finishes
#   8  a registrar started with no roots says nothing about its transfer doors at start (they stay closed)
#   P  `ainra ctl status` at the real clock raises the three alarms a pinned network raises anyway, none about the
#      new registrar; read at the pinned instant, the managed registrar's passport is `stale_status`: the stated
#      limit of a registrar keeping real time inside a pinned record (D-120)
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
{ [ -f packages/sdk-ts/dist/index.js ] && [ -f packages/sdk-ts/dist/conformance.js ]; } || make -s sdk-build >/dev/null
for b in registrar-box witnessd accredit ainra; do
  [ -x "target/release/$b" ] || { echo "managed-registrar-drill: target/release/$b is not built (make managed-registrar-drill builds it)"; exit 2; }
done
command -v gpg >/dev/null || { echo "managed-registrar-drill: GnuPG (gpg) is needed to seal the hand-over package"; exit 2; }

# Nothing a caller's shell happens to export may steer the throwaway networks, the registrars or the tool.
unset AINRA_STAGE_CLOCK AINRA_STAGE_RESIGN AINRA_STAGE_NEW_ROOT AINRA_STAGE_TAKE_BACK AINRA_CLOCK AINRA_STAGE_DIR \
      AINRA_STAGE_ROOT_SEED AINRA_MANAGED_DIR AINRA_MANAGED_PASSPHRASE_FILE AINRA_FRESH_KEYS AINRA_ROOTS_FILE \
      AINRA_STAGE_ISSUE_TOKEN AINRA_OPEN_WRITES AINRA_TEST_DERIVED_KEYS AINRA_STAGE AINRA_NETWORK AINRA_PRINCIPAL_CHECKER
R1=127.0.0.1:6107 ; R2=127.0.0.1:6111 ; WIT=127.0.0.1:6181 ; ARTP=9217
OURS=127.0.0.1:6122 ; THEIRS=127.0.0.1:6132 ; OWN=127.0.0.1:6142 ; SPARE=127.0.0.1:6152
PORTS=(6107 6111 6181 9217 6122 6132 6142 6152)
ID=registrar-example-org ; ID2=registrar-example-org-2
PINNED_NOW=$((1775865600 + 10*24*3600))
taken(){ (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
for p in "${PORTS[@]}"; do
  taken "$p" && { echo "managed-registrar-drill: something already listens on :$p — not starting"; exit 2; }
done
T="$(mktemp -d -p "${XDG_CACHE_HOME:-$HOME/.cache}" ainra-managed-drill-XXXXXX)" || exit 2
O="$T/out"; mkdir -p "$O"
export GNUPGHOME="$T/gnupg"; mkdir -m 700 "$GNUPGHOME"
# The hand-over passphrase: made for this run, kept in memory when the machine has a RAM file system, read by the
# tool from the file (AINRA_MANAGED_PASSPHRASE_FILE, tests only) and never echoed. A wrong one beside it.
RAM="$(mktemp -d -p "${XDG_RUNTIME_DIR:-/dev/shm}" ainra-managed-drill-XXXXXX 2>/dev/null)" || RAM="$T/ram"
mkdir -p "$RAM"; chmod 700 "$RAM"
( umask 077; head -c 24 /dev/urandom | base64 > "$RAM/pass"; head -c 24 /dev/urandom | base64 > "$RAM/wrong" )

bad=0
ok(){ echo "  ok    $1" | tee -a "$O/lines"; }
fail(){ echo "  ✗     $1" | tee -a "$O/lines"; bad=1; }
show(){ sed 's/^/        | /' "$1" | cut -c1-230; }
# net / pnet <stage.sh arguments…> — every call names its own folder, its own root seed and all four addresses.
net(){ AINRA_STAGE_DIR="$T/net" AINRA_STAGE_ROOT_SEED="$T/net-root.seed" AINRA_STAGE_CLOCK=wall AINRA_STAGE_REG1="$R1" \
       AINRA_STAGE_REG2="$R2" AINRA_STAGE_WIT="$WIT" AINRA_STAGE_ART="$ARTP" bash tools/stage.sh "$@"; }
pnet(){ AINRA_STAGE_DIR="$T/pinned" AINRA_STAGE_ROOT_SEED="$T/pinned-root.seed" AINRA_STAGE_REG1="$R1" \
        AINRA_STAGE_REG2="$R2" AINRA_STAGE_WIT="$WIT" AINRA_STAGE_ART="$ARTP" bash tools/stage.sh "$@"; }
# mr <ours|theirs|pours> <arguments…> — the tool, on one of the "machines": each is a folder of its own.
mr(){ local base="$1"; shift; AINRA_MANAGED_DIR="$T/$base" bash tools/managed-registrar.sh "$@"; }
pids=()
# shellcheck disable=SC2329  # run by the EXIT trap
cleanup(){
  local b d
  for b in ours theirs pours; do
    for d in "$T/$b"/registrar-*/; do [ -d "$d" ] && mr "$b" stop "$(basename "$d")" >/dev/null 2>&1; done
  done
  for p in "${pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
  # A registrar of this drill whose pid file was lost (a sabotaged tool leaves one): found by its data folder, which
  # is under this run's own temporary folder and nowhere else.
  pkill -f "registrar-box [^ ]+ [^ ]+ $T/" 2>/dev/null
  net down >/dev/null 2>&1
  pnet down >/dev/null 2>&1
  gpgconf --kill gpg-agent >/dev/null 2>&1
  rm -rf "$T" "$RAM"
}
trap cleanup EXIT
started=$(date +%s)

jget(){ node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const v=process.argv[1].split(".").reduce((o,k)=>o?.[k],JSON.parse(s));if(v!==undefined&&v!==null)process.stdout.write(String(v))}catch{}})' "$1"; }
enc(){ node -e 'process.stdout.write(encodeURIComponent(process.argv[1]))' "$1"; }
sum(){ sha256sum "$1" 2>/dev/null | cut -c1-64; }
fp(){ node tools/registrar-fingerprint.mjs "$1" 2>/dev/null; }
head_of(){ curl -s -m 10 "http://$1/witness-feed" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const c=JSON.parse(s).checkpoint;process.stdout.write(c.origin+" "+c.size+" "+c.root)}catch{}})'; }
signed_at(){ ./target/release/ainra directory digest "$1" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const j=JSON.parse(s);process.stdout.write(j.epoch+" "+j.issued_at)}catch{}})'; }
free_ports(){ local busy; for _ in $(seq 1 60); do busy=0; for p in "${PORTS[@]}"; do taken "$p" && busy=1; done; [ "$busy" = 0 ] && break; sleep 0.25; done; }
# The write token goes to curl on its standard input, never on a command line.
auth(){ printf 'header = "Authorization: Bearer %s"\n' "$(cat "$1")"; }
# issue <token file> <addr> <lineage> — prints the new passport's name (or what the registrar answered instead)
issue(){
  auth "$1" | curl -s -m 10 -K - -H 'Content-Type: application/json' \
    -d "{\"operator\":\"example-operator\",\"lineage\":\"$3\",\"version\":\"1.0.0\",\"tier\":\"L1\",\"auth_class\":\"A2\",\"principal_proof\":\"deadbeefdrill\",\"capabilities\":[\"read:x\"],\"scope_ceiling\":[\"read:x\"],\"hops\":[]}" \
    "http://$2/issue" | jget sub
}
revoke(){ auth "$1" | curl -s -m 10 -K - -H 'Content-Type: application/json' -d "{\"sub\":\"$3\"}" "http://$2/revoke"; }
# sdk <public dir> <addr> <passport> [verifier arguments…] — the registrar at <addr> presents the passport, and the
# repo's verifier checks the bundle against the network's published directory and roots, at this machine's clock
# unless told otherwise. Prints the verifier's one line; returns its exit.
sdk(){
  local pub="$1" addr="$2" sub="$3"; shift 3
  rm -f "$T/bundle.json"
  curl -fsS -m 10 "http://$addr/present?sub=$(enc "$sub")" -o "$T/bundle.json" 2>/dev/null || { echo "no presentation from $addr"; return 9; }
  node tools/ainra-verify.mjs --directory "$pub/directory.json" --roots "$pub/roots.json" --bundle "$T/bundle.json" "$@" 2>&1
}
ctl(){ ./target/release/ainra ctl status --net "$1" --roots "$1/roots.json" --state "$2" --fresh-max 600 "${@:3}" 2>&1; }
secs(){ echo "$(( $1 / 1000 )).$(printf '%03d' $(( $1 % 1000 )))"; }

echo "1 · a throwaway network that keeps real time, with its own root"
PUB="$T/net/public"
net up > "$O/net-up.log" 2>&1
if [ -s "$PUB/directory.json" ] && [ -s "$PUB/roots.json" ]; then
  read -r epoch _ <<< "$(signed_at "$PUB/directory.json")"
  ok "up: two registrars, a signed directory at epoch $epoch, a root made for this drill"
else fail "the throwaway network did not come up:"; tail -n 15 "$O/net-up.log"; echo "MANAGED REGISTRAR DRILL FAILED"; exit 1; fi

echo "2 · a managed registrar for Example Org"
# The control for "keys never derived from the id": what anyone can recompute from the id alone. Started with no roots,
# it is also the control for step 8.
AINRA_CLOCK=pinned ./target/release/registrar-box "$SPARE" "$ID" "$T/derived" > "$O/derived.log" 2>&1 & dpid=$!; pids+=("$dpid")
for _ in $(seq 1 60); do curl -s -m 1 -o /dev/null "http://$SPARE/accreditation" && break; sleep 0.25; done
derived="$(fp "http://$SPARE")"
kill "$dpid" 2>/dev/null; wait "$dpid" 2>/dev/null
# Created with a hostile shell around it: a pinned clock, keys asked to derive from the id, writes asked to be open.
t0=$(date +%s%N)
AINRA_CLOCK=pinned AINRA_TEST_DERIVED_KEYS=1 AINRA_OPEN_WRITES=1 \
  mr ours create example-org --name "Example Org" --addr "$OURS" --net "$PUB" --roots "$PUB/roots.json" > "$O/create.out" 2>&1; rc=$?
ms=$(( ( $(date +%s%N) - t0 ) / 1000000 ))
F="$T/ours/$ID"
mine="$(fp "http://$OURS")"
if [ "$rc" = 0 ] && [ "$ms" -lt 60000 ] && [ "$(curl -s -m 5 "http://$OURS/health" | jget registrar)" = "$ID" ] \
   && [ "$(stat -c %a "$F")" = 700 ] && [ "$(jget organisation < "$F/managed.json")" = "Example Org" ]; then
  ok "2a created and answering in $(secs "$ms") s of machine time: id $ID, its own folder (0700), its own address ($OURS)"
else fail "2a create did not give a running registrar within a minute (exit $rc, ${ms} ms):"; show "$O/create.out"; echo "MANAGED REGISTRAR DRILL FAILED"; exit 1; fi
show "$O/create.out"
entry="$(grep -m1 '^ *{"id": ' "$O/create.out" | sed 's/^ *//')"
if [ -n "$mine" ] && grep -qF "accreditation   http://$OURS/accreditation" "$O/create.out" && grep -qF "fingerprint     $mine" "$O/create.out" \
   && [ "$(echo "$entry" | jget fingerprint)" = "${mine#* }" ] && [ "$(echo "$entry" | jget url)" = "http://$OURS" ] \
   && grep -q "ainra directory request ACCREDIT --registrar $F/data" "$O/create.out"; then
  ok "2b it printed what the root's holder needs: the accreditation's address, the fingerprint (the one registrar-fingerprint.mjs computes from the address), the list entry, the formal request"
else fail "2b create did not print the address, the served fingerprint, the list entry and the request command"; fi
tok_ours="$(cat "$F/.issue-token")"
if [ "$(stat -c %a "$F/.issue-token")" = 600 ] && [[ "$tok_ours" =~ ^[0-9a-f]{64}$ ]] && ! grep -qF "$tok_ours" "$O/create.out" \
   && [ "$(stat -c %a "$F/data/registrar.secret")" = 600 ] && [ "$(stat -c %a "$F/data/note.secret")" = 600 ]; then
  ok "2c its write token is 32 bytes from the OS, kept 0600, and not in what create printed; its key files are 0600"
else fail "2c the token or the key files are not kept as they should be, or the token was printed"; fi
code="$(curl -s -m 5 -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -d '{}' "http://$OURS/issue")"
ts="$(curl -s -m 5 "http://$OURS/fresh-head?now=$PINNED_NOW" | jget ts)"
if [ -n "$derived" ] && [ -n "$mine" ] && [ "$derived" != "$mine" ] && [ "$code" = 401 ] && [ -n "$ts" ] && [ "$ts" != "$PINNED_NOW" ]; then
  ok "2d its keys are not the ones anyone can derive from its id (sha256:$(cut -c1-12 <<< "${derived#* sha256:}")… ≠ sha256:$(cut -c1-12 <<< "${mine#* sha256:}")…); a write with no token is 401; it keeps real time — whatever the caller's shell exported"
else fail "2d the caller's shell steered the registrar: derived keys '${derived#* }', its keys '${mine#* }', a tokenless write answered $code, fresh head at ${ts:-nothing} (pinned instant $PINNED_NOW)"; fi
mr ours stop "$ID" > "$O/stop1.out" 2>&1; mr ours start "$ID" > "$O/start1.out" 2>&1
if [ "$(fp "http://$OURS")" = "$mine" ]; then ok "2e stopped and started before its first passport: the same keys (they were on disk before the fingerprint was printed)"
else fail "2e a restart before the first write changed the registrar's keys: $(fp "http://$OURS") is not $mine"; fi
mr ours create example-org --name "Someone Else" --addr "$SPARE" > "$O/create-again.out" 2>&1; rc1=$?
mr ours create 07 --addr "$SPARE" --net "$PUB" > "$O/create-07.out" 2>&1; rc2=$?
mr ours create Example_Org --addr "$SPARE" > "$O/create-bad.out" 2>&1; rc3=$?
if [ "$rc1" = 1 ] && grep -q "$ID already has a folder here" "$O/create-again.out" && [ "$(fp "http://$OURS")" = "$mine" ] \
   && [ "$(jget organisation < "$F/managed.json")" = "Example Org" ] \
   && [ "$rc2" = 1 ] && grep -q "already names registrar-07 — nothing created" "$O/create-07.out" && [ ! -e "$T/ours/registrar-07" ] \
   && [ "$rc3" = 1 ] && grep -q "cannot be a registrar id" "$O/create-bad.out" && ! taken 6152; then
  ok "2f a second create with the same id is refused and changes nothing; so are an id the directory already names and one the name grammar refuses"
else fail "2f a create that must be refused was not (same id exit $rc1, registrar-07 exit $rc2, bad id exit $rc3):"; tail -n 2 "$O/create-again.out" "$O/create-07.out" "$O/create-bad.out"; fi
mr ours status > "$O/status1.out" 2>&1
if grep -q "^$ID · Example Org" "$O/status1.out" && grep -q "state          running since 20.*listening on $OURS" "$O/status1.out" \
   && grep -q "log            ainra-log/$ID · size 0" "$O/status1.out" && grep -q "directory      epoch 1: not named" "$O/status1.out"; then
  ok "2g status: running for Example Org, since when, log size 0, not yet in the directory (epoch 1)"
else fail "2g status does not say what runs, for whom, since when, how long the log is and that it is not in the directory:"; show "$O/status1.out"; fi

echo "3 · the root's holder signs it in"
for f in agreement independence monitor audit; do echo "drill placeholder: $f" > "$T/$f.txt"; done
node -e 'const fs=require("fs"),c=require("crypto"),d=process.argv[1];const a=(f,date)=>Object.assign({file:f,sha256:c.createHash("sha256").update(fs.readFileSync(d+"/"+f)).digest("hex")},date?{date}:{});
  fs.writeFileSync(d+"/evidence.json",JSON.stringify({prerequisites:{agreement:a("agreement.txt"),independence_attestation:a("independence.txt"),competitor_monitor:a("monitor.txt"),audit:a("audit.txt","2026-11-18")}}))' "$T"
curl -s -m 10 "http://$OURS/accreditation" > "$T/accreditation.json"
if ./target/release/ainra directory request ACCREDIT --registrar "$F/data" --filed-at "$(date +%s)" --test-root \
     --evidence "$T/evidence.json" --out "$T/accredit-request.json" > "$O/request.log" 2>&1 \
   && ./target/release/ainra directory check-request "$T/accredit-request.json" --directory "$PUB/directory.json" \
     --roots "$PUB/roots.json" --accreditation "$T/accreditation.json" > "$O/check-request.log" 2>&1; then
  ok "3a the formal request, as create printed it: signed by each of the registrar's keys, and check-request accepts it against what the address serves"
else fail "3a the formal request was not accepted:"; tail -n 6 "$O/request.log" "$O/check-request.log"; fi
before="$(sum "$PUB/directory.json")"
printf '[{"id":"%s","url":"http://%s","fingerprint":"sha256:%s"}]\n' "$ID" "$OURS" "$(printf '0%.0s' $(seq 1 64))" > "$T/net/genesis/outside-registrars.json"
net accredit > "$O/accredit-wrong.log" 2>&1; rc=$?
read -r epoch _ <<< "$(signed_at "$PUB/directory.json")"
if [ "$rc" != 0 ] && grep -q "not the one $ID's operator fingerprinted" "$O/accredit-wrong.log" && grep -q "nothing accredited, nothing published" "$O/accredit-wrong.log" \
   && [ "$(sum "$PUB/directory.json")" = "$before" ] && [ "$epoch" = 1 ]; then
  ok "3b listed with a wrong fingerprint: refused by name, nothing signed, the directory still epoch 1 and byte for byte what it was"
else fail "3b a wrong fingerprint was not refused with the directory unchanged (exit $rc, epoch $epoch):"; tail -n 4 "$O/accredit-wrong.log"; fi
printf '[%s]\n' "$entry" > "$T/net/genesis/outside-registrars.json"
net accredit > "$O/accredit-right.log" 2>&1; rc=$?
read -r epoch at <<< "$(signed_at "$PUB/directory.json")"
if [ "$rc" = 0 ] && [ "$epoch" = 2 ] && grep -q "accredited at epoch 2 and republished" "$O/accredit-right.log" && [ $(( $(date +%s) - at )) -lt 900 ]; then
  ok "3c listed with the entry create printed: signed in as the next directory epoch (2), dated now"
else fail "3c the right fingerprint was not signed in at epoch 2 (exit $rc, epoch $epoch):"; tail -n 6 "$O/accredit-right.log"; fi
c="$(ctl "$PUB" "$T/ctl.json")"; rc=$?; echo "$c" > "$O/ctl1.out"
if [ "$rc" = 0 ] && grep -q "^CTL OK" <<< "$c" && grep -q "epoch 2 · 3 registrar(s)" <<< "$c" && grep -q "$ID: log size 0 · status seq 0 · fresh head [0-9]*s old" <<< "$c" \
   && ! grep -q "ALARM" <<< "$c"; then
  ok "3d ainra ctl status, with no --now: epoch 2, three registrars, $ID among them, no alarm"
  grep -E "registrar\(s\)|$ID|^CTL" "$O/ctl1.out" | sed 's/^/        | /'
else fail "3d ainra ctl status does not show the new registrar without an alarm (exit $rc):"; tail -n 8 <<< "$c"; fi
mr ours status "$ID" > "$O/status2.out" 2>&1
if grep -q "directory      epoch 2: named, with these keys" "$O/status2.out"; then ok "3e status: named in directory epoch 2, with the keys it serves"
else fail "3e status does not find it in the directory:"; show "$O/status2.out"; fi

echo "4 · it issues, and revokes"
courier="$(issue "$F/.issue-token" "$OURS" courier)"; runaway="$(issue "$F/.issue-token" "$OURS" runaway)"; night="$(issue "$F/.issue-token" "$OURS" night-shift)"
r="$(revoke "$F/.issue-token" "$OURS" "$runaway")"
if [ "$courier" = "ainra:$ID:example-operator:courier@1.0.0" ] && [ -n "$runaway" ] && [ -n "$night" ] && grep -q '"seq"' <<< "$r"; then
  ok "4a issued under the organisation's name: $courier (and two more; one of them revoked)"
else fail "4a it did not issue three passports and revoke one: '$courier' '$runaway' '$night' $(cut -c1-120 <<< "$r")"; fi
v="$(sdk "$PUB" "$OURS" "$courier")"; rc=$?
if [ "$rc" = 0 ] && [ "$v" = "ainra-verify: VALID" ]; then ok "4b the repo's verifier, under the network's directory and roots, at the real clock: $courier is VALID"
else fail "4b the passport does not verify under the network's directory: $v (exit $rc)"; fi
v="$(sdk "$PUB" "$OURS" "$runaway")"; rc=$?
if [ "$rc" = 1 ] && [ "$v" = "ainra-verify: INVALID (revoked)" ]; then ok "4c the revoked one is refused by the same verifier: $v"
else fail "4c the revoked passport was not refused as revoked: $v (exit $rc)"; fi
m="$(./target/release/ainra monitor --registrar "http://$OURS" --net "$PUB" --roots "$PUB/roots.json" --state "$T/watcher.json" 2>&1)"; rc=$?
if [ "$rc" = 0 ] && grep -q "^MONITOR OK" <<< "$m" && grep -q "checkpoint at size 3 is signed under $ID's log key from the directory" <<< "$m"; then
  ok "4d an outside watcher (ainra monitor) takes its first look: the log, at size 3, checks out under the key the directory gives it"
else fail "4d the monitor does not accept the managed registrar's log (exit $rc):"; tail -n 5 <<< "$m"; fi
notekey="$(curl -s -m 5 "http://$OURS/note-key")"; read -r origin0 size0 root0 <<< "$(head_of "$OURS")"

echo "5 · the hand-over"
t0=$(date +%s%N)
AINRA_MANAGED_PASSPHRASE_FILE="$RAM/pass" mr ours handover "$ID" --out "$T/package" > "$O/handover.out" 2>&1; rc=$?
ms=$(( ( $(date +%s%N) - t0 ) / 1000000 ))
PKG="$T/package/$ID.handover.gpg"
if [ "$rc" = 0 ] && [ -s "$PKG" ] && [ "$(stat -c %a "$PKG")" = 600 ] && [ -s "$T/package/START-HERE.txt" ] && [ "$(find "$T/package" -type f | wc -l)" = 2 ] \
   && grep -q "the log         $origin0 · size $size0 at the hand-over" "$O/handover.out"; then
  ok "5a packed in $(secs "$ms") s: one sealed file ($(stat -c %s "$PKG") bytes) and START-HERE.txt; the log's head at the hand-over is recorded (size $size0)"
else fail "5a the hand-over was not packed (exit $rc):"; show "$O/handover.out"; echo "MANAGED REGISTRAR DRILL FAILED"; exit 1; fi
if ! tar -tf "$PKG" >/dev/null 2>&1 && ! grep -qa "registrar.secret" "$PKG" && ! grep -qa "$ID" "$PKG" \
   && ! gpg --batch --quiet --no-symkey-cache --pinentry-mode loopback --passphrase-file /dev/null --decrypt --output /dev/null "$PKG" 2>/dev/null; then
  ok "5b the package is sealed: no archive, no file name and no id can be read from it, and it does not open without a passphrase"
else fail "5b the package can be read without the passphrase"; fi
mr ours start "$ID" > "$O/start-pending.out" 2>&1; rc=$?
if [ "$rc" = 1 ] && grep -q "is being handed over" "$O/start-pending.out" && ! taken 6122 && [ -s "$F/data/registrar.secret" ]; then
  ok "5c here it is stopped, and start is refused while the hand-over is open (its keys are still here until the confirmation)"
else fail "5c the copy here still runs, or can be started, while its package is out (exit $rc)"; fi
if grep -q "$ID" "$T/package/START-HERE.txt" && grep -qF "${mine#* }" "$T/package/START-HERE.txt" \
   && grep -q "managed-registrar.sh receive $ID " "$T/package/START-HERE.txt" && grep -q "$(sum "$PKG")" "$T/package/START-HERE.txt"; then
  ok "5d START-HERE.txt names the registrar, its fingerprint, the package's SHA-256 and the one command that opens it"
else fail "5d START-HERE.txt does not say what the organisation needs"; fi

G="$T/theirs/$ID"
AINRA_MANAGED_PASSPHRASE_FILE="$RAM/wrong" mr theirs receive "$ID" "$PKG" --addr "$THEIRS" > "$O/receive-wrong.out" 2>&1; rc1=$?
left1="$(find "$T/theirs" -mindepth 1 2>/dev/null | wc -l)"
cp "$PKG" "$T/tampered.gpg"; printf '\x00' | dd of="$T/tampered.gpg" bs=1 seek=$(( $(stat -c %s "$PKG") / 2 )) conv=notrunc status=none
AINRA_MANAGED_PASSPHRASE_FILE="$RAM/pass" mr theirs receive "$ID" "$T/tampered.gpg" --addr "$THEIRS" > "$O/receive-tampered.out" 2>&1; rc2=$?
left2="$(find "$T/theirs" -mindepth 1 2>/dev/null | wc -l)"
AINRA_MANAGED_PASSPHRASE_FILE="$RAM/pass" mr theirs receive registrar-someone-else "$PKG" --addr "$THEIRS" > "$O/receive-other.out" 2>&1; rc3=$?
left3="$(find "$T/theirs" -mindepth 1 2>/dev/null | wc -l)"
if [ "$rc1" = 1 ] && grep -q "did not open" "$O/receive-wrong.out" && [ "$left1" = 0 ] \
   && [ "$rc2" = 1 ] && grep -q "nothing kept" "$O/receive-tampered.out" && [ "$left2" = 0 ] \
   && [ "$rc3" = 1 ] && grep -q "the package is $ID, not registrar-someone-else" "$O/receive-other.out" && [ "$left3" = 0 ] && ! taken 6132; then
  ok "5e it does not open with a wrong passphrase, nor with one byte changed, nor under another id; each refusal leaves no file behind and starts nothing"
else fail "5e a package that must be refused was not, or left something (wrong passphrase exit $rc1 left $left1; tampered exit $rc2 left $left2; other id exit $rc3 left $left3)"; fi
AINRA_MANAGED_PASSPHRASE_FILE="$RAM/pass" mr theirs receive "$ID" "$PKG" --addr "$THEIRS" --net "$PUB" > "$O/receive.out" 2>&1; rc=$?
read -r origin1 size1 root1 <<< "$(head_of "$THEIRS")"
if [ "$rc" = 0 ] && [ "$(fp "http://$THEIRS")" = "$mine" ] && [ "$(curl -s -m 5 "http://$THEIRS/note-key")" = "$notekey" ] && [ -n "$notekey" ] \
   && [ "$origin1 $size1 $root1" = "$origin0 $size0 $root0" ] && [ "$origin1" = "ainra-log/$ID" ] && [ "$G" != "$F" ]; then
  ok "5f opened with the passphrase into another folder and started on another address ($THEIRS): the same keys, the same log (origin, size $size1, root), the same note key"
else fail "5f the package did not come up as the same registrar (exit $rc):"; show "$O/receive.out"; echo "MANAGED REGISTRAR DRILL FAILED"; exit 1; fi
tok_theirs="$(cat "$G/.issue-token")"
code="$(printf 'header = "Authorization: Bearer %s"\n' "$tok_ours" | curl -s -m 5 -K - -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -d '{}' "http://$THEIRS/issue")"
if [ "$tok_theirs" != "$tok_ours" ] && [[ "$tok_theirs" =~ ^[0-9a-f]{64}$ ]] && [ "$(stat -c %a "$G/.issue-token")" = 600 ] && [ "$code" = 401 ]; then
  ok "5g the new home made a write token of its own; the operator's old token is refused there (401)"
else fail "5g the old token still writes at the new home, or no new one was made (old token answered $code)"; fi
day="$(issue "$G/.issue-token" "$THEIRS" day-shift)"
echo "$ID" | mr ours confirm "$ID" --at "http://$R1" > "$O/confirm-elsewhere.out" 2>&1; rc1=$?
echo "registrar-example" | mr ours confirm "$ID" --at "http://$THEIRS" > "$O/confirm-mistyped.out" 2>&1; rc2=$?
if [ "$rc1" = 1 ] && grep -q "does not serve $ID's keys" "$O/confirm-elsewhere.out" && [ "$rc2" = 1 ] && grep -q "nothing destroyed" "$O/confirm-mistyped.out" \
   && [ -s "$F/data/registrar.secret" ] && [ -s "$F/data/note.secret" ] && [ -s "$F/.issue-token" ] && [ -s "$PKG" ]; then
  ok "5h a confirmation pointed at another registrar is refused, and so is one with the id mistyped: nothing destroyed"
else fail "5h a confirmation that must be refused destroyed something, or was accepted (other registrar exit $rc1, mistyped exit $rc2)"; fi
echo "$ID" | mr ours confirm "$ID" --at "http://$THEIRS" > "$O/confirm.out" 2>&1; rc=$?
if [ "$rc" = 0 ] && [ ! -e "$F/data/registrar.secret" ] && [ ! -e "$F/data/note.secret" ] && [ ! -e "$F/.issue-token" ] && [ ! -e "$PKG" ] \
   && [ -z "$(find "$F" -name '*.secret' -o -name '.issue-token')" ] && [ -s "$F/HANDED-OVER.json" ] && [ -s "$F/data/registrar.json" ] \
   && grep -q "the log grew from $size0 to $((size0 + 1)) and rewrote nothing" "$O/confirm.out" \
   && grep -q "destroyed here  $F/data/registrar.secret" "$O/confirm.out" && grep -q "kept here       $F/HANDED-OVER.json" "$O/confirm.out" \
   && [ "$(jget fingerprint < "$F/HANDED-OVER.json")" = "${mine#* }" ] && [ "$(jget log_size < "$F/HANDED-OVER.json")" = "$size0" ]; then
  ok "5i confirmed against the new home (the same keys; ainra monitor: the log grew from $size0 to $((size0 + 1)) and rewrote nothing): here the keys, the token and the package are gone, and the record of the hand-over is kept"
  sed -n '/^managed-registrar: .* is handed over/,$p' "$O/confirm.out" | sed 's/^/        | /' | cut -c1-230
else fail "5i the confirmation did not destroy the keys here and keep the record (exit $rc):"; show "$O/confirm.out"; fi
mr ours start "$ID" > "$O/start-after.out" 2>&1; rc1=$?
AINRA_FRESH_KEYS=1 timeout 20 ./target/release/registrar-box "$SPARE" "$ID" "$F/data" > "$O/raw-start.log" 2>&1; rc2=$?
mr ours create example-org --name "Example Org" --addr "$SPARE" > "$O/create-after.out" 2>&1; rc3=$?
if [ "$rc1" = 1 ] && grep -q "was handed over on .*its keys are not here — not started" "$O/start-after.out" \
   && [ "$rc2" = 2 ] && grep -q "registrar.secret missing" "$O/raw-start.log" && grep -q "refusing to start an empty registrar over existing state" "$O/raw-start.log" \
   && [ "$rc3" = 1 ] && grep -q "handed over on .*its id is taken — nothing created" "$O/create-after.out" && ! taken 6122 && ! taken 6152; then
  ok "5j the old folder cannot be started as that registrar: the tool refuses, registrar-box itself refuses (no keys), and the id cannot be created here again"
else fail "5j the old folder can still become $ID (tool start exit $rc1, registrar-box exit $rc2, create exit $rc3):"; tail -n 2 "$O/start-after.out" "$O/raw-start.log" "$O/create-after.out"; fi
mr ours status "$ID" > "$O/status3.out" 2>&1
if grep -q "state          handed over on 20.*its keys are not here" "$O/status3.out"; then ok "5k status here: handed over, when, and how it was confirmed"
else fail "5k status does not say the registrar was handed over:"; show "$O/status3.out"; fi
# A reader that stops reading. The tool's second line arrives after the registrar is stopped and before it is packed:
# a tool that died there would leave a registrar that is neither running nor handed over.
I="$T/ours/registrar-example-pipe"
mr ours create example-pipe --addr "$SPARE" > "$O/pipe-create.out" 2>&1
AINRA_MANAGED_PASSPHRASE_FILE="$RAM/pass" mr ours handover registrar-example-pipe --out "$T/pipe-package" 2>/dev/null | head -n 1 > "$O/pipe-handover.out"
if [ -s "$I/HANDOVER-PENDING.json" ] && [ -s "$T/pipe-package/registrar-example-pipe.handover.gpg" ] && [ -s "$T/pipe-package/START-HERE.txt" ] \
   && [ ! -e "$I/MANIFEST.json" ] && ! taken 6152 && [ "$(wc -l < "$O/pipe-handover.out")" = 1 ]; then
  ok "5l a hand-over whose output is read by something that stops after one line still finishes: stopped, packed and recorded as open"
else fail "5l a reader that stopped reading stopped the hand-over half-way: $(find "$I" -mindepth 1 -maxdepth 1 -printf '%f ' 2>/dev/null)"; fi

echo "6 · at its new home"
before="$(sum "$PUB/directory.json")"
printf '[{"id":"%s","url":"http://%s","fingerprint":"%s"}]\n' "$ID" "$THEIRS" "${mine#* }" > "$T/net/genesis/outside-registrars.json"
net accredit > "$O/accredit-moved.log" 2>&1; rc=$?
if [ "$rc" = 0 ] && grep -q "accredited at epoch 2 and republished" "$O/accredit-moved.log" && [ "$(sum "$PUB/directory.json")" = "$before" ]; then
  ok "6a the root's holder points the list at the new address: the same keys, so the directory is the same epoch 2, byte for byte, and the record is published from the new home"
else fail "6a moving the address changed the directory, or publishing failed (exit $rc):"; tail -n 4 "$O/accredit-moved.log"; fi
m="$(./target/release/ainra monitor --registrar "http://$THEIRS" --net "$PUB" --roots "$PUB/roots.json" --state "$T/watcher.json" 2>&1)"; rc=$?
if [ "$rc" = 0 ] && grep -q "^MONITOR OK" <<< "$m" && grep -q "the log grew from 3 to 4 and rewrote nothing it had" <<< "$m" \
   && grep -q "log ainra-log/$ID at size 4" <<< "$m"; then
  ok "6b the outside watcher, with the memory it took before the hand-over, now shown the new home: the same log (ainra-log/$ID), grown from 3 to 4, nothing rewritten, signed under the directory's key"
else fail "6b the watcher does not accept the log at the new home as the log it saw (exit $rc):"; tail -n 6 <<< "$m"; fi
v="$(sdk "$PUB" "$THEIRS" "$courier")"; rc=$?
if [ "$rc" = 0 ] && [ "$v" = "ainra-verify: VALID" ]; then ok "6c the passport issued before the hand-over still verifies, presented by the new home: $courier is VALID"
else fail "6c the earlier passport no longer verifies: $v (exit $rc)"; fi
v="$(sdk "$PUB" "$THEIRS" "$day")"; rc=$?
if [ "$rc" = 0 ] && [ "$v" = "ainra-verify: VALID" ] && [ -n "$day" ]; then ok "6d a passport issued from the new home, with its own token: $day is VALID"
else fail "6d the passport issued at the new home does not verify: '$day' $v (exit $rc)"; fi
v0="$(sdk "$PUB" "$THEIRS" "$night")"
r="$(revoke "$G/.issue-token" "$THEIRS" "$night")"
v="$(sdk "$PUB" "$THEIRS" "$night")"; rc=$?
v2="$(sdk "$PUB" "$THEIRS" "$runaway")"
if [ "$v0" = "ainra-verify: VALID" ] && grep -q '"seq"' <<< "$r" && [ "$rc" = 1 ] && [ "$v" = "ainra-verify: INVALID (revoked)" ] && [ "$v2" = "ainra-verify: INVALID (revoked)" ]; then
  ok "6e a revocation made from the new home is seen: $night was VALID and is now refused as revoked; the one revoked before the hand-over is still revoked"
else fail "6e the revocation at the new home is not seen (before: $v0; after: $v; the earlier one: $v2)"; fi
net publish > "$O/publish-moved.log" 2>&1
c="$(ctl "$PUB" "$T/ctl.json")"; rc=$?; echo "$c" > "$O/ctl2.out"
if [ "$rc" = 0 ] && grep -q "^CTL OK" <<< "$c" && grep -q "epoch 2 · 3 registrar(s)" <<< "$c" && grep -q "$ID: log size 4 · status seq 2" <<< "$c" && ! grep -q "ALARM" <<< "$c"; then
  ok "6f ainra ctl status, with the memory from before the hand-over and no --now: no alarm (no shorter or forked log, no rewound status); $ID at log size 4, status seq 2"
else fail "6f ainra ctl status alarms after the hand-over (exit $rc):"; tail -n 8 <<< "$c"; fi
mr theirs status "$ID" > "$O/status4.out" 2>&1
if grep -q "origin         received here on 20.*its keys were made on another machine" "$O/status4.out" && grep -q "state          running since" "$O/status4.out" \
   && grep -q "directory      epoch 2: named, with these keys" "$O/status4.out"; then
  ok "6g status there: received, running, named in the directory with these keys — and it says its keys were made on another machine"
else fail "6g status at the new home is not what it should be:"; show "$O/status4.out"; fi

echo "7 · nothing secret was shown"
pass="$(cat "$RAM/pass")"
# The three secrets reach grep as a pattern file on a pipe, so the search itself puts none of them on a command line.
secrets(){ printf '%s\n' "$tok_ours" "$tok_theirs" "$pass"; }
hits="$(grep -rlF -f <(secrets) "$T" --exclude=.issue-token 2>/dev/null | head -n 3)"
running="$(ps -eo args)"
onps="$(grep -cF -f <(secrets) <<< "$running")"
if [ -z "$hits" ] && [ "$onps" = 0 ] && [ -n "$tok_ours" ] && [ -n "$tok_theirs" ] && [ -n "$pass" ] \
   && [ "$(grep -rlF -f <(printf '%s\n' "$tok_theirs") "$T" 2>/dev/null)" = "$G/.issue-token" ]; then
  ok "7a neither write token nor the passphrase is in anything written so far (every output of the tool and of this drill, START-HERE.txt, the registrars' own logs, the records kept), nor on any command line; the search does find the one token file it should"
else fail "7a a token or the passphrase was written or shown: ${hits:-on a command line ($onps)}"; fi

echo "8 · keys the operator never held: what exists today"
mr theirs create example-org-2 --name "Example Org" --addr "$OWN" --net "$PUB" --roots "$PUB/roots.json" > "$O/create-own.out" 2>&1; rc=$?
own="$(fp "http://$OWN")"
entry2="$(grep -m1 '^ *{"id": ' "$O/create-own.out" | sed 's/^ *//')"
printf '[{"id":"%s","url":"http://%s","fingerprint":"%s"},%s]\n' "$ID" "$THEIRS" "${mine#* }" "$entry2" > "$T/net/genesis/outside-registrars.json"
net accredit > "$O/accredit-own.log" 2>&1; rc2=$?
c="$(ctl "$PUB" "$T/ctl.json")"; rc3=$?; echo "$c" > "$O/ctl3.out"
if [ "$rc" = 0 ] && [ "$rc2" = 0 ] && [ -n "$own" ] && [ "${own#* }" != "${mine#* }" ] && [ ! -e "$T/ours/$ID2" ] \
   && grep -q "accredited at epoch 3 and republished" "$O/accredit-own.log" && [ "$rc3" = 0 ] && grep -q "epoch 3 · 4 registrar(s)" <<< "$c" && grep -q "^CTL OK" <<< "$c"; then
  ok "8a the organisation makes a second registrar itself ($ID2: its keys were never in the operator's folder) and is signed in under that id at epoch 3; four registrars, no alarm"
else fail "8a the organisation's own registrar was not made and signed in (create exit $rc, accredit exit $rc2, ctl exit $rc3):"; tail -n 4 "$O/create-own.out" "$O/accredit-own.log"; fi
t1="$(curl -s -m 5 "http://$THEIRS/transfers")"; t2="$(curl -s -m 5 "http://$OWN/transfers")"
line="transfer doors read directories under the roots in"
if cmp -s "$G/roots.json" "$PUB/roots.json" && grep -q "$line $G/roots.json" "$G/registrar.log" && grep -q "$line $T/theirs/$ID2/roots.json" "$T/theirs/$ID2/registrar.log" \
   && ! grep -q "transfer doors" "$O/derived.log" && [ "$(jget registrar <<< "$t1")" = "$ID" ] && [ "$(jget registrar <<< "$t2")" = "$ID2" ]; then
  ok "8b both run with the network's roots pinned, which the lineage transfer doors (D-102) need (each registrar's own start-up line; the roots travelled in the package, byte for byte the network's); a registrar started without roots says no such thing; /transfers answers on both, no move recorded"
  echo "        | not rehearsed: a move itself. Each lineage is moved by its operator's own signature, over a five-day public"
  echo "        | window on the registrars' real clock, and no command-line client for the operator's side exists yet."
else fail "8b the handed-over registrar and the organisation's own were not started with the network's roots for the transfer doors: $(grep -h "transfer doors" "$G/registrar.log" "$T/theirs/$ID2/registrar.log" | tail -n 2)"; fi

echo "P · the same start on a network that is still pinned"
mr theirs stop "$ID" > /dev/null 2>&1; mr theirs stop "$ID2" > /dev/null 2>&1
net down > /dev/null 2>&1; free_ports
PPUB="$T/pinned/public"
pnet up > "$O/pinned-up.log" 2>&1
if [ -s "$PPUB/directory.json" ]; then
  mr pours create example-org --name "Example Org" --addr "$OURS" --net "$PPUB" --roots "$PPUB/roots.json" > "$O/pinned-create.out" 2>&1
  H="$T/pours/$ID"
  entry="$(grep -m1 '^ *{"id": ' "$O/pinned-create.out" | sed 's/^ *//')"
  printf '[%s]\n' "$entry" > "$T/pinned/genesis/outside-registrars.json"
  keep="$(issue "$H/.issue-token" "$OURS" courier)"; gone="$(issue "$H/.issue-token" "$OURS" runaway)"
  revoke "$H/.issue-token" "$OURS" "$gone" > /dev/null
  pnet accredit > "$O/pinned-accredit.log" 2>&1; rc=$?
  read -r epoch at <<< "$(signed_at "$PPUB/directory.json")"
  v="$(sdk "$PPUB" "$OURS" "$keep")"; v2="$(sdk "$PPUB" "$OURS" "$gone")"
  if [ "$rc" = 0 ] && [ "$epoch" = 2 ] && [ "$at" = $((1775865600 - 3600)) ] && [ "$v" = "ainra-verify: VALID" ] && [ "$v2" = "ainra-verify: INVALID (revoked)" ]; then
    ok "P1 a managed registrar joins a pinned network the same way: signed in at epoch 2 (dated April 2026, as that network's directories are); at the real clock its passport is VALID and its revoked one refused"
  else fail "P1 the managed registrar did not join the pinned network (accredit exit $rc, epoch $epoch dated $at; $v; $v2):"; tail -n 4 "$O/pinned-accredit.log"; fi
  c="$(ctl "$PPUB" "$T/pinned-ctl.json" --now "$PINNED_NOW")"; rc=$?
  c2="$(ctl "$PPUB" "$T/pinned-ctl2.json")"; rc2=$?
  if [ "$rc" = 0 ] && grep -q "^CTL OK" <<< "$c" && grep -q "epoch 2 · 3 registrar(s)" <<< "$c" \
     && [ "$rc2" = 1 ] && grep -q "^CTL ALARM — 3 alarm(s)" <<< "$c2" && grep -q "ALARM  stale directory" <<< "$c2" \
     && [ "$(grep -c "ALARM  registrar-[01][0-9]: fresh head is [0-9]*s old" <<< "$c2")" = 2 ] && ! grep -q "ALARM.*$ID" <<< "$c2"; then
    ok "P2 ainra ctl status at the pinned instant (as a pinned network is read): three registrars, no alarm; with no --now, the three alarms a pinned network raises anyway (its April directory, its two registrars' April heads) and none about $ID"
  else fail "P2 ainra ctl status on the pinned network is not what a pinned network gives (pinned instant exit $rc; real clock exit $rc2):"; tail -n 4 <<< "$c"; tail -n 4 <<< "$c2"; fi
  v="$(sdk "$PPUB" "$OURS" "$keep" --now "$PINNED_NOW")"; rc=$?
  if [ "$rc" = 1 ] && [ "$v" = "ainra-verify: INVALID (stale_status)" ]; then
    ok "P3 the limit, held: read at the pinned instant, the same passport is stale_status — a registrar keeping real time signs its status today, and a reader standing in April 2026 refuses it"
  else fail "P3 at the pinned instant the managed registrar's passport read '$v' (exit $rc), not stale_status: the stated limit has moved"; fi
else fail "the pinned network did not come up:"; tail -n 10 "$O/pinned-up.log"; fi

took=$(( $(date +%s) - started ))
[ $bad = 0 ] && echo "MANAGED REGISTRAR DRILL OK: created, signed in on the right fingerprint only, issued and revoked, handed over to another machine with its log and keys, and the copy here destroyed (${took}s)" \
             || echo "MANAGED REGISTRAR DRILL FAILED (${took}s)"
exit $bad
