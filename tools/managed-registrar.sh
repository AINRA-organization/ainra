#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# tools/managed-registrar.sh — a registrar run for an organisation until it runs it itself.
#
# An organisation that already verifies who stands behind an agent can issue passports under its own name on the test
# network the day it asks, before it has learned to run the registrar: the network's operator starts one for it here
# ("managed"), and hands it over when the organisation is ready. A managed registrar joins the network exactly as one
# the network does not run (D-120, kits/registrar): its accreditation, a fingerprint by a second channel, the formal
# request. This tool changes no rule and no format; it starts, stops, packs and unpacks `registrar-box`.
#
#   create  <name> --addr HOST:PORT [--name "Organisation"] [--url PUBLIC-URL] [--net RECORD] [--roots roots.json]
#       A new registrar, id `registrar-<name>`, in its own folder: keys made by the operating system at first start
#       (never from the id), a write token made here, kept 0600 and never shown. Prints what the root's holder needs
#       to sign it in. Refused when the id already has a folder here, or the network's directory already names it.
#   status  [<id>]
#       What runs, for whom, since when, how long its log is, and whether the network's directory names its keys.
#   start | stop  <id>
#   handover <id> --out FOLDER
#       Stops the registrar and seals its whole state (keys, log, status, note key) into FOLDER/<id>.handover.gpg with
#       a passphrase the operator types (GnuPG symmetric, as tools/root-seal.sh), beside a plain START-HERE.txt for
#       the organisation. The copy here stays, stopped and unable to start, until the hand-over is confirmed.
#   receive <id> PACKAGE --addr HOST:PORT [--url PUBLIC-URL] [--net RECORD]
#       On the organisation's machine: opens the package into a new folder, checks every file against the list inside
#       it, makes a new write token, starts the registrar and checks it serves the same keys and the same log.
#   confirm <id> (--at URL | --on-their-word)
#       After the organisation runs it: checks that URL serves the same keys and a log that only grew from the one
#       handed over (`ainra monitor`), then destroys the keys, the token and the package here, and says what it
#       destroyed and what it kept. `--on-their-word` skips the check, for a new home this machine cannot reach.
#   resume  <id>
#       Undo a hand-over that was packed and never confirmed: the registrar starts here again.
#
# The folder is AINRA_MANAGED_DIR (default managed/ in this checkout): one subfolder per registrar.
#   <id>/data/            the registrar's state; registrar.secret and note.secret are its keys
#   <id>/.issue-token     its write token (0600)
#   <id>/managed.json     who it is for, where it listens, when it was made (nothing secret)
#   <id>/roots.json       the network's roots, when given: the lineage transfer doors (D-102) read directories under them
#
# Never printed, never on a command line: the token, the passphrase, any key. The passphrase is typed into GnuPG's own
# prompt; AINRA_MANAGED_PASSPHRASE_FILE (tests only) reads it from a file. The unsealed state is never written
# anywhere but the registrar's own folder: packing and opening are pipes.
#
# WITNESS: make managed-registrar-drill (tools/managed-registrar-drill.sh).
set -uo pipefail
# A reader that stops reading (`… | head -1`) must not stop a hand-over half-way: found 22 November 2026, when it left a
# registrar stopped and not yet packed. A closed pipe now costs the lines that were not read, never the step.
trap '' PIPE
CALLER_PWD="$PWD"
cd "$(dirname "$0")/.." || exit 2
REPO="$PWD"

abspath(){ case "$1" in /*) printf '%s' "$1" ;; *) printf '%s' "$CALLER_PWD/$1" ;; esac; }
case "${AINRA_MANAGED_DIR:-}" in
  "") BASE="$REPO/managed" ;;
  *)  BASE="$(abspath "$AINRA_MANAGED_DIR")" ;;
esac
BIN="$REPO/target/release"
FORMAT="ainra-managed-handover/1"

say(){ echo "managed-registrar: $*"; }
die(){ echo "managed-registrar: $*" >&2; exit 1; }
usage(){ sed -n '/^#   create /,/^# The folder is /p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 2; }
taken(){ (exec 3<>"/dev/tcp/$1/$2") 2>/dev/null; }
sum(){ sha256sum "$1" | cut -c1-64; }
utc(){ date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ; }
# The id a registrar may have: what the namespace grammar allows as a label (crates/ainra-core/src/name.rs: 1 to 63 of
# [a-z0-9-], no hyphen first or last) and what the root's holder can list (tools/stage.sh: `registrar-` and 1 to 40 of
# [a-z0-9-]). The id is in every passport's name, in the log's origin and in the status-list address, for good.
valid_id(){ [[ "$1" =~ ^registrar-[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$ ]]; }
valid_addr(){ [[ "$1" =~ ^[0-9A-Za-z.-]+:[0-9]{1,5}$ ]]; }
valid_url(){ [[ "$1" =~ ^https?://[A-Za-z0-9._~:/?#@!\&=+%-]+$ ]]; }
# Where this machine reaches a registrar listening on <addr> (every interface is reached on loopback).
local_url(){ case "$1" in 0.0.0.0:*) printf 'http://127.0.0.1:%s' "${1##*:}" ;; *) printf 'http://%s' "$1" ;; esac; }
need_programs(){
  [ -x "$BIN/registrar-box" ] && [ -x "$BIN/ainra" ] && return 0
  die "the programs are not built — run: cargo build --release -p ainra-services --bin registrar-box -p ainra-cli-rs --bin ainra"
}

# ── the registrar's own notes (managed.json, and the two hand-over records): plain JSON, nothing secret ──
info(){ # info <file> <field> — prints the field, or nothing
  node -e 'try{const v=process.argv[2].split(".").reduce((o,k)=>o?.[k],JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")));if(v!==undefined&&v!==null)process.stdout.write(String(v))}catch{}' "$1" "$2"
}
note(){ # note <file> key=value… — sets string fields (a value of digits only is a number), keeps the others
  local f="$1"; shift
  node -e 'const fs=require("fs"),f=process.argv[1];let j={};try{j=JSON.parse(fs.readFileSync(f,"utf8"))}catch{}
    for(const kv of process.argv.slice(2)){const i=kv.indexOf("="),k=kv.slice(0,i),v=kv.slice(i+1);j[k]=/^[0-9]+$/.test(v)?Number(v):v}
    fs.writeFileSync(f,JSON.stringify(j,null,2)+"\n")' "$f" "$@"
}
jget(){ node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const v=process.argv[1].split(".").reduce((o,k)=>o?.[k],JSON.parse(s));if(v!==undefined&&v!==null)process.stdout.write(String(v))}catch{}})' "$1"; }
folder(){ # folder <id> — the registrar's folder, or stop
  valid_id "$1" || die "'$1' is not a registrar id (registrar-<name>)"
  [ -f "$BASE/$1/managed.json" ] || die "no registrar $1 in $BASE"
  printf '%s' "$BASE/$1"
}

# ── the process ──
pid_of(){ # pid_of <id> — the pid, when this folder's registrar is running
  local f="$BASE/$1/pid" p
  [ -s "$f" ] || return 1
  p="$(tr -d ' \n' < "$f")"; [[ "$p" =~ ^[0-9]+$ ]] || return 1
  [ "$(ps -o comm= -p "$p" 2>/dev/null)" = registrar-box ] || return 1
  tr '\0' '\n' < "/proc/$p/cmdline" 2>/dev/null | grep -qxF "$BASE/$1/data" || return 1
  printf '%s' "$p"
}
start_daemon(){ # start_daemon <id> — 0 once its door answers as that id
  local id="$1" d="$BASE/$1" addr url host port bg
  addr="$(info "$d/managed.json" addr)"; url="$(local_url "$addr")"
  host="${addr%:*}"; port="${addr##*:}"; [ "$host" = 0.0.0.0 ] && host=127.0.0.1
  taken "$host" "$port" && { say "something already listens on $addr — $id not started"; return 1; }
  [ -s "$d/.issue-token" ] || { say "$id has no write token in $d/.issue-token — not started"; return 1; }
  (
    # Nothing the caller's shell exports reaches the registrar: not a pinned clock, not keys derived from the id, not
    # open writes. The environment is emptied here, in this shell, so the token is never on a command line.
    for v in $(compgen -e); do case "$v" in PATH|HOME) ;; *) unset "$v" 2>/dev/null ;; esac; done
    export AINRA_FRESH_KEYS=1
    [ -s "$d/roots.json" ] && export AINRA_ROOTS_FILE="$d/roots.json"
    AINRA_STAGE_ISSUE_TOKEN="$(cat "$d/.issue-token")"; export AINRA_STAGE_ISSUE_TOKEN
    exec nohup "$BIN/registrar-box" "$addr" "$id" "$d/data" >> "$d/registrar.log" 2>&1 < /dev/null
  ) &
  bg=$!; echo "$bg" > "$d/pid"   # the subshell becomes the registrar: one process, this pid
  for _ in $(seq 1 80); do
    [ "$(curl -s -m 2 "$url/health" | jget registrar)" = "$id" ] && pid_of "$id" >/dev/null && return 0
    kill -0 "$bg" 2>/dev/null || break
    sleep 0.25
  done
  say "$id did not come up on $addr; the end of $d/registrar.log:"
  tail -n 5 "$d/registrar.log" 2>/dev/null | sed 's/^/    /'
  kill "$bg" 2>/dev/null; wait "$bg" 2>/dev/null   # this shell's own child, whatever it became
  rm -f "$d/pid"
  return 1
}
stop_daemon(){ # stop_daemon <id> — 0 once it is gone
  local p
  # Only a process that is this folder's registrar is ever signalled: a number in an old pid file may belong to
  # anything by now.
  p="$(pid_of "$1")" || { rm -f "$BASE/$1/pid"; return 0; }
  kill "$p" 2>/dev/null
  for _ in $(seq 1 40); do kill -0 "$p" 2>/dev/null || break; sleep 0.25; done
  kill -0 "$p" 2>/dev/null && { kill -9 "$p" 2>/dev/null; sleep 0.5; }
  kill -0 "$p" 2>/dev/null && return 1
  rm -f "$BASE/$1/pid"
}
new_token(){ ( umask 077; head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$1" ) && [ "$(wc -c < "$1")" = 64 ]; }
destroy(){ # destroy <file>… — overwritten, then removed
  local f
  for f in "$@"; do [ -e "$f" ] || continue; shred -u "$f" 2>/dev/null || rm -f "$f"; done
}
wipe_folder(){ # a folder that never became a registrar: its secrets overwritten, then all of it removed
  local d="$1"
  case "$d" in "$BASE"/registrar-*) ;; *) return 1 ;; esac
  [ -d "$d" ] || return 0
  find "$d" -type f \( -name '*.secret' -o -name '.issue-token' \) -exec shred -u {} + 2>/dev/null
  rm -rf "$d"
}
fingerprint_of(){ node tools/registrar-fingerprint.mjs "$1" 2>/dev/null; }   # prints "<id> sha256:<hex>"
checkpoint_of(){ # checkpoint_of <url> — prints "origin size root" of the log's current signed head
  curl -s -m 10 "$1/witness-feed" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const c=JSON.parse(s).checkpoint;if(c.origin&&Number.isInteger(c.size)&&c.root)process.stdout.write(c.origin+" "+c.size+" "+c.root)}catch{}})'
}
roots_ok(){ node -e 'const j=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));process.exit(typeof j.root_ed25519==="string"&&typeof j.root_slh==="string"?0:1)' "$1" 2>/dev/null; }
# in_directory <record> <id> <accreditation.json> — reads the record's directory.json and prints one of
#   "epoch N: named, with these keys" | "epoch N: named, with OTHER keys" | "epoch N: not named" | nothing (unreadable)
in_directory(){
  local net="$1" dir
  dir="$(mktemp)" || return 1
  case "$net" in
    http://*|https://*) curl -fsS -m 10 "${net%/}/directory.json" -o "$dir" 2>/dev/null || { rm -f "$dir"; return 1; } ;;
    *) cp "$net/directory.json" "$dir" 2>/dev/null || { rm -f "$dir"; return 1; } ;;
  esac
  node -e 'const fs=require("fs");let d,a;try{d=JSON.parse(fs.readFileSync(process.argv[1],"utf8"))}catch{process.exit(1)}
    const id=process.argv[2],e=(d.entries||[]).find(x=>x.registrar===id);
    if(!e){console.log("epoch "+d.epoch+": not named");process.exit(0)}
    try{a=JSON.parse(fs.readFileSync(process.argv[3],"utf8"))}catch{console.log("epoch "+d.epoch+": named");process.exit(0)}
    const same=e.issuer_ed25519===a.issuer_key?.ed25519&&e.issuer_mldsa65===a.issuer_key?.mldsa65&&e.log_root_slh===a.log_root_key
      &&e.status_ed25519===a.status_key?.ed25519&&e.status_mldsa65===a.status_key?.mldsa65&&e.status_uri===a.status_uri;
    console.log("epoch "+d.epoch+": named, with "+(same?"these":"OTHER")+" keys")' "$dir" "$2" "$3"
  local rc=$?; rm -f "$dir"; return $rc
}

# ── the seal: GnuPG symmetric, AES-256, a slow key derivation — the same as tools/root-seal.sh ──
seal_to(){ # stdin → <file>
  if [ -n "${AINRA_MANAGED_PASSPHRASE_FILE:-}" ]; then
    gpg --batch --yes --quiet --no-symkey-cache --pinentry-mode loopback --passphrase-file "$AINRA_MANAGED_PASSPHRASE_FILE" \
      --symmetric --cipher-algo AES256 --s2k-mode 3 --s2k-digest-algo SHA512 --s2k-count 65011712 --output "$1"
  else
    gpg --quiet --no-symkey-cache --symmetric --cipher-algo AES256 --s2k-mode 3 --s2k-digest-algo SHA512 --s2k-count 65011712 --output "$1"
  fi
}
open_from(){ # <file> → stdout
  if [ -n "${AINRA_MANAGED_PASSPHRASE_FILE:-}" ]; then
    gpg --batch --yes --quiet --no-symkey-cache --pinentry-mode loopback --passphrase-file "$AINRA_MANAGED_PASSPHRASE_FILE" --decrypt --output - "$1"
  else
    gpg --quiet --no-symkey-cache --decrypt --output - "$1"
  fi
}
# What a package holds, in one fixed order: the list of its files, the roots when there are any, and the data folder.
members(){ # members <folder>
  ( cd "$1" && { echo MANIFEST.json; [ -f roots.json ] && echo roots.json; find data -type f | LC_ALL=C sort; } )
}
pack(){ # pack <folder> → stdout: the unsealed archive, never a file
  members "$1" | tar -C "$1" --no-recursion -cf - -T -
}

# ════════════════════════════════════════════════════════════════════════════════════════════════════════════
cmd_create(){
  local slug="" name="" addr="" url="" net="" roots="" id d t0 ms fp acc
  slug="${1:-}"; [ -n "$slug" ] && shift
  while [ $# -gt 0 ]; do
    case "$1" in
      --name) name="${2:-}"; shift 2 ;; --addr) addr="${2:-}"; shift 2 ;; --url) url="${2:-}"; shift 2 ;;
      --net) net="${2:-}"; shift 2 ;; --roots) roots="${2:-}"; shift 2 ;;
      *) die "create: unknown argument '$1'" ;;
    esac
  done
  [ -n "$slug" ] || usage
  id="registrar-${slug#registrar-}"
  valid_id "$id" || die "'$id' cannot be a registrar id: after 'registrar-', 1 to 40 of a-z, 0-9 and '-', no hyphen first or last"
  valid_addr "$addr" || die "create: --addr HOST:PORT is required (where the registrar listens)"
  [ -z "$url" ] || valid_url "$url" || die "create: --url must be an http(s) address"
  [ -n "$name" ] || name="${id#registrar-}"
  [[ "$name" =~ ^[[:print:]]{1,80}$ ]] || die "create: --name is 1 to 80 printable characters"
  d="$BASE/$id"
  # One id, one registrar. A second one would be other keys under the same name, the same log origin and the same
  # status-list address: two histories nobody could tell apart by name.
  if [ -e "$d" ]; then
    if [ -f "$d/HANDED-OVER.json" ]; then die "$id was run here and handed over on $(utc "$(info "$d/HANDED-OVER.json" confirmed_at)"); its id is taken — nothing created"
    else die "$id already has a folder here ($d) — nothing created"; fi
  fi
  [ -z "$net" ] || case "$net" in http://*|https://*) ;; *) net="$(abspath "$net")" ;; esac
  if [ -n "$net" ]; then
    case "$(in_directory "$net" "$id" /dev/null)" in
      *": named"*) die "the network's directory at $net already names $id — nothing created" ;;
      "") die "cannot read the directory of $net — nothing created" ;;
    esac
  fi
  if [ -n "$roots" ]; then
    roots="$(abspath "$roots")"
    roots_ok "$roots" || die "$roots does not name root_ed25519 and root_slh — nothing created"
  fi
  need_programs
  t0="$(date +%s%N)"
  ( umask 077; mkdir -p "$BASE" && mkdir "$d" "$d/data" ) || die "cannot make $d"
  new_token "$d/.issue-token" || { wipe_folder "$d"; die "cannot make a write token — nothing created"; }
  [ -z "$roots" ] || cp "$roots" "$d/roots.json"
  note "$d/managed.json" "id=$id" "organisation=$name" "addr=$addr" "url=${url:-$(local_url "$addr")}" "net=$net" \
    "origin=created" "created_at=$(date +%s)"
  if ! start_daemon "$id"; then wipe_folder "$d"; die "$id could not be started — nothing created, its folder removed"; fi
  # The keys must be on disk before their fingerprint leaves this machine. A registrar that kept them in memory until
  # its first write came back with other keys after a restart (found 22 November 2026, fixed in registrar-box).
  if [ ! -s "$d/data/registrar.secret" ] || [ ! -s "$d/data/registrar.json" ] || [ ! -s "$d/data/note.secret" ] \
     || [ "$(stat -c %a "$d/data/registrar.secret")" != 600 ] || [ "$(stat -c %a "$d/data/note.secret")" != 600 ]; then
    stop_daemon "$id"; wipe_folder "$d"
    die "$id started without keeping its keys on disk (0600) — nothing created, its folder removed"
  fi
  fp="$(fingerprint_of "$(local_url "$addr")")"
  case "$fp" in "$id sha256:"*) ;; *) stop_daemon "$id"; wipe_folder "$d"; die "$id does not serve an accreditation of its own — nothing created, its folder removed" ;; esac
  note "$d/managed.json" "fingerprint=${fp#* }"
  url="$(info "$d/managed.json" url)"; acc="$url/accreditation"
  ms=$(( ( $(date +%s%N) - t0 ) / 1000000 ))
  echo "managed-registrar: $id is running for $name (made and started in $((ms / 1000)).$(printf '%03d' $((ms % 1000))) s)"
  cat <<EOF
  listening       $addr
  folder          $d   (0700; its keys are in data/, made by this machine at first start)
  write token     kept in $d/.issue-token (0600) — not shown
  accreditation   $acc
  fingerprint     $fp

For the root's holder, to sign it in (kits/registrar/README.md):
  1. the address, by one channel:           $url
  2. the fingerprint, by another channel:   ${fp#* }
  3. the entry for <network folder>/genesis/outside-registrars.json:
       {"id": "$id", "url": "$url", "fingerprint": "${fp#* }"}
  4. the formal request, signed by each of this registrar's keys, over the organisation's evidence.json:
       ./target/release/ainra directory request ACCREDIT --registrar $d/data --filed-at "\$(date +%s)" --test-root \\
         --evidence evidence.json --out accredit-request.json
EOF
}

cmd_status(){
  local ids=() id d
  if [ $# -gt 0 ]; then folder "$1" >/dev/null; ids=("$1")
  else
    for d in "$BASE"/registrar-*/; do [ -f "${d}managed.json" ] && ids+=("$(basename "$d")"); done
    [ ${#ids[@]} -gt 0 ] || { say "no registrar in $BASE"; return 0; }
  fi
  for id in "${ids[@]}"; do status_one "$id"; done
}
status_one(){
  local id="$1" d="$BASE/$1" m addr url p since origin size h cp net fp acc where
  m="$d/managed.json"; addr="$(info "$m" addr)"; url="$(local_url "$addr")"; net="$(info "$m" net)"
  echo "$id · $(info "$m" organisation)"
  if [ "$(info "$m" origin)" = received ]; then
    echo "  origin         received here on $(utc "$(info "$m" received_at)"); its keys were made on another machine"
  else
    echo "  origin         created here on $(utc "$(info "$m" created_at)")"
  fi
  if [ -f "$d/HANDED-OVER.json" ]; then
    echo "  state          handed over on $(utc "$(info "$d/HANDED-OVER.json" confirmed_at)") ($(info "$d/HANDED-OVER.json" confirmed_by)); its keys are not here"
    echo "  log            $(info "$d/HANDED-OVER.json" log_origin) · size $(info "$d/HANDED-OVER.json" log_size) at the hand-over"
    echo "  fingerprint    $(info "$d/HANDED-OVER.json" fingerprint)"
    return 0
  fi
  if [ -f "$d/HANDOVER-PENDING.json" ]; then
    echo "  state          hand-over pending since $(utc "$(info "$d/HANDOVER-PENDING.json" packaged_at)"): stopped, and not startable here until confirm or resume"
    echo "  log            $(info "$d/HANDOVER-PENDING.json" log_origin) · size $(info "$d/HANDOVER-PENDING.json" log_size) when it was packed"
    echo "  fingerprint    $(info "$d/HANDOVER-PENDING.json" fingerprint)"
    echo "  package        $(info "$d/HANDOVER-PENDING.json" package)"
    return 0
  fi
  if p="$(pid_of "$id")"; then
    since="$(utc "$(date -d "$(ps -o lstart= -p "$p")" +%s 2>/dev/null)" 2>/dev/null)"
    echo "  state          running since ${since:-?} (pid $p), listening on $addr"
    h="$(curl -s -m 5 "$url/health")"; cp="$(checkpoint_of "$url")"
    if [ -n "$cp" ]; then
      read -r origin size _ <<< "$cp"
      echo "  log            $origin · size $size · $(echo "$h" | jget records) passport(s) current · status seq $(echo "$h" | jget status_seq)"
    else
      echo "  log            its door does not answer"
    fi
    acc="$(mktemp)"; curl -s -m 5 "$url/accreditation" -o "$acc"
    fp="$(fingerprint_of "$acc")"; echo "  fingerprint    ${fp#* }"
  else
    echo "  state          stopped (was listening on $addr)"
    echo "  log            size $(cat "$d/data/log.highwater" 2>/dev/null || echo '?') when it last saved"
    echo "  fingerprint    $(info "$m" fingerprint)"
    acc=/dev/null
  fi
  if [ -z "$net" ]; then echo "  directory      no network record named for it (create --net)"
  elif where="$(in_directory "$net" "$id" "$acc")"; then echo "  directory      $where ($net; read here, not verified: ainra ctl status verifies it)"
  else echo "  directory      $net could not be read"; fi
  [ "$acc" = /dev/null ] || rm -f "$acc"
  echo "  write token    kept in $d/.issue-token (0600) — not shown"
}

cmd_start(){
  local id="${1:-}" d; [ -n "$id" ] || usage; d="$(folder "$id")" || exit 1
  # A registrar that was handed over, or is being handed over, must not start here: the package may already be running
  # elsewhere, and two registrars signing from one key and one log would each grow a history of their own.
  [ -f "$d/HANDED-OVER.json" ] && die "$id was handed over on $(utc "$(info "$d/HANDED-OVER.json" confirmed_at)"); its keys are not here — not started"
  [ -f "$d/HANDOVER-PENDING.json" ] && die "$id is being handed over (packed $(utc "$(info "$d/HANDOVER-PENDING.json" packaged_at)")): starting it here could fork its log — confirm the hand-over, or undo it with: resume $id"
  need_programs
  pid_of "$id" >/dev/null && { say "$id is already running (pid $(pid_of "$id"))"; return 0; }
  start_daemon "$id" || exit 1
  say "$id started, listening on $(info "$d/managed.json" addr)"
}
cmd_stop(){
  local id="${1:-}"; [ -n "$id" ] || usage; folder "$id" >/dev/null || exit 1
  pid_of "$id" >/dev/null || { say "$id is not running"; return 0; }
  stop_daemon "$id" || die "$id did not stop"
  say "$id stopped"
}

cmd_handover(){
  local id="${1:-}" out="" d m addr url pend pkg cp origin size root fp net was_running=0 want got watched=no mrc
  [ -n "$id" ] || usage; shift
  while [ $# -gt 0 ]; do case "$1" in --out) out="${2:-}"; shift 2 ;; *) die "handover: unknown argument '$1'" ;; esac; done
  d="$(folder "$id")" || exit 1
  [ -n "$out" ] || die "handover: --out FOLDER is required (where the package is written)"
  out="$(abspath "$out")"
  [ -f "$d/HANDED-OVER.json" ] && die "$id was already handed over; its keys are not here"
  command -v gpg >/dev/null || die "GnuPG (gpg) is needed to seal the package"
  m="$d/managed.json"; addr="$(info "$m" addr)"; url="$(local_url "$addr")"; net="$(info "$m" net)"
  pend="$d/HANDOVER-PENDING.json"; pkg="$out/$id.handover.gpg"
  mkdir -p "$out" || die "cannot make $out"
  { [ -e "$pkg" ] || [ -e "$out/START-HERE.txt" ]; } && die "$out already holds a package — refusing to overwrite it; name another folder"
  if [ -f "$pend" ]; then
    # Packed before and not confirmed: the state has not moved since, so the same hand-over is packed again.
    origin="$(info "$pend" log_origin)"; size="$(info "$pend" log_size)"; root="$(info "$pend" log_root)"; fp="$(info "$pend" fingerprint)"
    watched="$(info "$pend" watched)"
    say "$id was packed before (and not confirmed); packing the same stopped state again"
  else
    pid_of "$id" >/dev/null || die "$id is not running: start it first, so its log's signed head can be recorded before it is packed"
    need_programs
    fp="$(fingerprint_of "$url")"; fp="${fp#* }"
    [[ "$fp" =~ ^sha256:[0-9a-f]{64}$ ]] || die "$id does not serve its accreditation — nothing packed"
    # The log as the world can check it today, kept for the confirmation: `ainra monitor` reads the directory under
    # the roots, the signed head under the directory's key, and every entry. The same state file, shown the new home,
    # proves that its log is this log, grown and not rewritten.
    if [ -n "$net" ] && [ -s "$d/roots.json" ]; then
      rm -f "$d/handover-watch.json"
      "$BIN/ainra" monitor --registrar "$url" --net "$net" --roots "$d/roots.json" --state "$d/handover-watch.json" > "$d/handover-watch.log" 2>&1; mrc=$?
      case "$mrc" in
        0) watched=yes ;;
        3) die "ainra monitor raises an alarm on $id's own log (see $d/handover-watch.log) — nothing packed" ;;
        *) rm -f "$d/handover-watch.json"; say "the log could not be checked under the network's directory ($(tail -n 1 "$d/handover-watch.log")); the confirmation will compare keys and size only" ;;
      esac
    else
      say "no network record or roots are named for $id; the confirmation will compare keys and size only"
    fi
    was_running=1
    # The head recorded for the hand-over is the head of the state that is packed: read while it runs, kept only if the
    # log on disk has that size once it has stopped (a write may land between the two).
    for _ in 1 2 3; do
      cp="$(checkpoint_of "$url")"; read -r origin size root <<< "$cp"
      stop_daemon "$id" || die "$id did not stop — nothing packed"
      [ -n "${root:-}" ] && [ "$(tr -d ' \n' < "$d/data/log.highwater" 2>/dev/null)" = "$size" ] && break
      root=""
      start_daemon "$id" >/dev/null 2>&1 || die "$id did not come back up while its log head was being read — nothing packed; look at $d/registrar.log"
    done
    [ -n "${root:-}" ] || die "$id's log head could not be read at rest (it kept growing, or its door did not answer) — nothing packed; it runs again"
  fi
  # The list inside the package: what it is, and the SHA-256 of every file, so the other side knows it opened whole.
  node -e 'const fs=require("fs"),c=require("crypto"),p=require("path"),[d,format,id,org,origin,size,root,fp,at]=process.argv.slice(1);
    const files={};const walk=(r)=>{for(const n of fs.readdirSync(p.join(d,r)).sort()){const q=r+"/"+n;if(fs.statSync(p.join(d,q)).isDirectory())walk(q);else files[q]=c.createHash("sha256").update(fs.readFileSync(p.join(d,q))).digest("hex")}};
    walk("data");if(fs.existsSync(p.join(d,"roots.json")))files["roots.json"]=c.createHash("sha256").update(fs.readFileSync(p.join(d,"roots.json"))).digest("hex");
    fs.writeFileSync(p.join(d,"MANIFEST.json"),JSON.stringify({format,id,organisation:org,log_origin:origin,log_size:Number(size),log_root:root,fingerprint:fp,packaged_at:Number(at),files},null,2)+"\n")' \
    "$d" "$FORMAT" "$id" "$(info "$m" organisation)" "$origin" "$size" "$root" "$fp" "$(date +%s)"
  want="$(pack "$d" | sha256sum | cut -c1-64)"
  say "sealing $id — GnuPG asks for the passphrase (twice to seal, once more to prove the package opens)"
  if ! ( umask 077; pack "$d" | seal_to "$pkg" ) || [ ! -s "$pkg" ]; then
    rm -f "$pkg" "$d/MANIFEST.json"
    [ "$was_running" = 1 ] && start_daemon "$id" >/dev/null 2>&1 && say "$id runs here again"
    die "the package was not sealed — nothing handed over"
  fi
  got="$(open_from "$pkg" 2>/dev/null | sha256sum | cut -c1-64)"
  if [ "$got" != "$want" ]; then
    rm -f "$pkg" "$d/MANIFEST.json"
    [ "$was_running" = 1 ] && start_daemon "$id" >/dev/null 2>&1 && say "$id runs here again"
    die "the sealed package did not open to the same bytes — removed; nothing handed over"
  fi
  rm -f "$d/MANIFEST.json"
  chmod 600 "$pkg"
  note "$pend" "id=$id" "log_origin=$origin" "log_size=$size" "log_root=$root" "fingerprint=$fp" "watched=$watched" \
    "packaged_at=$(date +%s)" "package=$pkg" "package_sha256=$(sum "$pkg")"
  start_here "$id" "$d" "$pkg" "$origin" "$size" "$fp" > "$out/START-HERE.txt"
  cat <<EOF
managed-registrar: $id is packed for $(info "$m" organisation)
  package         $pkg   (sealed; sha256 $(sum "$pkg"))
  beside it       $out/START-HERE.txt   (plain words for the organisation; nothing secret)
  the log         $origin · size $size at the hand-over
  fingerprint     $fp   (unchanged by a hand-over)
  here            $id is stopped and cannot be started while the hand-over is open; its keys are still in $d/data

Next:
  1. Give the organisation the folder $out by one channel and the passphrase by another.
  2. When their registrar answers:   bash tools/managed-registrar.sh confirm $id --at <their address>
     That checks it is the same registrar, then destroys the keys, the token and the package on this machine.
  3. If they will not take it after all, and every copy of the package is destroyed:   bash tools/managed-registrar.sh resume $id
EOF
}
start_here(){ # the plain-language file that travels beside the package
  local id="$1" d="$2" pkg="$3" origin="$4" size="$5" fp="$6" org
  org="$(info "$d/managed.json" organisation)"
  cat <<EOF
AINRA registrar hand-over: $id ($org)

Packed on $(date -u +%Y-%m-%d) by the operator who ran this registrar for you. Two files:

  $(basename "$pkg")
      Your registrar's whole state: its keys, its log, its status list and its log's note key, sealed with a
      passphrase. SHA-256 of the file: $(sum "$pkg")
  START-HERE.txt
      This file. Nothing in it is secret.

The passphrase is not in this folder and the tool never wrote it anywhere. The operator gives it to you by another
channel than the one this folder came by, for example read out on a call.

What you are taking over
  id            $id
  fingerprint   $fp
                (your keys as the network's directory names them; a hand-over does not change them)
  log           $origin, size $size at the hand-over

To start it on your machine
  1. Get the AINRA repository and build two programs:
       cargo build --release -p ainra-services --bin registrar-box -p ainra-cli-rs --bin ainra
  2. Open the package and start the registrar. You are asked for the passphrase.
       bash tools/managed-registrar.sh receive $id <this folder>/$(basename "$pkg") --addr 127.0.0.1:4922
     It checks every file against the list inside the package, makes a new write token for you (the operator's old
     one is not in the package and stops working), starts the registrar, and checks that it serves the fingerprint
     and the log above.
  3. Put it behind HTTPS at a stable address, with the read endpoints public (kits/registrar/README.md, step 1).
  4. Tell the operator that address. They check that it serves the same keys and the same log, grown and not
     rewritten, and then destroy their copy of the keys. The root's holder points the network's list at your address;
     your keys are the same, so no new directory is signed.

Until step 4 is done the operator's copy is stopped, not destroyed. Never run both: two registrars signing from one
key and one log would each grow a different history.

What a hand-over does not change
  These keys were made on the operator's machine and were there until the hand-over. Destroying that copy is the
  operator's act; nothing in the network can prove it was done. If you need keys that were never outside your own
  machine, kits/registrar/README.md ("Managed start") says what exists for that today and what does not.

Once your registrar runs and you hold a backup of its folder that you control, delete the package.
EOF
}

cmd_receive(){
  local id="${1:-}" pkg="${2:-}" addr="" url="" net="" d man fp cp origin size root why
  [ -n "$id" ] && [ -n "$pkg" ] || usage; shift 2
  while [ $# -gt 0 ]; do
    case "$1" in
      --addr) addr="${2:-}"; shift 2 ;; --url) url="${2:-}"; shift 2 ;; --net) net="${2:-}"; shift 2 ;;
      *) die "receive: unknown argument '$1'" ;;
    esac
  done
  valid_id "$id" || die "'$id' is not a registrar id (registrar-<name>)"
  valid_addr "$addr" || die "receive: --addr HOST:PORT is required (where the registrar will listen)"
  [ -z "$url" ] || valid_url "$url" || die "receive: --url must be an http(s) address"
  [ -z "$net" ] || case "$net" in http://*|https://*) ;; *) net="$(abspath "$net")" ;; esac
  pkg="$(abspath "$pkg")"; [ -s "$pkg" ] || die "no package at $pkg"
  command -v gpg >/dev/null || die "GnuPG (gpg) is needed to open the package"
  need_programs
  d="$BASE/$id"
  [ -e "$d" ] && die "$id already has a folder here ($d) — nothing opened"
  ( umask 077; mkdir -p "$BASE" && mkdir "$d" ) || die "cannot make $d"
  say "opening $(basename "$pkg") — GnuPG asks for the passphrase"
  # A pipe: the unsealed state reaches the disk only inside the registrar's own new folder. GnuPG checks the package's
  # integrity as it ends, so anything short of a clean end of both programs is thrown away, keys overwritten first.
  ( umask 077; open_from "$pkg" 2>/dev/null | tar -x -C "$d" --no-same-owner -f - 2>/dev/null; st=("${PIPESTATUS[@]}"); [ "${st[0]}" = 0 ] && [ "${st[1]}" = 0 ] )
  # shellcheck disable=SC2181
  if [ $? != 0 ]; then
    wipe_folder "$d"
    die "the package did not open (a wrong passphrase, or the file was changed) — nothing kept"
  fi
  man="$d/MANIFEST.json"
  # Exactly the files the list names, each with the SHA-256 it names, for this id, and nothing else in the folder.
  if ! why="$(node -e 'const fs=require("fs"),c=require("crypto"),p=require("path"),[d,format,id]=process.argv.slice(1);
      process.on("uncaughtException",(e)=>{console.log(e.message);process.exit(1)});
      const m=JSON.parse(fs.readFileSync(p.join(d,"MANIFEST.json"),"utf8"));
      if(m.format!==format)throw new Error("not a "+format+" package");
      if(m.id!==id)throw new Error("the package is "+m.id+", not "+id);
      const found=[];const walk=(r)=>{for(const n of fs.readdirSync(p.join(d,r))){const q=r?r+"/"+n:n,s=fs.lstatSync(p.join(d,q));
        if(s.isSymbolicLink())throw new Error("a link in the package: "+q);if(s.isDirectory())walk(q);else found.push(q)}};walk("");
      const want=Object.keys(m.files).concat("MANIFEST.json").sort();
      if(JSON.stringify(found.sort())!==JSON.stringify(want))throw new Error("the files are not the ones the list names");
      for(const [f,h] of Object.entries(m.files)){if(!/^(data\/[A-Za-z0-9._-]+|roots\.json)$/.test(f))throw new Error("an unexpected file: "+f);
        if(c.createHash("sha256").update(fs.readFileSync(p.join(d,f))).digest("hex")!==h)throw new Error(f+" is not the file the list names")}
      for(const f of ["data/registrar.secret","data/registrar.json","data/note.secret"])if(!m.files[f])throw new Error("the package has no "+f);' \
      "$d" "$FORMAT" "$id" 2>/dev/null)"; then
    wipe_folder "$d"
    die "the package was opened and refused: ${why:-its list could not be read} — nothing kept"
  fi
  chmod 700 "$d" "$d/data"; chmod 600 "$d/data/registrar.secret" "$d/data/note.secret"
  new_token "$d/.issue-token" || { wipe_folder "$d"; die "cannot make a write token — nothing kept"; }
  note "$d/managed.json" "id=$id" "organisation=$(info "$man" organisation)" "addr=$addr" "url=${url:-$(local_url "$addr")}" "net=$net" \
    "origin=received" "received_at=$(date +%s)" "fingerprint=$(info "$man" fingerprint)" \
    "handed_over_log_size=$(info "$man" log_size)" "handed_over_log_root=$(info "$man" log_root)" "handed_over_at=$(info "$man" packaged_at)"
  if ! start_daemon "$id"; then die "$id was opened into $d and did not start — the folder is kept; look at $d/registrar.log"; fi
  fp="$(fingerprint_of "$(local_url "$addr")")"; cp="$(checkpoint_of "$(local_url "$addr")")"; read -r origin size root <<< "$cp"
  if [ "${fp#* }" != "$(info "$man" fingerprint)" ] || [ "${origin:-}" != "$(info "$man" log_origin)" ] \
     || [ "${size:-}" != "$(info "$man" log_size)" ] || [ "${root:-}" != "$(info "$man" log_root)" ]; then
    stop_daemon "$id"
    die "$id started, and is not the registrar the package describes (fingerprint ${fp#* }, log ${origin:-?} size ${size:-?}) — stopped; the folder $d is kept"
  fi
  rm -f "$man"
  cat <<EOF
managed-registrar: $id is running here, from the package
  listening       $addr
  folder          $d   (0700; back it up, keep it private, never copy it to a second running registrar)
  same keys       fingerprint ${fp#* }
  same log        $origin · size $size · root $root
  write token     a new one, kept in $d/.issue-token (0600) — not shown; the previous operator's is not in the package

Next:
  1. Put it behind HTTPS at a stable address (kits/registrar/README.md, step 1) and tell the previous operator that address.
  2. They confirm the hand-over and destroy their copy; the root's holder points the network's list at your address.
  3. Delete the package once you hold a backup of $d that you control.
EOF
}

cmd_confirm(){
  local id="${1:-}" at="" word=0 d pend fp_want fp_got cp origin size root how typed pkg mrc net
  [ -n "$id" ] || usage; shift
  while [ $# -gt 0 ]; do
    case "$1" in --at) at="${2:-}"; shift 2 ;; --on-their-word) word=1; shift ;; *) die "confirm: unknown argument '$1'" ;; esac
  done
  d="$(folder "$id")" || exit 1
  pend="$d/HANDOVER-PENDING.json"
  [ -f "$d/HANDED-OVER.json" ] && die "$id's hand-over was confirmed on $(utc "$(info "$d/HANDED-OVER.json" confirmed_at)"); there is nothing left to destroy"
  [ -f "$pend" ] || die "$id is not being handed over (run handover first) — nothing destroyed"
  pid_of "$id" >/dev/null && die "$id is running here — nothing destroyed"
  fp_want="$(info "$pend" fingerprint)"; net="$(info "$d/managed.json" net)"
  if [ -n "$at" ]; then
    valid_url "$at" || die "confirm: --at must be an http(s) address"
    at="${at%/}"
    # The new home must be this registrar: the same keys, and a log that is this log, grown and not rewritten.
    fp_got="$(fingerprint_of "$at")"
    [ "$fp_got" = "$id $fp_want" ] || die "$at does not serve $id's keys (it serves: ${fp_got:-nothing readable}) — nothing destroyed"
    cp="$(checkpoint_of "$at")"; read -r origin size root <<< "$cp"
    [ "${origin:-}" = "$(info "$pend" log_origin)" ] || die "$at does not serve $id's log (${origin:-no signed head}) — nothing destroyed"
    [ "${size:-0}" -ge "$(info "$pend" log_size)" ] || die "the log at $at is SHORTER ($size) than the one handed over ($(info "$pend" log_size)) — nothing destroyed"
    if [ "$(info "$pend" watched)" = yes ] && [ -s "$d/handover-watch.json" ]; then
      need_programs
      cp "$d/handover-watch.json" "$d/confirm-watch.json"
      "$BIN/ainra" monitor --registrar "$at" --net "$net" --roots "$d/roots.json" --state "$d/confirm-watch.json" > "$d/confirm-watch.log" 2>&1; mrc=$?
      [ "$mrc" = 0 ] || die "ainra monitor does not accept the log at $at as the one handed over (exit $mrc; $(grep -m1 -E 'ALARM|monitor:' "$d/confirm-watch.log")) — nothing destroyed"
      how="checked at $at: the same keys, and the log grew from $(info "$pend" log_size) to $size and rewrote nothing (ainra monitor, under the network's directory)"
    else
      [ "$size" != "$(info "$pend" log_size)" ] || [ "$root" = "$(info "$pend" log_root)" ] || die "the log at $at has the size handed over and another root — nothing destroyed"
      how="checked at $at: the same keys and a log of size $size (handed over at $(info "$pend" log_size)); its growth was not checked against a directory"
    fi
    say "$how"
  elif [ "$word" = 1 ]; then
    how="on the organisation's word; the new home was not checked from this machine"
    say "not checked from here: taking the organisation's word that $id runs at its new home"
  else
    die "confirm: say where it runs now (--at URL), or --on-their-word"
  fi
  pkg="$(info "$pend" package)"
  cat <<EOF
This destroys, on this machine, and cannot be undone:
  $d/data/registrar.secret   every private key of $id (issuer, log root, status)
  $d/data/note.secret        the log's note key
  $d/.issue-token            the write token used here
  $pkg   the sealed package, if it is still there
Type the registrar's id to go on:
EOF
  read -r typed || typed=""
  [ "$typed" = "$id" ] || die "'$typed' is not $id — nothing destroyed"
  destroy "$d/data/registrar.secret" "$d/data/note.secret" "$d/.issue-token"
  local pkg_gone="was not at $pkg any more"
  if [ -f "$pkg" ] && [ "$(sum "$pkg")" = "$(info "$pend" package_sha256)" ]; then destroy "$pkg"; pkg_gone="destroyed at $pkg"; fi
  for f in "$d/data/registrar.secret" "$d/data/note.secret" "$d/.issue-token"; do
    [ -e "$f" ] && die "$f could not be destroyed — the hand-over is NOT recorded as confirmed; remove it by hand and run confirm again"
  done
  rm -f "$d/pid" "$d/confirm-watch.json"
  note "$d/HANDED-OVER.json" "id=$id" "organisation=$(info "$d/managed.json" organisation)" "fingerprint=$fp_want" \
    "log_origin=$(info "$pend" log_origin)" "log_size=$(info "$pend" log_size)" "log_root=$(info "$pend" log_root)" \
    "packaged_at=$(info "$pend" packaged_at)" "confirmed_at=$(date +%s)" "confirmed_by=$how" \
    "new_home=${at:-not recorded}" "package_sha256=$(info "$pend" package_sha256)"
  rm -f "$pend"
  cat <<EOF
managed-registrar: $id is handed over to $(info "$d/managed.json" organisation)
  destroyed here  $d/data/registrar.secret   (every private key of $id)
                  $d/data/note.secret        (the log's note key)
                  $d/.issue-token            (the write token used here)
                  the sealed package: $pkg_gone
  kept here       $d/HANDED-OVER.json        the record of the hand-over: id, fingerprint, the log's head, when, how confirmed
                  $d/data/registrar.json, entries.log, log.highwater   the public record as it was when packed; no key
                  $d/managed.json, registrar.log
  not in reach    any other copy of the package or of the passphrase, any backup of $d, and blocks an SSD or a
                  copy-on-write file system keeps after an overwrite. The keys were on this machine from $(utc "$(info "$d/managed.json" created_at)") to now.
  for the root    point $id's entry in outside-registrars.json at its new address; same keys, so no new directory
EOF
}

cmd_resume(){
  local id="${1:-}" d typed; [ -n "$id" ] || usage; d="$(folder "$id")" || exit 1
  [ -f "$d/HANDED-OVER.json" ] && die "$id was handed over; its keys are not here — it cannot be resumed"
  [ -f "$d/HANDOVER-PENDING.json" ] || die "$id is not being handed over — nothing to resume"
  cat <<EOF
$id was packed on $(utc "$(info "$d/HANDOVER-PENDING.json" packaged_at)") and is about to start here again.
If any copy of the package is started as well, two registrars will sign from one key and one log, and each will grow
a different history. Destroy every copy of the package first.
Type the registrar's id to go on:
EOF
  read -r typed || typed=""
  [ "$typed" = "$id" ] || die "'$typed' is not $id — nothing changed"
  need_programs
  mv "$d/HANDOVER-PENDING.json" "$d/handover-undone-$(date +%s).json"
  rm -f "$d/handover-watch.json"
  start_daemon "$id" || exit 1
  say "$id runs here again; the hand-over is undone"
}

cmd="${1:-}"; [ $# -gt 0 ] && shift
case "$cmd" in
  create)   cmd_create "$@" ;;
  status)   cmd_status "$@" ;;
  start)    cmd_start "$@" ;;
  stop)     cmd_stop "$@" ;;
  handover) cmd_handover "$@" ;;
  receive)  cmd_receive "$@" ;;
  confirm)  cmd_confirm "$@" ;;
  resume)   cmd_resume "$@" ;;
  *) usage ;;
esac
