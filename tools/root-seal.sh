#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# tools/root-seal.sh — keep the test network's root seed sealed at rest (D-117).
#
# The test root's 32-byte seed (D-109) signs every directory of the test network. Until 17 November 2026 it lay on the
# operator's everyday laptop in plain bytes, readable by anything running as the operator. Sealed, it is encrypted
# with a passphrase only the operator knows (GnuPG symmetric, AES-256, a slow key derivation), and is opened only for
# the moment a directory is signed, into memory (the per-user runtime directory, a RAM file system), then shredded.
# Nothing on the machine can sign for the root while the operator is away. A small computer that never touches a network
# is the next step (the operator's, when the hardware is there); this is the step that needs no hardware.
#
#   bash tools/root-seal.sh seal  [SEED]     encrypt SEED (default stage/genesis/root.seed) to SEED.gpg, prove it opens
#                                            to the same bytes, then shred the plain copy (and the backup copy given by
#                                            AINRA_ROOT_SEED_BACKUP, sealed the same way). Asks for the passphrase twice.
#   bash tools/root-seal.sh open  SEALED     decrypt into memory; print the path of the opened file (0600). The caller
#                                            shreds it; a guard shreds it after 10 minutes in any case.
#   bash tools/root-seal.sh status [SEED]    sealed, plain, or missing. Never prints the seed.
#
# The seed is never printed, never written outside the runtime directory in plain form, and never passed on a command
# line. AINRA_ROOT_SEAL_PASSPHRASE_FILE (tests only) reads the passphrase from a file instead of asking.
set -euo pipefail
cd "$(dirname "$0")/.." || exit 2

GPG=(gpg --batch --yes --quiet --no-symkey-cache)
pass_args(){ # the passphrase source: a test file, or the terminal (pinentry)
  if [ -n "${AINRA_ROOT_SEAL_PASSPHRASE_FILE:-}" ]; then
    printf '%s\n' --pinentry-mode loopback --passphrase-file "$AINRA_ROOT_SEAL_PASSPHRASE_FILE"
  fi
}
runtime(){ # a RAM file system to open the seed in: the per-user runtime directory, else /dev/shm; never a disk
  local d
  for d in "${XDG_RUNTIME_DIR:-}" /dev/shm; do
    [ -n "$d" ] && [ -d "$d" ] && [ -w "$d" ] && [ "$(findmnt -no FSTYPE --target "$d" 2>/dev/null)" = tmpfs ] && { printf '%s' "$d"; return 0; }
  done
  echo "root-seal: no RAM file system (XDG_RUNTIME_DIR or /dev/shm) to open the seed in — refusing to open it onto a disk" >&2
  return 1
}
digest(){ sha256sum "$1" | cut -c1-64; }

seal_one(){ # seal_one PLAIN — PLAIN.gpg, proven, then PLAIN shredded
  local plain="$1" sealed="$1.gpg" opened
  [ -s "$plain" ] || { echo "root-seal: $plain does not exist or is empty — nothing to seal" >&2; return 1; }
  [ -e "$sealed" ] && { echo "root-seal: $sealed already exists — refusing to overwrite a sealed seed" >&2; return 1; }
  local -a pa; mapfile -t pa < <(pass_args)
  if [ ${#pa[@]} -eq 0 ]; then
    # Interactive: gpg asks twice through pinentry when it encrypts.
    ( umask 077; gpg --quiet --no-symkey-cache --symmetric --cipher-algo AES256 --s2k-mode 3 --s2k-digest-algo SHA512 \
        --s2k-count 65011712 --output "$sealed" "$plain" )
  else
    ( umask 077; "${GPG[@]}" "${pa[@]}" --symmetric --cipher-algo AES256 --s2k-mode 3 --s2k-digest-algo SHA512 \
        --s2k-count 65011712 --output "$sealed" "$plain" )
  fi
  chmod 600 "$sealed"
  opened="$(open_one "$sealed")" || { rm -f "$sealed"; echo "root-seal: the sealed copy did not open — the plain seed is kept" >&2; return 1; }
  if [ "$(digest "$opened")" != "$(digest "$plain")" ]; then
    shred -u "$opened"; rm -f "$sealed"
    echo "root-seal: the sealed copy opened to different bytes — the plain seed is kept" >&2; return 1
  fi
  shred -u "$opened"
  shred -u "$plain"
  echo "root-seal: sealed $sealed (it opens to the same 32 bytes); the plain copy is shredded"
}

open_one(){ # open_one SEALED — prints the path of a 0600 file in RAM holding the seed
  local sealed="$1" dir out
  [ -s "$sealed" ] || { echo "root-seal: $sealed does not exist" >&2; return 1; }
  dir="$(runtime)" || return 1
  out="$(umask 077; mktemp "$dir/ainra-root-XXXXXXXX")"
  local -a pa; mapfile -t pa < <(pass_args)
  if ! { if [ ${#pa[@]} -eq 0 ]; then gpg --quiet --no-symkey-cache --decrypt --output - "$sealed"; else "${GPG[@]}" "${pa[@]}" --decrypt --output - "$sealed"; fi; } > "$out"; then
    shred -u "$out" 2>/dev/null || rm -f "$out"
    echo "root-seal: could not open $sealed (wrong passphrase?)" >&2; return 1
  fi
  # A guard: whatever happens to the caller, the opened seed does not outlive ten minutes.
  ( sleep 600; [ -e "$out" ] && shred -u "$out" ) >/dev/null 2>&1 &
  disown || true
  printf '%s\n' "$out"
}

status_one(){
  local plain="$1"
  if [ -s "$plain.gpg" ] && [ ! -e "$plain" ]; then echo "sealed: $plain.gpg"
  elif [ -s "$plain.gpg" ] && [ -e "$plain" ]; then echo "BOTH a sealed and a plain copy: $plain — shred the plain one after checking the sealed one opens"
  elif [ -s "$plain" ]; then echo "PLAIN (not sealed): $plain"
  else echo "missing: $plain"; fi
}

cmd="${1:-status}"
case "$cmd" in
  seal)
    seed="${2:-stage/genesis/root.seed}"
    seal_one "$seed"
    backup="${AINRA_ROOT_SEED_BACKUP:-$HOME/Desktop/ainra-secrets/staging-root.seed}"
    if [ -z "${2:-}" ] && [ -s "$backup" ]; then
      seal_one "$backup"
    fi
    ;;
  open) open_one "${2:?usage: root-seal.sh open SEALED}" ;;
  status)
    seed="${2:-stage/genesis/root.seed}"
    status_one "$seed"
    [ -z "${2:-}" ] && status_one "${AINRA_ROOT_SEED_BACKUP:-$HOME/Desktop/ainra-secrets/staging-root.seed}"
    ;;
  *) echo "usage: root-seal.sh seal [SEED] | open SEALED | status [SEED]" >&2; exit 2 ;;
esac
