#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# make root-seal-drill — the test root's seed sealed at rest (D-117), on a throwaway seed. Hermetic: its own GnuPG home,
# a seed made for the drill, a passphrase from a file. WITNESS: step 1 is the positive control (the sealed copy opens to
# the same 32 bytes); steps 2 to 5 must each refuse. If any of them goes through, this drill fails.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
T="$(mktemp -d)"; chmod 700 "$T"
export GNUPGHOME="$T/gnupg"; mkdir -m 700 "$GNUPGHOME"
cleanup(){ gpgconf --kill gpg-agent >/dev/null 2>&1; rm -rf "$T"; }
trap cleanup EXIT
bad=0; ok(){ echo "  ok    $1"; }; fail(){ echo "  ✗     $1"; bad=1; }
( umask 077; head -c 32 /dev/urandom > "$T/root.seed"; echo "drill-passphrase" > "$T/pass"; echo "not-it" > "$T/wrong" )
want="$(sha256sum "$T/root.seed" | cut -c1-64)"
export AINRA_ROOT_SEAL_PASSPHRASE_FILE="$T/pass"
seal(){ bash tools/root-seal.sh "$@" >"$T/out" 2>&1; }

echo "1 · seal a seed, and open it again"
if seal seal "$T/root.seed" && [ ! -e "$T/root.seed" ] && [ -s "$T/root.seed.gpg" ]; then
  o="$(bash tools/root-seal.sh open "$T/root.seed.gpg" 2>/dev/null)"
  if [ -n "$o" ] && [ "$(sha256sum "$o" | cut -c1-64)" = "$want" ] && [ "$(stat -c %a "$o")" = 600 ] \
     && [ "$(findmnt -no FSTYPE --target "$o")" = tmpfs ]; then ok "the plain copy is gone; the sealed one opens, in memory, 0600, to the same 32 bytes"
  else fail "the sealed seed did not open to the same bytes in memory"; fi
  [ -n "$o" ] && shred -u "$o"
else fail "seal: $(cat "$T/out")"; fi
grep -q "sealed:" <(bash tools/root-seal.sh status "$T/root.seed") && ok "status says sealed" || fail "status does not say sealed"

echo "2 · the wrong passphrase"
if AINRA_ROOT_SEAL_PASSPHRASE_FILE="$T/wrong" bash tools/root-seal.sh open "$T/root.seed.gpg" >"$T/out" 2>&1; then fail "opened with the wrong passphrase"
else n=0; for f in "${XDG_RUNTIME_DIR:-/dev/shm}"/ainra-root-* /dev/shm/ainra-root-*; do [ -e "$f" ] && n=$((n+1)); done; [ $n = 0 ] && ok "refused, and no opened file is left" || fail "refused, but $n opened file(s) left in memory"; fi

echo "3 · sealing over a sealed seed"
( umask 077; head -c 32 /dev/urandom > "$T/root.seed" )
if seal seal "$T/root.seed"; then fail "a second seal overwrote the first"; else ok "refused: $(head -1 "$T/out" | sed 's/.*— //')"; fi
[ -e "$T/root.seed" ] && ok "the plain copy that was not sealed is kept" || fail "the plain copy was destroyed without being sealed"
rm -f "$T/root.seed"

echo "4 · a sealed file that was tampered with"
cp "$T/root.seed.gpg" "$T/t.gpg"; printf '\x00' | dd of="$T/t.gpg" bs=1 seek=60 conv=notrunc status=none
if bash tools/root-seal.sh open "$T/t.gpg" >/dev/null 2>&1; then fail "a tampered sealed seed opened"; else ok "refused"; fi

echo "5 · a runtime directory that is on a disk"
DISK="$(mktemp -d -p "$PWD" .root-seal-drill-XXXXXX)"; trap 'cleanup; rm -rf "$DISK"' EXIT
if [ "$(findmnt -no FSTYPE --target "$DISK")" = tmpfs ]; then ok "skipped: this checkout is itself in memory"
else
  o="$(XDG_RUNTIME_DIR="$DISK" bash tools/root-seal.sh open "$T/root.seed.gpg" 2>/dev/null)"
  case "$o" in "$DISK"/*) fail "opened the seed onto a disk: $o";; "") ok "refused";; *) ok "not on the disk: opened in memory at $(dirname "$o") instead";; esac
  [ -n "$o" ] && [ -e "$o" ] && shred -u "$o"
fi
rm -rf "$DISK"

[ $bad = 0 ] && echo "ROOT SEAL DRILL OK: sealed at rest, opened only in memory with the passphrase; wrong passphrase, overwrite, tampering and disk all refused" || echo "ROOT SEAL DRILL FAILED"
exit $bad
