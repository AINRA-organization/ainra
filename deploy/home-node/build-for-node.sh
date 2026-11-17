#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# deploy/home-node/build-for-node.sh NODE [DIR] — build the node's programs HERE and copy them over (D-119).
#
# Compiling the network (whole-program optimisation over post-quantum signature code) is the heaviest thing a small
# node would ever do: long, and more memory than a small board has to spare. Running it is light. So this machine
# compiles once for the node's 64-bit ARM processor, as static programs that need nothing from the node's system,
# and the node runs them. Only what a node runs is sent: the registrar door, the witness, and the `ainra` tool. The
# signing tool (`accredit`) is not: a node does not sign.
#
# The programs are marked with the commit they were built from (target/release/.prebuilt); the node's install scripts
# use them, and compile nothing, only when its checkout is at that same commit.
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 2
NODE="${1:?usage: build-for-node.sh NODE [DIR]}"; DIR="${2:-ainra}"
TARGET=aarch64-unknown-linux-musl
OUT="target-node/$TARGET/release"
BINS=(registrar-box witnessd ainra)

git diff --quiet HEAD -- crates services Cargo.toml Cargo.lock \
  || { echo "✗ uncommitted changes to the code: commit first, so the programs match a commit the node can check out"; exit 1; }
rustup target list --installed 2>/dev/null | grep -qx "$TARGET" \
  || { echo "✗ the $TARGET target is missing here: rustup target add $TARGET"; exit 1; }
echo "== build for the node ($TARGET, static), here"
CARGO_TARGET_DIR="$PWD/target-node" CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
  cargo build --release -q --target "$TARGET" -p ainra-services --bin registrar-box --bin witnessd -p ainra-cli-rs --bin ainra \
  || { echo "✗ build failed"; exit 1; }
if command -v qemu-aarch64-static >/dev/null; then
  # Start each daemon for real under an emulator, in a throwaway folder on a spare loopback port, and require an HTTP
  # answer: a program that cannot run on the node's processor fails here, before anything there is touched.
  smoke(){ # smoke NAME URL-PATH ARGS… — start, wait for an answer, stop
    local name="$1" path="$2"; shift 2
    local d port pid ok=1
    d="$(mktemp -d)"; port=$((20000 + RANDOM % 20000))
    ( cd "$d" && exec env AINRA_STAGE=1 AINRA_CLOCK=pinned AINRA_FRESH_KEYS=1 \
        qemu-aarch64-static "$OLDPWD/$OUT/$name" "127.0.0.1:$port" "$@" >"$d/log" 2>&1 ) & pid=$!
    for _ in $(seq 1 40); do curl -s -m 1 -o /dev/null "http://127.0.0.1:$port$path" && { ok=0; break; }; sleep 0.25; done
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
    [ $ok = 0 ] || { echo "✗ $name did not answer under emulation:"; tail -3 "$d/log"; }
    rm -rf "$d"; return $ok
  }
  printf '{"seed":"build-for-node-smoke-not-a-secret","operator":"smoke","region":"smoke","contact":"none","note":"smoke"}' \
    > "$PWD/target-node/smoke-witness.json"
  smoke registrar-box /accreditation smoke ./data || exit 1
  smoke witnessd / "$PWD/target-node/smoke-witness.json" || exit 1
  qemu-aarch64-static "$OUT/ainra" --help >/dev/null 2>&1; [ $? -le 2 ] || { echo "✗ ainra did not start under emulation"; exit 1; }
  echo "   the registrar door and the witness answered, and the tool ran, on a 64-bit ARM processor (emulated here)"
fi
commit="$(git rev-parse HEAD)"
echo "== copy to $NODE:$DIR (commit ${commit:0:12})"
ssh -o BatchMode=yes "$NODE" "mkdir -p $DIR/target/release" || exit 1
rsync -a "${BINS[@]/#/$OUT/}" "$NODE:$DIR/target/release/" || exit 1
printf '%s\n' "$commit" | ssh -o BatchMode=yes "$NODE" "cat > $DIR/target/release/.prebuilt" || exit 1
ls -l "${BINS[@]/#/$OUT/}" | awk '{printf "   %-12s %5.1f MB\n", $NF, $5/1048576}' | sed "s|$OUT/||"
echo "built here, copied there: the node compiles nothing"
