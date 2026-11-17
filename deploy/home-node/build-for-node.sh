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
if command -v qemu-aarch64-static >/dev/null; then # run each once under emulation: a program that cannot start fails here, not there
  for b in "${BINS[@]}"; do
    qemu-aarch64-static "$OUT/$b" --help >/dev/null 2>&1; c=$?
    [ $c -le 2 ] || { echo "✗ $b did not start under emulation (exit $c)"; exit 1; }
  done
  echo "   each program starts on a 64-bit ARM processor (emulated here)"
fi
commit="$(git rev-parse HEAD)"
echo "== copy to $NODE:$DIR (commit ${commit:0:12})"
ssh -o BatchMode=yes "$NODE" "mkdir -p $DIR/target/release" || exit 1
rsync -a "${BINS[@]/#/$OUT/}" "$NODE:$DIR/target/release/" || exit 1
printf '%s\n' "$commit" | ssh -o BatchMode=yes "$NODE" "cat > $DIR/target/release/.prebuilt" || exit 1
ls -l "${BINS[@]/#/$OUT/}" | awk '{printf "   %-12s %5.1f MB\n", $NF, $5/1048576}' | sed "s|$OUT/||"
echo "built here, copied there: the node compiles nothing"
