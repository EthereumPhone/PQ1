#!/usr/bin/env bash
# Build "dist/PQ1 Demo": one double-clickable file for Ubuntu on x86-64 PCs.
#
#   ./build.sh            needs cc with static glibc (libc6-dev), xxd, tar
#
# The program is ../macos-demo/pq1-demo.c; the ERC-20 proofs and the golden requests come from
# ../android-demo, so the demos cannot drift: the binary has to pass --selftest against the Android
# goldens before anything is packaged.
set -euo pipefail
cd "$(dirname "$0")"
SRC=../macos-demo
mkdir -p build dist

# 1. The ERC-20 proofs as a C table.
"$SRC/gen_proofs.sh" >build/proofs.h

# 2. Static, so no library version on the target can stop it.
cc -std=gnu11 -Wall -Wextra -Werror -Ibuild -Os -s -static -pthread -o build/pq1-demo "$SRC/pq1-demo.c"

# 3. Same bytes as the Android goldens, or nothing ships.
build/pq1-demo --selftest ../android-demo/app/src/test/resources/golden

# 4. A tarball keeps the executable bit, which a bare file downloaded by a browser loses.
rm -rf dist/*
mkdir "dist/PQ1 Demo"
cp build/pq1-demo "dist/PQ1 Demo/PQ1 Demo"
cp README.txt "dist/PQ1 Demo/Read me.txt"
tar -C dist --owner=0 --group=0 -czf dist/PQ1-Demo-Ubuntu.tar.gz "PQ1 Demo"
ls -l "dist/PQ1 Demo/PQ1 Demo" dist/PQ1-Demo-Ubuntu.tar.gz
