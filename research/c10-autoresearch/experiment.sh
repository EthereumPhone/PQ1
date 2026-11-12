#!/usr/bin/env bash
# experiment.sh — one autoresearch evaluation of the CURRENT worktree state. Prints one JSON line.
#  1. host gate: rebuild the host golden checker against the edited sphincs-c10 and compare bytes;
#  2. kit gate + metric: build the SRAM bench, run it on the kit, evaluate (bytes again + cycles).
# Exit 0 = gates passed (the JSON has the metrics); 1 = gate failure; 2 = build/run error.
set -u
D="$(cd "$(dirname "$0")" && pwd)"; cd "$D"; mkdir -p out
( cd host && CARGO_TARGET_DIR="$D/target" cargo build --release --offline -q ) > out/host-build.log 2>&1 || { echo '{"ok": false, "why": "host build failed"}'; exit 2; }
"$D/target/release/c10-ar-host" check golden.bin > out/host.log 2>&1 || { echo "{\"ok\": false, \"why\": \"host gate: $(tail -1 out/host.log)\"}"; exit 1; }
./build.sh out/exp.elf > out/kit-build.log 2>&1 || { echo '{"ok": false, "why": "kit build failed"}'; exit 2; }
timeout 200 bash harness/run_c10.sh out/exp.elf 0x30000000 96 60 > out/kit-run.log 2>&1
./evaluate.py out/exp.elf.openocd.log golden.bin
