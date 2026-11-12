#!/usr/bin/env bash
# Replay the signer state of each listed commit on harness v3 (current harness files), one JSON per commit.
set -u
cd "$(dirname "$0")"; W="$(git rev-parse --show-toplevel)"; R=research/c10-autoresearch
for c in "$@"; do
  (cd "$W" && git checkout -q "$c" -- sphincs-c10 hw $R/bench/Cargo.toml $R/host)
  ./experiment_flash.sh > out/v3-$c.json 2>&1
  printf '%s %s\n' "$c" "$(cat out/v3-$c.json)"
done
(cd "$W" && git checkout -q HEAD -- sphincs-c10 hw $R/bench/Cargo.toml $R/host)
echo REPLAY_DONE
