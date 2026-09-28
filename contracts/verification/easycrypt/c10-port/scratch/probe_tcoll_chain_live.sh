#!/usr/bin/env bash
# Compile the wots-badenc/{tcoll,red} chain as TARGETS against the LIVE trees
# (base-c10-split + cdrafts-split), not the 2026-08-14 experiment copies.
# Question: is the chain promotable as-is?  Each file is its own target, in
# dependency order, with its .eco removed first (a `require` does not re-verify).
set -u
cd /work
T=experiments/wots-badenc/tcoll
R=experiments/wots-badenc/red
for f in "$T/TCollResEnum" "$R/BadEncSplit" "$R/BadEncToTColl" "$R/BadEncStep4"; do
  rm -f "$f.eco"
  s=$(date +%s)
  easycrypt compile -I base-c10-split -I cdrafts-split -I "$T" -I "$R" "$f.ec" > "/work/scratch/_live_$(basename $f).out" 2>&1
  rc=$?
  echo "$(basename $f) rc=$rc  $(( $(date +%s) - s ))s  $(tr '\r' '\n' < /work/scratch/_live_$(basename $f).out | grep -a '^\[critical\]' | head -1)"
  [ $rc -eq 0 ] || break
done
echo DONE
