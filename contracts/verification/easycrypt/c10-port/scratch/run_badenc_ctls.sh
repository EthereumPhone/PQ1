#!/usr/bin/env bash
cd "$(dirname "$0")/.."
for c in A B C D; do
  f="scratch/badenc_ctl$c.ec"
  out=$(sg docker -c "docker exec ec-grind bash -lc 'eval \$(opam env 2>/dev/null); cd /work && easycrypt compile -I base-c10-split -I cdrafts-split -I scratch \"$f\" 2>&1; echo __RC=\$?'" 2>&1)
  rc=$(printf '%s' "$out" | tr '\r' '\n' | grep -oE '__RC=[0-9]+' | tail -1 | cut -d= -f2)
  msg=$(printf '%s' "$out" | tr '\r' '\n' | grep -a '^\[critical\]' | head -1)
  echo "CTL$c rc=$rc"
  echo "     $msg"
done
