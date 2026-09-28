#!/usr/bin/env bash
cd "$(dirname "$0")/.."
for c in A B C; do
  out=$(sg docker -c "docker exec ec-grind bash -lc 'eval \$(opam env 2>/dev/null); cd /work && easycrypt compile -I base-c10-split -I cdrafts-split -I scratch \"scratch/wlc_ctl$c.ec\" 2>&1; echo __RC=\$?'" 2>&1)
  rc=$(printf '%s' "$out" | tr '\r' '\n' | grep -oE '__RC=[0-9]+' | tail -1 | cut -d= -f2)
  msg=$(printf '%s' "$out" | tr '\r' '\n' | grep -a '^\[critical\]' | head -1)
  echo "wlc_ctl$c rc=$rc"
  echo "   $msg"
done
