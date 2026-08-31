#!/usr/bin/env bash
# goal dump for the split tree; usage: ecgoal-split.sh <file.ec> [end-line]
f="$1"; end="${2:-999999}"; to="${EC_GOAL_TIMEOUT:-600}"
out=$(sg docker -c "docker exec -i ec-grind bash -lc 'eval \$(opam env 2>/dev/null); cd /work && head -n $end \"$f\" | timeout $to easycrypt cli -I base-c10-split -I cdrafts-split -I scratch 2>&1; echo __CLI_RC=\$?'" 2>&1)
rc=$(printf '%s\n' "$out" | grep -oE '__CLI_RC=[0-9]+' | tail -1 | cut -d= -f2)
[ "${rc:-1}" = "124" ] && { echo "!!! TIMEOUT — goal below is STALE, do not trust"; }
printf '%s\n' "$out" | tr '\r' '\n' | awk '/Current goal/{n=NR} {L[NR]=$0} END{for(i=(n>90?n-90:1);i<=NR;i++) print L[i]}' | tail -140
