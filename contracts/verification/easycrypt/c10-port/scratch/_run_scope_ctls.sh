#!/usr/bin/env bash
# UNTRACKED helper (2026-09-15): grade ONLY the scratch/_scope_* rows of cert-controls-split.tsv
# with PHASE 3's exact compile + first-[critical] + grep -F grading.  Run inside ec-grind.
set -u; set -o pipefail; cd "$(dirname "$0")/.."; export LC_ALL=C
B=base-c10-split; D=cdrafts-split; INC="-I $B -I $D"; bad=0; n=0
while IFS=$'\t' read -r path kind reason; do
  case "$path" in scratch/_scope_*) ;; *) continue;; esac
  n=$((n+1))
  out=$(easycrypt compile $INC "$path" 2>&1); rc=$?
  msg=$(printf '%s' "$out" | tr '\r' '\n' | grep -a '^\[critical\]' | head -1)
  if [ $rc -eq 0 ]; then
    if [ "$kind" = MUST-PASS ]; then echo "OK   $path (MUST-PASS)"; else echo "FAIL $path: MUST-FAIL but COMPILED"; bad=$((bad+1)); fi
  else
    if [ "$kind" = MUST-PASS ]; then echo "FAIL $path: MUST-PASS but failed -- $msg"; bad=$((bad+1))
    elif printf '%s' "$msg" | grep -qF "$reason"; then echo "OK   $path (MUST-FAIL, rejected for the DECLARED reason)  | $msg"
    else echo "FAIL $path: WRONG reason | got: $msg | declared: $reason"; bad=$((bad+1)); fi
  fi
done < cert-controls-split.tsv
echo "scope controls graded=$n bad=$bad"
