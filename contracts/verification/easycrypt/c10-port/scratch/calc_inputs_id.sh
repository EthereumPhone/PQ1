#!/usr/bin/env bash
# Compute INPUTS_SHA256 by EXECUTING cert_gate_split.sh's own lines, extracted verbatim
# (the B/D/INC and CLOSURE/BASELINE/STMTS assignments, then CTL_SRC .. the INPUTS_SHA256
# echo).  Run INSIDE ec-grind with LC_ALL=C.  Not a hand recomputation: the three
# 2026-08-25 failures were a different collation and a stale file list, and this reuses
# both from the gate.  The gate run then COMPARES this value itself, so a wrong one is RED.
set -u
cd "$(dirname "$0")/.."
export LC_ALL=C
eval "$(grep -E '^B=base-c10-split; D=cdrafts-split|^CLOSURE=closure-c10-split.txt' cert_gate_split.sh)"
eval "$(awk '/^CTL_SRC=/{on=1} on{print} /^echo "### INPUTS_SHA256/{exit}' cert_gate_split.sh)"
