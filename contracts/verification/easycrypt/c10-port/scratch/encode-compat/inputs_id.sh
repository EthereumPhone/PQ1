#!/usr/bin/env bash
# Recompute the SPLIT gate's INPUTS_SHA256 exactly as cert_gate_split.sh:106-108 does.
# MUST be run inside ec-grind with LC_ALL=C -- the hash is collation-sensitive.
# SELF-VALIDATING: run it against an unchanged tree and it must reproduce the value the
# gate printed.  If it does not, do NOT trust it -- take the gate's printed value instead.
set -u
cd /work
export LC_ALL=C
B=base-c10-split; D=cdrafts-split
CLOSURE=closure-c10-split.txt; BASELINE=cert-baseline-split.tsv; STMTS=cert-statements-split.tsv
CTL_SRC=$(awk -F'\t' '!/^#/ && NF{print $1}' cert-controls-split.tsv | sort -u | tr '\n' ' ')
CANARY_SRC="scratch/CANARY_gate_admitted.ec scratch/CANARY_modtype_A.ec scratch/CANARY_modtype_B.ec scratch/CANARY_admit_A.ec scratch/CANARY_admit_B.ec"
ROOTS_ID=""
while read -r n; do case "$n" in ''|\#*) continue;; esac; ROOTS_ID="$ROOTS_ID $D/$n.ec"; done < $CLOSURE
for n in WOTS_TW_ES FL_SL_XMSS_MT_ES FORS_ES SPHINCS_PLUS; do ROOTS_ID="$ROOTS_ID $B/$n.ec"; done
{ CERT_CONE_DIRS="base-c10-split,cdrafts-split" python3 tools/cert_cone.py $ROOTS_ID 2>/dev/null \
    | sed -n 's/^#   //p' | sort -u | while read -r f; do [ -f "$f" ] && sha256sum "$f"; done
  sha256sum $CLOSURE $BASELINE $STMTS cert-controls-split.tsv cert-watched-split.tsv cert-margin-split.tsv $CTL_SRC $CANARY_SRC tools/cert_cone.py tools/stmt_digest.py tools/forsc_grinding_margin.py tools/policy_cap_fence.py cert-quarantine-split.tsv tools/stmt_coverage.py cert-cone-files-split.tsv scratch/sweep.py cert_gate_split.sh 2>/dev/null; } | sha256sum | cut -c1-32
