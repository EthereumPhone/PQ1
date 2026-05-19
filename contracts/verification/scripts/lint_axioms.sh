#!/usr/bin/env bash
#
# lint_axioms.sh — gate against silently adding `True`-typed axioms or
# `True := trivial` theorem placeholders to the SphincsCVerify Lean
# project.
#
# Run from anywhere; resolves the repo root from its own location.
#
# Exit codes:
#   0  no new placeholders outside the allowlist (PASS)
#   1  at least one new placeholder; details on stderr (FAIL)
#   2  internal error (missing tooling, bad parse, etc.)
#
# Tooling required: lake (Lean 4), python3, awk, comm, sort.
#
# This is invoked from `make verify-theft-free` (and from CI).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
LEAN_DIR="${REPO_ROOT}/contracts/verification/lean"
KNOWN_AXIOMS="${SCRIPT_DIR}/known_true_axioms.txt"
KNOWN_THEOREMS="${SCRIPT_DIR}/known_trivial_theorems.txt"

# Ensure elan-installed lake is on PATH for CI environments.
export PATH="${HOME}/.elan/bin:${PATH}"

err() {
  printf 'lint_axioms.sh: %s\n' "$*" >&2
}

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    err "missing required tool: $1"
    exit 2
  fi
}

require lake
require python3
require comm
require sort
require awk

# Validate allowlist files exist.
for f in "${KNOWN_AXIOMS}" "${KNOWN_THEOREMS}"; do
  if [ ! -f "$f" ]; then
    err "allowlist missing: $f"
    exit 2
  fi
done

read_allowlist() {
  # Strip comments and blank lines; sort -u.
  awk 'NF && !/^[[:space:]]*#/' "$1" | sort -u
}

###############################################################################
# 1. Dump axiom types from the elaborated SphincsCVerify environment, find
#    those whose elaborated type's conclusion (after stripping foralls) is
#    `True`. Compare against the allowlist.
###############################################################################

printf '==> [lint_axioms] dumping axiom types from elaborated SphincsCVerify\n'
DUMP_OUT="$(cd "${LEAN_DIR}" && lake env lean scripts/dump_axiom_types.lean 2>&1)" || {
  err "lake env lean dump_axiom_types.lean failed:"
  printf '%s\n' "${DUMP_OUT}" >&2
  exit 2
}

# Collapse multi-line axiom blocks into one line each. A new block starts
# whenever the line begins with `SphincsCVerify.` (axiom name) or
# `def SphincsCVerify.` (shape def).
COLLAPSED="$(awk '
BEGIN { buf = "" }
/^SphincsCVerify\./ {
  if (buf != "") print buf
  buf = $0
  next
}
/^def SphincsCVerify\./ {
  if (buf != "") print buf
  buf = $0
  next
}
/^[[:space:]]*$/ {
  if (buf != "") { print buf; buf = "" }
  next
}
{
  if (buf != "") {
    # join continuation lines with a single space, collapsing leading ws.
    sub(/^[[:space:]]+/, " ")
    buf = buf $0
  }
}
END { if (buf != "") print buf }
' <<< "${DUMP_OUT}")"

# Step (a): which `_Shape` defs (in `Crypto/`) unfold to `True`?
SHAPE_DEFS_TRUE="$(printf '%s\n' "${COLLAPSED}" \
  | sed -nE 's/^def ([A-Za-z0-9._]+) : Prop :=.*True$/\1/p' \
  | sort -u)"

# Step (b): axioms whose conclusion is literally `True` (i.e. the type
# string ends in `, True` or `: True`).
DIRECT_TRUE_AXIOMS="$(printf '%s\n' "${COLLAPSED}" \
  | grep -v '^def ' \
  | grep -E '(, True$|: True$)' \
  | sed -nE 's/^([A-Za-z0-9._]+) :.*/\1/p' \
  | sort -u)"

# Step (c): axioms whose type is exactly a `_Shape` name from (a).
SHAPE_TRUE_AXIOMS="$(printf '%s\n' "${COLLAPSED}" \
  | grep -v '^def ' \
  | sed -nE 's/^([A-Za-z0-9._]+) : ([A-Za-z0-9._]+)$/\1 \2/p' \
  | awk -v shapes="${SHAPE_DEFS_TRUE}" '
      BEGIN {
        n = split(shapes, arr, "\n")
        for (i = 1; i <= n; i++) if (arr[i] != "") s[arr[i]] = 1
      }
      { if (s[$2]) print $1 }
    ' \
  | sort -u)"

TRUE_AXIOMS_FROM_LEAN="$( { printf '%s\n' "${DIRECT_TRUE_AXIOMS}"; printf '%s\n' "${SHAPE_TRUE_AXIOMS}"; } \
  | grep -v '^[[:space:]]*$' | sort -u)"

###############################################################################
# 2. Source-level scan for `theorem ... : True := trivial` placeholders and
#    `axiom ... : ..., True` declarations. The Python helper handles
#    namespace tracking and multi-line declarations; the Lean dump above is
#    needed for `_Shape`-typed axioms (whose source doesn't contain `True`
#    directly).
###############################################################################

printf '==> [lint_axioms] scanning source for True-typed theorem + axiom placeholders\n'
PLACEHOLDERS_RAW="$(python3 "${SCRIPT_DIR}/lint_placeholders.py")" || {
  err "lint_placeholders.py failed"
  exit 2
}

PLACEHOLDER_THEOREMS_ACTUAL="$(printf '%s\n' "${PLACEHOLDERS_RAW}" \
  | awk '/^PLACEHOLDER / { print $2 }' \
  | sort -u)"

TRUE_AXIOMS_FROM_SOURCE="$(printf '%s\n' "${PLACEHOLDERS_RAW}" \
  | awk '/^BAD_AXIOM / { print $2 }' \
  | sort -u)"

# Union the two sources: elaborated Lean dump (catches `_Shape`-typed) and
# Python source scan (catches direct `..., True` and any newly-added axiom).
TRUE_AXIOMS_ACTUAL="$( { printf '%s\n' "${TRUE_AXIOMS_FROM_LEAN}"; printf '%s\n' "${TRUE_AXIOMS_FROM_SOURCE}"; } \
  | grep -v '^[[:space:]]*$' | sort -u)"

TRUE_AXIOMS_EXPECTED="$(read_allowlist "${KNOWN_AXIOMS}")"

# Axioms that are in the actual list but NOT in the allowlist (new bad
# axioms) — these fail the lint.
NEW_TRUE_AXIOMS="$(comm -23 \
  <(printf '%s\n' "${TRUE_AXIOMS_ACTUAL}") \
  <(printf '%s\n' "${TRUE_AXIOMS_EXPECTED}"))"

# Axioms in the allowlist but NOT in the actual list (stale entries —
# the axiom was either removed or got real content). Surface as a warning
# but do not fail; let the human update the allowlist.
STALE_TRUE_AXIOMS="$(comm -13 \
  <(printf '%s\n' "${TRUE_AXIOMS_ACTUAL}") \
  <(printf '%s\n' "${TRUE_AXIOMS_EXPECTED}"))"

PLACEHOLDER_THEOREMS_EXPECTED="$(read_allowlist "${KNOWN_THEOREMS}")"

NEW_TRIVIAL_THEOREMS="$(comm -23 \
  <(printf '%s\n' "${PLACEHOLDER_THEOREMS_ACTUAL}") \
  <(printf '%s\n' "${PLACEHOLDER_THEOREMS_EXPECTED}"))"

STALE_TRIVIAL_THEOREMS="$(comm -13 \
  <(printf '%s\n' "${PLACEHOLDER_THEOREMS_ACTUAL}") \
  <(printf '%s\n' "${PLACEHOLDER_THEOREMS_EXPECTED}"))"

###############################################################################
# 3. Report.
###############################################################################

EXIT=0

if [ -n "${NEW_TRUE_AXIOMS//[[:space:]]/}" ]; then
  err ""
  err "FAIL: new \`True\`-typed axiom(s) detected (not in allowlist):"
  printf '  - %s\n' ${NEW_TRUE_AXIOMS} >&2
  err ""
  err "Either:"
  err "  (a) refactor the axiom to carry real semantic content (preferred),"
  err "  (b) or add it to ${KNOWN_AXIOMS} with a discharge-tier reference"
  err "      pointing to contracts/verification/docs/DISCHARGE_PLAN.md."
  EXIT=1
fi

if [ -n "${NEW_TRIVIAL_THEOREMS//[[:space:]]/}" ]; then
  err ""
  err "FAIL: new \`True := trivial\` placeholder theorem(s) (not in allowlist):"
  printf '  - %s\n' ${NEW_TRIVIAL_THEOREMS} >&2
  err ""
  err "Either:"
  err "  (a) replace the placeholder with a real propositional theorem,"
  err "  (b) or add it to ${KNOWN_THEOREMS}."
  EXIT=1
fi

if [ -n "${STALE_TRUE_AXIOMS//[[:space:]]/}" ]; then
  printf '\nNOTE: %d allowlisted True-typed axiom(s) no longer in source:\n' \
    "$(printf '%s\n' "${STALE_TRUE_AXIOMS}" | grep -c .)"
  printf '  - %s\n' ${STALE_TRUE_AXIOMS}
  printf 'These have either been removed or upgraded to real content.\n'
  printf 'Trim them from %s.\n' "${KNOWN_AXIOMS}"
fi

if [ -n "${STALE_TRIVIAL_THEOREMS//[[:space:]]/}" ]; then
  printf '\nNOTE: %d allowlisted trivial theorem(s) no longer in source:\n' \
    "$(printf '%s\n' "${STALE_TRIVIAL_THEOREMS}" | grep -c .)"
  printf '  - %s\n' ${STALE_TRIVIAL_THEOREMS}
  printf 'Trim them from %s.\n' "${KNOWN_THEOREMS}"
fi

if [ "${EXIT}" -eq 0 ]; then
  N_AXIOMS="$(printf '%s\n' "${TRUE_AXIOMS_ACTUAL}" | grep -c . || true)"
  N_THEOREMS="$(printf '%s\n' "${PLACEHOLDER_THEOREMS_ACTUAL}" | grep -c . || true)"
  printf '\n==> [lint_axioms] PASS\n'
  printf '    True-typed axioms (allowlisted):       %s\n' "${N_AXIOMS}"
  printf '    Trivial theorem placeholders (allowed): %s\n' "${N_THEOREMS}"
  printf '    See contracts/verification/docs/AXIOM_STATUS.json for discharge plan.\n'
fi

exit "${EXIT}"
