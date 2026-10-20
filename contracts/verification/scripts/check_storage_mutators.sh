#!/usr/bin/env bash
#
# check_storage_mutators.sh — CLOSED-WORLD GATE for invariant I-3 ("no
# reset path", CLAUDE.md invariant #7 "per-chain caps monotonic,
# unresettable").
#
# WHY THIS EXISTS
# ---------------
# `Wallet/Invariants.lean : no_reset_path` is a kernel theorem that the
# FOUR known counter-mutators (`bumpBootstrap`, `bumpSlot`, `setOffchain`,
# `addOwner`; `removeOwner` was deleted 2026-10-20) never decrease `bootstrapUses`, any
# `slotUses[j]`, or any `offchainSigCount[j]`. But "these are the ONLY
# Storage-mutating functions" is an *out-of-Lean closed-world assertion*:
# a future `def evilReset (s : Storage) : Storage := { s with bootstrapUses
# := 0 }` added to Storage.lean — with no matching no-decrease lemma — would
# escape the kernel entirely. `no_reset_path` would still type-check and
# still be true about its four conjuncts, yet the new resetter sits
# unverified beside it.
#
# This lint closes that gap structurally. It extracts the COMPLETE set of
# `def`s in `Wallet/Storage.lean` that *return a `Storage`* (return type
# `Storage` or `Option Storage` — the only way to introduce a new
# constructor/mutator) and the set of `def`s that perform a `{ s with ... }`
# record-update (the only way to mutate an existing `Storage`), and compares
# both against a PINNED allow-list below. If either set differs from the
# allow-list the lint FAILS — so adding any new Storage-returning /
# Storage-updating def forces a conscious decision:
#   1. add it to the allow-list here, AND
#   2. add a matching no-decrease (or counter-preservation) lemma to
#      Invariants.lean and wire it into `no_reset_path`.
#
# This converts the closed-world assumption from a comment into a CI gate.
#
# Run from anywhere; resolves the repo root from its own location.
#
# Exit codes:
#   0  the Storage-returning / Storage-updating def set matches the
#      allow-list (PASS)
#   1  the set drifted from the allow-list (FAIL) — a mutator was added,
#      removed, or renamed without updating this gate
#   2  internal error (missing file / tooling)
#
# Invoked from `make verify-storage-mutators` (and from CI).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
STORAGE_LEAN="${REPO_ROOT}/contracts/verification/lean/SphincsCVerify/Wallet/Storage.lean"

err() { printf 'check_storage_mutators.sh: %s\n' "$*" >&2; }

if [ ! -f "${STORAGE_LEAN}" ]; then
  err "Storage.lean not found at ${STORAGE_LEAN}"
  exit 2
fi

###############################################################################
# PINNED ALLOW-LISTS
#
# (A) Every `def` in Storage.lean whose return type is `Storage` or
#     `Option Storage`. These are the only functions that can produce a
#     `Storage` value (constructor or mutator). Each entry's monotonicity /
#     counter-preservation MUST be covered by a lemma in Invariants.lean and
#     wired into `no_reset_path` (or, for the two pure constructors `empty` /
#     `initialised`, be a fresh all-zero-counter genesis state).
#
#     empty         — genesis (all counters 0; no `s` input → cannot decrease)
#     initialised   — factory genesis (all counters 0; no `s` input)
#     bumpBootstrap — no_reset_path conjunct 1 (bumpBootstrap_no_decrease)
#     bumpSlot      — no_reset_path conjunct 2 (bumpSlot_no_decrease)
#     setOffchain   — no_reset_path conjunct 3 (setOffchain_no_decrease_offchain)
#     addOwner      — no_reset_path conjunct 4 (addOwner_preserves_counters)
#     tryInitialize — guarded wrapper over `initialised`; only fires when
#                     nextOwnerIndex == 0 (one-shot), producing the all-zero
#                     genesis state, so it cannot decrease a live counter.
#     (removeOwner, formerly conjunct 5, was deleted with on-chain owner
#      removal before launch, 2026-10-20.)
###############################################################################
ALLOWLIST_RETURNS_STORAGE=$(cat <<'EOF'
empty
initialised
bumpBootstrap
bumpSlot
setOffchain
addOwner
tryInitialize
EOF
)

# (B) Every `def` whose body contains a `{ s with ... }` record-update — the
#     only way to mutate an *existing* Storage. Strict subset of (A) minus
#     the pure constructors (empty/initialised build from scratch) and the
#     guarded wrapper (tryInitialize delegates to `initialised`).
ALLOWLIST_S_WITH=$(cat <<'EOF'
bumpBootstrap
bumpSlot
setOffchain
addOwner
EOF
)

# (C) Names of defs whose body ASSIGNS a cap-counter field — `bootstrapUses :=`,
#     `slotUses :=`, or `offchainSigCount :=` — by ANY construction syntax
#     (`{ s with ... }` OR a full record literal `{ bootstrapUses := 0, ... }`)
#     and regardless of return type (`Storage`, `Option Storage`, `Except _
#     Storage`, a tuple, …). This is the load-bearing gate: it keys on the
#     SEMANTIC act of writing a counter, so a resetter cannot evade it by hiding
#     behind a wrapper return type + a full record literal (the gap an
#     adversarial PoC demonstrated against filters (A)+(B), which key on
#     return-type and `{ s with }` syntax respectively). Allow-list = exactly the
#     defs that legitimately write a counter: the two all-zero genesis
#     constructors + the three monotone bumpers. addOwner / tryInitialize do
#     NOT write a cap-counter field.
ALLOWLIST_COUNTER_ASSIGN=$(cat <<'EOF'
empty
initialised
bumpBootstrap
bumpSlot
setOffchain
EOF
)

###############################################################################
# EXTRACTION
#
# Lean def signatures can span multiple lines, e.g.
#   def someMutator
#       (s : Storage) (index : Nat) (o : OwnerBytes) : Option Storage :=
# We join each `def NAME ... :=` declaration head into one logical line, then
# match the return type that immediately precedes `:=`.
###############################################################################

# Restrict to the `namespace Storage` ... `end Storage` block so we don't pick
# up unrelated defs (e.g. OwnerBytes.hasNMaskLayout).
STORAGE_BLOCK="$(awk '
  /^namespace Storage[[:space:]]*$/ { inblk = 1; next }
  /^end Storage[[:space:]]*$/       { inblk = 0; next }
  inblk { print }
' "${STORAGE_LEAN}")"

# Join each declaration head: accumulate from a line starting with `def `
# until we hit `:=` (the body separator), collapsing to one line.
JOINED_DEFS="$(printf '%s\n' "${STORAGE_BLOCK}" | awk '
  BEGIN { buf = ""; collecting = 0 }
  {
    line = $0
    if (collecting == 0 && line ~ /^def /) {
      buf = line
      collecting = 1
    } else if (collecting == 1) {
      sub(/^[[:space:]]+/, " ", line)
      buf = buf line
    }
    if (collecting == 1 && buf ~ /:=/) {
      # Trim everything from `:=` onward, print the decl head.
      sub(/:=.*/, "", buf)
      print buf
      buf = ""
      collecting = 0
    }
  }
')"

# (A) Names whose return type (last `: <Type>` before the trimmed `:=`) is
#     exactly `Storage` or `Option Storage`.
ACTUAL_RETURNS_STORAGE="$(printf '%s\n' "${JOINED_DEFS}" \
  | grep -E ':[[:space:]]*(Option[[:space:]]+)?Storage[[:space:]]*$' \
  | sed -nE 's/^def[[:space:]]+([A-Za-z0-9_]+).*/\1/p' \
  | sort -u)"

# (B) Names of defs whose body contains a `{ s with ... }` record-update.
#     The open-brace and `s with` may be on the same line (`some { s with x`)
#     or split across lines (`some {` / `s with x`). Re-scan the full Storage
#     block per-def: collapse each def's body to one whitespace-normalised
#     line and search for `{ s with` (any whitespace, including the former
#     newline, between `{` and `s with`).
ACTUAL_S_WITH="$(printf '%s\n' "${STORAGE_BLOCK}" | awk '
  function flush(   joined) {
    if (cur != "") {
      joined = body
      gsub(/[[:space:]]+/, " ", joined)
      if (joined ~ /\{ s with/) print cur
    }
  }
  /^def / {
    flush()
    cur = $2
    # Seed body with the def line itself so a one-line def whose body lives
    # on the same line (`def evilReset (s : Storage) : Storage := { s with
    # ... }`) is still scanned for the record-update.
    body = $0
    next
  }
  { body = body " " $0 }
  END { flush() }
' | sort -u)"

# (C) Names of defs that ASSIGN a cap-counter field (any syntax / any return
#     type). Same per-def body collapse as (B), but matching the counter-field
#     `:=` write directly rather than the `{ s with` syntax — so a full record
#     literal behind a wrapper return type cannot slip through.
ACTUAL_COUNTER_ASSIGN="$(printf '%s\n' "${STORAGE_BLOCK}" | awk '
  function flush(   joined) {
    if (cur != "") {
      joined = body
      gsub(/[[:space:]]+/, " ", joined)
      if (joined ~ /(bootstrapUses|slotUses|offchainSigCount)[[:space:]]*:=/) print cur
    }
  }
  /^def / { flush(); cur = $2; body = $0; next }
  { body = body " " $0 }
  END { flush() }
' | sort -u)"

###############################################################################
# COMPARE
###############################################################################

EXPECTED_A="$(printf '%s\n' "${ALLOWLIST_RETURNS_STORAGE}" | grep -v '^[[:space:]]*$' | sort -u)"
EXPECTED_B="$(printf '%s\n' "${ALLOWLIST_S_WITH}" | grep -v '^[[:space:]]*$' | sort -u)"
EXPECTED_C="$(printf '%s\n' "${ALLOWLIST_COUNTER_ASSIGN}" | grep -v '^[[:space:]]*$' | sort -u)"

EXIT=0

# --- Set (A): Storage-returning defs ---
NEW_A="$(comm -13 <(printf '%s\n' "${EXPECTED_A}") <(printf '%s\n' "${ACTUAL_RETURNS_STORAGE}"))"
MISSING_A="$(comm -23 <(printf '%s\n' "${EXPECTED_A}") <(printf '%s\n' "${ACTUAL_RETURNS_STORAGE}"))"

if [ -n "${NEW_A//[[:space:]]/}" ]; then
  err ""
  err "FAIL: NEW Storage-returning def(s) in Storage.lean not in the allow-list:"
  printf '  + %s\n' ${NEW_A} >&2
  err ""
  err "A new function that returns Storage / Option Storage is a new"
  err "constructor or mutator. The I-3 closed-world guarantee (no_reset_path"
  err "covers ALL mutators) no longer holds until you BOTH:"
  err "  1. add a matching no-decrease / counter-preservation lemma in"
  err "     Wallet/Invariants.lean and wire it into \`no_reset_path\`, AND"
  err "  2. add the def name to ALLOWLIST_RETURNS_STORAGE in this script."
  EXIT=1
fi

if [ -n "${MISSING_A//[[:space:]]/}" ]; then
  err ""
  err "FAIL: allow-listed Storage-returning def(s) no longer present in source:"
  printf '  - %s\n' ${MISSING_A} >&2
  err ""
  err "A mutator was removed or renamed. Update ALLOWLIST_RETURNS_STORAGE"
  err "(and the corresponding \`no_reset_path\` conjunct) to match."
  EXIT=1
fi

# --- Set (B): `{ s with }` record-update defs ---
NEW_B="$(comm -13 <(printf '%s\n' "${EXPECTED_B}") <(printf '%s\n' "${ACTUAL_S_WITH}"))"
MISSING_B="$(comm -23 <(printf '%s\n' "${EXPECTED_B}") <(printf '%s\n' "${ACTUAL_S_WITH}"))"

if [ -n "${NEW_B//[[:space:]]/}" ]; then
  err ""
  err "FAIL: NEW \`{ s with ... }\` record-update def(s) not in the allow-list:"
  printf '  + %s\n' ${NEW_B} >&2
  err ""
  err "An in-place Storage mutation must have a no-decrease lemma. Add the"
  err "lemma + wire it into \`no_reset_path\`, then add the name to"
  err "ALLOWLIST_S_WITH in this script."
  EXIT=1
fi

if [ -n "${MISSING_B//[[:space:]]/}" ]; then
  err ""
  err "FAIL: allow-listed \`{ s with ... }\` def(s) no longer present in source:"
  printf '  - %s\n' ${MISSING_B} >&2
  err "Update ALLOWLIST_S_WITH to match."
  EXIT=1
fi

# --- Set (C): cap-counter-assigning defs (the load-bearing semantic gate) ---
NEW_C="$(comm -13 <(printf '%s\n' "${EXPECTED_C}") <(printf '%s\n' "${ACTUAL_COUNTER_ASSIGN}"))"
MISSING_C="$(comm -23 <(printf '%s\n' "${EXPECTED_C}") <(printf '%s\n' "${ACTUAL_COUNTER_ASSIGN}"))"

if [ -n "${NEW_C//[[:space:]]/}" ]; then
  err ""
  err "FAIL: NEW def(s) ASSIGN a cap-counter field (bootstrapUses / slotUses /"
  err "offchainSigCount) but are not in the allow-list:"
  printf '  + %s\n' ${NEW_C} >&2
  err ""
  err "A def that writes a cap counter is a mutator REGARDLESS of its return"
  err "type or construction syntax (this gate caught what filters (A)+(B) miss:"
  err "a wrapper return type + a full record literal). The I-3 closed-world"
  err "guarantee (\`no_reset_path\` + \`Reachable\` completeness) no longer holds"
  err "until you BOTH: (1) add a no-decrease / counter-preservation lemma and a"
  err "matching \`Reachable\` transition, AND (2) add the name to"
  err "ALLOWLIST_COUNTER_ASSIGN here."
  EXIT=1
fi

if [ -n "${MISSING_C//[[:space:]]/}" ]; then
  err ""
  err "FAIL: allow-listed cap-counter-assigning def(s) no longer present:"
  printf '  - %s\n' ${MISSING_C} >&2
  err "Update ALLOWLIST_COUNTER_ASSIGN to match."
  EXIT=1
fi

###############################################################################
# REPORT
###############################################################################

if [ "${EXIT}" -eq 0 ]; then
  N_A="$(printf '%s\n' "${ACTUAL_RETURNS_STORAGE}" | grep -c . || true)"
  N_B="$(printf '%s\n' "${ACTUAL_S_WITH}" | grep -c . || true)"
  printf '==> [check_storage_mutators] PASS\n'
  printf '    Storage-returning defs (allow-listed):  %s\n' "${N_A}"
  printf '      %s\n' ${ACTUAL_RETURNS_STORAGE}
  printf '    { s with } record-update defs (allow):   %s\n' "${N_B}"
  printf '      %s\n' ${ACTUAL_S_WITH}
  N_C="$(printf '%s\n' "${ACTUAL_COUNTER_ASSIGN}" | grep -c . || true)"
  printf '    cap-counter-assigning defs (allow):      %s\n' "${N_C}"
  printf '      %s\n' ${ACTUAL_COUNTER_ASSIGN}
  printf '    Every Storage mutator is covered by a no_reset_path conjunct\n'
  printf '    (Wallet/Invariants.lean). I-3 closed-world gate intact, including\n'
  printf '    the semantic counter-assignment gate (C) — wrapper/record-literal\n'
  printf '    resetters cannot evade.\n'
fi

exit "${EXIT}"
