#!/usr/bin/env bash
# Turnkey Kontrol (KEVM) proof runner for the PQSmartWallet model-to-bytecode
# bridge (axioms A3.2 / A3.3 / A3.4) — KEVM symbolic-execution proofs DIRECTLY
# against the deployed runtime bytecode, an engine independent of Halmos with no
# hand-written LeanModel.sol mirror in the loop. REQUIRES a working K Framework
# backend (`kompile`, `kore-rpc-booster`); install via `kup install kontrol`
# (Nix) or the runtimeverification/kontrol Docker image. See
# ../docs/KONTROL_SCOPING.md.
#
# Stages EVERY harness under kontrol/test/ into the smart-wallet Foundry project
# (so its remappings + lib submodules resolve), then runs `kontrol build` +
# `kontrol prove` over all Kontrol* test contracts, then asserts the proof
# results against the pinned identity baseline below (fv-deep-review-2026-07-19
# F9 / sweep-F52 / tracker #197).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SW="$HERE/../../smart-wallet"            # the Foundry project (has lib/ + remappings)
SRC_DIR="$HERE/test"                     # all Kontrol harnesses live here
DEST_DIR="$SW/test/kontrol"
# Foundry >= 1.8 (the CI pin) enables dynamic test linking by default, which
# compiles `new X(...)` in test contracts to `vm.deployCode(...)`; the symbolic
# engines here expect plain creation code. Bytecode under test is unaffected.
export FOUNDRY_DYNAMIC_TEST_LINKING=false

# --- Proof-identity baseline (fv-deep-review-2026-07-19 F9 / sweep-F52) ------
# Every `prove_*` function wired under kontrol/test/, as the compiler-canonical
# <Contract>.<function>(<ABI types>) identity used by both fresh Foundry
# artifacts and `kontrol list`. Verified 2026-07-19 against the tree: 33 proofs
# across 5 harnesses — KontrolValidateUserOp 7, KontrolExecute 8,
# KontrolOwnerTable 9, KontrolFactory 6, KontrolBootstrapUnremovable 3 —
# matching the 33/33 discharge recorded in ../docs/KONTROL_SCOPING.md
# (2026-06-15; the 2026-07-18 sweep's "38 prove_ functions" was a miscount).
# 2026-10-20 (audit freeze, owner removal deleted): 31 proofs — KontrolOwnerTable
# 7 (three removal proofs replaced by one selector-absent proof), and the three
# KontrolBootstrapUnremovable proofs restated for the append-only owner set.
# Bump this list when adding/removing a proof; fv-deep-review-2026-07-19 F9.
EXPECTED_PROOFS=(
  "KontrolBootstrapUnremovable.prove_bootstrap_unchanged_by_addOwner(bytes)"
  "KontrolBootstrapUnremovable.prove_bootstrap_removal_selector_does_not_dispatch(address,bytes)"
  "KontrolBootstrapUnremovable.prove_bootstrap_reinitialize_rejected(bytes,bytes)"
  "KontrolExecute.prove_execute_requires_entrypoint(address,uint256,uint256,uint256,bytes)"
  "KontrolExecute.prove_execute_no_credit_reverts(uint256,uint256,uint256,bytes)"
  "KontrolExecute.prove_execute_rejects_self_target(uint256,uint256,bytes)"
  "KontrolExecute.prove_execute_pointwise(uint256,uint256,uint256,uint256,bytes)"
  "KontrolExecute.prove_execute_credit_one_shot(uint256,bytes)"
  "KontrolExecute.prove_execute_atomic_on_reverting_target(uint256,bytes)"
  "KontrolExecute.prove_executeBatch_rejects_self_target(uint256,bytes)"
  "KontrolExecute.prove_executeBatch_pointwise()"
  "KontrolFactory.prove_createAccount_iff(uint64,bool)"
  "KontrolFactory.prove_createAccount_rejects_non_nmasked_slot0()"
  "KontrolFactory.prove_createAccount_rejects_non_nmasked_master()"
  "KontrolFactory.prove_createAccount_rejects_duplicate_slot0()"
  "KontrolFactory.prove_createAccount_rejects_wrong_chain(uint64)"
  "KontrolFactory.prove_createAccount_already_deployed_returns_existing(uint64,bytes32,bytes32,bool)"
  "KontrolOwnerTable.prove_addOwner_len64_pointwise(bytes)"
  "KontrolOwnerTable.prove_addOwner_rejects_len63(bytes)"
  "KontrolOwnerTable.prove_addOwner_rejects_len65(bytes)"
  "KontrolOwnerTable.prove_removed_selector_does_not_dispatch(address,uint256,bytes)"
  "KontrolOwnerTable.prove_initialize_one_shot(bytes,bytes)"
  "KontrolOwnerTable.prove_initialize_fresh_pointwise(bytes,bytes)"
  "KontrolOwnerTable.prove_addOwner_rejects_non_entrypoint(address,bytes)"
  "KontrolValidateUserOp.prove_validate_slot_nonbypass(uint256,uint256,bool)"
  "KontrolValidateUserOp.prove_validate_bootstrap_nonbypass(uint256,bool)"
  "KontrolValidateUserOp.prove_validate_rejects_unset_owner(bool)"
  "KontrolValidateUserOp.prove_validate_rejects_non_entrypoint(address)"
  "KontrolValidateUserOp.prove_validate_rejects_bad_offset(uint256)"
  "KontrolValidateUserOp.prove_validate_rejects_bad_innerlen(uint256)"
  "KontrolValidateUserOp.prove_validate_rejects_bad_tailpad(bytes32)"
)

# Emit the exact contract-qualified proof identities wired in the source tree.
# The parser tracks the current Solidity contract, so a one-for-one rename or a
# same-count replacement cannot satisfy the baseline by count alone.
_wired_proof_inventory() {
  local harness
  for harness in "$SRC_DIR"/*.t.sol; do
    awk '
      /^[[:space:]]*(abstract[[:space:]]+)?contract[[:space:]]+/ {
        line = $0
        sub(/^[[:space:]]*(abstract[[:space:]]+)?contract[[:space:]]+/, "", line)
        sub(/[^A-Za-z0-9_].*$/, "", line)
        contract_name = line
        next
      }
      /^[[:space:]]*function[[:space:]]+prove_[A-Za-z0-9_]+/ {
        line = $0
        sub(/^[[:space:]]*function[[:space:]]+/, "", line)
        sub(/[^A-Za-z0-9_].*$/, "", line)
        if (contract_name == "") {
          print "<missing-contract>." line
        } else {
          print contract_name "." line
        }
      }
    ' "$harness"
  done | sort
}

_assert_expected_identity_text() {
  local actual_text="$1"
  local expected_text
  expected_text=$(printf '%s\n' "${EXPECTED_PROOFS[@]}" | sort)
  if [ "$actual_text" != "$expected_text" ]; then
    echo "==> FAIL: wired Kontrol proof identities differ from EXPECTED_PROOFS" >&2
    echo "    missing:" >&2
    comm -23 <(printf '%s\n' "$expected_text") <(printf '%s\n' "$actual_text") |
      sed 's/^/      - /' >&2
    echo "    unexpected:" >&2
    comm -13 <(printf '%s\n' "$expected_text") <(printf '%s\n' "$actual_text") |
      sed 's/^/      - /' >&2
    return 1
  fi
}

# The early source parser intentionally records names only. The load-bearing
# signature check uses fresh compiler artifacts after `kontrol build`; this
# preflight still catches a missing, renamed, or unexpected source proof before
# staging/backend work begins.
_assert_expected_source_names_text() {
  local actual_text="$1"
  local expected_text
  expected_text=$(printf '%s\n' "${EXPECTED_PROOFS[@]}" | sed 's/(.*$//' | sort)
  if [ "$actual_text" != "$expected_text" ]; then
    echo "==> FAIL: wired Kontrol proof names differ from EXPECTED_PROOFS" >&2
    echo "    missing:" >&2
    comm -23 <(printf '%s\n' "$expected_text") <(printf '%s\n' "$actual_text") |
      sed 's/^/      - /' >&2
    echo "    unexpected:" >&2
    comm -13 <(printf '%s\n' "$expected_text") <(printf '%s\n' "$actual_text") |
      sed 's/^/      - /' >&2
    return 1
  fi
}

# check_proof_inventory: the pinned baseline must match the wired source names.
check_proof_inventory() {
  _assert_expected_source_names_text "$(_wired_proof_inventory)"
}

# Emit compiler-canonical identities from every fresh Kontrol*.json artifact.
# `forge clean` runs immediately before `kontrol build`, so this cannot accept a
# deleted harness through stale artifacts. Scanning all matching artifacts also
# makes a newly added KontrolEvil.prove_* identity fail as unexpected.
_compiled_proof_inventory() {
  python3 - "$SW/out" <<'PY'
import json
import sys
from pathlib import Path

out_dir = Path(sys.argv[1])
for artifact in sorted(out_dir.glob("*.t.sol/Kontrol*.json")):
    contract = artifact.stem
    data = json.loads(artifact.read_text(encoding="utf-8"))
    methods = data.get("methodIdentifiers")
    if not isinstance(methods, dict):
        raise SystemExit(f"malformed Foundry artifact (no methodIdentifiers): {artifact}")
    for signature in sorted(methods):
        if signature.startswith("prove_"):
            print(f"{contract}.{signature}")
PY
}

check_compiled_proof_inventory() {
  _assert_expected_identity_text "$(_compiled_proof_inventory | sort)"
}

_is_expected_proof() {
  local candidate="$1" expected
  for expected in "${EXPECTED_PROOFS[@]}"; do
    [ "$candidate" = "$expected" ] && return 0
  done
  return 1
}

# `kontrol list` prints one blank-line-separated block per proof (pyk
# APRSummary.lines), of the form:
#   APRProof: test%kontrol%KontrolExecute.prove_execute_pointwise(uint256,uint256):0
#       status: ProofStatus.PASSED        ('status: PASSED' also accepted)
#       admitted: False
#       nodes / pending / failing / ...
#   Subproofs: 0
# _kontrol_list_records prints one tab-separated row per proof:
#   <Contract>.<function>(<ABI types>)  <version>  <status>  <admitted>
# Missing or ambiguous fields are emitted explicitly and therefore fail closed
# in assert_kontrol_list. Line-based (no multiline-record regexes) so it
# behaves identically under gawk and mawk.
_kontrol_list_records() {
  awk '
    function reset() {
      proof_id = ""
      version = "<missing>"
      status = "<missing>"
      admitted = "<missing>"
      status_fields = 0
      admitted_fields = 0
    }
    function flush() {
      if (proof_id == "") return
      if (status_fields != 1) status = "<ambiguous>"
      if (admitted_fields != 1) admitted = "<ambiguous>"
      printf "%s\t%s\t%s\t%s\n", proof_id, version, status, admitted
      reset()
    }
    function parse_header(line, raw, suffix) {
      raw = line
      sub(/^(APRProof|Proof):[[:space:]]*/, "", raw)
      sub(/[[:space:]]+$/, "", raw)
      version = "<missing>"
      if (match(raw, /:[0-9]+$/)) {
        suffix = substr(raw, RSTART + 1)
        raw = substr(raw, 1, RSTART - 1)
        version = suffix
      }
      sub(/^.*%/, "", raw)
      proof_id = raw
    }
    BEGIN                                          { reset() }
    /^(APRProof|Proof):[[:space:]]/                { flush(); parse_header($0); next }
    /^[[:space:]]+status:[[:space:]]*/ {
      status_fields++
      status = $0
      sub(/^[[:space:]]+status:[[:space:]]*/, "", status)
      sub(/[[:space:]]+$/, "", status)
      sub(/^ProofStatus\./, "", status)
      next
    }
    /^[[:space:]]+admitted:[[:space:]]*/ {
      admitted_fields++
      admitted = $0
      sub(/^[[:space:]]+admitted:[[:space:]]*/, "", admitted)
      sub(/[[:space:]]+$/, "", admitted)
      next
    }
    NF==0                                          { flush() }
    END                                            { flush() }
  ' "$1"
}

# assert_kontrol_list <kontrol-list-output-file>: every expected identity must
# have exactly one record, and that record must be fresh version 0, PASSED, and
# explicitly `admitted: False`. Non-prove setup records are ignored, but every
# selected `Kontrol*.prove_*` record must belong to the baseline.
assert_kontrol_list() {
  local listfile="$1"
  local records matches nrecords id got_id version status admitted rc=0
  records=$(_kontrol_list_records "$listfile")
  while IFS=$'\t' read -r got_id version status admitted; do
    [ -n "$got_id" ] || continue
    if [[ "$got_id" =~ ^Kontrol.*\.prove_ ]] && ! _is_expected_proof "$got_id"; then
      echo "==> FAIL: unexpected selected Kontrol proof record: $got_id" >&2
      rc=1
    fi
  done <<< "$records"
  for id in "${EXPECTED_PROOFS[@]}"; do
    matches=$(printf '%s\n' "$records" | awk -F '\t' -v expected="$id" '$1 == expected')
    nrecords=$(printf '%s\n' "$matches" | awk 'NF { count++ } END { print count + 0 }')
    if [ "$nrecords" -ne 1 ]; then
      echo "==> FAIL: expected exactly one 'kontrol list' record for $id; found $nrecords" >&2
      rc=1
      continue
    fi
    IFS=$'\t' read -r got_id version status admitted <<< "$matches"
    if [ "$got_id" != "$id" ] || [ "$version" != "0" ] ||
       [ "$status" != "PASSED" ] || [ "$admitted" != "False" ]; then
      echo "==> FAIL: invalid proof record for $id: version=$version status=$status admitted=$admitted (require version=0 status=PASSED admitted=False)" >&2
      rc=1
    fi
  done
  return "$rc"
}

# self_test: positive + negative controls for assert_kontrol_list, against
# synthetic `kontrol list` fixtures (no K backend needed).
self_test() {
  local d; d="$(mktemp -d /tmp/pq1-kontrol-baseline-selftest.XXXXXX)"
  local mk_block
  mk_block() {  # <id> <version> <status> <admitted|OMIT>
    printf 'APRProof: test%%kontrol%%%s:%s\n    status: %s\n' "$1" "$2" "$3"
    if [ "$4" != "OMIT" ]; then
      printf '    admitted: %s\n' "$4"
    fi
    printf '    nodes: 7\n    pending: 0\n    failing: 0\n    vacuous: 0\n    stuck: 0\n    terminal: 3\n    refuted: 0\n    bounded: 0\n    execution time: 0m1s\nSubproofs: 0\n\n'
  }
  local id rc=0
  # Complete fixture: all expected proofs PASSED, none admitted. An unrelated
  # setup proof demonstrates that records outside the identity baseline do not
  # affect the authoritative result.
  : > "$d/complete.txt"
  for id in "${EXPECTED_PROOFS[@]}"; do mk_block "$id" "0" "ProofStatus.PASSED" "False" >> "$d/complete.txt"; done
  mk_block "KontrolSetup.setUp()" "7" "ProofStatus.FAILED" "OMIT" >> "$d/complete.txt"
  # missing-one: drop the last expected proof
  : > "$d/missing.txt"
  for id in "${EXPECTED_PROOFS[@]:0:$((${#EXPECTED_PROOFS[@]}-1))}"; do mk_block "$id" "0" "ProofStatus.PASSED" "False" >> "$d/missing.txt"; done
  # failed-one: one proof FAILED
  : > "$d/failed.txt"
  for id in "${EXPECTED_PROOFS[@]}"; do
    if [ "$id" = "KontrolExecute.prove_execute_pointwise(uint256,uint256,uint256,uint256,bytes)" ]; then mk_block "$id" "0" "ProofStatus.FAILED" "False" >> "$d/failed.txt"; else mk_block "$id" "0" "ProofStatus.PASSED" "False" >> "$d/failed.txt"; fi
  done
  # admitted-one: one proof PASSED but admitted (not a real proof)
  : > "$d/admitted.txt"
  for id in "${EXPECTED_PROOFS[@]}"; do
    if [ "$id" = "KontrolFactory.prove_createAccount_iff(uint64,bool)" ]; then mk_block "$id" "0" "ProofStatus.PASSED" "True" >> "$d/admitted.txt"; else mk_block "$id" "0" "ProofStatus.PASSED" "False" >> "$d/admitted.txt"; fi
  done
  # missing-admission: omission must not be interpreted as False
  : > "$d/missing-admission.txt"
  for id in "${EXPECTED_PROOFS[@]}"; do
    if [ "$id" = "KontrolOwnerTable.prove_initialize_one_shot(bytes,bytes)" ]; then mk_block "$id" "0" "ProofStatus.PASSED" "OMIT" >> "$d/missing-admission.txt"; else mk_block "$id" "0" "ProofStatus.PASSED" "False" >> "$d/missing-admission.txt"; fi
  done
  # duplicate-version: a stale v0 pass plus a newer v1 failure is ambiguous,
  # not a valid proof receipt.
  cp "$d/complete.txt" "$d/duplicate-version.txt"
  mk_block "KontrolExecute.prove_execute_pointwise(uint256,uint256,uint256,uint256,bytes)" "1" "ProofStatus.FAILED" "False" >> "$d/duplicate-version.txt"
  # wrong-version: one passing record at a nonzero version is not fresh v0.
  : > "$d/wrong-version.txt"
  for id in "${EXPECTED_PROOFS[@]}"; do
    if [ "$id" = "KontrolValidateUserOp.prove_validate_slot_nonbypass(uint256,uint256,bool)" ]; then mk_block "$id" "1" "ProofStatus.PASSED" "False" >> "$d/wrong-version.txt"; else mk_block "$id" "0" "ProofStatus.PASSED" "False" >> "$d/wrong-version.txt"; fi
  done
  # unexpected selected prove_* record: all expected records plus a same-scope
  # proof must fail (non-prove setup records above remain allowed).
  cp "$d/complete.txt" "$d/unexpected-proof.txt"
  mk_block "KontrolEvil.prove_bypass()" "0" "ProofStatus.PASSED" "False" >> "$d/unexpected-proof.txt"
  # Same proof name and count, but a narrowed ABI type: this used to pass after
  # the parser erased the `(types)` suffix.
  sed 's/prove_createAccount_iff(uint64,bool)/prove_createAccount_iff(uint8,bool)/' \
    "$d/complete.txt" > "$d/signature-drift.txt"
  # empty fixture
  : > "$d/empty.txt"

  echo "-- self-test 1/12: complete fixture (${#EXPECTED_PROOFS[@]} PASSED v0 + unrelated setup record) — must be ACCEPTED"
  if assert_kontrol_list "$d/complete.txt" >/dev/null 2>&1; then echo "   OK: accepted"; else echo "   CONTROL FAILURE: rejected a complete list" >&2; rc=1; fi
  echo "-- self-test 2/12: missing-one fixture ($((${#EXPECTED_PROOFS[@]}-1)) PASSED) — must be REJECTED"
  if assert_kontrol_list "$d/missing.txt" >/dev/null 2>&1; then echo "   CONTROL FAILURE: missing proof accepted!" >&2; rc=1; else echo "   OK: rejected"; fi
  echo "-- self-test 3/12: failed-status fixture — must be REJECTED"
  if assert_kontrol_list "$d/failed.txt" >/dev/null 2>&1; then echo "   CONTROL FAILURE: FAILED proof accepted!" >&2; rc=1; else echo "   OK: rejected"; fi
  echo "-- self-test 4/12: admitted-proof fixture — must be REJECTED"
  if assert_kontrol_list "$d/admitted.txt" >/dev/null 2>&1; then echo "   CONTROL FAILURE: admitted proof accepted!" >&2; rc=1; else echo "   OK: rejected"; fi
  echo "-- self-test 5/12: missing-admission fixture — must be REJECTED"
  if assert_kontrol_list "$d/missing-admission.txt" >/dev/null 2>&1; then echo "   CONTROL FAILURE: proof without explicit admission state accepted!" >&2; rc=1; else echo "   OK: rejected"; fi
  echo "-- self-test 6/12: duplicate v0-PASSED + v1-FAILED fixture — must be REJECTED"
  if assert_kontrol_list "$d/duplicate-version.txt" >/dev/null 2>&1; then echo "   CONTROL FAILURE: duplicate proof versions accepted!" >&2; rc=1; else echo "   OK: rejected"; fi
  echo "-- self-test 7/12: single nonzero-version fixture — must be REJECTED"
  if assert_kontrol_list "$d/wrong-version.txt" >/dev/null 2>&1; then echo "   CONTROL FAILURE: nonzero proof version accepted!" >&2; rc=1; else echo "   OK: rejected"; fi
  echo "-- self-test 8/12: unexpected Kontrol*.prove_* record — must be REJECTED"
  if assert_kontrol_list "$d/unexpected-proof.txt" >/dev/null 2>&1; then echo "   CONTROL FAILURE: unexpected selected proof accepted!" >&2; rc=1; else echo "   OK: rejected"; fi
  echo "-- self-test 9/12: same-name result signature drift — must be REJECTED"
  if assert_kontrol_list "$d/signature-drift.txt" >/dev/null 2>&1; then echo "   CONTROL FAILURE: narrowed proof signature accepted!" >&2; rc=1; else echo "   OK: rejected"; fi
  echo "-- self-test 10/12: same-count source-name swap — must be REJECTED"
  local wired swapped
  wired="$(_wired_proof_inventory)"
  swapped=$(printf '%s\n' "$wired" | sed '1cKontrolEvil.prove_bypass' | sort)
  if _assert_expected_source_names_text "$swapped" >/dev/null 2>&1; then echo "   CONTROL FAILURE: same-count source-name swap accepted!" >&2; rc=1; else echo "   OK: rejected"; fi
  echo "-- self-test 11/12: same-name compiled signature drift — must be REJECTED"
  local compiled_drift
  compiled_drift=$(printf '%s\n' "${EXPECTED_PROOFS[@]}" |
    sed 's/prove_createAccount_iff(uint64,bool)/prove_createAccount_iff(uint8,bool)/' |
    sort)
  if _assert_expected_identity_text "$compiled_drift" >/dev/null 2>&1; then echo "   CONTROL FAILURE: narrowed compiled signature accepted!" >&2; rc=1; else echo "   OK: rejected"; fi
  echo "-- self-test 12/12: empty fixture — must be REJECTED"
  if assert_kontrol_list "$d/empty.txt" >/dev/null 2>&1; then echo "   CONTROL FAILURE: green-at-zero accepted!" >&2; rc=1; else echo "   OK: rejected"; fi
  rm -rf "$d"
  if [ "$rc" -eq 0 ]; then
    echo "run_kontrol.sh --self-test: all controls behave"
  else
    echo "run_kontrol.sh --self-test: CONTROL FAILURE" >&2
  fi
  return "$rc"
}

if [ "$#" -ne 0 ]; then
  if [ "$#" -eq 1 ] && [ "$1" = "--self-test" ]; then
    self_test
    exit $?
  fi
  echo "usage: $0 [--self-test]" >&2
  exit 2
fi

# This is the authoritative all-proof gate. A caller-controlled matcher could
# silently run only a subset while the persistent proof store supplied stale
# records for the rest, so partial MATCH overrides are not supported here.
if [ -v MATCH ]; then
  echo "ERROR: MATCH overrides are forbidden by the authoritative Kontrol gate; run the exact Kontrol.*\\.prove_ proof set." >&2
  exit 2
fi

# NOTE: `kompile` / `kore-rpc-booster` are NOT expected on the outer PATH when
# Kontrol is installed via `kup install kontrol` (Nix) — the `kontrol` wrapper
# prepends its OWN bundled K backend (k-<ver>/bin) internally. So we require
# only the `kontrol` CLI; it self-contains the symbolic-execution engine.
command -v kontrol >/dev/null 2>&1 || {
  echo "ERROR: 'kontrol' CLI not found. Install with:"
  echo "         bash <(curl https://kframework.org/install)   # installs kup (Nix)"
  echo "         kup install kontrol"
  echo "       or use the runtimeverification/kontrol Docker image."
  echo "       See ../docs/KONTROL_SCOPING.md."
  exit 2
}

# kontrol-cheatcodes (symbolic helpers) is a TRANSIENT kontrol artifact and must
# NOT linger in the smart-wallet lib/: Foundry auto-generates a remapping for
# every lib/ dir and folds the remapping list into solc metadata, so its mere
# presence shifts EVERY pinned contract codehash and turns the codehash freeze
# tests (`forge test`) red — a phantom failure for anyone who has run Kontrol.
# So we (a) install it only when a staged harness actually imports it (deferred
# until after staging; current harnesses use only forge-std cheatcodes), and
# (b) remove it on exit so a later `forge test` / CI sees the canonical
# foundry.lock lib set. See work-todo §34 + docs/KONTROL_SCOPING.md.
# UPDATE 2026-10-20: since the build sets `bytecode_hash = "none"` the lib set
# no longer reaches the codehashes; the cleanup stays so lib/ matches CI.
KCC_DIR="$SW/lib/kontrol-cheatcodes"
cleanup() {
  if [ -d "$DEST_DIR" ]; then
    rm -rf "$DEST_DIR"
    echo "Removed isolated staged Kontrol harness directory."
  fi
  if [ -d "$KCC_DIR" ]; then
    rm -rf "$KCC_DIR"
    echo "Removed transient kontrol-cheatcodes from lib/ (keeps codehash pins canonical)."
  fi
}
trap cleanup EXIT

check_proof_inventory

# The stage directory is owned by this runner and gitignored. Recreate it from
# empty so a deleted/renamed source harness cannot survive from an older run.
rm -rf "$DEST_DIR"
mkdir -p "$DEST_DIR"
# Stage every Kontrol harness, rewriting the repo-relative imports to the
# in-project location.
for h in "$SRC_DIR"/*.t.sol; do
  base="$(basename "$h")"
  sed 's#\.\./\.\./\.\./smart-wallet/src/#../../src/#g; s#\.\./\.\./\.\./smart-wallet/test/mocks/#../mocks/#g' \
    "$h" > "$DEST_DIR/$base"
  echo "Staged harness -> $DEST_DIR/$base"
done

# Install kontrol-cheatcodes ONLY if a staged harness imports it. The EXIT trap
# above removes it again afterward, so the common forge-std-only case never
# leaves lib/ polluted for the next `forge test` / CI codehash freeze check.
if grep -rqlE "kontrol-cheatcodes|KontrolCheats|KEVMCheats" "$DEST_DIR"/*.t.sol 2>/dev/null; then
  if [ ! -d "$KCC_DIR" ]; then
    echo "A staged harness imports kontrol-cheatcodes; installing transiently ..."
    ( cd "$SW" && forge install runtimeverification/kontrol-cheatcodes ) || true
  fi
fi

cd "$SW"
# Remove all compiler artifacts before Kontrol discovers tests. Deleting only
# the current harness basenames leaves artifacts for a previously staged,
# now-deleted Kontrol contract available to the proof selector.
forge clean
# Force the staged harnesses to recompile under kontrol's own
# `forge build --extra-output storageLayout ...`. A prior plain `forge build`
# can leave a harness artifact WITHOUT storageLayout, which `kontrol build`'s
# incremental forge step won't refresh, and kontrol then SILENTLY SKIPS the
# contract as "non-compatible JSON" (→ "Test identifiers not found" at prove).
# NOTE (2026-07-02, finding kontrol-gate-not-codehash-anchored): unlike run_halmos.sh
# — which runs PinnedCodehashes / PinnedBytecodeImmutableLemma / DeployedBytecodeReproCheck
# BEFORE its symbolic pass — this gate proves against whatever `kontrol build` emits from
# the current tree, with NO in-flow codehash certification. "Directly on the deployed
# bytecode" (THE_CLAIM / KONTROL_SCOPING) is anchored EXTERNALLY: the `contracts` CI job's
# codehash-freeze (test/PinnedCodehashes.t.sol) fails on any drift from the pinned/on-chain
# codehash, so on an undrifted tree the built bytecode matches the pins. A source drift would
# be proven against the drifted bytecode here without THIS gate flagging it — the freeze test
# is the tripwire, not run_kontrol.sh.
echo "=== kontrol build ==="
kontrol build --verbose
check_compiled_proof_inventory

# Prove every `prove_*` test in the Kontrol* harnesses. Delete persistent proof
# state first and force every selected proof to restart at fresh version 0.
# `--match-test` is a regex over the full `Contract.func(sig)` name; this gate
# deliberately rejects MATCH overrides. KONTROL_WORKERS remains tunable.
echo "=== kontrol clean (discard persistent proof store) ==="
kontrol clean --proofs

echo "=== kontrol prove (all Kontrol*.prove_* tests) ==="
kontrol prove \
  --reinit \
  --match-test 'Kontrol.*\.prove_' \
  --use-booster --workers "${KONTROL_WORKERS:-4}" --verbose

echo "=== kontrol list (proof status) ==="
KONTROL_LIST_OUT="${TMPDIR:-/tmp}/pq1-kontrol-list-$(date +%Y%m%d-%H%M%S).txt"
kontrol list | tee "${KONTROL_LIST_OUT}"

# Identity baseline (fv-deep-review-2026-07-19 F9 / sweep-F52): fail unless
# every pinned EXPECTED_PROOFS entry has exactly one fresh version-0 record
# that is PASSED with explicit `admitted: False` in `kontrol list` — a silent
# skip, stale/duplicate proof version, omitted admission state, dropped harness,
# or empty proof set must not go green.
assert_kontrol_list "${KONTROL_LIST_OUT}" || {
  echo "==> FAIL: Kontrol proof-identity baseline not met (see ${KONTROL_LIST_OUT})" >&2
  exit 1
}
echo "==> PASS: all ${#EXPECTED_PROOFS[@]} expected proofs have exactly one PASSED, admitted=False version-0 record (identity baseline, F9)"
