#!/usr/bin/env bash
#
# run_halmos.sh — bytecode-level discharge of the A3.* bridge axioms.
#
# 1. Certifies (via Foundry) that the compiled runtime bytecode has the
#    codehashes pinned in test/PinnedCodehashes.t.sol — so the symbolic
#    proof below is against the SAME bytecode the Lean `theft_free` closure
#    names. Also runs the immutable-window lemma (PinnedBytecodeImmutableLemma)
#    so the proof transports from the pinned instance to any instance modulo
#    the two certified immutables.
# 2. Symbolically executes the deployed bytecode with the patched Halmos.
#    Every `check_*` rule that passes is a proof over ALL inputs (modulo the
#    SMT solver + the SHA-256-as-uninterpreted-function abstraction = A1).
#
# Runs BOTH compiler profiles: `default` (runs=200) and `deploy`
# (runs=999999, the production build). For EACH profile we (1) certify the
# compiled runtime codehashes match PINNED_CODEHASHES.md + the immutable-
# window lemma, then (2) symbolically execute the FULL rule suite against
# that profile's bytecode. So the discharge holds for the production
# bytecode directly — not by a "control flow is identical across profiles"
# argument. (The immutable-window lemma still earns its keep WITHIN a
# profile: it transports each profile's pinned instance to every other
# instance of the same artifact, i.e. across differing constructor
# immutables — the harness verifier/EntryPoint addresses vs a real
# deployment.) Both profiles are mandatory for an authoritative green result.
#
# Exit non-zero if any rule fails or errors, if any expected harness did not
# run, or if the PASS count drops below the pinned rule floor (green-at-zero
# guard — fv-deep-review-2026-07-19 F9).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WALLET_DIR="$(cd "${HERE}/../../smart-wallet" && pwd)"
SOLVER="${HALMOS_SOLVER:-z3}"
export PATH="${HOME}/.local/bin:${PATH}"
# Foundry >= 1.8 (the CI pin) enables dynamic test linking by default, which
# compiles `new X(...)` in test contracts to `vm.deployCode(...)` — a cheat
# code Halmos does not implement, so every harness setUp() fails before any
# rule runs. Bytecode under test is unaffected; older forge ignores the key.
export FOUNDRY_DYNAMIC_TEST_LINKING=false

# --- Rule-identity floor (fv-deep-review-2026-07-19 F9) ----------------------
# The wired rule set: every `check_*` test function under
# contracts/smart-wallet/test/halmos/. Verified 2026-07-19: 42 rules across 8
# harnesses (prior receipts recorded 38 and predate HalmosIsValidSignature.t.sol,
# the 3 EIP-1271/G8 rules). Bump EXPECTED_RULES + EXPECTED_HALMOS_CONTRACTS when
# adding/removing a harness or rule; fv-deep-review-2026-07-19 F9.
# 2026-10-20 (audit freeze): still 42. HalmosMultiOwnable 7 -> 5 (three removal
# rules -> one selector-absent rule; the gate rule covers addOwnerBytes only),
# HalmosIsValidSignature 3 -> 5 (legacy isValidSignature(bytes,bytes) rules),
# HalmosExecuteEquiv's remove-selector rule restated as a rejection rule.
# Then 43: HalmosExecuteEquiv gains check_validate_bootstrap_success_stamps_no_credit
# (a successful bootstrap validation opens no execute path for any index; the
# removal-selector rule used to cover the successful-but-no-credit case).
EXPECTED_RULES=43
EXPECTED_RULE_IDENTITIES_SHA256=382a3564c0794f88ba4aa7a42a48f6cde1beb69f16a82328a88102fd3348b753
EXPECTED_HALMOS_CONTRACTS=(
  HalmosValidateUserOpEquiv
  HalmosValidateUserOp
  HalmosExecuteEquiv
  HalmosExecute
  HalmosMultiOwnable
  HalmosVerifier
  HalmosFactory
  HalmosIsValidSignature
)
HALMOS_SRC_DIR="${WALLET_DIR}/test/halmos"

# Emit the exact contract-qualified rule identities, sorted bytewise with one
# trailing newline per identity.  Contract qualification matters because
# Halmos prints bare function names beneath a preceding `Running ...:Contract`
# header.
expected_rule_identities() {
  local contract name
  for contract in "${EXPECTED_HALMOS_CONTRACTS[@]}"; do
    while read -r _ name; do
      [ -n "${name}" ] && printf '%s::%s\n' "${contract}" "${name}"
    done < <(
      grep -hoE "function check_[A-Za-z0-9_]+" \
        "${HALMOS_SRC_DIR}/${contract}.t.sol" || true
    )
  done | LC_ALL=C sort
}

# check_rule_inventory: the checker-owned exact identity pin must match the
# wired tree BEFORE solver time is spent.  Same-count substitution, duplicate
# declarations, or a harness/rule landing without a conscious pin bump stays
# red.
check_rule_inventory() {
  local wired digest duplicate source actual_contracts expected_contracts
  local -a identities
  local -a contract_files
  mapfile -t contract_files < <(
    for source in "${HALMOS_SRC_DIR}"/*.t.sol; do
      basename "${source}" .t.sol
    done | LC_ALL=C sort
  )
  actual_contracts=$(printf '%s\n' "${contract_files[@]}")
  expected_contracts=$(
    printf '%s\n' "${EXPECTED_HALMOS_CONTRACTS[@]}" | LC_ALL=C sort
  )
  if [ "${actual_contracts}" != "${expected_contracts}" ]; then
    echo "==> FAIL: Halmos harness-file inventory drift — every *.t.sol must be present exactly once in EXPECTED_HALMOS_CONTRACTS" >&2
    return 1
  fi
  mapfile -t identities < <(expected_rule_identities)
  wired="${#identities[@]}"
  if [ "${wired}" -ne "${EXPECTED_RULES}" ]; then
    echo "==> FAIL: ${HALMOS_SRC_DIR} wires ${wired} check_* rules but EXPECTED_RULES=${EXPECTED_RULES} — bump the pin (fv-deep-review-2026-07-19 F9)" >&2
    return 1
  fi
  duplicate=$(
    printf '%s\n' "${identities[@]}" |
      LC_ALL=C sort |
      uniq -d |
      head -1
  )
  if [ -n "${duplicate}" ]; then
    echo "==> FAIL: duplicate Halmos rule identity ${duplicate}" >&2
    return 1
  fi
  digest=$(
    printf '%s\n' "${identities[@]}" |
      sha256sum |
      awk '{print $1}'
  )
  if [ "${digest}" != "${EXPECTED_RULE_IDENTITIES_SHA256}" ]; then
    echo "==> FAIL: Halmos rule identity drift: sha256=${digest}; expected ${EXPECTED_RULE_IDENTITIES_SHA256} — inspect the exact Contract::check_* set and bump the pin deliberately" >&2
    return 1
  fi
}

# assert_pass_floor <halmos-output-file> <profile-label>
# Every expected harness must produce exactly one correctly-sized
# `Running N tests for ...:<Contract>` block, and the contract-qualified PASS
# identities beneath those blocks must be the exact pinned source set.  Counts
# alone are insufficient: 42 arbitrary PASS names used to satisfy this gate.
assert_pass_floor() {
  local outfile="$1" profile="$2"
  local contract want current="" identity line passes=0
  local running_re='Running[[:space:]]+([0-9]+)[[:space:]]+tests[[:space:]]+for[[:space:]]+.*:([A-Za-z0-9_]+)[[:space:]]*$'
  local pass_re='\[PASS\][[:space:]]+(check_[A-Za-z0-9_]+)\('
  local -a expected_identities
  declare -A expected=()
  declare -A seen=()
  declare -A running_seen=()

  mapfile -t expected_identities < <(expected_rule_identities)
  for identity in "${expected_identities[@]}"; do
    expected["${identity}"]=1
  done

  # Halmos colours its status markers (`ESC[32m[PASS]ESC[0m`) whenever its
  # console decides the stream is a terminal, which it can do even through
  # `tee`. Strip SGR sequences so a coloured receipt parses exactly like a
  # plain one (2026-10-20: a fully green run failed this floor on colour).
  while IFS= read -r line || [ -n "${line}" ]; do
    line="${line//$'\r'/}"
    if [[ "${line}" =~ ${running_re} ]]; then
      want="${BASH_REMATCH[1]}"
      contract="${BASH_REMATCH[2]}"
      if [[ ! " ${EXPECTED_HALMOS_CONTRACTS[*]} " =~ [[:space:]]${contract}[[:space:]] ]]; then
        echo "==> FAIL [${profile}]: unexpected Halmos harness block ${contract}" >&2
        return 1
      fi
      running_seen["${contract}"]=$(( ${running_seen["${contract}"]:-0} + 1 ))
      if [ "${running_seen["${contract}"]}" -ne 1 ]; then
        echo "==> FAIL [${profile}]: duplicate Running block for ${contract}" >&2
        return 1
      fi
      local source_count
      source_count=$(
        grep -cE "function check_[A-Za-z0-9_]+" \
          "${HALMOS_SRC_DIR}/${contract}.t.sol" || true
      )
      if [ "${want}" -ne "${source_count}" ]; then
        echo "==> FAIL [${profile}]: harness ${contract} ran ${want} tests but wires ${source_count} exact check_* identities" >&2
        return 1
      fi
      current="${contract}"
    elif [[ "${line}" =~ ${pass_re} ]]; then
      if [ -z "${current}" ]; then
        echo "==> FAIL [${profile}]: unscoped PASS record before any Running block" >&2
        return 1
      fi
      identity="${current}::${BASH_REMATCH[1]}"
      if [ -z "${expected["${identity}"]+present}" ]; then
        echo "==> FAIL [${profile}]: unexpected Halmos PASS identity ${identity}" >&2
        return 1
      fi
      seen["${identity}"]=$(( ${seen["${identity}"]:-0} + 1 ))
      if [ "${seen["${identity}"]}" -ne 1 ]; then
        echo "==> FAIL [${profile}]: duplicate Halmos PASS identity ${identity}" >&2
        return 1
      fi
      passes=$((passes + 1))
    elif [[ "${line}" =~ \[(FAIL|ERROR)\] ]]; then
      echo "==> FAIL [${profile}]: Halmos output contains ${BASH_REMATCH[0]}" >&2
      return 1
    fi
  done < <(sed 's/\x1b\[[0-9;]*m//g' "${outfile}")

  for contract in "${EXPECTED_HALMOS_CONTRACTS[@]}"; do
    if [ "${running_seen["${contract}"]:-0}" -ne 1 ]; then
      echo "==> FAIL [${profile}]: harness ${contract} produced no unique Running block" >&2
      return 1
    fi
  done
  for identity in "${expected_identities[@]}"; do
    if [ "${seen["${identity}"]:-0}" -ne 1 ]; then
      echo "==> FAIL [${profile}]: missing Halmos PASS identity ${identity}" >&2
      return 1
    fi
  done
  if [ "${passes}" -ne "${EXPECTED_RULES}" ]; then
    echo "==> FAIL [${profile}]: observed ${passes} exact PASS identities; expected ${EXPECTED_RULES}" >&2
    return 1
  fi
  echo "    identity OK [${profile}]: all ${#EXPECTED_HALMOS_CONTRACTS[@]} harnesses and ${passes} exact Contract::check_* PASS records matched the pin"
}

# self_test: positive + negative controls for assert_pass_floor (no solver).
self_test() {
  local d; d="$(mktemp -d /tmp/pq1-halmos-floor-selftest.XXXXXX)"
  local complete="${d}/complete.txt" zero="${d}/zero.txt"
  local missing="${d}/missing.txt" substituted="${d}/substituted.txt"
  local coloured="${d}/coloured.txt"
  local original_src_dir="${HALMOS_SRC_DIR}" fixture_src="${d}/src"
  : > "${complete}"; : > "${zero}"; : > "${missing}"; : > "${substituted}"
  local contract want name rc=0
  echo "-- self-test 1/6: exact harness-file inventory — extra file must be REJECTED"
  if ! check_rule_inventory >/dev/null 2>&1; then
    echo "   CONTROL FAILURE: rejected the current exact harness inventory" >&2
    rc=1
  else
    mkdir -p "${fixture_src}"
    cp "${HALMOS_SRC_DIR}"/*.t.sol "${fixture_src}/"
    : > "${fixture_src}/HalmosUnpinned.t.sol"
    HALMOS_SRC_DIR="${fixture_src}"
    if check_rule_inventory >/dev/null 2>&1; then
      echo "   CONTROL FAILURE: accepted an unpinned Halmos harness file" >&2
      rc=1
    else
      echo "   OK: rejected"
    fi
    HALMOS_SRC_DIR="${original_src_dir}"
  fi
  for contract in "${EXPECTED_HALMOS_CONTRACTS[@]}"; do
    want=$(grep -cE "function check_[A-Za-z0-9_]+" "${HALMOS_SRC_DIR}/${contract}.t.sol" || true)
    echo "Running ${want} tests for test/halmos/${contract}.t.sol:${contract}" >> "${complete}"
    echo "Running ${want} tests for test/halmos/${contract}.t.sol:${contract}" >> "${zero}"
    echo "Running ${want} tests for test/halmos/${contract}.t.sol:${contract}" >> "${substituted}"
    if [ "${contract}" != "HalmosIsValidSignature" ]; then
      echo "Running ${want} tests for test/halmos/${contract}.t.sol:${contract}" >> "${missing}"
    fi
    while read -r _ name; do
      echo "[PASS] ${name}() (paths: 1, time: 0.01s, bounds: [])" >> "${complete}"
      if [ "${contract}" != "HalmosIsValidSignature" ]; then
        echo "[PASS] ${name}() (paths: 1, time: 0.01s, bounds: [])" >> "${missing}"
      fi
    done < <(
      grep -hoE "function check_[A-Za-z0-9_]+" \
        "${HALMOS_SRC_DIR}/${contract}.t.sol" || true
    )
  done
  for contract in "${EXPECTED_HALMOS_CONTRACTS[@]}"; do
    want=$(grep -cE "function check_[A-Za-z0-9_]+" "${HALMOS_SRC_DIR}/${contract}.t.sol" || true)
    for _ in $(seq 1 "${want}"); do
      echo "[PASS] check_totally_unrelated() (paths: 1, time: 0.01s, bounds: [])" >> "${substituted}"
    done
  done
  echo "-- self-test 2/6: complete exact-identity fixture — must be ACCEPTED"
  if assert_pass_floor "${complete}" selftest >/dev/null 2>&1; then echo "   OK: accepted"; else echo "   CONTROL FAILURE: rejected a complete run" >&2; rc=1; fi
  echo "-- self-test 3/6: zero-PASS fixture — must be REJECTED"
  if assert_pass_floor "${zero}" selftest >/dev/null 2>&1; then echo "   CONTROL FAILURE: green-at-zero accepted!" >&2; rc=1; else echo "   OK: rejected"; fi
  echo "-- self-test 4/6: missing-one-harness fixture — must be REJECTED"
  if assert_pass_floor "${missing}" selftest >/dev/null 2>&1; then echo "   CONTROL FAILURE: missing-harness accepted!" >&2; rc=1; else echo "   OK: rejected"; fi
  echo "-- self-test 5/6: same-count arbitrary PASS identities — must be REJECTED"
  if assert_pass_floor "${substituted}" selftest >/dev/null 2>&1; then echo "   CONTROL FAILURE: arbitrary PASS identities accepted!" >&2; rc=1; else echo "   OK: rejected"; fi
  echo "-- self-test 6/6: the same run with ANSI-coloured markers — must be ACCEPTED"
  sed 's/\[PASS\]/\x1b[32m[PASS]\x1b[0m/' "${complete}" > "${coloured}"
  if ! grep -q $'\x1b' "${coloured}"; then
    echo "   CONTROL FAILURE: coloured fixture carries no escape sequence" >&2; rc=1
  elif assert_pass_floor "${coloured}" selftest >/dev/null 2>&1; then echo "   OK: accepted"; else echo "   CONTROL FAILURE: rejected a coloured complete run" >&2; rc=1; fi
  rm -rf "${d}"
  if [ "${rc}" -eq 0 ]; then
    echo "run_halmos.sh --self-test: all controls behave"
  else
    echo "run_halmos.sh --self-test: CONTROL FAILURE" >&2
  fi
  return "${rc}"
}

case "${1:-}" in
  --self-test)
    self_test
    exit $?
    ;;
  --check-output)
    [ $# -eq 2 ] || { echo "usage: $0 --check-output <halmos-output-file>" >&2; exit 2; }
    check_rule_inventory
    assert_pass_floor "$2" check-only
    exit $?
    ;;
esac

command -v halmos >/dev/null 2>&1 || { echo "halmos not installed — run setup_halmos.sh"; exit 2; }

check_rule_inventory

cd "${WALLET_DIR}"

certify_profile() {
  local profile="$1"
  echo "    [${profile}] codehash freeze + immutable-window lemma + deployed-bytecode repro"
  # DeployedBytecodeReproCheck self-skips off the deploy profile (the live
  # contracts were cut from runs=999999), so it is a no-op under default.
  FOUNDRY_PROFILE="${profile}" forge test \
    --match-contract 'PinnedCodehashes|PinnedBytecodeImmutableLemma|DeployedBytecodeReproCheck' >/dev/null
}

echo "==> [1/2] Certifying compiled bytecode == pinned codehashes (Foundry, both profiles)"
certify_profile default
certify_profile deploy
echo "    OK: wallet / factory / verifier codehashes match PINNED_CODEHASHES.md"
echo "    OK: runtime differs from the pinned instance only at the certified immutables"
echo "    OK: deploy-profile CREATE2 replay lands at the predicted production addresses/codehashes and matches the firmware CREATE2 constants"

run_symbolic() {
  local profile="$1"
  echo "==> [2/2] Halmos symbolic execution of the deployed bytecode [profile=${profile}]"
  FOUNDRY_PROFILE="${profile}" forge build --ast >/dev/null 2>&1
  # The contract alternation is derived from EXPECTED_HALMOS_CONTRACTS so the
  # identity floor above and the executed set can never drift apart (F9).
  local match_contract
  match_contract="Halmos($(IFS='|'; echo "${EXPECTED_HALMOS_CONTRACTS[*]#Halmos}"))"
  NO_COLOR=1 FOUNDRY_PROFILE="${profile}" halmos \
    --match-contract "${match_contract}" \
    --solver "${SOLVER}" --loop 4 \
    | tee "/tmp/pq1-halmos-run-${profile}.txt" | grep -E "Running|\[PASS\]|\[FAIL\]|\[ERROR\]|Symbolic test result"

  if grep -qE "\[FAIL\]|\[ERROR\]" "/tmp/pq1-halmos-run-${profile}.txt"; then
    echo "==> FAIL: at least one Halmos rule did not pass [profile=${profile}]"
    exit 1
  fi
  assert_pass_floor "/tmp/pq1-halmos-run-${profile}.txt" "${profile}" || {
    echo "==> FAIL: Halmos rule-identity floor not met [profile=${profile}]"
    exit 1
  }
  local passes
  passes=$(grep -c "\[PASS\]" "/tmp/pq1-halmos-run-${profile}.txt" || true)
  echo "==> PASS: ${passes} bytecode rules verified [profile=${profile}]"
  echo "    (A3.1 verifier gates / A3.2 validate equiv / A3.2-exec execute equiv / A3.3 factory iff / A3.4 owner table / EIP-1271 isValidSignature G8)"
}

run_symbolic default
run_symbolic deploy
