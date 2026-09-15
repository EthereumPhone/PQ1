#!/usr/bin/env python3
"""verify-ledger-consistency — anti-vacuity gate defending failure-class V5
("undischarged-but-advertised") from docs/verification/fv-adversarial-review-playbook.md.

The EF swarm's recurring proof finding (P1 / I-5) was *the ledger said one
thing and the kernel said another*: `theft_free_bytecode` carried a raw `hInv`
hypothesis while AXIOM_STATUS.json advertised the cap "discharged". This gate
makes the human-facing ledger (docs/AXIOM_STATUS.json) FALSIFIABLE against the
machine truth: it cross-checks the advertised closures, axiom inventory, status
counts, and headline-theorem statement shapes against the LIVE Lean dump and
the Lean source — and fails on any divergence.

Independent checks (all run; every failure is reported), headed by:

  C1  CLOSURE EXACT-SET — every theorem in the ledger's `closures` block has a
      `#print axioms` closure EXACTLY equal to the advertised set (no missing,
      no extra). Generalises lint_fv (c) from {theft_free, offchain} to every
      advertised theorem, and derives the expectation FROM the ledger (so
      editing the ledger to lie is caught against the live dump).
  C2  LINT_FV CROSS-CHECK — `closures[theft_free]` equals the hard-coded
      THEFT_EXPECTED+THEFT_KERNEL pin in lint_fv_invariants.sh, and the
      offchain entry equals that lint's OFF_ALLOWED. Binds this block to the
      existing pin so a 5th drift surface is never born.
  C3  NO UNDOCUMENTED AXIOM — every non-kernel axiom that actually appears in a
      tracked theorem's LIVE closure is documented as an `axioms[].name` entry
      in the ledger (silent trust-expansion guard).
  C4  NO PHANTOM LEDGER AXIOM — every non-kernel `axioms[].name` resolves to a
      real `axiom <ident>` declaration in the Lean source (can't pad the ledger
      with credibility-only entries).
  C5  COUNT CONSISTENCY — the status vocabulary is closed, every required
      `summary` count exists, and those counts equal the complete `axioms` tally
      (format_axiom_status.py READS these counts, so drift is real).
  C6  STATUS HYGIENE — unknown/bald statuses are rejected; no
      `placeholder`/`misleading` status remains; every
      `discharged-bytecode` axiom carries a real discharge artifact (pinned
      codehash / halmos / kontrol / certora session); every `cited-tcb` axiom
      carries a citation or artifact. No bald "discharged"/"cited" claim.
  C7  SIGNATURE PINS — each headline theorem's normalised statement text hashes
      to its pinned sha256, and satisfies its must_contain/must_not_contain
      substrings. Catches a re-introduced RAW HYPOTHESIS (e.g. reverting the P1
      fix to a bald-`hInv` conditional) that the axiom-closure checks cannot see.
  C8  NO sorryAx — belt-and-braces (verify-audit is the authoritative sorry gate).

  Further registry checks documented at their functions: C0 (mandatory floors),
  C9 (witness coverage), C10 (bridge-axiom RHS shape), C11 (exact closure key
  set), C13 (duplicate dump records), C14 (duplicate list identities), and the
  load itself rejects duplicate JSON object keys (C15). C16 pins the exact
  top-level schema and full canonical ledger value in addition to the
  axiom/artifact row schemas, canonical row and artifact values, artifact field
  types, artifact uniqueness, and status/method tallies — assurance prose,
  corollaries, witness descriptions, an ID/name swap, duplicated receipt, extra
  field, fabricated method, or null codehash cannot drift by shape/presence
  alone. Plain
  `json.loads` is silently last-wins, which would let a benign second record
  hide a rogue first one (the advertised-vs-checked divergence this gate exists
  to close).

================================  SCOPE / CAVEAT  =============================
The LIVE-closure source is `#print axioms` (dump_axioms.lean). In Lean v4.22.0
(this tree) `collectAxioms` was believed to be in the pre-#8842 UNDER-REPORT
window (the #8842 fix merged 2025-07; whether this pin carries it is
unverified — check before relying on either reading). `make verify-lean4checker`
is an INDEPENDENT kernel/environment REPLAY: it catches declarations that fail
to kernel-check, but it does NOT recompute the axiom closure and cannot reveal
a `collectAxioms` omission (its Replay re-adds referenced `.axiomInfo`
declarations as legal axioms; the #8840 shape survives it — FV deep review F5,
2026-07-19). THIS gate checks advertised-vs-#print-axioms CONSISTENCY and the
ledger's internal coherence; it deliberately does NOT try to close the
under-report gap — the allowlist backstop for that class (an external checker
with a `permitted_axioms` list, e.g. nanoda_lib) is tracked as a follow-up.
(NB: --dump expects `#print axioms` format, i.e. dump_axioms.lean output; it
does NOT parse lean4checker's report format. Use a pre-captured dump_axioms
output for offline/CI runs.)

This gate closes V5 (advertised != actual) and V4-adjacent surfaces. It does
NOT catch V7 (latent-FALSE axiom — non-detonatable while lean/ is mathlib-free)
or V11 (wrong spec). See the playbook §A. Do not let "we have a ledger gate
now" become the next overconfidence.
==============================================================================

Usage:
    check_ledger_consistency.py [--dump <file>] [--self-test]

  --dump FILE   use a pre-captured `dump_axioms.lean` output (the `#print axioms`
                format) instead of running lake. (NOT a lean4checker report —
                that has a different format; verify-lean4checker is its own gate.)
  --self-test   run the WIRED-IN NEGATIVE CONTROL: feed each check a corrupted
                input and assert it fires. Proves the gate is not vacuous.
                (Exits 0 iff every corruption was caught.)

Exit: 0 = consistent; 1 = at least one divergence; 2 = internal error.
"""
from __future__ import annotations

import json
import os
import pwd
import re
import subprocess
import sys
from pathlib import Path

KERNEL = {"propext", "Classical.choice", "Quot.sound"}
STATUS_TO_SUMMARY_KEY = {
    "cited-tcb": "cited_tcb",
    "discharged-bytecode": "discharged_bytecode",
    "kernel-tcb": "kernel_tcb",
    "placeholder": "placeholder_true_typed",
    "misleading": "misleading",
}
ALLOWED_AXIOM_STATUSES = frozenset(STATUS_TO_SUMMARY_KEY)
REQUIRED_SUMMARY_KEYS = frozenset(
    (*STATUS_TO_SUMMARY_KEY.values(), "total_axioms_in_closure")
)
# Checker-owned schema/value pins. Each row is compact JSON, bytewise sorted,
# with one trailing "\n", then SHA-256:
#   axiom schema:    [axiom id, sorted row keys]
#   artifact schema: [axiom id, axiom status, artifact type, sorted keys]
#   axiom values:    [axiom id, sorted [field, value] pairs except artifacts]
#   artifact values: [axiom id, artifact index, sorted [field, value] pairs]
# Update only alongside an inspected, intentional AXIOM_STATUS change.
# RE-PINNED 2026-08-20 for the intentional 2026-08-20 ledger edit (issues
# #674/#678): A2 (`entrypoint_honest`) demoted from axiom to kernel-proved
# theorem — its ledger row + its 3 closure presences removed (schema/value
# drift) — plus the A3.2 kontrol evidence refresh (stale 4/4 → 7/7) and the
# two A3.2 certora-rule-set artifacts marked historical/unexecuted (new
# `evidence` field — artifact schema drift). Also absorbs the two earlier
# unpinned ledger edits that left C16 red on master (the 66cf2eba U+200B
# removal in A5-ITSR noted in 7cf06a0e's commit message + one more).
EXPECTED_AXIOM_SCHEMA_SHA256 = (
    "e236341847edfe07334cd99239eac7596d70b4f25f377c81f663b16415615a50"
)
EXPECTED_ARTIFACT_SCHEMA_SHA256 = (
    "fa023a607167fa08afb7b6e7dc79bb8c11bb50c05c55afd4d6fb80f20cc07c05"
)
EXPECTED_AXIOM_VALUE_SHA256 = (
    "6891215b18a003668d191227c02299f1f89553c7f289f57f28b25bd556d9142d"
)
EXPECTED_ARTIFACT_VALUE_SHA256 = (
    "3e102b39f55a62f843a408e415109f7fb01af9d1b98d769478cfb0bb5335db47"
)
EXPECTED_LEDGER_TOP_LEVEL_FIELDS = frozenset({
    "axioms",
    "claim_corollaries",
    "closures",
    "closures_doc",
    "critical_alert",
    "discharge_states",
    "headline_one_line",
    "headline_status",
    "headline_status_explanation",
    "headline_theorem",
    "last_updated",
    "schema_version",
    "signature_pins",
    "signature_pins_doc",
    "summary",
    "witness_coverage",
    "witness_coverage_doc",
})
EXPECTED_LEDGER_VALUE_SHA256 = (
    "52a465c150893ea9579888d21b6046ff81c258465eb41e94566066040cd22eca"
)
EXPECTED_ARTIFACT_METHOD_STATUS_COUNTS = {
    ("cited-tcb", "citation"): 2,
    ("cited-tcb", "computed-margin"): 1,
    ("cited-tcb", "foundry-parity"): 2,
    ("cited-tcb", "mechanized-assumption"): 1,
    ("cited-tcb", "negative-result"): 1,
    ("cited-tcb", "partial-mechanization"): 1,
    ("discharged-bytecode", "adversarial-screen"): 1,
    ("discharged-bytecode", "certora-rule-set"): 3,
    ("discharged-bytecode", "cross-validation"): 1,
    ("discharged-bytecode", "executable-lean-differential"): 1,
    ("discharged-bytecode", "foundry-invariant"): 1,
    ("discharged-bytecode", "foundry-parity"): 1,
    ("discharged-bytecode", "halmos-session"): 8,
    ("discharged-bytecode", "kontrol-kevm-session"): 4,
    ("discharged-bytecode", "lean-refinement"): 1,
}
AXIOM_REQUIRED_FIELDS = frozenset({
    "citation",
    "description",
    "discharge_artifacts",
    "id",
    "lean_type",
    "name",
    "status",
    "status_detail",
})
AXIOM_OPTIONAL_FIELDS = frozenset({
    "covers",
    "discharge_tier",
    "lean_type_note",
})
ARTIFACT_STRING_FIELDS = frozenset({
    "conf",
    "date",
    "evidence",
    "model_contract",
    "path",
    "tool",
    "type",
})

# --------------------------------------------------------------------------- #
# MANDATORY REGISTRY (F8, 2026-07-16, closes the deletion-tolerance vacuity).
#
# Every other check in this gate iterates a DECLARED collection, so deleting a
# whole collection (e.g. all of `closures`, or the entire `axioms` array with a
# zeroed `summary`) makes the per-entry loops run zero times and PASS silently.
# These IDs are hard-coded HERE — deliberately NOT derived from the ledger, so an
# edit that deletes a ledger entry cannot also delete its floor in one stroke —
# and asserted present, so a deletion is a hard failure. Mirrors the hard-coded
# KERNEL set + the THEFT_EXPECTED pin cross-check (C2).
HEADLINE_THEOREM = "SphincsCVerify.Spec.Theorems.theft_free"
MANDATORY_CLOSURES = {
    "SphincsCVerify.Spec.Theorems.theft_free",                       # flagship
    "SphincsCVerify.Spec.Theorems.theft_free_bytecode",
    "SphincsCVerify.Spec.Theorems.theft_free_bytecode_reachable",
    "SphincsCVerify.Spec.Theorems.theft_free_with_calldata_binding",
    "SphincsCVerify.Spec.Theorems.factory_squat_defence_bytecode",
    "SphincsCVerify.Wallet.Invariants.reachable_implies_combinedCap",
    "SphincsCVerify.Wallet.OffchainBinding.offchain_nested_disjoint_from_userop_digest",
}
MANDATORY_SIGNATURE_PINS = {
    "SphincsCVerify.Spec.Theorems.theft_free",
    "SphincsCVerify.Spec.Theorems.theft_free_bytecode",
    "SphincsCVerify.Spec.Theorems.theft_free_bytecode_reachable",
    "SphincsCVerify.Spec.Theorems.factory_squat_defence_bytecode",
    "SphincsCVerify.Wallet.Invariants.reachable_implies_combinedCap",
}
MANDATORY_WITNESSES = {
    "SphincsCVerify.Wallet.Invariants.combinedCapInvariant_empty",
    "SphincsCVerify.Wallet.Invariants.combinedCapInvariant_initialised",
    "SphincsCVerify.Interpreter.C10.H_adrs_dischargeable",
    "SphincsCVerify.Interpreter.C10.H_sib_dischargeable",
    "SphincsCVerify.Wallet.CreditLedger.execute_step_satisfiable",
}
MANDATORY_COROLLARIES = {
    "SphincsCVerify.Spec.Theorems.theft_free_with_calldata_binding",
    "SphincsCVerify.Spec.Theorems.executeBatch_faithful",
    "SphincsCVerify.Wallet.Invariants.initialize_called_exactly_once",
    "SphincsCVerify.Wallet.Invariants.owner_set_nonempty_after_init",
    "SphincsCVerify.Wallet.Invariants.cannot_remove_bootstrap",
    "SphincsCVerify.Wallet.Invariants.create2_address_chain_independent",
    "SphincsCVerify.Wallet.Invariants.factory_requires_bootstrap_sig",
    "SphincsCVerify.Wallet.Invariants.eip1271_forbids_bootstrap",
}
# C11 — EXACT `closures` identity pin (2026-07-25, closure-review residual):
# the mandatory floors above require only that the load-bearing subset be
# present, and C1 iterates only ledger-declared entries — so a ledger edit that
# DELETED a non-mandatory tracked identity (shrinking the pinned receipt from
# 18 theorems to 17) sailed through C0/C1/C5 with zero failures (reproduced:
# dropping `SphincsCVerify.Crypto.honest_sig_not_forgery`).  Pin the exact key
# set: adding, renaming, or deleting a tracked closure identity must
# consciously update this second authoritative copy — the same discipline as
# the proof-mutation corpus digest.  (The reverse direction — live dump records
# beyond these keys — is deliberately NOT pinned: dump_axioms.lean prints ~79
# further audit-context theorems on purpose.)
EXPECTED_CLOSURES_KEYS = {
    "SphincsCVerify.Crypto.honest_sig_not_forgery",
    "SphincsCVerify.Crypto.keyHistory_empty_signs_nothing",
    "SphincsCVerify.Spec.Theorems.deployed_executeBatch_requires_prior_token",
    "SphincsCVerify.Spec.Theorems.deployed_execute_requires_prior_token",
    "SphincsCVerify.Spec.Theorems.executeBatch_faithful",
    "SphincsCVerify.Spec.Theorems.factory_squat_defence_bytecode",
    "SphincsCVerify.Spec.Theorems.theft_free",
    "SphincsCVerify.Spec.Theorems.theft_free_bytecode",
    "SphincsCVerify.Spec.Theorems.theft_free_bytecode_reachable",
    "SphincsCVerify.Spec.Theorems.theft_free_with_calldata_binding",
    "SphincsCVerify.Wallet.Invariants.cannot_remove_bootstrap",
    "SphincsCVerify.Wallet.Invariants.create2_address_chain_independent",
    "SphincsCVerify.Wallet.Invariants.eip1271_forbids_bootstrap",
    "SphincsCVerify.Wallet.Invariants.factory_requires_bootstrap_sig",
    "SphincsCVerify.Wallet.Invariants.initialize_called_exactly_once",
    "SphincsCVerify.Wallet.Invariants.owner_set_nonempty_after_init",
    "SphincsCVerify.Wallet.Invariants.reachable_implies_combinedCap",
    "SphincsCVerify.Wallet.OffchainBinding.offchain_nested_disjoint_from_userop_digest",
}
# The flagship `theft_free` trust base (A1..A5, non-kernel). Deleting any of
# these from `axioms[]` silently shrinks the advertised assumption set.
# (A2 `entrypoint_honest` was removed from this floor 2026-08-20: it is now
# a PROVED kernel-only theorem in Bridge/EntryPoint.lean, not an axiom —
# its load-bearingness is enforced by the proof-mutation gate's
# A2-load-bearing rename check, not by a ledger row.)
MANDATORY_AXIOM_NAMES = {
    "SphincsCVerify.Bridge.solidityVerifier_compiles_correctly",       # A3.1
    "SphincsCVerify.Bridge.precompile_0x02_is_FIPS_180_4",             # A1
    "SphincsCVerify.Bridge.evm_bytecode_executes_correctly",           # A4
    "SphincsCVerify.Crypto.EUF_CMA_SPHINCSplusC",                      # A5
    "SphincsCVerify.Crypto.ITSR_F",                                    # A5
    "SphincsCVerify.Crypto.SM_DT_TCR_F",                               # A5
    "SphincsCVerify.Crypto.hMsg_random_oracle",                        # A5
}
MANDATORY_COLLECTIONS = ["closures", "signature_pins", "witness_coverage", "axioms", "claim_corollaries"]

SCRIPT_DIR = Path(__file__).resolve().parent
VERIF_DIR = SCRIPT_DIR.parent
LEAN_DIR = VERIF_DIR / "lean"
LEDGER_PATH = VERIF_DIR / "docs" / "AXIOM_STATUS.json"
LINT_FV_PATH = SCRIPT_DIR / "lint_fv_invariants.sh"
DUMP_SCRIPT = "scripts/dump_axioms.lean"


# --------------------------------------------------------------------------- #
# parsing helpers
# --------------------------------------------------------------------------- #
def parse_dump(text: str) -> dict[str, set[str]]:
    """Parse `#print axioms` output into {theorem_fqn: {axiom_fqn, ...}}.

    `#print axioms` wraps long lists across lines; flatten first.  A theorem
    MUST record exactly once: the dict is last-wins by construction, so a
    same-name second record (either form) could launder a rogue first closure
    beneath a benign one — reject the dump outright.
    """
    flat = re.sub(r"\s+", " ", text)
    closures: dict[str, set[str]] = {}
    seen: set[str] = set()

    def note(name: str) -> None:
        if name in seen:
            raise SystemExit(
                f"FAIL: duplicate dump record for headline `{name}` — a dump with a "
                f"repeated identity is not a well-formed evidence record (last-wins "
                f"overwrite would let a benign second record hide a rogue first one).")
        seen.add(name)

    for m in re.finditer(r"'([^']+)' depends on axioms: \[([^\]]*)\]", flat):
        name = m.group(1)
        note(name)
        axset = {a.strip() for a in m.group(2).split(",") if a.strip()}
        closures[name] = axset
    for m in re.finditer(r"'([^']+)' does not depend on any axioms", flat):
        note(m.group(1))
        closures.setdefault(m.group(1), set())
    return closures


def parse_bash_array(text: str, var: str) -> list[str]:
    """Extract the quoted string entries of a bash `VAR=( ... )` array."""
    m = re.search(re.escape(var) + r"=\(\s*(.*?)\)", text, re.DOTALL)
    if not m:
        return []
    return re.findall(r'"([^"]+)"', m.group(1))


def _reject_duplicate_keys(pairs: list) -> dict:
    """`object_pairs_hook` that REJECTS duplicate JSON object keys.  Plain
    `json.loads` is silently last-wins: a duplicated ledger key would let a
    benign SECOND record govern every check while a rogue FIRST record is
    what a top-down human reader sees — the advertised-vs-checked (V5)
    divergence this gate exists to close.  Symmetric with the duplicate
    dump-record rejection in `parse_dump` (C13)."""
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(
                f"duplicate key {key!r} in the ledger JSON — a last-wins overwrite "
                f"would let a benign second record hide a rogue first one")
        obj[key] = value
    return obj


def load_ledger() -> dict:
    """Load AXIOM_STATUS.json rejecting duplicate object keys."""
    return json.loads(LEDGER_PATH.read_text(encoding="utf-8"),
                      object_pairs_hook=_reject_duplicate_keys)


def axiom_ident(name: str) -> str:
    """Last dotted component of an axiom `name`, tolerating a compound display
    name like `...solidityWalletExecute_compiles_correctly (+ ...Batch...)`."""
    head = name.strip().split()[0] if name.strip() else name
    return head.split(".")[-1]


def extract_statement(text: str, short: str) -> str | None:
    """`theorem <short> ...` up to and including the first `:= by` delimiter,
    whitespace-normalised. Mirrors the seeding in scripts at gate-authoring time.
    """
    m = re.search(r"(\btheorem\s+" + re.escape(short) + r"\b.*?:=\s+by)", text, re.DOTALL)
    if not m:
        return None
    return re.sub(r"\s+", " ", m.group(1)).strip()


def sha256_hex(s: str) -> str:
    import hashlib
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _pinned_lake() -> str:
    """The elan shim under the password-database home — never via PATH."""
    lake = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".elan" / "bin" / "lake"
    if not lake.is_file():
        raise SystemExit(f"ERROR: lake not found at the pinned elan location ({lake}).")
    return str(lake)


def _pinned_tool_env() -> dict:
    """Environment for evidence-tool subprocesses.  The elan dispatcher
    re-roots toolchain resolution from ELAN_HOME (falling back to HOME) at
    exec time, and ELAN_TOOLCHAIN overrides the lean-toolchain file's
    selection — all caller-mutable.  Force the password-database root and
    drop the selection override (wave-3 Opus 5 / Kimi K3 HIGH,
    coordinator-reproduced with a planted $ELAN_HOME toolchain)."""
    home = pwd.getpwuid(os.getuid()).pw_dir
    env = dict(os.environ)
    env["HOME"] = home
    env["ELAN_HOME"] = str(Path(home) / ".elan")
    env.pop("ELAN_TOOLCHAIN", None)
    # Dynamic-loader injection is the same startup class at the binary level:
    # never propagate a caller preload/audit/library path into evidence tools.
    for ld_var in ("LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"):
        env.pop(ld_var, None)
    return env


def run_live_dump() -> str:
    """Run dump_axioms.lean and return combined output. Non-fatal exit (the
    script ends on a missing `main`); we gate on emitted content, like lint_fv.

    The Lean toolchain is part of the evidence trust root: resolve it exactly
    like the Makefile does — the elan shim under the password-database home,
    with ELAN_HOME/HOME forced to that same root — never through the caller's
    PATH or elan environment.  A planted bare `lake` and a planted
    `$ELAN_HOME` toolchain were both shown to answer this call with forged
    `#print axioms` output (wave-2 SOL / wave-3 Opus 5 + Kimi K3 HIGH,
    coordinator-reproduced), which would make every closure comparison below
    run against attacker-authored "live truth"."""
    lake = _pinned_lake()
    try:
        cp = subprocess.run(
            [lake, "env", "lean", DUMP_SCRIPT],
            cwd=str(LEAN_DIR), capture_output=True, text=True, timeout=900,
            env=_pinned_tool_env(),
        )
    except FileNotFoundError:
        raise SystemExit(f"ERROR: `{lake}` not executable (need elan-installed Lean 4).")
    except subprocess.TimeoutExpired:
        raise SystemExit("ERROR: dump_axioms.lean timed out (>900s).")
    return cp.stdout + cp.stderr


# --------------------------------------------------------------------------- #
# pure checks: each takes parsed data, returns list[str] of failures
# --------------------------------------------------------------------------- #
def check_closures(ledger: dict, live: dict[str, set[str]]) -> list[str]:
    fails = []
    for thm, expected in ledger.get("closures", {}).items():
        exp = set(expected)
        if thm not in live:
            fails.append(f"C1 {thm}: advertised in `closures` but ABSENT from the live dump "
                         f"(rename? dropped from dump_axioms.lean? proof error?)")
            continue
        got = live[thm]
        missing = exp - got
        extra = got - exp
        if missing or extra:
            parts = []
            if missing:
                parts.append("MISSING " + ", ".join(sorted(missing)))
            if extra:
                parts.append("EXTRA " + ", ".join(sorted(extra)))
            fails.append(f"C1 {thm}: advertised closure != live closure — " + "; ".join(parts))
    return fails


def check_lint_fv_crosscheck(ledger: dict, lint_text: str) -> list[str]:
    fails = []
    expected = set(parse_bash_array(lint_text, "THEFT_EXPECTED"))
    kernel = set(parse_bash_array(lint_text, "THEFT_KERNEL"))
    if not expected or not kernel:
        fails.append("C2 could not parse THEFT_EXPECTED/THEFT_KERNEL from lint_fv_invariants.sh "
                     "(format changed? — reconcile by hand before trusting this gate)")
        return fails
    lint_set = expected | kernel
    tf = "SphincsCVerify.Spec.Theorems.theft_free"
    ledger_set = set(ledger.get("closures", {}).get(tf, []))
    if ledger_set != lint_set:
        fails.append(f"C2 closures[theft_free] != lint_fv THEFT_EXPECTED+THEFT_KERNEL pin — "
                     f"ledger-only={sorted(ledger_set - lint_set)} lint-only={sorted(lint_set - ledger_set)}")
    # offchain entry vs OFF_ALLOWED. NB: OFF_ALLOWED is a permitted ALLOWLIST in
    # lint_fv (it lists the full kernel triple even though the actual offchain
    # closure uses only {propext, Quot.sound}), so the binding here is SUBSET
    # (ledger closure within the allowlist) + keccak present. Exactness of the
    # offchain closure itself is enforced by C1 against the live dump.
    off_allowed = set(parse_bash_array(lint_text, "OFF_ALLOWED"))
    off_thm = "SphincsCVerify.Wallet.OffchainBinding.offchain_nested_disjoint_from_userop_digest"
    off_ledger = set(ledger.get("closures", {}).get(off_thm, []))
    if off_allowed and off_ledger:
        outside = off_ledger - off_allowed
        if outside:
            fails.append(f"C2 closures[offchain] has axiom(s) OUTSIDE lint_fv OFF_ALLOWED: "
                         f"{sorted(outside)}")
        keccak = "SphincsCVerify.Wallet.OffchainBinding.keccak_sha256_cross_separation"
        if keccak not in off_ledger:
            fails.append("C2 closures[offchain] is missing keccak_sha256_cross_separation "
                         "(the Gap-3 RAW32-oracle defense would be vacuous).")
    return fails


def _documented_axioms(ledger: dict) -> tuple[set[str], set[str]]:
    """(short-idents, full-names) of every axiom the ledger documents, including
    the `covers` list of a compound entry (so a row that bundles e.g. the single
    + Batch execute axioms must ENUMERATE both full FQNs, not hide one in prose)."""
    short = set(KERNEL)
    full = set(KERNEL)
    for a in ledger.get("axioms", []):
        short.add(axiom_ident(a["name"]))
        full.add(a["name"].strip().split()[0])
        for c in a.get("covers", []):
            short.add(axiom_ident(c))
            full.add(c.strip().split()[0])
    return short, full


def check_no_undocumented_axiom(ledger: dict, live: dict[str, set[str]]) -> list[str]:
    fails = []
    documented, documented_full = _documented_axioms(ledger)
    tracked = set(ledger.get("closures", {}))
    seen: dict[str, str] = {}
    for thm in tracked:
        for ax in live.get(thm, set()):
            seen.setdefault(ax, thm)
    for ax, where in sorted(seen.items()):
        if ax in KERNEL:
            continue
        if ax in documented_full or axiom_ident(ax) in documented:
            continue
        fails.append(f"C3 axiom `{ax}` appears in the live closure of {where} but is NOT "
                     f"documented as an `axioms[].name` entry in the ledger (silent trust expansion).")
    return fails


def check_no_phantom_axiom(ledger: dict, source_idents: set[str]) -> list[str]:
    fails = []
    for a in ledger.get("axioms", []):
        if a.get("status") == "kernel-tcb":
            continue
        for nm in [a["name"]] + a.get("covers", []):
            ident = axiom_ident(nm)
            if ident not in source_idents:
                fails.append(f"C4 ledger axiom {a['id']} (`{nm}`) has no `axiom {ident}` "
                             f"declaration in the Lean source — phantom/credibility-only entry?")
    return fails


def _canonical_rows_digest(rows: list[list[object]]) -> str:
    encoded = sorted(
        json.dumps(row, ensure_ascii=True, separators=(",", ":"))
        for row in rows
    )
    return sha256_hex("".join(f"{row}\n" for row in encoded))


def check_ledger_schema(ledger: dict) -> list[str]:
    """C16 — exact document/row schemas and values plus artifact invariants."""
    fails: list[str] = []
    if not isinstance(ledger, dict):
        return ["C16 ledger root is not an object."]

    top_level_fields = set(ledger)
    if top_level_fields != EXPECTED_LEDGER_TOP_LEVEL_FIELDS:
        missing = sorted(EXPECTED_LEDGER_TOP_LEVEL_FIELDS - top_level_fields)
        extra = sorted(top_level_fields - EXPECTED_LEDGER_TOP_LEVEL_FIELDS)
        fails.append(
            "C16 exact top-level ledger schema drift: "
            f"missing={missing}, extra={extra}"
        )
    ledger_value_digest = sha256_hex(
        json.dumps(
            ledger,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )
    if ledger_value_digest != EXPECTED_LEDGER_VALUE_SHA256:
        fails.append(
            "C16 exact full-ledger value drift: "
            f"sha256={ledger_value_digest}, "
            f"expected {EXPECTED_LEDGER_VALUE_SHA256}"
        )

    axioms = ledger.get("axioms")
    if not isinstance(axioms, list):
        return ["C16 axioms is not an array."]

    axiom_schema_rows: list[list[object]] = []
    axiom_value_rows: list[list[object]] = []
    artifact_schema_rows: list[list[object]] = []
    artifact_value_rows: list[list[object]] = []
    seen_artifact_values: dict[str, tuple[object, int]] = {}
    method_status_counts: dict[tuple[str, str], int] = {}
    allowed_axiom_fields = AXIOM_REQUIRED_FIELDS | AXIOM_OPTIONAL_FIELDS
    allowed_artifact_fields = ARTIFACT_STRING_FIELDS | {
        "pinned_codehash",
        "runs",
    }

    def method_component(value: object) -> str:
        if isinstance(value, str):
            return value
        return f"<{type(value).__name__}:{value!r}>"

    for index, axiom in enumerate(axioms):
        if not isinstance(axiom, dict):
            fails.append(f"C16 axioms[{index}] is not an object.")
            continue
        axiom_id = axiom.get("id")
        status = axiom.get("status")
        axiom_schema_rows.append([axiom_id, sorted(axiom)])
        axiom_value_rows.append([
            axiom_id,
            [
                [field, axiom[field]]
                for field in sorted(axiom)
                if field != "discharge_artifacts"
            ],
        ])

        missing = sorted(AXIOM_REQUIRED_FIELDS - set(axiom))
        extra = sorted(set(axiom) - allowed_axiom_fields)
        if missing:
            fails.append(
                f"C16 axiom {axiom_id!r} is missing required field(s) {missing}"
            )
        if extra:
            fails.append(
                f"C16 axiom {axiom_id!r} has unpinned field(s) {extra}"
            )

        for field in (
            "description",
            "id",
            "lean_type",
            "name",
            "status",
            "status_detail",
        ):
            value = axiom.get(field)
            if not isinstance(value, str) or not value:
                fails.append(
                    f"C16 axiom {axiom_id!r}.{field} must be a non-empty string, "
                    f"got {value!r}"
                )
        citation = axiom.get("citation")
        if citation is not None and (
            not isinstance(citation, str) or not citation
        ):
            fails.append(
                f"C16 axiom {axiom_id!r}.citation must be null or a non-empty "
                f"string, got {citation!r}"
            )
        for field in ("discharge_tier", "lean_type_note"):
            if field in axiom and (
                not isinstance(axiom[field], str) or not axiom[field]
            ):
                fails.append(
                    f"C16 axiom {axiom_id!r}.{field} must be a non-empty string"
                )
        if "covers" in axiom and (
            not isinstance(axiom["covers"], list)
            or not axiom["covers"]
            or any(
                not isinstance(item, str) or not item
                for item in axiom["covers"]
            )
        ):
            fails.append(
                f"C16 axiom {axiom_id!r}.covers must be a non-empty string array"
            )

        artifacts = axiom.get("discharge_artifacts")
        if not isinstance(artifacts, list):
            fails.append(
                f"C16 axiom {axiom_id!r}.discharge_artifacts is not an array"
            )
            continue
        for artifact_index, artifact in enumerate(artifacts):
            if not isinstance(artifact, dict):
                fails.append(
                    f"C16 axiom {axiom_id!r} artifact[{artifact_index}] is not "
                    "an object"
                )
                continue
            method = artifact.get("type")
            artifact_schema_rows.append([
                axiom_id,
                status,
                method,
                sorted(artifact),
            ])
            artifact_value_rows.append([
                axiom_id,
                artifact_index,
                [
                    [field, artifact[field]]
                    for field in sorted(artifact)
                ],
            ])
            canonical_artifact = json.dumps(
                artifact,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
            if canonical_artifact in seen_artifact_values:
                prior_id, prior_index = seen_artifact_values[
                    canonical_artifact
                ]
                fails.append(
                    f"C16 duplicate discharge artifact at axiom "
                    f"{axiom_id!r}[{artifact_index}] exactly repeats "
                    f"{prior_id!r}[{prior_index}]"
                )
            else:
                seen_artifact_values[canonical_artifact] = (
                    axiom_id,
                    artifact_index,
                )
            count_key = (
                method_component(status),
                method_component(method),
            )
            method_status_counts[count_key] = (
                method_status_counts.get(count_key, 0) + 1
            )

            artifact_extra = sorted(
                set(artifact) - allowed_artifact_fields
            )
            if artifact_extra:
                fails.append(
                    f"C16 axiom {axiom_id!r} artifact {method!r} has unpinned "
                    f"field(s) {artifact_extra}"
                )
            for field in ARTIFACT_STRING_FIELDS:
                if field in artifact and (
                    not isinstance(artifact[field], str)
                    or not artifact[field]
                ):
                    fails.append(
                        f"C16 axiom {axiom_id!r} artifact {method!r}.{field} "
                        "must be a non-empty string"
                    )
            if "pinned_codehash" in artifact:
                codehash = artifact["pinned_codehash"]
                if not isinstance(codehash, str) or re.fullmatch(
                    r"0x[0-9a-fA-F]{64}", codehash
                ) is None:
                    fails.append(
                        f"C16 axiom {axiom_id!r} artifact {method!r} has "
                        f"invalid pinned_codehash {codehash!r}"
                    )
            if "runs" in artifact and (
                type(artifact["runs"]) is not int
                or artifact["runs"] <= 0
            ):
                fails.append(
                    f"C16 axiom {axiom_id!r} artifact {method!r}.runs must be "
                    f"a positive integer, got {artifact['runs']!r}"
                )

    axiom_schema_digest = _canonical_rows_digest(axiom_schema_rows)
    if axiom_schema_digest != EXPECTED_AXIOM_SCHEMA_SHA256:
        fails.append(
            "C16 exact axiom-row schema drift: "
            f"sha256={axiom_schema_digest}, "
            f"expected {EXPECTED_AXIOM_SCHEMA_SHA256}"
        )
    artifact_schema_digest = _canonical_rows_digest(artifact_schema_rows)
    if artifact_schema_digest != EXPECTED_ARTIFACT_SCHEMA_SHA256:
        fails.append(
            "C16 exact discharge-artifact schema drift: "
            f"sha256={artifact_schema_digest}, "
            f"expected {EXPECTED_ARTIFACT_SCHEMA_SHA256}"
        )
    axiom_value_digest = _canonical_rows_digest(axiom_value_rows)
    if axiom_value_digest != EXPECTED_AXIOM_VALUE_SHA256:
        fails.append(
            "C16 exact axiom-row value drift: "
            f"sha256={axiom_value_digest}, "
            f"expected {EXPECTED_AXIOM_VALUE_SHA256}"
        )
    artifact_value_digest = _canonical_rows_digest(artifact_value_rows)
    if artifact_value_digest != EXPECTED_ARTIFACT_VALUE_SHA256:
        fails.append(
            "C16 exact discharge-artifact value drift: "
            f"sha256={artifact_value_digest}, "
            f"expected {EXPECTED_ARTIFACT_VALUE_SHA256}"
        )
    if method_status_counts != EXPECTED_ARTIFACT_METHOD_STATUS_COUNTS:
        actual = sorted(
            (status_name, method_name, count)
            for (status_name, method_name), count
            in method_status_counts.items()
        )
        expected = sorted(
            (status_name, method_name, count)
            for (status_name, method_name), count
            in EXPECTED_ARTIFACT_METHOD_STATUS_COUNTS.items()
        )
        fails.append(
            "C16 artifact status/method tally drift: "
            f"actual={actual}, expected={expected}"
        )
    return fails


def check_counts(ledger: dict) -> list[str]:
    fails = []
    axioms = ledger.get("axioms", [])
    summary = ledger.get("summary", {})
    if not isinstance(summary, dict):
        return ["C5 summary is not an object."]
    tally: dict[str, int] = {}
    for index, a in enumerate(axioms):
        if not isinstance(a, dict):
            fails.append(f"C5 axioms[{index}] is not an object.")
            continue
        status = a.get("status", "?")
        if not isinstance(status, str):
            status = f"<{type(status).__name__}:{status!r}>"
        tally[status] = tally.get(status, 0) + 1
    unknown = sorted(set(tally) - ALLOWED_AXIOM_STATUSES)
    if unknown:
        fails.append(
            "C5 unknown axioms[].status value(s): "
            f"{unknown}; allowed={sorted(ALLOWED_AXIOM_STATUSES)}"
        )
    missing = sorted(REQUIRED_SUMMARY_KEYS - set(summary))
    if missing:
        fails.append(f"C5 summary is missing required count field(s): {missing}")
    checks = [
        (summary_key, tally.get(status, 0))
        for status, summary_key in STATUS_TO_SUMMARY_KEY.items()
    ] + [("total_axioms_in_closure", len(axioms))]
    for key, actual in checks:
        if key not in summary:
            continue
        if (
            not isinstance(summary[key], int)
            or isinstance(summary[key], bool)
            or summary[key] < 0
        ):
            fails.append(
                f"C5 summary.{key} must be a non-negative integer, "
                f"got {summary[key]!r}"
            )
            continue
        if summary[key] != actual:
            fails.append(f"C5 summary.{key} = {summary[key]} but actual tally = {actual} "
                         f"(the hand-maintained count drifted from the axioms array)")
    known_total = sum(tally.get(status, 0) for status in ALLOWED_AXIOM_STATUSES)
    if known_total != len(axioms):
        fails.append(
            f"C5 known status tally = {known_total} but axioms length = "
            f"{len(axioms)} (an entry escaped the closed vocabulary)"
        )
    return fails


def check_status_hygiene(ledger: dict) -> list[str]:
    fails = []
    axioms = ledger.get("axioms", [])
    if not isinstance(axioms, list):
        return ["C6 axioms is not an array."]
    for a in axioms:
        if not isinstance(a, dict):
            fails.append("C6 axiom row is not an object.")
            continue
        st = a.get("status")
        if st not in ALLOWED_AXIOM_STATUSES:
            fails.append(
                f"C6 axiom {a.get('id', '?')} (`{a.get('name', '?')}`) has "
                f"unknown status {st!r}; allowed={sorted(ALLOWED_AXIOM_STATUSES)}"
            )
            continue
        if st in ("placeholder", "misleading"):
            fails.append(f"C6 axiom {a['id']} (`{a['name']}`) has status `{st}` — the ledger "
                         f"advertises 0 placeholder/misleading; reintroducing one must be conscious.")
        if st == "discharged-bytecode":
            arts = a.get("discharge_artifacts", [])
            ok = isinstance(arts, list) and any(
                isinstance(art, dict) and (
                    (
                        isinstance(art.get("pinned_codehash"), str)
                        and re.fullmatch(
                            r"0x[0-9a-fA-F]{64}",
                            art["pinned_codehash"],
                        )
                        is not None
                    )
                    or (
                        art.get("type")
                        in (
                            "halmos-session",
                            "kontrol-kevm-session",
                            "certora-rule-set",
                            "lean-refinement",
                            "executable-lean-differential",
                        )
                    )
                )
                for art in arts
            )
            if not ok:
                fails.append(f"C6 axiom {a['id']} marked `discharged-bytecode` but carries no "
                             f"discharge artifact (pinned codehash / halmos / kontrol / certora / lean).")
        if st == "cited-tcb":
            artifacts = a.get("discharge_artifacts")
            if not a.get("citation") and not (
                isinstance(artifacts, list) and artifacts
            ):
                fails.append(f"C6 axiom {a['id']} marked `cited-tcb` but carries neither a citation "
                             f"nor a discharge artifact.")
    return fails


def check_signature_pins(ledger: dict, file_reader) -> list[str]:
    fails = []
    for thm, pin in ledger.get("signature_pins", {}).items():
        short = thm.split(".")[-1]
        rel = pin["file"]
        text = file_reader(rel)
        if text is None:
            fails.append(f"C7 {thm}: pinned file {rel} not readable")
            continue
        stmt = extract_statement(text, short)
        if stmt is None:
            fails.append(f"C7 {thm}: could not extract `theorem {short} ... := by` "
                         f"(body delimiter changed? refactor?) — reconcile the pin by hand.")
            continue
        got = sha256_hex(stmt)
        if got != pin["sha256"]:
            fails.append(f"C7 {thm}: statement-hash DRIFT — pinned {pin['sha256'][:16]}… "
                         f"got {got[:16]}…. The theorem STATEMENT changed (a hypothesis added/removed, "
                         f"a conjunct dropped). If intended, update the pin; else it is a regression.")
            continue
        for sub in pin.get("must_contain", []):
            if sub not in stmt:
                fails.append(f"C7 {thm}: statement must contain `{sub}` but does not.")
        for sub in pin.get("must_not_contain", []):
            if sub in stmt:
                fails.append(f"C7 {thm}: statement must NOT contain `{sub}` but does "
                             f"(a forbidden raw hypothesis crept back in).")
    return fails


def check_no_sorry(live_text: str) -> list[str]:
    return ["C8 sorryAx present in a tracked closure — a proof is incomplete."] if "sorryAx" in live_text else []


def check_witness_coverage(ledger: dict, live: dict[str, set[str]]) -> list[str]:
    """C9 — ENFORCED non-vacuity-witness coverage. Each `witness_coverage` entry
    names a hand-written witness lemma proving a headline hypothesis is satisfiable
    (so the K conditional that conditions on it is not vacuous). The witness must
    (a) be PRESENT in the live dump (tracked by dump_axioms.lean + compiled) and
    (b) be KERNEL-ONLY — a non-vacuity witness that itself leans on a project axiom
    could be circular (the axiom might be the very thing being witnessed)."""
    fails = []
    for entry in ledger.get("witness_coverage", []):
        w = entry["witness"]
        construct = entry.get("construct", "?")
        if w not in live:
            fails.append(f"C9 witness `{w}` (for {construct}) is NOT in the live dump — the "
                         f"hypothesis would be UNWITNESSED (possibly vacuous). Restore the lemma "
                         f"or add `#print axioms {w}` to dump_axioms.lean.")
            continue
        rogue = live[w] - KERNEL
        if rogue:
            fails.append(f"C9 witness `{w}` closure carries non-kernel axiom(s) {sorted(rogue)} — a "
                         f"non-vacuity witness must be kernel-only, else it may be circular (resting "
                         f"on the very assumption it claims to witness).")
    return fails


# --------------------------------------------------------------------------- #
# C0 — MANDATORY REGISTRY (F8): deletion-tolerance guard.
# --------------------------------------------------------------------------- #
def check_mandatory_registry(ledger: dict) -> list[str]:
    """C0 — every mandatory collection is non-empty AND every hard-coded floor ID
    (flagship + bytecode/reachability chain closures, signature pins, non-vacuity
    witnesses, claim corollaries, and the flagship A1..A5 axiom names) is present.
    Closes the deletion-tolerance vacuity: deleting a whole `closures`/`axioms`/…
    collection (which makes every per-entry loop pass zero times) now fails here,
    as does silently pruning a single load-bearing ID."""
    fails = []
    for key in MANDATORY_COLLECTIONS:
        col = ledger.get(key)
        if not col:
            fails.append(f"C0 mandatory collection `{key}` is EMPTY or ABSENT — a whole evidence "
                         f"collection was deleted; the per-entry checks would pass vacuously.")
    if ledger.get("headline_theorem") != HEADLINE_THEOREM:
        fails.append(f"C0 headline_theorem = {ledger.get('headline_theorem')!r}, expected "
                     f"{HEADLINE_THEOREM!r} (the flagship was renamed or removed).")
    closures = ledger.get("closures", {})
    for t in sorted(MANDATORY_CLOSURES):
        if t not in closures:
            fails.append(f"C0 mandatory closure `{t}` absent from `closures` (deleted?).")
    pins = ledger.get("signature_pins", {})
    for t in sorted(MANDATORY_SIGNATURE_PINS):
        if t not in pins:
            fails.append(f"C0 mandatory signature_pin `{t}` absent from `signature_pins` (deleted?).")
    witnesses = {e.get("witness") for e in ledger.get("witness_coverage", [])}
    for w in sorted(MANDATORY_WITNESSES):
        if w not in witnesses:
            fails.append(f"C0 mandatory non-vacuity witness `{w}` absent from `witness_coverage` (deleted?).")
    coros = set(ledger.get("claim_corollaries", []))
    for c in sorted(MANDATORY_COROLLARIES):
        if c not in coros:
            fails.append(f"C0 mandatory claim corollary `{c}` absent from `claim_corollaries` (deleted?).")
        if c not in closures:
            fails.append(f"C0 claim corollary `{c}` is not a `closures` key (its closure is unpinned).")
    _, documented_full = _documented_axioms(ledger)
    for a in sorted(MANDATORY_AXIOM_NAMES):
        if a not in documented_full and axiom_ident(a) not in _documented_axioms(ledger)[0]:
            fails.append(f"C0 mandatory flagship axiom `{a}` not documented in `axioms[]` — the "
                         f"theft_free trust base (A1..A5) was silently pruned.")
    return fails


def check_closures_identity_pin(ledger: dict) -> list[str]:
    """C11 — the exact `closures` key set MUST equal EXPECTED_CLOSURES_KEYS.
    C0's floors only police a mandatory subset and C1 only iterates declared
    entries, so without this pin a quiet deletion of any other tracked identity
    shrinks the pinned evidence receipt while the gate stays green."""
    keys = set(ledger.get("closures", {}))
    if keys == EXPECTED_CLOSURES_KEYS:
        return []
    missing = sorted(EXPECTED_CLOSURES_KEYS - keys)
    extra = sorted(keys - EXPECTED_CLOSURES_KEYS)
    parts = []
    if missing:
        parts.append("DELETED " + ", ".join(missing))
    if extra:
        parts.append("UNPINNED-NEW " + ", ".join(extra))
    return [f"C11 closures identity drift ({len(keys)} keys, expected "
            f"{len(EXPECTED_CLOSURES_KEYS)}) — {'; '.join(parts)}. Adding, renaming, or "
            f"deleting a tracked closure identity must consciously update EXPECTED_CLOSURES_KEYS."]


def check_unique_list_identities(ledger: dict) -> list[str]:
    """C14 — duplicate IDENTITIES inside ledger lists.  The per-entry checks
    consume these lists via `set(...)` (C1 closures, C9 witnesses, C0
    corollaries), which silently dedupes: a duplicated identity inflates the
    C5 tallies and creates first-vs-last ambiguity for every other consumer
    of the same file, even though it cannot hide a rogue entry (C5/C6
    iterate every element).  Reject duplicates so list records carry exact
    identities, symmetric with the duplicate dump-record rejection (C13),
    the manifest parser, and the duplicate-key-rejecting ledger load."""
    fails = []

    def dups(items: list) -> list:
        seen, repeated = set(), set()
        for item in items:
            if item in seen:
                repeated.add(item)
            seen.add(item)
        return sorted(repeated)

    for thm, lst in ledger.get("closures", {}).items():
        repeated = dups(list(lst))
        if repeated:
            fails.append(f"C14 {thm}: duplicate axiom identit{'ies' if len(repeated) > 1 else 'y'} "
                         f"{repeated} in the `closures` list — a list record must carry exact "
                         f"identities (silently deduped by set() today, first-vs-last ambiguous "
                         f"for every other ledger consumer).")
    repeated = dups([a["id"] for a in ledger.get("axioms", []) if a.get("id") is not None])
    if repeated:
        fails.append(f"C14 duplicate `axioms[].id` {repeated} — each documented axiom must "
                     f"record exactly once.")
    repeated = dups([a["name"] for a in ledger.get("axioms", []) if a.get("name") is not None])
    if repeated:
        fails.append(f"C14 duplicate `axioms[].name` {repeated} — the same logical axiom under "
                     f"two ids is still a duplicate identity (first-vs-last ambiguous for every "
                     f"name-keyed consumer).")
    repeated = dups([e["witness"] for e in ledger.get("witness_coverage", []) if e.get("witness") is not None])
    if repeated:
        fails.append(f"C14 duplicate `witness_coverage[].witness` {repeated} — each "
                     f"non-vacuity witness must record exactly once.")
    repeated = dups(list(ledger.get("claim_corollaries", [])))
    if repeated:
        fails.append(f"C14 duplicate `claim_corollaries` {repeated} — each claim corollary "
                     f"must record exactly once.")
    return fails


# --------------------------------------------------------------------------- #
# source-ident harvest (for C4)
# --------------------------------------------------------------------------- #
def harvest_source_axiom_idents() -> set[str]:
    idents: set[str] = set()
    spec = LEAN_DIR / "SphincsCVerify"
    if not spec.is_dir():
        return idents
    pat = re.compile(r"^\s*axiom\s+([A-Za-z_][A-Za-z0-9_']*)")
    for f in spec.rglob("*.lean"):
        try:
            for line in f.read_text(encoding="utf-8").splitlines():
                m = pat.match(line)
                if m:
                    idents.add(m.group(1))
        except OSError:
            continue
    return idents


# --------------------------------------------------------------------------- #
# negative control
# --------------------------------------------------------------------------- #
def self_test() -> int:
    """WIRED-IN NEGATIVE CONTROL. Feed each check a corrupted input; assert it
    fires. If any corruption is NOT caught, the gate is vacuous → fail loudly."""
    print("=== check_ledger_consistency --self-test (negative control) ===")
    tf = "SphincsCVerify.Spec.Theorems.theft_free"
    base_closure = ["propext", "Classical.choice", "Quot.sound",
                    "SphincsCVerify.Bridge.solidityVerifier_compiles_correctly"]
    ledger = {
        "closures": {tf: list(base_closure)},
        "axioms": [
            {"id": "A3.1", "name": "SphincsCVerify.Bridge.solidityVerifier_compiles_correctly",
             "status": "discharged-bytecode",
             "discharge_artifacts": [{"type": "halmos-session", "pinned_codehash": "0xabc"}]},
            {"id": "K", "name": "propext", "status": "kernel-tcb"},
        ],
        "summary": {"cited_tcb": 0, "discharged_bytecode": 1, "kernel_tcb": 1,
                    "placeholder_true_typed": 0, "misleading": 0, "total_axioms_in_closure": 2},
        "signature_pins": {},
    }
    live_ok = {tf: set(base_closure)}
    cases = []

    # C1: live closure drops an advertised axiom -> must fire
    cases.append(("C1 missing", check_closures(ledger, {tf: set(base_closure[:-1])})))
    # C1: live closure gains an undocumented axiom -> must fire
    cases.append(("C1 extra", check_closures(ledger, {tf: set(base_closure + ["Foo.sneaky"])})))
    # C3: undocumented axiom in live closure -> must fire
    cases.append(("C3", check_no_undocumented_axiom(ledger, {tf: set(base_closure + ["Foo.undocumented"])})))
    # C4: phantom ledger axiom (not in source) -> must fire
    cases.append(("C4", check_no_phantom_axiom(ledger, set())))
    # C5: count drift -> must fire
    bad_counts = dict(ledger); bad_counts["summary"] = dict(ledger["summary"]); bad_counts["summary"]["discharged_bytecode"] = 99
    cases.append(("C5", check_counts(bad_counts)))
    # C5: unknown status with a co-adjusted known count -> must still fire
    unknown_status = json.loads(json.dumps(ledger))
    unknown_status["axioms"][0]["status"] = "discharged"
    unknown_status["summary"]["discharged_bytecode"] = 0
    cases.append(("C5 unknown status", check_counts(unknown_status)))
    # C5: deleting a required summary field must not silently skip the check
    missing_summary = json.loads(json.dumps(ledger))
    del missing_summary["summary"]["discharged_bytecode"]
    cases.append(("C5 missing summary field", check_counts(missing_summary)))
    # C6: discharged-bytecode with no artifact -> must fire
    bad_hygiene = {"axioms": [{"id": "X", "name": "SphincsCVerify.Bridge.x", "status": "discharged-bytecode",
                               "discharge_artifacts": []}]}
    cases.append(("C6 no-artifact", check_status_hygiene(bad_hygiene)))
    cases.append(("C6 unknown status", check_status_hygiene(
        {"axioms": [{"id": "U", "name": "n", "status": "discharged"}]})))
    # C6: a placeholder reappears -> must fire
    cases.append(("C6 placeholder", check_status_hygiene({"axioms": [{"id": "P", "name": "n", "status": "placeholder"}]})))
    # C7: signature drift -> must fire
    pin_ledger = {"signature_pins": {tf: {"file": "x.lean", "sha256": "deadbeef" * 8}}}
    cases.append(("C7 hash", check_signature_pins(
        pin_ledger, lambda r: "theorem theft_free (a : Nat) : True := by trivial")))
    # C7: must_not_contain violated -> must fire
    pin_ledger2 = {"signature_pins": {tf: {"file": "x.lean",
                   "sha256": sha256_hex("theorem theft_free (hInv : X) : True := by"),
                   "must_not_contain": ["hInv"]}}}
    cases.append(("C7 forbidden", check_signature_pins(
        pin_ledger2, lambda r: "theorem theft_free (hInv : X) : True := by trivial")))
    # C8: sorryAx -> must fire
    cases.append(("C8", check_no_sorry("'x' depends on axioms: [sorryAx]")))
    # C10: A3.1 bridge axiom RHS reverted to verifyYulModel -> must fire
    def _reverted_reader(rel):
        if "Refinement.lean" in rel:
            return "axiom solidityVerifier_compiles_correctly :\n  ∀ x, foo x = verifyYulModel x\n\n/-- next -/"
        return "def deployedVerifier (x : T) : Bool :=\n  verifyYulModel x\n\n/-! next -/"
    cases.append(("C10 verifyYulModel-revert", check_bridge_axiom_rhs(_reverted_reader)))
    # C9: witness missing from the dump -> must fire
    wc_ledger = {"witness_coverage": [{"construct": "cap", "witness": "Foo.cap_witness"}]}
    cases.append(("C9 missing", check_witness_coverage(wc_ledger, {})))
    # C9: witness present but rests on a non-kernel axiom -> must fire
    cases.append(("C9 rogue", check_witness_coverage(
        wc_ledger, {"Foo.cap_witness": {"propext", "Some.project_axiom"}})))

    # C0 (F8) DELETION NEGATIVES — the vacuity the per-entry loops could not see.
    # A ledger that satisfies every mandatory floor (the clean control for C0):
    mand = {
        "headline_theorem": HEADLINE_THEOREM,
        "closures": {t: [] for t in (MANDATORY_CLOSURES | MANDATORY_COROLLARIES)},
        "signature_pins": {t: {} for t in MANDATORY_SIGNATURE_PINS},
        "witness_coverage": [{"witness": w} for w in MANDATORY_WITNESSES],
        "claim_corollaries": sorted(MANDATORY_COROLLARIES),
        "axioms": [{"name": a} for a in MANDATORY_AXIOM_NAMES] + [{"name": "propext"}],
    }
    # (a) whole `closures` collection wiped -> must fire
    cases.append(("C0 closures deleted", check_mandatory_registry({**mand, "closures": {}})))
    # (b) only the flagship theft_free closure dropped -> must fire
    cl_no_flag = {k: v for k, v in mand["closures"].items() if k != HEADLINE_THEOREM}
    cases.append(("C0 flagship closure dropped", check_mandatory_registry({**mand, "closures": cl_no_flag})))
    # (c) whole `signature_pins` collection wiped -> must fire
    cases.append(("C0 signature_pins deleted", check_mandatory_registry({**mand, "signature_pins": {}})))
    # (d) whole `witness_coverage` collection wiped -> must fire
    cases.append(("C0 witness_coverage deleted", check_mandatory_registry({**mand, "witness_coverage": []})))
    # (e) whole `axioms` array wiped (the case check_counts alone misses) -> must fire
    cases.append(("C0 axioms deleted", check_mandatory_registry({**mand, "axioms": []})))
    # (f) `claim_corollaries` wiped -> must fire
    cases.append(("C0 claim_corollaries deleted", check_mandatory_registry({**mand, "claim_corollaries": []})))
    # (g) flagship theorem renamed -> must fire
    cases.append(("C0 headline_theorem mutated", check_mandatory_registry({**mand, "headline_theorem": "X.evil"})))
    # (h) a single flagship axiom (A5 EUF-CMA) pruned from axioms[] -> must fire
    ax_no_a5 = [a for a in mand["axioms"] if a["name"] != "SphincsCVerify.Crypto.EUF_CMA_SPHINCSplusC"]
    cases.append(("C0 flagship axiom pruned", check_mandatory_registry({**mand, "axioms": ax_no_a5})))

    # C11 EXACT-IDENTITY NEGATIVES — deleting a NON-mandatory tracked closure
    # (the reproduced 18->17 shrink) or adding an unpinned one must both fire.
    full_closures = {k: [] for k in EXPECTED_CLOSURES_KEYS}
    shrunk_closures = {k: v for k, v in full_closures.items()
                       if k != "SphincsCVerify.Crypto.honest_sig_not_forgery"}
    cases.append(("C11 non-mandatory closure deleted", check_closures_identity_pin({"closures": shrunk_closures})))
    cases.append(("C11 unpinned closure added", check_closures_identity_pin({"closures": {**full_closures, "X.evil": []}})))

    # C13 DUPLICATE-RECORD NEGATIVE — a same-name second dump record must be
    # rejected outright (last-wins overwrite would launder a rogue closure).
    try:
        parse_dump("'Dup.thm' depends on axioms: [Evil]\n'Dup.thm' depends on axioms: []\n")
        dup_fails: list[str] = []
    except SystemExit:
        dup_fails = ["duplicate dump record rejected"]
    cases.append(("C13 duplicate dump record", dup_fails))

    # C14 DUPLICATE LIST-IDENTITY NEGATIVES — duplicates inside ledger lists
    # must fire even though the per-entry checks dedupe via set().
    cases.append(("C14 duplicate closures-list axiom", check_unique_list_identities(
        {"closures": {tf: base_closure + [base_closure[0]]}})))
    cases.append(("C14 duplicate axioms[].id", check_unique_list_identities(
        {"axioms": [{"id": "A5"}, {"id": "A5"}]})))
    cases.append(("C14 duplicate axioms[].name", check_unique_list_identities(
        {"axioms": [{"id": "A5a", "name": "X.dup"}, {"id": "A5b", "name": "X.dup"}]})))
    cases.append(("C14 duplicate witness", check_unique_list_identities(
        {"witness_coverage": [{"witness": "W.one"}, {"witness": "W.one"}]})))
    cases.append(("C14 duplicate claim_corollaries", check_unique_list_identities(
        {"claim_corollaries": ["X.one", "X.one"]})))

    # C15 DUPLICATE LEDGER OBJECT KEY NEGATIVE — the load itself must reject
    # last-wins JSON (a benign second record hiding a rogue first one).
    try:
        json.loads('{"closures": {"t": ["Evil"], "t": []}}',
                   object_pairs_hook=_reject_duplicate_keys)
        dup_key_fails: list[str] = []
    except ValueError:
        dup_key_fails = ["duplicate ledger object key rejected"]
    cases.append(("C15 duplicate ledger object key", dup_key_fails))

    # C16 EXACT ROW/ARTIFACT SCHEMA+VALUE NEGATIVES — exercise the live pins,
    # not a hand-built miniature that could drift away from AXIOM_STATUS.json.
    schema_clean = load_ledger()
    extra_axiom_field = json.loads(json.dumps(schema_clean))
    extra_axiom_field["axioms"][0]["reviewer_only"] = True
    cases.append((
        "C16 extra axiom field",
        check_ledger_schema(extra_axiom_field),
    ))
    missing_axiom_field = json.loads(json.dumps(schema_clean))
    del missing_axiom_field["axioms"][0]["description"]
    cases.append((
        "C16 missing axiom field",
        check_ledger_schema(missing_axiom_field),
    ))
    fabricated_method = json.loads(json.dumps(schema_clean))
    fabricated_method["axioms"][0]["discharge_artifacts"][0][
        "type"
    ] = "fabricated-method"
    cases.append((
        "C16 fabricated artifact method",
        check_ledger_schema(fabricated_method),
    ))
    null_codehash = json.loads(json.dumps(schema_clean))
    codehash_replaced = False
    for axiom in null_codehash["axioms"]:
        for artifact in axiom["discharge_artifacts"]:
            if "pinned_codehash" in artifact:
                artifact["pinned_codehash"] = None
                codehash_replaced = True
                break
        if codehash_replaced:
            break
    cases.append((
        "C16 null pinned codehash",
        check_ledger_schema(null_codehash) if codehash_replaced else [],
    ))
    swapped_axiom_names = json.loads(json.dumps(schema_clean))
    swapped_rows = {
        axiom["id"]: axiom for axiom in swapped_axiom_names["axioms"]
    }
    if "A3.1" in swapped_rows and "A5-EUFCMA" in swapped_rows:
        swapped_rows["A3.1"]["name"], swapped_rows["A5-EUFCMA"]["name"] = (
            swapped_rows["A5-EUFCMA"]["name"],
            swapped_rows["A3.1"]["name"],
        )
        swapped_name_fails = check_ledger_schema(swapped_axiom_names)
    else:
        swapped_name_fails = []
    cases.append((
        "C16 swapped axiom ID/name binding",
        swapped_name_fails,
    ))
    substituted_artifact_value = json.loads(json.dumps(schema_clean))
    artifact_value_replaced = False
    for axiom in substituted_artifact_value["axioms"]:
        for artifact in axiom["discharge_artifacts"]:
            for field in ("evidence", "path", "date", "tool"):
                if field in artifact:
                    artifact[field] += "-mutated"
                    artifact_value_replaced = True
                    break
            if artifact_value_replaced:
                break
        if artifact_value_replaced:
            break
    cases.append((
        "C16 substituted artifact value",
        (
            check_ledger_schema(substituted_artifact_value)
            if artifact_value_replaced
            else []
        ),
    ))
    duplicated_artifact = json.loads(json.dumps(schema_clean))
    a1_row = next(
        (
            axiom for axiom in duplicated_artifact["axioms"]
            if axiom.get("id") == "A1"
        ),
        None,
    )
    if (
        a1_row is not None
        and len(a1_row.get("discharge_artifacts", [])) >= 2
    ):
        a1_row["discharge_artifacts"][1] = json.loads(json.dumps(
            a1_row["discharge_artifacts"][0]
        ))
        duplicated_artifact_fails = check_ledger_schema(
            duplicated_artifact
        )
    else:
        duplicated_artifact_fails = []
    cases.append((
        "C16 duplicate artifact value",
        duplicated_artifact_fails,
    ))
    added_corollary = json.loads(json.dumps(schema_clean))
    added_corollary["claim_corollaries"].append(
        "Fabricated.Assurance.Claim"
    )
    cases.append((
        "C16 appended claim corollary",
        check_ledger_schema(added_corollary),
    ))
    substituted_witness_construct = json.loads(json.dumps(schema_clean))
    substituted_witness_construct["witness_coverage"][0][
        "construct"
    ] = "fabricated assurance construct"
    cases.append((
        "C16 substituted witness construct",
        check_ledger_schema(substituted_witness_construct),
    ))
    substituted_headline = json.loads(json.dumps(schema_clean))
    substituted_headline[
        "headline_one_line"
    ] = "Everything is unconditionally proven."
    cases.append((
        "C16 substituted assurance headline",
        check_ledger_schema(substituted_headline),
    ))
    extra_top_level = json.loads(json.dumps(schema_clean))
    extra_top_level["reviewer_only"] = True
    cases.append((
        "C16 extra top-level field",
        check_ledger_schema(extra_top_level),
    ))

    # control: a CLEAN input must NOT fire (guards against always-fire vacuity)
    clean = check_closures(ledger, live_ok) + check_counts(ledger) \
        + check_status_hygiene(ledger) + check_mandatory_registry(mand) \
        + check_closures_identity_pin({"closures": full_closures}) \
        + check_unique_list_identities(ledger) + check_unique_list_identities(mand) \
        + check_ledger_schema(schema_clean)

    ok = True
    for label, result in cases:
        if not result:
            print(f"  FAIL: corruption `{label}` was NOT caught — gate is vacuous for this check!")
            ok = False
        else:
            print(f"  ok: `{label}` caught ({result[0][:70]}…)")
    if clean:
        print(f"  FAIL: a CLEAN closure produced a failure (gate always-fires): {clean}")
        ok = False
    else:
        print("  ok: clean closure produced no failure (not always-firing)")
    print("=== self-test PASS ===" if ok else "=== self-test FAILED ===")
    return 0 if ok else 1


def check_bridge_axiom_rhs(file_reader) -> list[str]:
    """C10 (2026-07-02, finding a31/A3.1-RHS-unpinned): the A3.1 bridge axiom RHS and
    the `deployedVerifier` def body MUST be `execC10Asm`, never the truncating
    `verifyYulModel` (FALSE as a ∀ off N-masked keys — the bytecode's two
    `and(key,N_MASK)==key` guards). A silent revert to `= verifyYulModel` keeps every
    closure axiom NAME identical, so C1 (name-diff) cannot see it — this pins the RHS
    SHAPE. The docstrings above both decls DISCUSS verifyYulModel, so we extract only the
    declaration BODY (past the `:` / `:=`, up to the next blank line / decl)."""
    fails = []
    checks = [
        ("lean/SphincsCVerify/Bridge/Refinement.lean",
         r"\baxiom\s+solidityVerifier_compiles_correctly\b\s*:(.*?)(?=\n\n|\n/-|\n\s*axiom\b|\n\s*def\b|\n\s*theorem\b)",
         "A3.1 axiom solidityVerifier_compiles_correctly RHS"),
        ("lean/SphincsCVerify/Bridge/EntryPoint.lean",
         r"\bdef\s+deployedVerifier\b.*?:=(.*?)(?=\n\n|\n/-|\n\s*def\b|\n\s*theorem\b)",
         "deployedVerifier def body"),
    ]
    for rel, pat, label in checks:
        text = file_reader(rel)
        if text is None:
            fails.append(f"C10 {label}: source file {rel} unreadable.")
            continue
        m = re.search(pat, text, re.DOTALL)
        if not m:
            fails.append(f"C10 {label}: declaration not found in {rel} (renamed/moved? reconcile the pin).")
            continue
        body = m.group(1)
        if "execC10Asm" not in body:
            fails.append(f"C10 {label}: must be `execC10Asm` but it is ABSENT "
                         f"(reverted to the FALSE-as-∀ verifyYulModel form?).")
        if "verifyYulModel" in body:
            fails.append(f"C10 {label}: contains `verifyYulModel` — the truncating form is FALSE "
                         f"as a ∀ off N-masked keys; the RHS must be `execC10Asm`.")
    return fails


# --------------------------------------------------------------------------- #
def main() -> int:
    args = sys.argv[1:]
    if "--self-test" in args:
        return self_test()
    dump_file = None
    if "--dump" in args:
        i = args.index("--dump")
        try:
            dump_file = args[i + 1]
        except IndexError:
            print("ERROR: --dump needs a file argument", file=sys.stderr)
            return 2

    try:
        ledger = load_ledger()
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: cannot load ledger {LEDGER_PATH}: {exc}", file=sys.stderr)
        return 2

    live_text = Path(dump_file).read_text(encoding="utf-8") if dump_file else run_live_dump()
    live = parse_dump(live_text)
    if not live:
        print("ERROR: no axiom closures parsed from the dump — is the Lean project built? "
              "(cd lean && lake build SphincsCVerify)", file=sys.stderr)
        return 2

    lint_text = LINT_FV_PATH.read_text(encoding="utf-8") if LINT_FV_PATH.exists() else ""
    source_idents = harvest_source_axiom_idents()

    def reader(rel: str) -> str | None:
        p = VERIF_DIR / rel
        try:
            return p.read_text(encoding="utf-8")
        except OSError:
            return None

    fails: list[str] = []
    fails += check_mandatory_registry(ledger)
    fails += check_closures_identity_pin(ledger)
    fails += check_unique_list_identities(ledger)
    fails += check_closures(ledger, live)
    fails += check_lint_fv_crosscheck(ledger, lint_text) if lint_text else \
        ["C2 lint_fv_invariants.sh not found — cannot cross-check the closure pin."]
    fails += check_no_undocumented_axiom(ledger, live)
    fails += check_no_phantom_axiom(ledger, source_idents)
    fails += check_ledger_schema(ledger)
    fails += check_counts(ledger)
    fails += check_status_hygiene(ledger)
    fails += check_signature_pins(ledger, reader)
    fails += check_bridge_axiom_rhs(reader)
    fails += check_no_sorry(live_text)
    fails += check_witness_coverage(ledger, live)

    print("=== verify-ledger-consistency (advertised AXIOM_STATUS.json vs live Lean truth) ===")
    print(f"  closures tracked: {len(ledger.get('closures', {}))} | "
          f"axioms documented: {len(ledger.get('axioms', []))} | "
          f"signature pins: {len(ledger.get('signature_pins', {}))} | "
          f"witnesses: {len(ledger.get('witness_coverage', []))}")
    print("  NOTE: live source is `#print axioms` (under-reports in lean v4.22.0); "
          "verify-lean4checker is NOT a completeness backstop: it replays the "
          "SAME version-matched C++ kernel and cannot see the #8840 omission "
          "shape (corrected 2026-08-11; see run_lean4checker.sh:28-33). The "
          "allowlist backstop is TRACKED AND NOT IMPLEMENTED.")
    if fails:
        print(f"\nFAIL: {len(fails)} ledger/kernel divergence(s):", file=sys.stderr)
        for f in fails:
            print(f"  - {f}", file=sys.stderr)
        print("\nThe human-facing ledger no longer matches the machine truth. "
              "Reconcile docs/AXIOM_STATUS.json with the Lean source/dump.", file=sys.stderr)
        return 1
    print("\nOK: every advertised closure, exact full-ledger/row/artifact schema "
          "and value, count, status/method tally, and headline-statement pin "
          "matches the live Lean truth.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
