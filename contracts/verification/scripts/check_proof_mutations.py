#!/usr/bin/env python3
"""verify-proof-mutation — the proof-side analogue of cargo-mutants, defending
failure-class V4 ("dead conjunct / vacuous lemma") from the FV adversarial-review
playbook. It answers the gut-check mechanically:

    "If I deleted this axiom / weakened this lemma — would something turn red?"

For each entry in lean/scripts/proof_mutations.json it mutates the Lean source
in a way whose outcome is KNOWN (delete-by-rename a load-bearing axiom -> expect
BUILD FAIL; comment out a non-consumed marker -> expect BUILD PASS + an exact
closure drop; rename a zero-consumer axiom -> expect BUILD PASS), rebuilds the
whole library, and asserts the result matches `expect`. A green-when-it-should-
be-red is a vacuity, reported as a failure. Most mutations EXECUTE a specific
falsifiability claim AXIOM_STATUS.json makes only in prose.

ROBUSTNESS (non-negotiable, per the playbook):
  * Every mutation must MATERIALLY change the file (find present, EXACTLY once,
    replace != find). A mutation that fails to apply is a HARD FAIL of the
    manifest (exit 2), NEVER a silent skip — otherwise the catcher reproduces
    the exact vacuity it exists to catch.
  * A permanent CANARY mutation (a guaranteed build-break in theft_free) must
    trip. If it does not, the harness is broken and ALL results are void.
  * The mutated file is ALWAYS reverted (finally + atexit + SIGINT/SIGTERM),
    and the revert is VERIFIED (re-read == original); a failed revert is a hard
    error with a `git checkout` recovery hint.
  * The full library is rebuilt (lake build SphincsCVerify rebuilds the changed
    module + all reverse-dependencies; mathlib stays cached) so a `build_fails`
    mutation can't pass spuriously on a stale incremental artifact.

SCOPE: closes V4 + the load-bearingness claims. Does NOT close V7 (a latent-FALSE
axiom still type-checks -> invisible to mutation while lean/ is mathlib-free) or
V11 (wrong spec). See docs/verification/fv-adversarial-review-playbook.md §A.

Usage:
    check_proof_mutations.py [--tier quick|default|full] [--list]
Environment: MUTATIONS=quick|default|full overrides the tier for direct checker
runs (default: default). The authoritative Make target passes `--tier default`
and rejects a caller-set MUTATIONS variable.

Exit: 0 = every mutation behaved as expected; 1 = a vacuity/broken-claim found;
      2 = harness/manifest error (mutation didn't apply, canary didn't trip,
          revert failed, build tooling missing).
"""
from __future__ import annotations

import atexit
import collections
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

import pwd

SCRIPT_DIR = Path(__file__).resolve().parent
VERIF_DIR = SCRIPT_DIR.parent
LEAN_DIR = VERIF_DIR / "lean"
MANIFEST = LEAN_DIR / "scripts" / "proof_mutations.json"
DUMP_SCRIPT = "scripts/dump_axioms.lean"
KERNEL = {"propext", "Classical.choice", "Quot.sound"}


def _pinned_lake() -> str:
    """The elan shim under the password-database home — never via PATH (a
    planted `lake` exiting 0 on the baseline build and non-zero on every
    mutant rebuild would read all mutations as "correctly broke" with no
    Lean ever run — wave-3 Opus 5 MEDIUM, same class as the closed wave-2
    ledger-dump finding)."""
    lake = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".elan" / "bin" / "lake"
    if not lake.is_file():
        raise HarnessError(f"lake not found at the pinned elan location ({lake})")
    return str(lake)


def _pinned_tool_env() -> dict:
    """Environment for evidence-tool subprocesses: force the elan/home root
    to the password-database home and drop ELAN_TOOLCHAIN, so the dispatcher
    cannot be re-rooted or re-selected by caller-mutable environment."""
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

TIER_ORDER = {"quick": 0, "default": 1, "full": 2}
# Checker-owned exact identity pin.  The source-order-independent digest is over
# the sorted fully-qualified names, one UTF-8 name per line with a final newline.
# A legitimate headline change must consciously update both pins.
EXPECTED_DUMP_HEADLINE_COUNT = 102
EXPECTED_DUMP_HEADLINE_SET_SHA256 = (
    "99b6c0bc2c53a4a25bca59d6de1bcabd414bc6a6ac7e4e502c04997e3a736acc"
)
# Checker-owned corpus identity.  The definition digest is over the complete
# mutation objects sorted by id and serialized as canonical JSON.  Pinning the
# definitions (not only their count/ids) keeps a weakened replacement, tier
# demotion, or changed expected outcome from silently shrinking the campaign.
EXPECTED_MUTATION_COUNT = 13
EXPECTED_MUTATION_ID_SET_SHA256 = (
    "bf901ee7432f4d73f4f567117e96d13b40205b30361e89e735dd3edc70e2965e"
)
EXPECTED_MUTATION_DEFINITIONS_SHA256 = (
    "1ce0292e6817e6d88ba9fbc5afc60e24c067043adc95d04ed94d4ea85dd77a3f"
)
EXPECTED_TIER_COUNTS = {"quick": 2, "default": 8, "full": 13}

# Global so the signal/atexit handler can restore a half-applied mutation.
_ACTIVE: tuple[Path, str] | None = None


def _restore_active() -> None:
    global _ACTIVE
    if _ACTIVE is None:
        return
    path, orig = _ACTIVE
    try:
        path.write_text(orig, encoding="utf-8")
    except OSError:
        sys.stderr.write(f"\n!!! COULD NOT REVERT {path} — run `git checkout -- {path}` !!!\n")
    _ACTIVE = None


def _signal_handler(signum, frame):
    sys.stderr.write(f"\n[caught signal {signum}] reverting active mutation…\n")
    _restore_active()
    sys.exit(2)


atexit.register(_restore_active)
signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


def parse_dump(text: str) -> dict[str, set[str]]:
    flat = re.sub(r"\s+", " ", text)
    out: dict[str, set[str]] = {}
    for m in re.finditer(r"'([^']+)' depends on axioms: \[([^\]]*)\]", flat):
        out[m.group(1)] = {a.strip() for a in m.group(2).split(",") if a.strip()}
    for m in re.finditer(r"'([^']+)' does not depend on any axioms", flat):
        out.setdefault(m.group(1), set())
    return out


def expected_dump_headlines(script_text: str | None = None) -> list[str]:
    if script_text is None:
        script_text = (LEAN_DIR / DUMP_SCRIPT).read_text(encoding="utf-8")
    headlines = re.findall(
        r"(?m)^[ \t]*#print[ \t]+axioms[ \t]+([A-Za-z0-9_'.]+)[ \t]*$",
        script_text,
    )
    if not headlines or len(headlines) != len(set(headlines)):
        raise HarnessError(
            "dump_axioms.lean must request a nonempty, duplicate-free headline set"
        )
    identity = hashlib.sha256(
        ("\n".join(sorted(headlines)) + "\n").encode("utf-8")
    ).hexdigest()
    if (
        len(headlines) != EXPECTED_DUMP_HEADLINE_COUNT
        or identity != EXPECTED_DUMP_HEADLINE_SET_SHA256
    ):
        raise HarnessError(
            "dump_axioms.lean headline inventory drift: "
            f"count={len(headlines)} sha256={identity}; expected "
            f"count={EXPECTED_DUMP_HEADLINE_COUNT} "
            f"sha256={EXPECTED_DUMP_HEADLINE_SET_SHA256}"
        )
    return headlines


def validate_dump_output(returncode: int, stdout: str, stderr: str) -> dict[str, set[str]]:
    combined = stdout + stderr
    if returncode != 0:
        raise HarnessError(
            "axiom dump command failed before a complete receipt "
            f"(exit {returncode}); tail: {combined[-500:].strip()}"
        )
    expected = expected_dump_headlines()
    flat = re.sub(r"\s+", " ", combined)
    record_names = re.findall(
        r"'([^']+)' (?:depends on axioms: \[[^\]]*\]|does not depend on any axioms)",
        flat,
    )
    counts = collections.Counter(record_names)
    missing = sorted(name for name in expected if counts[name] == 0)
    duplicate = sorted(name for name in expected if counts[name] != 1 and counts[name] > 0)
    parsed = parse_dump(combined)
    unexpected = sorted(set(parsed) - set(expected))
    if missing or duplicate or unexpected:
        raise HarnessError(
            "axiom dump is incomplete/ambiguous: "
            f"missing={missing}, duplicate={duplicate}, unexpected={unexpected}"
        )
    return parsed


def run_build() -> tuple[bool, str]:
    """lake build SphincsCVerify — full transitive rebuild. (ok, tail-output)."""
    cp = subprocess.run([_pinned_lake(), "build", "SphincsCVerify"], cwd=str(LEAN_DIR),
                        capture_output=True, text=True, timeout=1800,
                        env=_pinned_tool_env())
    out = (cp.stdout + cp.stderr)
    return cp.returncode == 0, out[-1500:]


def run_dump() -> dict[str, set[str]]:
    try:
        cp = subprocess.run(
            [_pinned_lake(), "env", "lean", DUMP_SCRIPT],
            cwd=str(LEAN_DIR),
            capture_output=True,
            text=True,
            timeout=900,
            env=_pinned_tool_env(),
        )
    except subprocess.TimeoutExpired as exc:
        raise HarnessError(
            f"axiom dump timed out after {exc.timeout}s; no partial output is accepted"
        ) from exc
    return validate_dump_output(cp.returncode, cp.stdout, cp.stderr)


class HarnessError(Exception):
    pass


def validate_mutation_manifest(manifest: object) -> list[dict]:
    """Return the exact pinned mutation corpus or fail closed."""
    if not isinstance(manifest, dict):
        raise HarnessError("proof_mutations.json must contain a JSON object")
    muts = manifest.get("mutations")
    if not isinstance(muts, list) or not muts:
        raise HarnessError("proof_mutations.json mutations must be a nonempty list")
    if any(not isinstance(mut, dict) for mut in muts):
        raise HarnessError("every proof mutation must be a JSON object")

    ids = [mut.get("id") for mut in muts]
    if any(not isinstance(mut_id, str) or not mut_id for mut_id in ids):
        raise HarnessError("every proof mutation must have a nonempty string id")
    duplicate_ids = sorted(
        mut_id for mut_id, count in collections.Counter(ids).items() if count != 1
    )
    if duplicate_ids:
        raise HarnessError(f"duplicate proof-mutation ids: {duplicate_ids}")
    if ids.count("canary") != 1:
        raise HarnessError("proof-mutation corpus must contain exactly one canary")

    sorted_ids = sorted(ids)
    id_digest = hashlib.sha256(
        ("\n".join(sorted_ids) + "\n").encode("utf-8")
    ).hexdigest()
    canonical_mutations = sorted(muts, key=lambda mut: mut["id"])
    definition_digest = hashlib.sha256(
        json.dumps(
            canonical_mutations,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    if (
        len(muts) != EXPECTED_MUTATION_COUNT
        or id_digest != EXPECTED_MUTATION_ID_SET_SHA256
        or definition_digest != EXPECTED_MUTATION_DEFINITIONS_SHA256
    ):
        raise HarnessError(
            "proof-mutation corpus identity drift: "
            f"count={len(muts)} id_sha256={id_digest} "
            f"definition_sha256={definition_digest}; expected "
            f"count={EXPECTED_MUTATION_COUNT} "
            f"id_sha256={EXPECTED_MUTATION_ID_SET_SHA256} "
            f"definition_sha256={EXPECTED_MUTATION_DEFINITIONS_SHA256}"
        )

    for tier, expected_count in EXPECTED_TIER_COUNTS.items():
        selected = [
            mut for mut in muts
            if TIER_ORDER.get(mut.get("tier", "default"), 99) <= TIER_ORDER[tier]
        ]
        if len(selected) != expected_count:
            raise HarnessError(
                f"proof-mutation {tier} tier selects {len(selected)} definitions; "
                f"expected exactly {expected_count}"
            )
    return muts


def load_mutation_manifest() -> list[dict]:
    try:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HarnessError(f"cannot parse {MANIFEST}: {exc}") from exc
    return validate_mutation_manifest(manifest)


def dump_validation_self_test() -> bool:
    """Pure controls: headline drift and partial receipts must be rejected."""
    source = (LEAN_DIR / DUMP_SCRIPT).read_text(encoding="utf-8")
    expected = expected_dump_headlines(source)
    delete_line = f"#print axioms {expected[-1]}"
    try:
        expected_dump_headlines(source.replace(delete_line, "", 1))
    except HarnessError:
        pass
    else:
        return False
    substitute_line = f"#print axioms {expected[0]}"
    try:
        expected_dump_headlines(
            source.replace(
                substitute_line,
                "#print axioms SphincsCVerify.SelfTest.ForgedHeadline",
                1,
            )
        )
    except HarnessError:
        pass
    else:
        return False
    one = expected[0]
    partial = f"'{one}' does not depend on any axioms\n"
    for returncode in (1, 0):
        try:
            validate_dump_output(returncode, partial, "fatal: truncated dump\n")
        except HarnessError:
            continue
        return False
    complete = "".join(
        f"'{headline}' does not depend on any axioms\n" for headline in expected
    )
    try:
        parsed = validate_dump_output(0, complete, "")
    except HarnessError:
        return False
    return set(parsed) == set(expected)


def apply_and_test(mut: dict) -> tuple[bool, str]:
    """Apply one mutation, rebuild, evaluate vs `expect`, ALWAYS revert.
    Returns (matched_expectation, detail). Raises HarnessError on a
    didn't-apply / failed-revert condition (manifest/harness fault, exit 2)."""
    global _ACTIVE
    path = LEAN_DIR / mut["file"]
    if not path.exists():
        raise HarnessError(f"{mut['id']}: target file {path} does not exist")
    orig = path.read_text(encoding="utf-8")
    find, replace = mut["find"], mut["replace"]

    # --- materiality guards (the anti-vacuity-in-the-catcher checks) ---
    n = orig.count(find)
    if n == 0:
        raise HarnessError(f"{mut['id']}: find-string ABSENT in {mut['file']} — "
                           f"mutation did not apply (file drifted?). Reconcile the manifest.")
    if n != 1:
        raise HarnessError(f"{mut['id']}: find-string occurs {n}x in {mut['file']} (not unique) — "
                           f"ambiguous mutation. Tighten the find-string.")
    if replace == find:
        raise HarnessError(f"{mut['id']}: replace == find (no-op mutation).")
    mutated = orig.replace(find, replace)
    if mutated == orig:
        raise HarnessError(f"{mut['id']}: applying the mutation changed nothing.")

    detail = ""
    try:
        _ACTIVE = (path, orig)
        path.write_text(mutated, encoding="utf-8")
        if path.read_text(encoding="utf-8") == orig:
            raise HarnessError(f"{mut['id']}: write did not take effect.")

        build_ok, build_tail = run_build()
        outcome = "build_passes" if build_ok else "build_fails"

        closure_ok = True
        if mut["expect"] == "build_passes" and build_ok and "closure_check" in mut:
            cc = mut["closure_check"]
            live = run_dump()
            got = live.get(cc["theorem"])
            exp = set(cc["expect_axioms"])
            if got is None:
                closure_ok = False
                detail += f" [closure: theorem {cc['theorem']} absent from dump]"
            elif got != exp:
                closure_ok = False
                detail += (f" [closure drift: MISSING {sorted(exp - got)} "
                           f"EXTRA {sorted(got - exp)}]")
            else:
                detail += f" [closure dropped to exactly {len(exp)} as advertised]"

        matched = (outcome == mut["expect"]) and closure_ok
        if not matched and outcome == "build_fails" and mut["expect"] == "build_passes":
            detail += f" [build tail: …{build_tail[-300:].strip()}]"
        detail = f"outcome={outcome} expect={mut['expect']}" + detail
        return matched, detail
    finally:
        path.write_text(orig, encoding="utf-8")
        if path.read_text(encoding="utf-8") != orig:
            _ACTIVE = (path, orig)
            raise HarnessError(f"{mut['id']}: REVERT FAILED for {path} — run `git checkout -- {path}`")
        _ACTIVE = None


def main() -> int:
    args = sys.argv[1:]
    try:
        dump_control_ok = dump_validation_self_test()
        muts = load_mutation_manifest()
    except HarnessError as exc:
        print(f"ERROR: proof-mutation receipt/corpus check failed: {exc}", file=sys.stderr)
        return 2
    if not dump_control_ok:
        print(
            "ERROR: closure-dump negative control failed; headline drift or "
            "partial output could be accepted",
            file=sys.stderr,
        )
        return 2
    if args == ["--self-test"]:
        try:
            validate_mutation_manifest({"mutations": []})
        except HarnessError:
            pass
        else:
            print(
                "ERROR: empty proof-mutation corpus negative control was accepted",
                file=sys.stderr,
            )
            return 2
        print(
            "check_proof_mutations --self-test PASS "
            "(headline deletion/substitution and partial dumps rejected; "
            "complete pinned dump and exact nonempty mutation corpus accepted)"
        )
        return 0
    tier = os.environ.get("MUTATIONS", "default")
    if "--tier" in args:
        tier = args[args.index("--tier") + 1]
    if tier not in TIER_ORDER:
        print(f"ERROR: unknown tier {tier!r} (quick|default|full)", file=sys.stderr)
        return 2

    sel = [m for m in muts if TIER_ORDER[m.get("tier", "default")] <= TIER_ORDER[tier]]
    # Canary is ALWAYS included regardless of tier.
    if not any(m["id"] == "canary" for m in sel):
        sel = [m for m in muts if m["id"] == "canary"] + sel
    expected_selected = EXPECTED_TIER_COUNTS[tier]
    if len(sel) != expected_selected:
        print(
            f"ERROR: tier {tier} selected {len(sel)} mutations; "
            f"expected exactly {expected_selected}",
            file=sys.stderr,
        )
        return 2

    if "--list" in args:
        for m in sel:
            print(f"  [{m.get('tier','default'):7s}] {m['id']:28s} expect={m['expect']:13s} {m['file']}")
        return 0

    print(f"=== verify-proof-mutation (tier={tier}, {len(sel)} mutations) ===")
    print("    proof-side cargo-mutants: delete/weaken a claim, expect the build to react.")
    print("    Each mutation rebuilds the full library (~1-5 min) then reverts.\n")

    # Verify shell tooling up front.
    try:
        subprocess.run([_pinned_lake(), "--version"], cwd=str(LEAN_DIR), capture_output=True, timeout=60,
                        env=_pinned_tool_env())
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print("ERROR: `lake` not runnable (need elan-installed Lean 4).", file=sys.stderr)
        return 2

    results = []
    canary_ok = None
    for m in sel:
        t0 = time.time()
        print(f"--> {m['id']:28s} ({m['file']})  expect={m['expect']}")
        try:
            matched, detail = apply_and_test(m)
        except HarnessError as e:
            print(f"    HARNESS ERROR: {e}", file=sys.stderr)
            return 2
        dt = time.time() - t0
        mark = "ok " if matched else "FAIL"
        print(f"    [{mark}] {detail}  ({dt:.0f}s)")
        results.append((m, matched, detail))
        if m["id"] == "canary":
            canary_ok = matched

    # Canary gate: if the canary did not behave (build_fails), the harness is void.
    if canary_ok is not True:
        print("\n=== HARNESS BROKEN: the canary mutation did NOT break the build. "
              "The mutation harness cannot detect a fault — ALL results are void. ===", file=sys.stderr)
        return 2

    failures = [(m, d) for (m, ok, d) in results if not ok]
    print()
    if failures:
        print(f"FAIL: {len(failures)} mutation(s) did not behave as the ledger claims:", file=sys.stderr)
        for m, d in failures:
            print(f"  - {m['id']}: {d}", file=sys.stderr)
            print(f"      ledger claim: {m.get('ledger_claim','')}", file=sys.stderr)
        print("\nA build_fails-expected mutation that PASSED = a dead/vacuous dependency "
              "(V4). A build_passes-expected mutation that FAILED = a 'not load-bearing' "
              "or closure claim in AXIOM_STATUS.json is FALSE. Reconcile.", file=sys.stderr)
        return 1
    print(f"OK: all {len(results)} mutations behaved as advertised "
          f"(load-bearing claims break on deletion; markers/zero-consumers stay green "
          f"with the exact closure drop).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
