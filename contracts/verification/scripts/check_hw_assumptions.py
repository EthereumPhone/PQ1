#!/usr/bin/env python3
"""verify-hw-assumptions — falsifiability gate for the HW-ASSUME ledger.

`docs/HW_ASSUMPTIONS.json` inventories the firmware-side hardware assumptions:
claims about silicon we did not design and cannot inspect.
`TRUST_ASSUMPTIONS.md`'s §Out-of-scope explicitly EXCLUDES firmware, so before
this ledger existed those premises lived only in prose scattered across docs and
comments.

**What this gate can and cannot do.** Unlike `check_ledger_consistency.py`,
there is no machine truth to check a row against — there is no `#print axioms`
for a die, and running a test on our two bench boards does not make a statement
about ST's fab true. So this gate deliberately does NOT try to validate the
premises. It falsifies everything *around* them, which is the part that rots:

  C1  ID DISCIPLINE      — ids are unique and match HW-ASSUME-[A-Z0-9-]+.
  C2  SCHEMA             — every row carries the required fields, a status from
                           the declared vocabulary, and a non-empty statement,
                           note and consumed_by. HARDENED 2026-08-20 (#669):
                           `evidence` must be a NON-EMPTY list with at least
                           one ANCHORED entry — the C3 loop over an empty or
                           anchor-less list vacuously passes, so gutting every
                           evidence list used to turn the whole ledger green.
  C3  ANCHORS RESOLVE    — every evidence `ref` file exists and, where an
                           `anchor` is given, that exact string is still present
                           in it. This is what catches a row going stale when
                           code moves out from under it — the failure mode that
                           turns a ledger back into prose.
  C4  TESTS ARE REAL     — `falsifying_test.exists: true` REQUIRES a
                           `make_target` that actually exists in a Makefile.
                           A claimed test that cannot be run is worse than an
                           admitted absence, because it reads as evidence.
                           HARDENED 2026-08-20 (#669): existence is not enough —
                           an arbitrary target (`make all` is not a falsifying
                           test) must not read as evidence. The target must
                           either match the hardware/e2e-test naming convention
                           (HW_TEST_TARGET_RE: ends `-hw`/`-e2e`/`-stress...`,
                           or is `e2e[-...]`) or its recipe text must cite the
                           row's own HW-ASSUME id.
  C5  BIDIRECTIONAL      — the load-bearing one, borrowed from OpenTitan's
                           RTL<->Hjson countermeasure cross-check (which this
                           project's 2026-07-17 hardware survey identified as
                           the only transferable half of their approach, since
                           we can never FPV our silicon and they designed
                           theirs): the set of HW-ASSUME ids in the ledger must
                           EXACTLY equal the set referenced across the tree.
                           An id cited in code/docs with no row is an
                           UNLEDGERED assumption. A row nobody cites is dead
                           weight that will drift.
  C6  FALSIFYING TEST    — every row states one that could fail. `exists:false`
                           is honest; an empty/absent description is not.

Run: `make -C contracts/verification verify-hw-assumptions`
     `python3 scripts/check_hw_assumptions.py --self-test`  (proves the gate bites)
"""

import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
LEDGER = REPO / "contracts/verification/docs/HW_ASSUMPTIONS.json"

ID_RE = re.compile(r"HW-ASSUME-[A-Z0-9][A-Z0-9-]*")
REQUIRED = ("id", "surface", "statement", "status", "evidence",
            "falsifying_test", "consumed_by", "note", "last_reviewed")

# Where a HW-ASSUME id may legitimately be referenced. The ledger itself and
# this gate are excluded from the "referenced" sweep for obvious reasons.
SWEEP_GLOBS = ("*.rs", "*.md", "*.py", "*.toml", "*.json", "*.tla", "*.sh")
SWEEP_SKIP = ("/target/", "/.git/", "/node_modules/", "HW_ASSUMPTIONS.json",
              "check_hw_assumptions.py", "/lib/forge-std/", "/lib/openzeppelin",
              "/contracts/smart-wallet/lib/")


def fail(errs, msg):
    errs.append(msg)


def load(path=LEDGER):
    with open(path) as fh:
        return json.load(fh)


def sweep_referenced_ids():
    """Every HW-ASSUME id cited anywhere in the tree, mapped to its files.

    ONE pass, so the skip list cannot be applied inconsistently. It was, once:
    an earlier version took names from a `git grep -ho` pass that ignored
    SWEEP_SKIP and locations from a `-n` pass that honoured it. That silently
    worked right up until this file itself was committed — `git grep` only sees
    TRACKED files — at which point the self-test's own ghost id
    (`HW-ASSUME-NOBODY-CITES-THIS`, a string that exists purely to be absent
    from the ledger) became "referenced" and the gate failed on itself. Keep the
    filtering in exactly one place.
    """
    hits = {}
    try:
        out = subprocess.run(
            ["git", "grep", "-nE", ID_RE.pattern],
            cwd=REPO, capture_output=True, text=True, timeout=120,
        )
    except Exception:
        return hits
    for line in out.stdout.splitlines():
        path = line.split(":", 1)[0]
        if any(s in f"/{path}" for s in SWEEP_SKIP):
            continue
        for m in ID_RE.findall(line):
            hits.setdefault(m, set()).add(path)
    return hits


# C4 (#669): an EXISTING make target is not automatically a falsifying test —
# `make all`/`make secure` exist too. Accept a claimed test target only when its
# name follows the repo's hardware/e2e-test convention below, or when the
# target's recipe text cites the row's own HW-ASSUME id (checked separately).
HW_TEST_TARGET_RE = re.compile(r"(?:^e2e(?:-|$)|-hw$|-e2e$|-stress(?:-|$))")


def makefile_targets():
    """{target_name: recipe_text} across the repo Makefiles. The recipe body
    (tab-indented lines after the target header) is kept so C4 (#669) can
    honour the escape hatch: a non-conventionally-named target is acceptable
    when its recipe cites the claiming row's HW-ASSUME id."""
    targets = {}
    for mf in (REPO / "Makefile", REPO / "contracts/verification/Makefile"):
        if not mf.exists():
            continue
        cur, buf = None, []
        for line in mf.read_text().splitlines() + [""]:
            m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*):", line)
            if m:
                if cur is not None and cur not in targets:
                    targets[cur] = "\n".join(buf)
                cur, buf = m.group(1), []
            elif cur is not None and (line.startswith("\t") or not line.strip()):
                buf.append(line)
            elif line.strip() and not line.startswith("#"):
                cur, buf = None, []
        if cur is not None and cur not in targets:
            targets[cur] = "\n".join(buf)
    return targets


def check(ledger, referenced, targets):
    errs = []
    rows = ledger.get("assumptions", [])
    if not rows:
        fail(errs, "C2: ledger has no `assumptions` rows")
        return errs

    vocab = set(ledger.get("_status_vocabulary", {}))
    seen = set()

    for row in rows:
        rid = row.get("id", "<no-id>")

        # C1 — id discipline
        if not ID_RE.fullmatch(rid or ""):
            fail(errs, f"C1: bad id {rid!r} (want HW-ASSUME-...)")
        if rid in seen:
            fail(errs, f"C1: duplicate id {rid}")
        seen.add(rid)

        # C2 — schema
        for f in REQUIRED:
            if f not in row:
                fail(errs, f"C2: {rid}: missing field `{f}`")
        if row.get("status") not in vocab:
            fail(errs, f"C2: {rid}: status {row.get('status')!r} not in _status_vocabulary {sorted(vocab)}")
        for f in ("statement", "note"):
            if not (row.get(f) or "").strip():
                fail(errs, f"C2: {rid}: `{f}` is empty — a row with no stated premise is not a row")
        if not row.get("consumed_by"):
            fail(errs, f"C2: {rid}: `consumed_by` is empty — an assumption nothing depends on should be deleted, not tracked")
        # C2 — evidence floor (#669): the C3 loop over an EMPTY or anchor-less
        # evidence list vacuously passes, so gutting every row's evidence used
        # to leave the whole gate green. Require >=1 entry AND >=1 anchored entry.
        evidence = row.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            fail(errs, f"C2: {rid}: `evidence` is empty — a row with no evidence is prose in JSON")
        elif not any(isinstance(e, dict) and e.get("anchor") for e in evidence):
            fail(errs, f"C2: {rid}: no evidence entry carries an `anchor` — an unanchored row drifts into prose")

        # C3 — anchors resolve
        for ev in row.get("evidence", []):
            ref = ev.get("ref")
            if not ref:
                fail(errs, f"C3: {rid}: evidence entry with no `ref`")
                continue
            p = REPO / ref
            if not p.exists():
                fail(errs, f"C3: {rid}: evidence ref does not exist: {ref}")
                continue
            anchor = ev.get("anchor")
            if anchor:
                try:
                    body = p.read_text(errors="ignore")
                except Exception as e:
                    fail(errs, f"C3: {rid}: cannot read {ref}: {e}")
                    continue
                if anchor not in body:
                    fail(errs, f"C3: {rid}: anchor not found in {ref}: {anchor!r} "
                               f"— the code moved out from under this row; re-point it (do not delete the row)")

        # C4/C6 — the falsifying test
        ft = row.get("falsifying_test") or {}
        if not (ft.get("description") or "").strip():
            fail(errs, f"C6: {rid}: no falsifying_test.description — a row with no test that could fail is prose in JSON")
        if ft.get("exists") is True:
            tgt = ft.get("make_target")
            if not tgt:
                fail(errs, f"C4: {rid}: falsifying_test.exists=true but no make_target")
            elif tgt not in targets:
                fail(errs, f"C4: {rid}: falsifying_test.make_target `{tgt}` is not a real Makefile target "
                           f"— a claimed test that cannot be run reads as evidence and is not")
            elif not HW_TEST_TARGET_RE.search(tgt) and rid not in targets.get(tgt, ""):
                fail(errs, f"C4: {rid}: falsifying_test.make_target `{tgt}` exists but is not a hardware/e2e test "
                           f"(its name must match {HW_TEST_TARGET_RE.pattern!r}, or its recipe must cite {rid}) "
                           f"— an arbitrary existing target reads as evidence and is not")

    # C5 — bidirectional
    ledger_ids = seen
    ref_ids = set(referenced)
    unledgered = ref_ids - ledger_ids
    if unledgered:
        for u in sorted(unledgered):
            where = ", ".join(sorted(referenced.get(u, {"?"})))
            fail(errs, f"C5: {u} is referenced but has NO ledger row (cited in: {where}) "
                       f"— that is an unledgered hardware assumption")
    dead = ledger_ids - ref_ids
    if dead:
        for d in sorted(dead):
            fail(errs, f"C5: {d} has a ledger row but is referenced NOWHERE in the tree "
                       f"— dead rows drift; cite it or delete it")
    return errs


def self_test():
    """Prove the gate bites: each mutation MUST be caught."""
    base = load()
    targets = makefile_targets()
    refs = sweep_referenced_ids()
    ok = check(base, refs, targets)
    if ok:
        print("SELF-TEST ABORTED: the live ledger is already failing:")
        for e in ok:
            print("   ", e)
        return 1

    cases = []

    # C3: break an anchor.
    m = json.loads(json.dumps(base))
    m["assumptions"][0]["evidence"][0]["anchor"] = "this string is not in that file"
    cases.append(("C3 stale anchor", m, refs))

    # C4: claim a test that does not exist.
    m = json.loads(json.dumps(base))
    m["assumptions"][0]["falsifying_test"]["exists"] = True
    m["assumptions"][0]["falsifying_test"]["make_target"] = "definitely-not-a-target"
    cases.append(("C4 fake make target", m, refs))

    # C5: an id cited in the tree with no row.
    m = json.loads(json.dumps(base))
    dropped = m["assumptions"].pop(0)
    cases.append((f"C5 unledgered ({dropped['id']})", m, refs))

    # C5: a row nobody cites.
    m = json.loads(json.dumps(base))
    ghost = json.loads(json.dumps(base["assumptions"][0]))
    ghost["id"] = "HW-ASSUME-NOBODY-CITES-THIS"
    m["assumptions"].append(ghost)
    cases.append(("C5 dead row", m, refs))

    # C6: no falsifying test.
    m = json.loads(json.dumps(base))
    m["assumptions"][0]["falsifying_test"]["description"] = ""
    cases.append(("C6 no falsifying test", m, refs))

    # C2: bogus status.
    m = json.loads(json.dumps(base))
    m["assumptions"][0]["status"] = "totally-proven"
    cases.append(("C2 status outside vocabulary", m, refs))

    # C2 (#669): gutted evidence list — C3 over an empty list vacuously passes.
    m = json.loads(json.dumps(base))
    m["assumptions"][0]["evidence"] = []
    cases.append(("C2 gutted evidence list", m, refs))

    # C2 (#669): evidence entries present but ALL anchor-less — same vacuity.
    m = json.loads(json.dumps(base))
    for ev in m["assumptions"][0]["evidence"]:
        ev.pop("anchor", None)
    cases.append(("C2 anchor-less evidence", m, refs))

    # C4 (#669): an ARBITRARY REAL make target that is not a hardware/e2e test
    # and whose recipe does not cite the row id.
    m = json.loads(json.dumps(base))
    m["assumptions"][0]["falsifying_test"]["exists"] = True
    m["assumptions"][0]["falsifying_test"]["make_target"] = "secure"
    cases.append(("C4 arbitrary real target (non-hw)", m, refs))

    rc = 0
    for name, mutated, r in cases:
        errs = check(mutated, r, targets)
        if errs:
            print(f"  [ok  ] {name:34s} -> caught: {errs[0][:88]}")
        else:
            print(f"  [FAIL] {name:34s} -> SURVIVED (this gate is vacuous)")
            rc = 1

    # C4 escape-hatch POSITIVE control: a non-conventional target name must be
    # ACCEPTED when its recipe text cites the claiming row's id — proves the
    # restriction is not always-firing.
    m = json.loads(json.dumps(base))
    rid0 = m["assumptions"][0]["id"]
    m["assumptions"][0]["falsifying_test"]["exists"] = True
    m["assumptions"][0]["falsifying_test"]["make_target"] = "weird-internal-probe"
    fake_targets = dict(targets)
    fake_targets["weird-internal-probe"] = f'\t@echo "falsifies {rid0}"\n\t./bench-probe.sh\n'
    errs = check(m, refs, fake_targets)
    if errs:
        print(f"  [FAIL] C4 recipe-cites-id escape hatch    -> false positive: {errs[0][:80]}")
        rc = 1
    else:
        print(f"  [ok  ] C4 recipe-cites-id escape hatch    -> accepted (not always-firing)")
    return rc


def main():
    if "--self-test" in sys.argv:
        print("=== verify-hw-assumptions self-test (each mutation MUST be caught) ===")
        rc = self_test()
        print("=== self-test PASS ===" if rc == 0 else "=== self-test FAIL ===")
        return rc

    ledger = load()
    errs = check(ledger, sweep_referenced_ids(), makefile_targets())
    rows = ledger.get("assumptions", [])
    if errs:
        print(f"verify-hw-assumptions: {len(errs)} problem(s) in {LEDGER.relative_to(REPO)}:")
        for e in errs:
            print("  -", e)
        return 1

    by_status = {}
    for r in rows:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
    testable = sum(1 for r in rows if (r["falsifying_test"] or {}).get("exists"))
    print(f"verify-hw-assumptions: OK — {len(rows)} hardware assumptions ledgered.")
    print("  by status: " + ", ".join(f"{k}={v}" for k, v in sorted(by_status.items())))
    print(f"  with a runnable falsifying test: {testable}/{len(rows)}")
    print("  NOTE: this gate checks the ledger's HYGIENE, never the premises. "
          "No amount of green here makes a claim about silicon true.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
