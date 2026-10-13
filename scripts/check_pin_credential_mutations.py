#!/usr/bin/env python3
"""verify-pin-credential-gates — would the #855 guards turn red if the defect came back?

Issue #855 (Ledger Donjon report): each secure element held the PIN in a form
that needed nothing from the microcontroller, so reading either chip gave the
PIN. The guards added with the fix are host tests and source-text pins. A guard
that stays green when its property is broken is worse than no guard, so this
gate re-introduces each form of the defect, one at a time, and requires the
guard that claims to police it to fail.

For each entry in scripts/pin_credential_mutations.json:

  1. apply one source edit (`find` must occur EXACTLY once; a mutation that does
     not apply is a hard error, never a skip);
  2. run only the named test filter of the secure crate's host suite;
  3. require that the run fails AND that every test named in `must_fail` is
     reported FAILED (a compile error counts only for entries marked
     `"expect": "compile_error"`);
  4. restore the file, verify the restore byte-for-byte, and move its mtime
     forward so the build cache cannot keep serving the mutated object.

A CANARY entry (id "canary") runs first. If it is not caught the machinery
itself is broken and every other result is void.

This shows the listed guards are not vacuous for the listed edits. It does not
show the guards are complete: an edit that is not in the manifest may still
survive. Add an entry whenever a guard is added.

INTERRUPTED RUNS. While a mutation is applied the working tree contains the
defect. A SIGINT/SIGTERM restores it, but a power loss or a host crash cannot
(this happened on 2026-10-13: the machine went down with the canary applied,
leaving `HalfMask::apply` a no-op in an uncommitted security fix). So:

  * before a file is mutated its original bytes and a journal entry are
    written under target/pin-credential-mutations/ and fsynced; the next run
    finds the journal and restores the file before it does anything else;
  * `--check` (no cargo, a second or two) verifies that every `find` occurs
    exactly once and that no entry's inserted text is present, and it applies
    each mutation in memory to prove it would notice that mutation if it were
    left in the tree. So it fails for a file that still carries a mutation and
    for a manifest whose anchor has rotted. CI runs it on every PR, so a
    leftover mutation cannot be merged and the manifest cannot go stale
    unnoticed even though the mutation run itself is local.

Usage:  check_pin_credential_mutations.py [--list] [--check] [--self-test] [--only ID[,ID...]]
Exit:   0 every mutation was caught as expected (or --check / --self-test passed)
        1 a mutation survived (a vacuous guard)
        2 manifest / machinery error (did not apply, canary survived, restore
          failed, a mutation is still applied, an interrupted run was found
          by --check)
"""
from __future__ import annotations

import argparse
import atexit
import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = Path(__file__).with_name("pin_credential_mutations.json")
CARGO_TEST = [
    "cargo", "test", "--locked", "-p", "sphincs-tz-secure",
    "--no-default-features", "--features", "mock-se,debug-log,ui-semihosting", "--",
]

JOURNAL_DIR = ROOT / "target" / "pin-credential-mutations"

# Printed when --check fails, because the person reading it is usually someone
# who edited an unrelated-looking line and has never seen this file.
CHECK_HELP = """
What this means. scripts/pin_credential_mutations.json lists source edits that
re-introduce the #855 defect (a secure element shown a PIN). Each entry names
its line by exact text (`find`), and this check requires that text to occur
exactly once.

  occurs 0 times
      Usually: you changed or moved a line a mutation anchors on. That is
      allowed. Update the entry's `find` (and `replace`) to the new text,
      then run
          python3 scripts/check_pin_credential_mutations.py --only <id>
      and expect CAUGHT. If it reports SURVIVED, your change removed what the
      guard was guarding: fix the code or the guard, not the manifest.
      Rarely ("the MUTATION may still be applied", or you did not touch that
      file): an interrupted `make verify-pin-credential-gates` left the defect
      in the tree. Look at `git diff -- <file>`, restore it, do not commit.
  occurs 2 or more times
      The anchor text is no longer unique. Lengthen `find` until it is.
  "the MUTATION is applied"
      The text a mutation inserts is in the file. Restore the file; do not
      commit.

Deleting an entry to get green removes a regression check for a security
defect; say why in the commit if you do."""

_restore: dict[Path, bytes] = {}


def _write_durably(path: Path, data: bytes) -> None:
    with open(path, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())


def _sync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def journal_begin(journal_dir: Path, root: Path, target: Path, original: bytes, mutation_id: str) -> None:
    """Record, durably, what is about to be mutated and what it must go back to."""
    journal_dir.mkdir(parents=True, exist_ok=True)
    _write_durably(journal_dir / "original.bin", original)
    entry = {
        "id": mutation_id,
        "file": target.relative_to(root).as_posix(),
        "sha256": hashlib.sha256(original).hexdigest(),
    }
    _write_durably(journal_dir / "in-progress.json", json.dumps(entry).encode())
    _sync_dir(journal_dir)


def journal_end(journal_dir: Path) -> None:
    (journal_dir / "in-progress.json").unlink(missing_ok=True)
    (journal_dir / "original.bin").unlink(missing_ok=True)


def journal_pending(journal_dir: Path) -> dict | None:
    path = journal_dir / "in-progress.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        # A journal that cannot be read still means a run was interrupted.
        return {"id": "?", "file": "?", "sha256": ""}


def journal_recover(journal_dir: Path, root: Path) -> str | None:
    """Undo a mutation an interrupted run left applied. Return what was done,
    or None when there was nothing to recover. Raises RuntimeError when a
    journal exists but the file cannot be restored from it."""
    entry = journal_pending(journal_dir)
    if entry is None:
        return None
    backup = journal_dir / "original.bin"
    if not backup.exists():
        raise RuntimeError(f"interrupted run on {entry['file']} ({entry['id']}) but the backup is missing")
    original = backup.read_bytes()
    if hashlib.sha256(original).hexdigest() != entry["sha256"]:
        raise RuntimeError(f"interrupted run on {entry['file']} ({entry['id']}) but the backup does not match its digest")
    target = root / entry["file"]
    _write_durably(target, original)
    now = time.time() + 1
    os.utime(target, (now, now))
    journal_end(journal_dir)
    return f"recovered from an interrupted run: restored {entry['file']} (mutation `{entry['id']}` was still applied)"


def applied_shape(find: bytes, replace: bytes, text: bytes) -> str | None:
    """Why `text` looks like it has this mutation applied, or None.

    A mutation that replaces or deletes text removes its own anchor, so the
    count check below sees it. One that INSERTS text keeps the anchor (`find`
    is part of `replace`), and with the mutation applied `find` still occurs
    once: only the presence of `replace` gives it away. (Review 2026-10-13:
    both reviewers found the one insertion entry slipping through.)
    """
    if find in replace and replace in text:
        return "its `replace` text is present"
    return None


def undetectable(entries: list[dict], root: Path) -> list[str]:
    """Entries that this check could NOT see if they were left applied.

    Each mutation is applied in memory to the file as it is now and the
    result is fed to the same tests `check_manifest` uses. An entry listed
    here would make the "no mutation left in the tree" claim false, so it is
    a manifest error: reshape the entry until its mutated form is visible.
    """
    blind = []
    for e in entries:
        find, replace = e["find"].encode(), e["replace"].encode()
        original = (root / e["file"]).read_bytes()
        if original.count(find) != 1:
            continue  # reported by check_manifest
        mutated = original.replace(find, replace)
        if mutated.count(find) == 1 and applied_shape(find, replace, mutated) is None:
            blind.append(e["id"])
    return blind


def check_manifest(entries: list[dict], root: Path) -> list[str]:
    """Every `find` must occur exactly once, and no mutation may be applied.
    Returns the problems found."""
    problems = []
    for e in entries:
        text = (root / e["file"]).read_bytes()
        count = text.count(e["find"].encode())
        if count == 1:
            shape = applied_shape(e["find"].encode(), e["replace"].encode(), text)
            if shape is not None:
                problems.append(
                    f"{e['id']}: the MUTATION is applied in {e['file']} ({shape}); restore the file"
                )
            continue
        hint = ""
        # Only a hint, and only where it can mean something: when `replace`
        # is part of `find` (a mutation that deletes text) its presence says
        # nothing. A real interrupted run is reported from the journal.
        if count == 0 and e["replace"] not in e["find"] and text.count(e["replace"].encode()) >= 1:
            hint = " -- the mutated text is present: the MUTATION may still be applied (an interrupted run?)"
        problems.append(f"{e['id']}: `find` occurs {count} times in {e['file']} (must be exactly 1){hint}")
    return problems


def self_test() -> int:
    """The recovery path and --check, on a throwaway tree."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "src").mkdir()
        target = root / "src" / "f.rs"
        original = b"fn apply() { out = half ^ mask; }\n"
        target.write_bytes(original)
        entries = [{"id": "t", "file": "src/f.rs", "find": "out = half ^ mask;", "replace": "out = half;"}]
        jdir = root / "journal"
        if check_manifest(entries, root):
            print("self-test: a clean tree was reported dirty", file=sys.stderr)
            return 2
        # A run that died with the mutation applied.
        journal_begin(jdir, root, target, original, "t")
        target.write_bytes(original.replace(b"out = half ^ mask;", b"out = half;"))
        problems = check_manifest(entries, root)
        if len(problems) != 1 or "MUTATION may still be applied" not in problems[0]:
            print(f"self-test: --check missed an applied mutation: {problems}", file=sys.stderr)
            return 2
        # An ordinary edit of an anchored line must be reported, without the
        # claim that a mutation is applied.
        target.write_bytes(original.replace(b"half ^ mask", b"half  ^  mask"))
        problems = check_manifest(entries, root)
        if len(problems) != 1 or "MUTATION" in problems[0]:
            print(f"self-test: an edited anchor was misreported: {problems}", file=sys.stderr)
            return 2
        target.write_bytes(original.replace(b"out = half ^ mask;", b"out = half;"))
        if journal_pending(jdir) is None:
            print("self-test: the journal was not found", file=sys.stderr)
            return 2
        message = journal_recover(jdir, root)
        if message is None or target.read_bytes() != original or journal_pending(jdir) is not None:
            print("self-test: recovery did not restore the file", file=sys.stderr)
            return 2
        if check_manifest(entries, root):
            print("self-test: the tree is still dirty after recovery", file=sys.stderr)
            return 2
        # A mutation that INSERTS text keeps its anchor. It must still be seen
        # when applied, with no journal, and must not be reported when it is
        # not applied.
        insertion = [{"id": "ins", "file": "src/f.rs", "find": "fn apply() {",
                      "replace": "fn leak() {}\nfn apply() {"}]
        if check_manifest(insertion, root) or undetectable(insertion, root):
            print("self-test: a clean tree was reported dirty (insertion entry)", file=sys.stderr)
            return 2
        target.write_bytes(original.replace(b"fn apply() {", b"fn leak() {}\nfn apply() {"))
        problems = check_manifest(insertion, root)
        if len(problems) != 1 or "MUTATION is applied" not in problems[0]:
            print(f"self-test: --check missed an applied insertion: {problems}", file=sys.stderr)
            return 2
        target.write_bytes(original)
        # An entry whose applied form this check cannot see is a manifest error.
        blind = [{"id": "blind", "file": "src/f.rs", "find": "half ^ mask", "replace": "half ^ mask ^ 0"}]
        if undetectable(blind, root) != []:
            print("self-test: an insertion with a visible `replace` was called undetectable", file=sys.stderr)
            return 2
        # ... such as one whose replacement re-forms its own anchor.
        (root / "src" / "g.rs").write_bytes(b"aab\n")
        reforms = [{"id": "reforms", "file": "src/g.rs", "find": "ab", "replace": "b"}]
        if undetectable(reforms, root) != ["reforms"]:
            print("self-test: an entry that re-forms its anchor was not reported as undetectable", file=sys.stderr)
            return 2
        # A journal whose backup was tampered with or lost must not be trusted.
        journal_begin(jdir, root, target, original, "t")
        (jdir / "original.bin").write_bytes(b"something else")
        try:
            journal_recover(jdir, root)
        except RuntimeError:
            pass
        else:
            print("self-test: a backup that fails its digest was restored", file=sys.stderr)
            return 2
    print("verify-pin-credential-gates --self-test: OK (recovery, --check incl. insertions, bad-backup refusal)")
    return 0


def _restore_all() -> None:
    for path, original in list(_restore.items()):
        path.write_bytes(original)
        # Move mtime FORWARD: a restore that leaves an older-or-equal mtime can
        # let cargo keep the object it built from the mutated source.
        now = time.time() + 1
        os.utime(path, (now, now))
        if path.read_bytes() != original:
            print(f"FATAL: could not restore {path}; run `git checkout -- {path}`", file=sys.stderr)
            os._exit(2)
        del _restore[path]


def _on_signal(signum, _frame) -> None:
    _restore_all()
    sys.exit(2)


def run_one(entry: dict) -> tuple[str, str]:
    """Return (verdict, detail). verdict in {"caught", "survived", "error"}."""
    path = ROOT / entry["file"]
    original = path.read_bytes()
    find = entry["find"].encode()
    replace = entry["replace"].encode()
    if find == replace:
        return "error", "find == replace"
    count = original.count(find)
    if count != 1:
        return "error", f"`find` occurs {count} times in {entry['file']} (must be exactly 1)"

    _restore[path] = original
    try:
        # Durable record first: if the host dies while the mutation is in the
        # tree, the next run restores it from here.
        journal_begin(JOURNAL_DIR, ROOT, path, original, entry["id"])
        path.write_bytes(original.replace(find, replace))
        now = time.time() + 1
        os.utime(path, (now, now))
        env = dict(os.environ)
        env.pop("RUSTFLAGS", None)
        # The property tests fail on purpose here. Do not let proptest write
        # a regressions file into the tree for a failure we caused.
        env["PROPTEST_DISABLE_FAILURE_PERSISTENCE"] = "true"
        proc = subprocess.run(
            CARGO_TEST + entry["filter"].split(),
            cwd=ROOT, env=env, capture_output=True, text=True,
        )
        out = proc.stdout + proc.stderr
    finally:
        _restore_all()
        journal_end(JOURNAL_DIR)

    expect = entry.get("expect", "tests_fail")
    if expect == "compile_error":
        if proc.returncode != 0 and "error[" in out and "test result:" not in out:
            return "caught", "does not compile"
        return "survived", "expected a compile error, but the crate built"

    if proc.returncode == 0:
        return "survived", "the test run passed with the defect re-introduced"
    if "test result:" not in out:
        return "error", "the run failed before any test executed (compile error?):\n" + out[-1500:]
    missing = [t for t in entry["must_fail"] if f"{t} ... FAILED" not in out]
    if missing:
        return "survived", "the run failed, but not through the named guard(s): " + ", ".join(missing)
    return "caught", ", ".join(entry["must_fail"])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--check", action="store_true",
                    help="no cargo: every `find` occurs exactly once (no leftover mutation, no rotten anchor)")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--only", default="")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    manifest = json.loads(MANIFEST.read_text())
    entries = manifest["mutations"]
    ids = [e["id"] for e in entries]
    if len(ids) != len(set(ids)):
        print("manifest error: duplicate mutation ids", file=sys.stderr)
        return 2
    if ids[0] != "canary":
        print("manifest error: the first entry must be the canary", file=sys.stderr)
        return 2

    if args.list:
        for e in entries:
            print(f"{e['id']:44s} {e['file']}")
        return 0

    if args.check:
        pending = journal_pending(JOURNAL_DIR)
        if pending is not None:
            print(
                f"verify-pin-credential-gates --check: FAIL -- an interrupted run left mutation "
                f"`{pending['id']}` applied to {pending['file']}; run this tool without --check to restore it",
                file=sys.stderr,
            )
            return 2
        problems = check_manifest(entries, ROOT)
        blind = undetectable(entries, ROOT)
        if problems or blind:
            print("verify-pin-credential-gates --check: FAIL", file=sys.stderr)
            for line in problems:
                print(f"- {line}", file=sys.stderr)
            for mutation_id in blind:
                print(f"- {mutation_id}: this check could not see the mutation if it were left applied; "
                      f"reshape the entry (see `undetectable`)", file=sys.stderr)
            print(CHECK_HELP, file=sys.stderr)
            return 2
        print(f"verify-pin-credential-gates --check: OK -- {len(entries)} mutations apply cleanly, "
              f"none is applied, and each would be seen here if it were")
        return 0

    only = {x for x in args.only.split(",") if x}
    unknown = only - set(ids)
    if unknown:
        print(f"unknown mutation id(s): {sorted(unknown)}", file=sys.stderr)
        return 2

    try:
        recovered = journal_recover(JOURNAL_DIR, ROOT)
    except RuntimeError as err:
        print(f"FATAL: {err}; inspect the file and restore it by hand (git diff)", file=sys.stderr)
        return 2
    if recovered:
        print(recovered, flush=True)
    # All-or-nothing: do not start mutating a tree the manifest does not fit.
    problems = check_manifest(entries, ROOT)
    if problems:
        print("manifest error: the tree does not match the manifest; nothing was run", file=sys.stderr)
        for line in problems:
            print(f"- {line}", file=sys.stderr)
        return 2

    atexit.register(_restore_all)
    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    survivors, errors, caught = [], [], 0
    for e in entries:
        if only and e["id"] not in only and e["id"] != "canary":
            continue
        verdict, detail = run_one(e)
        print(f"{verdict.upper():8s} {e['id']}: {detail}", flush=True)
        if verdict == "caught":
            caught += 1
        elif verdict == "survived":
            if e["id"] == "canary":
                print("canary survived: the mutation machinery is broken; all results void", file=sys.stderr)
                return 2
            survivors.append(e["id"])
        else:
            errors.append(e["id"])
            if e["id"] == "canary":
                return 2

    print(f"\nverify-pin-credential-gates: {caught} caught, {len(survivors)} survived, {len(errors)} error(s)")
    if errors:
        return 2
    return 1 if survivors else 0


if __name__ == "__main__":
    sys.exit(main())
