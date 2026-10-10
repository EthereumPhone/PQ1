#!/usr/bin/env python3
"""Typed nonce, header and whole-signer changes must break their unchanged proofs."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import re
import subprocess
import tempfile
from test_fors_auth_proof_controls import LAKE, ROOT, require_semantic_rejection

FAMILIES = {
    "nonce": (["SignNoncePure"], "pureGrindR", [
        ("discard-optrand", "forsRandomizer sk message opt c", "forsRandomizer sk message none c"),
        ("wrong-public-seed", "forsGrindDigest sk (pad16Pure seed)", "forsGrindDigest sk (pad16Pure root)"),
        ("erase-exhaustion", "else .fail .assertionFailure", "else .div"),
    ]),
    "indices": (["SignHeaderSpec"], "headerForsIndices", [
        ("shift-window", "(j*11)", "(j*11+1)"),
        ("truncate-window", "% 2048", "% 1024"),
    ]),
    "header": (["SignHeaderSpec"], "signerHeaderTail", [
        ("wrong-write-start", "{ start := 0#usize,", "{ start := 1#usize,"),
        ("wrong-last-index", "params.K - 1#usize", "params.K - 2#usize"),
        ("discard-write", "ok (seed, index_mut_back s2,", "ok (seed, sig,"),
    ]),
    "whole": (["SignWholeSpec"], "pureWholeSign", [
        ("wrong-grind-message", "pureGrindR sk msg seed root opt", "pureGrindR sk sk seed root opt"),
        ("wrong-forest-secret", "forsSignerSecrets s sk ht indices", "forsSignerSecrets s s ht indices"),
        ("wrong-forest-path", "forsSignerPaths s sk ht indices", "forsSignerPaths s sk 0#u32 indices"),
        ("skip-forest-write", "(serializedForest (serializedNonce r) (forsSignerSecrets s sk ht indices)\n      (forsSignerPaths s sk ht indices))", "(serializedNonce r)"),
    ]),
}
DECL = re.compile(r"^(?:private |noncomputable )?(def|abbrev|theorem) ([A-Za-z0-9_.]+)\b", re.M)


def parts(source):
    start = source.index("namespace Extracted.Equiv") + len("namespace Extracted.Equiv")
    body = source[start:].rsplit("end Extracted.Equiv", 1)[0].rstrip()
    assert body.endswith("end")
    return source[:start-len("namespace Extracted.Equiv")], body[:-3].rstrip()


def fixture(family, before=None, after=None):
    modules, target, _ = FAMILIES[family]
    inputs = [parts((ROOT / "Extracted" / (m + ".lean")).read_text()) for m in modules]
    imports = "\n".join(dict.fromkeys(line for header, _ in inputs for line in header.splitlines()
                                    if line.startswith("import "))) + "\n"
    bodies = [body.replace("noncomputable section", "") for _, body in inputs]
    extra = ""
    if before is not None:
        body = bodies[0]
        spans = list(DECL.finditer(body))
        i = next(i for i, m in enumerate(spans) if m[2] == target)
        a, b = spans[i].start(), spans[i+1].start() if i+1 < len(spans) else len(body)
        declaration = body[a:b]
        assert declaration.count(before) == 1, (family, before)
        bodies[0] = body[:a] + declaration.replace(before, after) + body[b:]
    # Each fixture is independent of every imported theorem with the same
    # source name. Cloned helpers and all their consumers are renamed together.
    names = {m[2] for body in bodies for m in DECL.finditer(body)}
    for name in sorted(names, key=len, reverse=True):
        pattern = re.escape(name) + r"(?![A-Za-z0-9_])"
        bodies = [re.sub(pattern, name + "_probe", b) for b in bodies]
    prefix = imports + "open Aeneas Aeneas.Std Result ControlFlow Error\n" + extra
    full = prefix + "\nnamespace Extracted.Equiv\nnoncomputable section\n" + "\n".join("section\n" + body + "\nend\n" for body in bodies) + "\nend\nend Extracted.Equiv\n"
    definitions = []
    for body in bodies:
        spans = list(DECL.finditer(body))
        for i, m in enumerate(spans):
            if m[1] in {"def", "abbrev"}:
                end = spans[i+1].start() if i+1 < len(spans) else len(body)
                declaration = body[m.start():end].rstrip()
                # A doc comment belongs to the following theorem, not this
                # definition-only typing fixture.
                if declaration.endswith("-/") and "/--" in declaration:
                    declaration = declaration[:declaration.rfind("/--")].rstrip()
                definitions.append(declaration)
    typed = prefix + "\nnamespace Extracted.Equiv\nopen sphincs_c10\nnoncomputable section\nset_option maxRecDepth 8192\n" + "\n".join(definitions) + "\nend\nend Extracted.Equiv\n"
    assert "sorry" not in full and "axiom " not in full
    return full, typed


def main():
    with tempfile.TemporaryDirectory(prefix="sign-whole-controls-") as td:
        def run(name, source):
            path = Path(td) / (name + ".lean")
            path.write_text(source)
            return subprocess.run([str(LAKE), "env", "lean", str(path)], cwd=ROOT,
                                  capture_output=True, text=True, timeout=90)
        for family in FAMILIES:
            result = run(family + "-positive", fixture(family)[0])
            assert result.returncode == 0, (family, result.stdout, result.stderr)
            print("PASS baseline: " + family, flush=True)
        jobs = [(family, name, before, after) for family, (_, _, changes) in FAMILIES.items()
                for name, before, after in changes]
        def negative(job):
            family, name, before, after = job
            proof, definitions = fixture(family, before, after)
            typed = run(family + "-" + name + "-definitions", definitions)
            assert typed.returncode == 0, (family, name, typed.stdout, typed.stderr)
            require_semantic_rejection(run(family + "-" + name, proof), family + "/" + name)
            print("PASS typed rejection: " + family + "/" + name, flush=True)
        with ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(negative, jobs))
    print(f"OK: whole signer proof controls: {len(FAMILIES)} positive baselines; {len(jobs)} typed semantic changes rejected")


if __name__ == "__main__":
    main()
