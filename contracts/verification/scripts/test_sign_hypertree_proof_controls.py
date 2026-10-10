#!/usr/bin/env python3
"""Typed changes to the actual loop and its pure specification must be rejected."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import re
import subprocess
import tempfile
from test_fors_auth_proof_controls import LAKE, ROOT, require_semantic_rejection

FAMILIES = {
    "crypto": (["SignLayerCrypto"], "pureWotsSign", [
        ("wrong-secret", "wotsSignChains seed sk", "wotsSignChains seed seed"),
        ("discard-count", "layer tree leaf, c)", "layer tree leaf, 0#u32)"),
        ("erase-failure", "else .fail .assertionFailure", "else .div"),
    ]),
    "layer": (["SignHypertreeLayer"], "pureSignLayer", [
        ("wrong-offset", "(2336+836*layer.val)", "(2336+835*layer.val)"),
        ("wrong-root-height", "tree 9 0)", "tree 8 0)"),
        ("wrong-wots-layer", "pureWotsSign seed sk (signLayerId layer) tree leaf current",
         "pureWotsSign seed sk 0#u32 tree leaf current"),
    ]),
    "body": (["SignLayerSerializeCaller", "SignHypertreeLayer"], "hypertree.sign_inner_loop3.body", [
        ("wrong-leaf-mask", "lift (idx_tree &&& i2)", "lift (idx_tree &&& 255#u32)"),
        ("wrong-tree-shift", "idx_tree >>> i", "idx_tree >>> 8#usize"),
        ("wrong-signing-seed", "wots.sign_with_shuffle seed sk_seed layer", "wots.sign_with_shuffle seed seed layer"),
    ]),
    "loop": (["SignHypertreeLoop"], "hypertree.sign_inner_loop3", [
        ("skip-first-layer", "(iter, sig, offset, current_node, idx_tree)",
         "({start := 1#u32, «end» := iter.«end»}, sig, offset, current_node, idx_tree)"),
        ("erase-tree-index", "(iter, sig, offset, current_node, idx_tree)",
         "(iter, sig, offset, current_node, 0#u32)"),
        ("reuse-initial-offset", "offset1 current_node1 idx_tree1", "offset current_node1 idx_tree1"),
    ]),
    "caller": (["SignHypertreeCaller"], "signerRootCheck", [
        ("wrong-final-offset", "massert (4008#usize = right_val1)", "massert (4007#usize = right_val1)"),
        ("invert-root-check", "if b\n  then", "if !b\n  then"),
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
    if family in {"body", "loop"}:
        original = (ROOT / "Extracted/SignForest/Funs.lean").read_text()
        start = original.index("def " + target + "\n")
        extra = original[start:original.index("/--", start)]
        if before is not None:
            assert extra.count(before) == 1, (family, before)
            extra = extra.replace(before, after)
        # Loop-body references stay bound to the real unmodified body when
        # mutating only the enclosing loop. Body matcher names follow its clone.
        pattern = re.escape(target) + (r"(?![A-Za-z0-9_.])" if family == "loop" else r"(?![A-Za-z0-9_])")
        extra = re.sub(pattern, target + "_probe", extra)
        bodies = [re.sub(pattern, target + "_probe", b) for b in bodies]
        extra = "namespace sphincs_c10\nopen Aeneas Aeneas.Std Result ControlFlow Error\nnoncomputable section\n" + extra + "\nend\nend sphincs_c10\n"
    elif before is not None:
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
    with tempfile.TemporaryDirectory(prefix="sign-hypertree-controls-") as td:
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
    print(f"OK: two-layer signer proof controls: {len(FAMILIES)} positive baselines; {len(jobs)} typed semantic changes rejected")


if __name__ == "__main__":
    main()
