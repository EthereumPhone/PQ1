#!/usr/bin/env python3
"""Replay the list/UInt64 model and semantic controls; no Rust extraction claim."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time

HERE = Path(__file__).resolve().parent
NAMESPACE = "StreamingHistory"
DECL = re.compile(r"^(structure|def|theorem|#print|end)\b", re.M)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def declarations(source: str) -> list[tuple[str, str]]:
    starts = list(DECL.finditer(source))
    return [(m.group(1), source[m.start():starts[i + 1].start()
            if i + 1 < len(starts) else len(source)].rstrip())
            for i, m in enumerate(starts)]


def definitions(source: str) -> str:
    bodies = [body for kind, body in declarations(source) if kind in {"structure", "def"}]
    require(len(bodies) == 11, "model declaration census changed")
    return "import Std\nnamespace StreamingHistory\n" + "\n\n".join(bodies) + "\n"


def census(log: str) -> dict[str, list[str]]:
    result = {}
    pattern = re.compile(r"^'StreamingHistory\.(\w+)' (?:depends on axioms: \[([^]]*)\]|"
                         r"does not depend on any axioms)$")
    for line in log.splitlines():
        match = pattern.fullmatch(line)
        require(match is not None, "unexpected baseline/census output: " + line[:160])
        name, axioms = match.groups()
        require(name not in result, "duplicate axiom census entry")
        result[name] = [] if not axioms else sorted(axioms.split(", "))
        require(set(result[name]) <= {"propext", "Quot.sound"}, "unapproved axiom closure")
    return result


def check_sources(profile: Path = HERE) -> tuple[dict, str]:
    config = json.loads((profile / "profile.json").read_text())
    require(config["format"] == 1, "unsupported profile")
    require("StreamingHistory.lean" in config["source_sha256"], "missing proof source pin")
    require("lean-toolchain" in config["source_sha256"], "missing toolchain pin")
    for name, digest in config["original_sources"].items():
        require(config["source_sha256"].get("source/" + name) == digest, "source map pin omitted")
    for name, digest in config["source_sha256"].items():
        require(sha(profile / name) == digest, "source identity changed: " + name)
    source = (profile / "StreamingHistory.lean").read_text()
    require(not re.search(r"\b(?:native_decide|ofReduceBool|sorry|admit|unsafe)\b|"
                          r"@\[(?:csimp|extern)\b|^axiom\b", source, re.M),
            "unapproved proof shortcut")
    names = re.findall(r"^theorem (\w+)", source, re.M)
    printed = re.findall(r"^#print axioms (\w+)", source, re.M)
    require(names == printed == list(config["axioms"]), "theorem enrollment changed")
    require(len(names) == len(set(names)) == 39, "theorem census changed")
    signatures = {body.split()[1]: hashlib.sha256(body.split(":= by", 1)[0].encode()).hexdigest()
                  for kind, body in declarations(source) if kind == "theorem"}
    require(signatures == config["signature_sha256"], "theorem signatures changed")
    definitions(source)
    return config, source


def run_lean(lean: Path, out: Path, name: str, source: str) -> tuple[dict, str]:
    directory = out / name
    directory.mkdir()
    path = directory / "StreamingHistory.lean"
    path.write_text(source)
    logpath = directory / "lean.log"
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8", "LEAN_PATH": ""}
    command = ["prlimit", "--cpu=85:90", "--fsize=16777216:16777216", "--", str(lean),
               "-DmaxHeartbeats=1000000", "-o", str(directory / "StreamingHistory.olean"), str(path)]
    start = time.monotonic()
    timed_out = False
    with logpath.open("xb") as log:
        process = subprocess.Popen(command, cwd=directory, env=env, stdout=log,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=90)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGKILL)
            code = process.wait()
    text = logpath.read_text()
    record = {"command": command, "environment": env, "exit": code,
              "seconds": time.monotonic() - start, "timed_out": timed_out,
              "source_sha256": sha(path), "log_sha256": sha(logpath)}
    (directory / "result.json").write_text(json.dumps(record, indent=2) + "\n")
    require(not timed_out and code in {0, 1}, "resource/setup failure in " + name)
    require(not re.search(r"maximum (?:recursion|number of heartbeats)|unknown (?:module|constant)|"
                          r"Unknown constant|unexpected token|failed to synthesize|out of memory|"
                          r"unknown package|object file .* does not exist", text),
            "setup/elaboration/resource failure in " + name)
    return record, text


# Each changed definition is typechecked separately. A concrete counterexample
# also checks that the intended semantic property is false, before proof rejection.
CONTROLS = {
    "wrong-remainder": (
        "let tail := input.drop rem", "let tail := input.take (input.length - rem)",
        "step_conserves",
        "(step [255] (List.range 64)).residual = [0] ∧ "
        "(step [255] (List.range 64)).emitted ++ (step [255] (List.range 64)).residual "
        "≠ [255] ++ List.range 64"),
    "lost-residual": (
        "s.emitted, s.residual, 1 + s.newBlocks", "s.emitted, [], 1 + s.newBlocks",
        "step_conserves",
        "(step [255] (List.range 64)).residual = [] ∧ "
        "(step [255] (List.range 64)).emitted.length = 64 ∧ "
        "(step [255] (List.range 64)).emitted ++ (step [255] (List.range 64)).residual "
        "≠ [255] ++ List.range 64"),
    "omitted-block": (
        "s.residual, 1 + s.newBlocks", "s.residual, s.newBlocks",
        "step_emitted_length",
        "(step [255] (List.range 64)).newBlocks = 0 ∧ "
        "(step [255] (List.range 64)).emitted.length ≠ "
        "64 * (step [255] (List.range 64)).newBlocks"),
    "wrong-scale": (
        "checkedMul 8 total", "checkedMul 7 total", "bitLength_exact",
        "bitLength 0 1 = some 7 ∧ bitLength 0 1 ≠ some 8"),
}


def replay(lean: Path, out: Path) -> dict:
    config, source = check_sources()
    require(sha(lean) == config["lean_binary_sha256"], "Lean executable changed")
    version = subprocess.check_output([str(lean), "--version"], text=True, timeout=30).strip()
    require(version == config["lean_version"], "Lean version changed")
    out.mkdir(parents=True, exist_ok=False)
    records = {}
    record, log = run_lean(lean, out, "baseline", source)
    require(record["exit"] == 0 and census(log) == config["axioms"], "baseline proof/census failed")
    records["baseline"] = record
    equivalent = source.replace("1 + s.newBlocks", "s.newBlocks + 1")
    require(equivalent != source, "identity control absent")
    record, log = run_lean(lean, out, "equivalent-count", equivalent)
    require(record["exit"] == 0 and census(log) == config["axioms"], "equivalent control failed")
    records["equivalent-count"] = record
    for name, (old, new, target, witness) in CONTROLS.items():
        require(source.count(old) == 1, "ambiguous mutation: " + name)
        mutant = source.replace(old, new)
        model = definitions(mutant)
        record, log = run_lean(lean, out, name + "-definitions", model + "end StreamingHistory\n")
        require(record["exit"] == 0 and not log, "ill-typed mutant: " + name)
        records[name + "-definitions"] = record
        witness_source = model + "theorem counterexample : " + witness + " := by decide\n" + \
            "#print axioms counterexample\nend StreamingHistory\n"
        record, log = run_lean(lean, out, name + "-witness", witness_source)
        require(record["exit"] == 0 and census(log) == {"counterexample": []},
                "counterexample not kernel-checked: " + name)
        records[name + "-witness"] = record
        record, log = run_lean(lean, out, name + "-proof", mutant)
        start = mutant[:mutant.index("theorem " + target + " ")].count("\n") + 1
        body = next(b for k, b in declarations(mutant) if k == "theorem" and b.split()[1] == target)
        stop = start + body.count("\n")
        errors = re.findall(r"StreamingHistory\.lean:(\d+):\d+: error", log)
        require(record["exit"] == 1 and errors and start <= int(errors[0]) <= stop,
                "unchanged consumer did not reject at intended theorem: " + name)
        records[name + "-proof"] = record
    require(check_sources()[0] == config and sha(lean) == config["lean_binary_sha256"],
            "inputs changed during replay")
    result = {"accepted": True, "claim": config["claim"], "lean_version": version,
              "source_sha256": config["source_sha256"], "axioms": config["axioms"],
              "results": records, "trust_boundary": config["trust_boundary"]}
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-only", action="store_true")
    parser.add_argument("--lean", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.source_only:
        config, _ = check_sources()
        print(f"Source identity and {len(config['axioms'])} theorem signatures accepted; no proof replay")
    else:
        require(args.lean is not None and args.output is not None, "--lean and --output required")
        result = replay(args.lean.resolve(), args.output.resolve())
        print(f"Accepted {len(result['axioms'])} theorem closures and four semantic controls")


if __name__ == "__main__":
    main()
