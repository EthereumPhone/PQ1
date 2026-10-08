#!/usr/bin/env python3
"""Fail-closed comparison of a complete Charon/Aeneas regeneration.

The extract-* targets historically compared only the transformed `Funs.lean`.
That allowed a generated `Types.lean` or external-template interface to drift
while `make verify-extraction-regen` stayed green. This checker consumes one
fresh, clean Aeneas output directory and enforces:

* the exact expected raw `*.lean` filename set (no omitted/unexpected module);
* byte-for-byte equality for generated Funs/Types after the target's existing
  deterministic Funs transform;
* attribute-to-declaration binding and Lean-elaborated type equality between
  generated `*External_Template.lean` files and their deliberately
  hand-completed committed `*External.lean` counterparts.

FormatDecimal's generated `Types.lean` is intentionally deduplicated into the
canonical U256Mul Types module, so that one raw file is compared there.
"""
from __future__ import annotations

import collections
import hashlib
import json
import os
import pwd
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from check_extraction_freshness import max_attempts_consistency_errors

VERIF_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[3]
REGISTRY = VERIF_DIR / "extraction_registry.json"
ATTR_RE = re.compile(
    r'(?m)^[ \t]*@\[\s*(rust_(?:fun|const|type))\s+"((?:\\.|[^"\\])*)"\s*\]',
    re.DOTALL,
)
IMPORT_RE = re.compile(r"(?m)^[ \t]*import[ \t]+(Extracted(?:\.[A-Za-z0-9_']+)+)[ \t]*$")
DECL_RE = re.compile(
    r"(?m)^[ \t]*(?:axiom|structure|inductive|opaque|abbrev|"
    r"(?:noncomputable[ \t]+)?def)"
    r"[ \t\r\n]+([A-Za-z0-9_'.]+)"
)
DECL_AFTER_ATTR_RE = re.compile(
    r"^(?:(?:[ \t\r\n]+)|(?:--[^\r\n]*(?:\r?\n|$))|(?:/-.*?-/))*"
    r"(?:axiom|structure|inductive|opaque|abbrev|"
    r"(?:noncomputable[ \t]+)?def)"
    r"[ \t\r\n]+([A-Za-z0-9_'.]+)",
    re.DOTALL,
)
AXIOM_NAME_RE = re.compile(
    r"(?m)^([ \t]*axiom[ \t\r\n]+)([A-Za-z0-9_'.]+)"
)
IMPORT_LINE_RE = re.compile(r"(?m)^[ \t]*import[^\r\n]*(?:\r?\n|$)")

# Opaque functions are emitted as un-attributed template axioms by Aeneas, but
# these committed implementations deliberately carry rust_fun bindings. Keep
# that asymmetry explicit and checker-owned; every other local extra is drift.
ALLOWED_EXTRA_LOCAL_BINDINGS = {
    ("extract-hash-fns", "FunsExternal.lean"): collections.Counter(
        {
            (
                "rust_fun",
                "sphincs_c10::hash::sha256_bytes",
                "hash.sha256_bytes",
            ): 1,
            (
                "rust_fun",
                "sphincs_c10::hash::sha256_parts",
                "hash.sha256_parts",
            ): 1,
        }
    ),
    ("extract-tx-merkle", "FunsExternal.lean"): collections.Counter(
        {
            (
                "rust_fun",
                "pqsigner_tx::erc20::merkle::leaf_hash",
                "erc20.merkle.leaf_hash",
            ): 1,
            (
                "rust_fun",
                "pqsigner_tx::erc20::merkle::node_hash",
                "erc20.merkle.node_hash",
            ): 1,
        }
    ),
}


def external_attributes(text: str) -> collections.Counter[tuple[str, str]]:
    return collections.Counter(ATTR_RE.findall(text))


def declaration_names(text: str) -> collections.Counter[str]:
    return collections.Counter(DECL_RE.findall(text))


def attributed_declarations(
    text: str,
) -> tuple[collections.Counter[tuple[str, str, str]], list[str]]:
    """Bind each rust_* attribute to the declaration immediately following it."""
    records: collections.Counter[tuple[str, str, str]] = collections.Counter()
    errors: list[str] = []
    for attr in ATTR_RE.finditer(text):
        declaration = DECL_AFTER_ATTR_RE.match(text[attr.end():])
        kind, rust_name = attr.groups()
        if declaration is None:
            errors.append(
                f'attribute {kind} "{rust_name}" is not immediately attached '
                "to a supported declaration"
            )
            continue
        records[(kind, rust_name, declaration.group(1))] += 1
    return records, errors


def extracted_import_path(module: str) -> Path:
    return VERIF_DIR / "extracted" / (module.replace(".", "/") + ".lean")


def imported_text_closure(start: Path) -> list[str]:
    """Read a committed external module and its recursive `Extracted.*` imports."""
    pending = [start]
    seen: set[Path] = set()
    texts: list[str] = []
    while pending:
        path = pending.pop()
        if path in seen:
            continue
        seen.add(path)
        text = path.read_text(encoding="utf-8")
        texts.append(text)
        for module in IMPORT_RE.findall(text):
            imported = extracted_import_path(module)
            if imported.is_file():
                pending.append(imported)
    return texts


def compare_exact(label: str, committed: Path, regenerated: Path) -> list[str]:
    if not committed.is_file():
        return [f"{label}: committed file missing: {committed}"]
    if not regenerated.is_file():
        return [f"{label}: regenerated file missing: {regenerated}"]
    if committed.read_bytes() != regenerated.read_bytes():
        try:
            committed_label = committed.relative_to(REPO_ROOT)
        except ValueError:
            committed_label = committed
        return [
            f"{label}: regenerated content differs: "
            f"{committed_label} vs {regenerated}"
        ]
    return []


def _pinned_lake() -> str:
    """The elan shim under the password-database home — never via PATH."""
    lake = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".elan" / "bin" / "lake"
    if not lake.is_file():
        raise SystemExit(f"ERROR: lake not found at the pinned elan location ({lake}).")
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


def run_lean_source(source: str) -> subprocess.CompletedProcess[str]:
    """Elaborate an ephemeral conformance module in the extracted Lean project.

    Resolves lake through the pinned elan shim with a forced elan/home root —
    a PATH- or ELAN_HOME-planted `lake` must not author the "regenerated"
    interface this checker compares against the committed one (same class as
    the closed wave-2/wave-3 ledger-dump findings)."""
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        suffix=".lean",
        prefix="pq-extraction-interface-",
    ) as module:
        module.write(source)
        module.flush()
        return subprocess.run(
            [_pinned_lake(), "env", "lean", module.name],
            cwd=VERIF_DIR / "extracted",
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
            env=_pinned_tool_env(),
        )


def lean_signature_errors(
    label: str, committed: Path, template_text: str
) -> list[str]:
    """Require generated axiom types to equal committed declaration types.

    The regenerated declarations are renamed under a private prefix so the
    committed module and exact template signatures can be elaborated together.
    Each pair must expose the same universe-parameter arity, then both types are
    instantiated with the same rigid universe parameters before
    `Lean.Meta.isDefEq`.  Independent universe metavariables are unsound here:
    Lean can solve the polymorphic side to a monomorphic universe.  Do not encode
    this as a homogeneous term equality either: the elaborator may insert a
    coercion into one side and accept declarations whose types are not
    definitionally equal.
    """
    declaration_names_in_order = AXIOM_NAME_RE.findall(template_text)
    names = [name for _, name in declaration_names_in_order]
    if not names:
        return []
    try:
        relative = committed.relative_to(VERIF_DIR / "extracted").with_suffix("")
    except ValueError:
        return [f"{label}: committed external module is outside extracted project"]
    module_name = ".".join(relative.parts)

    transformed = IMPORT_LINE_RE.sub("", template_text)
    transformed = ATTR_RE.sub("", transformed)
    transformed = AXIOM_NAME_RE.sub(
        lambda match: (
            f"{match.group(1)}ExtractionRegenExpected.{match.group(2)}"
        ),
        transformed,
    )
    checks = "\n\n".join(
        "run_meta do\n"
        "  let expectedInfo ← Lean.getConstInfo "
        f"``ExtractionRegenExpected.{name}\n"
        f"  let actualInfo ← Lean.getConstInfo ``{name}\n"
        "  unless expectedInfo.levelParams.length == "
        "actualInfo.levelParams.length do\n"
        f'    throwError "extraction signature universe-parameter mismatch: {name}"\n'
        "  let levels := expectedInfo.levelParams.map Lean.mkLevelParam\n"
        "  let expectedType := expectedInfo.instantiateTypeLevelParams levels\n"
        "  let actualType := actualInfo.instantiateTypeLevelParams levels\n"
        "  unless ← Lean.Meta.isDefEq expectedType actualType do\n"
        f'    throwError "extraction signature type mismatch: {name}"'
        for name in names
    )
    source = (
        f"import {module_name}\n"
        "import Lean.Meta.Basic\n"
        f"{transformed}\n{checks}\n"
    )
    try:
        result = run_lean_source(source)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [f"{label}: Lean signature conformance check could not run: {exc}"]
    if result.returncode == 0:
        return []
    output = (result.stdout + "\n" + result.stderr).strip().splitlines()
    detail = "\n".join(output[-12:])
    return [
        f"{label}: regenerated external declaration type differs from committed "
        f"interface (Lean exit {result.returncode})"
        + (f":\n{detail}" if detail else "")
    ]


def raw_output_errors(
    output_dir: Path, pins: dict[str, str], ignored: set[str]
) -> list[str]:
    actual = {
        path.name for path in output_dir.glob("*.lean") if path.name not in ignored
    }
    expected = set(pins)
    errors = []
    if actual != expected:
        errors.append(
            "raw generated module inventory drift; "
            f"missing={sorted(expected - actual)}, "
            f"unexpected={sorted(actual - expected)}"
        )
    for name in sorted(actual & expected):
        digest = hashlib.sha256((output_dir / name).read_bytes()).hexdigest()
        if digest != pins[name]:
            errors.append(
                f"raw generated file {name} hash drift; "
                f"expected {pins[name]}, got {digest}"
            )
    return errors


def compare_external_interface(
    label: str,
    committed: Path,
    template: Path,
    *,
    check_lean_types: bool = True,
    allowed_extra_local_bindings: (
        collections.Counter[tuple[str, str, str]] | None
    ) = None,
) -> list[str]:
    if not committed.is_file() or not template.is_file():
        return [
            f"{label}: external interface file missing "
            f"(committed={committed.is_file()}, template={template.is_file()})"
        ]
    template_text = template.read_text(encoding="utf-8")
    closure = imported_text_closure(committed)
    expected_bindings, expected_binding_errors = attributed_declarations(
        template_text
    )
    actual_bindings: collections.Counter[tuple[str, str, str]] = (
        collections.Counter()
    )
    actual_decls: collections.Counter[str] = collections.Counter()
    for text in closure:
        records, _ = attributed_declarations(text)
        actual_bindings.update(records)
        actual_decls.update(declaration_names(text))
    local_bindings, local_binding_errors = attributed_declarations(closure[0])
    allowed_extra_local_bindings = (
        allowed_extra_local_bindings or collections.Counter()
    )
    expected_decls = declaration_names(template_text)
    missing_bindings = sorted((expected_bindings - actual_bindings).elements())
    duplicate_bindings = sorted(
        record
        for record, expected_count in expected_bindings.items()
        if actual_bindings[record] != expected_count
        and actual_bindings[record] > expected_count
    )
    unexpected_local_bindings = sorted(
        (
            local_bindings
            - expected_bindings
            - allowed_extra_local_bindings
        ).elements()
    )
    missing_allowed_local_bindings = sorted(
        (allowed_extra_local_bindings - local_bindings).elements()
    )
    missing_decls = sorted((expected_decls - actual_decls).elements())
    errors = [
        f"{label}: regenerated template {message}"
        for message in expected_binding_errors
    ]
    errors.extend(
        f"{label}: committed external module {message}"
        for message in local_binding_errors
    )
    if (
        missing_bindings
        or duplicate_bindings
        or unexpected_local_bindings
        or missing_allowed_local_bindings
        or missing_decls
    ):
        errors.append(
            f"{label}: hand-completed/imported external interface does not "
            "match the regenerated template; "
            f"missing_bindings={missing_bindings}, "
            f"duplicate_bindings={duplicate_bindings}, "
            f"unexpected_local_bindings={unexpected_local_bindings}, "
            f"missing_checker_owned_local_bindings="
            f"{missing_allowed_local_bindings}, "
            f"missing_declarations={missing_decls}"
        )
    if check_lean_types:
        errors.extend(lean_signature_errors(label, committed, template_text))
    return errors


def target_specific_errors(
    target: str,
    *,
    proto_text: str | None = None,
    pinstate_lean_text: str | None = None,
) -> list[str]:
    """Checks required by a hand-completed target beyond generator signatures."""
    if target != "extract-pinstate":
        return []
    return max_attempts_consistency_errors(proto_text, pinstate_lean_text)


def check_target(target: str, output_dir: Path, transformed_funs: Path | None) -> list[str]:
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    entry = next((e for e in registry["entries"] if e["target"] == target), None)
    if entry is None:
        return [f"unknown extraction target {target!r}"]
    if not output_dir.is_dir():
        return [f"Aeneas output directory missing: {output_dir}"]

    errors: list[str] = []
    for rel in entry["generated_lean"]:
        committed = REPO_ROOT / rel
        name = committed.name
        if name == "FunsExternal.lean":
            raw_name = "FunsExternal_Template.lean"
            errors.extend(
                compare_external_interface(
                    f"{target} FunsExternal",
                    committed,
                    output_dir / raw_name,
                    allowed_extra_local_bindings=(
                        ALLOWED_EXTRA_LOCAL_BINDINGS.get(
                            (target, name), collections.Counter()
                        )
                    ),
                )
            )
        elif name == "TypesExternal.lean":
            raw_name = "TypesExternal_Template.lean"
            errors.extend(
                compare_external_interface(
                    f"{target} TypesExternal",
                    committed,
                    output_dir / raw_name,
                    allowed_extra_local_bindings=(
                        ALLOWED_EXTRA_LOCAL_BINDINGS.get(
                            (target, name), collections.Counter()
                        )
                    ),
                )
            )
        elif name == "Funs.lean":
            candidate = transformed_funs or (output_dir / name)
            errors.extend(compare_exact(f"{target} Funs", committed, candidate))
        else:
            fixed_candidate = output_dir / name.replace(".lean", ".fixed.lean")
            candidate = fixed_candidate if fixed_candidate.is_file() else output_dir / name
            errors.extend(
                compare_exact(f"{target} {name}", committed, candidate)
            )

    # FormatDecimal deliberately shares the byte-identical generated U256 type
    # with U256Mul instead of committing a duplicate declaration.
    if target == "extract-format-decimal":
        errors.extend(
            compare_exact(
                f"{target} deduplicated Types",
                VERIF_DIR / "extracted/Extracted/U256Mul/Types.lean",
                output_dir / "Types.lean",
            )
        )

    errors.extend(target_specific_errors(target))

    ignored = {
        path.name for path in output_dir.glob("*.fixed.lean")
    }
    if transformed_funs is not None:
        ignored.add(transformed_funs.name)
    errors.extend(
        f"{target}: {message}"
        for message in raw_output_errors(
            output_dir, entry["raw_generated_sha256"], ignored
        )
    )
    return errors


def self_test() -> int:
    ok = True
    with tempfile.TemporaryDirectory(prefix="pq-extraction-output-selftest-") as tmp:
        root = Path(tmp)
        committed = root / "committed.lean"
        regenerated = root / "regenerated.lean"
        committed.write_text("def value := 1\n", encoding="utf-8")
        regenerated.write_text("def value := 1\n", encoding="utf-8")
        if compare_exact("clean", committed, regenerated):
            print("FAIL: exact generated-file clean control was rejected")
            ok = False
        regenerated.write_text("def value := 2\n", encoding="utf-8")
        if compare_exact("mutant", committed, regenerated):
            print("  ok: generated Types/content drift is CAUGHT")
        else:
            print("FAIL: generated Types/content drift escaped")
            ok = False

        template = root / "FunsExternal_Template.lean"
        external = root / "FunsExternal.lean"
        template.write_text(
            '@[rust_const "crate::LIMIT"]\naxiom crate.LIMIT : Nat\n',
            encoding="utf-8",
        )
        external.write_text(
            '@[rust_const "crate::LIMIT"]\ndef crate.LIMIT : Nat := 10\n',
            encoding="utf-8",
        )
        if compare_external_interface(
            "clean external", external, template, check_lean_types=False
        ):
            print("FAIL: matching hand-completed external interface was rejected")
            ok = False
        external.write_text("def crate.LIMIT : Nat := 10\n", encoding="utf-8")
        if compare_external_interface(
            "mutant external", external, template, check_lean_types=False
        ):
            print("  ok: dropped generated external-template identity is CAUGHT")
        else:
            print("FAIL: dropped external-template identity escaped")
            ok = False

        template.write_text(
            '@[rust_const "crate::LIMIT"]\naxiom crate.LIMIT : Nat\n'
            '@[rust_fun "crate::read_limit"]\n'
            "axiom crate.read_limit : Nat → Nat\n",
            encoding="utf-8",
        )
        external.write_text(
            '@[rust_const "crate::LIMIT"]\n'
            "def crate.read_limit : Nat → Nat := fun value => value\n"
            '@[rust_fun "crate::read_limit"]\n'
            "def crate.LIMIT : Nat := 10\n",
            encoding="utf-8",
        )
        if compare_external_interface(
            "swapped binding", external, template, check_lean_types=False
        ):
            print("  ok: attribute-to-declaration swap is CAUGHT")
        else:
            print("FAIL: swapped external attribute bindings escaped")
            ok = False

        external.write_text(
            '@[rust_const "crate::LIMIT"]\ndef crate.LIMIT : Nat := 10\n'
            '@[rust_fun "crate::read_limit"]\n'
            "def crate.read_limit : Nat → Nat := fun value => value\n"
            '@[rust_const "crate::UNEXPECTED"]\n'
            "def crate.UNEXPECTED : Nat := 0\n",
            encoding="utf-8",
        )
        if compare_external_interface(
            "extra binding", external, template, check_lean_types=False
        ):
            print("  ok: unexpected local external binding is CAUGHT")
        else:
            print("FAIL: unexpected local external binding escaped")
            ok = False

        raw = root / "raw"
        raw.mkdir()
        (raw / "Funs.lean").write_text("def f := 1\n", encoding="utf-8")
        (raw / "Types.lean").write_text("def T := Nat\n", encoding="utf-8")
        pins = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in raw.glob("*.lean")
        }
        if raw_output_errors(raw, pins, set()):
            print("FAIL: clean raw-output hash/inventory control was rejected")
            ok = False
        (raw / "Unexpected.lean").write_text("def decoy := 0\n", encoding="utf-8")
        if raw_output_errors(raw, pins, set()):
            print("  ok: unexpected generated module inventory is CAUGHT")
        else:
            print("FAIL: unexpected generated module escaped")
            ok = False
        (raw / "Unexpected.lean").unlink()
        (raw / "Types.lean").unlink()
        if raw_output_errors(raw, pins, set()):
            print("  ok: missing generated Types module is CAUGHT")
        else:
            print("FAIL: missing generated Types module escaped")
            ok = False
        (raw / "Types.lean").write_text("def T := Bool\n", encoding="utf-8")
        if raw_output_errors(raw, pins, set()):
            print("  ok: raw generated Types/template signature drift is CAUGHT")
        else:
            print("FAIL: raw generated content/hash drift escaped")
            ok = False
    print("check_extraction_regen_output --self-test PASS" if ok else
          "check_extraction_regen_output --self-test FAILED")
    return 0 if ok else 1


def self_test_lean() -> int:
    """Toolchain-backed controls used only by the real regeneration gate."""
    ok = True
    committed_pinstate = (
        VERIF_DIR / "extracted/Extracted/PinState/Funs.lean"
    )
    matching = lean_signature_errors(
        "matching type control",
        committed_pinstate,
        "import Aeneas\n"
        "open Aeneas Aeneas.Std Result\n"
        "axiom pqsigner_domain.PER_SLOT_CT_LEN : Result Std.Usize\n",
    )
    if not matching:
        print("  ok: matching external declaration signature is ACCEPTED")
    else:
        print(
            "FAIL: matching external declaration signature was rejected: "
            f"{matching}"
        )
        ok = False

    alpha_equivalent = lean_signature_errors(
        "universe alpha-equivalence control",
        committed_pinstate,
        "axiom id : {α : Sort uFresh} → α → α\n",
    )
    if not alpha_equivalent:
        print("  ok: alpha-equivalent polymorphic signature is ACCEPTED")
    else:
        print(
            "FAIL: alpha-equivalent polymorphic signature was rejected: "
            f"{alpha_equivalent}"
        )
        ok = False

    monomorphic_drift = lean_signature_errors(
        "universe specialization control",
        committed_pinstate,
        "axiom id : {α : Type} → α → α\n",
    )
    if monomorphic_drift:
        print("  ok: polymorphic-to-monomorphic universe drift is CAUGHT")
    else:
        print("FAIL: universe-specialized external declaration escaped")
        ok = False

    mismatched = lean_signature_errors(
        "plain type-drift control",
        committed_pinstate,
        "import Aeneas\n"
        "open Aeneas Aeneas.Std Result\n"
        "axiom pqsigner_domain.PER_SLOT_CT_LEN : Result Bool\n",
    )
    if mismatched:
        print("  ok: same-name external declaration type drift is CAUGHT")
    else:
        print("FAIL: wrong external declaration type escaped Lean conformance")
        ok = False

    # A homogeneous equality silently coerces the committed `Result Std.Usize`
    # into `Result Nat` in this pinned Lean/Aeneas environment.  The production
    # Meta-level type comparison must reject that exact formerly-green shape.
    coercible_mismatch = lean_signature_errors(
        "coercible type-drift control",
        committed_pinstate,
        "import Aeneas\n"
        "open Aeneas Aeneas.Std Result\n"
        "axiom pqsigner_domain.PER_SLOT_CT_LEN : Result Nat\n",
    )
    if coercible_mismatch:
        print("  ok: coercible external declaration type drift is CAUGHT")
    else:
        print("FAIL: coercible external declaration type drift escaped")
        ok = False

    matching_pin = target_specific_errors(
        "extract-pinstate",
        proto_text="pub const MAX_ATTEMPTS: u8 = 10;\n",
        pinstate_lean_text=(
            "def pqsigner_proto.MAX_ATTEMPTS : Result Std.U8 := ok 10#u8\n"
        ),
    )
    if not matching_pin:
        print("  ok: matching PinState MAX_ATTEMPTS is ACCEPTED")
    else:
        print(f"FAIL: matching PinState MAX_ATTEMPTS rejected: {matching_pin}")
        ok = False

    stale_pin = target_specific_errors(
        "extract-pinstate",
        proto_text="pub const MAX_ATTEMPTS: u8 = 10;\n",
        pinstate_lean_text=(
            "def pqsigner_proto.MAX_ATTEMPTS : Result Std.U8 := ok 11#u8\n"
        ),
    )
    if stale_pin:
        print("  ok: stale hand-completed PinState MAX_ATTEMPTS is CAUGHT")
    else:
        print("FAIL: stale hand-completed PinState MAX_ATTEMPTS escaped regen")
        ok = False

    print("check_extraction_regen_output --self-test-lean PASS" if ok else
          "check_extraction_regen_output --self-test-lean FAILED")
    return 0 if ok else 1


def main() -> int:
    args = sys.argv[1:]
    if args == ["--self-test"]:
        return self_test()
    if args == ["--self-test-lean"]:
        return self_test_lean()
    if len(args) not in (2, 3):
        print(
            "usage: check_extraction_regen_output.py "
            "<extract-target> <aeneas-output-dir> [transformed-Funs.lean]",
            file=sys.stderr,
        )
        return 2
    target = args[0]
    output_dir = Path(args[1]).resolve()
    transformed = Path(args[2]).resolve() if len(args) == 3 else None
    errors = check_target(target, output_dir, transformed)
    if errors:
        print(f"FAIL: incomplete/drifted Aeneas output for {target}:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print(f"OK: {target} complete Aeneas output matches committed generated surface")
    return 0


if __name__ == "__main__":
    sys.exit(main())
