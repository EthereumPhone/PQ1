#!/usr/bin/env python3
"""Assert whether the #846 gateway gate is compiled into a secure ELF (#896).

The nested-gate test fixture has two builds: the positive one keeps the
one-at-a-time gate, the negative control (`gateway-gate-off`) removes it. The
negative control is only evidence if the gate is really gone, and the positive
run only means something if the gate is really there, so each Makefile recipe
checks the ELF it is about to flash with this script.

What it inspects: the body of `__acle_se_nsc_is_unlocked`. NOT
`nsc_is_unlocked`, which the CMSE linker turns into a two-instruction veneer
stub (`sg; b.w __acle_se_nsc_is_unlocked`) in both builds. Any
`OUTLINED_FUNCTION_*` helper the body calls is folded in, because opt-level
"z" enables LLVM's MachineOutliner and could move the gate's instructions out
of the body.

Gate present  = an exclusive-access pair (ldaex/ldrex + stlex/strex) AND a
                literal reference to the `GATEWAY_GATE` static's address.
Gate absent   = neither, in a body that was actually found and is non-trivial.

Fails closed: a missing symbol, an empty or tiny extraction, or a missing
`GATEWAY_GATE` symbol is an error, never "absent".

Usage: check_gateway_gate_in_elf.py <secure.elf> present|absent
"""

import re
import subprocess
import sys

BODY_SYM = "__acle_se_nsc_is_unlocked"
MIN_BODY_INSNS = 8
EXCL_LOAD = re.compile(r"\b(ldaex|ldrex)\b", re.I)
EXCL_STORE = re.compile(r"\b(stlex|strex)\b", re.I)
OUTLINED_CALL = re.compile(r"\bbl\s+[0-9a-f]+\s+<(OUTLINED_FUNCTION_[0-9]+)>")
INSN_LINE = re.compile(r"^\s*[0-9a-f]+:\s")


def run(cmd):
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout


def gate_address(elf):
    """Address of the GATEWAY_GATE static, from the demangled symbol table."""
    for line in run(["arm-none-eabi-nm", "-C", elf]).splitlines():
        parts = line.split(maxsplit=2)
        if len(parts) == 3 and parts[2].endswith("nsc::GATEWAY_GATE"):
            return parts[0].lower().lstrip("0") or "0"
    return None


def function_bodies(elf):
    """Map symbol name -> list of disassembly lines for every function."""
    bodies, cur = {}, None
    for line in run(["arm-none-eabi-objdump", "-d", elf]).splitlines():
        m = re.match(r"^[0-9a-f]+ <([^>]+)>:$", line)
        if m:
            cur = m.group(1)
            bodies[cur] = []
        elif cur is not None:
            if line.strip() == "":
                cur = None
            else:
                bodies[cur].append(line)
    return bodies


def main():
    if len(sys.argv) != 3 or sys.argv[2] not in ("present", "absent"):
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    elf, want = sys.argv[1], sys.argv[2]

    addr = gate_address(elf)
    if addr is None:
        print(f"ERROR: no nsc::GATEWAY_GATE symbol in {elf}")
        return 1

    bodies = function_bodies(elf)
    body = bodies.get(BODY_SYM)
    if body is None:
        print(f"ERROR: {BODY_SYM} not found in {elf} (renamed? not a CMSE entry?)")
        return 1
    insns = [l for l in body if INSN_LINE.match(l)]
    if len(insns) < MIN_BODY_INSNS:
        print(f"ERROR: {BODY_SYM} has only {len(insns)} lines; refusing to judge a "
              "trivial or truncated extraction")
        return 1

    # Fold in outlined helpers the body calls (one level is what the outliner emits).
    scanned = list(body)
    helpers = sorted(set(OUTLINED_CALL.findall("\n".join(body))))
    for h in helpers:
        scanned.extend(bodies.get(h, []))
    text = "\n".join(scanned)

    has_excl = bool(EXCL_LOAD.search(text)) and bool(EXCL_STORE.search(text))
    refs_gate = re.search(r"\b0*" + re.escape(addr) + r"\b", text, re.I) is not None
    present = has_excl and refs_gate

    print(f"  {BODY_SYM}: {len(insns)} lines, outlined helpers folded in: "
          f"{helpers or 'none'}")
    print(f"  GATEWAY_GATE @ 0x{addr}: referenced={refs_gate}, "
          f"exclusive-access pair={has_excl}")

    if want == "present":
        if present:
            print("  gate PRESENT: OK")
            return 0
        print("  !! gate NOT present in an image that must carry it")
        return 1
    if not has_excl and not refs_gate:
        print("  gate ABSENT: OK")
        return 0
    print("  !! gate (or part of it) still present in an image that must not carry it")
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"ERROR: could not inspect the ELF ({e}); refusing to judge")
        sys.exit(1)
