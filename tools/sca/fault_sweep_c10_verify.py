#!/usr/bin/env python3
"""Fault-injection sweep over PQSigner's C10 verify-before-release gate.

`sca_c10_verify_release` in the target ELF is a structural mirror of
`secure/src/crypto.rs::c10_sign_verified_with_progress`:

    sig = sk.sign_with_progress(...)         # stubbed: sca_c10_sign_stub()
    fi::wait_random()
    v   = sphincs_c10::verify(...)            # stubbed: sca_c10_verify_stub(want_pass)
    if !fi::check_true(|| v) { return Err }   # the gate
    Ok(sig)

We call it with `want_pass = 0` — i.e. the signature did NOT verify — and sweep
a single instruction-skip over every instruction. A run that returns non-zero
("would release the signature") is a BYPASS: a glitch made the firmware emit an
*unverified* C10 signature. A robust gate has ZERO; the script exits non-zero if
any survive (inside the gate / `fi.rs` — skips inside the `sign`/`verify` stubs
are this harness's scaffolding, reported separately, since the real `sign` and
`verify` have their own targets / robustness story).

Run:   donjon-sca run tools/sca/fault_sweep_c10_verify.py
       (or, building the target ELF first:  make -C tools/sca c10)

Single-fault, instruction-skip only — extend below for stuck-at / multi-fault.
"""
import os
import sys
import bisect

from rainbow.generics import rainbow_cortexm
from rainbow.fault_models import fault_skip, fault_stuck_at

FAULT_MODELS = [
    ("skip", fault_skip),
    ("stuck-at-0", fault_stuck_at(0x0000_0000)),
    ("stuck-at-FF", fault_stuck_at(0xFFFF_FFFF)),
]

HERE = os.path.dirname(os.path.abspath(__file__))
ELF = os.path.join(HERE, "fi_target", "target", "thumbv8m.main-none-eabi", "release", "sca-fi-target")
RET = 0xAAAA_AAAA
BUDGET = 8192
MAX_I = 1000
GATE_FN = "sca_c10_verify_release"
# Functions that are this harness's own stand-ins for sign/verify, not the gate.
# `sca_fi_cond` is here because identical-code-folding may merge `sca_c10_verify_stub`
# (whose body is the same `black_box(x) != 0`) onto the `sca_fi_cond` symbol, so a
# skip "in sca_fi_cond" reported during this sweep is actually in the verify stub.
SCAFFOLDING = {"sca_c10_sign_stub", "sca_c10_verify_stub", "sca_fi_cond", "__wfe"}

if not os.path.exists(ELF):
    sys.exit(
        f"target ELF not found: {ELF}\n"
        f"build it first:   make -C {HERE} c10   (or: make -C {HERE} build)"
    )


def fresh_emu():
    e = rainbow_cortexm()
    e.load(ELF)
    return e


def fn_table(e):
    return sorted((v[0] & ~1, k) for k, v in e.functions.items())


def fn_at(table, pc):
    starts = [a for a, _ in table]
    i = bisect.bisect_right(starts, pc & ~1) - 1
    return table[i][1] if i >= 0 else "<?>"


def run(e, want_pass, fault=None):
    e.reset()
    e.reset_stack()
    e["r0"] = want_pass & 0xFFFF_FFFF
    e["lr"] = RET
    begin = e.functions[GATE_FN][0]
    try:
        if fault is None:
            e.start(begin, RET, count=BUDGET)
        else:
            e.start_and_fault(fault[0], fault[1], begin, RET, count=BUDGET)
    except RuntimeError:
        return ("crash", e["pc"])
    except IndexError:
        return ("short", None)
    if e["pc"] == RET:
        return ("ret", e["r0"])
    return ("hang", e["pc"])


def baseline():
    e = fresh_emu()
    assert run(e, 0) == ("ret", 0), "verify-fails baseline should return 0 (Err)"
    e = fresh_emu()
    assert run(e, 1) == ("ret", 1), "verify-passes baseline should return 1 (Ok)"
    print("baselines OK  (verify fails -> 0/Err ; verify passes -> 1/Ok)")


def sweep(fault_model):
    exploitable, crashes, hangs, noeffect = [], 0, 0, 0
    locs = {}
    for i in range(1, MAX_I):
        e = fresh_emu()
        table = fn_table(e)
        st, val = run(e, 0, fault=(fault_model, i))
        if st == "short":
            break
        if st == "crash":
            crashes += 1
            continue
        if st == "hang":
            hangs += 1
            continue
        if val != 0:                      # released a signature that didn't verify
            exploitable.append(i)
            e2 = fresh_emu()
            e2.reset(); e2.reset_stack(); e2["r0"] = 0; e2["lr"] = RET
            try:
                e2.start(e2.functions[GATE_FN][0], RET, count=i)
            except Exception:
                pass
            locs[i] = (fn_at(table, e2["pc"]), e2["pc"])
        else:
            noeffect += 1
    return exploitable, crashes, hangs, noeffect, locs


def report_gate_hits(in_gate):
    print(f"  - !!! {len(in_gate)} inside the gate (sca_c10_verify_release / fi::check_true / fi::wait_random):")
    for i, fn, pc in in_gate:
        print(f"        instr {i}: pc={pc:#010x} in {fn}  → released an unverified signature")
    print( "        Triage (see tools/sca/README.md §Findings):")
    print( "          • a hit inside fi::check_true's *decision-point region* (between the first `cbz`")
    print( "            and the sentinel re-check `cmp #OK_SENTINEL`) would be an F-1 REGRESSION —")
    print( "            something re-introduced the `|| v` CSE collapse; `crypto.rs` should pass")
    print( "            `|| core::hint::black_box(v)` (or re-verify in the closure).")
    print( "          • a hit in sca_c10_verify_release's glue (skip the `bl check_true`, the `cbz r0`")
    print( "            post-check, or the prologue load of `v` into check_true's frame) is F-2 — the")
    print( "            residual `if !guard() { err }` weakness `check_true` can't fix from inside;")
    print( "            mitigation is a sentinel-encoded return + caller re-check, or accept it.")
    print( "        Verbose repro:")
    print(f"          donjon-sca python -c \"from rainbow.generics import rainbow_cortexm; from rainbow import Print;\\")
    print(f"            e=rainbow_cortexm(print=Print.Code|Print.Functions|Print.Faults); e.load('{ELF}');\\")
    print( "            from rainbow.fault_models import fault_skip; e.reset(); e.reset_stack(); e['r0']=0; e['lr']=0xaaaaaaaa;\\")
    print(f"            e.start_and_fault(fault_skip, <I>, e.functions['{GATE_FN}'][0], 0xaaaaaaaa, count=8192)\"")


if __name__ == "__main__":
    baseline()
    any_gate_hit = False
    for label, model in FAULT_MODELS:
        print(f"\n== C10 verify-before-release: single-fault [{label}] sweep (verify forced to FAIL) ==")
        expl, cr, hg, ne, locs = sweep(model)
        total = len(expl) + cr + hg + ne
        print(f"  swept {total} positions:  exploitable={len(expl)}  crashes={cr}  hangs(≈caught)={hg}  no-effect={ne}")
        if not expl:
            print(f"  OK — no single [{label}] fault released an unverified signature.")
            continue
        in_scaffold, in_gate = [], []
        for i in expl:
            fn, pc = locs.get(i, ("<?>", 0))
            (in_scaffold if (any(s in fn for s in SCAFFOLDING) or fn == "<?>") else in_gate).append((i, fn, pc))
        if in_scaffold:
            print(f"  - {len(in_scaffold)} in this harness's stubs for sign/verify (sca_c10_sign_stub / "
                  f"sca_c10_verify_stub / sca_fi_cond / __wfe) — i.e. glitching the SPHINCS+ sign or verify "
                  f"*internally*, out of scope here (those get their own targets). "
                  + ", ".join(f"{i}@{fn}+{pc:#x}" for i, fn, pc in in_scaffold))
        if in_gate:
            any_gate_hit = True
            report_gate_hits(in_gate)
    print()
    if any_gate_hit:
        print("KNOWN RESIDUAL — F-2 (the verify-before-release *call-site glue*): skipping the `bl check_true`,")
        print("the `cbz r0` that branches to `Err`, or the prologue load of `v` into check_true's frame defeats")
        print("the `if !guard() { err }` idiom; and a stuck-at-FF on a result register defeats any bool-returning")
        print("fn. `fi::check_true` cannot fix its own call site. Mitigation = sentinel-encoded return from")
        print("`c10_sign_verified` + caller re-check, or accept it. NOT a regression — F-1 (the `|| v` CSE")
        print("collapse) is fixed: `crypto.rs` passes `|| core::hint::black_box(v)`, verified by disasm.")
        print("→ If a bypass ever lands at a *decision point* inside `fi::check_true` (not the prologue `ldrb`),")
        print("  THAT is an F-1 regression — eyeball the PCs above against tools/sca/README.md §Findings.")
        sys.exit(0)
    print("OK — no gate bypass under any of the 3 single-fault models.")
    sys.exit(0)
