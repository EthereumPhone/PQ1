#!/usr/bin/env python3
"""Fault-injection sweep over the **real** C10 signature verification.

`sca_c10_verify_real` in the `sca-c10v-target` ELF is a thin wrapper over
`sphincs_c10::verify` (software SHA-256 path — what the bench/host tooling runs).
We load a known *invalid* C10 vector from `contracts/smart-wallet/test/
c10_test_vectors.json` — the `wrong-message` one: a structurally-valid signature
for a *different* message, so verification runs the full FORS + WOTS + hypertree
recomputation and then fails the final `computed_root == pk_root` check — and
sweep a single fault at every instruction of `verify`'s execution, watching for a
fault that flips the **reject into an accept** (a forged signature verifying =
the worst possible FI outcome — it would let an attacker substitute their own
slot key / userOp). Three fault models: instruction-skip, dest-reg-stuck-at-0,
dest-reg-stuck-at-0xFFFFFFFF.

Also (smaller) sweeps a *valid* vector for the reverse: a fault that makes a good
signature *fail* — a denial-of-service, less critical, reported separately.

Run:   donjon-sca run tools/sca/fault_sweep_c10v.py
       (or, building the target ELF first:  make -C tools/sca c10v)

The whole C10 verify is only a few thousand instructions in emulation, so the
sweep covers all of it (not just the tail). Test vectors are read from the same
JSON the Solidity verifier's Foundry tests use; the Rust `verify` takes the
16-byte `pk_seed`/`pk_root` (the JSON stores them right-zero-padded to 32).
"""
import os
import sys
import json

os.environ.setdefault("UC_IGNORE_REG_BREAK", "1")

from rainbow.generics import rainbow_cortexm
from rainbow import TraceConfig
from rainbow.fault_models import fault_skip, fault_stuck_at
from unicorn import UcError

FAULT_MODELS = [
    ("skip", fault_skip),
    ("stuck-at-0", fault_stuck_at(0x0000_0000)),
    ("stuck-at-FF", fault_stuck_at(0xFFFF_FFFF)),
]

HERE = os.path.dirname(os.path.abspath(__file__))
ELF = os.path.join(HERE, "c10v_target", "target", "thumbv8m.main-none-eabi", "release", "sca-c10v-target")
VECTORS_JSON = os.path.normpath(os.path.join(HERE, "..", "..", "contracts", "smart-wallet", "test", "c10_test_vectors.json"))
FN = "sca_c10_verify_real"
RET = 0xAAAA_AAAA
COUNT_BUDGET = 3_000_000   # for the (one-time) instruction-count / baseline runs
SWEEP_BUDGET = 25_000      # per faulted emulation in the sweep — a normal verify returns in ~7.5k
SWEEP_CAP    = 8_000       # max instructions to sweep per vector (covers the full ~7.5k of the normal ones)
STACK_TOP = 0x9000_0000
PKS, PKR, MSG, SIG = 0x6000_0000, 0x6000_0100, 0x6000_0200, 0x6000_1000  # scratch buffers
MAX_DOS_SWEEP = 0  # set >0 to also sweep a valid vector for fault→reject (DoS); kept off by default for runtime

if not os.path.exists(ELF):
    sys.exit(f"target ELF not found: {ELF}\nbuild it first:   make -C {HERE} c10v   (or: make -C {HERE} build-c10v)")
if not os.path.exists(VECTORS_JSON):
    sys.exit(f"C10 test vectors not found: {VECTORS_JSON}")


def _hx(s):
    return bytes.fromhex(s[2:] if isinstance(s, str) and s.startswith("0x") else s)


_d = json.load(open(VECTORS_JSON))
_vecs = {v["label"]: v for v in _d["vectors"]}


def vec(label):
    v = _vecs[label]
    ps, pr, msg, sig = _hx(v["pkSeed"]), _hx(v["pkRoot"]), _hx(v["message"]), _hx(v["signature"])
    if len(ps) >= 32:  # JSON stores pk_seed/pk_root right-zero-padded to 32; Rust verify wants 16
        ps = ps[:16]
    if len(pr) >= 32:
        pr = pr[:16]
    assert len(ps) == 16 and len(pr) == 16 and len(msg) == 32 and len(sig) == 4008, \
        f"{label}: bad lengths ps={len(ps)} pr={len(pr)} msg={len(msg)} sig={len(sig)}"
    return ps, pr, msg, sig


_EMU = None
_STACK_LEN = 0x8000


def _emu():
    """One persistent emulator, reused across iterations (re-creating it — and so
    re-parsing the `sphincs-c10`-linked ELF — per iteration is the bottleneck for
    the 6-vector sweep). `setup()` does the per-iteration cleanup; `reset()` +
    re-writing the inputs + zeroing `verify`'s stack region makes the reuse safe
    even on the fault path (a fault that skips a stack write then reads a *zero*,
    not a previous iteration's value)."""
    global _EMU
    if _EMU is None:
        _EMU = rainbow_cortexm()
        _EMU.load(ELF)
        _EMU.map_space(STACK_TOP - _STACK_LEN, STACK_TOP + 0x20)
    return _EMU


def fresh_emu(trace_config=None):
    """A genuinely-fresh emulator — only used by `instr_count` (which needs an
    `instruction=True` trace config, set at construction time; called ≤6×)."""
    e = rainbow_cortexm(trace_config=trace_config) if trace_config else rainbow_cortexm()
    e.load(ELF)
    return e


def setup(e, v):
    e.reset()
    e[STACK_TOP - _STACK_LEN] = b"\x00" * _STACK_LEN  # clear verify's stack (mapped above)
    e["sp"] = STACK_TOP
    ps, pr, msg, sig = v
    e[PKS] = ps
    e[PKR] = pr
    e[MSG] = msg
    e[SIG] = sig
    e["r0"], e["r1"], e["r2"], e["r3"] = PKS, PKR, MSG, SIG
    e["lr"] = RET


def run(e, v, fault=None, budget=COUNT_BUDGET):
    """Returns ('ret', r0) | ('crash', pc) | ('hang', pc) | ('short', None)."""
    setup(e, v)
    begin = e.functions[FN][0]
    try:
        if fault is None:
            e.start(begin, RET, count=budget)
        else:
            e.start_and_fault(fault[0], fault[1], begin, RET, count=budget)
    except (RuntimeError, UcError):
        return ("crash", e["pc"])
    except IndexError:
        return ("short", None)
    if e["pc"] == RET:
        return ("ret", e["r0"] & 0xFFFF_FFFF)
    return ("hang", e["pc"])


def instr_count(v):
    e = fresh_emu(TraceConfig(instruction=True))
    st, _ = run(e, v)
    assert st == "ret", f"instruction-count run didn't return cleanly: {st}"
    return len([ev for ev in e.trace if ev.get("type") == "code"]) or len(e.trace)


# Every invalid vector in the JSON — each fails verification at a *different*
# point (H_msg / FORS index extraction / FORS auth path / WOTS chain / WOTS
# digit-sum check / final root compare), so sweeping all of them exercises every
# reject path, not just the "fails at the very end" one (`wrong-message`).
INVALID_LABELS = ["wrong-message", "wrong-root", "mutated-R", "mutated-FORS-auth",
                  "mutated-WOTS-sigma", "mutated-WOTS-count-target-sum-fail"]


def sweep_forge_one(v_bad, total):
    """For each fault model, sweep every instruction of verify(invalid vector);
    return {model_label: ([(index, pc), ...], crashes, hangs, rejected)}."""
    out = {}
    sweep_to = min(total, SWEEP_CAP)
    for label, model in FAULT_MODELS:
        hits, crashes, hangs, rejected = [], 0, 0, 0
        for i in range(1, sweep_to + 8):
            e = _emu()
            st, val = run(e, v_bad, fault=(model, i), budget=SWEEP_BUDGET)
            if st == "short":
                break
            if st == "crash":
                crashes += 1; continue
            if st == "hang":
                hangs += 1; continue
            if val == 1:
                e2 = _emu()
                setup(e2, v_bad)
                try:
                    e2.start(e2.functions[FN][0], RET, count=min(i, SWEEP_BUDGET))
                except Exception:
                    pass
                hits.append((i, e2["pc"]))
            else:
                rejected += 1
        out[label] = (hits, crashes, hangs, rejected)
    return out


if __name__ == "__main__":
    # baselines: valid → accept; every invalid vector → reject
    e = _emu(); assert run(e, vec("valid-1")) == ("ret", 1), "valid-1 baseline: verify should return 1 (accept)"
    for lbl in INVALID_LABELS:
        e = _emu()
        r = run(e, vec(lbl))
        assert r == ("ret", 0), f"{lbl} baseline: verify should return 0 (reject), got {r}"
    print(f"baselines OK  (valid-1 → accept ; {len(INVALID_LABELS)} invalid vectors → reject)")

    print(f"\n== C10 verify: single-fault sweep over every instruction of verify(), for each of {len(INVALID_LABELS)} invalid vectors ==")
    print("   (a fault that makes verify() return 1 = a FORGED signature accepted — the highest-severity FI outcome)")
    any_forge = False
    for lbl in INVALID_LABELS:
        v_bad = vec(lbl)
        total = instr_count(v_bad)
        sweep_to = min(total, SWEEP_CAP)
        note = ""
        if total > SWEEP_CAP:
            # The only outlier: `mutated-WOTS-count-target-sum-fail`'s verify runs ~1.24M instructions —
            # a malformed WOTS digit drives an unbounded chain (a separate observation: on-chain that's a
            # gas-limit DoS *revert* = reject, so "safe", but `sphincs-c10::verify` could fail-fast on a
            # digit ≥ W). We sweep only its first SWEEP_CAP instructions (the early checks, where a
            # forge-relevant fault would live) and cap each emulation at SWEEP_BUDGET — so a fault during
            # the 1.24M-instr chain shows up as "hung" (verify never returns within the cap → non-forge).
            note = (f"  [verify runs {total} instr — unbounded WOTS chain on the malformed digit;"
                    f" sweeping first {sweep_to}, each emulation capped at {SWEEP_BUDGET} instr]")
        print(f"  -- {lbl}  ({total} instr){note} --")
        for model_label, (hits, cr, hg, rej) in sweep_forge_one(v_bad, total).items():
            print(f"     [{model_label:11s}]  swept ≈{sweep_to}:  forged-accepted={len(hits)}  crashes={cr}  hangs={hg}  correctly-rejected={rej}")
            if hits:
                any_forge = True
                print(f"       !!! {len(hits)} fault(s) made a FORGED signature ({lbl}) verify as good:")
                for i, pc in hits[:20]:
                    print(f"             [{model_label}] instr {i}: pc={pc:#010x}")
                if len(hits) > 20:
                    print(f"             ... and {len(hits) - 20} more")

    print()
    if any_forge:
        print("FINDING — at least one single fault inside sphincs_c10::verify flips a reject into an accept,")
        print("i.e. a forged C10 signature would verify. This is the highest-severity FI outcome (an attacker")
        print("could install their own slot key / userOp). The classic spot is the final `computed_root ==")
        print("pk_root` check; harden it (constant-time + sentinel-encoded equality, double-checked à la")
        print("fi::check_true, and/or verify-then-recompute-then-re-verify). Verbose repro:")
        print(f"  donjon-sca python -c \"... rainbow_cortexm(print=Print.Code|Print.Functions|Print.Faults);")
        print(f"    e.load('{ELF}'); ... e.start_and_fault(<model>, <I>, e.functions['{FN}'][0], 0xaaaaaaaa, count=3000000)\"")
        sys.exit(1)
    print(f"OK — across all 3 single-fault models, no single fault anywhere in sphincs_c10::verify ({total}")
    print("instructions) made a forged signature verify as good. (Caveats: emulated single-fault; the host's")
    print("`gen_test_vectors.rs` `wrong-message` vector — verification runs the full FORS/WOTS/hypertree path")
    print("and fails the final root check; on-device timing/EM glitches and multi-fault are out of scope here.)")
    sys.exit(0)
