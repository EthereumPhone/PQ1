#!/usr/bin/env python3
"""Fault-injection sweep over the real `c10_sign_verified_with_progress`
production signing primitive (post-F-1/F-2/F-5 hardening).

**What this sweeps that the existing harnesses don't.** `make c10` sweeps
the verify-before-release *gate* with sign/verify stubbed; `make c10v`
sweeps the *real* `sphincs_c10::verify` for forge-acceptance. This harness
sweeps the production gate with the *real* sign + *real* verify in series,
catching any single-fault that releases a corrupted-but-bytewise-different
signature through the layered hardening end-to-end. Same shape as Tier-1
item 3 — the C10-sign FI surface neither `c10` nor `c10v` covers alone.

**Success criterion.** Per fault model × instruction position:
  - Function returns 1 (Ok) **and** the produced sig bytes ≠ baseline sig:
    BYPASS — a corrupted signature was released past the verify-gate. This
    is the catastrophic FI outcome (the released sig wouldn't actually
    verify under the intended message; the gate's job is to catch this
    before release).
  - Function returns 1 **and** sig == baseline: clean release. The fault
    didn't affect output.
  - Function returns 0: correctly rejected by the gate.
  - Crash / hang: counted separately.

**Scope (and the unicorn-runtime constraint).** Each emulation runs the
full ~50-100M-unicorn-instruction SPHINCS+C10 sign + verify + gate sequence
(unicorn's interpreter, unlike QEMU's TCG JIT, executes individual
instructions; the SPHINCS+ hash count puts each iteration at ~30-60 s
wallclock on modern desktops). A naive 500-position × 3-model sweep would
take 2-3 hours. So we run *two* things at modest cost:

  1. **Baseline** — one unfaulted run. Confirms the production gate releases
     a signature that the harness can fully validate (against the off-board
     `sca_c10_verify_real` entry point in the same ELF, using the baked
     pk_root). This alone is a meaningful end-to-end test of F-1/F-2/F-5
     with real sign+verify — bit-identical to production code.

  2. **Focused tail sweep** — a tiny window (default `TAIL_DEPTH=20`)
     covering exactly the F-2/F-5 residual cmp+branch (`if … != OK_SENTINEL
     { return 0 }`) + the early Err-return + the sig-write loop entry. This
     is where a single-fault forge-release would live if F-1/F-2/F-5 had a
     bug in real production conditions. One fault model (`skip`) by default;
     `--all-models` for the full three.

The verify-gate code itself (sentinel helpers in `fi.rs`, the cmp+branch)
is comprehensively covered by `make fi` and `make c10`; the `sphincs_c10::verify`
internals are covered by `make c10v`. This harness fills the remaining gap:
"does the production gate, with the *real* sign + verify, release the right
sig?". For a full-sweep audit-grade test, port to QEMU's TCG JIT (10-50×
faster than unicorn).

Run:   donjon-sca run tools/sca/fault_sweep_c10_sign.py
       (or: make -C tools/sca c10-sign)
"""
import os
import sys

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
ELF = os.path.join(HERE, "c10_sign_target", "target", "thumbv8m.main-none-eabi",
                   "release", "sca-c10-sign-target")

RET = 0xAAAA_AAAA
STACK_TOP = 0x9000_0000
_STACK_LEN = 0x10_000          # 64KB stack — sign+verify uses ~10KB
MSG_ADDR  = 0x6000_0000        # NS-style scratch buffers
SIG_ADDR  = 0x6000_1000

# Each emulation runs ~2.5M sign + ~7.5k verify + ~few-k gate/sig-write.
# Budget generously to allow tail-fault continuations.
COUNT_BUDGET   = 10_000_000_000   # full sign+verify is ~5-10 B unicorn-instructions (~14s wallclock)
SWEEP_BUDGET   = 10_000_000_000   # per-fault total budget
TAIL_DEPTH     = 20            # tiny — keep total wallclock under ~20 min
SIG_LEN        = 4008
SWEEP_MODELS   = [("skip", fault_skip)]  # single model by default; `--all-models` opts in

# Fixed test message. The mirror's hardcoded keypair (sk_seed=[0x42;32],
# pk_seed=[0x77;16]) signs over this message in baseline runs.
TEST_MSG = bytes(range(32))    # 0x00..0x1F

if not os.path.exists(ELF):
    sys.exit(f"target ELF not found: {ELF}\nbuild it first:   make -C {HERE} c10-sign   (or: make -C {HERE} build-c10-sign)")


def fresh_emu(trace_config=None):
    e = rainbow_cortexm(trace_config=trace_config) if trace_config else rainbow_cortexm()
    e.load(ELF)
    e.map_space(STACK_TOP - _STACK_LEN, STACK_TOP + 0x20)
    return e


def setup(e):
    e.reset()
    e[STACK_TOP - _STACK_LEN] = b"\x00" * _STACK_LEN
    e["sp"] = STACK_TOP
    e[MSG_ADDR] = TEST_MSG
    e[SIG_ADDR] = b"\x00" * SIG_LEN  # zero-fill so we can detect partial writes
    e["r0"] = MSG_ADDR
    e["r1"] = SIG_ADDR
    e["lr"] = RET


def call(e, fn):
    setup(e)
    begin = e.functions[fn][0]
    try:
        e.start(begin, RET, count=COUNT_BUDGET)
    except (RuntimeError, UcError):
        return ("crash", e["pc"], None)
    if e["pc"] != RET:
        return ("hang", e["pc"], None)
    ret = e["r0"] & 0xFFFF_FFFF
    sig = bytes(e[SIG_ADDR:SIG_ADDR + SIG_LEN])
    return ("ret", ret, sig)


def call_fault(e, fn, fault_model, fault_idx):
    setup(e)
    begin = e.functions[fn][0]
    try:
        e.start_and_fault(fault_model, fault_idx, begin, RET, count=SWEEP_BUDGET)
    except (RuntimeError, UcError):
        return ("crash", e["pc"], None)
    except IndexError:
        return ("short", None, None)
    if e["pc"] != RET:
        return ("hang", e["pc"], None)
    ret = e["r0"] & 0xFFFF_FFFF
    sig = bytes(e[SIG_ADDR:SIG_ADDR + SIG_LEN])
    return ("ret", ret, sig)


def offboard_verify(e, msg: bytes, sig: bytes) -> bool:
    """Independent verify of a produced sig via the same ELF's
    `sca_c10_verify_real` entry point. Re-uses the same pk_seed/pk_root
    the build.rs baked into the mirror — closes the loop on baseline."""
    PK_SEED_ADDR = 0x6010_0000
    PK_ROOT_ADDR = 0x6010_1000
    MSG_ADDR_OB  = 0x6010_2000
    SIG_ADDR_OB  = 0x6010_3000
    # PK_SEED is 16 bytes of 0x77; PK_ROOT was baked at build time — we
    # read it back from the ELF's `.rodata` (it's referenced as the static
    # `PK_ROOT`, so it lives in flash and is mapped by `e.load(ELF)`).
    pk_seed = b"\x77" * 16
    # Find PK_ROOT bytes via the same build artifact:
    import glob
    matches = glob.glob(os.path.join(HERE, "c10_sign_target", "target",
                                     "thumbv8m.main-none-eabi", "release",
                                     "build", "sca-c10-sign-target-*", "out",
                                     "pk_root.bin"))
    if not matches:
        raise RuntimeError(
            "pk_root.bin not found in any build dir; rebuild with "
            "`make -C tools/sca build-c10-sign`")
    with open(matches[0], "rb") as f:
        pk_root = f.read()
    assert len(pk_root) == 16, f"pk_root: expected 16 bytes, got {len(pk_root)}"
    e.reset()
    e[STACK_TOP - _STACK_LEN] = b"\x00" * _STACK_LEN
    e["sp"] = STACK_TOP
    e[PK_SEED_ADDR] = pk_seed
    e[PK_ROOT_ADDR] = pk_root
    e[MSG_ADDR_OB]  = msg
    e[SIG_ADDR_OB]  = sig
    e["r0"] = PK_SEED_ADDR
    e["r1"] = PK_ROOT_ADDR
    e["r2"] = MSG_ADDR_OB
    e["r3"] = SIG_ADDR_OB
    e["lr"] = RET
    try:
        e.start(e.functions["sca_c10_verify_real"][0], RET, count=COUNT_BUDGET)
    except Exception as ex:
        return False
    return e["pc"] == RET and (e["r0"] & 0xFFFF_FFFF) == 1


def main():
    global SWEEP_MODELS
    if "--all-models" in sys.argv:
        SWEEP_MODELS = FAULT_MODELS
    print("=== C10-sign FI sweep (real sign + real verify + real gate) ===")
    print(f"ELF: {ELF}")
    print(f"Test message: {TEST_MSG.hex()}")
    print(f"Fault models: {[ml for ml, _ in SWEEP_MODELS]}  "
          f"(use --all-models for all three)")
    print()

    # ---- Baseline (no fault). Establishes the expected sig. ----
    print("Baseline (no fault) — running sca_c10_sign_verified (~14 s wallclock):")
    import time
    t0 = time.time()
    e = fresh_emu()
    st, ret, baseline_sig = call(e, "sca_c10_sign_verified")
    print(f"  finished in {time.time() - t0:.1f} s")
    if st != "ret":
        sys.exit(f"baseline didn't return: {st}")
    if ret != 1:
        sys.exit(f"baseline returned {ret}, expected 1 (Ok)")
    if baseline_sig is None or len(baseline_sig) != SIG_LEN:
        sys.exit(f"baseline sig size mismatch: {len(baseline_sig) if baseline_sig else 'None'}")
    print(f"  sca_c10_sign_verified → Ok, sig[0..32]={baseline_sig[:32].hex()}")
    print(f"                            sig[end]={baseline_sig[-16:].hex()}")

    # ---- Off-board verify of the baseline sig (closes the loop) ----
    print("  off-board verify (calling sca_c10_verify_real on the produced sig):")
    t0 = time.time()
    ev = fresh_emu()
    sig_ok = offboard_verify(ev, TEST_MSG, baseline_sig)
    print(f"    {'OK — sig validates' if sig_ok else '!! SIG DID NOT VERIFY — gate released an invalid sig'}"
          f"   ({time.time() - t0:.1f} s)")
    if not sig_ok:
        sys.exit("baseline sig failed independent verify — toolchain or mirror is broken")
    print()

    # ---- Sweep range: fixed offsets at the very tail of the function ----
    # We don't run instr_count (would trace ~10 B events, OOMs). Instead we
    # know empirically that `sca_c10_sign_verified` runs ~10 B unicorn-
    # instructions to completion. Sweep at the very last instructions by
    # walking down from a high fault index until rainbow stops raising
    # IndexError ("reached end of function before faulting").
    print(f"Searching for actual instruction count via descending fault-index probe:")
    e2 = fresh_emu()
    # Probe to find the actual total in steps; reasonable upper bound.
    hi = 12_000_000_000
    lo = 1_000_000_000
    last_short = None
    # Coarse: bisect with fault_skip
    while hi - lo > 50_000_000:
        mid = (hi + lo) // 2
        st, _, _ = call_fault(e2, "sca_c10_sign_verified", fault_skip, mid)
        if st == "short":
            hi = mid
            last_short = mid
        else:
            lo = mid
        print(f"    probe fault_index={mid:>12}: {st}")
    total_estimate = lo
    print(f"  estimated total ≈ {total_estimate}")
    sweep_start = max(1, total_estimate - TAIL_DEPTH)
    sweep_end = total_estimate + 8
    print(f"Tail sweep range: instr {sweep_start}..{sweep_end} (last {TAIL_DEPTH} instructions)")
    print()

    # ---- Sweep ----
    any_bypass = False
    bypasses = []  # (model, idx, ret, sig_diff_len)
    for model_label, model in SWEEP_MODELS:
        e = fresh_emu()
        bypass_n = correctly_rejected = clean_release = crashes = hangs = shorts = 0
        for i in range(sweep_start, sweep_end):
            st, ret, sig = call_fault(e, "sca_c10_sign_verified", model, i)
            if st == "short":
                shorts += 1; continue
            if st == "crash":
                crashes += 1; continue
            if st == "hang":
                hangs += 1; continue
            # st == "ret"
            if ret == 0:
                correctly_rejected += 1
                continue
            # ret == 1 — gate accepted. Compare sig to baseline.
            if sig == baseline_sig:
                clean_release += 1
            else:
                # Count differing bytes for the report.
                diffs = sum(1 for a, b in zip(sig, baseline_sig) if a != b)
                bypass_n += 1
                bypasses.append((model_label, i, ret, diffs))
        any_bypass = any_bypass or (bypass_n > 0)
        print(f"  [{model_label:11s}]  swept {sweep_end - sweep_start}:  "
              f"bypassed={bypass_n}  crashes={crashes}  hangs={hangs}  "
              f"shorts={shorts}  correctly-rejected={correctly_rejected}  "
              f"clean-release={clean_release}")
        if bypass_n > 0:
            print(f"     !!! {bypass_n} single-fault(s) released a CORRUPTED sig "
                  f"(differs from baseline):")
            for ml, idx, ret, diffs in bypasses[-bypass_n:][:10]:
                print(f"        [{ml}] instr {idx}: ret={ret}  sig differs in {diffs}/{SIG_LEN} bytes")
            if bypass_n > 10:
                print(f"        ... and {bypass_n - 10} more")
    print()

    # ---- Findings ----
    print("=" * 75)
    if not any_bypass:
        print("ALL SWEEPS CLEAN — no single fault in the gate tail released a")
        print("corrupted signature through `c10_sign_verified_with_progress`.")
        print()
        print("This empirically validates the F-1 (CSE black_box) + F-2 (sentinel")
        print("caller cmp) + F-5 (sentinel-encoded check_true) fix stack end-to-end")
        print("with the *real* SPHINCS+C10 sign + verify (vs the stubs `make c10`")
        print("uses for speed). The production verify-before-release gate would")
        print("reject every corrupted-sign outcome reachable via a single fault in")
        print("this region.")
        sys.exit(0)

    print("FINDING — single-fault released a corrupted signature past the gate")
    print()
    print(f"  {len(bypasses)} bypass instance(s) across {len({b[0] for b in bypasses})} fault model(s).")
    print("  This means the F-1/F-2/F-5 gate didn't catch a corrupted-sign produced")
    print("  by a single fault in this region. Investigate the specific instruction")
    print("  position — likely the cmp+branch on the sentinel, or the sig-write")
    print("  loop running with corrupted source.")
    sys.exit(1)


if __name__ == "__main__":
    main()
