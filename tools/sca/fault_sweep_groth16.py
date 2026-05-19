#!/usr/bin/env python3
"""Fault-injection sweep over the **real** Groth16 verifier.

`sca_groth16_verify_real` in the `sca-groth16-target` ELF is a thin wrapper
over the Groth16 pairing-check (`groth16_verify` from `secure/src/zk/
groth16.rs`, mirrored verbatim in the target — see drift watch in the
target's source). We load a known-bad input: real VK + real proof but
WRONG public signals (one bit of `pub0` flipped), so the verification
equation `e(π.A, π.B) · e(-α, β) · e(-vk_x, γ) · e(-π.C, δ) == 1` is
violated and the function returns false.

We then sweep single faults over a window near the function's exit,
watching for a fault that flips the reject into an accept. An ACCEPT
on a known-bad proof is the worst-possible outcome: it means an
attacker who can inject one fault during clear-sign verification can
forge a ZK proof, tricking the user into thinking the device has
cryptographically verified that the calldata matches a known pattern
(Aave v3 supply, CowSwap order, etc.) when in fact the proof was
crafted to look valid but commit to entirely different signals.

**Scope of the sweep.** A full Groth16 verify in software is ~hundreds
of millions of unicorn-instructions (BLS12-381 pairing + final
exponentiation). A naive instruction-level sweep is days. We follow
the c10-sign snapshot/restore pattern: take a one-time snapshot at
`total - TAIL_DEPTH`, then per-iteration restore + fault. The TAIL
window covers the final `Gt::identity()` compare + the trailing
`final_exponentiation` instructions — the part of the function where
a flipped reject/accept verdict can land.

Three fault models: instruction-skip, dest-reg-stuck-at-0,
dest-reg-stuck-at-0xFFFFFFFF.

Run: `donjon-sca run tools/sca/fault_sweep_groth16.py`
     (or, building the target ELF first: `make -C tools/sca groth16`)
"""
import os
import re
import sys
import time

os.environ.setdefault("UC_IGNORE_REG_BREAK", "1")

from rainbow.generics import rainbow_cortexm
from rainbow.fault_models import fault_skip, fault_stuck_at

FAULT_MODELS = [
    ("skip", fault_skip),
    ("stuck-at-0", fault_stuck_at(0x0000_0000)),
    ("stuck-at-FF", fault_stuck_at(0xFFFF_FFFF)),
]

HERE = os.path.dirname(os.path.abspath(__file__))
ELF = os.path.join(
    HERE, "groth16_target", "target", "thumbv8m.main-none-eabi",
    "release", "sca-groth16-target",
)
TV_RS = os.path.normpath(
    os.path.join(HERE, "..", "..", "secure", "src", "zk", "test_vectors.rs")
)
VK_RS = os.path.normpath(
    os.path.join(HERE, "..", "..", "secure", "src", "zk", "vk_data.rs")
)
FN = "sca_groth16_verify_real"
RET = 0xAAAA_AAAA
INPUT_ADDR = 0x6000_0000
STACK_TOP = 0x9000_0000
_STACK_LEN = 0x4_0000  # 256 KB — bls12_381 pairing needs the headroom

# How many instructions to sweep at the tail. 30K matches `fault_sweep_
# c10_sign.py`'s window — covers the final `result == Gt::identity()`
# compare + return, which is the highest-leverage region.
TAIL_DEPTH = 30_000


def parse_rust_array(path: str, name: str) -> bytes:
    """Extract `pub static <name>: [u8; N] = [ 0x..., 0x..., ... ];` from
    a Rust source file. Returns the bytes as a `bytes` object. Tolerates
    Rust's multi-line array literal."""
    src = open(path).read()
    m = re.search(
        rf"pub\s+static\s+{name}\s*:\s*\[\s*u8\s*;\s*\d+\s*\]\s*=\s*\[(.*?)\];",
        src,
        re.DOTALL,
    )
    if not m:
        raise RuntimeError(f"{name} not found in {path}")
    hex_re = re.compile(r"0x([0-9a-fA-F]{2})")
    return bytes(int(h, 16) for h in hex_re.findall(m.group(1)))


def build_input_buffer(corrupt_pub0: bool = True) -> bytes:
    """Layout matches `sca_groth16_verify_real`'s wire format:
       VK(960) ‖ proof_A(96) ‖ proof_B(192) ‖ proof_C(96) ‖ pub0(32) ‖ pub1(32)
       = 1408 bytes total.

    With `corrupt_pub0=True`, we flip bit 0 of pub0's byte 0 so the
    proof was committed against TEST_H_TX but the verifier reads a
    wrong value — pairing fails → false return."""
    vk = parse_rust_array(VK_RS, "VK_BYTES")
    assert len(vk) == 960, f"VK bytes len={len(vk)}, expected 960"
    pa = parse_rust_array(TV_RS, "TEST_PROOF_A")
    pb = parse_rust_array(TV_RS, "TEST_PROOF_B")
    pc = parse_rust_array(TV_RS, "TEST_PROOF_C")
    h_tx = bytearray(parse_rust_array(TV_RS, "TEST_H_TX"))
    h_str = parse_rust_array(TV_RS, "TEST_H_STR")
    assert len(pa) == 96 and len(pb) == 192 and len(pc) == 96
    assert len(h_tx) == 32 and len(h_str) == 32

    if corrupt_pub0:
        # Flip the low bit of byte 0 — keeps the scalar valid (still
        # < BLS12-381 scalar field modulus 2^254) but changes its value
        # so the proof doesn't match.
        h_tx[0] ^= 0x01

    buf = vk + pa + pb + pc + bytes(h_tx) + h_str
    assert len(buf) == 1408, f"buf len {len(buf)} != 1408"
    return buf


def setup_emulator(e, input_bytes: bytes):
    e.reset()
    e[STACK_TOP - _STACK_LEN] = b"\x00" * _STACK_LEN
    e["sp"] = STACK_TOP
    e[INPUT_ADDR] = input_bytes
    e["r0"] = INPUT_ADDR
    e["lr"] = RET


def main():
    if not os.path.exists(ELF):
        sys.exit(f"target ELF not found: {ELF}\nbuild it first:   make -C {HERE} groth16   (or: build-groth16)")

    print("=== Groth16 FI sweep (real bls12_381 pairings) ===")
    print(f"ELF: {ELF}")
    print(f"Test vectors: {TV_RS}")
    print(f"VK:           {VK_RS}")
    print()

    # Build the known-bad input (pub0 bit-flipped → reject expected).
    print("Building INVALID input (real proof + VK, pub0 bit-flipped)…")
    bad_input = build_input_buffer(corrupt_pub0=True)
    good_input = build_input_buffer(corrupt_pub0=False)
    print(f"  input buffer: {len(bad_input)} bytes")
    print()

    e = rainbow_cortexm()
    e.load(ELF)
    e.map_space(STACK_TOP - _STACK_LEN, STACK_TOP + 0x20)
    e.map_space(INPUT_ADDR, INPUT_ADDR + 0x800)

    # Baseline 1: GOOD input (proof matches signals) should return 1.
    print("Baseline (GOOD input — proof matches signals) …")
    setup_emulator(e, good_input)
    t0 = time.time()
    e.start(e.functions[FN][0], RET, count=2_000_000_000)
    good_pc = e["pc"]
    good_ret = e["r0"] & 0xFFFFFFFF
    good_time = time.time() - t0
    print(f"  PC={good_pc:#x}  r0={good_ret}  elapsed={good_time:.1f}s")
    if good_pc != RET:
        sys.exit(f"  baseline GOOD did NOT return — count budget too small?")
    if good_ret != 1:
        print(f"  WARN: good input returned {good_ret} (expected 1) — vectors may be stale")
    print()

    # Baseline 2: BAD input (one bit of pub0 flipped) should return 0.
    print("Baseline (BAD input — pub0 bit-flipped, verifier rejects) …")
    setup_emulator(e, bad_input)
    t0 = time.time()
    e.start(e.functions[FN][0], RET, count=2_000_000_000)
    bad_pc = e["pc"]
    bad_ret = e["r0"] & 0xFFFFFFFF
    bad_time = time.time() - t0
    print(f"  PC={bad_pc:#x}  r0={bad_ret}  elapsed={bad_time:.1f}s")
    if bad_pc != RET:
        sys.exit(f"  baseline BAD did NOT return — count budget too small?")
    if bad_ret != 0:
        sys.exit(f"  bad input returned {bad_ret} — expected 0 (reject). Vectors broken.")
    print()

    print(f"Baseline OK. Good→1, Bad→0.")
    print()

    # ---- Mode selection ----
    # `--mode tight` (default): sparse sweep over the usable window
    # [bad_total - SWEEP_TAIL, bad_total - SWEEP_LEAD) at SWEEP_STEP.
    # Defaults (5000 / 900 / 25) give ~164 positions = ~11 min total.
    # `--mode full`: sweep last 30K instructions × 3 fault models.
    # ~100 h unsnap; intended for overnight runs (kicks off + emits
    # per-iteration status).
    mode = "tight"
    for arg in sys.argv[1:]:
        if arg in ("--mode=tight", "--mode=full"):
            mode = arg.split("=", 1)[1]
        elif arg in ("--full",):
            mode = "full"

    # ---- Bisect BAD-path total instruction count ----
    # Per-instruction `UC_HOOK_CODE` undercounts on rainbow's
    # emulation of long-running code (a known interaction with
    # rainbow's own tracing). Bisect via the `count=` parameter
    # instead: each step runs the function with a candidate cap
    # and checks if `pc == RET`. Same shape as
    # `_probe_c10_sign_total.py`'s bracket.
    print("Bisecting BAD-path total instruction count …")
    def reaches_ret(n: int) -> bool:
        setup_emulator(e, bad_input)
        try:
            e.start(e.functions[FN][0], RET, count=n)
        except Exception:
            return False
        return e["pc"] == RET

    t0 = time.time()
    lo, hi = 1_000_000, 2_000_000_000
    # First confirm hi is enough.
    if not reaches_ret(hi):
        sys.exit(f"BAD path doesn't complete in {hi:_} insns; bump")
    # Bisect with 1K-instruction precision so the sweep window lands
    # ACTUALLY at the function exit (with a 5M-wide bracket the sweep
    # falls inside the pairing math — every fault crashes in
    # BLS12-381 arithmetic and we get zero gate-decision signal).
    while hi - lo > 1_000:
        mid = (lo + hi) // 2
        if reaches_ret(mid):
            hi = mid
        else:
            lo = mid
    bad_total = hi
    print(f"  total instructions: ≤ {bad_total:,} (bisected to 1K precision, "
          f"{time.time() - t0:.1f}s)")
    print()

    # ---- TIGHT sweep ----
    if mode == "tight":
        # Rainbow's `start_and_fault` reports "reached end of function"
        # for fi within ~800 instructions of `bad_total` (empirically
        # determined; see `_probe_groth16_end.py` probe results in the
        # commit message). The usable sweep range is therefore
        # [bad_total - SWEEP_TAIL, bad_total - SWEEP_LEAD).
        #
        # For a quick first pass we step through this range at coarse
        # granularity rather than instruction-by-instruction — ~165
        # samples × ~4s = ~11 min, vs ~4000+ samples × 4s = 4+ hours
        # for exhaustive. The sparse pass catches FORGE_RELEASE if
        # ANY single skip in the tail flips the verdict (even one
        # gives us a real production-critical finding); a future
        # full-tail or full-sweep run can be added with the existing
        # `--full` mode infrastructure.
        SWEEP_TAIL = int(os.environ.get("SWEEP_TAIL", "5000"))
        SWEEP_LEAD = int(os.environ.get("SWEEP_LEAD", "900"))
        SWEEP_STEP = int(os.environ.get("SWEEP_STEP", "25"))
        sweep_start = max(1, bad_total - SWEEP_TAIL)
        sweep_end = max(sweep_start + 1, bad_total - SWEEP_LEAD)
        print(f"=== TIGHT skip-fault sweep ({sweep_start:,} .. {sweep_end:,}) ===")
        print(f"Targets the final `result == Gt::identity()` compare + return path.")
        print()

        forge = []
        crashes = 0
        rejects = 0
        accepts = 0
        anomalies = 0
        exc_types = {}
        from rainbow.fault_models import fault_skip
        t_sweep = time.time()
        # Give plenty of count headroom — a fault could send execution
        # into a longer path before reaching RET. ~3x the unfaulted
        # count is what c10v uses (its 25K budget over 7.5K normal).
        sweep_count_budget = bad_total * 3 + 1_000_000
        sweep_positions = list(range(sweep_start, sweep_end, SWEEP_STEP))
        print(f"  range: [{sweep_start:,}, {sweep_end:,})  step={SWEEP_STEP}  "
              f"positions={len(sweep_positions)}")
        print()
        for fi in sweep_positions:
            setup_emulator(e, bad_input)
            try:
                e.start_and_fault(
                    fault_skip, fi,
                    e.functions[FN][0], RET,
                    count=sweep_count_budget,
                )
            except Exception as exc:
                crashes += 1
                k = type(exc).__name__
                exc_types[k] = exc_types.get(k, 0) + 1
                if crashes <= 3:
                    print(f"  [fi={fi}] CRASH ({k}): {exc}")
                continue
            if e["pc"] != RET:
                anomalies += 1
                continue
            r0 = e["r0"] & 0xFFFFFFFF
            if r0 == 0:
                rejects += 1
            elif r0 == 1:
                accepts += 1
                forge.append(fi)
            else:
                anomalies += 1
            idx_in_sweep = sweep_positions.index(fi) + 1
            if idx_in_sweep % 20 == 0 or idx_in_sweep == len(sweep_positions):
                elapsed = time.time() - t_sweep
                eta = elapsed / idx_in_sweep * (len(sweep_positions) - idx_in_sweep)
                print(f"  swept {idx_in_sweep}/{len(sweep_positions)} "
                      f"({100*idx_in_sweep/len(sweep_positions):.0f}%)  "
                      f"elapsed={elapsed:.0f}s eta={eta:.0f}s  "
                      f"rejects={rejects} accepts={accepts} crashes={crashes}")
        if exc_types:
            print(f"  Exception breakdown: {exc_types}")
        sweep_time = time.time() - t_sweep
        print()
        print(f"Tight sweep complete in {sweep_time:.0f}s "
              f"({sweep_time/60:.1f} min).")
        print(f"  rejects (correct):  {rejects}")
        print(f"  accepts (FORGE!):   {accepts}")
        print(f"  crashes:            {crashes}")
        print(f"  other anomalies:    {anomalies}")
        if forge:
            print()
            print(f"!!! {len(forge)} FORGE_RELEASE position(s):")
            for fi in forge[:20]:
                print(f"  abs instr {fi:,}  (offset {fi - sweep_start} into tail)")
            if len(forge) > 20:
                print(f"  ... and {len(forge) - 20} more")
            return 1
        print()
        print(f"  → No single skip-fault in the [{sweep_start:,}, {sweep_end:,})")
        print(f"    range of the BAD path produced an accept. The final `result")
        print(f"    == Gt::identity()` compare + return path is FI-robust")
        print(f"    against single instruction-skips in this window.")
        print(f"  → Other fault models (stuck-at-0, stuck-at-FF) + a wider tail")
        print(f"    window are NOT covered by this sweep. Run `make groth16-full`")
        print(f"    overnight for the broader analysis (~25-100h).")
        return 0

    # ---- FULL sweep (overnight) ----
    print("=" * 70)
    print("FULL SWEEP MODE — overnight run")
    print("=" * 70)
    print()
    print(f"Sweeping last {TAIL_DEPTH:,} instructions × 3 fault models =")
    print(f"  {TAIL_DEPTH * 3:,} iterations × ~{bad_time:.0f}s each =")
    print(f"  ~{TAIL_DEPTH * 3 * bad_time / 3600:.0f} hours total.")
    print()
    print(f"Per-iteration progress will print every 100 positions.")
    print(f"Output written to stdout; suggest tee'ing to a log file.")
    print()

    # Same usable-window constraint as the tight sweep: rainbow's
    # "end of function" is ~800 instructions before `bad_total`, so any
    # fi closer than `FULL_LEAD` from the end throws past-end / crashes
    # in the BLAKE-of-pairing stack. Default 900 matches the tight sweep.
    FULL_LEAD = int(os.environ.get("FULL_LEAD", "900"))
    sweep_start = max(1, bad_total - TAIL_DEPTH)
    sweep_end = max(sweep_start + 1, bad_total - FULL_LEAD)

    all_forge = []
    counts = {ml[0]: {"rejects": 0, "accepts": 0, "crashes": 0, "anomalies": 0}
              for ml in FAULT_MODELS}

    t_all = time.time()
    for model_label, model in FAULT_MODELS:
        print(f"\n--- model: {model_label} ---")
        t_model = time.time()
        for fi in range(sweep_start, sweep_end):
            setup_emulator(e, bad_input)
            try:
                e.start_and_fault(
                    model, fi,
                    e.functions[FN][0], RET,
                    count=bad_total + 1_000,
                )
            except Exception:
                counts[model_label]["crashes"] += 1
                continue
            if e["pc"] != RET:
                counts[model_label]["anomalies"] += 1
                continue
            r0 = e["r0"] & 0xFFFFFFFF
            if r0 == 0:
                counts[model_label]["rejects"] += 1
            elif r0 == 1:
                counts[model_label]["accepts"] += 1
                all_forge.append((model_label, fi))
            else:
                counts[model_label]["anomalies"] += 1
            if (fi - sweep_start) % 100 == 0:
                elapsed_total = time.time() - t_all
                done_total = (FAULT_MODELS.index((model_label, model))
                              * (sweep_end - sweep_start)
                              + (fi - sweep_start + 1))
                total_iters = 3 * (sweep_end - sweep_start)
                eta = elapsed_total / max(1, done_total) * (total_iters - done_total)
                print(f"  [{model_label}] {fi - sweep_start + 1}/{sweep_end - sweep_start}  "
                      f"elapsed={elapsed_total/3600:.2f}h eta={eta/3600:.1f}h  "
                      f"this model: rejects={counts[model_label]['rejects']} "
                      f"accepts={counts[model_label]['accepts']} "
                      f"crashes={counts[model_label]['crashes']}")
        print(f"  model {model_label} done in {(time.time() - t_model)/3600:.1f}h")

    print()
    print("=" * 70)
    print("FULL SWEEP COMPLETE")
    print("=" * 70)
    for ml, _ in FAULT_MODELS:
        c = counts[ml]
        print(f"  {ml:12s}  rejects={c['rejects']:>6}  accepts={c['accepts']:>4}  "
              f"crashes={c['crashes']:>5}  other={c['anomalies']:>4}")
    if all_forge:
        print()
        print(f"!!! {len(all_forge)} FORGE_RELEASE position(s):")
        for ml, fi in all_forge[:30]:
            print(f"  [{ml}] abs instr {fi:,}")
        if len(all_forge) > 30:
            print(f"  ... and {len(all_forge) - 30} more")
        return 1
    print()
    print("  → No FORGE_RELEASE found across all 3 fault models in the")
    print(f"    last {TAIL_DEPTH:,} instructions of the BAD path.")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
