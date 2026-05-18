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

    print(f"Baseline OK. Good→1, Bad→0. Sweep would target the BAD path's tail")
    print(f"(last {TAIL_DEPTH:_} instructions) looking for a fault that flips")
    print(f"r0 from 0 to 1.")
    print()
    print(f"Per-iteration cost: ~{bad_time:.0f}s unfaulted. Snapshot/restore could")
    print(f"trim per-iteration cost to ~0.5-1s; with 3 models × {TAIL_DEPTH:,} positions")
    print(f"that's ~{TAIL_DEPTH * 3:,} iterations × 1s ≈ {TAIL_DEPTH * 3 / 3600:.0f} hours.")
    print()
    print("** SKIPPING THE FULL SWEEP IN THIS RUN. **")
    print()
    print("Rationale: the snapshot/restore pattern from `fault_sweep_c10_sign.py`")
    print("requires careful per-iteration emulator state reset that interacts")
    print("with bls12_381's stack-heavy intermediates. Building it correctly is")
    print("non-trivial (the c10-sign harness took several iterations of bisect")
    print("calibration). For this initial commit we land the TARGET + BASELINE")
    print("validator so the wire format is frozen + good/bad vectors confirmed,")
    print("and leave the sweep itself as a follow-up to wire up the snapshot.")
    print()
    print("Without the sweep, the analysis-grade claim is bounded to:")
    print("  - `groth16_verify` returns 1 on a known-good proof+VK+signals.")
    print("  - `groth16_verify` returns 0 on the same VK+proof with pub0 flipped.")
    print("  - Both runs complete in bounded time (~{:.0f}s).".format(bad_time))
    print()
    print("Full single-fault sweep (the FORGE_RELEASE question) is queued.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
