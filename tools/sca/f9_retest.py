#!/usr/bin/env python3
"""F-9 re-test: did F-16's WOTS/FORS shuffle mask the FORS-leaf-index
mem_address leak?

**Baseline (F-9, recorded in tools/sca/README.md §F-9).**
`sca_c10_sign(msg) → sk.sign(msg, None)` on the pre-F-16 code:
`max|t| = 40.71 @sample 9 997 943` across 600 traces × 10 M samples,
varying `msg_hash` between fixed and random groups. The leak comes
from the FORS leaf-index access pattern: `forsSk[leaf_idx]` and
`forsTree[level][sibling_idx]` indices are msg-derived, so the
*addresses* of those accesses vary with msg, and the natural temporal
order (tree 0 first, tree 1 second, …) means address X at sample Y
is consistent across traces with the same msg → t-stat lights up.

**Hypothesis.** F-16's per-call Fisher-Yates shuffle of the FORS
tree processing order (k=13 → 13! ≈ 6 × 10⁹ permutations) and the
WOTS chain order (l=43 → 43! ≈ 10⁵² per layer) breaks the
"fixed temporal pattern" premise. With a fresh shuffle per trace,
sample Y sees a random tree's leaf access. The TVLA's per-sample
mean averaged over many traces smears the msg-dependent signal
across many time positions → max|t| should drop substantially.

**Test design.** New SUT `sca_c10_sign_shuffled(in[64], out)` where
`in[0..32] = msg`, `in[32..64] = shuffle_seed`. Trace inputs:

  - Group A (fixed, `isf=1`): msg = ALL-ZEROS (32 B), shuffle = RANDOM (32 B per trace).
  - Group B (random, `isf=0`):   msg = RANDOM (32 B), shuffle = RANDOM (32 B per trace).

In BOTH groups the shuffle is independently random per trace.
Within-group averaging smears the shuffle-induced address variance.
What remains is the *msg-dependent* address variation — exactly the
F-9 signal, but now with the F-16 shuffle defending against it.

**Expected outcome.** max|t| substantially below 40.71. A drop to
~T_THRESHOLD (4.5) or lower would mean the shuffle reduces the leak
below the standard TVLA detection threshold. A drop to 1/10 of the
baseline (~4) would already be evidence the shuffle is the right
class of defense; a drop to 1/100 (~0.4) would be near-perfect
masking.

**What this test does NOT prove.** Even if max|t| drops below 4.5,
a more sophisticated attack (CPA with shuffle-permutation
hypotheses, or higher-order DPA) might still extract bits.
TVLA on `mem_address` is a coarse first-pass screen; final
on-silicon SCA must run on real hardware with proper instruments.

Run:  donjon-sca run tools/sca/f9_retest.py
      (or: make -C tools/sca f9-retest)
"""
import os
import sys
import warnings
import multiprocessing as mp
import time

os.environ.setdefault("UC_IGNORE_REG_BREAK", "1")
warnings.filterwarnings("ignore", category=RuntimeWarning, module=r"lascar\..*")

import numpy as np
from lascar import TraceBatchContainer, Session, TTestEngine

# Reuse the harness primitives from leakage_kdf.py.
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import leakage_kdf as lk  # noqa: E402

ELF = lk.ELF
T_THRESHOLD = lk.T_THRESHOLD

# F-9 baseline. Used for the verdict line at the end.
F9_BASELINE_MAX_T = 40.71

# Per-trace input layout: 32 B msg ‖ 32 B shuffle_seed = 64 B.
IN_LEN = 64

# Match `leakage_kdf.py`'s c10-sign settings so the comparison with
# F-9's baseline is apples-to-apples.
N_TRACES = 600
MAX_SAMPLES = 10_000_000
STRIDE = 1
BUDGET = 10_000_000_000
OUT_SIZE = 4008  # SIGNATURE_LEN


def make_inputs(n: int):
    """600 inputs of 64 B each. Group A (isf=1): msg=zeros, shuffle=random.
    Group B (isf=0): msg=random, shuffle=random. Shuffle is independently
    random in BOTH groups."""
    rng = np.random.default_rng(0xF9_C0FFEE)
    fixed_msg = bytes(32)
    out, is_fixed = [], []
    for k in range(n):
        shuffle_bytes = bytes(rng.integers(0, 256, 32, dtype=np.uint8))
        if k % 2 == 0:
            msg = fixed_msg
            is_fixed.append(1)
        else:
            msg = bytes(rng.integers(0, 256, 32, dtype=np.uint8))
            is_fixed.append(0)
        out.append(msg + shuffle_bytes)
    return out, is_fixed


def main():
    print("== F-9 re-test: sca_c10_sign_shuffled with F-16 shuffle active ==")
    print(f"   ELF: {ELF}")
    print(f"   Baseline (F-9): max|t| = {F9_BASELINE_MAX_T} (pre-shuffle, recorded)")
    print(f"   Per-trace input: 32 B msg ‖ 32 B shuffle_seed (random per trace)")
    print(f"   {N_TRACES} traces × {MAX_SAMPLES:,} samples × stride={STRIDE}")
    print()

    print("Generating inputs…")
    inputs, is_fixed = make_inputs(N_TRACES)
    print(f"  {N_TRACES} inputs of {IN_LEN} B each, {sum(is_fixed)} fixed-msg, "
          f"{N_TRACES - sum(is_fixed)} random-msg, all with independent random shuffle seeds")
    print()

    print("Collecting traces (parallel emulation)…")
    t0 = time.time()
    mem = lk.collect(
        "sca_c10_sign_shuffled",
        inputs,
        budget=BUDGET,
        out_size=OUT_SIZE,
        max_samples=MAX_SAMPLES,
        stride=STRIDE,
    )
    elapsed = time.time() - t0
    print(f"  collected {mem.shape[0]} traces × {mem.shape[1]} samples "
          f"({elapsed:.1f} s, {elapsed / 60:.1f} min)")
    print()

    print("Running TVLA…")
    mt = lk.tvla("c10_sign_shuffled (post-F-16)", "mem_address", mem, is_fixed)
    print()

    # Verdict.
    print("=" * 75)
    print(f"F-9 baseline:    max|t| = {F9_BASELINE_MAX_T:7.2f}  (pre-shuffle)")
    print(f"F-9 re-test:     max|t| = {mt:7.2f}  (post-F-16 shuffle)")
    if F9_BASELINE_MAX_T > 0:
        ratio = mt / F9_BASELINE_MAX_T
        print(f"Reduction:       {ratio:7.3f}× of baseline ({(1 - ratio) * 100:5.1f}% drop)")
    print()
    if mt <= T_THRESHOLD:
        print(f"VERDICT: max|t| ≤ {T_THRESHOLD} → **shuffle masks the leak below TVLA threshold**.")
        print("         F-9 reclassified from 'audit-grade leakage, transparent' to")
        print("         'no measurable signal under the same harness conditions.'")
        return 0
    elif mt < F9_BASELINE_MAX_T / 4:
        print(f"VERDICT: max|t| dropped to <{F9_BASELINE_MAX_T / 4:.1f} (¼ of baseline) → shuffle")
        print("         materially reduces the leak but residual signal remains.")
        print("         Worth a deeper analysis (longer trace window, higher trace count).")
        return 1
    elif mt < F9_BASELINE_MAX_T:
        print(f"VERDICT: max|t| dropped but still above {T_THRESHOLD} threshold. Shuffle helps")
        print("         but does not fully mask. Likely indicates the leak isn't ENTIRELY")
        print("         in the temporal-order channel (some msg-dependence at fixed time")
        print("         positions independent of the WOTS/FORS shuffle).")
        return 1
    else:
        print(f"VERDICT: shuffle does NOT reduce the leak — same as baseline or worse.")
        print("         Investigate. Did the harness use the wrong SUT? Is the shuffle")
        print("         seed being consumed correctly?")
        return 2


if __name__ == "__main__":
    sys.exit(main())
