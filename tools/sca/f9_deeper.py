#!/usr/bin/env python3
"""F-9 deeper sweep — tests F-16's shuffle effect on the SECRET-bearing
region of C10 sign (FORS leaf secrets + WOTS chain seeds), past
`grind_r`.

**Why this exists.** The original F-9 sweep + the post-F-16 re-test
(`f9_retest.py`) both cover a 10 M-sample window that stops near the
end of `fors::grind_r`. The leak found at sample ~9.99 M turns out
to be `grind_r`'s msg-dependent iteration count (transparent — see
README §F-9 re-test). F-16's shuffle protects code that runs AFTER
`grind_r`:

  - `fors::sign_fors_tree` — touches FORS leaf secrets (the
    `forsSk[leaf_idx]` values derived from `sk_seed`).
  - `wots::sign_with_shuffle` — touches WOTS chain seeds (the
    `wots_secret(sk_seed, ...)` values).

Both live PAST sample 10 M, so the 10 M-window sweep cannot
directly measure F-16's effect on the layer it was designed to
defend. This deeper sweep uses larger stride to reach into the
FORS+WOTS region while staying within the 64 GB-RAM budget the host
imposes (per F-9 §Limitation: 600 × 50 M @ stride=1 OOM-killed
lascar).

**Memory budget.**
  - trace array = N_traces × max_samples × 1 byte
  - lascar t-test working arrays add ~3-4× peak memory
  - For 200 traces × 30 M samples stored = 6 GB trace + ~18 GB
    lascar peak ≈ 24 GB → fits in 64 GB with margin.

With stride=10, 30 M samples stored represents ~300 M mem events of
function execution — covers `grind_r` (≈10 M) + FORS sign (≈30 M)
+ some of WOTS sign.

Drops to 200 traces (vs F-9's 600) to keep memory in bounds. 200 is
below the audit-grade statistical-power threshold for max|t|=4.5
detection (~5σ) but more than enough to detect a hypothetical
≥10σ leak; the question this sweep answers is "does F-16 visibly
reduce leakage in the SECRET-bearing region?" and a clear yes/no
needs only a few-σ resolution.

Run:  make -C tools/sca f9-deeper
"""
import os
import sys
import warnings
import time

os.environ.setdefault("UC_IGNORE_REG_BREAK", "1")
warnings.filterwarnings("ignore", category=RuntimeWarning, module=r"lascar\..*")

import numpy as np  # noqa: F401 — sets the env for lascar

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import leakage_kdf as lk  # noqa: E402
import f9_retest as f9    # noqa: E402

ELF = lk.ELF
T_THRESHOLD = lk.T_THRESHOLD

# Configuration knobs — see module docstring for the rationale.
#
# **Tuning the wall-time budget.** Per the F-9 re-test, 600 traces ×
# 10M samples × stride=1 took ~11 min wall on 22 workers. This deeper
# sweep with stride=10 means the emulator runs 10× longer per trace
# (it stops on N_stored = MAX_SAMPLES = 10M which corresponds to
# 100M mem events at stride=10). Drop to 100 traces (vs 600) to bring
# wall back to ~10-20 min. That covers ~100M mem events — enough to
# reach past grind_r (≈10M) and well into FORS sign (≈10-40M) +
# early WOTS sign (≈40M+).
N_TRACES = 100
MAX_SAMPLES = 10_000_000
STRIDE = 10
BUDGET = 100_000_000_000
OUT_SIZE = 4008


def main():
    print("== F-9 deeper sweep: tests F-16 on the SECRET-bearing region ==")
    print(f"   ELF: {ELF}")
    print(f"   {N_TRACES} traces × {MAX_SAMPLES:,} samples stored × stride={STRIDE}")
    print(f"   → covers ~{(MAX_SAMPLES * STRIDE):,} mem events of function execution")
    print(f"   (grind_r ≈ first 10 M; FORS sign ≈ next ~30 M; WOTS sign ≈ next ~50 M)")
    print()

    print("Generating inputs…")
    inputs, is_fixed = f9.make_inputs(N_TRACES)
    print(f"  {N_TRACES} × 80 B inputs (msg + opt_rand + shuffle_seed)")
    print(f"  Group A (fixed msg, isf=1): {sum(is_fixed)} traces")
    print(f"  Group B (random msg, isf=0): {N_TRACES - sum(is_fixed)} traces")
    print(f"  opt_rand AND shuffle_seed independently random in BOTH groups")
    print()

    print("Collecting traces (parallel emulation; this may take ~10-30 min)…")
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
    mt = lk.tvla(
        f"c10_sign deeper (n={N_TRACES}, stride={STRIDE})",
        "mem_address",
        mem,
        is_fixed,
    )
    print()

    # Verdict.
    print("=" * 75)
    print(f"F-9 baseline (10 M window @ stride 1):  max|t| = {f9.F9_BASELINE_MAX_T:7.2f}")
    print(f"F-9 deeper sweep (this run):            max|t| = {mt:7.2f}")
    print(f"F-9 deeper sweep coverage:              ~{(MAX_SAMPLES * STRIDE) / 1e6:.0f} M mem events"
          f" (= grind_r + FORS sign + most of WOTS sign)")
    print()
    if mt <= T_THRESHOLD:
        print(f"VERDICT: max|t| ≤ {T_THRESHOLD} → **no measurable msg-dependent leakage in")
        print("         the SECRET-bearing region (FORS + WOTS) under F-13 hedged R +")
        print("         F-16 shuffle.** This is the strongest evidence the audit can")
        print("         produce from emulation. On-silicon SCA still needed for")
        print("         physical-channel verification.")
        return 0
    elif mt < 10.0:
        print(f"VERDICT: max|t| < 10 → low but non-zero msg-dependent leakage in the")
        print("         SECRET-bearing region. F-16 reduces but does not fully mask.")
        print(f"         Worth localising via snapshot/restore narrower windows.")
        return 1
    elif mt < f9.F9_BASELINE_MAX_T:
        print(f"VERDICT: residual leakage similar to or worse than F-9 baseline.")
        print(f"         F-16 ineffective at this layer? Investigate.")
        return 2
    else:
        print(f"VERDICT: residual leakage ≥ F-9 baseline. Investigate harness setup.")
        return 2


if __name__ == "__main__":
    sys.exit(main())
