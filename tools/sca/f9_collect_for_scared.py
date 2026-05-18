#!/usr/bin/env python3
"""F-9 trace collector for the scared-driven convergence analysis.

Stage 1 of the F-9 scared follow-up. Re-uses `leakage_kdf.collect`
(rainbow + Unicorn emulation) to produce the same fixed-vs-random TVLA
input the lascar harness used in `f9_retest.py` — but dumps the result
to a `.npz` file so a separate scared-sca process (different venv,
numpy 2) can pick it up.

Why two stages: scared requires numpy ≥ 2 + Python ≥ 3.11, lascar is
pinned to numpy 1 in `donjon-sca`'s venv. Trying to merge the envs
deadlocks both. The serialised `.npz` is the contract.

Run:  make -C tools/sca f9-scared-collect
Out:  tools/sca/out/f9_traces.npz  (≈ 4 GB for default config)

Default config matches `f9_retest.py` (600 × 10 M × stride=1) so the
scared convergence curve is directly comparable to the lascar baseline
of max|t|=4.93 at full N.
"""
import os
import sys
import time

os.environ.setdefault("UC_IGNORE_REG_BREAK", "1")

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import leakage_kdf as lk  # noqa: E402
import f9_retest as f9    # noqa: E402

OUT_DIR = os.path.join(HERE, "out")
OUT_FILE = os.path.join(OUT_DIR, "f9_traces.npz")

# Tunable via env.
N_TRACES = int(os.environ.get("F9_SCARED_N", "600"))
MAX_SAMPLES = int(os.environ.get("F9_SCARED_MAX_SAMPLES", "10000000"))
STRIDE = int(os.environ.get("F9_SCARED_STRIDE", "1"))
BUDGET = 10_000_000_000
OUT_SIZE = 4008


def main():
    print("== F-9 scared trace collector (stage 1) ==")
    print(f"   target ELF:    {lk.ELF}")
    print(f"   {N_TRACES} traces × {MAX_SAMPLES:,} samples × stride={STRIDE}")
    print(f"   output:        {OUT_FILE}")
    print()

    os.makedirs(OUT_DIR, exist_ok=True)

    print("Generating inputs (fixed-vs-random msg, random opt_rand + shuffle)…")
    inputs, is_fixed = f9.make_inputs(N_TRACES)
    is_fixed = np.array(is_fixed, dtype=np.uint8)
    # Split inputs back out so scared can reference the public part.
    inp_bytes = np.array([list(b) for b in inputs], dtype=np.uint8)
    msg = inp_bytes[:, 0:32]
    opt_rand = inp_bytes[:, 32:48]
    shuffle_seed = inp_bytes[:, 48:80]
    print(f"  {N_TRACES} inputs, {int(is_fixed.sum())} fixed, "
          f"{N_TRACES - int(is_fixed.sum())} random")
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
    print(f"  {mem.shape[0]} traces × {mem.shape[1]} samples in "
          f"{elapsed:.1f} s ({elapsed / 60:.1f} min)")
    print(f"  trace tensor: {mem.nbytes / 1e9:.2f} GB ({mem.dtype})")
    print()

    print(f"Saving to {OUT_FILE} …")
    np.savez(
        OUT_FILE,
        samples=mem,
        is_fixed=is_fixed,
        msg=msg,
        opt_rand=opt_rand,
        shuffle_seed=shuffle_seed,
        meta=np.array([
            ("n_traces", N_TRACES),
            ("max_samples", MAX_SAMPLES),
            ("stride", STRIDE),
            ("symbol", "sca_c10_sign_shuffled"),
        ], dtype="O"),
    )
    on_disk = os.path.getsize(OUT_FILE) / 1e9
    print(f"  wrote {on_disk:.2f} GB on disk")
    print()
    print("Next: make -C tools/sca f9-scared")
    return 0


if __name__ == "__main__":
    sys.exit(main())
