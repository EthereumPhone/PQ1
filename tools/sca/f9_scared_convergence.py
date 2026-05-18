#!/usr/bin/env python3
"""F-9 scared convergence analysis (stage 2).

Loads the trace tensor produced by `f9_collect_for_scared.py`, runs
scared's `TTestAnalysis` repeatedly over incrementing trace-count
prefixes to produce a fixed-vs-random TVLA curve of max|t| as a
function of #traces.

Why scared (over lascar's `TTestEngine`): scared's TVLA is a one-line
container + `.run()` call and Welch-correct out of the box; lascar's
needs a custom Container subclass to handle the fixed-vs-random split.
The `convergence_step=` kwarg only exists on scared's Attack classes
(CPA/DPA), NOT on `TTestAnalysis` — so we roll our own convergence
by re-running TVLA on `ths[:n]` for each `n` step. Cheap at our
sample sizes (≤ 600 traces × 10 M samples).

Output:
  - stdout: convergence table + final max|t|
  - tools/sca/out/f9_scared_convergence.png  (max|t| vs #traces)

Run:  make -C tools/sca f9-scared
"""
import os
import sys

import numpy as np
import scared
from estraces import read_ths_from_ram

HERE = os.path.dirname(os.path.abspath(__file__))
TRACES_FILE = os.path.join(HERE, "out", "f9_traces.npz")
CURVE_PNG = os.path.join(HERE, "out", "f9_scared_convergence.png")

# TVLA threshold per ISO/IEC 17825 + NIST 800-22 conventions.
T_THRESHOLD = 4.5

# How often to snapshot the t-stat — every CONVERGENCE_STEP traces.
# At N=600 this gives 30 points; at N=60 we get only 3, which is
# why the collect stage defaults to 600.
CONVERGENCE_STEP = int(os.environ.get("F9_SCARED_STEP", "20"))


def load_traces():
    if not os.path.exists(TRACES_FILE):
        print(f"ERROR: {TRACES_FILE} not found.", file=sys.stderr)
        print("Run `make -C tools/sca f9-scared-collect` first.", file=sys.stderr)
        sys.exit(2)
    print(f"Loading {TRACES_FILE} …")
    z = np.load(TRACES_FILE, allow_pickle=True)
    samples = z["samples"]
    is_fixed = z["is_fixed"]
    msg = z["msg"]
    print(f"  samples:  {samples.shape}  {samples.dtype}  ({samples.nbytes/1e9:.2f} GB)")
    print(f"  fixed:    {int(is_fixed.sum())}/{len(is_fixed)}")
    print(f"  msg:      {msg.shape}")
    print()
    return samples, is_fixed, msg


def make_ths(samples, is_fixed, msg):
    """Wrap the loaded numpy arrays into scared's TraceHeaderSet."""
    # scared / estraces expects float32 samples for the t-test pipeline;
    # cast from the uint8 Hamming-weight proxy lascar's harness emitted.
    samples_f32 = samples.astype(np.float32)
    return read_ths_from_ram(
        samples=samples_f32,
        is_fixed=is_fixed.astype(np.uint8),
        msg=msg.astype(np.uint8),
    )


def main():
    samples, is_fixed, msg = load_traces()
    n_traces, n_samples = samples.shape
    print(f"Building TraceHeaderSet (n={n_traces}, samples={n_samples}) …")
    ths = make_ths(samples, is_fixed, msg)
    print(f"  {ths}")
    print()

    # Split into fixed-group and random-group ths views.
    fix_idx = np.flatnonzero(is_fixed == 1)
    rnd_idx = np.flatnonzero(is_fixed == 0)
    print(f"  fixed group: {len(fix_idx)} traces")
    print(f"  rand group:  {len(rnd_idx)} traces")
    ths_fix = ths[fix_idx]
    ths_rnd = ths[rnd_idx]

    # Convergence loop: at each step, take the first `n` traces from
    # BOTH groups (smallest such that both have ≥ CONVERGENCE_STEP * k),
    # run TVLA, record max|t|. The "n" reported is total trace count
    # across both groups for direct comparability with the lascar
    # harness (which feeds the engine all traces in one shot).
    half_step = CONVERGENCE_STEP // 2
    min_group = min(len(fix_idx), len(rnd_idx))
    n_steps = min_group // half_step
    print(f"Running convergence: {n_steps} steps of "
          f"{CONVERGENCE_STEP} traces each "
          f"(={half_step} per group) …")

    points = []
    for step in range(1, n_steps + 1):
        k = step * half_step
        ths_fix_k = ths[fix_idx[:k]]
        ths_rnd_k = ths[rnd_idx[:k]]
        c_k = scared.TTestContainer(ths_fix_k, ths_rnd_k)
        a_k = scared.TTestAnalysis()
        a_k.run(c_k)
        maxt_k = float(np.abs(np.nan_to_num(a_k.result)).max())
        n_total = 2 * k
        points.append((n_total, maxt_k))
        verdict = "LEAK" if maxt_k > T_THRESHOLD else "flat"
        print(f"  step {step:>3d}/{n_steps}  n={n_total:>5d}  max|t|={maxt_k:>7.3f}  {verdict}")
    print()

    # Final run on EVERYTHING (might use the unbalanced tail).
    container = scared.TTestContainer(ths_fix, ths_rnd)
    analysis = scared.TTestAnalysis()
    analysis.run(container)
    final_t = np.nan_to_num(analysis.result)
    final_maxt = float(np.abs(final_t).max())

    final_verdict = "LEAK" if final_maxt > T_THRESHOLD else "flat"
    print(f"Final ({n_traces} traces, full set): max|t| = {final_maxt:.3f} → {final_verdict}")
    print()

    # Optional plot.
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("(matplotlib not installed in this venv; skipping PNG)")
        plt = None

    if plt is not None and points:
        os.makedirs(os.path.dirname(CURVE_PNG), exist_ok=True)
        xs = [p[0] for p in points]
        ys = [p[1] for p in points]
        fig, ax = plt.subplots(figsize=(8, 4.5))
        ax.plot(xs, ys, marker="o", lw=1.2, label="max|t| (post-F-16, hedged R)")
        ax.axhline(T_THRESHOLD, color="r", ls="--", lw=1, label=f"TVLA threshold {T_THRESHOLD}")
        ax.set_xlabel("#traces")
        ax.set_ylabel("max|t|")
        ax.set_title("F-9 scared convergence — sca_c10_sign_shuffled (fixed vs random msg)")
        ax.legend(loc="best")
        ax.grid(True, alpha=0.3)
        fig.tight_layout()
        fig.savefig(CURVE_PNG, dpi=120)
        print(f"Curve saved: {CURVE_PNG}")

    # Exit code: 0 if convergence stays below threshold at every step,
    # 1 if any step exceeded threshold but final value is flat (would
    # indicate a transient spike worth investigating), 2 if final is
    # itself leaking.
    if final_maxt > T_THRESHOLD:
        return 2
    if any(mt > T_THRESHOLD for _, mt in points):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
