#!/usr/bin/env python3
"""F-27 — `seed_wizard.rs::prefix_is_exact_word` leakage harness.

F-25 closed the `bip39::lookup_prefix` leak on the recovery path. While
sweeping the surrounding code I found a SECOND wordlist binary-search in
`secure/src/ui/seed_wizard.rs::prefix_is_exact_word`:

  fn prefix_is_exact_word(p: &str) -> bool {
      let mut lo = 0usize;
      let mut hi = WORDLIST.len();
      while lo < hi {
          let mid = (lo + hi) / 2;
          match WORDLIST[mid].as_bytes().cmp(p.as_bytes()) {
              Less    => lo = mid + 1,
              Greater => hi = mid,
              Equal   => return true,
          }
      }
      false
  }

Same leak class as F-25. Called from the candidate-pick gate during
recovery — every long-press Right on a typed prefix invokes this. The
`mid` sequence depends on the comparison results which depend on the
secret prefix bytes.

Production threat model: an EM-scoping attacker with CPU access during
the 60-120 s recovery-typing window collects per-keystroke traces; each
shows ~11 binary-search midpoint loads keyed on the prefix.

Run: `make -C tools/sca seedwizard-exact-leak`
"""
import os
import sys
import time
import warnings

os.environ.setdefault("UC_IGNORE_REG_BREAK", "1")
warnings.filterwarnings("ignore", category=RuntimeWarning)

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import leakage_kdf as lk  # noqa: E402

np.seterr(all="ignore")

N_TRACES = 600
ZERO_VAR_SENTINEL = 1e6

# A 4-letter prefix sits at the unique-prefix boundary (the typical case
# where `prefix_is_exact_word` actually gets called: the user typed all
# 4 letters and `lookup_prefix` returned `Multiple`).
FIXED_PREFIX = b"abou"


def make_inputs(n: int):
    rng = np.random.default_rng(0xCAFEC0DE)
    out, is_fixed = [], []
    for k in range(n):
        if k % 2 == 0:
            out.append(FIXED_PREFIX)
            is_fixed.append(1)
        else:
            chars = bytes(ord("a") + int(c) for c in rng.integers(0, 26, 4))
            out.append(chars)
            is_fixed.append(0)
    return out, is_fixed


def main():
    if not os.path.exists(lk.ELF):
        print(f"ERROR: {lk.ELF} not found.")
        print("Run `make -C tools/sca build-kdf` first.")
        sys.exit(2)

    print("=" * 70)
    print("F-27 — seed_wizard.rs::prefix_is_exact_word leakage")
    print("=" * 70)
    print(f"Target:   {lk.ELF}")
    print(f"N_TRACES: {N_TRACES} (300 fixed @ \"abou\", 300 random [a-z]^4)")
    print()

    def measure(sym, label, max_samples=None):
        inp, isf = make_inputs(N_TRACES)
        t0 = time.time()
        mem = lk.collect(sym, inp, out_size=1, max_samples=max_samples)
        print(f"\n[{label}]")
        print(f"  symbol: {sym}")
        print(f"  collected {mem.shape[0]} traces × {mem.shape[1]:,} samples "
              f"({time.time() - t0:.1f} s)")

        import lascar
        container = lascar.TraceBatchContainer(
            mem, np.array(isf, dtype=np.uint8).reshape(-1, 1)
        )
        eng = lascar.TTestEngine(lambda v: int(v[0]))
        lascar.Session(container, engine=eng).run(batch_size=200)
        t_raw = eng.finalize()
        t = np.abs(np.nan_to_num(t_raw, nan=0.0, posinf=0.0, neginf=0.0))
        t[t > ZERO_VAR_SENTINEL] = 0.0
        mt = float(t.max()) if t.size else 0.0
        verdict = "LEAKAGE" if mt > lk.T_THRESHOLD else "flat"
        print(f"  max|t| = {mt:.3f}  → {verdict}")
        if t.size and mt > 0:
            peak = int(np.argmax(t))
            top5 = np.argsort(t)[-5:][::-1]
            print(f"  peak sample: {peak:,}/{mem.shape[1]:,}")
            print("  top-5 samples:")
            for idx in top5:
                print(f"    sample {int(idx):>6,}  |t|={t[idx]:.2f}")
        return mt

    # Baseline — leaky binary search (regression sentinel).
    mt_leaky = measure("sca_seedwizard_prefix_is_exact_word",
                       "BASELINE — leaky binary search")

    # F-27 fix validator — constant-time scan.
    mt_ct = measure("sca_seedwizard_prefix_is_exact_word_ct",
                    "F-27 FIX — constant-time scan",
                    max_samples=200_000)

    print()
    print("=" * 70)
    print("F-27 fix-vs-baseline:")
    print(f"  leaky binary search   max|t| = {mt_leaky:7.3f}")
    print(f"  ct scan (post-fix)    max|t| = {mt_ct:7.3f}  "
          f"({'CLEAN' if mt_ct <= lk.T_THRESHOLD else 'STILL LEAKS'})")
    print("=" * 70)

    if mt_ct <= lk.T_THRESHOLD and mt_leaky > lk.T_THRESHOLD:
        print()
        print("✓ Fix validated. Baseline still leaks (regression sentinel ok),")
        print("  CT scan closes the leak.")
        return 0
    if mt_ct > lk.T_THRESHOLD:
        print()
        print("✗ CT scan still leaks — likely a missing `core::hint::black_box`")
        print("  barrier letting LLVM fold the scan to a direct lookup.")
        return 2
    if mt_leaky <= lk.T_THRESHOLD:
        print()
        print("Unexpected — baseline binary search should leak. Investigate.")
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
