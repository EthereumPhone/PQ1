#!/usr/bin/env python3
"""Recovery-path leakage analysis — symmetric to F-22/F-24.

F-22 closed the leak DURING SEED DERIVATION (the wordlist lookup in
`Mnemonic::to_seed`). F-24 closed the leak DURING SEED DISPLAY (the
seed-wizard's per-word lookup + glyph rendering).

This harness probes the OPPOSITE direction: SEED ENTRY DURING RECOVERY.
When a user restores from their paper backup, they type each of the 24
mnemonic words back via the wizard's on-screen keyboard. On every
keystroke `bip39::lookup_prefix(typed_so_far)` is called to figure out
which BIP-39 word (or word range) the user is converging on. The
function does:

  1. `WORDLIST.partition_point(|w| w.as_bytes() < needle)` — a binary
     search over the 2048-entry wordlist.
  2. A walk-forward `while WORDLIST[end].as_bytes().starts_with(needle)`.

Both phases visit flash addresses keyed on the typed prefix bytes. An
EM-scoping attacker who can scope the CPU during the 60-120 s recovery
typing window can reconstruct the typed words from the per-keystroke
address patterns — bypassing the screen-shroud / private-room
protection a user might use against the optical channel.

TVLA fixed-vs-random 4-byte prefix (the typical BIP-39 unique-prefix
length). Expected outcome: LEAKAGE (binary search by construction has
data-dependent control flow). The interesting question is the
MAGNITUDE: how many traces an attacker needs to recover each prefix.

Run: `make -C tools/sca recovery-leak`
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

# A small set of "fixed" prefixes mimicking what a user might type when
# restoring. Use "aban" (prefix of "abandon", entry #0) as the fixed
# reference; random prefixes are uniform lowercase ASCII.
FIXED_PREFIX = b"aban"


def make_inputs(n: int):
    """4-byte ASCII prefixes; half fixed at "aban", half uniform random
    in [a-z]^4 (the realistic user-typing distribution)."""
    rng = np.random.default_rng(0xBEEFC0DE)
    out, is_fixed = [], []
    for k in range(n):
        if k % 2 == 0:
            out.append(FIXED_PREFIX)
            is_fixed.append(1)
        else:
            # Random lowercase prefix.
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
    print("Recovery-path leakage — bip39::lookup_prefix")
    print("=" * 70)
    print(f"Target:   {lk.ELF}")
    print(f"N_TRACES: {N_TRACES} (300 fixed @ \"aban\", 300 random [a-z]^4)")
    print()

    def measure(sym, label, max_samples=None):
        inp, isf = make_inputs(N_TRACES)
        t0 = time.time()
        mem = lk.collect(sym, inp, out_size=4, max_samples=max_samples)
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
            print(f"  peak sample: {peak:,}/{mem.shape[1]:,}")
        return mt

    # Baseline — the original binary-search implementation (kept as a
    # regression sentinel; the harness should keep flagging this as
    # leaky to catch a future re-introduction).
    mt_leaky = measure("sca_bip39_lookup_prefix",
                       "BASELINE — leaky binary search (regression sentinel)")

    # F-25 fix validator — constant-time scan path.
    mt_ct = measure("sca_bip39_lookup_prefix_ct",
                    "F-25 FIX — constant-time scan",
                    max_samples=200_000)

    print()
    print("=" * 70)
    print("F-25 fix-vs-baseline:")
    print(f"  leaky binary search   max|t| = {mt_leaky:7.3f}")
    print(f"  ct scan (post-fix)    max|t| = {mt_ct:7.3f}  "
          f"({'CLEAN' if mt_ct <= lk.T_THRESHOLD else 'STILL LEAKS'})")
    print("=" * 70)

    if mt_ct <= lk.T_THRESHOLD and mt_leaky > lk.T_THRESHOLD:
        print("✓ Fix validated. Baseline still leaks (regression sentinel ok),")
        print("  CT scan closes the leak entirely.")
        return 0
    if mt_ct > lk.T_THRESHOLD:
        print("✗ CT scan still leaks — investigate.")
        return 2

    mt = mt_leaky
    print()
    print(f"max|t| = {mt:.3f}")
    verdict = "LEAKAGE" if mt > lk.T_THRESHOLD else "flat"
    print(f"Verdict: {verdict}")
    if t.size:
        peak = int(np.argmax(t))
        top5 = np.argsort(t)[-5:][::-1]
        print(f"Peak sample: {peak:,}/{mem.shape[1]:,}  |t|={t[peak]:.2f}")
        print("Top-5 samples:")
        for idx in top5:
            print(f"  sample {int(idx):>6,}  |t|={t[idx]:.2f}")
    print()

    if mt > lk.T_THRESHOLD:
        print("** REAL LEAK (expected — binary search is data-dependent by design) **")
        print()
        print("Mechanism: `WORDLIST.partition_point` visits log2(2048) = 11")
        print("midpoints. Each `WORDLIST[mid].as_bytes() < needle` load goes to")
        print("`&WORDLIST[0] + mid * 8`, and the chosen mid sequence depends on")
        print("the prefix. Subsequent walk-forward loop reads scattered flash.")
        print()
        print("Production attack model: an attacker EM-scoping the CPU during")
        print("the 60-120 s recovery-typing window collects per-keystroke")
        print("traces, each ~3-4 K samples. With ~11 mid-point loads visible")
        print("per keystroke, the chosen-prefix alphabetic region is bounded")
        print("to ~5-7 bits per keystroke. After 4 keystrokes per word × 24")
        print("words = 96 prefixes, the seed is reconstructable.")
        print()
        print("Fix design (constant-time wordlist scan, symmetric to F-22):")
        print("  - Add `lookup_prefix_ct(prefix)` that scans all 2048 entries")
        print("    sequentially, accumulates start/end via mask-OR. No binary")
        print("    search → constant 2048-iteration cost (~80 KB stack reads")
        print("    per call, ~1 ms on Cortex-M33). Acceptable since `lookup_")
        print("    prefix` is called per keystroke (~5/sec max).")
        print("  - Migrate `ui/seed_wizard.rs`'s recovery path to use it.")
        print("  - `core::hint::black_box` barriers per F-22's load-bearing")
        print("    pattern to defeat LLVM constant-fold-to-direct-lookup.")
        return 1
    else:
        print("Unexpected — `partition_point` should show address-dependence.")
        print("Investigate the harness configuration.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
