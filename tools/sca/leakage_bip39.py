#!/usr/bin/env python3
"""BIP-39 entropy→seed leakage analysis.

`Mnemonic::from_entropy(entropy).to_seed("")` is the FIRST CPU operation
that touches raw 32-byte BIP-39 entropy during recovery / first-unlock.
If it leaks via `mem_address`, an attacker scoping the CPU's address
bus (cache misses, prefetch units, DMA descriptors visible to
power/EM) can reconstruct entropy bits from a single boot trace —
bypassing every downstream defence (FI guards, dual-SE split,
hardware PIN gate).

The hot suspect: `WORDLIST[index]` lookups. The BIP-39 derivation
splits (entropy ‖ 8-bit-checksum) into 24 × 11-bit indices, then
loads `WORDLIST[index]` for each. Each load is at
`WORDLIST_BASE + index * sizeof(&str)`, so the low bits of the load
ADDRESS encode the secret index. Classic T-table-style address leak.

Two TVLA modes:

  1. `sca_bip39_word_indices` — the SHA-256(entropy) checksum +
     11-bit index unpacking, no wordlist access. Expected flat
     (loop index is loop-counter-derived, NOT entropy-derived).

  2. `sca_bip39_wordlist_lookup` — same as (1) plus the per-word
     `WORDLIST[index]` load. THIS is where address leakage shows up
     if `wordlist::WORDLIST` is a contiguous `[&str; 2048]` (the
     production layout).

For each non-flat result we report the PEAK SAMPLE position so the
finding is actionable (disassemble around that sample to see the
exact load instruction).

Run: `make -C tools/sca bip39-leak`
"""
import os
import sys
import time

os.environ.setdefault("UC_IGNORE_REG_BREAK", "1")

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import leakage_kdf as lk  # noqa: E402

N_TRACES = 600


def make_inputs(n: int):
    """Half-fixed (zeros), half random — same shape as `rand_inputs`."""
    return lk.rand_inputs(n, 32)


def run_tvla(label: str, fn_sym: str, *, out_size=48, max_samples=None):
    print(f"\n== {label} ==")
    print(f"   symbol:     {fn_sym}")
    inp, isf = make_inputs(N_TRACES)
    t0 = time.time()
    mem = lk.collect(fn_sym, inp, out_size=out_size, max_samples=max_samples)
    elapsed = time.time() - t0
    print(f"   collected {mem.shape[0]} traces × {mem.shape[1]:,} samples "
          f"({elapsed:.1f} s)")

    mt = lk.tvla(label, "mem_address", mem, isf)

    # Always report the peak so a "flat" result is also actionable.
    import lascar
    container = lascar.TraceBatchContainer(
        mem, np.array(isf, dtype=np.uint8).reshape(-1, 1)
    )
    eng = lascar.TTestEngine(lambda v: int(v[0]))
    lascar.Session(container, engine=eng).run(batch_size=200)
    t = np.abs(np.nan_to_num(eng.finalize()))
    if t.size:
        peak = int(np.argmax(t))
        # Top-5 peaks across the trace for spatial localisation.
        top5 = np.argsort(t)[-5:][::-1]
        print(f"   peak sample: {peak:,}/{mem.shape[1]:,}  |t|={t[peak]:.2f}")
        print(f"   top-5 samples:")
        for idx in top5:
            print(f"     sample {int(idx):>6,}  |t|={t[idx]:.2f}")
    return mt


def main():
    if not os.path.exists(lk.ELF):
        print(f"ERROR: {lk.ELF} not found.")
        print("Run `make -C tools/sca build-kdf` first.")
        sys.exit(2)

    print("=" * 70)
    print("BIP-39 entropy→seed leakage TVLA")
    print("=" * 70)

    # The non-wordlist mirror: SHA-256 + 11-bit-index unpacking only.
    # Establishes a baseline for "what does the entropy-handling code
    # path look like without the wordlist lookup".
    mt_indices = run_tvla(
        "sca_bip39_word_indices — SHA-256(entropy) + 11-bit unpacking",
        "sca_bip39_word_indices", out_size=48,
    )
    if mt_indices > lk.T_THRESHOLD:
        print(f"   → LEAKAGE (max|t| > {lk.T_THRESHOLD}). Unexpected — neither")
        print(f"     SHA-256 nor the loop-counter-keyed index unpacking should")
        print(f"     have entropy-address dependence. Investigate the peak.")
    else:
        print(f"   → flat. Baseline established: the SHA-256 + unpacking path")
        print(f"     itself doesn't address-leak.")

    # The full suspect: lookup added on top.
    mt_lookup = run_tvla(
        "sca_bip39_wordlist_lookup — index derivation + WORDLIST[idx]",
        "sca_bip39_wordlist_lookup", out_size=48,
    )
    if mt_lookup > lk.T_THRESHOLD:
        print()
        print("=" * 70)
        print("** LEAKAGE FINDING **")
        print("=" * 70)
        print(f"  max|t| = {mt_lookup:.2f} (> {lk.T_THRESHOLD} threshold)")
        print(f"  Where: see top-5 peaks above.")
        print(f"  Mechanism (suspect): each `WORDLIST[idx]` load goes to")
        print(f"  `WORDLIST_BASE + idx * sizeof(&str)`. The address bits")
        print(f"  encode the secret idx, and rainbow's mem_address channel")
        print(f"  records the Hamming weight of every load address.")
        print(f"  Impact: an attacker with the same channel resolution on")
        print(f"  real silicon (power/EM scoping of the address bus) can")
        print(f"  recover ~11 bits per indexed load × 24 loads = ~264 bits")
        print(f"  ≫ the 256-bit BIP-39 entropy. Total seed reconstruction")
        print(f"  from a single boot trace.")
        print(f"  Mitigations: (a) constant-time wordlist scan (load every")
        print(f"  entry, conditional-mask on idx — defeats address-side leak)")
        print(f"  (b) drop the wordlist from the seed-derivation path entirely")
        print(f"  — compute PBKDF2 over a different deterministic encoding")
        print(f"  that doesn't need word lookups (requires a BIP-39 protocol")
        print(f"  divergence; not viable). (a) is the realistic fix.")
        print(f"  Production note: this affects the first-unlock path which")
        print(f"  runs `derive_keypair_from_entropy` → `with_bip39_seed` →")
        print(f"  `Mnemonic::to_seed`. Only the COLD-BOOT trace exposes it.")
        return 1
    else:
        print(f"   → flat (max|t| = {mt_lookup:.2f}). The wordlist lookup")
        print(f"     either doesn't address-leak, OR the lookup samples")
        print(f"     are outside the captured trace window, OR the layout")
        print(f"     of WORDLIST in flash is more constant-time than naive")
        print(f"     analysis suggests.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
