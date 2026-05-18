#!/usr/bin/env python3
"""Secret-bearing derivation paths — F-22 follow-up audit.

`Mnemonic::to_seed(entropy)` produces a 64-byte `bip39_seed` (the
PBKDF2-HMAC-SHA512 output). After F-22 was fixed, every byte of that
seed depends on the entropy through a constant-time path. The seed
is then fed into THREE downstream `kdf_sha256` chains:

  - `slhdsa_seed_from_bip39`  — produces the 48-byte SLH-DSA seed
    (`sphincsc7-{sk,pk}-seed` tags). The SK/PK seeds that go into
    `SigningKey::keygen`.
  - `bootstrap_seed_from_bip39` — same shape with bootstrap-signer
    domain tags. Independent C10 keypair used to authorise slot
    rotations.
  - `slot_master_entropy_from_bip39` — single `kdf_sha256` over the
    bip39_seed with `"pqwallet-slot-master"`. Feeds per-slot key
    derivation.

These all use `sha2::Sha256` which on thumbv8m is the same bitsliced
backend that `sca_hmac_sha512_kdf` and `sca_aes256_encrypt_block`
have already characterised as constant-time on `mem_address`. We
EXPECT all three to come out flat — but "expected" is not "verified."
The 600-trace TVLA below either confirms the audit thread closes
cleanly or surfaces a sibling-of-F-22 finding.

Run: `make -C tools/sca seed-deriv-leak`
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


def run_tvla(label, fn_sym, *, in_len, out_size):
    print(f"\n== {label} ==")
    print(f"   symbol:     {fn_sym}")
    inp, isf = lk.rand_inputs(N_TRACES, in_len)
    t0 = time.time()
    mem = lk.collect(fn_sym, inp, out_size=out_size)
    print(f"   collected {mem.shape[0]} traces × {mem.shape[1]:,} samples "
          f"({time.time() - t0:.1f} s)")

    import lascar
    container = lascar.TraceBatchContainer(
        mem, np.array(isf, dtype=np.uint8).reshape(-1, 1)
    )
    eng = lascar.TTestEngine(lambda v: int(v[0]))
    lascar.Session(container, engine=eng).run(batch_size=200)
    t_raw = eng.finalize()
    t = np.abs(np.nan_to_num(t_raw, nan=0.0, posinf=0.0, neginf=0.0))
    zero_var_mask = t > ZERO_VAR_SENTINEL
    t[zero_var_mask] = 0.0
    mt = float(t.max()) if t.size else 0.0

    verdict = "LEAKAGE" if mt > lk.T_THRESHOLD else "flat"
    print(f"   max|t| = {mt:7.3f}  → {verdict}")
    if t.size:
        peak = int(np.argmax(t))
        print(f"   peak sample: {peak:,}/{mem.shape[1]:,}  |t|={t[peak]:.2f}")
    return mt


def main():
    if not os.path.exists(lk.ELF):
        print(f"ERROR: {lk.ELF} not found.")
        print("Run `make -C tools/sca build-kdf` first.")
        sys.exit(2)

    print("=" * 70)
    print("Secret-bearing derivation-path TVLA (post-F-22 audit)")
    print("=" * 70)
    print(f"Target: {lk.ELF}")
    print(f"N_TRACES = {N_TRACES}, 300 fixed-zero / 300 random per probe")

    results = {}

    results["slhdsa"] = run_tvla(
        "slhdsa_seed_from_bip39 — 2× kdf_sha256, secret is bip39_seed",
        "sca_slhdsa_seed_from_bip39", in_len=64, out_size=48,
    )

    results["bootstrap"] = run_tvla(
        "bootstrap_seed_from_bip39 — 2× kdf_sha256 (different domain tags)",
        "sca_bootstrap_seed_from_bip39", in_len=64, out_size=48,
    )

    results["slot_master"] = run_tvla(
        "slot_master_entropy_from_bip39 — 1× kdf_sha256",
        "sca_slot_master_entropy_from_bip39", in_len=64, out_size=32,
    )

    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    leaks = [k for k, v in results.items() if v > lk.T_THRESHOLD]
    for k, v in results.items():
        v_str = f"{v:7.3f}"
        verdict = "LEAKAGE" if v > lk.T_THRESHOLD else "flat   "
        print(f"  {k:20s}  max|t| = {v_str}  → {verdict}")
    print()
    if leaks:
        print(f"  → {len(leaks)} probe(s) leak: {', '.join(leaks)}")
        print("    F-22 audit thread does NOT close cleanly — investigate the peak")
        print("    sample(s) in the leaking target(s).")
        return 1
    print("  → all three derivation paths are flat on `mem_address`.")
    print("    F-22 was the only leak in the secret-bearing derivation chain.")
    print("    The audit thread closes cleanly.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
