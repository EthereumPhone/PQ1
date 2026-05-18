#!/usr/bin/env python3
"""SAES-CMAC wrapper leakage analysis.

**What this tests**: the production CMAC wrapper (`secure/src/cmac.rs::
cmac_generic` and `kdf_cmac_counter_generic`), `#[path]`-included verbatim
into `tools/sca/saes_kdf_target/`. The AES primitive itself is a SOFTWARE
AES-256 here (the `aes` crate's bitsliced soft backend, same one
`pqsigner-domain`'s AES-GCM falls through to) because rainbow / Unicorn
cannot model the STM32U585 SAES coprocessor that the production code uses
via `KeySel::Dhuk`.

**Measurement channel**: rainbow's `mem_address` Hamming-weight stream
— records the HW of each memory access ADDRESS, not the loaded VALUE.
A TVLA flip means the function makes a memory access whose ADDRESS
depends on the variable input (the canonical example being a T-table
implementation where `out = SBOX[in[i] ^ key[i]]` indexes into a table
at an address that's both key- and input-dependent). The bitsliced
software AES on thumbv8m has NO T-tables, so no key-dependent
addresses — TVLA is expected to flatline on the AES itself. The
INTERESTING question this test answers is whether the WRAPPER
(`cmac_generic`'s `double_l` / CBC XOR / branch dispatch, plus
`kdf_cmac_counter_generic`'s label-and-counter packing) introduces
any input-dependent memory addresses.

**The four TVLA modes**:

1. `sca_saes_cmac` vary KEY, fix message — detects samples whose address
   depends on the key.
2. `sca_saes_cmac` vary MESSAGE, fix key — detects samples whose address
   depends on the message.
3. `sca_saes_kdf_one_block` vary KEY, fix label — same as (1) plus the
   KDF wrapper's label-packing.
4. `sca_saes_kdf_one_block` vary LABEL, fix key — same as (2) for the
   KDF wrapper.

**Production interpretation**: in production, DHUK lives in SAES silicon
registers; the CPU never sees its bytes. The wrapper code on the CPU
is byte-identical to what we test here. A clean result on all four
modes rules out one specific leak class (data-dependent memory
addresses in the wrapper) at audit-grade emulation resolution.
Power/EM leakage on register VALUES, and the SAES coprocessor's own
side-channel surface, require on-silicon SCA with a scope.

Run: `make -C tools/sca saes-kdf`
"""
import os
import sys
import time

os.environ.setdefault("UC_IGNORE_REG_BREAK", "1")

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# Reuse the trace-collection + TVLA primitives from leakage_kdf — same
# rainbow-driven emulator, same `tvla()` definition + `T_THRESHOLD = 4.5`.
import leakage_kdf as lk  # noqa: E402

ELF = os.path.join(
    HERE, "saes_kdf_target", "target", "thumbv8m.main-none-eabi", "release",
    "sca-saes-kdf-target",
)

N_TRACES = 600
KEY_LEN = 32
MSG_LEN = 16
LABEL_LEN = 16
INPUT_LEN = KEY_LEN + MSG_LEN  # both sca_saes_cmac and sca_saes_kdf use 48-B inputs
TAG_LEN = 16


def vary_inputs(n: int, *, vary_key: bool, vary_msg: bool, key_len=KEY_LEN, msg_len=MSG_LEN):
    """Build `n` inputs of `key_len + msg_len` bytes each. Half the inputs
    are the all-zero "fixed" reference; the other half randomise the
    selected halves.

    - `vary_key=True, vary_msg=False`: bytes [0..key_len) flip random; tail fixed.
    - `vary_key=False, vary_msg=True`: bytes [key_len..) flip random; head fixed.
    - both True: BOTH halves randomise.
    """
    rng = np.random.default_rng(0xDADDA10C)
    fixed = bytes(key_len + msg_len)
    out, is_fixed = [], []
    for k in range(n):
        if k % 2 == 0:
            out.append(fixed)
            is_fixed.append(1)
        else:
            buf = bytearray(fixed)
            if vary_key:
                buf[:key_len] = bytes(rng.integers(0, 256, key_len, dtype=np.uint8))
            if vary_msg:
                buf[key_len:key_len + msg_len] = bytes(
                    rng.integers(0, 256, msg_len, dtype=np.uint8)
                )
            out.append(bytes(buf))
            is_fixed.append(0)
    return out, is_fixed


def run_tvla(label: str, fn_sym: str, *, vary_key: bool, vary_msg: bool,
             msg_len=MSG_LEN, n_traces=N_TRACES):
    print(f"\n== {label} ==")
    print(f"   symbol:     {fn_sym}")
    print(f"   variation:  key={vary_key}  msg={vary_msg}")
    print(f"   {n_traces} traces, INPUT_LEN={KEY_LEN + msg_len} B")

    inp, isf = vary_inputs(n_traces, vary_key=vary_key, vary_msg=vary_msg,
                           msg_len=msg_len)
    t0 = time.time()
    mem = lk.collect(fn_sym, inp, out_size=TAG_LEN)
    elapsed = time.time() - t0
    print(f"   collected {mem.shape[0]} × {mem.shape[1]:,} samples in "
          f"{elapsed:.1f} s")

    mt = lk.tvla(label, "mem_address", mem, isf)
    return mt, mem, isf


def main():
    if not os.path.exists(ELF):
        print(f"ERROR: {ELF} not found.")
        print("Run `make -C tools/sca build-saes-kdf` first.")
        sys.exit(2)

    # Point lk.ELF at our target — collect() reads `lk.ELF` directly per-worker.
    lk.ELF = ELF

    print("====================================================================")
    print("SAES-CMAC wrapper leakage analysis (cmac_generic + kdf_cmac_counter)")
    print("====================================================================")
    print(f"ELF: {ELF}")

    rc = 0

    # Test 1: vary KEY only — every key-dependent sample is a candidate
    # wrapper-leak finding. Expected: leakage CONFINED to AES round samples
    # (software AES will leak its key, but the wrapper's bookkeeping
    # should not).
    mt_cmac_k, _, _ = run_tvla(
        "sca_saes_cmac — VARY KEY (32 B), FIX MSG (16 zeros)",
        "sca_saes_cmac",
        vary_key=True, vary_msg=False,
    )
    if mt_cmac_k > lk.T_THRESHOLD:
        print(f"   → LEAKAGE detected (max|t| > {lk.T_THRESHOLD}).")
        print(f"     Worth checking whether the peak sample falls INSIDE an AES")
        print(f"     call, or in the wrapper's `double_l` / CBC-XOR / branch-")
        print(f"     dispatch logic. The latter would be a real wrapper bug.")
    else:
        print(f"   → flat on mem_address. The `aes` crate's bitsliced soft")
        print(f"     backend on thumbv8m has no data-dependent memory accesses")
        print(f"     (no T-table lookups), and `cmac_generic`/`kdf_cmac_counter_"
              f"generic`")
        print(f"     don't introduce any either. This is the same clean-signal")
        print(f"     result `leakage_kdf.py` already reports for `sca_aes256_"
              f"encrypt_block`")
        print(f"     and `sca_aesgcm_wrap`.")

    # Test 2: vary MSG only — message-dependent samples are expected
    # (wrapper legitimately processes message → tag). Length-dispatch
    # branches in cmac_generic are keyed on length, which is fixed in
    # this test, so they should NOT flip.
    mt_cmac_m, _, _ = run_tvla(
        "sca_saes_cmac — FIX KEY (32 zeros), VARY MSG (16 B)",
        "sca_saes_cmac",
        vary_key=False, vary_msg=True,
    )
    if mt_cmac_m > lk.T_THRESHOLD:
        print(f"   → mem_address-leakage on message variation. Expected at the")
        print(f"     message load + CBC XOR + AES rounds. Wrapper's branch-dispatch")
        print(f"     should NOT contribute because msg length is fixed at 16 B.")
    else:
        print(f"   → flat on mem_address.")

    # Test 3: same two variations on the FULL KDF path
    # (`kdf_cmac_counter_generic` wraps `cmac_generic` with label+counter
    # packing). Extra wrapper code: scratch[..label.len()].copy_from_slice(label);
    # scratch[label.len()] = counter; bounds checks; loop control.
    mt_kdf_k, _, _ = run_tvla(
        "sca_saes_kdf_one_block — VARY KEY (32 B), FIX LABEL (16 zeros)",
        "sca_saes_kdf_one_block",
        vary_key=True, vary_msg=False, msg_len=LABEL_LEN,
    )

    mt_kdf_l, _, _ = run_tvla(
        "sca_saes_kdf_one_block — FIX KEY (32 zeros), VARY LABEL (16 B)",
        "sca_saes_kdf_one_block",
        vary_key=False, vary_msg=True, msg_len=LABEL_LEN,
    )

    # Summary.
    print()
    print("====================================================================")
    print("SUMMARY")
    print("====================================================================")
    print(f"  sca_saes_cmac          vary key:   max|t| = {mt_cmac_k:7.2f}")
    print(f"  sca_saes_cmac          vary msg:   max|t| = {mt_cmac_m:7.2f}")
    print(f"  sca_saes_kdf_one_block vary key:   max|t| = {mt_kdf_k:7.2f}")
    print(f"  sca_saes_kdf_one_block vary label: max|t| = {mt_kdf_l:7.2f}")
    print()
    print("  Interpretation:")
    print(f"    rainbow's `mem_address` channel records the Hamming weight of")
    print(f"    memory access ADDRESSES, not loaded VALUES. A clean (max|t| ≤")
    print(f"    {lk.T_THRESHOLD}) result on all four modes means: NEITHER the")
    print(f"    bitsliced software AES NOR the CMAC wrapper makes a memory")
    print(f"    access whose ADDRESS depends on key or message. That's the")
    print(f"    constant-time-on-mem-address property we want (and is the same")
    print(f"    result `leakage_kdf.py` reports for the AES-GCM entropy-wrap).")
    print()
    print("  What this does NOT cover:")
    print(f"    - Power/EM leakage on register VALUES (S-box outputs, CBC")
    print(f"      state). Real silicon SCA with a scope is needed for that.")
    print(f"    - Production SAES coprocessor leakage. The SAES has its own")
    print(f"      side-channel surface that emulation cannot model.")
    print()
    print("  PRODUCTION interpretation:")
    print(f"    DHUK lives in SAES silicon registers; the wrapper code on the")
    print(f"    CPU is the same in production. This test rules out one specific")
    print(f"    class of leak (data-dependent memory addresses in the wrapper)")
    print(f"    at audit-grade emulation resolution. Remaining production-")
    print(f"    surface SCA work belongs on real silicon under a scope.")

    return rc


if __name__ == "__main__":
    sys.exit(main())
