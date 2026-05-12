#!/usr/bin/env python3
"""Side-channel *leakage* analysis (the first lascar target in tools/sca).

`rainbow` records an execution trace under a Hamming-weight leakage model;
`lascar` does the statistics. Subjects (all in the `sca-kdf-target` ELF):

  1. `sca_leaky_sbox`  — the **positive control**: `out[i] = AES_SBOX[in[i] ^ KEY[i]]`,
     i in 0..16. Has a secret-dependent table access (`&SBOX + (in^key)`), so it
     leaks via the `mem_address` channel. TVLA (fixed-vs-random input) must light
     up; a CPA over `KEY[i]` with selection `HW(&SBOX + (in[i] ^ guess))` must
     recover all 16 bytes. Confirms the lascar pipeline detects leakage when it's
     there.

  2. `sca_aes256_encrypt_block` — the AES `pqsigner-domain`'s entropy-blob wrap
     uses: `AES-256-ENC(fixed_key, plaintext)`, the `aes` crate's bitsliced
     "soft" backend on thumbv8m. TVLA (fixed-vs-random plaintext) on the
     `mem_address` channel should be **flat**: a bitsliced AES does no
     plaintext-dependent memory access (no T-tables) → no T-table-cache-timing /
     mem-address side channel. (The S-box *output value* lands in a register and
     depends on `plaintext ^ key` — that's unavoidable in any AES and needs a
     scope-based DPA on the device, not detectable by an emulated fixed-vs-random
     `mem_address` test, to characterise.)

  3. `sca_aesgcm_wrap` — a structural mirror of `encrypt_entropy_blob`'s
     AES-256-GCM wrap of the 32-byte entropy under a fixed key + nonce. TVLA
     (fixed-vs-random entropy) on the `mem_address` channel should be **flat**
     (constant-time AES + constant-time GHASH). Note: the *deployed* wrap is a
     single encryption with a fixed nonce — an attacker can't run a DPA campaign
     against it anyway; the residual is the *single-trace* leakage of the wrap
     key / keystream during that one operation (SPA/template), which this test
     doesn't probe.

Run:   donjon-sca run tools/sca/leakage_kdf.py
       (or, building the target ELF first:  make -C tools/sca kdf)
"""
import os
import sys
import warnings

os.environ.setdefault("UC_IGNORE_REG_BREAK", "1")
# lascar's TTestEngine does (m0-m1)/sqrt(...) per sample; when a channel is
# perfectly flat (zero variance — i.e. no data dependence, which is what we want
# to see) that's 0/0 → a benign RuntimeWarning. `tvla()` nan_to_num's the result.
warnings.filterwarnings("ignore", category=RuntimeWarning, module=r"lascar\..*")

import numpy as np
import cle
from rainbow.generics import rainbow_cortexm
from rainbow import TraceConfig, HammingWeight
from lascar import TraceBatchContainer, Session, TTestEngine, CpaEngine, ConsoleOutputMethod, hamming

HERE = os.path.dirname(os.path.abspath(__file__))
ELF = os.path.join(HERE, "kdf_target", "target", "thumbv8m.main-none-eabi", "release", "sca-kdf-target")
RET = 0xAAAA_AAAA
BUDGET = 200_000
SCRATCH_IN, SCRATCH_OUT = 0x6000_0000, 0x6000_1000
STACK_TOP = 0x9000_0000
# Must match SCA_LEAKY_KEY in kdf_target/src/main.rs (the AES FIPS-197 test-vector key).
SCA_LEAKY_KEY = bytes([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                       0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c])
T_THRESHOLD = 4.5  # standard TVLA leakage threshold

if not os.path.exists(ELF):
    sys.exit(f"target ELF not found: {ELF}\nbuild it first:   make -C {HERE} kdf   (or: make -C {HERE} build-kdf)")

# &SCA_AES_SBOX (for the leaky-toy CPA's mem-address selection function).
_e0 = rainbow_cortexm()
_e0.load(ELF)
_e0.map_space(STACK_TOP - 0x8000, STACK_TOP + 0x20)
_e0["sp"] = STACK_TOP
_e0["lr"] = RET
_e0.start(_e0.functions["sca_leaky_sbox_table_addr"][0], RET, count=64)
SBOX_ADDR = _e0["r0"] & 0xFFFF_FFFF
del _e0


def collect(sym, inputs):
    """Emulate `sym(in_ptr, out_ptr)` once per input; return the `mem_address`
    channel as a 2-D uint16 array (n_traces × min_len). (Only this channel —
    rainbow's per-instruction `register` tracing does a `reg_read` of every reg
    capstone names as a dest, and on unicorn 2.1.x some of those ids error out
    inside the bitsliced AES code; `mem_address` works universally and is the
    channel that matters for "is it constant-time?" anyway — the meaningful leak
    is a data-dependent memory *address*, e.g. a T-table lookup.)"""
    rows = []
    for inp in inputs:
        e = rainbow_cortexm(trace_config=TraceConfig(mem_address=HammingWeight()))
        e.load(ELF)
        e.map_space(STACK_TOP - 0x8000, STACK_TOP + 0x20)
        e["sp"] = STACK_TOP
        e[SCRATCH_IN] = bytes(inp)
        e[SCRATCH_OUT] = b"\x00" * 64
        e["r0"] = SCRATCH_IN
        e["r1"] = SCRATCH_OUT
        e["lr"] = RET
        e.start(e.functions[sym][0], RET, count=BUDGET)
        rows.append(np.array([ev["address"] for ev in e.trace if "address" in ev], dtype=np.uint16))
    ml = min(len(r) for r in rows)
    return np.array([r[:ml] for r in rows])


def tvla(label, channel_name, traces, is_fixed):
    """Welch fixed-vs-random t-test on one channel. Returns max|t|."""
    container = TraceBatchContainer(traces, np.array(is_fixed, dtype=np.uint8).reshape(-1, 1))
    eng = TTestEngine(lambda v: int(v[0]))
    Session(container, engine=eng).run(batch_size=200)
    t = np.abs(np.nan_to_num(eng.finalize()))
    mt = float(t.max()) if t.size else 0.0
    verdict = "LEAKAGE" if mt > T_THRESHOLD else "flat"
    print(f"  TVLA [{label} / {channel_name}]: max|t| = {mt:7.2f}  ({traces.shape[0]} traces, "
          f"{traces.shape[1]} samples)  → {verdict}" + (f"  @sample {int(t.argmax())}" if mt > T_THRESHOLD else ""))
    return mt


def cpa_leaky(mem_traces, inputs):
    """CPA over SCA_LEAKY_KEY using the mem-address channel: selection
    HW(&SBOX + (in[i] ^ guess)). Returns #bytes recovered correctly."""
    inputs = np.array([list(x) for x in inputs], dtype=np.uint8)
    container = TraceBatchContainer(mem_traces, inputs)
    recovered = 0
    for byte in range(16):
        def sel(v, guess, b=byte):
            return hamming(np.uint32(SBOX_ADDR) + np.uint32(v[b] ^ guess))
        eng = CpaEngine(sel, range(256), solution=SCA_LEAKY_KEY[byte])
        Session(container, engine=eng).run(batch_size=200)
        res = np.nan_to_num(eng.finalize())
        best = int(np.argmax(np.max(np.abs(res), axis=1)))
        ok = best == SCA_LEAKY_KEY[byte]
        recovered += ok
        if byte < 4 or not ok:
            print(f"    CPA byte {byte:2d}: best guess {best:#04x}  true {SCA_LEAKY_KEY[byte]:#04x}  "
                  + ("MATCH" if ok else "miss"))
    print(f"  CPA [leaky_sbox]: recovered {recovered}/16 key bytes correctly")
    return recovered


def rand_inputs(n, length):
    rng = np.random.default_rng(0xC0FFEE)
    fixed = bytes(length)  # the "fixed" class is all-zeros
    out, is_fixed = [], []
    for k in range(n):
        if k % 2 == 0:
            out.append(fixed); is_fixed.append(1)
        else:
            out.append(bytes(rng.integers(0, 256, length, dtype=np.uint8))); is_fixed.append(0)
    return out, is_fixed


N_TOY = 256       # the leaky toy leaks strongly — few traces suffice
N_CT = 600        # the constant-time subjects: enough for a first-pass "flat" claim


def constant_time_subject(name, fn_sym, in_len, what, ok_msg):
    print(f"\n== {name} ==")
    inp, isf = rand_inputs(N_CT, in_len)
    mem = collect(fn_sym, inp)
    t = tvla(name, "mem_address", mem, isf)
    if t > T_THRESHOLD:
        print(f"  → NOTE: {what} does data-dependent memory accesses (a T-table / cache mem-address side channel?).")
        print("    Investigate — the `aes` crate's bitsliced soft backend on thumbv8m was expected to be table-free.")
        return 1
    print(f"  → flat on mem_address: {ok_msg}")
    print("    (Note: the secret-mixed *register values* — S-box outputs, GHASH state — are unavoidable in any")
    print("    AES/GCM; characterising *that* needs a scope-based DPA on the running device, not an emulated")
    print("    fixed-vs-random mem-address test, which only catches data-dependent *addresses*.)")
    return 0


if __name__ == "__main__":
    rc = 0

    print("== positive control: sca_leaky_sbox (out[i] = SBOX[in[i] ^ KEY[i]]) ==")
    inp, isf = rand_inputs(N_TOY, 16)
    mem = collect("sca_leaky_sbox", inp)
    t_mem = tvla("leaky_sbox", "mem_address", mem, isf)
    if t_mem <= T_THRESHOLD:
        print("  !!! the positive control did NOT leak on mem_address — the lascar/rainbow pipeline is broken; aborting.")
        sys.exit(2)
    rand_idx = [k for k in range(len(inp)) if isf[k] == 0]   # CPA: only the random-input traces carry info
    rec = cpa_leaky(mem[rand_idx], [inp[k] for k in rand_idx])
    if rec < 14:
        print(f"  !!! CPA recovered only {rec}/16 — pipeline check failed; aborting.")
        sys.exit(2)
    print(f"  → pipeline verified: TVLA detects the leak (max|t| {t_mem:.1f} @ the SBOX[] load address); "
          f"CPA recovers {rec}/16 key bytes.")

    rc |= constant_time_subject(
        "sca_aes256_encrypt_block (the `aes` crate's AES-256, fixed key, vary plaintext)",
        "sca_aes256_encrypt_block", 16,
        "the `aes` crate's AES-256",
        "the `aes` crate's AES-256 (bitsliced soft backend on thumbv8m) is constant-time w.r.t. its plaintext —\n"
        "    no data-dependent memory accesses → no T-table / cache mem-address side channel. This is the AES\n"
        "    `pqsigner-domain`'s entropy-blob wrap uses.",
    )
    rc |= constant_time_subject(
        "sca_aesgcm_wrap (mirror of encrypt_entropy_blob: AES-256-GCM-wrap the 32-B entropy under a fixed key+nonce)",
        "sca_aesgcm_wrap", 32,
        "the entropy-blob AES-GCM wrap",
        "the entropy-blob AES-GCM wrap does no entropy-dependent memory access in emulation (constant-time AES\n"
        "    + constant-time GHASH). Caveat: the *deployed* wrap is a single encryption with a fixed nonce, so\n"
        "    there's no attacker-chosen-input DPA surface anyway — the residual is the single-trace leakage of the\n"
        "    wrap key / keystream during that one boot-time operation (SPA / template), which a scope on the\n"
        "    device would probe, not this emulated fixed-vs-random test.",
    )

    print("\nDone. (lascar TVLA + CPA on the `mem_address` channel, emulation-only — analog/register-HW leakage of")
    print("the running device still needs a scope; see tools/sca/README.md and the `lascar`/`rainbow` skills.)")
    sys.exit(rc)
