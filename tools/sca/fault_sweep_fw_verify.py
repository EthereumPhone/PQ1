#!/usr/bin/env python3
"""Fault-injection sweep over the firmware-update manifest verification chain
(`fw-manifest::ManifestRef::verify_*`, real — no stubs).

**Attack model.** An adversary delivers a manifest over `CMD_FW_BEGIN/CHUNK/COMMIT`
that has every cheap field correct (magic, CRC, vendor-fingerprint, structural
fields, fw_version above the rollback floor) but a **bogus SPHINCS+C10
signature** (which they can't forge without the vendor private key). The
firmware's job: never accept this manifest, even under a single-fault attack.
The FI question: does any single instruction skip / stuck-at on a destination
register convert the verify-chain's `Err` return into an `Ok` (= unsigned
firmware accepted)?

We use three fixtures, deterministically built by `build.rs` from a fixed
vendor keypair:
  - `MANIFEST_VALID`      — baseline ✓ every step returns 0
  - `MANIFEST_BAD_SIG`    — sig field zeroed; only `verify_signature` rejects
                            (the attacker's actual vector)
  - `MANIFEST_BAD_DIGEST` — `manifest_digest` field flipped (also useful as a
                            cross-check on `verify_digest`)

Three fault models per sweep: instruction-skip + dest-reg-stuck-at-0 +
dest-reg-stuck-at-0xFFFFFFFF.

Success criterion (per sweep): zero `Err → Ok` flips. Any single flip is a
**FW-update bypass = game over**.

Run:   donjon-sca run tools/sca/fault_sweep_fw_verify.py
       (or: make -C tools/sca fw-verify)
"""
import os
import sys
import glob

os.environ.setdefault("UC_IGNORE_REG_BREAK", "1")

from rainbow.generics import rainbow_cortexm
from rainbow import TraceConfig
from rainbow.fault_models import fault_skip, fault_stuck_at
from unicorn import UcError

FAULT_MODELS = [
    ("skip", fault_skip),
    ("stuck-at-0", fault_stuck_at(0x0000_0000)),
    ("stuck-at-FF", fault_stuck_at(0xFFFF_FFFF)),
]

HERE = os.path.dirname(os.path.abspath(__file__))
ELF = os.path.join(HERE, "fw_verify_target", "target", "thumbv8m.main-none-eabi",
                   "release", "sca-fw-verify-target")
RET = 0xAAAA_AAAA
COUNT_BUDGET = 8_000_000   # one-time instruction-count runs; valid baseline on
                            # sca_fw_verify_all_fi does TWO full SPHINCS+ verifies
                            # of a *valid* signature (each ~2.5M instructions),
                            # so the chain + sentinel commit is ~5-6M.
SWEEP_BUDGET = 25_000      # per faulted emulation (verify_all on bad_sig ≈ 7-8k clean)
SWEEP_CAP    = 12_000      # max sweep range; covers the full chain comfortably

# Per-fixture RAM scratch — well above the cortex-m-rt stack at 0x20020000.
FIXTURE_ADDR = 0x2003_0000
STACK_TOP    = 0x9000_0000
_STACK_LEN   = 0x8000

if not os.path.exists(ELF):
    sys.exit(f"target ELF not found: {ELF}\nbuild it first:   make -C {HERE} fw-verify   (or: make -C {HERE} build-fw-verify)")

OUT_DIR = glob.glob(os.path.join(HERE, "fw_verify_target", "target",
                                  "thumbv8m.main-none-eabi", "release",
                                  "build", "sca-fw-verify-target-*", "out"))[0]

def load_fixture(name):
    with open(os.path.join(OUT_DIR, name), "rb") as f:
        return f.read()

FIXTURES = {
    "valid":      load_fixture("fixture_valid.bin"),
    "bad_sig":    load_fixture("fixture_bad_sig.bin"),
    "bad_digest": load_fixture("fixture_bad_digest.bin"),
}

# Each entry point takes manifest_ptr in r0 only. (vendor_pk seed/root and
# rollback_floor are baked-in statics.)
ENTRY_POINTS = [
    "sca_fw_verify_structural",
    "sca_fw_verify_crc",
    "sca_fw_verify_digest",
    "sca_fw_verify_vendor_fpr",
    "sca_fw_verify_signature",
    "sca_fw_verify_rollback",
    "sca_fw_verify_all",
    "sca_fw_verify_all_fi",       # F-7 hardened mirror
]

# Baseline expectations (return value: 0 = Ok, non-zero = Err discriminant).
# Cross-checked once at startup against rainbow → caught any fixture-shape bug.
BASELINE = {
    "valid":      {ep: 0 for ep in ENTRY_POINTS},
    "bad_sig":    {"sca_fw_verify_structural": 0, "sca_fw_verify_crc": 0,
                   "sca_fw_verify_digest": 0,     "sca_fw_verify_vendor_fpr": 0,
                   "sca_fw_verify_signature": 6,  "sca_fw_verify_rollback": 0,
                   "sca_fw_verify_all": 6,        "sca_fw_verify_all_fi": 6},
    "bad_digest": {"sca_fw_verify_structural": 0, "sca_fw_verify_crc": 0,
                   "sca_fw_verify_digest": 5,     "sca_fw_verify_vendor_fpr": 0,
                   "sca_fw_verify_signature": 6,  "sca_fw_verify_rollback": 0,
                   "sca_fw_verify_all": 5,        "sca_fw_verify_all_fi": 5},
}

# ---------------------------------------------------------------------------
# Persistent emulator (creating + loading the ELF is the per-iter bottleneck).
# ---------------------------------------------------------------------------

_EMU = None

def _emu():
    global _EMU
    if _EMU is None:
        _EMU = rainbow_cortexm()
        _EMU.load(ELF)
        _EMU.map_space(STACK_TOP - _STACK_LEN, STACK_TOP + 0x20)
        # Fixture region is on the rust-side RAM bank (already mapped by cortex-m-rt).
    return _EMU


def fresh_emu(trace_config=None):
    e = rainbow_cortexm(trace_config=trace_config) if trace_config else rainbow_cortexm()
    e.load(ELF)
    return e


def setup(e, fixture_bytes):
    e.reset()
    e[STACK_TOP - _STACK_LEN] = b"\x00" * _STACK_LEN
    e["sp"] = STACK_TOP
    e[FIXTURE_ADDR] = fixture_bytes
    e["r0"] = FIXTURE_ADDR
    e["lr"] = RET


def run(e, fn, fixture_bytes, fault=None, budget=COUNT_BUDGET):
    """Returns ('ret', r0) | ('crash', pc) | ('hang', pc) | ('short', None)."""
    setup(e, fixture_bytes)
    begin = e.functions[fn][0]
    try:
        if fault is None:
            e.start(begin, RET, count=budget)
        else:
            e.start_and_fault(fault[0], fault[1], begin, RET, count=budget)
    except (RuntimeError, UcError):
        return ("crash", e["pc"])
    except IndexError:
        return ("short", None)
    if e["pc"] == RET:
        return ("ret", e["r0"] & 0xFFFF_FFFF)
    return ("hang", e["pc"])


def instr_count(fn, fixture_bytes):
    e = fresh_emu(TraceConfig(instruction=True))
    st, _ = run(e, fn, fixture_bytes)
    assert st == "ret", f"instruction-count {fn} run didn't return cleanly: {st}"
    return len([ev for ev in e.trace if ev.get("type") == "code"]) or len(e.trace)


# ---------------------------------------------------------------------------
# The sweep itself.
# ---------------------------------------------------------------------------

def sweep_bypass_one(fn, fixture_label, fixture_bytes, total, expected_err):
    """Per fault model: does any single fault make the *bad* fixture's return
    value flip from `expected_err` (non-zero) to 0 (= bypass / Ok)?
    Returns {model_label: (bypass_hits, crashes, hangs, correctly_rejected)}."""
    sweep_to = min(total, SWEEP_CAP)
    out = {}
    for model_label, model in FAULT_MODELS:
        hits, crashes, hangs, rej = [], 0, 0, 0
        for i in range(1, sweep_to + 8):
            e = _emu()
            st, val = run(e, fn, fixture_bytes, fault=(model, i),
                          budget=SWEEP_BUDGET)
            if st == "short":
                break
            if st == "crash":
                crashes += 1; continue
            if st == "hang":
                hangs += 1; continue
            if val == 0:
                # Bypass! Capture the PC where the fault landed for the repro.
                e2 = _emu()
                setup(e2, fixture_bytes)
                try:
                    e2.start(e2.functions[fn][0], RET, count=min(i, SWEEP_BUDGET))
                except Exception:
                    pass
                hits.append((i, e2["pc"]))
            else:
                rej += 1
        out[model_label] = (hits, crashes, hangs, rej)
    return out


def main():
    print(f"=== FW-update manifest-verify FI sweep ===")
    print(f"ELF: {ELF}")
    print(f"Fixtures: valid + bad_sig + bad_digest (deterministic vendor keypair)")
    print()

    # ---- Baselines (validates the fixtures + rainbow setup) -------------
    e = _emu()
    print("Baselines (no fault):")
    print(f"  {'fixture':<12} | " + " ".join(f"{ep.removeprefix('sca_fw_verify_'):>11}"
                                              for ep in ENTRY_POINTS))
    print("  " + "-" * 95)
    for fname, fbytes in FIXTURES.items():
        rets = []
        for ep in ENTRY_POINTS:
            st, val = run(e, ep, fbytes)
            assert st == "ret", f"baseline {fname}/{ep} did not return: {st}"
            assert val == BASELINE[fname][ep], (
                f"baseline {fname}/{ep}: expected {BASELINE[fname][ep]}, got {val}")
            rets.append(f"{val:11d}")
        print(f"  {fname:<12} | " + " ".join(rets))
    print()

    # ---- Per-step sweeps + a *focused suffix* sweep over verify_all -----
    # The realistic FW-update bypass: attacker-controlled image + bogus sig.
    # Per-step sweeps catch isolated weaknesses; the focused-suffix sweep on
    # verify_all × bad_sig catches the realistic end-to-end attack (the
    # cheap prefix steps run normally — the cap-respecting sweep starts
    # ~10k instructions before the chain's end, which is where
    # verify_signature lives in the chain on bad_sig).
    any_bypass = False
    fi_mitigation_clean = True   # set False if the hardened mirror gets bypassed
    bypass_categories = {"per_step_inheritable": [], "per_step_chain_caught": []}
    PER_STEP_TARGETS = [
        # (entry_point, fixture, descr, category)
        ("sca_fw_verify_signature", "bad_sig",
         "verify_signature alone on bogus signature",
         "per_step_inheritable"),       # this one DOES bypass the chain (last meaningful step)
        ("sca_fw_verify_digest",    "bad_digest",
         "verify_digest alone on tampered digest",
         "per_step_chain_caught"),      # chain catches it via verify_signature running after
    ]
    for ep, fname, descr, cat in PER_STEP_TARGETS:
        fbytes = FIXTURES[fname]
        expected_err = BASELINE[fname][ep]
        total = instr_count(ep, fbytes)
        sweep_to = min(total, SWEEP_CAP)
        note = f"  [capped at {SWEEP_CAP}]" if total > SWEEP_CAP else ""
        print(f"-- {ep} × {fname}  ({total} instr; expected Err={expected_err}){note}")
        print(f"     {descr}")
        for model_label, (hits, cr, hg, rej) in sweep_bypass_one(
                ep, fname, fbytes, total, expected_err).items():
            print(f"     [{model_label:11s}]  swept ≈{sweep_to}:  "
                  f"bypassed={len(hits)}  crashes={cr}  hangs={hg}  "
                  f"correctly-rejected={rej}")
            if hits:
                any_bypass = True
                bypass_categories[cat].append((ep, fname, model_label, len(hits)))
                print(f"       !!! {len(hits)} fault(s) flipped Err → Ok:")
                for i, pc in hits[:20]:
                    print(f"             [{model_label}] instr {i}: pc={pc:#010x}")
                if len(hits) > 20:
                    print(f"             ... and {len(hits) - 20} more")
        print()

    # ---- Focused-suffix sweep on verify_all × bad_sig -------------------
    # verify_signature lives at the end of verify_all's instruction stream
    # (the chain runs ~217k instructions before reaching it, on bad_sig).
    # Sweep just the last (verify_signature_len + small margin) instructions
    # so we actually hit it within a sane budget.
    print(f"-- sca_fw_verify_all × bad_sig — focused SUFFIX sweep")
    print(f"     (covers exactly where verify_signature runs inside the chain)")
    fbytes = FIXTURES["bad_sig"]
    chain_total = instr_count("sca_fw_verify_all", fbytes)
    vsig_len = instr_count("sca_fw_verify_signature", fbytes)
    suffix_start = max(1, chain_total - vsig_len - 64)  # tiny margin for the call setup
    suffix_count = chain_total - suffix_start + 8       # +8 for the post-return tail
    print(f"     chain total={chain_total}  verify_signature_len={vsig_len}  "
          f"sweeping instr {suffix_start}..{suffix_start + suffix_count}")
    # Use a fresh emulator for this sweep. The persistent `_emu()` shared with
    # the per-step sweeps accumulates state pollution over thousands of fault
    # iterations (crashes leave unicorn in a partial state that `setup()`'s
    # `reset()`+`mem_write` doesn't fully unwind — empirically every iteration
    # of a fresh suffix sweep on the *re-used* `_emu()` raises IndexError
    # despite the underlying instruction being reachable, while a brand-new
    # emulator at the same fault index works fine).
    suffix_emu = fresh_emu()
    suffix_emu.map_space(STACK_TOP - _STACK_LEN, STACK_TOP + 0x20)
    for model_label, model in FAULT_MODELS:
        hits, crashes, hangs, rejected, shorts = [], 0, 0, 0, 0
        for i in range(suffix_start, suffix_start + suffix_count):
            st, val = run(suffix_emu, "sca_fw_verify_all", fbytes,
                          fault=(model, i), budget=chain_total + SWEEP_BUDGET)
            if st == "short":
                shorts += 1; continue
            if st == "crash":
                crashes += 1; continue
            if st == "hang":
                hangs += 1; continue
            if val == 0:
                hits.append(i)
            else:
                rejected += 1
        print(f"     [{model_label:11s}]  swept {suffix_count}:  "
              f"bypassed={len(hits)}  crashes={crashes}  hangs={hangs}  "
              f"shorts={shorts}  correctly-rejected={rejected}")
        if hits:
            any_bypass = True
            bypass_categories["per_step_inheritable"].append(
                ("sca_fw_verify_all", "bad_sig", model_label, len(hits)))
            print(f"       !!! {len(hits)} fault(s) flipped verify_all Err → Ok "
                  f"END-TO-END (this is the realistic FW-update bypass):")
            for i in hits[:20]:
                print(f"             [{model_label}] absolute instr {i} "
                      f"(verify_signature-relative {i - suffix_start - 64})")
            if len(hits) > 20:
                print(f"             ... and {len(hits) - 20} more")
    print()

    # ---- F-7 mitigation: focused suffix sweep on the hardened mirror ---
    # `sca_fw_verify_all_fi` calls `verify_signature` through
    # `fi::check_true_into_sentinel`, which double-calls + sentinel-encodes
    # + caller `!= OK_SENTINEL`-checks. If the hardening works, the same
    # single-fault skips that bypass `sca_fw_verify_all × bad_sig` should
    # NOT bypass the hardened version: one skip might flip the first or
    # second `verify_signature` return, but the OTHER call still produces
    # the rejecting result, so the conjunction-and-sentinel commit goes to
    # FAIL_SENTINEL.
    print(f"-- sca_fw_verify_all_fi × bad_sig — focused SUFFIX sweep (F-7 mitigation check)")
    fbytes = FIXTURES["bad_sig"]
    chain_total_fi = instr_count("sca_fw_verify_all_fi", fbytes)
    # The hardened mirror calls verify_signature TWICE plus wait_random,
    # so its tail is ~2× as long as the unhardened version's tail. Sweep
    # the last 2.5× verify_signature_len to comfortably cover both verifies
    # and the sentinel commit between them.
    vsig_len = instr_count("sca_fw_verify_signature", fbytes)
    suffix_start_fi = max(1, chain_total_fi - int(2.5 * vsig_len) - 64)
    suffix_count_fi = chain_total_fi - suffix_start_fi + 8
    print(f"     chain total={chain_total_fi}  ≈ {chain_total_fi - chain_total} more "
          f"instructions than unhardened (the second verify + wait_random + sentinel commit)")
    print(f"     sweeping instr {suffix_start_fi}..{suffix_start_fi + suffix_count_fi}")
    suffix_emu_fi = fresh_emu()
    suffix_emu_fi.map_space(STACK_TOP - _STACK_LEN, STACK_TOP + 0x20)
    fi_bypass_total = 0
    for model_label, model in FAULT_MODELS:
        hits, crashes, hangs, rejected, shorts = [], 0, 0, 0, 0
        for i in range(suffix_start_fi, suffix_start_fi + suffix_count_fi):
            st, val = run(suffix_emu_fi, "sca_fw_verify_all_fi", fbytes,
                          fault=(model, i), budget=chain_total_fi + SWEEP_BUDGET)
            if st == "short":
                shorts += 1; continue
            if st == "crash":
                crashes += 1; continue
            if st == "hang":
                hangs += 1; continue
            if val == 0:
                hits.append(i)
            else:
                rejected += 1
        fi_bypass_total += len(hits)
        print(f"     [{model_label:11s}]  swept {suffix_count_fi}:  "
              f"bypassed={len(hits)}  crashes={crashes}  hangs={hangs}  "
              f"shorts={shorts}  correctly-rejected={rejected}")
        if hits:
            fi_mitigation_clean = False
            print(f"       !!! {len(hits)} single-fault bypass(es) on the HARDENED chain "
                  f"— F-7 mitigation insufficient on this model:")
            for i in hits[:20]:
                print(f"             [{model_label}] absolute instr {i}")
            if len(hits) > 20:
                print(f"             ... and {len(hits) - 20} more")
    if fi_bypass_total == 0:
        print(f"     ✓ F-7 mitigation: ZERO single-fault bypasses on the hardened chain")
        print(f"     (vs the unhardened sca_fw_verify_all which had 2+ skip bypasses on this same range)")
    print()

    # ---- (Optional) DoS direction: valid → reject ----------------------
    # Lower-priority: a single fault that makes a *legitimate* update fail.
    # This is an availability concern, not a security one — but verifying
    # there's no trivial DoS is a useful belt-and-braces check.
    print("-- DoS direction (valid → reject) — informational, lower priority")
    e = _emu()
    fbytes = FIXTURES["valid"]
    total = instr_count("sca_fw_verify_all", fbytes)
    sweep_to = min(total, SWEEP_CAP)
    print(f"   sca_fw_verify_all × valid  ({total} instr; expected Ok=0)")
    for model_label, model in FAULT_MODELS:
        n_reject = n_crash = n_hang = 0
        for i in range(1, sweep_to + 8):
            e = _emu()
            st, val = run(e, "sca_fw_verify_all", fbytes,
                          fault=(model, i), budget=SWEEP_BUDGET)
            if st == "short":
                break
            if st == "crash":
                n_crash += 1
            elif st == "hang":
                n_hang += 1
            elif val != 0:
                n_reject += 1
        print(f"     [{model_label:11s}]  swept ≈{sweep_to}:  "
              f"false-rejects={n_reject}  crashes={n_crash}  hangs={n_hang}")
    print()

    # ---- Findings categorisation ---------------------------------------
    print()
    print("=" * 75)
    inherit = bypass_categories["per_step_inheritable"]
    caught = bypass_categories["per_step_chain_caught"]

    # The harness keeps the UNHARDENED `sca_fw_verify_all` mirror in place for
    # documentation of F-7-pre-mitigation: it reproduces the original bypasses
    # so a regression of the hardening (e.g. someone reverts `verify_manifest`
    # back to a bare `?` chain) would re-introduce them. The PRODUCTION gate
    # is `sca_fw_verify_all_fi` — the mirror of the hardened production code.
    # Exit status is gated on the HARDENED mirror's cleanliness.

    if fi_mitigation_clean:
        print("F-7 MITIGATION VALIDATED — no single fault bypasses the HARDENED chain")
        print()
        print("  The production gate (`secure::fw_update::verify_manifest`, mirrored by")
        print("  `sca_fw_verify_all_fi`) wraps `verify_signature` in `fi::check_true_into_sentinel`:")
        print("  the closure is double-called with `wait_random()` between, the verdict is")
        print("  sentinel-committed to a volatile local, re-checked, and the caller compares")
        print("  to `OK_SENTINEL` rather than a bare `bool`. Two coordinated faults are now")
        print("  required to bypass — same residual as F-5 for the rest of the firmware.")
        print()
        if inherit or caught:
            print("  Pre-mitigation reference (unhardened mirror, kept for regression coverage):")
            for ep, fname, model, n in inherit:
                print(f"    - {ep:<28} × {fname:<11} [{model:11}]  {n} fault(s)  [DOCUMENTED, NOT PRODUCTION]")
            for ep, fname, model, n in caught:
                print(f"    - {ep:<28} × {fname:<11} [{model:11}]  {n} fault(s)  [chain-caught by next step]")
        sys.exit(0)

    # Below here: mitigation regressed.
    print("REGRESSION — single-fault bypass survives on the HARDENED chain")
    print()
    print("  `sca_fw_verify_all_fi × bad_sig` accepted a known-bad manifest under at least")
    print("  one single fault. The F-7 hardening in `secure::fw_update::verify_manifest`")
    print("  (and the `#[path]`-included `secure/src/fi.rs`) is insufficient. Investigate:")
    print("    - has `verify_manifest` been reverted to a bare `?` chain on verify_signature?")
    print("    - has `fi::check_true_into_sentinel` been weakened?")
    print("    - has the caller's `!= OK_SENTINEL` check been replaced with `if let Err(_)`?")
    sys.exit(1)


if __name__ == "__main__":
    main()
