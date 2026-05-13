#!/usr/bin/env python3
"""Fault-injection sweep over the NS-pointer validation predicates that gate
every NSC gateway entry — `secure::nsc::ptr_validate::validate_ns_{read,write}_ptr`.

**Attack model.** Every gateway command (`cmd_sign_userop`, `cmd_request_unlock`,
…) receives raw `u32` pointers from the non-secure world. Before the secure
world dereferences them it MUST prove the target range lies entirely inside an
NS-classified region, does not overlap the shared command mailbox, and that
`ptr + len` doesn't overflow. A single fault that skips any of those checks
turns an NS-supplied pointer into an arbitrary S-world read or write —
classic TrustZone bypass. (This is the FI-side analog of the rainbow upstream
`HW_analysis/pin_fault.py` Trezor demo: a small predicate whose `Err→Ok` flip
breaks an isolation boundary.)

We exercise the mirror with five scenarios per direction; only the first
should return `accept`:

  scenario           | description                                  | expected
  -------------------|----------------------------------------------|----------
  valid_ns_sram      | clearly inside NS SRAM, len reasonable       | accept
  s_world_ptr        | pointer NOT in any NS region (S-RAM-like)    | reject
  mailbox_overlap    | pointer aliases the shared command mailbox   | reject
  null_ptr           | ptr == 0                                     | reject
  overflow           | ptr + len overflows u32                      | reject

For each (entry_point, scenario) and each of the three fault models
(skip / stuck-at-0 / stuck-at-FF) we sweep every instruction of the
predicate. A single fault that flips an `reject` expectation into `accept`
is a finding — flagged F-8 (read) / F-9 (write) if either turns up.

The harness also runs the hardened mirror (`sca_ns_validate_*_fi`, which
wraps the predicate in `fi::check_true_into_sentinel`) over the same
scenarios as a side-by-side mitigation evaluation.

Run:   donjon-sca run tools/sca/fault_sweep_ns_ptr.py
       (or: make -C tools/sca ns-ptr)
"""
import os
import sys

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
ELF = os.path.join(HERE, "ns_ptr_target", "target", "thumbv8m.main-none-eabi",
                   "release", "sca-ns-ptr-target")
RET = 0xAAAA_AAAA
SWEEP_BUDGET = 5_000

# `sphincs-tz-shared` w/o stm32u585 → mps2-an505 layout:
#   NS_SRAM_BASE = 0x2802_0000  NS_SRAM_END = 0x2822_0000
#   NS_FLASH_BASE = 0x0020_0000  NS_FLASH_END = 0x0040_0000
#   SHARED_MAILBOX_BASE = 0x2802_FF00  SHARED_MAILBOX_END = 0x2802_FF18
NS_SRAM_BASE       = 0x2802_0000
SHARED_MAILBOX_BASE = 0x2802_FF00

SCENARIOS = [
    # (label, ptr, len, expected_accept[plain], expected_accept[fi])
    ("valid_ns_sram",    NS_SRAM_BASE + 0x1000, 64,    True,  True),
    ("s_world_ptr",      0x3000_0000,           64,    False, False),
    ("mailbox_overlap",  SHARED_MAILBOX_BASE,   16,    False, False),
    ("null_ptr",         0x0000_0000,           64,    False, False),
    ("overflow",         0xFFFF_FF00,           0x200, False, False),
]

# Plain (unhardened) predicates: return 1 on accept, 0 on reject.
# FI variant: returns 0xA5A5_A5A5 on accept, anything else on reject.
PLAIN_ACCEPT_VAL = 1
FI_OK_SENTINEL   = 0xA5A5_A5A5

ENTRY_POINTS = [
    # (name, expected-accept-value, is_fi_variant)
    ("sca_ns_validate_read",     PLAIN_ACCEPT_VAL, False),
    ("sca_ns_validate_write",    PLAIN_ACCEPT_VAL, False),
    ("sca_ns_validate_read_fi",  FI_OK_SENTINEL,   True),
    ("sca_ns_validate_write_fi", FI_OK_SENTINEL,   True),
]

if not os.path.exists(ELF):
    sys.exit(f"target ELF not found: {ELF}\nbuild it first:   make -C {HERE} ns-ptr")

# ---------------------------------------------------------------------------
# Emulator setup — one per sweep to dodge cross-iteration state pollution
# ---------------------------------------------------------------------------

def fresh_emu(trace_config=None):
    e = rainbow_cortexm(trace_config=trace_config) if trace_config else rainbow_cortexm()
    e.load(ELF)
    return e

STACK_TOP = 0x9000_0000

def setup(e):
    e.reset()
    e["sp"] = STACK_TOP

def call(e, fn, ptr, length):
    setup(e)
    e["r0"] = ptr & 0xFFFF_FFFF
    e["r1"] = length & 0xFFFF_FFFF
    e["lr"] = RET
    begin = e.functions[fn][0]
    try:
        e.start(begin, RET, count=20_000)
    except (RuntimeError, UcError):
        return None
    if e["pc"] != RET:
        return None
    return e["r0"] & 0xFFFF_FFFF

def call_fault(e, fn, ptr, length, fault_model, fault_idx):
    setup(e)
    e["r0"] = ptr & 0xFFFF_FFFF
    e["r1"] = length & 0xFFFF_FFFF
    e["lr"] = RET
    begin = e.functions[fn][0]
    try:
        e.start_and_fault(fault_model, fault_idx, begin, RET, count=SWEEP_BUDGET)
    except (RuntimeError, UcError):
        return ("crash", None)
    except IndexError:
        return ("short", None)
    if e["pc"] == RET:
        return ("ret", e["r0"] & 0xFFFF_FFFF)
    return ("hang", e["pc"])

def instr_count(fn, ptr, length):
    e = fresh_emu(TraceConfig(instruction=True))
    r = call(e, fn, ptr, length)
    if r is None:
        return 0
    return len([ev for ev in e.trace if ev.get("type") == "code"])

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=== NS-pointer validation FI sweep ===")
    print(f"ELF: {ELF}")
    print()

    # Baselines (no fault). Every scenario × every entry-point — confirms the
    # validator behaves as the harness expects before we start faulting.
    print("Baselines (no fault):")
    print(f"  {'scenario':<18}", end="")
    for ep, _, _ in ENTRY_POINTS:
        print(f" | {ep.removeprefix('sca_ns_validate_'):>11}", end="")
    print()
    print("  " + "-" * 90)
    e = fresh_emu()
    for label, ptr, length, plain_ok, fi_ok in SCENARIOS:
        print(f"  {label:<18}", end="")
        for ep, accept_val, is_fi in ENTRY_POINTS:
            r = call(e, ep, ptr, length)
            expected_accept = fi_ok if is_fi else plain_ok
            ok_marker = ""
            if r is None:
                disp = "ERR"
            else:
                got_accept = (r == accept_val)
                if got_accept != expected_accept:
                    ok_marker = " !"
                disp = f"0x{r:08x}"
            print(f" | {disp:>11}{ok_marker}", end="")
        print()
    print()

    # Full sweep — for each (ep, scenario), sweep over all instructions × fault models.
    any_bypass = False
    bypasses_plain = []  # (ep, scenario_label, model, count)
    bypasses_fi    = []
    for ep, accept_val, is_fi in ENTRY_POINTS:
        for label, ptr, length, plain_ok, fi_ok in SCENARIOS:
            expected_accept = fi_ok if is_fi else plain_ok
            # Skip baselines that should accept; we sweep ONLY the reject-
            # cases (these are the security-critical "can a fault flip
            # reject → accept" tests).
            if expected_accept:
                continue
            total = instr_count(ep, ptr, length)
            if total == 0:
                print(f"-- {ep} × {label}: instruction count failed; skipping")
                continue
            print(f"-- {ep} × {label}  (len={total} instr)")
            for model_label, model in FAULT_MODELS:
                e = fresh_emu()  # fresh per model — dodges cross-state pollution
                hits, crashes, hangs, shorts, rejected = [], 0, 0, 0, 0
                for i in range(1, total + 8):
                    st, val = call_fault(e, ep, ptr, length, model, i)
                    if st == "short":
                        break
                    if st == "crash":
                        crashes += 1; continue
                    if st == "hang":
                        hangs += 1; continue
                    if val == accept_val:
                        hits.append((i, val))
                    else:
                        rejected += 1
                print(f"     [{model_label:11s}]  swept ≈{total}:  "
                      f"bypassed={len(hits)}  crashes={crashes}  hangs={hangs}  "
                      f"correctly-rejected={rejected}")
                if hits:
                    any_bypass = True
                    if is_fi:
                        bypasses_fi.append((ep, label, model_label, len(hits)))
                    else:
                        bypasses_plain.append((ep, label, model_label, len(hits)))
                    print(f"       !!! {len(hits)} fault(s) accepted a bad pointer:")
                    for i, val in hits[:20]:
                        print(f"             [{model_label}] instr {i}: r0=0x{val:08x}")
                    if len(hits) > 20:
                        print(f"             ... and {len(hits) - 20} more")
            print()

    # Findings
    print("=" * 75)
    if not any_bypass:
        print("ALL SWEEPS CLEAN — every reject-scenario stays a reject under every fault")
        print("model on both the plain and the FI-hardened predicates.")
        sys.exit(0)

    if bypasses_plain:
        print("FINDING — NS-pointer validation bypass on the PLAIN (production) predicate:")
        for ep, scen, model, n in bypasses_plain:
            print(f"    - {ep:<28} × {scen:<16} [{model:11}]  {n} fault(s)")
        print()
        print("  Production exposure: every gateway command (`cmd_*` in secure/src/nsc/)")
        print("  calls `NsPtr::validate_{read,write}` (which dispatches to these predicates)")
        print("  before dereferencing. A single fault here lets an NS-supplied pointer")
        print("  point into secure RAM / the shared mailbox → arbitrary S-world R/W,")
        print("  potentially leaking the master seed cache, slot key cache, or PIN-attempt")
        print("  flash address.")
        print()
        print("  Hardening: wrap `validate_ns_{read,write}_ptr` calls in")
        print("  `fi::check_true_into_sentinel` (the `sca_ns_validate_*_fi` mirror shows")
        print("  this pattern; raises the bar from 1 to ~2 coordinated faults). Migrate")
        print("  `NsPtr::validate_{read,write}` callers (or the `NsPtr::validate_*` methods")
        print("  themselves) to compare a sentinel rather than handle a `bool` Result.")

    if bypasses_fi:
        print()
        print("FINDING — even the FI-hardened predicate was bypassed:")
        for ep, scen, model, n in bypasses_fi:
            print(f"    - {ep:<28} × {scen:<16} [{model:11}]  {n} fault(s)")
        print("  Investigate fi::check_true_into_sentinel's behaviour with this caller shape.")

    sys.exit(1 if bypasses_plain else 0)


if __name__ == "__main__":
    main()
