#!/usr/bin/env python3
"""Fault-injection sweep over the off-chain gap + combined-cap enforcement
gates that bound a single SPHINCS+C10 slot key to MAX_SLOT_USES = 65,536
signatures per chain. A single-fault bypass of either gate erodes this
structural invariant — which in turn underwrites (a) the SPHINCS+ subset-
resilience margin, and (b) the F-9 FORS-leaf-index leakage budget (the
"transparent" leak's exposure is at most 65 k observations per slot key).

Production gates (verbatim from `secure/src/nsc/cmd_sign_offchain.rs:202-223`):

  let gap = local_offchain.saturating_sub(last_userop);
  if gap >= MAX_OFFCHAIN_GAP {  // 100
      return NscStatus::OffchainGapExceeded as u32;
  }
  let new_count = match local_offchain.checked_add(1) {
      Some(v) => v,
      None => return NscStatus::OffchainCapExceeded as u32,
  };
  if new_count > MAX_SLOT_USES {  // 65_536
      return NscStatus::OffchainCapExceeded as u32;
  }

Mirror returns:
  0 = accept (proceed to sign)  ← the value a faulted reject would flip TO
  1 = gap rejected
  2 = cap rejected (overflow or > MAX_SLOT_USES)

The sweep tests every (scenario, fault model, instruction) combination; any
case where a reject-scenario returns 0 = single-fault bypass. Plain mirror
should find some bypasses (production has no FI hardening on these gates);
the FI mirror (sentinel-wrapped) should be clean.
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
ELF = os.path.join(HERE, "cap_target", "target", "thumbv8m.main-none-eabi",
                   "release", "sca-cap-target")
RET = 0xAAAA_AAAA
SWEEP_BUDGET = 50_000
STACK_TOP = 0x9000_0000

MAX_OFFCHAIN_GAP = 100
MAX_SLOT_USES = 65_536

# Scenarios: (label, local_offchain, last_userop, expected_plain, expected_fi)
# expected = the value the gate SHOULD return (0=accept, 1=gap-reject, 2=cap-reject).
SCENARIOS = [
    ("valid_accept",     10,                   5,                  0, 0),
    ("gap_at_boundary",  MAX_OFFCHAIN_GAP,     0,                  1, 1),  # gap = 100 = REJECT (>=)
    ("gap_well_over",    500,                  0,                  1, 1),
    ("cap_at_max",       MAX_SLOT_USES,        MAX_SLOT_USES,      2, 2),  # new = MAX+1 → cap reject
    ("cap_overflow",     0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF, 2, 2),  # gap=0; new overflows
]

ENTRY_POINTS = [
    # (name, accept_value, is_fi_variant)
    ("sca_cap_check_plain",        0, False),
    ("sca_cap_check_fi",           0, True),
    ("sca_cap_check_callsite_fi",  0, True),   # F-10 production fix shape
]

if not os.path.exists(ELF):
    sys.exit(f"target ELF not found: {ELF}\nbuild it first:   make -C {HERE} cap")


def fresh_emu(trace_config=None):
    e = rainbow_cortexm(trace_config=trace_config) if trace_config else rainbow_cortexm()
    e.load(ELF)
    return e


def setup_args(e, local_offchain: int, last_userop: int):
    """ARM AAPCS calling convention for two u64 arguments: r0,r1 carry the
    first u64 (low,high words); r2,r3 carry the second."""
    e.reset()
    e["sp"] = STACK_TOP
    e["r0"] = local_offchain & 0xFFFF_FFFF
    e["r1"] = (local_offchain >> 32) & 0xFFFF_FFFF
    e["r2"] = last_userop & 0xFFFF_FFFF
    e["r3"] = (last_userop >> 32) & 0xFFFF_FFFF
    e["lr"] = RET


def call(e, fn, local_offchain, last_userop):
    setup_args(e, local_offchain, last_userop)
    try:
        e.start(e.functions[fn][0], RET, count=SWEEP_BUDGET)
    except (RuntimeError, UcError):
        return None
    if e["pc"] != RET:
        return None
    return e["r0"] & 0xFFFF_FFFF


def call_fault(e, fn, local_offchain, last_userop, fault_model, fault_idx):
    setup_args(e, local_offchain, last_userop)
    try:
        e.start_and_fault(fault_model, fault_idx, e.functions[fn][0], RET,
                          count=SWEEP_BUDGET)
    except (RuntimeError, UcError):
        return ("crash", None)
    except IndexError:
        return ("short", None)
    if e["pc"] != RET:
        return ("hang", None)
    return ("ret", e["r0"] & 0xFFFF_FFFF)


def instr_count(fn, local_offchain, last_userop):
    e = fresh_emu(TraceConfig(instruction=True))
    r = call(e, fn, local_offchain, last_userop)
    if r is None:
        return 0
    return len([ev for ev in e.trace if ev.get("type") == "code"])


def main():
    print("=== Off-chain gap + combined-cap enforcement FI sweep ===")
    print(f"ELF: {ELF}")
    print(f"MAX_OFFCHAIN_GAP={MAX_OFFCHAIN_GAP}, MAX_SLOT_USES={MAX_SLOT_USES}")
    print()

    # Baselines (no fault) — confirm fixture behaviour matches expected
    print("Baselines (no fault):")
    print(f"  {'scenario':<18}", end="")
    for ep, _, _ in ENTRY_POINTS:
        print(f" | {ep.removeprefix('sca_cap_check_'):>11}", end="")
    print()
    print("  " + "-" * 50)
    e = fresh_emu()
    for label, local, last, exp_plain, exp_fi in SCENARIOS:
        print(f"  {label:<18}", end="")
        for ep, accept_val, is_fi in ENTRY_POINTS:
            r = call(e, ep, local, last)
            expected = exp_fi if is_fi else exp_plain
            mark = "" if r == expected else f" !!(expected {expected})"
            print(f" | {('ERR' if r is None else str(r)):>11}{mark}", end="")
        print()
    print()

    # Sweep — for each entry point × reject scenario × fault model.
    any_plain_bypass = False
    any_fi_bypass = False
    bypasses_plain = []
    bypasses_fi = []

    for ep, accept_val, is_fi in ENTRY_POINTS:
        for label, local, last, exp_plain, exp_fi in SCENARIOS:
            expected = exp_fi if is_fi else exp_plain
            if expected == accept_val:
                continue   # skip baselines — only sweep REJECT scenarios
            total = instr_count(ep, local, last)
            if total == 0:
                print(f"-- {ep} × {label}: baseline failed, skipping")
                continue
            print(f"-- {ep} × {label}  (len={total} instr; expected={expected})")
            for model_label, model in FAULT_MODELS:
                e = fresh_emu()
                hits, crashes, hangs, shorts, rejected = [], 0, 0, 0, 0
                for i in range(1, total + 8):
                    st, val = call_fault(e, ep, local, last, model, i)
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
                    bucket = bypasses_fi if is_fi else bypasses_plain
                    bucket.append((ep, label, model_label, len(hits)))
                    if is_fi:
                        any_fi_bypass = True
                    else:
                        any_plain_bypass = True
                    print(f"       !!! {len(hits)} fault(s) flipped reject → accept "
                          f"(allow signing past the cap):")
                    for i, val in hits[:10]:
                        print(f"             [{model_label}] instr {i}: ret={val}")
                    if len(hits) > 10:
                        print(f"             ... and {len(hits) - 10} more")
            print()

    # ---- Findings ----
    print("=" * 75)
    if not any_plain_bypass and not any_fi_bypass:
        print("ALL SWEEPS CLEAN — no single fault bypasses either gate (plain or hardened).")
        sys.exit(0)

    if any_fi_bypass:
        print("REGRESSION — FI-hardened predicate was bypassed:")
        for ep, scen, model, n in bypasses_fi:
            print(f"    - {ep:<24} × {scen:<18} [{model:11}]  {n} fault(s)")
        print()
        print("  The sentinel-wrap pattern that protected F-7 / F-8 doesn't here.")
        print("  Investigate fi::check_true_into_sentinel's interaction with the u64-arg shape.")
        sys.exit(1)

    if any_plain_bypass:
        print("FINDING — plain (production) gate is single-fault-bypassable:")
        for ep, scen, model, n in bypasses_plain:
            print(f"    - {ep:<24} × {scen:<18} [{model:11}]  {n} fault(s)")
        print()
        print("  Production exposure: a fault here lets the firmware sign past the 65k")
        print("  per-slot-per-chain cap, eroding the SPHINCS+ subset-resilience margin and")
        print("  the F-9 FORS-leaf-index leakage budget.")
        print()
        print("  The FI-hardened mirror (`sca_cap_check_fi`) shows the fix: wrap each gate")
        print("  in `pqsigner_fi::check_true_into_sentinel`. Production fix would be the same")
        print("  pattern applied in `secure/src/nsc/cmd_sign_offchain.rs`.")
        sys.exit(0 if not any_fi_bypass else 1)


if __name__ == "__main__":
    main()
