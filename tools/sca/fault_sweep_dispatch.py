#!/usr/bin/env python3
"""Fault-injection sweep over the Type 1 / Type 2 dispatch logic in
cmd_sign_userop.rs:160-236. The companion provides `flags` and `slot_index`;
the firmware parses two booleans (`include_init_code`, `register_slot`) and
runs three sanity checks before deciding which sigs to emit.

**The bypass class we want to detect:**

  (a) User sends flags=0 (Type 2 only). A single fault flips
      `register_slot` to true → firmware silently emits a Type 1, which
      installs an attacker-controlled slot key at slot_index. On-chain
      `validateUserOp` re-validates the bootstrap C10 sig, so a faulted
      Type 1 still has to be paired with a valid bootstrap-key signature —
      but the unfaulted firmware would produce that. Blast radius: bounded
      by on-chain re-validation; worth confirming firmware-side robustness.

  (b) User sends flags=REGISTER_SLOT|slot=1 (legit rotation). A single
      fault skips the `register_slot && slot_idx == 0` check → if attacker
      also clamps slot_idx to 0, the firmware tries to register slot 0
      (which would conflict with the factory-pre-registered slot 0).

  (c) Both flags set simultaneously (incompatible). A fault skips the
      mutex check → firmware proceeds with ambiguous behaviour.

Mirror returns:
  0 = TYPE_2_ONLY     1 = TYPE_1_PLUS_2     2 = DEPLOY     99 = REJECTED

Test scenarios: each row has a (flags, slot_index, expected_plain, expected_fi).
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
ELF = os.path.join(HERE, "dispatch_target", "target",
                   "thumbv8m.main-none-eabi", "release", "sca-dispatch-target")
RET = 0xAAAA_AAAA
SWEEP_BUDGET = 50_000
STACK_TOP = 0x9000_0000

FLAG_INCLUDE_INIT_CODE = 0x8000_0000
FLAG_REGISTER_SLOT = 0x4000_0000

# Scenarios: (label, flags, slot_index, expected_decision).
# expected_decision: 0=T2, 1=T1+T2, 2=Deploy, 99=Rejected.
# For each scenario the harness sweeps faults and looks for a result
# DIFFERENT from expected — especially "0→1" (silent Type 1 emit) or
# "99→1/2" (skipping a sanity check to permit a bad combo).
SCENARIOS = [
    # (label, flags, slot_index, expected)
    ("plain_t2",         0,                                          5, 0),   # bypass class (a): expect 0, watch for 1
    ("register_slot",    FLAG_REGISTER_SLOT,                         3, 1),
    ("deploy",           FLAG_INCLUDE_INIT_CODE,                     0, 2),
    ("both_flags",       FLAG_INCLUDE_INIT_CODE | FLAG_REGISTER_SLOT, 1, 99), # mutex — bypass class (c)
    ("init_with_slot",   FLAG_INCLUDE_INIT_CODE,                     1, 99), # init+nonzero slot
    ("register_slot0",   FLAG_REGISTER_SLOT,                         0, 99), # register+slot0 — bypass class (b)
]

ENTRY_POINTS = [
    ("sca_dispatch_decide_plain", False),
    ("sca_dispatch_decide_fi",    True),
]

if not os.path.exists(ELF):
    sys.exit(f"target ELF not found: {ELF}\nbuild it first:   make -C {HERE} dispatch")


def fresh_emu(trace_config=None):
    e = rainbow_cortexm(trace_config=trace_config) if trace_config else rainbow_cortexm()
    e.load(ELF)
    return e


def setup_args(e, flags: int, slot_index: int):
    e.reset()
    e["sp"] = STACK_TOP
    e["r0"] = flags & 0xFFFF_FFFF
    e["r1"] = slot_index & 0xFFFF_FFFF
    e["lr"] = RET


def call(e, fn, flags, slot_index):
    setup_args(e, flags, slot_index)
    try:
        e.start(e.functions[fn][0], RET, count=SWEEP_BUDGET)
    except (RuntimeError, UcError):
        return None
    if e["pc"] != RET:
        return None
    return e["r0"] & 0xFFFF_FFFF


def call_fault(e, fn, flags, slot_index, fault_model, fault_idx):
    setup_args(e, flags, slot_index)
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


def instr_count(fn, flags, slot_index):
    e = fresh_emu(TraceConfig(instruction=True))
    r = call(e, fn, flags, slot_index)
    if r is None:
        return 0
    return len([ev for ev in e.trace if ev.get("type") == "code"])


def main():
    print("=== Type 1/2 dispatch FI sweep ===")
    print(f"ELF: {ELF}")
    print()

    # Baselines — confirm fixture behaviour
    print("Baselines (no fault):")
    print(f"  {'scenario':<18}", end="")
    for ep, _ in ENTRY_POINTS:
        print(f" | {ep.removeprefix('sca_dispatch_decide_'):>11}", end="")
    print()
    print("  " + "-" * 60)
    e = fresh_emu()
    for label, flags, slot, expected in SCENARIOS:
        print(f"  {label:<18}", end="")
        for ep, is_fi in ENTRY_POINTS:
            r = call(e, ep, flags, slot)
            mark = "" if r == expected else f" !!(expected {expected})"
            print(f" | {('ERR' if r is None else str(r)):>11}{mark}", end="")
        print()
    print()

    # Sweep all scenarios with each fault model. A "bypass" is any return
    # value that DIFFERS from `expected` — particularly any case where a
    # Type-2-only request (expected=0) returns 1 (Type 1 emission), or where
    # a rejected scenario (expected=99) returns 0/1/2 (accepted).
    any_critical = False
    findings_plain = []
    findings_fi = []

    for ep, is_fi in ENTRY_POINTS:
        for label, flags, slot, expected in SCENARIOS:
            total = instr_count(ep, flags, slot)
            if total == 0:
                print(f"-- {ep} × {label}: baseline failed, skipping")
                continue
            print(f"-- {ep} × {label}  (len={total} instr; expected={expected})")
            for model_label, model in FAULT_MODELS:
                e = fresh_emu()
                deviations = {}   # observed_value -> count
                crashes = hangs = shorts = 0
                for i in range(1, total + 8):
                    st, val = call_fault(e, ep, flags, slot, model, i)
                    if st == "short":
                        break
                    if st == "crash":
                        crashes += 1; continue
                    if st == "hang":
                        hangs += 1; continue
                    if val != expected:
                        deviations[val] = deviations.get(val, 0) + 1
                expected_n = sum(1 for _ in range(1, total + 8)) - sum(deviations.values()) - crashes - hangs
                # Count "critical" deviations: silent T1 emission (any 1
                # when expected was 0), or rejection-bypass (any 0/1/2 when
                # expected was 99).
                critical_count = 0
                critical_classes = []
                for dev, n in deviations.items():
                    if expected == 0 and dev == 1:
                        critical_count += n
                        critical_classes.append(f"0→1 ({n})")  # silent Type 1
                    elif expected == 99 and dev in (0, 1, 2):
                        critical_count += n
                        critical_classes.append(f"99→{dev} ({n})")
                print(f"     [{model_label:11s}]  swept ≈{total}:  "
                      f"deviations={dict(deviations)}  crashes={crashes}  "
                      f"hangs={hangs}  correctly={expected_n}")
                if critical_count > 0:
                    any_critical = True
                    bucket = findings_fi if is_fi else findings_plain
                    bucket.append((ep, label, model_label, critical_count, critical_classes))
                    print(f"       !!! {critical_count} CRITICAL bypass(es): "
                          f"{', '.join(critical_classes)}")
            print()

    # ---- Findings ----
    print("=" * 75)
    if not any_critical:
        print("ALL SWEEPS CLEAN — no single fault induces a silent Type 1 emission")
        print("or bypasses a sanity-check rejection (plain or hardened).")
        sys.exit(0)
    if findings_plain:
        print("FINDING — plain dispatch has critical single-fault bypasses:")
        for ep, scen, model, n, classes in findings_plain:
            print(f"    - {ep:<32} × {scen:<18} [{model:11}]  {n} ({', '.join(classes)})")
    if findings_fi:
        print()
        print("FINDING — FI-hardened dispatch also bypassable (input-register class, like F-10):")
        for ep, scen, model, n, classes in findings_fi:
            print(f"    - {ep:<32} × {scen:<18} [{model:11}]  {n} ({', '.join(classes)})")
    sys.exit(1)


if __name__ == "__main__":
    main()
