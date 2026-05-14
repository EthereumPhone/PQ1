#!/usr/bin/env python3
"""Fault-injection sweep over the local off-chain counter SCAN logic
(`secure/src/hw/flash.rs::offchain_count_read`).

**Attack we're testing — counter rollback via fault on read.** A fault
that makes `offchain_count_read` return a value LOWER than the actual
maximum stored in flash. Each successful attack lets cmd_sign_offchain
believe the counter is lower than it is → one extra signature past the
MAX_SLOT_USES = 65,536 cap. Over N successful attacks: N extra signatures.

This extends F-10's threat model: F-10 tested the GAP+CAP comparison
predicates with values already in registers. THIS harness tests the
underlying flash counter SCAN path that produces those register values.
A rollback at this layer is structurally more dangerous than F-10's
input-register attack — F-10 only buys ~1 extra sig per fault (the
flash-promote step re-anchors on next call), but a fault on the SCAN
that consistently underreports would NOT be caught by the promote step
(promote uses the same scan).

The fixture: a populated 8 KB page with 100 valid OFFCHAIN_TYPE_COUNT
entries for our slot, counts 1..=100. Expected read result: 100.
Any fault that produces `r < 100` is a rollback.
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
ELF = os.path.join(HERE, "flashctr_target", "target", "thumbv8m.main-none-eabi",
                   "release", "sca-flashctr-target")
RET = 0xAAAA_AAAA
SWEEP_BUDGET = 5_000_000   # generous — scan can run ~512 × overhead per QW
STACK_TOP = 0x9000_0000

# Page + slot-key live in mapped RAM at fixed addresses.
PAGE_ADDR     = 0x6000_0000
SLOT_KEY_ADDR = 0x6000_2000

# Production constants
OFFCHAIN_QW_SIZE    = 16
OFFCHAIN_CAPACITY   = 512
OFFCHAIN_TYPE_COUNT = 0x01

# We use a non-zero slot_key for the test (chosen arbitrarily).
TEST_SLOT_KEY = b"\x11\x22\x33\x44\x55\x66\x77\x88"

# Build the page contents: N_ENTRIES valid OFFCHAIN_TYPE_COUNT entries with
# counts 1..=N_ENTRIES for our slot, then blank. Expected scan result: N_ENTRIES.
N_ENTRIES = 100  # well below CAPACITY so we have blank QWs to detect end-of-journal


def _entry_qw(slot_key: bytes, type_byte: int, count: int) -> bytes:
    """Pack one 16-byte QW. Mirrors `entry_qw` in hw/flash.rs:956."""
    assert len(slot_key) == 8
    count_be = count.to_bytes(8, "big")    # 8-byte BE
    return slot_key + bytes([type_byte]) + count_be[1:]   # drop top byte → 7-byte count


def build_page() -> bytes:
    """Populate the first N_ENTRIES QWs with valid COUNT entries 1..=N_ENTRIES,
    rest are blank (0xFF). The TYPE_COUNT max for our slot is N_ENTRIES."""
    buf = bytearray()
    for c in range(1, N_ENTRIES + 1):
        buf += _entry_qw(TEST_SLOT_KEY, OFFCHAIN_TYPE_COUNT, c)
    # Pad with blank QWs up to page size
    remaining = (OFFCHAIN_CAPACITY * OFFCHAIN_QW_SIZE) - len(buf)
    buf += b"\xff" * remaining
    return bytes(buf)


PAGE = build_page()
EXPECTED_MAX = N_ENTRIES   # 100


def fresh_emu(trace_config=None):
    e = rainbow_cortexm(trace_config=trace_config) if trace_config else rainbow_cortexm()
    e.load(ELF)
    e.map_space(STACK_TOP - 0x8000, STACK_TOP + 0x20)
    e.map_space(PAGE_ADDR, PAGE_ADDR + 0x4000)  # 16 KB enough for page + slot_key
    return e


def setup(e):
    e.reset()
    e[STACK_TOP - 0x8000] = b"\x00" * 0x8000
    e["sp"] = STACK_TOP
    e[PAGE_ADDR] = PAGE
    e[SLOT_KEY_ADDR] = TEST_SLOT_KEY
    e["r0"] = PAGE_ADDR
    e["r1"] = SLOT_KEY_ADDR
    e["lr"] = RET


def call(e, fn):
    setup(e)
    try:
        e.start(e.functions[fn][0], RET, count=SWEEP_BUDGET)
    except (RuntimeError, UcError):
        return None
    if e["pc"] != RET:
        return None
    # u64 return in r0:r1 (little-endian word pair, ARM AAPCS).
    lo = e["r0"] & 0xFFFF_FFFF
    hi = e["r1"] & 0xFFFF_FFFF
    return lo | (hi << 32)


def call_fault(e, fn, fault_model, fault_idx):
    setup(e)
    try:
        e.start_and_fault(fault_model, fault_idx, e.functions[fn][0], RET,
                          count=SWEEP_BUDGET)
    except (RuntimeError, UcError):
        return ("crash", None)
    except IndexError:
        return ("short", None)
    if e["pc"] != RET:
        return ("hang", None)
    lo = e["r0"] & 0xFFFF_FFFF
    hi = e["r1"] & 0xFFFF_FFFF
    return ("ret", lo | (hi << 32))


def instr_count(fn):
    e = fresh_emu(TraceConfig(instruction=True))
    r = call(e, fn)
    if r is None:
        return 0
    return len([ev for ev in e.trace if ev.get("type") == "code"])


def main():
    print("=== Off-chain counter SCAN FI sweep (flash rollback attack) ===")
    print(f"ELF: {ELF}")
    print(f"Page populated with {N_ENTRIES} OFFCHAIN_TYPE_COUNT entries (counts 1..={N_ENTRIES})")
    print(f"Expected scan result: {EXPECTED_MAX}")
    print()

    # Baselines (no fault)
    print("Baselines (no fault):")
    e = fresh_emu()
    for fn in ["sca_flashctr_read_plain", "sca_flashctr_read_fi"]:
        r = call(e, fn)
        ok = "OK" if r == EXPECTED_MAX else f"!! EXPECTED {EXPECTED_MAX}"
        print(f"  {fn:<32}: returned {r}  ({ok})")
    print()

    # Sweep — count of (return value, frequency) deviations, focusing on
    # ROLLBACK (returned < EXPECTED_MAX = under-report; lets attacker
    # bypass the cap by ~delta signatures).
    any_rollback_plain = False
    any_rollback_fi = False
    rollbacks_plain = []
    rollbacks_fi = []

    for fn in ["sca_flashctr_read_plain", "sca_flashctr_read_fi"]:
        is_fi = fn.endswith("_fi")
        total = instr_count(fn)
        if total == 0:
            print(f"-- {fn}: baseline failed, skipping")
            continue
        print(f"-- {fn}  (len={total} instr)")
        for model_label, model in FAULT_MODELS:
            e = fresh_emu()
            deviations = {}
            crashes = hangs = 0
            for i in range(1, total + 8):
                st, val = call_fault(e, fn, model, i)
                if st == "short":
                    break
                if st == "crash":
                    crashes += 1; continue
                if st == "hang":
                    hangs += 1; continue
                if val != EXPECTED_MAX:
                    deviations[val] = deviations.get(val, 0) + 1
            correct = total + 8 - sum(deviations.values()) - crashes - hangs - 1
            # Count "rollback" cases: returned a value < EXPECTED_MAX
            # (under-report → attacker gets bonus signatures).
            rollbacks = {k: v for k, v in deviations.items() if k < EXPECTED_MAX}
            n_rollback = sum(rollbacks.values())
            # Count "u64::MAX" cases (the FI mirror's halt-on-glitch signal)
            n_halt = deviations.get((1 << 64) - 1, 0)
            other_dev = sum(v for k, v in deviations.items()
                            if k >= EXPECTED_MAX and k != ((1 << 64) - 1))
            print(f"     [{model_label:11s}]  swept ≈{total}:  "
                  f"correct={correct}  rollback={n_rollback}  halt-on-glitch={n_halt}  "
                  f"other-dev={other_dev}  crashes={crashes}  hangs={hangs}")
            if n_rollback > 0:
                bucket = rollbacks_fi if is_fi else rollbacks_plain
                bucket.append((fn, model_label, n_rollback, rollbacks))
                if is_fi:
                    any_rollback_fi = True
                else:
                    any_rollback_plain = True
                print(f"       !!! {n_rollback} ROLLBACK case(s) — read returned < {EXPECTED_MAX}:")
                # Show a few of the most interesting ones (smallest values, which are the WORST rollbacks)
                for val, cnt in sorted(rollbacks.items())[:5]:
                    delta = EXPECTED_MAX - val
                    print(f"             returned {val} (delta={delta:+}; {cnt}x)")
        print()

    # ---- Findings ----
    print("=" * 75)
    if not any_rollback_plain and not any_rollback_fi:
        print("ALL SWEEPS CLEAN — no single fault induces a counter rollback.")
        sys.exit(0)
    if any_rollback_plain:
        print("FINDING — plain `offchain_count_read` is single-fault rollback-bypassable:")
        for fn, model, n, rb in rollbacks_plain:
            print(f"    - {fn:<32} [{model:11}]  {n} rollback(s)  (delta range: "
                  f"{EXPECTED_MAX - max(rb.keys())}..{EXPECTED_MAX - min(rb.keys())})")
        print()
        print("  Production impact: a successful fault on the SCAN loop lets the firmware")
        print("  underreport `local_offchain_count`. cmd_sign_offchain then permits more")
        print("  signatures than the MAX_SLOT_USES = 65,536 cap should allow. The")
        print("  flash-promote step (F-10's natural defense) does NOT help here — promote")
        print("  uses the same scan, so a fault that rolls back the read rolls back the")
        print("  promote target too.")
        print()
        print("  Fix direction: scan twice with wait_random between, halt-on-mismatch.")
        print("  The `sca_flashctr_read_fi` variant in flashctr_target shows the pattern.")
    if any_rollback_fi:
        print()
        print("REGRESSION — even the hardened scan-twice variant rolled back:")
        for fn, model, n, rb in rollbacks_fi:
            print(f"    - {fn:<32} [{model:11}]  {n} rollback(s)")
        sys.exit(1)
    sys.exit(0 if not any_rollback_plain else 1)


if __name__ == "__main__":
    main()
