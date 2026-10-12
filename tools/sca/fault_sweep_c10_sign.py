#!/usr/bin/env python3
"""Tail fault sweep of a host-emulated C10 sign/verify gate mirror.

The target uses real sphincs-c10 signing and verification, fixed test keys,
fixed randomness and a deterministic delay stub. It is not the production
firmware image or a hardware experiment. Only the final TAIL_DEPTH instructions
are sampled, under three emulator fault models, for one message/key pair.

An unfaulted baseline must return 1 and pass a separate, unfaulted invocation
of the same ELF's verifier. Every byte-different output returned with literal
success (1) is verified; verifier crashes, budget exhaustion or noncanonical
returns are errors, never rejection evidence. A changed accepted output fails
this check, but is not by itself an EUF-CMA forgery on a new message. Rejected
changed outputs are reported as output corruption, not dismissed as harmless.

Calibration runs in an isolated process. Each trial restores CPU/RAM, with an
unfaulted restore tripwire. These checks do not establish complete emulator
fidelity, coverage of the signer body, fault resistance or shipment authority.

Run: make -C tools/sca c10-sign
"""
import glob
import os
import subprocess
import sys
import time

os.environ.setdefault("UC_IGNORE_REG_BREAK", "1")

from rainbow.generics import rainbow_cortexm
from rainbow import TraceConfig
from rainbow.fault_models import fault_skip, fault_stuck_at
from unicorn import UcError

FAULT_MODELS = []   # filled in inside main() — see /tmp/single_thread_late_snap.py
                     # for why this matters (creating the closures at module-load
                     # produces different fault behaviour than creating in main())

HERE = os.path.dirname(os.path.abspath(__file__))
ELF = os.path.join(HERE, "c10_sign_target", "target", "thumbv8m.main-none-eabi",
                   "release", "sca-c10-sign-target")

RET = 0xAAAA_AAAA
STACK_TOP = 0x9000_0000
_STACK_LEN = 0x10_000          # 64KB stack — sign+verify uses ~10KB
MSG_ADDR  = 0x6000_0000        # NS-style scratch buffers
SIG_ADDR  = 0x6000_1000

# Each emulation runs ~2.5M sign + ~7.5k verify + ~few-k gate/sig-write.
# Budget generously to allow tail-fault continuations.
COUNT_BUDGET   = 10_000_000_000   # full sign+verify is ~2.6 B unicorn-instructions (~14s wallclock)
SWEEP_BUDGET   = 10_000_000_000   # per-fault total budget
TAIL_DEPTH     = 30_000        # covers gate cmp+branch + entire sig-write loop + epilogue
SIG_LEN        = 4008
CONTINUE_BUDGET = 500_000_000  # post-snapshot budget for setup paths (tripwire, bisect from 2.5 B snapshot)
WORKER_BUDGET   = 200_000      # per-worker-iter budget — workers snapshot right before the tail
                               # so each iteration emulates at most TAIL_DEPTH (~30K) instructions
SWEEP_MODELS   = FAULT_MODELS  # all 3 models — snapshot/restore makes the sweep cheap

# Fixed test message. The mirror's hardcoded keypair (sk_seed=[0x42;32],
# pk_seed=[0x77;16]) signs over this message in baseline runs.
TEST_MSG = bytes(range(32))    # 0x00..0x1F

if not os.path.exists(ELF):
    sys.exit(f"target ELF not found: {ELF}\nbuild it first:   make -C {HERE} c10-sign   (or: make -C {HERE} build-c10-sign)")


def fresh_emu(trace_config=None):
    e = rainbow_cortexm(trace_config=trace_config) if trace_config else rainbow_cortexm()
    e.load(ELF)
    e.map_space(STACK_TOP - _STACK_LEN, STACK_TOP + 0x20)
    return e


def setup(e):
    e.reset()
    e[STACK_TOP - _STACK_LEN] = b"\x00" * _STACK_LEN
    e["sp"] = STACK_TOP
    e[MSG_ADDR] = TEST_MSG
    e[SIG_ADDR] = b"\x00" * SIG_LEN  # zero-fill so we can detect partial writes
    e["r0"] = MSG_ADDR
    e["r1"] = SIG_ADDR
    e["lr"] = RET


def call(e, fn):
    setup(e)
    begin = e.functions[fn][0]
    try:
        e.start(begin, RET, count=COUNT_BUDGET)
    except (RuntimeError, UcError):
        return ("crash", e["pc"], None)
    if e["pc"] != RET:
        return ("hang", e["pc"], None)
    ret = e["r0"] & 0xFFFF_FFFF
    sig = bytes(e[SIG_ADDR:SIG_ADDR + SIG_LEN])
    return ("ret", ret, sig)


def call_fault(e, fn, fault_model, fault_idx):
    setup(e)
    begin = e.functions[fn][0]
    try:
        e.start_and_fault(fault_model, fault_idx, begin, RET, count=SWEEP_BUDGET)
    except (RuntimeError, UcError):
        return ("crash", e["pc"], None)
    except IndexError:
        return ("short", None, None)
    if e["pc"] != RET:
        return ("hang", e["pc"], None)
    ret = e["r0"] & 0xFFFF_FFFF
    sig = bytes(e[SIG_ADDR:SIG_ADDR + SIG_LEN])
    return ("ret", ret, sig)


# ---------------------------------------------------------------------------
# Snapshot / restore — the 22× speedup mechanism.
#
# Unicorn's `context_save()` captures CPU registers + internal state but NOT
# memory. We separately dump every mapped region (the cortex-m-rt RAM bank +
# our manually-mapped stack + scratch buffers). On restore we re-write each
# region's bytes verbatim. Verified correct via POC: 5 consecutive restores
# produce the byte-identical baseline signature.
# ---------------------------------------------------------------------------

def take_snapshot(e, fn, snapshot_at_instr):
    """Run `fn` partway (up to `snapshot_at_instr`) and capture (ctx, mem_snap, pc, sp).
    Returns None if the function returned before snapshot_at_instr (snapshot
    point too far)."""
    setup(e)
    begin = e.functions[fn][0]
    try:
        e.start(begin, RET, count=snapshot_at_instr)
    except (RuntimeError, UcError):
        return None
    if e["pc"] == RET:
        return None  # snapshot too late — function already returned
    ctx = e.emu.context_save()
    # Dump every mapped region (skip read-only flash via heuristic; the flash
    # is the ELF image which doesn't change).
    mem_snap = {}
    for begin_addr, end_addr, perms in e.emu.mem_regions():
        size = end_addr - begin_addr + 1
        if begin_addr < 0x0900_0000:
            # Heuristic: low addresses (< 0x09000000) are the flash mapping;
            # skip them. RAM regions live at 0x20000000+ (cortex-m-rt) and
            # 0x60000000+ / 0x90000000+ (our scratch + stack).
            continue
        mem_snap[begin_addr] = bytes(e.emu.mem_read(begin_addr, size))
    return (ctx, mem_snap, e["pc"])


def call_fault_from_snapshot(e, snapshot, fault_model, fault_idx_relative):
    """Restore from snapshot and inject a fault at `fault_idx_relative`
    instructions past the snapshot point. Returns same tuple as call_fault."""
    ctx, mem_snap, snap_pc = snapshot
    e.emu.context_restore(ctx)
    for addr, data in mem_snap.items():
        e.emu.mem_write(addr, data)
    try:
        e.start_and_fault(fault_model, fault_idx_relative, snap_pc, RET,
                          count=CONTINUE_BUDGET)
    except (RuntimeError, UcError):
        return ("crash", e["pc"], None)
    except IndexError:
        return ("short", None, None)
    if e["pc"] != RET:
        return ("hang", e["pc"], None)
    ret = e["r0"] & 0xFFFF_FFFF
    sig = bytes(e[SIG_ADDR:SIG_ADDR + SIG_LEN])
    return ("ret", ret, sig)


def call_from_snapshot(e, snapshot):
    """Restore + continue (no fault). Used to find total_instr_count via
    bisect starting from the snapshot, and to verify restore correctness."""
    ctx, mem_snap, snap_pc = snapshot
    e.emu.context_restore(ctx)
    for addr, data in mem_snap.items():
        e.emu.mem_write(addr, data)
    try:
        e.start(snap_pc, RET, count=CONTINUE_BUDGET)
    except (RuntimeError, UcError):
        return ("crash", e["pc"], None)
    if e["pc"] != RET:
        return ("hang", e["pc"], None)
    return ("ret", e["r0"] & 0xFFFF_FFFF,
            bytes(e[SIG_ADDR:SIG_ADDR + SIG_LEN]))


def load_pk_root():
    """Reject missing or conflicting build roots; baseline binds the value to ELF."""
    paths = glob.glob(os.path.join(HERE, "c10_sign_target", "target",
        "thumbv8m.main-none-eabi", "release", "build",
        "sca-c10-sign-target-*", "out", "pk_root.bin"))
    roots = set()
    for path in paths:
        with open(path, "rb") as stream:
            roots.add(stream.read())
    if len(roots) != 1 or any(len(root) != 16 for root in roots):
        raise RuntimeError("missing, malformed or conflicting pk_root.bin; rebuild target")
    return roots.pop()


def classify_release(ret, sig, baseline):
    if ret == 0:
        return "rejected"
    if ret != 1:
        return "invalid_return"
    return "clean" if sig == baseline else "needs_verify"


def offboard_verify(e, msg: bytes, sig: bytes) -> bool:
    """Unfaulted verify of a produced sig via the same ELF's
    `sca_c10_verify_real` entry point. Re-uses the same pk_seed/pk_root
    the build.rs baked into the mirror — closes the loop on baseline."""
    PK_SEED_ADDR = 0x6010_0000
    PK_ROOT_ADDR = 0x6010_1000
    MSG_ADDR_OB  = 0x6010_2000
    SIG_ADDR_OB  = 0x6010_3000
    # PK_SEED is 16 bytes of 0x77; PK_ROOT was baked at build time — we
    # read it back from the ELF's `.rodata` (it's referenced as the static
    # `PK_ROOT`, so it lives in flash and is mapped by `e.load(ELF)`).
    pk_seed = b"\x77" * 16
    pk_root = load_pk_root()
    e.reset()
    e[STACK_TOP - _STACK_LEN] = b"\x00" * _STACK_LEN
    e["sp"] = STACK_TOP
    e[PK_SEED_ADDR] = pk_seed
    e[PK_ROOT_ADDR] = pk_root
    e[MSG_ADDR_OB]  = msg
    e[SIG_ADDR_OB]  = sig
    e["r0"] = PK_SEED_ADDR
    e["r1"] = PK_ROOT_ADDR
    e["r2"] = MSG_ADDR_OB
    e["r3"] = SIG_ADDR_OB
    e["lr"] = RET
    try:
        e.start(e.functions["sca_c10_verify_real"][0], RET, count=COUNT_BUDGET)
    except (RuntimeError, UcError) as ex:
        raise RuntimeError("unfaulted verifier failed") from ex
    if e["pc"] != RET:
        raise RuntimeError("unfaulted verifier exceeded its instruction budget")
    result = e["r0"] & 0xFFFF_FFFF
    if result not in (0, 1):
        raise RuntimeError(f"unfaulted verifier returned noncanonical value {result}")
    return result == 1


# ---------------------------------------------------------------------------
# (Multiprocessing infrastructure removed — empirically didn't deliver a
# speedup over single-thread snapshot+restore in this harness shape. The
# bottleneck after applying snapshot/restore is no longer CPU but rather
# the one-time partial-run + Python overhead per iteration. The single-
# thread version runs 90 k faults in ~18 s wallclock — fast enough not to
# need a multi-core dispatcher. If a wider sweep (e.g. > 500 k faults)
# becomes the goal, revisit; FaultFinder (ASHES'24) is the proven multi-
# core Unicorn pattern to adopt.)
# ---------------------------------------------------------------------------


def calibrate_count():
    """Count an unfaulted execution without installing per-instruction hooks.

    Scan in bounded chunks, then bisect only the final chunk using complete
    CPU/RAM snapshots. This process is discarded before fault injection.
    """
    e = fresh_emu()
    setup(e)
    pc = e.functions["sca_c10_sign_verified"][0]
    consumed = 0
    chunk = 100_000_000
    while consumed < COUNT_BUDGET:
        ctx = e.emu.context_save()
        memory = {
            begin: bytes(e.emu.mem_read(begin, end - begin + 1))
            for begin, end, _ in e.emu.mem_regions() if begin >= 0x0900_0000
        }
        budget = min(chunk, COUNT_BUDGET - consumed)
        e.start(pc, RET, count=budget)
        if e["pc"] == RET:
            if (e["r0"] & 0xFFFF_FFFF) != 1:
                raise RuntimeError("calibration baseline returned failure")
            low, high = 0, budget
            while high - low > 1:
                middle = (low + high) // 2
                e.emu.context_restore(ctx)
                for addr, data in memory.items():
                    e.emu.mem_write(addr, data)
                e.start(pc, RET, count=middle)
                if e["pc"] == RET:
                    high = middle
                else:
                    low = middle
            print(consumed + high)
            return
        consumed += budget
        pc = e["pc"]
    raise RuntimeError("calibration did not return within its instruction budget")


def main():
    global SWEEP_MODELS, FAULT_MODELS
    # Create fault-model closures INSIDE main() — moving them to module-level
    # (as we previously had) somehow corrupted stuck-at fault behaviour, with
    # the swept-positions cumulating to ~100 % crash rate. /tmp/single_thread_late_snap.py
    # creates them at runtime and works fine. Same here.
    FAULT_MODELS = [
        ("skip", fault_skip),
        ("stuck-at-0", fault_stuck_at(0x0000_0000)),
        ("stuck-at-FF", fault_stuck_at(0xFFFF_FFFF)),
    ]
    SWEEP_MODELS = FAULT_MODELS
    print("=== C10-sign FI sweep (real sign + real verify + real gate) ===")
    print(f"ELF: {ELF}")
    print(f"Test message: {TEST_MSG.hex()}")
    print(f"Fault models: {[ml for ml, _ in SWEEP_MODELS]}  "
          f"(all three enabled)")
    print()

    # ---- Single-emulator pattern (verbatim from /tmp/single_thread_late_snap.py POC) ----
    # Critical: this is the ONLY known pattern that doesn't fall into the
    # 100%-crash trap. NO helper functions (call/take_snapshot/etc) — they
    # inadvertently re-setup the emulator in a way that breaks fault-injection
    # results on stuck-at models.
    print("Baseline (no fault) — verbatim POC pattern:")
    t0 = time.time()
    e_main = rainbow_cortexm()
    e_main.load(ELF)
    e_main.map_space(STACK_TOP - _STACK_LEN, STACK_TOP + 0x20)
    # Setup
    e_main.reset()
    e_main[STACK_TOP - _STACK_LEN] = b"\x00" * _STACK_LEN
    e_main["sp"] = STACK_TOP
    e_main[MSG_ADDR] = TEST_MSG
    e_main[SIG_ADDR] = b"\x00" * SIG_LEN
    e_main["r0"] = MSG_ADDR
    e_main["r1"] = SIG_ADDR
    e_main["lr"] = RET
    # Baseline run
    e_main.start(e_main.functions["sca_c10_sign_verified"][0], RET, count=10_000_000_000)
    if e_main["pc"] != RET or (e_main["r0"] & 0xFFFF_FFFF) != 1:
        sys.exit("baseline did not return success within its instruction budget")
    baseline_sig = bytes(e_main[SIG_ADDR:SIG_ADDR + SIG_LEN])
    print(f"  baseline run finished in {time.time() - t0:.1f} s, "
          f"sig[0..16]={baseline_sig[:16].hex()}")
    print()

    # Calibrate in a separate process: bisection must not contaminate the
    # emulator used for fault injection. A fixed count goes stale when the
    # compiler or any linked source changes.
    calibrated = subprocess.run(
        [sys.executable, os.path.abspath(__file__), "--calibrate-count"],
        check=True, capture_output=True, text=True,
    )
    total_estimate = int(calibrated.stdout.strip().splitlines()[-1])
    if not TAIL_DEPTH < total_estimate <= COUNT_BUDGET:
        sys.exit(f"invalid calibrated instruction count: {total_estimate}")
    sweep_snap_at = total_estimate - TAIL_DEPTH
    sweep_start_rel = 1
    sweep_end_rel = TAIL_DEPTH + 16   # small margin past function end → some "short" iterations
    print(f"  total instructions = {total_estimate:_} (measured in isolated process)")
    print(f"  sweep snapshot point: {sweep_snap_at:_} "
          f"(tail sweep covers {TAIL_DEPTH:_} instr past it)")
    print()

    sweep_t0 = time.time()

    # Save every changed successful output for actual unfaulted verification.
    # A byte pattern alone cannot establish that a signature is invalid.
    # Verbatim POC: setup + partial run to snap, capture ctx + mem snapshot.
    print(f"  taking sweep-snapshot at instr {sweep_snap_at:_} (inline POC pattern) …")
    t0 = time.time()
    sweep_emu = e_main
    sweep_emu.reset()
    sweep_emu[STACK_TOP - _STACK_LEN] = b"\x00" * _STACK_LEN
    sweep_emu["sp"] = STACK_TOP
    sweep_emu[MSG_ADDR] = TEST_MSG
    sweep_emu[SIG_ADDR] = b"\x00" * SIG_LEN
    sweep_emu["r0"] = MSG_ADDR
    sweep_emu["r1"] = SIG_ADDR
    sweep_emu["lr"] = RET
    sweep_emu.start(sweep_emu.functions["sca_c10_sign_verified"][0], RET,
                    count=sweep_snap_at)
    if sweep_emu["pc"] == RET:
        sys.exit("sweep-snapshot point past function return")
    sweep_ctx = sweep_emu.emu.context_save()
    sweep_mem = {}
    for begin_addr, end_addr, _perms in sweep_emu.emu.mem_regions():
        if begin_addr < 0x09000000:
            continue
        sweep_mem[begin_addr] = bytes(sweep_emu.emu.mem_read(begin_addr, end_addr - begin_addr + 1))
    sweep_snap_pc = sweep_emu["pc"]
    print(f"    snapshot taken (pc={sweep_snap_pc:#x}, mem_size={sum(len(d) for d in sweep_mem.values()):_} B, "
          f"{time.time() - t0:.1f} s)")

    # Tripwire: restore + run forward (no fault), confirm sig matches baseline.
    sweep_emu.emu.context_restore(sweep_ctx)
    for addr, data in sweep_mem.items():
        sweep_emu.emu.mem_write(addr, data)
    sweep_emu.start(sweep_snap_pc, RET, count=500_000_000)
    tw_ok = (sweep_emu["pc"] == RET and (sweep_emu["r0"] & 0xFFFFFFFF) == 1
             and bytes(sweep_emu[SIG_ADDR:SIG_ADDR + SIG_LEN]) == baseline_sig)
    if not tw_ok:
        sys.exit(f"tripwire FAILED: pc={sweep_emu['pc']:#x}")
    print(f"    tripwire OK")

    any_forge = False
    forge_cases = []
    corruption_cases = []
    needs_verify_cases = []
    counters = {ml: {"forge": 0, "benign_drop": 0, "rejected": 0, "clean": 0,
                     "crash": 0, "hang": 0, "short": 0, "invalid_return": 0} for ml, _ in SWEEP_MODELS}

    for model_label, model in SWEEP_MODELS:
        c = counters[model_label]
        model_t0 = time.time()
        for i in range(sweep_start_rel, sweep_end_rel):
            # Verbatim POC pattern: restore + mem_write + start_and_fault.
            sweep_emu.emu.context_restore(sweep_ctx)
            for addr, data in sweep_mem.items():
                sweep_emu.emu.mem_write(addr, data)
            try:
                sweep_emu.start_and_fault(model, i, sweep_snap_pc, RET,
                                           count=WORKER_BUDGET)
            except (RuntimeError, UcError):
                c["crash"] += 1; continue
            except IndexError:
                c["short"] += 1; continue
            if sweep_emu["pc"] != RET:
                c["hang"] += 1; continue
            ret_val = sweep_emu["r0"] & 0xFFFF_FFFF
            sig = bytes(sweep_emu[SIG_ADDR:SIG_ADDR + SIG_LEN])
            outcome = classify_release(ret_val, sig, baseline_sig)
            if outcome == "needs_verify":
                needs_verify_cases.append((model_label, i, sig))
            else:
                c[outcome] += 1
        model_t = time.time() - model_t0
        n_swept = sweep_end_rel - sweep_start_rel
        print(f"  [{model_label:11s}]  swept {n_swept}:  ({model_t:.1f} s, "
              f"{n_swept / model_t:.0f} faults/s)")

    sweep_t = time.time() - sweep_t0
    print(f"  sweep complete: wallclock={sweep_t:.1f} s")

    # A separate unfaulted verifier invocation; this is the same implementation,
    # not an independent cryptographic oracle. Never reuse the faulted emulator.
    verify_emu = fresh_emu()
    if not offboard_verify(verify_emu, TEST_MSG, baseline_sig):
        raise RuntimeError("unfaulted baseline signature failed verification")
    print("  Baseline signature verified")
    if needs_verify_cases:
        print(f"  Verifying all {len(needs_verify_cases)} changed successful outputs …")
        t_v0 = time.time()
        for ml, idx, sig in needs_verify_cases:
            if offboard_verify(verify_emu, TEST_MSG, sig):
                counters[ml]["forge"] += 1
                forge_cases.append((ml, idx, 1, sig))
                any_forge = True
            else:
                counters[ml]["benign_drop"] += 1
                corruption_cases.append((ml, idx, 1, "verified-not-forge"))
        print(f"    done in {time.time() - t_v0:.1f} s")

    # Report per-model counters
    print()
    for ml, _model in SWEEP_MODELS:
        c = counters[ml]
        total = sum(c.values())
        print(f"  [{ml:11s}]  swept {total}:  "
              f"ACCEPTED_CHANGED_OUTPUT={c['forge']}  output-corruption={c['benign_drop']}  "
              f"crashes={c['crash']}  hangs={c['hang']}  shorts={c['short']}  "
              f"noncanonical-returns={c['invalid_return']}  "
              f"correctly-rejected={c['rejected']}  clean-release={c['clean']}")
        if c["forge"] > 0:
            forges_for_model = [f for f in forge_cases if f[0] == ml]
            print(f"     !!! {c['forge']} ACCEPTED CHANGED OUTPUT (sig validates under intended message):")
            for fm, fi, fret, _fsig in forges_for_model[:20]:
                abs_instr = sweep_snap_at + fi
                print(f"        [{fm}] rel_instr {fi} (abs {abs_instr:_}): ret={fret}")
    total_wallclock = time.time() - sweep_t0
    print(f"  (total sweep wallclock: {total_wallclock:.1f} s; "
          f"off-board verify called {len(needs_verify_cases)} of "
          f"{len(corruption_cases) + len(forge_cases)} anomalies)")
    print()
    # Report observed corruption without inferring the fault location or harmlessness.
    if corruption_cases:
        print(f"  Informational: {len(corruption_cases)} output-corruption case(s) "
              f"(each changed output was rejected by the unfaulted verifier)")
        print()

    print("Scope: one fixed key/message, emulator gate mirror, final instruction tail;")
    print("crashes, hangs, noncanonical returns and unsampled paths remain explicit.")
    if not any_forge:
        print("PASS: no changed output returned with literal success was accepted")
        print("by the unfaulted verifier in these sampled trials.")
        sys.exit(0)
    print(f"FAIL: {len(forge_cases)} changed successful outputs passed verification")
    sys.exit(1)


if __name__ == "__main__":
    if sys.argv[1:] == ["--calibrate-count"]:
        calibrate_count()
    else:
        main()
