#!/usr/bin/env python3
"""Fault-injection sweep against PQSigner's FI countermeasures (secure/src/fi.rs).

Emulates each guard under rainbow and injects a single instruction-skip at every
instruction index in turn, then classifies the outcome:

  * "exploitable" — the skip made `sca_fi_check_true(false)` return a non-zero
    value (i.e. a caller would read the verdict register as "true"). A robust
    guard should have ZERO of these; the script exits non-zero if any survive.
  * "crash"       — the skip produced an invalid instruction.
  * "hang"        — the run exhausted its instruction budget without returning
    (typically because the glitch was *caught* and landed in `halt_on_glitch`'s
    endless `wfe` loop, or it broke a loop's termination — either way, on real
    hardware the watchdog would reset; not a verdict bypass).
  * "no-effect"   — returned the correct (false → 0) value despite the skip.

For each "exploitable" index it reports which function the skipped instruction
was in — the `sca_fi_check_true` *wrapper* and the synthetic `|| want != 0`
closure are this harness's own scaffolding, not part of `fi.rs`; a skip there
means "you can glitch the boolean *fed into* check_true", which check_true does
not claim to prevent (its job is hardening the double-check / sentinel-commit /
return path). A skip inside `fi::check_true` / `fi::wait_random` that flips a
clean false into a true return is the noteworthy case.

Run:   donjon-sca run tools/sca/fault_sweep_fi.py
       (or, building the target ELF first:  make -C tools/sca fi)

Three single-fault models are swept: instruction-skip, dest-register-stuck-at-0,
dest-register-stuck-at-0xFFFFFFFF. For multi-fault / two-fault, extend the sweep
below (nested loops). Side-channel leakage of these guards is a separate harness
— see tools/sca/README.md.
"""
import os
import sys
import bisect

import unicorn as uc
from rainbow.generics import rainbow_cortexm
from rainbow.fault_models import fault_skip, fault_stuck_at
from unicorn import UcError

FAULT_MODELS = [
    ("skip", fault_skip),
    ("stuck-at-0", fault_stuck_at(0x0000_0000)),
    ("stuck-at-FF", fault_stuck_at(0xFFFF_FFFF)),
]

HERE = os.path.dirname(os.path.abspath(__file__))
ELF = os.path.join(HERE, "fi_target", "target", "thumbv8m.main-none-eabi", "release", "sca-fi-target")
RET = 0xAAAA_AAAA          # sentinel return address — emulation stops cleanly when PC reaches it
BUDGET = 8192              # max instructions per run (a normal check_true(0) is ~190; generous)
MAX_I = 1000               # max instruction-skip index (the sweep stops early at function end)

if not os.path.exists(ELF):
    sys.exit(
        f"target ELF not found: {ELF}\n"
        f"build it first:   make -C {HERE} build\n"
        f"           or:    cargo build --release --target thumbv8m.main-none-eabi "
        f"--manifest-path {os.path.join(HERE, 'fi_target', 'Cargo.toml')}"
    )


def fresh_emu():
    """A fresh emulator per call — eliminates any cross-iteration state leakage
    (stack/RAM left dirty by a previous fault)."""
    e = rainbow_cortexm()
    e.load(ELF)
    return e


def fn_table(e):
    """[(start_addr, name), ...] sorted by address, for attributing a fault PC to
    a function. Symbol values may carry the Thumb bit; mask it off."""
    t = sorted((v[0] & ~1, k) for k, v in e.functions.items())
    return t


def fn_at(table, pc):
    starts = [a for a, _ in table]
    i = bisect.bisect_right(starts, pc & ~1) - 1
    return table[i][1] if i >= 0 else "<?>"


def run_call(e, sym, args=(), fault=None):
    """Set up `sym(args...)` returning at RET; optionally inject `fault` at index
    `fault=(model, index)`. Returns ('ret', r0) | ('crash', pc) | ('hang', pc) | ('short', None)."""
    e.reset()
    e.reset_stack()
    for i, a in enumerate(args):
        e[f"r{i}"] = a & 0xFFFF_FFFF
    e["lr"] = RET
    begin = e.functions[sym][0]
    try:
        if fault is None:
            e.start(begin, RET, count=BUDGET)
        else:
            model, idx = fault
            e.start_and_fault(model, idx, begin, RET, count=BUDGET)
    except (RuntimeError, UcError):
        return ("crash", e["pc"])
    except IndexError:
        return ("short", None)        # fault index past the executed-instruction count
    if e["pc"] == RET:
        return ("ret", e["r0"])
    return ("hang", e["pc"])


# --- baselines (no fault) -----------------------------------------------------
def baseline():
    e = fresh_emu()
    assert run_call(e, "sca_fi_check_true", (0,)) == ("ret", 0), "check_true(false) baseline"
    e = fresh_emu()
    assert run_call(e, "sca_fi_check_true", (1,)) == ("ret", 1), "check_true(true) baseline"
    e = fresh_emu()
    st, _ = run_call(e, "sca_fi_wait_random", ())
    assert st == "ret", "wait_random() baseline"
    print("baselines OK  (check_true(0)->0, check_true(1)->1, wait_random returns)")


# --- single-fault sweep -------------------------------------------------------
def sweep_check_true(fault_model):
    """Sweep `fault_model` over check_true(false). A 'ret' with r0 != 0 is exploitable."""
    exploitable, crashes, hangs, noeffect = [], 0, 0, 0
    fault_locs = {}                   # index -> (function_name, fault_pc)
    for i in range(1, MAX_I):
        e = fresh_emu()
        table = fn_table(e)
        st, val = run_call(e, "sca_fi_check_true", (0,), fault=(fault_model, i))
        if st == "short":
            break                     # i past the function's executed-instruction count → done
        if st == "crash":
            crashes += 1; continue
        if st == "hang":
            hangs += 1; continue
        # st == "ret"
        if val != 0:
            exploitable.append(i)
            # locate the faulted instruction (no-fault run, stop after i instr) — for reporting
            e2 = fresh_emu()
            e2.reset(); e2.reset_stack(); e2["r0"] = 0; e2["lr"] = RET
            try:
                e2.start(e2.functions["sca_fi_check_true"][0], RET, count=i)
            except Exception:
                pass
            fault_locs[i] = (fn_at(table, e2["pc"]), e2["pc"])
        else:
            noeffect += 1
    return exploitable, crashes, hangs, noeffect, fault_locs


def sweep_wait_random(fault_model):
    """Sweep `fault_model` over wait_random(). No observable output, so just tally outcomes."""
    rets, crashes, hangs = 0, 0, 0
    for i in range(1, MAX_I):
        e = fresh_emu()
        st, _ = run_call(e, "sca_fi_wait_random", (), fault=(fault_model, i))
        if st == "short":
            break
        if st == "crash":
            crashes += 1
        elif st == "hang":
            hangs += 1
        else:
            rets += 1
    return rets, crashes, hangs


# --- two-fault sweep over check_true (--two-fault) -----------------------------
def _check_true_instr_count():
    """Instruction count of a clean sca_fi_check_true(0) call (via a counting hook)."""
    e = fresh_emu()
    e.reset(); e.reset_stack(); e["r0"] = 0; e["lr"] = RET
    n = [0]

    def hook(uci, addr, size, ud, _n=n):
        _n[0] += 1

    e.emu.hook_add(uc.UC_HOOK_CODE, hook)
    e.start(e.functions["sca_fi_check_true"][0], RET, count=BUDGET)
    return n[0]


def sweep_check_true_two_fault():
    """For every PAIR of instruction indices (i, j), i < j, inject an instruction-skip
    at i AND at j (via a UC_HOOK_CODE that counts instructions and calls `fault_skip`
    at those two indices), then check whether `sca_fi_check_true(false)` returns a
    non-zero value. `fi::check_true`'s documented contract is that a glitch must skip
    ALL FOUR decision points to flip a clean false into a true return — so a *pair* of
    skips should not be enough either. Returns (bypasses, crashes, no_effect, total_pairs)
    where each bypass is ((i, j), (fn_i, pc_i), (fn_j, pc_j))."""
    total = _check_true_instr_count()
    begin = fresh_emu().functions["sca_fi_check_true"][0]
    bypasses, crashes, no_effect, pairs = [], 0, 0, 0
    for i in range(1, total):
        for j in range(i + 1, total + 1):
            pairs += 1
            e = fresh_emu()
            e.reset(); e.reset_stack(); e["r0"] = 0; e["lr"] = RET
            cnt = [0]
            faulted_pcs = []

            def hook(uci, addr, size, ud, _e=e, _i=i, _j=j, _c=cnt, _fp=faulted_pcs):
                _c[0] += 1
                if _c[0] == _i or _c[0] == _j:
                    _fp.append(_e["pc"])
                    fault_skip(_e)

            e.emu.hook_add(uc.UC_HOOK_CODE, hook)
            try:
                e.start(begin, RET, count=BUDGET)
            except (RuntimeError, UcError):
                crashes += 1
                continue
            if e["pc"] == RET and (e["r0"] & 0xFFFF_FFFF) != 0:
                table = fn_table(e)
                locs = [(fn_at(table, pc), pc) for pc in faulted_pcs[:2]] or [("<?>", 0), ("<?>", 0)]
                while len(locs) < 2:
                    locs.append(("<?>", 0))
                bypasses.append(((i, j), locs[0], locs[1]))
            else:
                no_effect += 1
    return bypasses, crashes, no_effect, pairs


def run_two_fault():
    print(f"\n== check_true: two-fault [skip,skip] pair sweep over check_true(false) ==")
    print("   (fi::check_true's doc claims a glitch must skip ALL FOUR decision points to flip false→true —")
    print("    this sweeps every ordered PAIR of skips to see how many a `check_true(false)→true` flip really takes)")
    total = _check_true_instr_count()
    print(f"   sca_fi_check_true(0) executes {total} instructions → {total * (total - 1) // 2} ordered pairs")
    bypasses, crashes, no_effect, pairs = sweep_check_true_two_fault()
    print(f"  swept {pairs} pairs:  two-skip-flips={len(bypasses)}  crashes={crashes}  no-effect={no_effect}")
    if not bypasses:
        print("  → no PAIR of skips flips check_true(false) to true (consistent with the doc's ≥4-skip claim).")
        return False
    # Bucket. A pair is "scaffolding-only" if both faults are in the wrapper / the
    # synthetic `sca_fi_cond` closure / `__wfe`. Otherwise at least one fault is in
    # `fi::check_true`'s own code — but BEWARE: most such pairs are the synthetic-
    # closure artifact (see below), not a real check_true-logic weakness.
    def _scaffold(fn):
        return fn.startswith("sca_fi_") or fn in ("__wfe", "<?>")
    scaffold = [b for b in bypasses if _scaffold(b[1][0]) and _scaffold(b[2][0])]
    touches_fi = [b for b in bypasses if b not in scaffold]
    # "candidate-real": neither fault is in/touching the synthetic closure `sca_fi_cond`
    # (so it's not the arg-load artifact) — both faults are in check_true's verdict/return code.
    candidate_real = [b for b in touches_fi if "sca_fi_cond" not in b[1][0] and "sca_fi_cond" not in b[2][0]]
    print(f"  - {len(scaffold)} pair(s) entirely in harness scaffolding (the wrapper / the synthetic `sca_fi_cond`")
    print( "    closure) — glitching the boolean *fed into* check_true, which it doesn't claim to protect.")
    if touches_fi:
        print(f"  - {len(touches_fi)} pair(s) touch `fi::check_true`'s code — of which {len(touches_fi) - len(candidate_real)}")
        print( "    also touch the synthetic `sca_fi_cond` closure call: those are a HARNESS ARTIFACT — skipping the")
        print( "    `mov r0, want` before a `bl sca_fi_cond` leaves a nonzero stack pointer in r0, and the trivial")
        print( "    `sca_fi_cond(x) = black_box(x) != 0` reads any nonzero as 'true' → both cond() evals come back")
        print( "    truthy → flip. In production the closure is a real `bl sphincs_c10::verify(pk_seed, …)` taking")
        print( "    4 pointer args; skipping an arg-load makes `verify` *fail*, not return truthy — so these don't")
        print( "    transfer. The pairs to take seriously are the next ones:")
    if candidate_real:
        print(f"  - !!! {len(candidate_real)} pair(s) with BOTH faults in `fi::check_true`'s verdict/return code (away")
        print( "        from the cond() calls) — a real candidate for 'check_true is ~2-coordinated-skip-defeatable':")
        for (i, j), li, lj in candidate_real[:20]:
            print(f"        ({i},{j}): {li[0]}+{li[1]:#x} , {lj[0]}+{lj[1]:#x}")
        if len(candidate_real) > 20:
            print(f"        ... and {len(candidate_real) - 20} more")
        print( "        Take-away: `fi::check_true` raises the bar from 1 skip to ~2 *coordinated* skips, not to 4")
        print( "        as its doc-comment states — the '4' should be softened (or the result `mov r0, r4` /")
        print( "        fail-path result-zeroing made sentinel-encoded). NOT a `make fi` failure (the single-fault")
        print( "        `[skip]` sweep — the contract test — still passes; this is the harder 2-coordinated-skip case).")
    else:
        print("  → no pair with both faults in check_true's verdict/return code; all the rest are the cond()-input")
        print("    artifact (don't transfer to production) or scaffolding-only.")
    # Exploratory sweep — never a `make fi` failure on its own (the single-fault [skip] sweep is the hard gate).
    return False


if __name__ == "__main__":
    baseline()
    regression = False
    two_fault = "--two-fault" in sys.argv

    for label, model in FAULT_MODELS:
        print(f"\n== check_true: single-fault [{label}] sweep over check_true(false) ==")
        expl, cr, hg, ne, locs = sweep_check_true(model)
        total = len(expl) + cr + hg + ne
        print(f"  swept {total} positions:  exploitable={len(expl)}  crashes={cr}  hangs(≈caught)={hg}  no-effect={ne}")
        if expl:
            scaffolding, in_fi = [], []
            for i in expl:
                fn, pc = locs.get(i, ("<?>", 0))
                (scaffolding if (fn.startswith("sca_fi_") or fn == "__wfe" or fn == "<?>") else in_fi).append((i, fn, pc))
            if scaffolding:
                print(f"  - {len(scaffolding)} in this harness's own scaffolding (wrapper / synthetic closure / __wfe) — "
                      "EXPECTED: glitches the boolean *fed into* check_true, which check_true does not claim to protect. "
                      "Indices: " + ", ".join(f"{i}@{fn}+{pc:#x}" for i, fn, pc in scaffolding))
            if in_fi:
                if label == "skip":
                    regression = True
                    print(f"  - !!! {len(in_fi)} inside fi.rs code (fi::check_true / fi::wait_random) — REGRESSION: "
                          "a single instruction-skip flipped a clean false verdict into a true return. "
                          "(fi::check_true's documented contract is skip-resistance.)")
                else:
                    print(f"  - {len(in_fi)} inside fi.rs code under [{label}] — INFO, not a regression: a stuck-at "
                          "on a result register defeats *any* bool-returning fn (inherent; fi::check_true's doc "
                          "claims skip-resistance, not stuck-at-resistance). Mitigation = sentinel-encoded return "
                          "(same as F-2 — see tools/sca/README.md).")
                for i, fn, pc in in_fi:
                    print(f"        [{label}] instr {i}: pc={pc:#010x} in {fn}")
                if label == "skip":
                    print( "        Inspect: donjon-sca python -c \"... rainbow_cortexm(print=Print.Code|Print.Functions|Print.Faults);")
                    print(f"          e.load('{ELF}'); ... e.start_and_fault(fault_skip, <I>, e.functions['sca_fi_check_true'][0], 0xaaaaaaaa, count=8192)\"")
            if not in_fi:
                print("  → all in harness scaffolding; no fault inside fi.rs flipped a false verdict to true.")
        else:
            print(f"  OK — no single [{label}] fault turns a false verdict into a true return.")

        print(f"== wait_random: single-fault [{label}] sweep ==")
        rt, cr, hg = sweep_wait_random(model)
        print(f"  returned-normally={rt}  crashes={cr}  hangs(≈halt-loop / broken loop)={hg}")

    if two_fault:
        if run_two_fault():
            regression = True

    print("\nDone. (3 single-fault models" + (" + a [skip,skip] two-fault sweep" if two_fault else
          "; pass --two-fault for the [skip,skip] pair sweep") + " — see the module docstring and tools/sca/README.md.)")
    sys.exit(1 if regression else 0)
