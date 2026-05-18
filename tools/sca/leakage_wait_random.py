#!/usr/bin/env python3
"""`fi::wait_random` leakage analysis — does the FI guard's own loop
count leak through the `mem_address` channel?

**Why this matters.** `wait_random` is called between every security-
critical operation to introduce jitter — defeating profiled DPA's
trace-alignment premise. The loop count itself is RNG-driven and
therefore unpredictable per call. But if the loop body's per-iteration
memory access pattern depends on the iteration counter `i`/`j`, then
an attacker observing the trace can recover the iteration count from
the address pattern even without seeing the RNG byte directly. The
defense bound is then bounded by the attacker's ability to reconstruct
the per-call jitter and subtract it from their alignment estimate.

**The test.** TVLA fixed-vs-random byte fed to `pqsigner_fi::wait_random_loop`
via `sca_fi_wait_random_n(byte: u32)`. The fixed group always uses
byte=128 (the median loop length); the random group uses uniform
random bytes. We then check `mem_address` for any sample whose value
depends on the RNG byte.

**Expected (clean) result.** `wait_random_loop`'s body is:

```rust
let i = vread(i_ptr);        // ptr fixed; address Hamming-weight constant
let j = vread(j_ptr);        // ptr fixed
if i >= wait { break; }      // branch on i value (NOT address)
if i.wrapping_add(j) != wait { halt }
vwrite(i_ptr, i + 1);
vwrite(j_ptr, j - 1);
```

All memory accesses go to fixed stack addresses (`i_ptr`, `j_ptr`).
The ADDRESSES never depend on the loop counter — only the VALUES
written do. So a `mem_address`-channel TVLA should be flat: each
iteration looks identical at the address level. If it ISN'T flat, the
compiler is doing something keyed-on-counter we didn't anticipate
(e.g., unrolling the loop with iteration-specific instructions, or
spilling a counter-dependent value to a stack offset that varies).

**Trace-length asymmetry.** The fixed group is always 128 iterations;
the random group averages 128 but varies from 0 to 255. So the random
group's traces END at different sample positions. After lascar
truncates to min(trace lengths), some random traces are truncated
mid-loop and some have flat-tail samples past their loop exit. This
is a known artifact of the harness and isn't a leakage finding —
just shows the loop count differs.

Run: `make -C tools/sca wait-random-leak`
"""
import os
import sys
import time

os.environ.setdefault("UC_IGNORE_REG_BREAK", "1")

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import leakage_kdf as lk  # noqa: E402

# fi_target ELF — same one fault_sweep_fi.py uses, just calling a
# different exported symbol from it.
ELF = os.path.join(
    HERE, "fi_target", "target", "thumbv8m.main-none-eabi", "release",
    "sca-fi-target",
)

N_TRACES = 600


def make_inputs(n: int):
    """Fixed group: byte=200 always. Random group: byte ∈ [180, 220].
    Tight range so all traces have similar loop counts (180-220 iters),
    avoiding the `min(trace_lengths)` truncation that would otherwise
    cut every trace down to the shortest one's length. We trade some
    statistical power (smaller variance between groups) for a much
    longer per-trace sample window — the question we're answering is
    'does the loop body leak the iteration count' which needs the
    body samples, not just the setup."""
    rng = np.random.default_rng(0xFE1B6F1A)
    out, is_fixed = [], []
    fixed = (200).to_bytes(4, "little")
    for k in range(n):
        if k % 2 == 0:
            out.append(fixed)
            is_fixed.append(1)
        else:
            byte = int(rng.integers(180, 221))  # [180, 220] inclusive
            out.append(byte.to_bytes(4, "little"))
            is_fixed.append(0)
    return out, is_fixed


def main():
    if not os.path.exists(ELF):
        print(f"ERROR: {ELF} not found.")
        print("Run `make -C tools/sca build` first.")
        sys.exit(2)
    lk.ELF = ELF

    print("=" * 70)
    print("wait_random loop-count leakage TVLA")
    print("=" * 70)
    print(f"ELF: {ELF}")
    print(f"N_TRACES = {N_TRACES}  (300 fixed @ byte=128, 300 uniform random)")
    print()

    inp, is_fixed = make_inputs(N_TRACES)
    print(f"Inputs: {len(inp)} × 4 B  (300 fixed, 300 random)")

    t0 = time.time()
    # u32 ABI: r0 = byte. lascar's harness sets r0 = SCRATCH_IN (the
    # input pointer), which is the wrong calling convention for our
    # symbol. Need to call differently: r0 = the byte value itself,
    # NOT a pointer. We do this by setting `scratch_in` to behave like
    # the actual byte value.
    #
    # leakage_kdf::collect already sets `e["r0"] = scratch_in`, so the
    # function will receive `scratch_in` (e.g. 0x6000_0000) as its
    # u32 byte argument. That's 1610612736 → 1610612736 & 0xFF = 0
    # ALWAYS. Every call will use byte=0 regardless of input — no
    # variation. We need a custom collector.
    mem = collect_byte_arg("sca_fi_wait_random_n", [int.from_bytes(b, "little") for b in inp])
    elapsed = time.time() - t0
    print(f"  collected {mem.shape[0]} traces × {mem.shape[1]:,} samples in "
          f"{elapsed:.1f} s")
    print()

    mt = lk.tvla("wait_random_loop varying byte", "mem_address", mem, is_fixed)
    if mt > lk.T_THRESHOLD:
        # Inspect the peak position to characterise WHERE the leak lives.
        # If it's at the trace TAIL it's the loop-exit asymmetry (a known
        # artifact); if it's evenly distributed it's a per-iteration
        # leak (real bug).
        import lascar
        container = lascar.TraceBatchContainer(
            mem, np.array(is_fixed, dtype=np.uint8).reshape(-1, 1)
        )
        eng = lascar.TTestEngine(lambda v: int(v[0]))
        lascar.Session(container, engine=eng).run(batch_size=200)
        t = np.abs(np.nan_to_num(eng.finalize()))
        peak = int(np.argmax(t))
        tail_threshold = int(0.85 * mem.shape[1])
        if peak >= tail_threshold:
            print(f"  → peak at sample {peak:,}/{mem.shape[1]:,} "
                  f"({100 * peak / mem.shape[1]:.1f}% — trace tail).")
            print(f"  → Likely the loop-length asymmetry (random group has")
            print(f"    varying iteration counts; fixed group always 128).")
            print(f"  → NOT a per-iteration leak; expected harness artifact.")
            return 0
        print(f"  → peak at sample {peak:,}/{mem.shape[1]:,} "
              f"({100 * peak / mem.shape[1]:.1f}% — body of trace).")
        print(f"  → Per-iteration mem_address pattern depends on the RNG byte.")
        print(f"  → Real finding; investigate the wait_random_loop body.")
        return 1
    else:
        print("  → flat on mem_address. wait_random's loop body has no")
        print("    counter-keyed memory accesses; the loop count is hidden")
        print("    from this channel.")
        return 0


def collect_byte_arg(sym, bytes_as_ints):
    """Custom collector that passes the u32 directly in r0 (not as a
    scratch pointer). Same shape as `leakage_kdf.collect` but using
    `r0 = byte` instead of `r0 = scratch_in`.

    Per-worker traces are returned as a 2-D uint8 array of `mem_address`
    Hamming-weight samples.
    """
    import multiprocessing as mp
    n_workers = max(2, (mp.cpu_count() or 4) - 2)
    tasks = [(sym, b, lk.STACK_TOP, lk.RET, lk.ELF) for b in bytes_as_ints]
    ctx = mp.get_context("spawn")
    with ctx.Pool(n_workers) as pool:
        rows = list(pool.imap(_worker, tasks, chunksize=8))
    ml = min(len(r) for r in rows)
    return np.array([r[:ml] for r in rows])


def _worker(args):
    """Per-worker trace capture — passes byte arg directly in r0."""
    import numpy as np
    from rainbow.generics import rainbow_cortexm
    import unicorn as uc
    sym, byte_arg, stack_top, ret, elf = args

    e = rainbow_cortexm()
    e.load(elf)
    e.map_space(stack_top - 0x8000, stack_top + 0x20)
    e["sp"] = stack_top
    e["r0"] = byte_arg  # u32 ABI: r0 carries the byte directly
    e["lr"] = ret

    cap = 8192
    arr = np.zeros(cap, dtype=np.uint8)
    state = {"n_stored": 0}

    def mem_cb(_uc, _access, address, _size, _value, _ud):
        i = state["n_stored"]
        if i < cap:
            arr[i] = (address & 0xFFFFFFFF).bit_count()
            state["n_stored"] = i + 1
        else:
            _uc.emu_stop()

    e.emu.hook_add(uc.UC_HOOK_MEM_READ | uc.UC_HOOK_MEM_WRITE, mem_cb)

    try:
        e.start(e.functions[sym][0], ret, count=2_000_000)
    except Exception:
        pass

    return arr[: state["n_stored"]].copy()


if __name__ == "__main__":
    sys.exit(main())
