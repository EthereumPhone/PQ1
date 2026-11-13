# C10 autoresearch, round 7: Fable 5.2's driver hypotheses (2026-11-13)

Constraint for this round: output-identical changes only (owner: no change to any security bound).
Read-only advice; cycle figures are arithmetic from the ledger's unit costs, not measurements.

**Ceiling:**
- **v2:** about 5-6 M per pass (8-9% of 65.6 M), realistically 2.5-4 M. Another ~3 M exists only by changing fault posture or relying on #1151.
- **v1:** about 5-8 M of 110 M.

**Cost model:**
- One-block digests start the engine only at DCAL, so CPU work is serial with the engine.
- Chain step: 18 bus accesses × ~2.6 + 65 engine = ~112, against 116.2 measured.
- fors_subtree16: excess ~20 cycles per digest, from serial per-leaf bookkeeping.
- search43: excess 12-18 cycles per try.
- The four `rev`s per feedback digest sit inside the floor.

**Microbench first:**
- **Engine floor:** INIT, 10 DIN, DCAL, N nops, one SR read; sweep N.
- **Store cost:** K back-to-back DIN stores.
- **HR read:** `ldm` ×4 against 4 `ldr`.
- **Search:** a real-target case, since 137 is all early reject.

## Ranked

**Group A: output-identical**

1. **Two-tier DCIS poll**, straight-line first polls in `v2_wait_dcis`: ~2 cycles/digest, ~1 M. [v1]
2. **Timed first poll**, padded to the measured engine time: 3-4 cycles/digest, 1.5-2 M. Overlaps item 1. [v1]
3. **DATATYPE = 32-bit for feedback digests**: no `rev`, ~1.5 M. Risk: NBLW semantics under DATATYPE 00. [v1] ~1.2 M
4. **fors_subtree16:** index bookkeeping and sibling load inside the engine window (split DCAL/take): 0.8-1.2 M.
5. **wots_chains16:** per-chain store and index work in the next PRF's window: ~0.35 M.
6. **search43:** preload the 8 sm words during the wait: 0.3-0.5 M.
7. **Skip the redundant entry ready poll and STR write** between chained entries: ~0.1 M.
8. **grind_r:** word-level patch and an HR3-only read per try: ~0.2 M.
9. **Whole-layer entry:** ≤ 0.3 M. [FV-major]

**Group B: fault posture or undocumented behaviour (owner decision)**

10. **Drop the per-digest SR_DINIS clear**, if INIT clears DCIS: 1.3 M. Removes a stale-DCIS tripwire.
11. **no-busy-wait on the v2 loops (#1151):** ≤ 1-2 cycles/digest.

**v1 (deployed format)**

13. **search128:** digit sum plus exact early reject in the driver, with no extern `pred` per try: 3-5 M.
14. **chain_steps:** countdown poll with an encodable immediate, since `t > 10_000_000` pins a register: 1-3 M. [FSBL] Keep it behind the secure-only feature.
15. **v1 R grind in the driver:** 0.7-1 M.

**Non-driver**
- Profile v2 head; about 2 M sits outside the driver entries.
- `pack`'s release asserts on the generic path.
- Parity check: product builds lack `target-cpu=cortex-m33`.

**Not worth doing:** see the round 6 discards, midstate, DMA, asm chain step, H10/H11, T_43, track-B reuse.

**Order:** microbench → 1/2 → 3 → 4 → 13 → 14 → 5, 6, 8 → Group B to the owner.
