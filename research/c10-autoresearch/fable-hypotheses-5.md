# C10 autoresearch, round 6: Fable 5.2's new v2 hypotheses (2026-11-13)

Fable worked read-only against branch head `85fc69bef` (H1–H6 kept): mean sign 69.80 M, keygen 22.05 M, 48.47 M with the top cache. It ran no builds or kit runs. Its cycle figures are instruction counts from the disassembly, not measurements. Outcomes are in `ledger.md`, round 6.

**Unexplained gap.** Keygen is 43.1k cycles per key. Minus T_43 (about 1.4k), that is about 120 cycles per chain digest against a unit-cost formula of about 111 (less H6's STR write). About 10 cycles per digest, roughly 3.5 M per pass, is unaccounted for.

Digests per pass: 352.8k chain + PRF (182k with the cache), 79.8k FORS, 61.4k grind tries.

## Ranked list

0. **Test zero.** Time `pqsigner_v2_chain16` with `steps = 4096` alone, and count ready-poll turns per step. Use keygen (constant work, no grind) as the evaluator for items 1–3.
1. **Register diet in the chain and subtree loops** (output-identical).
   - Each chain step reloads four values from the stack between DIN stores: 15 live values against 13 usable registers.
   - Frees: use the A7 word as the loop counter; make the timeout an immediate.
   - The subtree entry reloads all four `S` words per digest.
   - Expected about 1.5 M per pass (ceiling about 3 M).
2. **Poll-phase sweep** (output-identical). DCAL to DCIS is fixed, and a poll turn is about 8 cycles, so post-DCIS latency is 0–8 cycles set by code shape. That would explain why removing reads made loops slower (H5, v1 lever 3). Insert 0..7 `nop`s before the first poll; expected about 1 M per pass. Re-sweep after any loop edit.
3. **Feed digests back with no byte swap (DATATYPE = 32-bit)** (output-identical). It drops four `rev`s per feedback digest: about 1.5 M per pass. Risks:
   - the BUSY tail may already hide them (H5 precedent);
   - NBLW semantics in that mode were not checked.
4. **Retune `target_sum`** (format and parameter). Exact tries per grind: 30,698 at 205, 9,192 at 200, 3,130 at 195.
   - At 200: −5.8 M per pass (8%), verify +10 hashes (about +2.5–4.5k gas).
   - It reopens every proof constant tied to 205.
5. **Two secrets per PRF digest** (format: keys and addresses change; the verifier does not).
   - About −4 M per pass, keygen −1.3 M; it halves the `sk_seed`-keyed digests (the DPA target).
   - The second secret waits on the stack and needs a wipe.
6. **Asymmetric hypertree split 8 + 10** (format, only with the top cache). About −11 M per pass on the cached head.
   - Keygen doubles. A7's `kp` needs 10 bits.
   - The cache stops being optional (structural FI trade).
7. **Whole-layer driver entry** (output-identical): under 1 M per pass. It moves Merkle logic out of the extracted Rust.
8. **Pass B reuses pass A's R nonce** (track B): about 0.8 M per pass. Unreviewed FI analysis.

**FI passes:** nothing else redundant; H15 and H16 stand.

## Not worth doing

- **T_43:** at the floor; it cannot reach 11 blocks.
- **Grind micro-tuning:** the try count is fixed by the format; only item 4 changes it.
- **Dropping or shortening `S`:** a multi-target security change.
- **Several digit windows per digest.**
- **Grinding R toward a cached layer-0 tree:** it breaks few-time security.
- **w = 4.**
- **Fused R grind** (estimated about 0.7 M) **and §6's one-block R** (about 0.3 M). Note: the fused R grind was measured as H7 at −0.73 M mean.
- **One-block H_MSG.**

## What Fable could not check

- Cycle counts (from disassembly only).
- The 120-versus-111 split between loop and entry.
- NBLW with DATATYPE = 00.
- Gas per added chain step.
- The FV impact of items 4–6.
- The FORS parameters (k, a).
