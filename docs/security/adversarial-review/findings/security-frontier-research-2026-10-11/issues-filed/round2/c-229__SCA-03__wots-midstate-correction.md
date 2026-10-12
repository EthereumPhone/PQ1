COMMENT_ON: 229
---
A correction to one sentence of this issue's premise, and one small follow-up, from the 2026-10 security research (item SCA-03). The item's own proposal was reviewed and should **not** be built; what survives is the correction. Lines are at master `c2fab970`.

**The correction**

This issue, and the archived note it was migrated from (`docs/archive/work-todo-retired-2026-07-19.md:1920`), say there is no cacheable midstate after `sk_seed` because `sk_seed` is not block-aligned, and that any midstate route changes the PRF layout and so breaks launch invariant 6. For the half of the pseudo-random function (PRF) that serves the one-time signatures (WOTS), that is not what the code does:

- `sphincs-c10/src/hash.rs:378`: `wots_secret` hashes `sk_seed` (32 bytes), "wots" (4), the layer (4), a 32-byte tree field, the key-pair index and the chain index.
- `sphincs-c10/src/hash.rs:180`: the tree field is a 64-bit value written into the last 8 of its 32 bytes. The first 24 are zero.
- So the first 64-byte block is `sk_seed`, "wots", the layer and 24 zero bytes. With two layers (`sphincs-c10/src/params.rs:25`) there are exactly two possible first blocks per key. The state after the first block is constant per key and layer, with the layout unchanged and the output byte-identical. Invariant 6 is not touched.
- The invariant-6 objection does hold for `fors_secret` (`sphincs-c10/src/hash.rs:410`), which is a single block, and for the secret-keyed grind.

**Why this still is not a countermeasure to build**

The research proposed computing those two midstates once per signature and resuming from them. The review refuted it as a side-channel measure:

- `fors_secret` and the grind still absorb `sk_seed` at a fixed offset tens of thousands of times per signature, so the exposure of the raw seed falls by a small factor, not to zero.
- Resuming means loading a secret midstate into the hash engine once per call, at a fixed offset, about as often as the seed is loaded today. By the reviewer's analysis the top-layer midstate alone is enough to forge. The leak is moved, not removed.
- It needs a context-restore path that the HASH driver does not have (`hw/src/hash.rs` has no context-swap registers), it moves the formal-verification extraction pins of the hash module, and it would share one cached secret across both passes of the double computation.
- Which load leaks more on this silicon is unknown until #228 is run.

So: keep this issue as the next-generation candidate it is, correct the "no cacheable midstate" sentence so that it applies to FORS and the grind only, and do not schedule a midstate change before #228 has a result.

**Follow-up that is worth doing now**

- [ ] Split the hash census (`sphincs-c10/src/hash.rs:63`) into two counts: calls that absorb raw `sk_seed`, and compressions that run on a secret chaining value. Add the grind, which hashes `sk_seed` (`sphincs-c10/src/fors.rs:117`) and is not counted today. Do not lower the existing lower bounds in `sphincs-c10/tests/hash_counts.rs:73`; second-block compressions stay secret-touching.

Firmware and test only. Note that the hash-counter tests run in no CI suite (#722).

<sub>**Provenance.** Security frontier research, 2026-10-11 (report item SCA-03, section 4; status "redesign needed", refuted as written). Report priority P3 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
