**Pre-launch strategic decision. Nothing has landed, and nothing frozen was changed.** Measured during the 2026-11-12 signing-speed loop.

## Finding

On the U585 HASH, hashing is engine-bound per **block**: 66 cycles per SHA-256 block, plus ~2.6 cycles per input word. Every C10 tweakable-hash preimage spans 2–3 blocks:

| preimage | size | blocks |
|---|---:|---:|
| `th` and chain steps | 96 B | 2 |
| `th_pair`, nodes and count-grind tries | 128 B | 3 |
| WOTS PRF | 80 B | 2 |

The cheaper ways around this were measured and are dead:

- A midstate via context restore costs as much as the block it saves: 108 cycles, and 36 of the 38 context registers carry state.
- DMA feed is no faster.
- Per-digest cost is at the engine floor, and the digest count is at the FI-design minimum.

A preimage of ≤ 55 bytes is **one** block. A kit prototype of the chain step, with the same loop and the same checks:

| chain step | cycles |
|---|---:|
| today: 96 B, 2 blocks | 198 |
| hypothetical: 52 B (`seed16 ‖ compact address ‖ value16`), 1 block | **119 (−40%)** |

## What a one-block "C10 v2" would mean

**Shape:**

- the seed truncated to 16 bytes;
- a compact address (C10's fields fit in ≤ 7 bytes);
- 16-byte values;
- chains `seed ‖ adrs ‖ v`, nodes `seed ‖ adrs ‖ left ‖ right` (55 B), and the grind `seed ‖ adrs ‖ msg ‖ count`.

**Projected effect**, by arithmetic on the measured unit costs:

- about −36% per signing pass;
- cached sign: ~1.47 s → ~0.95 s without the top cache, and ~1.02 s → ~0.68 s with it (#1148);
- keygen roughly halves;
- on-chain verification gas also drops. The SHA-256 precompile costs 60 + 12 per word, so a `th` goes from 96 to 84 gas and a node from 108 to 84.

**Cost.** This is why it is a decision, not an optimisation.

- **Wire format:** every hash preimage changes. The signature stays 4,008 B, but its bytes change.
- **On-chain verifier (`SPHINCsC10Asm.sol`):** it changes, and with it the codehash pins, the initCode hash and **every wallet address**.
- **Invariant 6:** it allows this only before launch. CLAUDE.md says no devices have shipped and that parameters and tags are still renamable.
- **Formal verification and tests:** all KATs, the Lean extraction, the EasyCrypt drafts and the probability claims for the hash layer must be redone.
- **Security argument:** the tweakable-hash argument needs a fresh pass. The compact address keeps domains separated, and the 16-byte seed/value is the standard "simple" shape, but it still needs review.
- **Upstream:** it diverges from upstream SPHINCS-.

**Deadline:** the option exists only until launch.
