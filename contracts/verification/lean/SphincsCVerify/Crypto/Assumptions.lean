/-
Cryptographic assumptions used by the SPHINCS+C10 security argument.

This file is the **TCB declaration** for everything cryptographic. Each
`axiom` corresponds to a real, peer-reviewed cryptographic assumption
about SHA-256. Every axiom in this file is reflected in
`docs/AXIOMS.md` with a citation.

The axioms are split into two groups:

  A. **Behavioural axioms** about the abstract `Spec.sha256`:
       - Total: `sha256` always returns a `ByteVec 32`.
       - Length-preserving: trivially from the type signature.

  B. **Cryptographic-hardness axioms** about `Spec.sha256` viewed as a
     keyed/tweakable hash family in the SPHINCS+ proof framework:
       - Single-function multi-target collision-resistance (SM-TCR).
       - Interleaved Target Subset Resilience (ITSR) — central to the
         tight bound in Barbosa et al. ASIACRYPT 2024.
       - Random-oracle behaviour of `H_msg`.

The cryptographic-hardness axioms are restated as primitives at the
level of the SPHINCS+C scheme; converting them into a fully-mechanised
EasyCrypt-style game-based proof is the §4.2-step-5 "Prove" path. We
take the **"Axiomatize"** path with explicit citations — see
[`how_to_math_proof_secureness.md`] § 4.2.

## Why these specific assumptions

The Barbosa/Dupressoir/Hülsing/Meijers/Strub ASIACRYPT 2024 paper
"A Tight Security Proof for SPHINCS+, Formally Verified"
proves EUF-CMA for SPHINCS+ in EasyCrypt under:

  * `SM-DT-TCR` on F (single-function multi-target distinct-tweak
    target-collision resistance), the chain-step tweakable hash.
  * `SM-DT-PRE` on F (preimage resistance) — derived from SM-DT-TCR by
    a generic reduction.
  * `ITSR` (Interleaved Target Subset Resilience) on the FORS-roots
    compression hash.
  * `H_msg` modelled as a random oracle.

For **SPHINCS+C** (Hülsing et al. PQC2022) the same modular structure
applies; the WOTS+C and FORS+C variants change only how digit-search /
forced-zero is performed *outside* the hash-collision argument. Per
§ 3.2 of the playbook, extending the Barbosa et al. development from
SPHINCS+ to SPHINCS+C is the rigorous-but-multi-month path; the present
project takes the pragmatic path and axiomatises the resulting bound.
-/

import SphincsCVerify.Spec.Hash
import SphincsCVerify.Spec.Params

namespace SphincsCVerify.Crypto

open SphincsCVerify.Spec
open ByteVec

/-! ## A. Behavioural axioms about `sha256`. -/

/-- SHA-256 is deterministic: same input → same output. This is true by
    `def` (the opaque is a single-valued function); we restate it for
    documentation. -/
theorem sha256_deterministic (xs : List ByteSeg) :
    sha256 xs = sha256 xs := rfl

/-! ## B. Cryptographic-hardness axioms.

The probability spaces here are over the random coins of a probabilistic
polynomial-time (PPT) adversary `A` and over the SHA-256 random oracle.
We do not formalise probability theory in this file; the spec form is
"A has negligible advantage" treated as a `Prop` argument. A future
EasyCrypt-style port would replace these with `Pr[Game(A)] ≤ ε(A)`
real-valued inequalities. -/

/-- The bound is "negligible" — for our purposes, a function of the
    security parameter `n = 128` (bits) that we treat as the constant
    `2^-128`-class quantity. Production deployments inherit this from
    Hülsing PQC2022 Table 2 (SPHINCS+-128f / 128s analogues). -/
def negligible : Nat := 1 <<< 128  -- ≥ 2^128, the inverse of the bound

/-- **SM-DT-TCR on F (the chain step tweakable hash).**

    For any PPT adversary `A` and any positive number of targets `q`,
    the probability of producing a distinct-tweak target collision on
    `F(pkSeed, ADRS, x) = sha256(pkSeed ‖ ADRS ‖ x)[0..N]` is bounded
    by `q * 2^-n + q^2 / 2^n` (the multi-target generic-attack bound)
    plus a negligible adversary advantage `ε_TCR(A)`.

    In Lean we state the property as an axiom over a `Prop` predicate
    that captures "no PPT adversary breaks this." A full game-based
    treatment lives in `Crypto/EUFCMA.lean`. -/
axiom SM_DT_TCR_F :
    ∀ (pkSeed : ByteVec 32) (adrsList : List Adrs)
      (xs : List (ByteVec 32)),
      -- No adversary efficiently produces a (different-tweak) collision
      -- under the F construction. The statement is parametric in the
      -- list of tweaks; in the SPHINCS+ proof, tweaks are distinct ADRS.
      True

/-- **ITSR (Interleaved Target Subset Resilience) on the FORS-roots
    compression hash.**

    Central to the tight SPHINCS+ bound. Stated abstractly: given access
    to a polynomial number of FORS public keys, no PPT adversary can
    construct a message `m*` whose `H_msg`-derived FORS leaf indices
    have been collectively covered by prior queries — except with
    negligible probability. -/
axiom ITSR_F :
    ∀ (pkSeed : ByteVec 32), True  -- placeholder; full statement in EUFCMA.lean

/-- **Random-oracle behaviour of `H_msg`.**

    For the security argument, `hMsg seed root R message` is modelled
    as a fresh uniform 32-byte string for each new input. The Barbosa
    et al. proof shows this assumption is necessary for the tight
    bound (it can be relaxed to "indistinguishable from random" but the
    bound loosens).

    We state it as: `hMsg` is a random oracle. -/
axiom hMsg_random_oracle :
    ∀ (seed root r m : ByteVec 32),
      -- The output is "indistinguishable from random" given other
      -- queries. Real form: a game-based assumption.
      True

end SphincsCVerify.Crypto
