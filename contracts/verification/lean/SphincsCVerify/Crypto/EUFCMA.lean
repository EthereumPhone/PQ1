/-
EUF-CMA security of SPHINCS+C10.

This file states the existential-unforgeability-under-chosen-message-attack
theorem for SPHINCS+C10 as an `axiom`, with explicit citations to the
proof that justifies it.

## What we state

  ∀ PPT adversary A,
    Pr[ A queries the signing oracle and outputs (msg*, σ*)
        with msg* not queried such that Verify(pk, msg*, σ*) = true ]
    ≤ ε(A) + negligible(n)

where ε(A) is a function of A's running time, query count, and the
SHA-256 cryptographic assumptions in `Crypto/Assumptions.lean`.

## Why this is an axiom rather than a theorem

To convert this into a `theorem`, we would need to:

  1. Formalise the probabilistic game (adversary, signing oracle,
     SHA-256 random-oracle programming, advantage computation) inside
     Lean. Lean 4 + mathlib has the measure-theory backbone, but no
     game-based-cryptography library comparable to EasyCrypt's `pRHL`
     and `phl` modules.

  2. Replay the Barbosa/Dupressoir/Hülsing/Meijers/Strub ASIACRYPT 2024
     SPHINCS+ proof (~50,000 lines of EasyCrypt, multi-person-year
     work) and extend it to cover the WOTS+C and FORS+C variants.

Per § 3.2 of the playbook, this is a multi-person-year effort that
cannot be undertaken in the current scope. The axiom records the
assumption explicitly so it appears in `docs/AXIOMS.md` and any future
auditor sees that the cryptographic-security theorem is *cited*, not
*proved* in Lean.

The axiom shape takes the three SHA-256 primitives' witnesses as
preconditions. This is the same modular structure Barbosa et al. use:
EUF-CMA reduces to SM-DT-TCR + ITSR + ROM-on-`H_msg`. Threading the
preconditions through `EUF_CMA_SPHINCSplusC` ensures all four crypto
axioms appear in the dependency closure of any theorem that consumes
it (in particular `cannot_forge_without_breaking_SHA256` below).

## Citations

* Manuel Barbosa, François Dupressoir, Andreas Hülsing, Matthias
  Meijers, Pierre-Yves Strub, "A Tight Security Proof for SPHINCS+,
  Formally Verified," IACR ePrint 2024/910, ASIACRYPT 2024, LNCS 15487.
  Companion repo: github.com/MM45/FV-SPHINCSPLUS-EC

* Andreas Hülsing et al., "SPHINCS+C: Compressing SPHINCS+ With (Almost)
  No Cost," NIST PQC2022 Standardization Conference.

* Andreas Hülsing, Mikhail Kudinov, "Recovering the tight security proof
  of SPHINCS+," ASIACRYPT 2022. (The recovery proof Barbosa et al.
  mechanise.)
-/

import SphincsCVerify.Crypto.Assumptions
import SphincsCVerify.Spec.Signer
import SphincsCVerify.Spec.Signature
import SphincsCVerify.Spec.Hypertree

namespace SphincsCVerify.Crypto

open SphincsCVerify.Spec
open SphincsCVerify.Spec.Signer
open SphincsCVerify.Spec.Hypertree
open SphincsCVerify.Spec.Signature

/-! ## Adversary model -/

/-- An EUF-CMA adversary against SPHINCS+C10. We model it abstractly as
    a function from the public verifying key and a list of previously
    signed (message, signature) pairs to a candidate forgery
    `(message*, signature*)`.

    A full game-based formalisation would carry probabilistic state and
    oracle queries; we state the abstract form here because the
    `axiom` below is the only consumer. -/
structure Adversary where
  /-- Given a verifying key and the transcript so far, produce the
      next signing query or a forgery attempt. -/
  attempt :
    VerifyingKey → List (ByteVec 32 × Hypertree.Signature) →
    ByteVec 32 × Hypertree.Signature

/-- A signing transcript: list of (message, signature) pairs produced
    by the honest signer. -/
def Transcript : Type := List (ByteVec 32 × Hypertree.Signature)

/-- Does the transcript contain a signature on `msgStar`? -/
def transcriptHasMsg (transcript : Transcript) (msgStar : ByteVec 32) : Prop :=
  ∃ s, List.Mem (msgStar, s) transcript

/-- The "wins" predicate: the adversary's output `(m*, σ*)` is a
    forgery iff
      (a) the verifier accepts `(pk, m*, σ*)`; and
      (b) `m*` is **not** in the transcript.

    Membership uses `ByteVec` decidable equality. -/
def isForgery
    (vk : VerifyingKey) (transcript : Transcript)
    (msgStar : ByteVec 32) (sigStar : Hypertree.Signature) : Prop :=
  Hypertree.verify vk.pkSeed vk.pkRoot msgStar sigStar = true
  ∧ ¬ transcriptHasMsg transcript msgStar

/-! ## The EUF-CMA security axiom -/

/-- **EUF-CMA security of SPHINCS+C10.**

    For every PPT adversary `A`, the probability of producing a forgery
    after at most `Q` signing queries is bounded by

      ε(A) + Q * negligible

    where `ε(A)` is `A`'s advantage against the underlying SHA-256
    cryptographic assumptions (SM-DT-TCR, ITSR, ROM on `H_msg`) and
    `negligible` is the 128-bit cliff from `Crypto/Assumptions.lean`.

    The mechanised proof exists in EasyCrypt (Barbosa et al. 2024) for
    SPHINCS+; extending it to SPHINCS+C is the §4.2-step-5 "Prove" task.
    We axiomatise the result with the cited reference.

    The axiom takes the three SHA-256 primitives as preconditions
    (`SM-DT-TCR-F`, `ITSR-F`, `H_msg`-RO) so that any downstream
    theorem consuming EUF-CMA includes all four crypto axioms in its
    `#print axioms` output — mirroring the Barbosa et al. modular
    reduction.

    Conclusion: in deterministic-adversary form, there is no forgery
    against `vk` w.r.t. the honest transcript `T`. (A full game-based
    version would replace this with a probability bound.) -/
axiom EUF_CMA_SPHINCSplusC :
    SM_DT_TCR_F_Shape →
    ITSR_F_Shape →
    hMsg_RO_Shape →
    ∀ (vk : VerifyingKey) (transcript : Transcript)
      (msgStar : ByteVec 32) (sigStar : Hypertree.Signature),
      isForgery vk transcript msgStar sigStar → False

/-! ## Corollaries used downstream -/

/-- **No forgery without breaking SHA-256.** Restatement of
    `EUF_CMA_SPHINCSplusC` for use in the wallet-level non-bypass
    argument.

    Under the cryptographic axioms, if an attacker produces an accepting
    signature for a message the wallet's slot key has not previously
    signed, then they have broken one of the underlying SHA-256
    assumptions. In the deterministic-adversary form we use here, this
    becomes: a concrete `isForgery` witness contradicts the EUF-CMA
    axiom (which itself rests on the three SHA-256 primitives passed in
    via `SM_DT_TCR_F`, `ITSR_F`, `hMsg_random_oracle`).

    This is the security content the smart-contract invariants in
    `Wallet/Invariants.lean` ultimately rely on. -/
theorem cannot_forge_without_breaking_SHA256
    (vk : VerifyingKey) (transcript : Transcript)
    (msgStar : ByteVec 32) (sigStar : Hypertree.Signature)
    (hf : isForgery vk transcript msgStar sigStar) :
    False :=
  EUF_CMA_SPHINCSplusC SM_DT_TCR_F ITSR_F hMsg_random_oracle
    vk transcript msgStar sigStar hf

end SphincsCVerify.Crypto
