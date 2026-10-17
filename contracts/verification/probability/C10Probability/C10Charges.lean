import C10Probability.C10Sign
import C10Probability.C10Verify
import C10Probability.C10Keygen

/-! Derived costs of the complete executed clients. Prefix comparisons use
independent uniform hidden secrets and initially empty tables. Node charges
use the actual shared physical oracle, count cached calls in their budgets,
and retain the total-call zero term. These are not a forgery reduction. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

theorem c10_finish_physical_eval (secret : Digest) (table : Memo ByteKey Digest)
    (seed : ByteKey) (randomizer : Randomizer) (digest : Digest) (shuffle : ByteKey)
    (n : ℕ) (hn : n ≤ 2 ^ 32) :
    evalProgram digestDraw (mapProgram (privateKey prefixedPrivateInput secret)
      (c10FinishProgram id seed randomizer digest shuffle n hn)) table =
      c10Finish (privateKey prefixedPrivateInput secret) table seed randomizer digest shuffle n hn := by
  rw [c10_finish_map]
  exact c10_finish_eval _ _ _ _ _ _ _ _

theorem c10_sign_physical_eval (secret : Digest) (table : Memo ByteKey Digest)
    (random message seed root shuffle : ByteKey)
    (m n : ℕ) (hm : m ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32) :
    evalProgram digestDraw (mapProgram (privateKey prefixedPrivateInput secret)
      (c10SignProgram id random message seed root shuffle m n hm hn)) table =
      c10Sign (privateKey prefixedPrivateInput secret) table random message seed root shuffle m n hm hn := by
  rw [c10_sign_map]
  exact c10_sign_eval _ _ _ _ _ _ _ _ _ _ _

theorem c10_finish_prefix_error (seed : ByteKey) (randomizer : Randomizer)
    (digest : Digest) (shuffle : ByteKey) (n : ℕ) (hn : n ≤ 2 ^ 32)
    (event : Set (Option C10Signature)) :
    |((privateShared digestDraw digestDraw prefixedPrivateInput
        (PMF.pure (c10FinishProgram id seed randomizer digest shuffle n hn))).toOuterMeasure event).toReal -
      ((privateIndependent digestDraw
        (PMF.pure (c10FinishProgram id seed randomizer digest shuffle n hn))).toOuterMeasure event).toReal| ≤
      ((2 * n + 364290 : ℕ) : ℝ) / 2 ^ 256 := by
  apply private_secret_event_error_real _ (2 * n + 364290)
  intro program hp
  have he : program = c10FinishProgram id seed randomizer digest shuffle n hn := by simpa using hp
  rw [he]
  exact c10_finish_public _ _ _ _ _ _

theorem c10_sign_prefix_error (random message seed root shuffle : ByteKey)
    (m n : ℕ) (hm : m ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32)
    (event : Set (Option C10Signature)) :
    |((privateShared digestDraw digestDraw prefixedPrivateInput
        (PMF.pure (c10SignProgram id random message seed root shuffle m n hm hn))).toOuterMeasure event).toReal -
      ((privateIndependent digestDraw
        (PMF.pure (c10SignProgram id random message seed root shuffle m n hm hn))).toOuterMeasure event).toReal| ≤
      ((m + 2 * n + 364290 : ℕ) : ℝ) / 2 ^ 256 := by
  apply private_secret_event_error_real _ (m + 2 * n + 364290)
  intro program hp
  have he : program = c10SignProgram id random message seed root shuffle m n hm hn := by simpa using hp
  rw [he]
  exact c10_sign_public _ _ _ _ _ _ _ _ _

theorem c10_finish_domain_bad_bound (secret : Digest) (seed : ByteKey)
    (randomizer : Randomizer) (digest : Digest) (shuffle : ByteKey)
    (n : ℕ) (hn : n ≤ 2 ^ 32) (hs : seed.length = 32) :
    (c10Finish (privateKey prefixedPrivateInput secret) (fun _ => none)
      seed randomizer digest shuffle n hn).toOuterMeasure {out | DomainNodeBad out.2} ≤
        ((Nat.choose 435042 2 + (2 * n + 435044) : ℕ) : ℝ≥0∞) / 2 ^ 128 := by
  have h := digest_program_domain_node_bad_bound
    (PMF.pure (c10FinishProgram (privateKey prefixedPrivateInput secret)
      seed randomizer digest shuffle n hn)) 435042 (by
        intro program hp
        have he : program = c10FinishProgram (privateKey prefixedPrivateInput secret)
            seed randomizer digest shuffle n hn := by simpa using hp
        rw [he]
        exact c10_finish_selected _ _ _ _ _ _ _ hs)
  simpa only [randomizedProgram_pure, c10_finish_eval] using h

theorem c10_sign_domain_bad_bound (secret : Digest) (random message seed root shuffle : ByteKey)
    (m n : ℕ) (hm : m ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32) (hs : seed.length = 32)
    (hr : root.length = 32) (hmsg : message.length = 32) :
    (c10Sign (privateKey prefixedPrivateInput secret) (fun _ => none)
      random message seed root shuffle m n hm hn).toOuterMeasure {out | DomainNodeBad out.2} ≤
        ((Nat.choose (m + 435042) 2 + (2 * m + 2 * n + 435044) : ℕ) : ℝ≥0∞) / 2 ^ 128 := by
  have h := digest_program_domain_node_bad_bound
    (PMF.pure (c10SignProgram (privateKey prefixedPrivateInput secret)
      random message seed root shuffle m n hm hn)) (m + 435042) (by
        intro program hp
        have he : program = c10SignProgram (privateKey prefixedPrivateInput secret)
            random message seed root shuffle m n hm hn := by simpa using hp
        rw [he]
        exact c10_sign_selected _ _ _ _ _ _ _ _ _ _ hs hr hmsg)
  simpa only [randomizedProgram_pure, c10_sign_eval] using h

theorem c10_verify_domain_bad_bound (seed root message : ByteKey) (sig : C10Signature)
    (hs : seed.length = 32) (hr : root.length = 32) (hm : message.length = 32) :
    (c10Verify id (fun _ => none) seed root message sig).toOuterMeasure
      {out | DomainNodeBad out.2} ≤ (64264 : ℝ≥0∞) / 2 ^ 128 := by
  have h := digest_program_domain_node_bad_bound
    (PMF.pure (c10VerifyProgram id seed root message sig)) 358 (by
      intro program hp
      have he : program = c10VerifyProgram id seed root message sig := by simpa using hp
      rw [he]
      exact c10_verify_selected _ _ _ _ hs hr hm)
  simpa only [randomizedProgram_pure, c10_verify_eval,
    show Nat.choose 358 2 + 361 = 64264 by decide +kernel] using h

theorem c10_keygen_domain_bad_bound (secret publicSeed : Digest) :
    (c10Keygen (privateKey prefixedPrivateInput secret) (fun _ => none) publicSeed).toOuterMeasure
      {out | DomainNodeBad out.2} ≤
        ((Nat.choose 177151 2 + 177151 : ℕ) : ℝ≥0∞) / 2 ^ 128 := by
  have h := digest_program_domain_node_bad_bound
    (PMF.pure (c10KeygenProgram (privateKey prefixedPrivateInput secret) publicSeed)) 177151 (by
      intro program _
      exact selectedBudget_total _ program)
  simpa only [randomizedProgram_pure, c10_keygen_eval] using h

end
end C10Probability
