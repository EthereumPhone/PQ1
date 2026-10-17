import C10Probability.ForestAccess
import C10Probability.DomainNodeCharges

/-! Bounds for the named ideal shared-cache clients. Prefix comparisons sample
an independent uniform hidden secret and start with empty tables. Node bounds
start with an empty cache and conservatively select every allowed raw call.
These events and compiler equalities are not a complete forgery theorem. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

theorem fors_tree_physical_eval (secret : Digest) (table : Memo ByteKey Digest)
    (seed : ByteKey) (ht tree target : ℕ) :
    evalProgram digestDraw (mapProgram (privateKey prefixedPrivateInput secret)
      (forsTreeProgram id seed ht tree target)) table =
      forsTree (privateKey prefixedPrivateInput secret) table seed ht tree target := by
  rw [fors_tree_map]
  exact fors_tree_eval _ _ _ _ _ _

theorem fors_sign_physical_eval (secret : Digest) (table : Memo ByteKey Digest)
    (seed : ByteKey) (ht tree target : ℕ) :
    evalProgram digestDraw (mapProgram (privateKey prefixedPrivateInput secret)
      (forsSignProgram id seed ht tree target)) table =
      forsSign (privateKey prefixedPrivateInput secret) table seed ht tree target := by
  rw [fors_sign_map]
  exact fors_sign_eval _ _ _ _ _ _

theorem forest_sign_physical_eval (secret : Digest) (table : Memo ByteKey Digest)
    (seed : ByteKey) (ht : ℕ) (digest : Digest) (shuffle : ByteKey) :
    evalProgram digestDraw (mapProgram (privateKey prefixedPrivateInput secret)
      (forestSignProgram id seed ht digest shuffle)) table =
      forestSign (privateKey prefixedPrivateInput secret) table seed ht digest shuffle := by
  rw [forest_sign_map]
  exact forest_sign_eval _ _ _ _ _ _

theorem fors_tree_prefix_error (seed : ByteKey) (ht tree target : ℕ)
    (event : Set (Randomizer × List Randomizer)) :
    |((privateShared digestDraw digestDraw prefixedPrivateInput
        (PMF.pure (forsTreeProgram id seed ht tree target))).toOuterMeasure event).toReal -
      ((privateIndependent digestDraw
        (PMF.pure (forsTreeProgram id seed ht tree target))).toOuterMeasure event).toReal| ≤
      (4095 : ℝ) / 2 ^ 256 := by
  apply private_secret_event_error_real _ 4095
  intro program hp
  have he : program = forsTreeProgram id seed ht tree target := by simpa using hp
  rw [he]
  exact fors_tree_public _ _ _ _

theorem fors_sign_prefix_error (seed : ByteKey) (ht tree target : ℕ)
    (event : Set (Randomizer × List Randomizer)) :
    |((privateShared digestDraw digestDraw prefixedPrivateInput
        (PMF.pure (forsSignProgram id seed ht tree target))).toOuterMeasure event).toReal -
      ((privateIndependent digestDraw
        (PMF.pure (forsSignProgram id seed ht tree target))).toOuterMeasure event).toReal| ≤
      (4095 : ℝ) / 2 ^ 256 := by
  apply private_secret_event_error_real _ 4095
  intro program hp
  have he : program = forsSignProgram id seed ht tree target := by simpa using hp
  rw [he]
  exact fors_sign_public _ _ _ _

theorem forest_sign_prefix_error (seed : ByteKey) (ht : ℕ) (digest : Digest)
    (shuffle : ByteKey) (event : Set ForestOutput) :
    |((privateShared digestDraw digestDraw prefixedPrivateInput
        (PMF.pure (forestSignProgram id seed ht digest shuffle))).toOuterMeasure event).toReal -
      ((privateIndependent digestDraw
        (PMF.pure (forestSignProgram id seed ht digest shuffle))).toOuterMeasure event).toReal| ≤
      (53386 : ℝ) / 2 ^ 256 := by
  apply private_secret_event_error_real _ 53386
  intro program hp
  have he : program = forestSignProgram id seed ht digest shuffle := by simpa using hp
  rw [he]
  exact forest_sign_public _ _ _ _

theorem forest_sign_raw_trace (secret : Digest) (table : Memo ByteKey Digest)
    (seed : ByteKey) (ht : ℕ) (digest : Digest) (shuffle : ByteKey)
    (out : TraceOutput ByteKey Digest ForestOutput)
    (ho : out ∈ (traceProgram digestDraw
      (forestSignProgram (privateKey prefixedPrivateInput secret) seed ht digest shuffle) table).support) :
    out.queries.length ≤ 80022 := by
  exact traceProgram_length _ _ _ _ ho

theorem forest_recover_raw_trace (table : Memo ByteKey Digest) (seed : ByteKey) (ht : ℕ)
    (digest : Digest) (secrets : List Randomizer) (auths : List (List Randomizer))
    (out : TraceOutput ByteKey Digest Randomizer)
    (ho : out ∈ (traceProgram digestDraw
      (forestRecoverProgram id seed ht digest secrets auths) table).support) :
    out.queries.length ≤ 146 := by
  exact traceProgram_length _ _ _ _ ho

theorem fors_tree_node_coefficient : Nat.choose 6143 2 + 6143 = 18871296 := by
  rw [Nat.choose_two_right]

theorem fors_sign_node_coefficient : Nat.choose 6144 2 + 6144 = 18877440 := by
  rw [Nat.choose_two_right]

theorem forest_sign_node_coefficient : Nat.choose 80022 2 + 80022 = 3201800253 := by
  rw [Nat.choose_two_right]

theorem forest_recover_node_coefficient : Nat.choose 146 2 + 146 = 10731 := by
  rw [Nat.choose_two_right]

theorem fors_tree_domain_bad_bound (secret : Digest) (seed : ByteKey) (ht tree target : ℕ) :
    (forsTree (privateKey prefixedPrivateInput secret) (fun _ => none)
      seed ht tree target).toOuterMeasure {out | DomainNodeBad out.2} ≤
      (18871296 : ℝ≥0∞) / 2 ^ 128 := by
  have h := digest_program_domain_node_bad_bound
    (PMF.pure (forsTreeProgram (privateKey prefixedPrivateInput secret) seed ht tree target))
    6143 (fun program _ => selectedBudget_total _ program)
  simpa only [randomizedProgram_pure, fors_tree_eval, fors_tree_node_coefficient] using h

theorem fors_sign_domain_bad_bound (secret : Digest) (seed : ByteKey) (ht tree target : ℕ) :
    (forsSign (privateKey prefixedPrivateInput secret) (fun _ => none)
      seed ht tree target).toOuterMeasure {out | DomainNodeBad out.2} ≤
      (18877440 : ℝ≥0∞) / 2 ^ 128 := by
  have h := digest_program_domain_node_bad_bound
    (PMF.pure (forsSignProgram (privateKey prefixedPrivateInput secret) seed ht tree target))
    6144 (fun program _ => selectedBudget_total _ program)
  simpa only [randomizedProgram_pure, fors_sign_eval, fors_sign_node_coefficient] using h

theorem forest_sign_domain_bad_bound (secret : Digest) (seed : ByteKey) (ht : ℕ)
    (digest : Digest) (shuffle : ByteKey) :
    (forestSign (privateKey prefixedPrivateInput secret) (fun _ => none)
      seed ht digest shuffle).toOuterMeasure {out | DomainNodeBad out.2} ≤
      (3201800253 : ℝ≥0∞) / 2 ^ 128 := by
  have h := digest_program_domain_node_bad_bound
    (PMF.pure (forestSignProgram (privateKey prefixedPrivateInput secret) seed ht digest shuffle))
    80022 (fun program _ => selectedBudget_total _ program)
  simpa only [randomizedProgram_pure, forest_sign_eval, forest_sign_node_coefficient] using h

theorem forest_recover_domain_bad_bound (seed : ByteKey) (ht : ℕ) (digest : Digest)
    (secrets : List Randomizer) (auths : List (List Randomizer)) :
    (forestRecover id (fun _ => none) seed ht digest secrets auths).toOuterMeasure
      {out | DomainNodeBad out.2} ≤ (10731 : ℝ≥0∞) / 2 ^ 128 := by
  have h := digest_program_domain_node_bad_bound
    (PMF.pure (forestRecoverProgram id seed ht digest secrets auths))
    146 (fun program _ => selectedBudget_total _ program)
  simpa only [randomizedProgram_pure, forest_recover_eval, forest_recover_node_coefficient] using h

end
end C10Probability
