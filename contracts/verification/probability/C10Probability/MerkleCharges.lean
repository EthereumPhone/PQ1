import C10Probability.TreeAccess
import C10Probability.MerkleRecover
import C10Probability.DomainNodeCharges

/-! All charges apply to the stated ideal memo oracle. Prefix transfer requires
an independent uniform hidden secret and empty initial tables. The node-event
bound charges every subtree call, including private/cached calls; it does not
assume separate or fresh leaves. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

theorem subtree_root_physical_eval (secret : Digest) (table : Memo ByteKey Digest)
    (seed : ByteKey) (layer tree : ℕ) :
    evalProgram digestDraw (mapProgram (privateKey prefixedPrivateInput secret)
      (subtreeRootProgram id seed layer tree)) table =
      subtreeRoot (privateKey prefixedPrivateInput secret) table seed layer tree := by
  rw [subtree_root_map]
  exact subtree_root_eval _ _ _ _ _

theorem merkle_build_physical_eval (secret : Digest) (table : Memo ByteKey Digest)
    (seed : ByteKey) (layer tree target : ℕ) :
    evalProgram digestDraw (mapProgram (privateKey prefixedPrivateInput secret)
      (merkleBuildProgram id seed layer tree target)) table =
      merkleBuild (privateKey prefixedPrivateInput secret) table seed layer tree target := by
  rw [merkle_build_map]
  exact merkle_build_eval _ _ _ _ _ _

theorem subtree_root_prefix_error (seed : ByteKey) (layer tree : ℕ) (event : Set Randomizer) :
    |((privateShared digestDraw digestDraw prefixedPrivateInput
        (PMF.pure (subtreeRootProgram id seed layer tree))).toOuterMeasure event).toReal -
      ((privateIndependent digestDraw
        (PMF.pure (subtreeRootProgram id seed layer tree))).toOuterMeasure event).toReal| ≤
      (155135 : ℝ) / 2 ^ 256 := by
  apply private_secret_event_error_real _ 155135
  intro program hp
  have he : program = subtreeRootProgram id seed layer tree := by simpa using hp
  rw [he]
  exact subtree_root_public _ _ _

theorem merkle_build_prefix_error (seed : ByteKey) (layer tree target : ℕ)
    (event : Set (List Randomizer × Randomizer)) :
    |((privateShared digestDraw digestDraw prefixedPrivateInput
        (PMF.pure (merkleBuildProgram id seed layer tree target))).toOuterMeasure event).toReal -
      ((privateIndependent digestDraw
        (PMF.pure (merkleBuildProgram id seed layer tree target))).toOuterMeasure event).toReal| ≤
      (155135 : ℝ) / 2 ^ 256 := by
  apply private_secret_event_error_real _ 155135
  intro program hp
  have he : program = merkleBuildProgram id seed layer tree target := by simpa using hp
  rw [he]
  exact merkle_build_public _ _ _ _

theorem subtree_root_raw_trace (secret : Digest) (table : Memo ByteKey Digest)
    (seed : ByteKey) (layer tree : ℕ) (out : TraceOutput ByteKey Digest Randomizer)
    (ho : out ∈ (traceProgram digestDraw
      (subtreeRootProgram (privateKey prefixedPrivateInput secret) seed layer tree) table).support) :
    out.queries.length ≤ 177151 := by
  exact traceProgram_length _ _ _ _ ho

theorem merkle_build_raw_trace (secret : Digest) (table : Memo ByteKey Digest)
    (seed : ByteKey) (layer tree target : ℕ)
    (out : TraceOutput ByteKey Digest (List Randomizer × Randomizer))
    (ho : out ∈ (traceProgram digestDraw
      (merkleBuildProgram (privateKey prefixedPrivateInput secret) seed layer tree target) table).support) :
    out.queries.length ≤ 177151 := by
  exact traceProgram_length _ _ _ _ ho

theorem subtree_node_coefficient : Nat.choose 177151 2 + 177151 = 15691326976 := by
  rw [Nat.choose_two_right]

theorem subtree_root_domain_bad_bound (secret : Digest) (seed : ByteKey) (layer tree : ℕ) :
    (subtreeRoot (privateKey prefixedPrivateInput secret) (fun _ => none)
      seed layer tree).toOuterMeasure {out | DomainNodeBad out.2} ≤
      (15691326976 : ℝ≥0∞) / 2 ^ 128 := by
  have h := digest_program_domain_node_bad_bound
    (PMF.pure (subtreeRootProgram (privateKey prefixedPrivateInput secret) seed layer tree))
    177151 (fun program _ => selectedBudget_total _ program)
  simpa only [randomizedProgram_pure, subtree_root_eval, subtree_node_coefficient] using h

theorem merkle_build_domain_bad_bound (secret : Digest) (seed : ByteKey) (layer tree target : ℕ) :
    (merkleBuild (privateKey prefixedPrivateInput secret) (fun _ => none)
      seed layer tree target).toOuterMeasure {out | DomainNodeBad out.2} ≤
      (15691326976 : ℝ≥0∞) / 2 ^ 128 := by
  have h := digest_program_domain_node_bad_bound
    (PMF.pure (merkleBuildProgram (privateKey prefixedPrivateInput secret) seed layer tree target))
    177151 (fun program _ => selectedBudget_total _ program)
  simpa only [randomizedProgram_pure, merkle_build_eval, subtree_node_coefficient] using h

theorem merkle_recover_raw_trace (table : Memo ByteKey Digest) (seed : ByteKey) (layer tree : ℕ)
    (leaf : Randomizer) (index : ℕ) (auth : List Randomizer)
    (out : TraceOutput ByteKey Digest Randomizer)
    (ho : out ∈ (traceProgram digestDraw (merkleRecoverProgram id seed layer tree leaf index auth)
      table).support) : out.queries.length ≤ 9 := by
  exact traceProgram_length _ _ _ _ ho

theorem merkle_recover_public (seed : ByteKey) (layer tree : ℕ)
    (leaf : Randomizer) (index : ℕ) (auth : List Randomizer) :
    PublicBudget (merkleRecoverProgram (Sum.inl : ByteKey → WotsQuery)
      seed layer tree leaf index auth) 9 := by
  exact publicBudget_total _

theorem merkle_recover_selected (seed : ByteKey) (layer tree : ℕ)
    (leaf : Randomizer) (index : ℕ) (auth : List Randomizer) :
    SelectedBudget nodeQuery (merkleRecoverProgram id seed layer tree leaf index auth) 9 := by
  exact selectedBudget_total _ _

theorem merkle_recover_domain_bad_bound (seed : ByteKey) (layer tree : ℕ)
    (leaf : Randomizer) (index : ℕ) (auth : List Randomizer) :
    (merkleRecover id (fun _ => none) seed layer tree leaf index auth).toOuterMeasure
      {out | DomainNodeBad out.2} ≤ (45 : ℝ≥0∞) / 2 ^ 128 := by
  have h := digest_program_domain_node_bad_bound
    (PMF.pure (merkleRecoverProgram id seed layer tree leaf index auth))
    9 (fun program _ => selectedBudget_total _ program)
  simpa only [randomizedProgram_pure, merkle_recover_eval,
    show Nat.choose 9 2 + 9 = 45 from rfl] using h

end
end C10Probability
