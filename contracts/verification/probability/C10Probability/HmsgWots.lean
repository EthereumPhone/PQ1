import C10Probability.QueryExclusion
import C10Probability.WotsSigning
import C10Probability.WotsRecovery

/-! WOTS and shuffle operations do not enter the 160-byte public H_msg pool.
Compression uses its proved 43-node result width. -/
namespace C10Probability
noncomputable section

def hmsgWidth (key : ByteKey) : Bool := decide (key.length = 160)

def hmsgQuery : WotsQuery → Bool
  | .inl key => hmsgWidth key
  | .inr _ => false

theorem wots_fill_hmsg_excluded (seed : ByteKey) (layer tree kp : ℕ)
    (steps : Fin 43 → ℕ) (order : List (Fin 43)) (sigma : WotsSigma)
    (width : seed.length = 32) :
    QueryExclusion hmsgQuery (fun _ => True)
      (wotsFillProgram id seed layer tree kp steps order sigma) := by
  apply queryExclusion_stateFold
  · intro i state _
    rw [wotsFillStep, queryExclusion_mapReturn]
    refine ⟨rfl, fun digest => ?_⟩
    apply queryExclusion_chain
    intro pos value
    simp only [id_eq, hmsgQuery, hmsgWidth, wots_chain_input_length _ _ _ _ _ _ _ width]
    decide
  · trivial

theorem wots_leaf_hmsg_excluded (seed : ByteKey) (layer tree kp : ℕ)
    (width : seed.length = 32) :
    QueryExclusion hmsgQuery (fun _ => True) (wotsLeafProgram id seed layer tree kp) := by
  rw [wotsLeafProgram]
  apply queryExclusion_bind hmsgQuery (fun _ => True) _ _ _
  · rw [wotsLeafFillProgram, queryExclusion_cast]
    exact wots_fill_hmsg_excluded seed layer tree kp _ _ _ width
  · intro sigma _
    refine ⟨?_, fun _ => True.intro⟩
    simp only [id_eq, hmsgQuery, hmsgWidth,
      wots_pk_input_length _ _ _ _ _ width List.length_ofFn]
    decide

theorem wots_recovery_hmsg_excluded (seed : ByteKey) (layer tree kp : ℕ)
    (message : ByteKey) (sigma : WotsSigma) (nonce : Counter)
    (width : seed.length = 32) (messageWidth : message.length = 16) :
    QueryExclusion hmsgWidth (fun _ => True)
      (wotsRecoveryProgram seed layer tree kp message sigma nonce) := by
  refine ⟨?_, fun digest => ?_⟩
  · simp only [hmsgWidth, wots_count_key_length _ _ _ _ _ _ width messageWidth]
    decide
  · by_cases accepted : wotsAccept (wotsOfDigest digest) = true
    · rw [wotsRecoveryAfter, dif_pos accepted]
      apply queryExclusion_bind hmsgWidth (fun values => values.length = 43) _ _ _
      · rw [wotsAcceptedChainsProgram, queryExclusion_cast]
        have excluded (i : Fin 43) (pos : ℕ) (value : Randomizer) :
            hmsgWidth (wotsChainInput seed layer tree kp i.val pos value) = false := by
          simp only [hmsgWidth, wots_chain_input_length _ _ _ _ _ _ _ width]
          decide
        unfold wotsRecoverChainsProgram wotsRemaining
        with_reducible exact (queryExclusion_collection hmsgWidth
          (fun i : Fin 43 => wotsChainInput seed layer tree kp i.val) randomizerOfDigest
          (fun i => (wotsOfDigest digest i).val) (fun i => 7 - (wotsOfDigest digest i).val)
          sigma excluded wotsIndices 43 wots_indices_length)
      · intro values length
        refine ⟨?_, fun _ => True.intro⟩
        simp only [hmsgWidth, wots_pk_input_length _ _ _ _ _ width length]
        decide
    · rw [wotsRecoveryAfter, dif_neg accepted]
      trivial

theorem shuffle_blocks_hmsg_excluded (seed : ByteKey) (start n : ℕ)
    (width : seed.length = 32) :
    QueryExclusion hmsgQuery (fun _ => True) (shuffleBlocksProgram Sum.inl seed start n) := by
  induction n generalizing start with
  | zero => trivial
  | succ n ih =>
    refine ⟨?_, fun digest => ?_⟩
    · simp only [hmsgQuery, hmsgWidth, shuffle_block_input_length _ _ width]
      decide
    · rw [queryExclusion_mapReturn]
      exact ih (start + 1)

theorem wots_shuffle_hmsg_excluded (seed : ByteKey) (width : seed.length = 32) :
    QueryExclusion hmsgQuery (fun _ => True) (wotsShuffleProgram Sum.inl seed) := by
  by_cases zero : seed = List.replicate 32 0
  · rw [wotsShuffleProgram, if_pos zero]
    trivial
  · rw [wotsShuffleProgram, if_neg zero, queryExclusion_mapReturn]
    exact shuffle_blocks_hmsg_excluded seed 0 4 width

theorem wots_sign_hmsg_excluded (seed : ByteKey) (layer tree kp : ℕ)
    (message shuffle : ByteKey) (n : ℕ) (hb : n ≤ 2 ^ 32)
    (width : seed.length = 32) (messageWidth : message.length = 16)
    (shuffleWidth : shuffle.length = 32) :
    QueryExclusion hmsgQuery (fun _ => True)
      (wotsSignProgram id seed layer tree kp message shuffle n hb) := by
  rw [wotsSignProgram, queryExclusion_cast]
  apply queryExclusion_bind hmsgQuery (fun _ => True) _ _ _
  · rw [queryExclusion_map, wotsCountProgram, queryExclusion_cast]
    apply queryExclusion_count
    intro key member
    obtain ⟨i, rfl⟩ := List.mem_ofFn.mp member
    simp only [Function.comp_def, id_eq, hmsgQuery, hmsgWidth,
      wots_count_key_length _ _ _ _ _ _ width messageWidth]
    decide
  · intro found _
    cases found with
    | none => rw [wotsSignAfterProgram]; trivial
    | some found =>
      obtain ⟨count, digest⟩ := found
      by_cases accepted : wotsAccept (wotsOfDigest digest) = true
      · rw [wotsSignAfterProgram, dif_pos accepted]
        apply queryExclusion_bind hmsgQuery (fun _ => True) _ _ _
          (wots_shuffle_hmsg_excluded shuffle shuffleWidth)
        intro order _
        rw [queryExclusion_mapReturn, wotsAcceptedFillProgram, queryExclusion_cast]
        exact wots_fill_hmsg_excluded seed layer tree kp _ _ _ width
      · rw [wotsSignAfterProgram, dif_neg accepted]
        trivial

end
end C10Probability
