import C10Probability.QueryReplay
import C10Probability.RecoveryRelabel
import C10Probability.WotsPrivate
import Mathlib.Data.List.Forall2

/-! The actual ordered recovery collection supplies a lookup witness at each
of its 43 positions. The output order and complete cache are retained. -/
namespace C10Probability
noncomputable section

variable {I K α N : Type*}

theorem replay_chain_collection_positions (table : Memo K α) (input : I → ℕ → N → K)
    (project : α → N) (starts steps : I → ℕ) (values : I → N)
    (indices : List I) (result : List N)
    (recorded : replayProgram table
      (chainCollectionProgram input project starts steps values indices) = some result) :
    List.Forall₂ (fun i endpoint => replayProgram table
      (chainProgram (input i) project (starts i) (steps i) (values i)) = some endpoint)
      indices result := by
  induction indices generalizing result with
  | nil =>
    have empty : [] = result := Option.some.inj recorded
    subst result
    exact .nil
  | cons index rest ih =>
    simp only [chainCollectionProgram, replay_program_cast, replay_program_bind,
      replay_program_map_return] at recorded
    cases head : replayProgram table
      (chainProgram (input index) project (starts index) (steps index) (values index)) with
    | none => simp only [head, Option.bind_none] at recorded; cases recorded
    | some endpoint =>
      simp only [head, Option.bind_some] at recorded
      cases tail : replayProgram table
        (chainCollectionProgram input project starts steps values rest) with
      | none => simp only [tail, Option.map_none] at recorded; cases recorded
      | some endpoints =>
        simp only [tail, Option.map_some, Option.some.injEq] at recorded
        subst result
        exact .cons head (ih endpoints tail)

theorem replay_wots_recovery_positions (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (word : WotsWord)
    (accepted : wotsAccept word = true) (sigma : WotsSigma) (result : List Randomizer)
    (recorded : replayProgram table (mapProgram encode
      (wotsAcceptedChainsProgram seed layer tree kp word accepted sigma)) = some result) :
    List.Forall₂ (fun i endpoint => replayProgram table
      (chainProgram (fun position value => encode
        (wotsChainInput seed layer tree kp i.val position value)) randomizerOfDigest
        (word i).val (7 - (word i).val) (sigma i)) = some endpoint) wotsIndices result := by
  rw [wotsAcceptedChainsProgram, mapProgram_cast, replay_program_cast] at recorded
  have mapped := chain_collection_program_map encode
    (fun i : Fin 43 => wotsChainInput seed layer tree kp i.val) randomizerOfDigest
    (fun i => (word i).val) (fun i => 7 - (word i).val) sigma wotsIndices
  have unlabelled := (congrArg (fun program => replayProgram table program) mapped).symm.trans recorded
  exact replay_chain_collection_positions table _ randomizerOfDigest _ _ sigma wotsIndices result unlabelled

theorem replay_wots_recovery_length (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (word : WotsWord)
    (accepted : wotsAccept word = true) (sigma : WotsSigma) (result : List Randomizer)
    (recorded : replayProgram table (mapProgram encode
      (wotsAcceptedChainsProgram seed layer tree kp word accepted sigma)) = some result) :
    result.length = 43 := by
  have relation := replay_wots_recovery_positions encode table seed layer tree kp word accepted sigma result recorded
  exact relation.length_eq.symm.trans wots_indices_length

theorem replay_wots_recovery_endpoint (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (word : WotsWord)
    (accepted : wotsAccept word = true) (sigma endpoints : WotsSigma)
    (recorded : replayProgram table (mapProgram encode
      (wotsAcceptedChainsProgram seed layer tree kp word accepted sigma)) = some (List.ofFn endpoints))
    (i : Fin 43) :
    replayProgram table (chainProgram (fun position value => encode
      (wotsChainInput seed layer tree kp i.val position value)) randomizerOfDigest
      (word i).val (7 - (word i).val) (sigma i)) = some (endpoints i) := by
  have relation := replay_wots_recovery_positions encode table seed layer tree kp word accepted sigma
    (List.ofFn endpoints) recorded
  have left : i.val < wotsIndices.length := by rw [wots_indices_length]; exact i.isLt
  have right : i.val < (List.ofFn endpoints).length := by rw [List.length_ofFn]; exact i.isLt
  have leftEq : wotsIndices.get ⟨i.val, left⟩ = i := by
    simp only [wotsIndices, List.get_eq_getElem, List.getElem_ofFn, id_eq]
  have rightEq : (List.ofFn endpoints).get ⟨i.val, right⟩ = endpoints i := by
    simp only [List.get_eq_getElem, List.getElem_ofFn]
  have atIndex := relation.get left right
  rw [leftEq, rightEq] at atIndex
  exact atIndex

end
end C10Probability
