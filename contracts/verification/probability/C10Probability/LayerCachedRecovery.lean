import C10Probability.LayerHonest

/-! Honest signing recovery is a complete cached replay. The actual builder
and signer supply every recovery lookup, including the accepted count and
returned authentication path. Replacing that replay by its result preserves
the full memo law; it is not an assumption that signatures verify correctly. -/
namespace C10Probability
noncomputable section
variable {K : Type*}

def layerCachedOutput (built : List Randomizer × Randomizer) (signed : WotsSignature) : LayerSigned :=
  signed.map (fun value => (⟨value.1, value.2, built.1⟩, built.2))

theorem layer_sign_after_cached_replay (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree leaf : ℕ) (message : Randomizer) (shuffle : ByteKey)
    (n : ℕ) (bound : n ≤ 2 ^ 32) (leafBound : leaf < 512)
    (built : List Randomizer × Randomizer) (signed : WotsSignature)
    (builder : replayProgram table (merkleBuildProgram encode seed layer tree leaf) = some built)
    (signer : replayProgram table (wotsSignProgram encode seed layer tree leaf
      (nodeValueBytes message) shuffle n bound) = some signed) :
    replayProgram table (layerSignAfterProgram encode seed layer tree leaf message built.1 signed) =
      some (layerCachedOutput built signed) := by
  cases signed with
  | none => rfl
  | some value =>
    obtain ⟨sigma, count⟩ := value
    obtain ⟨_, generated, generatedReplay, authReplay⟩ :=
      replay_merkle_build_recovery encode table seed layer tree leaf built builder leafBound
    have recovered := (replay_wots_sign_recovery encode table seed layer tree leaf
      (nodeValueBytes message) shuffle n bound sigma count generated signer generatedReplay).2
    have full : replayProgram table (layerRecoverProgram (fun key => encode (.inl key))
        seed layer tree leaf message ⟨sigma, count, built.1⟩) = some built.2 := by
      rw [layerRecoverProgram, replay_program_bind, recovered, Option.bind_some]
      exact authReplay
    simp only [layerSignAfterProgram, replay_program_map_return, full, Option.map_some,
      layerCachedOutput]

def layerCachedProgram (encode : WotsQuery → K) (seed : ByteKey) (layer tree leaf : ℕ)
    (message : Randomizer) (shuffle : ByteKey) (n : ℕ) (bound : n ≤ 2 ^ 32) :
    QueryProgram K Digest LayerSigned (n + 177511) :=
  castProgram (by omega)
    (bindProgram (merkleBuildProgram encode seed layer tree leaf) (fun built =>
      bindProgram (shuffleDeriveProgram (fun key => encode (.inl key)) shuffle (layerShuffleLabel layer))
        (fun subseed => bindProgram
          (wotsSignProgram encode seed layer tree leaf (nodeValueBytes message) subseed n bound)
          (fun signed => .done (n := 107) (layerCachedOutput built signed)))))

attribute [irreducible] layerCachedProgram

theorem layer_sign_cached_eval [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree leaf : ℕ) (message : Randomizer) (shuffle : ByteKey)
    (n : ℕ) (bound : n ≤ 2 ^ 32) (leafBound : leaf < 512) :
    evalProgram digestDraw (layerSignProgram encode seed layer tree leaf message shuffle n bound) table =
      evalProgram digestDraw (layerCachedProgram encode seed layer tree leaf message shuffle n bound) table := by
  simp only [layerSignProgram, layerCachedProgram, evalProgram_cast, evalProgram_bind]
  apply bind_eq_of_support
  intro built builtSupport
  apply bind_eq_of_support
  intro subseed seedSupport
  apply bind_eq_of_support
  intro signed signedSupport
  have extension := memo_extends_trans
    (eval_program_extends digestDraw _ built.2 subseed seedSupport)
    (eval_program_extends digestDraw _ subseed.2 signed signedSupport)
  have builder := eval_program_replay_later digestDraw _ table built builtSupport signed.2 extension
  have signer := eval_program_replay digestDraw _ subseed.2 signed signedSupport
  exact replay_program_eval digestDraw _ signed.2 (layerCachedOutput built.1 signed.1)
    (layer_sign_after_cached_replay encode signed.2 seed layer tree leaf message subseed.1
      n bound leafBound built.1 signed.1 builder signer)

end
end C10Probability
