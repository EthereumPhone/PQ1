import C10Probability.ProgramReplayWitness
import C10Probability.WotsSigningReplay
import C10Probability.LayerSign

/-! Actual layer signing retains its builder, shuffle derivation, returned
WOTS values and reconstruction. Builder and reconstructed roots are not
assumed equal. The chain witness is derived from the signing procedure. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem replay_layer_sign_after_success (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree leaf : ℕ) (message : Randomizer) (auth : List Randomizer)
    (signed : WotsSignature) (sig : LayerSignature) (root : Randomizer)
    (recorded : replayProgram table
      (layerSignAfterProgram encode seed layer tree leaf message auth signed) = some (some (sig, root))) :
    signed = some (sig.sigma, sig.count) ∧ sig.auth = auth ∧
      replayProgram table (layerRecoverProgram (fun key => encode (.inl key))
        seed layer tree leaf message sig) = some root := by
  cases signed with
  | none => cases recorded
  | some signed =>
    obtain ⟨sigma, count⟩ := signed
    rw [layerSignAfterProgram] at recorded
    obtain ⟨actual, replay, equal⟩ := replay_program_map_witness table _ _ _ recorded
    simp only [Option.some.injEq, Prod.mk.injEq] at equal
    obtain ⟨rfl, rfl⟩ := equal
    exact ⟨rfl, rfl, replay⟩

theorem replay_layer_sign_witness (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree leaf : ℕ) (message : Randomizer) (shuffle : ByteKey)
    (n : ℕ) (bound : n ≤ 2 ^ 32) (sig : LayerSignature) (root : Randomizer)
    (recorded : replayProgram table
      (layerSignProgram encode seed layer tree leaf message shuffle n bound) = some (some (sig, root))) :
    ∃ built subseed,
      replayProgram table (merkleBuildProgram encode seed layer tree leaf) = some built ∧
      replayProgram table (shuffleDeriveProgram (fun key => encode (.inl key))
        shuffle (layerShuffleLabel layer)) = some subseed ∧
      replayProgram table (wotsSignProgram encode seed layer tree leaf
        (nodeValueBytes message) subseed n bound) = some (some (sig.sigma, sig.count)) ∧
      sig.auth = built.1 ∧
      replayProgram table (layerRecoverProgram (fun key => encode (.inl key))
        seed layer tree leaf message sig) = some root := by
  rw [layerSignProgram, replay_program_cast] at recorded
  obtain ⟨built, hb, rest⟩ := replay_program_bind_witness table _ _ _ recorded
  obtain ⟨subseed, hs, rest⟩ := replay_program_bind_witness table _ _ _ rest
  obtain ⟨signed, hw, rest⟩ := replay_program_bind_witness table _ _ _ rest
  obtain ⟨choice, auth, recovered⟩ := replay_layer_sign_after_success encode table seed
    layer tree leaf message built.1 signed sig root rest
  exact ⟨built, subseed, hb, hs, choice ▸ hw, auth, recovered⟩

def LayerChainWitness (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree leaf : ℕ) (message : Randomizer) (shuffle : ByteKey)
    (n : ℕ) (bound : n ≤ 2 ^ 32) (sig : LayerSignature) (root : Randomizer) : Prop :=
  replayProgram table (layerSignProgram encode seed layer tree leaf message shuffle n bound) =
    some (some (sig, root)) ∧
  ∃ subseed digest,
    replayProgram table (shuffleDeriveProgram (fun key => encode (.inl key))
      shuffle (layerShuffleLabel layer)) = some subseed ∧
    replayProgram table (wotsSignProgram encode seed layer tree leaf
      (nodeValueBytes message) subseed n bound) = some (some (sig.sigma, sig.count)) ∧
    replayProgram table (mapProgram (fun key => encode (.inl key))
      (wotsCountProgram seed layer tree leaf (nodeValueBytes message) 0 n
        (by simpa using bound))) = some (some (sig.count, digest)) ∧
    wotsAccept (wotsOfDigest digest) = true ∧
    ∀ i, replayProgram table (wotsSeedChainProgram encode seed layer tree leaf i.val
      (wotsOfDigest digest i).val) = some (sig.sigma i)

theorem replay_layer_chain_witness (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree leaf : ℕ) (message : Randomizer) (shuffle : ByteKey)
    (n : ℕ) (bound : n ≤ 2 ^ 32) (sig : LayerSignature) (root : Randomizer)
    (recorded : replayProgram table
      (layerSignProgram encode seed layer tree leaf message shuffle n bound) = some (some (sig, root))) :
    LayerChainWitness encode table seed layer tree leaf message shuffle n bound sig root := by
  obtain ⟨_, subseed, _, hs, signed, _, _⟩ := replay_layer_sign_witness encode table seed
    layer tree leaf message shuffle n bound sig root recorded
  obtain ⟨digest, counted, accepted, positions⟩ := replay_wots_sign_witness encode table seed
    layer tree leaf (nodeValueBytes message) subseed n bound sig.sigma sig.count signed
  exact ⟨recorded, subseed, digest, hs, signed, counted, accepted, positions⟩

end
end C10Probability
