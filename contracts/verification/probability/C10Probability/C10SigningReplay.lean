import C10Probability.HypertreeSigningReplay
import C10Probability.C10Sign

/-! Successful C10 signing retains one joint randomizer, forest and ordered
two-layer witness. Each returned WOTS component has its actual accepted
count result and private-seeded prefixes in the same final lookup cache. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem replay_c10_finish_witness (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (randomizer : Randomizer) (digest : Digest) (shuffle : ByteKey)
    (n : ℕ) (bound : n ≤ 2 ^ 32) (sig : C10Signature)
    (recorded : replayProgram table
      (c10FinishProgram encode seed randomizer digest shuffle n bound) = some (some sig)) :
    ∃ forest top,
      replayProgram table (forestSignProgram encode seed (hypertreeIndex digest) digest shuffle) = some forest ∧
      sig.randomizer = randomizer ∧ sig.secrets = forest.secrets ∧ sig.auths = forest.auths ∧
      replayProgram table (hypertreeSignProgram encode seed shuffle n bound 2 0
        (hypertreeIndex digest) forest.pk []) = some (some (sig.layers, top)) := by
  rw [c10FinishProgram, replay_program_cast] at recorded
  obtain ⟨forest, hf, rest⟩ := replay_program_bind_witness table _ _ _ recorded
  obtain ⟨signed, ht, equal⟩ := replay_program_map_witness table _ _ _ rest
  cases signed with
  | none => cases equal
  | some signed =>
    have he : (⟨randomizer, forest.secrets, forest.auths, signed.1⟩ : C10Signature) = sig :=
      Option.some.inj equal
    subst sig
    exact ⟨forest, signed.2, hf, rfl, rfl, rfl, ht⟩

theorem replay_c10_sign_witness (encode : WotsQuery → K) (table : Memo K Digest)
    (random message seed root shuffle : ByteKey) (m n : ℕ)
    (rBound : m ≤ 2 ^ 32) (wBound : n ≤ 2 ^ 32) (sig : C10Signature)
    (recorded : replayProgram table
      (c10SignProgram encode random message seed root shuffle m n rBound wBound) = some (some sig)) :
    ∃ trial digest forest top,
      replayProgram table (randomizerUnderProgram encode random message seed root m rBound) =
        some (some (trial, sig.randomizer, digest)) ∧
      replayProgram table (forestSignProgram encode seed (hypertreeIndex digest) digest shuffle) = some forest ∧
      sig.secrets = forest.secrets ∧ sig.auths = forest.auths ∧
      replayProgram table (hypertreeSignProgram encode seed shuffle n wBound 2 0
        (hypertreeIndex digest) forest.pk []) = some (some (sig.layers, top)) := by
  rw [c10SignProgram, replay_program_cast] at recorded
  obtain ⟨found, hr, rest⟩ := replay_program_bind_witness table _ _ _ recorded
  cases found with
  | none => cases rest
  | some found =>
    obtain ⟨trial, randomizer, digest⟩ := found
    obtain ⟨forest, top, hf, equal, secrets, auths, signed⟩ :=
      replay_c10_finish_witness encode table seed randomizer digest shuffle n wBound sig rest
    refine ⟨trial, digest, forest, top, ?_, hf, secrets, auths, signed⟩
    simpa only [equal] using hr

def C10ChainWitness (encode : WotsQuery → K) (table : Memo K Digest)
    (random message seed root shuffle : ByteKey) (m n : ℕ)
    (rBound : m ≤ 2 ^ 32) (wBound : n ≤ 2 ^ 32) (sig : C10Signature) : Prop :=
  ∃ trial digest forest lower upper middle top,
    replayProgram table (randomizerUnderProgram encode random message seed root m rBound) =
      some (some (trial, sig.randomizer, digest)) ∧
    replayProgram table (forestSignProgram encode seed (hypertreeIndex digest) digest shuffle) = some forest ∧
    sig.secrets = forest.secrets ∧ sig.auths = forest.auths ∧ sig.layers = [lower, upper] ∧
    LayerChainWitness encode table seed 0 (hypertreeParent (hypertreeIndex digest))
      (hypertreeLeaf (hypertreeIndex digest)) forest.pk shuffle n wBound lower middle ∧
    LayerChainWitness encode table seed 1 0 (hypertreeLeaf (hypertreeParent (hypertreeIndex digest)))
      middle shuffle n wBound upper top

theorem replay_c10_chain_witness (encode : WotsQuery → K) (table : Memo K Digest)
    (random message seed root shuffle : ByteKey) (m n : ℕ)
    (rBound : m ≤ 2 ^ 32) (wBound : n ≤ 2 ^ 32) (sig : C10Signature)
    (recorded : replayProgram table
      (c10SignProgram encode random message seed root shuffle m n rBound wBound) = some (some sig)) :
    C10ChainWitness encode table random message seed root shuffle m n rBound wBound sig := by
  obtain ⟨trial, digest, forest, top, hr, hf, secrets, auths, ht⟩ := replay_c10_sign_witness
    encode table random message seed root shuffle m n rBound wBound sig recorded
  obtain ⟨lower, upper, middle, layers, hl, hu⟩ := replay_hypertree_sign_two encode table seed shuffle
    n wBound (hypertreeIndex digest) forest.pk top sig.layers ht
  rw [hypertree_second_parent_zero] at hu
  exact ⟨trial, digest, forest, lower, upper, middle, top, hr, hf, secrets, auths, layers,
    replay_layer_chain_witness encode table seed 0 (hypertreeParent (hypertreeIndex digest))
      (hypertreeLeaf (hypertreeIndex digest)) forest.pk shuffle n wBound lower middle hl,
    replay_layer_chain_witness encode table seed 1 0
      (hypertreeLeaf (hypertreeParent (hypertreeIndex digest))) middle shuffle n wBound upper top hu⟩

end
end C10Probability
