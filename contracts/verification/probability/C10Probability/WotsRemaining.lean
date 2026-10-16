import C10Probability.ChainCollection
import C10Probability.WotsChain

/-! The recovery cost follows from the actual accepted base-eight word,
not from an assumed call budget. Ordered chains retain all memoized replies. -/
namespace C10Probability
noncomputable section

def wotsIndices : List (Fin 43) := List.ofFn id

def wotsRemaining (word : WotsWord) : ℕ :=
  collectionSteps (fun i => 7 - (word i).val) wotsIndices

theorem wots_indices_length : wotsIndices.length = 43 := by
  simp [wotsIndices]

theorem wots_remaining_sum (word : WotsWord) :
    wotsRemaining word + (∑ i, (word i).val) = 301 := by
  have hi (i : Fin 43) : 7 - (word i).val + (word i).val = 7 := by
    have h := (word i).isLt
    omega
  simp only [wotsRemaining, collectionSteps, wotsIndices, List.map_ofFn,
    Function.comp_def, id_eq, List.sum_ofFn]
  rw [← Finset.sum_add_distrib]
  simp only [hi]
  norm_num

theorem wots_remaining_le (word : WotsWord) : wotsRemaining word ≤ 301 := by
  have h := wots_remaining_sum word
  omega

theorem wots_accepted_remaining (word : WotsWord) (ha : wotsAccept word = true) :
    wotsRemaining word = 96 := by
  have hs : (∑ i, (word i).val) = 205 := by
    simpa only [wotsAccept, decide_eq_true_eq] using ha
  have h := wots_remaining_sum word
  omega

def wotsRecoverChainsProgram (seed : ByteKey) (layer tree kp : ℕ)
    (word : WotsWord) (sigma : Fin 43 → Randomizer) :
    QueryProgram ByteKey Digest (List Randomizer) (wotsRemaining word) :=
  chainCollectionProgram (fun i => wotsChainInput seed layer tree kp i.val)
    randomizerOfDigest (fun i => (word i).val) (fun i => 7 - (word i).val)
    sigma wotsIndices

def wotsRecoverChains (table : Memo ByteKey Digest) (seed : ByteKey)
    (layer tree kp : ℕ) (word : WotsWord) (sigma : Fin 43 → Randomizer) :
    PMF (List Randomizer × Memo ByteKey Digest) :=
  chainCollectionLoop digestDraw (fun i => wotsChainInput seed layer tree kp i.val)
    randomizerOfDigest (fun i => (word i).val) (fun i => 7 - (word i).val)
    sigma wotsIndices table

theorem wots_recover_chains_eval (table : Memo ByteKey Digest) (seed : ByteKey)
    (layer tree kp : ℕ) (word : WotsWord) (sigma : Fin 43 → Randomizer) :
    evalProgram digestDraw (wotsRecoverChainsProgram seed layer tree kp word sigma) table =
      wotsRecoverChains table seed layer tree kp word sigma := by
  exact evalProgram_chainCollection _ _ _ _ _ _ _ _

theorem wots_recover_chains_length (table : Memo ByteKey Digest) (seed : ByteKey)
    (layer tree kp : ℕ) (word : WotsWord) (sigma : Fin 43 → Randomizer)
    (out : List Randomizer × Memo ByteKey Digest)
    (ho : out ∈ (wotsRecoverChains table seed layer tree kp word sigma).support) :
    out.1.length = 43 := by
  simpa only [wots_indices_length] using
    chainCollectionLoop_length digestDraw
      (fun i => wotsChainInput seed layer tree kp i.val) randomizerOfDigest
      (fun i => (word i).val) (fun i => 7 - (word i).val) sigma wotsIndices table out ho

/-- Keep routine budget elaboration from reducing all 43 dependent chains.
The full interpreter equation below unfolds this definition explicitly. -/
def wotsAcceptedChainsProgram (seed : ByteKey) (layer tree kp : ℕ)
    (word : WotsWord) (ha : wotsAccept word = true) (sigma : Fin 43 → Randomizer) :
    QueryProgram ByteKey Digest (List Randomizer) 96 :=
  castProgram (wots_accepted_remaining word ha)
    (wotsRecoverChainsProgram seed layer tree kp word sigma)

attribute [irreducible] wotsAcceptedChainsProgram

theorem wots_accepted_chains_eval (table : Memo ByteKey Digest) (seed : ByteKey)
    (layer tree kp : ℕ) (word : WotsWord) (ha : wotsAccept word = true)
    (sigma : Fin 43 → Randomizer) :
    evalProgram digestDraw (wotsAcceptedChainsProgram seed layer tree kp word ha sigma) table =
      wotsRecoverChains table seed layer tree kp word sigma := by
  rw [wotsAcceptedChainsProgram, evalProgram_cast, wots_recover_chains_eval]

theorem wots_accepted_chains_budget (seed : ByteKey) (layer tree kp : ℕ)
    (word : WotsWord) (ha : wotsAccept word = true) (sigma : Fin 43 → Randomizer) :
    SelectedBudget nodeQuery (wotsAcceptedChainsProgram seed layer tree kp word ha sigma) 96 := by
  exact selectedBudget_total nodeQuery (n := 96)
    (wotsAcceptedChainsProgram seed layer tree kp word ha sigma)

end
end C10Probability
