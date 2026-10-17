import C10Probability.StateFold
import C10Probability.WotsRemaining
import C10Probability.WotsCompression
import C10Probability.PrivateSecret

/-! Exact tagged WOTS derivation and positional private/public chain filling.
The private label excludes the secret itself; physical interpretation prepends
its full32-byte encoding. All other inputs and the full reply/cache are retained. -/
namespace C10Probability
noncomputable section

abbrev WotsQuery := Sum ByteKey ByteKey
abbrev WotsSigma := Fin 43 → Randomizer

def wotsTag : ByteKey := [119, 111, 116, 115]

def wotsPrivateTail (layer tree kp index : ℕ) : ByteKey :=
  wotsTag ++ beBytes 4 layer ++ beBytes 32 tree ++ beBytes 4 kp ++ beBytes 4 index

theorem wots_private_tail_length (layer tree kp index : ℕ) :
    (wotsPrivateTail layer tree kp index).length = 48 := by
  simp [wotsPrivateTail, wotsTag, be_bytes_length]

theorem wots_private_input_length (secret : Digest) (layer tree kp index : ℕ) :
    (prefixedPrivateInput secret (wotsPrivateTail layer tree kp index)).length = 80 := by
  simp [prefixedPrivateInput, secretBytes, wots_private_tail_length]

theorem wots_private_input_selected (secret : Digest) (layer tree kp index : ℕ) :
    nodeQuery (prefixedPrivateInput secret (wotsPrivateTail layer tree kp index)) = true := by
  apply node_query_other_width <;> simp [wots_private_input_length]

variable {K L : Type*}

theorem mapProgram_chain (encode : K → L) (input : ℕ → Randomizer → K)
    (start steps : ℕ) (current : Randomizer) :
    mapProgram encode (chainProgram input randomizerOfDigest start steps current) =
      chainProgram (fun pos value => encode (input pos value)) randomizerOfDigest
        start steps current := by
  induction steps generalizing start current with
  | zero => rfl
  | succ steps ih =>
    simp only [chainProgram, mapProgram, ih]

def wotsSeedChainProgram (encode : WotsQuery → K) (seed : ByteKey)
    (layer tree kp index steps : ℕ) : QueryProgram K Digest Randomizer (steps + 1) :=
  .query (encode (.inr (wotsPrivateTail layer tree kp index))) (fun digest =>
    chainProgram (fun pos value => encode (.inl (wotsChainInput seed layer tree kp index pos value)))
      randomizerOfDigest 0 steps (randomizerOfDigest digest))

def wotsSeedChain [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp index steps : ℕ) : PMF (Randomizer × Memo K Digest) :=
  (memoQuery digestDraw table (encode (.inr (wotsPrivateTail layer tree kp index)))).bind
    (fun reply => chainLoop digestDraw
      (fun pos value => encode (.inl (wotsChainInput seed layer tree kp index pos value)))
      randomizerOfDigest 0 steps (randomizerOfDigest reply.1) reply.2)

theorem wots_seed_chain_eval [DecidableEq K] (encode : WotsQuery → K)
    (table : Memo K Digest) (seed : ByteKey) (layer tree kp index steps : ℕ) :
    evalProgram digestDraw (wotsSeedChainProgram encode seed layer tree kp index steps) table =
      wotsSeedChain encode table seed layer tree kp index steps := by
  simp only [wotsSeedChainProgram, evalProgram, evalProgram_chain, wotsSeedChain]

theorem wots_seed_chain_map (encode : K → L) (labels : WotsQuery → K)
    (seed : ByteKey) (layer tree kp index steps : ℕ) :
    mapProgram encode (wotsSeedChainProgram labels seed layer tree kp index steps) =
      wotsSeedChainProgram (encode ∘ labels) seed layer tree kp index steps := by
  simp only [wotsSeedChainProgram, mapProgram, mapProgram_chain, Function.comp_def]

theorem wots_seed_chain_public (seed : ByteKey) (layer tree kp index steps : ℕ) :
    PublicBudget (wotsSeedChainProgram id seed layer tree kp index steps) steps := by
  intro digest
  exact publicBudget_total _

def wotsFillStep (encode : WotsQuery → K) (seed : ByteKey) (layer tree kp : ℕ)
    (steps : Fin 43 → ℕ) (i : Fin 43) (sigma : WotsSigma) :
    QueryProgram K Digest WotsSigma (steps i + 1) :=
  mapReturnProgram (fun value => Function.update sigma i value)
    (wotsSeedChainProgram encode seed layer tree kp i.val (steps i))

def wotsFillProgram (encode : WotsQuery → K) (seed : ByteKey) (layer tree kp : ℕ)
    (steps : Fin 43 → ℕ) (order : List (Fin 43)) (sigma : WotsSigma) :
    QueryProgram K Digest WotsSigma (collectionSteps (fun i => steps i + 1) order) :=
  stateFoldProgram (fun i => steps i + 1) (wotsFillStep encode seed layer tree kp steps) order sigma

def wotsFillLoop [DecidableEq K] (encode : WotsQuery → K) (seed : ByteKey)
    (layer tree kp : ℕ) (steps : Fin 43 → ℕ) :
    List (Fin 43) → WotsSigma → Memo K Digest → PMF (WotsSigma × Memo K Digest)
  | [], sigma, table => PMF.pure (sigma, table)
  | i :: rest, sigma, table =>
      (wotsSeedChain encode table seed layer tree kp i.val (steps i)).bind
        (fun out => wotsFillLoop encode seed layer tree kp steps rest
          (Function.update sigma i out.1) out.2)

theorem wots_fill_eval [DecidableEq K] (encode : WotsQuery → K) (seed : ByteKey)
    (layer tree kp : ℕ) (steps : Fin 43 → ℕ) (order : List (Fin 43))
    (sigma : WotsSigma) (table : Memo K Digest) :
    evalProgram digestDraw (wotsFillProgram encode seed layer tree kp steps order sigma) table =
      wotsFillLoop encode seed layer tree kp steps order sigma table := by
  induction order generalizing sigma table with
  | nil => rfl
  | cons i rest ih =>
    simp only [wotsFillProgram, stateFoldProgram, evalProgram_cast, evalProgram_bind,
      wotsFillStep, evalProgram_mapReturn, wots_seed_chain_eval, PMF.bind_map,
      wotsFillLoop] at ih ⊢
    congr 1
    funext out
    exact ih _ _

theorem wots_fill_public (seed : ByteKey) (layer tree kp : ℕ) (steps : Fin 43 → ℕ)
    (order : List (Fin 43)) (sigma : WotsSigma) :
    PublicBudget (wotsFillProgram id seed layer tree kp steps order sigma)
      (collectionSteps steps order) := by
  apply publicBudget_stateFold
  intro i state
  rw [wotsFillStep, publicBudget_mapReturn]
  exact wots_seed_chain_public seed layer tree kp i.val (steps i)

theorem wots_fill_map (encode : K → L) (labels : WotsQuery → K) (seed : ByteKey)
    (layer tree kp : ℕ) (steps : Fin 43 → ℕ) (order : List (Fin 43))
    (sigma : WotsSigma) :
    mapProgram encode (wotsFillProgram labels seed layer tree kp steps order sigma) =
      wotsFillProgram (encode ∘ labels) seed layer tree kp steps order sigma := by
  simp only [wotsFillProgram, mapProgram_stateFold, wotsFillStep,
    mapProgram_mapReturn, wots_seed_chain_map]
  rfl

theorem wots_fill_cost (steps : Fin 43 → ℕ) (order : List (Fin 43)) :
    collectionSteps (fun i => steps i + 1) order = collectionSteps steps order + order.length := by
  induction order with
  | nil => rfl
  | cons i rest ih =>
    simp only [collectionSteps, List.map_cons, List.sum_cons, List.length_cons] at ih ⊢
    omega

end
end C10Probability
