import C10Probability.ForsTree
import C10Probability.ForsRecover

/-! The forest's per-tree call signs and then actually recovers the root. It
does not replace that recovery by the builder's root or assume their equality. -/
namespace C10Probability
noncomputable section

variable {K L : Type*}

structure ForestTreeResult where
  secret : Randomizer
  auth : List Randomizer
  root : Randomizer
  deriving DecidableEq

def forestOneProgram (encode : WotsQuery → K) (seed : ByteKey) (ht tree target : ℕ) :
    QueryProgram K Digest ForestTreeResult 6156 :=
  bindProgram (forsSignProgram encode seed ht tree target) (fun sig =>
    mapReturnProgram (fun root => ⟨sig.1, sig.2, root⟩)
      (forsRecoverProgram (fun key => encode (.inl key)) seed ht tree target sig.1 sig.2))

def forestOne [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree target : ℕ) : PMF (ForestTreeResult × Memo K Digest) :=
  (forsSign encode table seed ht tree target).bind
    (fun sig => (forsRecover (fun key => encode (.inl key)) sig.2 seed ht tree target
      sig.1.1 sig.1.2).map (fun root => (⟨sig.1.1, sig.1.2, root.1⟩, root.2)))

theorem forest_one_eval [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree target : ℕ) :
    evalProgram digestDraw (forestOneProgram encode seed ht tree target) table =
      forestOne encode table seed ht tree target := by
  simp only [forestOneProgram, evalProgram_bind, evalProgram_mapReturn, fors_sign_eval,
    fors_recover_eval, forestOne]

theorem forest_one_map (encode : K → L) (labels : WotsQuery → K)
    (seed : ByteKey) (ht tree target : ℕ) :
    mapProgram encode (forestOneProgram labels seed ht tree target) =
      forestOneProgram (encode ∘ labels) seed ht tree target := by
  simp only [forestOneProgram, mapProgram_bind, mapProgram_mapReturn,
    fors_sign_map, fors_recover_map, Function.comp_def]

theorem forest_one_public (seed : ByteKey) (ht tree target : ℕ) :
    PublicBudget (forestOneProgram id seed ht tree target) 4107 := by
  exact publicBudget_bind _ _ 4095 12 (fors_sign_public seed ht tree target)
    (fun _ => publicBudget_total _)

theorem fors_sign_auth_length [DecidableEq K] (encode : WotsQuery → K)
    (table : Memo K Digest) (seed : ByteKey) (ht tree target : ℕ)
    (out : (Randomizer × List Randomizer) × Memo K Digest)
    (ho : out ∈ (forsSign encode table seed ht tree target).support) :
    out.1.2.length = 11 := by
  rw [forsSign, PMF.mem_support_bind_iff] at ho
  obtain ⟨secret, _, ho⟩ := ho
  rw [PMF.mem_support_map_iff] at ho
  obtain ⟨result, hr, rfl⟩ := ho
  exact fors_tree_auth_length encode secret.2 seed ht tree target result hr

theorem forest_one_auth_length [DecidableEq K] (encode : WotsQuery → K)
    (table : Memo K Digest) (seed : ByteKey) (ht tree target : ℕ)
    (out : ForestTreeResult × Memo K Digest)
    (ho : out ∈ (forestOne encode table seed ht tree target).support) :
    out.1.auth.length = 11 := by
  rw [forestOne, PMF.mem_support_bind_iff] at ho
  obtain ⟨sig, hs, ho⟩ := ho
  rw [PMF.mem_support_map_iff] at ho
  obtain ⟨root, _, rfl⟩ := ho
  exact fors_sign_auth_length encode table seed ht tree target sig hs

end
end C10Probability
