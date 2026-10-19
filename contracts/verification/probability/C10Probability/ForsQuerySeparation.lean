import C10Probability.ForestSignOpening
import C10Probability.QueryExclusion
import C10Probability.C10Sign
import C10Probability.C10Keygen

/-! The unchanged WOTS, key-generation and randomizer components cannot read
an ordinary FORS private target. Public calls are disjoint by the sum-key tag;
private WOTS and counter calls are separated by their proved byte lengths. -/
namespace C10Probability
noncomputable section
variable {K L α R H P : Type*}

theorem query_exclusion_all_mapped (select : K → Bool) (encode : L → K)
    (excluded : ∀ key, select (encode key) = false) {n : ℕ} (program : QueryProgram L α R n) :
    QueryExclusion select (fun _ => True) (mapProgram encode program) := by
  induction program with
  | done value => trivial
  | query key next ih => exact ⟨excluded key, ih⟩

theorem query_exclusion_sealed [DecidableEq K] (target : K) {n : ℕ}
    (program : QueryProgram K α R n)
    (excluded : QueryExclusion (fun key => decide (key = target)) (fun _ => True) program) :
    OpeningSealed target (liftOpening (P := P) (H := H) program) := by
  induction program with
  | done value => trivial
  | query key next ih =>
    exact ⟨of_decide_eq_false excluded.1, fun reply => ih reply (excluded.2 reply)⟩

def forsTargetSelect (target : ForsTarget) (key : WotsQuery) : Bool := decide (key = forsTargetKey target)

theorem fors_public_excluded (target : ForsTarget) {n : ℕ} (program : QueryProgram ByteKey α R n) :
    QueryExclusion (forsTargetSelect target) (fun _ => True) (mapProgram Sum.inl program) := by
  exact query_exclusion_all_mapped _ _ (fun key => by simp [forsTargetSelect, fors_target_not_public]) program

theorem wots_fill_fors_excluded (target : ForsTarget) (seed : ByteKey) (layer tree kp : ℕ)
    (steps : Fin 43 → ℕ) (order : List (Fin 43)) (sigma : WotsSigma) :
    QueryExclusion (forsTargetSelect target) (fun _ => True)
      (wotsFillProgram id seed layer tree kp steps order sigma) := by
  apply queryExclusion_stateFold
  · intro i state _
    rw [wotsFillStep, queryExclusion_mapReturn]
    refine ⟨?_, fun digest => ?_⟩
    · simp only [id_eq, forsTargetSelect, fors_target_not_wots, decide_false]
    · apply queryExclusion_chain
      intro pos value
      simp only [id_eq, forsTargetSelect, fors_target_not_public, decide_false]
  · trivial

theorem wots_leaf_fors_excluded (target : ForsTarget) (seed : ByteKey) (layer tree kp : ℕ) :
    QueryExclusion (forsTargetSelect target) (fun _ => True) (wotsLeafProgram id seed layer tree kp) := by
  rw [wotsLeafProgram]
  apply queryExclusion_bind (forsTargetSelect target) (fun _ => True) _ _ _
  · rw [wotsLeafFillProgram, queryExclusion_cast]
    exact wots_fill_fors_excluded target seed layer tree kp _ _ _
  · intro sigma _
    refine ⟨?_, fun _ => trivial⟩
    simp only [id_eq, forsTargetSelect, fors_target_not_public, decide_false]

set_option maxRecDepth 20000 in
theorem subtree_fors_excluded {S : Type*} (target : ForsTarget) (seed : ByteKey) (layer tree : ℕ)
    (remember : ℕ → ℕ → Randomizer → Randomizer → S → S) (initial : S) :
    QueryExclusion (forsTargetSelect target) (fun _ => True)
      (subtreeProgram id seed layer tree remember initial) := by
  rw [subtreeProgram, queryExclusion_cast, queryExclusion_mapReturn]
  simp only [Function.comp_def, id_eq]
  let stack : ShapeStack Randomizer [] := PUnit.unit
  with_reducible refine (queryExclusion_tree (forsTargetSelect target) 345
    (wotsLeafProgram id seed layer tree) (wots_leaf_fors_excluded target seed layer tree)
    (fun kp h left right => Sum.inl (treePairInput seed layer tree kp h left right))
    randomizerOfDigest remember ?_ 512 0 [] stack initial)
  intro kp height left right
  simp only [forsTargetSelect, fors_target_not_public, decide_false]

theorem wots_sign_fors_excluded (target : ForsTarget) (seed : ByteKey) (layer tree kp : ℕ)
    (message shuffle : ByteKey) (n : ℕ) (hb : n ≤ 2 ^ 32) :
    QueryExclusion (forsTargetSelect target) (fun _ => True)
      (wotsSignProgram id seed layer tree kp message shuffle n hb) := by
  rw [wotsSignProgram, queryExclusion_cast]
  apply queryExclusion_bind (forsTargetSelect target) (fun _ => True) _ _ _
    (fors_public_excluded target _)
  intro found _
  cases found with
  | none => rw [wotsSignAfterProgram]; trivial
  | some found =>
    obtain ⟨count, digest⟩ := found
    by_cases accepted : wotsAccept (wotsOfDigest digest) = true
    · rw [wotsSignAfterProgram, dif_pos accepted]
      apply queryExclusion_bind (forsTargetSelect target) (fun _ => True) _ _ _
      · simpa only [wots_shuffle_map, Function.comp_id] using
          fors_public_excluded target (wotsShuffleProgram id shuffle)
      · intro order _
        rw [queryExclusion_mapReturn, wotsAcceptedFillProgram, queryExclusion_cast]
        exact wots_fill_fors_excluded target seed layer tree kp _ _ _
    · rw [wotsSignAfterProgram, dif_neg accepted]
      trivial

theorem layer_sign_fors_excluded (target : ForsTarget) (seed : ByteKey) (layer tree leaf : ℕ)
    (message : Randomizer) (shuffle : ByteKey) (n : ℕ) (hb : n ≤ 2 ^ 32) :
    QueryExclusion (forsTargetSelect target) (fun _ => True)
      (layerSignProgram id seed layer tree leaf message shuffle n hb) := by
  rw [layerSignProgram, queryExclusion_cast]
  apply queryExclusion_bind (forsTargetSelect target) (fun _ => True) _ _ _
  · rw [merkleBuildProgram, queryExclusion_mapReturn]
    exact subtree_fors_excluded target seed layer tree _ _
  · intro built _
    apply queryExclusion_bind (forsTargetSelect target) (fun _ => True) _ _ _
    · simpa only [shuffle_derive_map, Function.comp_id] using
        fors_public_excluded target (shuffleDeriveProgram id shuffle (layerShuffleLabel layer))
    · intro subseed _
      apply queryExclusion_bind (forsTargetSelect target) (fun _ => True) _ _ _
        (wots_sign_fors_excluded target seed layer tree leaf (nodeValueBytes message) subseed n hb)
      intro signed _
      cases signed with
      | none => trivial
      | some signed =>
        rw [layerSignAfterProgram, queryExclusion_mapReturn]
        simpa only [layer_recover_map, Function.comp_id] using
          fors_public_excluded target (layerRecoverProgram id seed layer tree leaf message _)

theorem hypertree_sign_fors_excluded (target : ForsTarget) (seed shuffle : ByteKey)
    (n : ℕ) (hb : n ≤ 2 ^ 32) (steps layer index : ℕ) (current : Randomizer)
    (signatures : List LayerSignature) :
    QueryExclusion (forsTargetSelect target) (fun _ => True)
      (hypertreeSignProgram id seed shuffle n hb steps layer index current signatures) := by
  induction steps generalizing layer index current signatures with
  | zero => rw [hypertreeSignProgram]; trivial
  | succ steps ih =>
    rw [hypertreeSignProgram, queryExclusion_cast]
    apply queryExclusion_bind (forsTargetSelect target) (fun _ => True) _ _ _
      (layer_sign_fors_excluded target _ _ _ _ _ _ _ _)
    intro signed _
    cases signed with
    | none => trivial
    | some signed => exact ih _ _ _ _

theorem c10_keygen_fors_excluded (target : ForsTarget) (publicSeed : Digest) :
    QueryExclusion (forsTargetSelect target) (fun _ => True) (c10KeygenProgram id publicSeed) := by
  rw [c10KeygenProgram, queryExclusion_mapReturn, subtreeRootProgram, queryExclusion_mapReturn]
  exact subtree_fors_excluded target _ 1 0 _ _

end
end C10Probability
