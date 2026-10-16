import C10Probability.KeyCollision

/-! Independent schedules and their exact collision detector. These laws make
the pre-sampled schedule an explicit experiment, including its full length. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

variable {K L : Type*}

def drawList (q : PMF K) : ℕ → PMF (List K)
  | 0 => PMF.pure []
  | n + 1 => q.bind fun key => (drawList q n).map (List.cons key)

theorem drawList_length (q : PMF K) (n : ℕ) (keys : List K)
    (h : keys ∈ (drawList q n).support) : keys.length = n := by
  induction n generalizing keys with
  | zero => have he : keys = [] := by simpa [drawList] using h
            simp [he]
  | succ n ih =>
    rw [drawList, PMF.mem_support_bind_iff] at h
    obtain ⟨key, _, h⟩ := h
    rw [PMF.mem_support_map_iff] at h
    obtain ⟨tail, ht, rfl⟩ := h
    simp [ih tail ht]

theorem drawList_map (q : PMF K) (f : K → L) (n : ℕ) :
    drawList (q.map f) n = (drawList q n).map (List.map f) := by
  induction n with
  | zero => simp [drawList, PMF.pure_map]
  | succ n ih =>
    simp only [drawList, PMF.bind_map, PMF.map_bind, ih, PMF.map_comp, Function.comp_def]
    rfl

def collisionScan [DecidableEq K] (seen : Finset K) : List K → Bool
  | [] => false
  | key :: keys => if key ∈ seen then true else collisionScan (insert key seen) keys

theorem collisionScan_false [DecidableEq K] (seen : Finset K) (keys : List K) :
    collisionScan seen keys = false ↔ keys.Nodup ∧ ∀ key ∈ keys, key ∉ seen := by
  induction keys generalizing seen with
  | nil => simp [collisionScan]
  | cons key keys ih =>
    by_cases hk : key ∈ seen
    · simp [collisionScan, hk]
    · simp only [collisionScan, hk, ↓reduceIte, ih, Finset.mem_insert, not_or,
        List.nodup_cons, List.mem_cons, forall_eq_or_imp]
      constructor
      · rintro ⟨hd, h⟩
        exact ⟨⟨fun hm => (h key hm).1 rfl, hd⟩, by simp, fun other ho => (h other ho).2⟩
      · rintro ⟨⟨hn, hd⟩, _, h⟩
        exact ⟨hd, fun other ho => ⟨fun he => hn (he ▸ ho), h other ho⟩⟩

theorem collisionScan_repeat [DecidableEq K] (key : K) : collisionScan ∅ [key, key] = true := by
  simp [collisionScan]

theorem collisionScan_history [DecidableEq K] (seen : Finset K) (key : K) (hk : key ∈ seen) :
    collisionScan seen [key] = true := by simp [collisionScan, hk]

theorem collisionScan_fresh_single [DecidableEq K] (seen : Finset K) (key : K) (hk : key ∉ seen) :
    collisionScan seen [key] = false := by simp [collisionScan, hk]

theorem drawList_collision [DecidableEq K] [Fintype K] [Nonempty K] (seen : Finset K) (n : ℕ) :
    (drawList (PMF.uniformOfFintype K) n).map (collisionScan seen) =
      keyCollision seen n := by
  induction n generalizing seen with
  | zero => simp [drawList, keyCollision, PMF.pure_map, collisionScan]
  | succ n ih =>
    rw [drawList, PMF.map_bind, keyCollision]
    congr 1
    funext key
    rw [PMF.map_comp]
    by_cases hk : key ∈ seen
    · simpa only [Function.comp_def, collisionScan, hk, ↓reduceIte, Function.const] using
        (PMF.map_const (drawList (PMF.uniformOfFintype K) n) true)
    · simpa only [Function.comp_def, collisionScan, hk, ↓reduceIte] using ih (insert key seen)

end
end C10Probability
