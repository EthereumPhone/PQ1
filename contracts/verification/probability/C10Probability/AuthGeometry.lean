import C10Probability.ForsTree
import C10Probability.TreeReference

/-! Exact sibling selection for the two existing collectors. The common form
retains out-of-range `List.set` behavior; the Merkle kept check stays explicit. -/
namespace C10Probability
noncomputable section

def collectAuth (target kp height : ℕ) (left right : Randomizer)
    (auth : List Randomizer) : List Randomizer :=
  if 2 * (kp / 2 ^ (height + 1)) = siblingIndex (target / 2 ^ height) then
    auth.set height left
  else if 2 * (kp / 2 ^ (height + 1)) + 1 = siblingIndex (target / 2 ^ height) then
    auth.set height right
  else auth

theorem auth_pair_start (kp height : ℕ) :
    (kp / 2 ^ (height + 1) * 2 ^ (height + 1)) / 2 ^ height =
      2 * (kp / 2 ^ (height + 1)) := by
  rw [pow_succ]
  have hp : 0 < 2 ^ height := pow_pos (by decide) _
  have he : kp / (2 ^ height * 2) * (2 ^ height * 2) =
      (2 * (kp / (2 ^ height * 2))) * 2 ^ height := by ring
  rw [he, Nat.mul_div_cancel _ hp]

theorem auth_remember_nodes (target kp height : ℕ) (left right : Randomizer)
    (state : AuthKeep) :
    (authRemember target kp height left right state).nodes =
      if (state.kept[height]?).getD false then state.nodes
      else collectAuth target kp height left right state.nodes := by
  simp only [authRemember, auth_pair_start, collectAuth]
  split
  · rfl
  · split
    · rfl
    · split <;> rfl

theorem fors_remember_collect (target kp height : ℕ) (left right : Randomizer)
    (auth : List Randomizer) :
    forsRemember target kp height left right auth =
      collectAuth target kp height left right auth := by
  have hp : 0 < 2 ^ height := pow_pos (by decide) _
  have hs : kp / 2 ^ (height + 1) * 2 ^ (height + 1) =
      (2 * (kp / 2 ^ (height + 1))) * 2 ^ height := by rw [pow_succ]; ring
  have hs' : kp / 2 ^ (height + 1) * 2 ^ (height + 1) + 2 ^ height =
      (2 * (kp / 2 ^ (height + 1)) + 1) * 2 ^ height := by rw [hs]; ring
  unfold forsRemember
  dsimp only
  rw [hs', hs]
  simp only [Nat.mul_left_inj (Nat.ne_of_gt hp), collectAuth]
  by_cases hl : 2 * (kp / 2 ^ (height + 1)) = siblingIndex (target / 2 ^ height)
  · have parity : siblingIndex (target / 2 ^ height) % 2 = 0 := by omega
    simp [hl, parity]
  · by_cases hr : 2 * (kp / 2 ^ (height + 1)) + 1 = siblingIndex (target / 2 ^ height)
    · have parity : siblingIndex (target / 2 ^ height) % 2 ≠ 0 := by omega
      simp [hl, hr, parity]
    · simp only [hl, hr, ↓reduceIte]
      split <;> simp_all [eq_comm]

theorem sibling_parent (index : ℕ) : siblingIndex index / 2 = index / 2 := by
  unfold siblingIndex
  split <;> omega

theorem sibling_left (block : ℕ) : siblingIndex (2 * block) = 2 * block + 1 := by
  simp [siblingIndex]

theorem sibling_right (block : ℕ) : siblingIndex (2 * block + 1) = 2 * block := by
  simp [siblingIndex]

theorem aligned_merge_edge (kp height : ℕ)
    (aligned : (kp + 1) % 2 ^ (height + 1) = 0) :
    kp + 1 = 2 ^ (height + 1) * (kp / 2 ^ (height + 1) + 1) := by
  have hp : 0 < 2 ^ (height + 1) := pow_pos (by decide) _
  have he := Nat.mod_add_div (kp + 1) (2 ^ (height + 1))
  rw [aligned, Nat.zero_add] at he
  have hq : 0 < (kp + 1) / 2 ^ (height + 1) := by
    apply Nat.pos_of_ne_zero
    intro hz
    rw [hz, Nat.mul_zero] at he
    omega
  obtain ⟨b, hb⟩ := Nat.exists_eq_succ_of_ne_zero (Nat.ne_of_gt hq)
  rw [hb] at he
  change 2 ^ (height + 1) * (b + 1) = kp + 1 at he
  have hk : kp = 2 ^ (height + 1) * (b + 1) - 1 := by omega
  have hd : kp / 2 ^ (height + 1) = b := by rw [hk]; exact tree_parent_index height b
  rw [hd]
  omega

end
end C10Probability
