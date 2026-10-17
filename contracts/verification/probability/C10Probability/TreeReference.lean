import C10Probability.TreeCertificate
import C10Probability.PathReplay

/-! A complete, aligned tree certificate supplies a recorded reference path
for every leaf. The selected leaf may be chosen after the tree was built. -/
namespace C10Probability
noncomputable section

variable {K α N : Type*}

theorem tree_parent_index (height block : ℕ) :
    (2 ^ (height + 1) * (block + 1) - 1) / 2 ^ (height + 1) = block := by
  have hp : 0 < 2 ^ (height + 1) := pow_pos (by decide) _
  apply Nat.div_eq_of_lt_le
  · have he : 2 ^ (height + 1) * (block + 1) = block * 2 ^ (height + 1) + 2 ^ (height + 1) := by ring
    omega
  · have he : (block + 1) * 2 ^ (height + 1) = 2 ^ (height + 1) * (block + 1) := Nat.mul_comm _ _
    have hpos : 0 < 2 ^ (height + 1) * (block + 1) := Nat.mul_pos hp (by omega)
    omega

theorem tree_leaf_quotient (height block offset : ℕ) (bound : offset < 2 ^ height) :
    (2 ^ height * block + offset) / 2 ^ height = block := by
  rw [Nat.mul_add_div (pow_pos (by decide) height), Nat.div_eq_of_lt bound, Nat.add_zero]

theorem recorded_tree_reference (table : Memo K α) (leaf : ℕ → Option N)
    (pair : ℕ → ℕ → N → N → K) (project : α → N)
    {height edge : ℕ} {root : N}
    (recorded : RecordedTreeNode table leaf
      (fun kp h left right => pair h (kp / 2 ^ (h + 1)) left right) project height edge root)
    (block offset : ℕ) (aligned : edge = 2 ^ height * (block + 1))
    (bound : offset < 2 ^ height) :
    ∃ value auth, leaf (2 ^ height * block + offset) = some value ∧
      auth.length = height ∧
      replayPath table pair project 0 (2 ^ height * block + offset) value auth = some root := by
  induction recorded generalizing block offset with
  | leaf kp value hl =>
    have hk : kp = block := by simp only [pow_zero, one_mul] at aligned; omega
    have ho : offset = 0 := by simpa only [pow_zero, Nat.lt_one_iff] using bound
    subst block
    subst offset
    exact ⟨value, [], by simpa using hl, rfl, rfl⟩
  | pair height edge left right reply hl hr hd ihl ihr =>
    have he : edge = 2 ^ height * (2 * block + 2) := by rw [aligned, pow_succ]; ring
    have heleft : edge - 2 ^ height = 2 ^ height * (2 * block + 1) := by
      have he' : edge = 2 ^ height * (2 * block + 1) + 2 ^ height := by rw [he]; ring
      omega
    have heright : edge = 2 ^ height * ((2 * block + 1) + 1) := by simpa [Nat.add_assoc] using he
    have hp : (edge - 1) / 2 ^ (height + 1) = block := by rw [aligned]; exact tree_parent_index height block
    have lookup : table (pair height block left right) = some reply := by simpa only [hp] using hd
    by_cases side : offset < 2 ^ height
    · obtain ⟨value, auth, hleaf, hlen, hpath⟩ := ihl (2 * block) offset heleft side
      have hi : 2 ^ (height + 1) * block + offset = 2 ^ height * (2 * block) + offset := by rw [pow_succ]; ring
      refine ⟨value, auth ++ [right], ?_, by simp [hlen], ?_⟩
      · simpa only [hi] using hleaf
      · rw [hi, replay_path_append, hpath, Option.bind_some, hlen, Nat.zero_add,
          tree_leaf_quotient height (2 * block) offset side]
        have parity : (2 * block) % 2 = 0 := by omega
        have parent : (2 * block) / 2 = block := by omega
        simp only [replayPath, pathPairInput, parity, ↓reduceIte, parent,
          lookup, Option.bind_some]
    · have hlow : 2 ^ height ≤ offset := by omega
      have hbound : offset - 2 ^ height < 2 ^ height := by rw [pow_succ] at bound; omega
      obtain ⟨value, auth, hleaf, hlen, hpath⟩ := ihr (2 * block + 1) (offset - 2 ^ height) heright hbound
      have hi : 2 ^ (height + 1) * block + offset =
          2 ^ height * (2 * block + 1) + (offset - 2 ^ height) := by
        have hm : 2 ^ height * (2 * block + 1) = 2 ^ (height + 1) * block + 2 ^ height := by rw [pow_succ]; ring
        omega
      refine ⟨value, auth ++ [left], ?_, by simp [hlen], ?_⟩
      · simpa only [hi] using hleaf
      · rw [hi, replay_path_append, hpath, Option.bind_some, hlen, Nat.zero_add,
          tree_leaf_quotient height (2 * block + 1) (offset - 2 ^ height) hbound]
        have parity : (2 * block + 1) % 2 ≠ 0 := by omega
        have parent : (2 * block + 1) / 2 = block := by omega
        simp only [replayPath, pathPairInput, parity, ↓reduceIte, parent,
          lookup, Option.bind_some]

end
end C10Probability
