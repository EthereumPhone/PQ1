import C10Probability.AuthCertificate
import C10Probability.AuthGeometry

/-! Certified stored siblings reconstruct the certified root. Uniqueness uses
functional cache lookups, not hash injectivity or collision exclusion. -/
namespace C10Probability
noncomputable section

variable {K α N : Type*}

theorem recorded_auth_path (table : Memo K α) (leaf : ℕ → Option N)
    (pair : ℕ → ℕ → N → N → K) (project : α → N) (auth : List N)
    {height edge : ℕ} {root : N}
    (recorded : RecordedTreeNode table leaf
      (fun kp h left right => pair h (kp / 2 ^ (h + 1)) left right) project height edge root)
    (block offset : ℕ) (aligned : edge = 2 ^ height * (block + 1))
    (bound : offset < 2 ^ height) (length : height ≤ auth.length)
    (slots : ∀ j, j < height → RecordedAuthSlot table leaf
      (fun kp h left right => pair h (kp / 2 ^ (h + 1)) left right) project
      (2 ^ height * block + offset) auth j) :
    ∃ value, leaf (2 ^ height * block + offset) = some value ∧
      replayPath table pair project 0 (2 ^ height * block + offset) value (auth.take height) = some root := by
  induction recorded generalizing block offset with
  | leaf kp value hl =>
    have hk : kp = block := by simp only [pow_zero, one_mul] at aligned; omega
    have ho : offset = 0 := by simpa only [pow_zero, Nat.lt_one_iff] using bound
    subst block
    subst offset
    exact ⟨value, by simpa using hl, by simp [replayPath]⟩
  | pair height edge left right reply hl hr hd ihl ihr =>
    have he : edge = 2 ^ height * (2 * block + 2) := by rw [aligned, pow_succ]; ring
    have heleft : edge - 2 ^ height = 2 ^ height * (2 * block + 1) := by
      have he' : edge = 2 ^ height * (2 * block + 1) + 2 ^ height := by rw [he]; ring
      omega
    have heright : edge = 2 ^ height * ((2 * block + 1) + 1) := by simpa [Nat.add_assoc] using he
    have hp : (edge - 1) / 2 ^ (height + 1) = block := by rw [aligned]; exact tree_parent_index height block
    have lookup : table (pair height block left right) = some reply := by simpa only [hp] using hd
    have prefixLength : (auth.take height).length = height := by simp only [List.length_take]; omega
    by_cases side : offset < 2 ^ height
    · have hi : 2 ^ (height + 1) * block + offset = 2 ^ height * (2 * block) + offset := by rw [pow_succ]; ring
      obtain ⟨value, hleaf, hpath⟩ := ihl (2 * block) offset heleft side (by omega)
        (fun j hj => by simpa only [hi] using slots j (by omega))
      obtain ⟨sibling, stored, cert⟩ := slots height (by omega)
      have siblingEdge : (siblingIndex ((2 ^ (height + 1) * block + offset) / 2 ^ height) + 1) *
          2 ^ height = edge := by
        rw [hi, tree_leaf_quotient height (2 * block) offset side, sibling_left, he]
        ring
      rw [siblingEdge] at cert
      have equal : sibling = right := recorded_tree_node_unique table leaf _ project cert hr
      subst sibling
      refine ⟨value, by simpa only [hi] using hleaf, ?_⟩
      rw [List.take_add_one, stored, Option.toList_some, hi, replay_path_append, hpath,
        Option.bind_some, prefixLength, Nat.zero_add, tree_leaf_quotient height (2 * block) offset side]
      have parity : (2 * block) % 2 = 0 := by omega
      have parent : (2 * block) / 2 = block := by omega
      simp only [replayPath, pathPairInput, parity, ↓reduceIte, parent, lookup, Option.bind_some]
    · have hlow : 2 ^ height ≤ offset := by omega
      have hbound : offset - 2 ^ height < 2 ^ height := by rw [pow_succ] at bound; omega
      have hi : 2 ^ (height + 1) * block + offset =
          2 ^ height * (2 * block + 1) + (offset - 2 ^ height) := by
        have hm : 2 ^ height * (2 * block + 1) = 2 ^ (height + 1) * block + 2 ^ height := by rw [pow_succ]; ring
        omega
      obtain ⟨value, hleaf, hpath⟩ := ihr (2 * block + 1) (offset - 2 ^ height)
        heright hbound (by omega) (fun j hj => by simpa only [hi] using slots j (by omega))
      obtain ⟨sibling, stored, cert⟩ := slots height (by omega)
      have siblingEdge : (siblingIndex ((2 ^ (height + 1) * block + offset) / 2 ^ height) + 1) *
          2 ^ height = edge - 2 ^ height := by
        rw [hi, tree_leaf_quotient height (2 * block + 1) (offset - 2 ^ height) hbound,
          sibling_right, heleft]
        ring
      rw [siblingEdge] at cert
      have equal : sibling = left := recorded_tree_node_unique table leaf _ project cert hl
      subst sibling
      refine ⟨value, by simpa only [hi] using hleaf, ?_⟩
      rw [List.take_add_one, stored, Option.toList_some, hi, replay_path_append, hpath,
        Option.bind_some, prefixLength, Nat.zero_add,
        tree_leaf_quotient height (2 * block + 1) (offset - 2 ^ height) hbound]
      have parity : (2 * block + 1) % 2 ≠ 0 := by omega
      have parent : (2 * block + 1) / 2 = block := by omega
      simp only [replayPath, pathPairInput, parity, ↓reduceIte, parent, lookup, Option.bind_some]

theorem collected_complete_path (table : Memo K α) (leaf : ℕ → Option N)
    (pair : ℕ → ℕ → N → N → K) (project : α → N)
    (target height : ℕ) (auth : List N) (root : N)
    (collected : CollectedTreeNode table leaf
      (fun kp h left right => pair h (kp / 2 ^ (h + 1)) left right) project
      target auth height (2 ^ height) root)
    (length : auth.length = height) (bound : target < 2 ^ height) :
    ∃ value, leaf target = some value ∧ replayPath table pair project 0 target value auth = some root := by
  have cert := recorded_auth_path table leaf pair project auth collected.1 0 target
    (by simp) bound (by omega) (by simpa using collected.2 (by omega) bound)
  simpa only [Nat.mul_zero, Nat.zero_add, ← length, List.take_length] using cert

end
end C10Probability
