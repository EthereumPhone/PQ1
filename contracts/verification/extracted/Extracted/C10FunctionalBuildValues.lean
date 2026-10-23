/- Algebraic laws for shared construction values; no oracle scheduling claim. -/
import Extracted.C10Representation
import Aeneas
import Mathlib.Data.Nat.Bitwise

open C10Representation
namespace Extracted.C10FunctionalBuildValues

theorem nodes_zero (f : List Int → List Int) seed layer tree kind kp total leaves :
    tree_nodes_value f seed layer tree kind kp total 0 leaves = leaves := rfl

theorem nodes_succ (f : List Int → List Int) seed layer tree kind kp total leaves n :
    tree_nodes_value f seed layer tree kind kp total (n+1) leaves =
      tree_level_value f seed layer tree kind kp total (n+1)
        (tree_nodes_value f seed layer tree kind kp total n leaves) := by
  simp [tree_nodes_value, List.range_succ]

theorem level_length (f : List Int → List Int) seed layer tree kind kp total h nodes :
    (tree_level_value f seed layer tree kind kp total h nodes).length = 2^(total-h) := by
  simp [tree_level_value]

theorem nodes_length (f : List Int → List Int) seed layer tree kind kp total leaves n
    (hlen : leaves.length = 2^total) :
    (tree_nodes_value f seed layer tree kind kp total n leaves).length = 2^(total-n) := by
  cases n with
  | zero => simpa [nodes_zero] using hlen
  | succ n => rw [nodes_succ, level_length]

theorem auth_length (f : List Int → List Int) seed layer tree kind kp total leaves idx :
    (tree_auth_values f seed layer tree kind kp total leaves idx).length = total := by
  simp [tree_auth_values]

theorem root_value (f : List Int → List Int) seed layer tree kind kp total leaves :
    tree_root_value f seed layer tree kind kp total leaves =
      (tree_nodes_value f seed layer tree kind kp total total leaves).getD 0
        (List.replicate 16 0) := rfl

theorem level_get (f : List Int → List Int) seed layer tree kind kp total h nodes i
    (hi : i < 2^(total-h)) :
    (tree_level_value f seed layer tree kind kp total h nodes).getD i (List.replicate 16 0) =
      tree_pair_value f seed (address_words layer tree kind kp 0 (Int.ofNat h) (Int.ofNat i))
        (nodes.getD (2*i) (List.replicate 16 0))
        (nodes.getD (2*i+1) (List.replicate 16 0)) := by
  simp [tree_level_value, hi]

def recursiveNode (f : List Int → List Int) (seed : List Int)
    (layer tree kind kp : Int) (leaves : List (List Int)) : Nat → Nat → List Int
  | 0, i => leaves.getD i (List.replicate 16 0)
  | h+1, i => tree_pair_value f seed
      (address_words layer tree kind kp 0 (Int.ofNat (h+1)) (Int.ofNat i))
      (recursiveNode f seed layer tree kind kp leaves h (2*i))
      (recursiveNode f seed layer tree kind kp leaves h (2*i+1))

theorem nodes_get_eq (f : List Int → List Int) seed layer tree kind kp total leaves n i
    (hn : n ≤ total) (hi : i < 2^(total-n)) :
    (tree_nodes_value f seed layer tree kind kp total n leaves).getD i (List.replicate 16 0) =
      recursiveNode f seed layer tree kind kp leaves n i := by
  induction n generalizing i with
  | zero => rfl
  | succ n ih =>
      have hs : total-n = (total-(n+1))+1 := by omega
      have hp : 2^(total-n) = 2^(total-(n+1))*2 := by rw [hs, pow_succ]
      rw [nodes_succ, level_get f seed layer tree kind kp total (n+1) _ i hi]
      rw [recursiveNode, ih (2*i) (by omega) (by omega), ih (2*i+1) (by omega) (by omega)]

theorem root_eq_node (f : List Int → List Int) seed layer tree kind kp total leaves :
    tree_root_value f seed layer tree kind kp total leaves =
      recursiveNode f seed layer tree kind kp leaves total 0 := by
  rw [root_value, nodes_get_eq f seed layer tree kind kp total leaves total 0 (by omega) (by simp)]

theorem auth_get (f : List Int → List Int) seed layer tree kind kp total leaves idx h
    (hh : h < total) :
    (tree_auth_values f seed layer tree kind kp total leaves idx).getD h (List.replicate 16 0) =
      (tree_nodes_value f seed layer tree kind kp total h leaves).getD
        (Int.toNat (if (idx / (2^h : Int)) % 2 = 0 then idx / (2^h : Int) + 1
                    else idx / (2^h : Int) - 1)) (List.replicate 16 0) := by
  simp [tree_auth_values, hh]

theorem sibling_outside (q b : Int) (hb : b % 2 = 0) (hq : b ≤ q) :
    b ≤ (if q % 2 = 0 then q+1 else q-1) := by
  split <;> omega

theorem sibling_inside (q b : Int) (hb : b % 2 = 0) (hq : 0 ≤ q ∧ q < b) :
    0 ≤ (if q % 2 = 0 then q+1 else q-1) ∧
      (if q % 2 = 0 then q+1 else q-1) < b := by
  split <;> omega

theorem pow_two_even (n : Nat) (hn : 0 < n) : (2^n : Int) % 2 = 0 := by
  obtain ⟨m, rfl⟩ := Nat.exists_eq_succ_of_ne_zero (by omega : n ≠ 0)
  simp [pow_succ]

theorem auth_outside_get (f : List Int → List Int) seed layer tree kind kp total leaves
    (idx : Int) h (hh : h < total) (hlen : leaves.length = 2^total)
    (hi : (2^total : Int) ≤ idx) :
    (tree_auth_values f seed layer tree kind kp total leaves idx).getD h
      (List.replicate 16 0) = List.replicate 16 0 := by
  have hp : (2^(total-h) : Int) * 2^h = 2^total := by
    rw [← pow_add, Nat.sub_add_cancel (by omega : h ≤ total)]
  have hq : (2^(total-h) : Int) ≤ idx / 2^h :=
    (Int.le_ediv_iff_mul_le (by positivity : (0:Int) < 2^h)).2 (by rwa [hp])
  have hs := sibling_outside (idx / 2^h) (2^(total-h))
    (pow_two_even (total-h) (by omega)) hq
  rw [auth_get f seed layer tree kind kp total leaves idx h hh]
  apply List.getD_eq_default
  rw [nodes_length f seed layer tree kind kp total leaves h hlen]
  have hc : (Int.ofNat (2^(total-h))) = (2^(total-h) : Int) := by simp
  rw [← hc] at hs
  exact Int.toNat_le_toNat hs

theorem auth_outside (f : List Int → List Int) seed layer tree kind kp total leaves
    (idx : Int) (hlen : leaves.length = 2^total) (hi : (2^total : Int) ≤ idx) :
    tree_auth_values f seed layer tree kind kp total leaves idx =
      List.replicate total (List.replicate 16 0) := by
  apply List.ext_getElem (by simp [auth_length])
  intro h hh hr
  have ht : h < total := by simpa [auth_length] using hh
  have he := auth_outside_get f seed layer tree kind kp total leaves idx h ht hlen hi
  rw [List.getD_eq_getElem _ _ hh] at he
  simpa only [List.getElem_replicate] using he

theorem sibling_xor (q : Nat) :
    q ^^^ 1 = if q % 2 = 0 then q+1 else q-1 := by
  split
  · rename_i h; exact Nat.xor_one_of_even (Nat.even_iff.mpr h)
  · rename_i h; exact Nat.xor_one_of_odd (Nat.odd_iff.mpr (by omega))

theorem sibling_int_nat_index (q : Nat) :
    Int.toNat (if Int.ofNat q % 2 = 0 then Int.ofNat q + 1 else Int.ofNat q - 1) =
      q ^^^ 1 := by
  have hm : Int.ofNat q % 2 = 0 ↔ q % 2 = 0 := by
    change (q:Int) % (2:Nat) = 0 ↔ _
    rw [← Int.natCast_emod]
    exact ⟨Int.ofNat.inj, congrArg Int.ofNat⟩
  rw [sibling_xor]
  simp only [hm]
  split
  · exact Int.toNat_add_nat (Int.natCast_nonneg q) 1
  · exact Int.toNat_sub q 1

theorem sibling_int_nat (idx h : Nat) :
    Int.toNat (if (Int.ofNat idx / (2^h : Int)) % 2 = 0
      then Int.ofNat idx / (2^h : Int) + 1 else Int.ofNat idx / (2^h : Int) - 1) =
      (idx / 2^h) ^^^ 1 := by
  have hd : Int.ofNat idx / (2^h : Int) = Int.ofNat (idx / 2^h) := by
    simp [Int.natCast_ediv]
  rw [hd, sibling_int_nat_index]

theorem sibling_nat_inside (q b : Nat) (hb : b % 2 = 0) (hq : q < b) : q ^^^ 1 < b := by
  rw [sibling_xor]
  split <;> omega

theorem sibling_nat_outside (q b : Nat) (hb : b % 2 = 0) (hq : b ≤ q) : b ≤ q ^^^ 1 := by
  rw [sibling_xor]
  split <;> omega

theorem sibling_nat_range (idx h total : Nat) (hh : h < total) (hi : idx < 2^total) :
    (idx / 2^h) ^^^ 1 < 2^(total-h) := by
  have hp : 2^(total-h)*2^h = (2^total : Nat) := by
    rw [← pow_add, Nat.sub_add_cancel (by omega : h ≤ total)]
  have hq : idx / 2^h < 2^(total-h) :=
    (Nat.div_lt_iff_lt_mul (by positivity : 0 < (2:Nat)^h)).2 (by rwa [hp])
  have hs : total-h = (total-h-1)+1 := by omega
  have hb : (2^(total-h) : Nat) % 2 = 0 := by rw [hs, pow_succ]; omega
  exact sibling_nat_inside _ _ hb hq

theorem auth_nat_node (f : List Int → List Int) seed layer tree kind kp total leaves idx h
    (hh : h < total) (hi : idx < 2^total) :
    (tree_auth_values f seed layer tree kind kp total leaves (Int.ofNat idx)).getD h
      (List.replicate 16 0) =
      recursiveNode f seed layer tree kind kp leaves h ((idx / 2^h) ^^^ 1) := by
  rw [auth_get f seed layer tree kind kp total leaves (Int.ofNat idx) h hh, sibling_int_nat,
    nodes_get_eq f seed layer tree kind kp total leaves h _ (by omega)
      (sibling_nat_range idx h total hh hi)]

/-- The full machine-width target's shifted sibling cannot wrap into the
    constructed tree. The upper bound justifies the actual shift's modulus. -/
theorem sibling_shift_outside (idx h total bits : Nat) (hh : h < total)
    (ht : total ≤ bits) (hlo : 2^total ≤ idx) (hhi : idx < 2^bits) :
    2^total ≤ ((idx / 2^h) ^^^ 1)*2^h ∧ ((idx / 2^h) ^^^ 1)*2^h < 2^bits := by
  have hp (n : Nat) (hn : h ≤ n) : 2^(n-h)*2^h = (2^n : Nat) := by
    rw [← pow_add, Nat.sub_add_cancel hn]
  have hq : 2^(total-h) ≤ idx / 2^h :=
    (Nat.le_div_iff_mul_le (by positivity : 0 < (2:Nat)^h)).2
      (by rwa [hp total (by omega)])
  have hs : total-h = (total-h-1)+1 := by omega
  have hb : (2^(total-h) : Nat) % 2 = 0 := by rw [hs, pow_succ]; omega
  constructor
  · have hl := Nat.mul_le_mul_right (2^h) (sibling_nat_outside _ _ hb hq)
    simpa only [hp total (by omega)] using hl
  · have hu := Nat.mul_lt_mul_of_pos_right
      (sibling_nat_range idx h bits (by omega) hhi) (by positivity : 0 < (2:Nat)^h)
    simpa only [hp bits (by omega)] using hu

end Extracted.C10FunctionalBuildValues
