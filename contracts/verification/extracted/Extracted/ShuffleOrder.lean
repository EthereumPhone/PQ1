/- Positional consequences of the actual shuffle theorem, used by signing. -/
import Extracted.ShuffleSpec
open Aeneas Aeneas.Std Result
namespace Extracted.Equiv

theorem shuffleByte_val (j : Nat) (hj : j < 256) : (shuffleByte j).val = j := by
  change j % 256 = j
  exact Nat.mod_eq_of_lt hj

theorem shuffle_order_bound (n : Nat) (a : Std.Array Std.U8 64#usize)
    (hn : n ≤ 64) (hp : shufflePermutation n a) (i : Nat) (hi : i < n) :
    (a.val[i]!).val < n := by
  have hlen : a.val.length = 64 := by simpa using a.property
  have hit : i < (a.val.take n).length := by simp [List.length_take, hlen]; omega
  have hm : a.val[i]! ∈ a.val.take n := by
    have h := List.getElem_mem hit
    rw [List.getElem_take] at h
    rwa [getElem!_pos a.val i (by omega)]
  obtain ⟨j, hj, he⟩ := List.mem_map.mp (hp.1.mem_iff.mp hm)
  have hjn := List.mem_range.mp hj
  rw [← he, shuffleByte_val j (by omega)]
  exact hjn

theorem shuffle_order_covers (n : Nat) (a : Std.Array Std.U8 64#usize)
    (hn : n ≤ 64) (hp : shufflePermutation n a) (j : Nat) (hj : j < n) :
    ∃ i, i < n ∧ (a.val[i]!).val = j := by
  have hm : shuffleByte j ∈ a.val.take n :=
    hp.1.mem_iff.mpr (List.mem_map.mpr ⟨j, List.mem_range.mpr hj, rfl⟩)
  obtain ⟨i, hi, he⟩ := List.getElem_of_mem hm
  have hlen : a.val.length = 64 := by simpa using a.property
  have hin : i < n := by simpa [List.length_take, hlen, hn] using hi
  refine ⟨i, hin, ?_⟩
  rw [List.getElem_take] at he
  rw [getElem!_pos a.val i (by omega), he, shuffleByte_val j (by omega)]
end Extracted.Equiv
