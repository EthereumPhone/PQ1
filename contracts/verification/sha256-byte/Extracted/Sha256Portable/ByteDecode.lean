import Extracted.Sha256Portable.ByteLoop

open Aeneas Aeneas.Std Result
open sha256_portable PQ1Research.MutableZip

namespace Sha256Portable.Bytes
set_option maxHeartbeats 2000000
set_option maxRecDepth 4096

theorem chunks_four_length (l : List α) :
    ∀ c ∈ (List.toChunksExact 4 (by decide) l).1, c.length = 4 := by
  rw [List.toChunksExact]
  split
  · simp
  · simp only [List.mem_cons]
    intro c hc
    rcases hc with rfl | hc
    · simp only [List.length_take]
      omega
    · exact chunks_four_length (l.drop 4) c hc
termination_by l.length
decreasing_by simp only [List.length_drop]; omega

theorem chunks_four_count (l : List α) :
    (List.toChunksExact 4 (by decide) l).1.length = l.length / 4 := by
  rw [List.toChunksExact]
  split
  · simp only [List.length_nil]
    omega
  · simp only [List.length_cons]
    rw [chunks_four_count]
    simp only [List.length_drop]
    omega
termination_by l.length
decreasing_by simp only [List.length_drop]; omega

theorem chunks_four_get (l : List α) (j : Nat)
    (hj : j < (List.toChunksExact 4 (by decide) l).1.length) :
    (List.toChunksExact 4 (by decide) l).1[j] = (l.drop (4 * j)).take 4 := by
  by_cases hl : l.length < 4
  · have := chunks_four_count l
    omega
  · have he : (List.toChunksExact 4 (by decide) l).1 =
        l.take 4 :: (List.toChunksExact 4 (by decide) (l.drop 4)).1 := by
      rw [List.toChunksExact]
      simp only [dite_eq_right hl]
    simp only [he, List.length_cons] at hj
    cases j with
    | zero => simp only [he, List.getElem_cons_zero, Nat.mul_zero, List.drop_zero]
    | succ j =>
      simp only [he, List.getElem_cons_succ]
      rw [chunks_four_get (l.drop 4) j (by omega)]
      simp only [List.drop_drop]
      congr 2
      omega
termination_by l.length
decreasing_by simp only [List.length_drop]; omega

/-- Concrete value returned by the existing four-byte chunk iterator model. -/
def splitFour (s : Slice Std.U8) : core.slice.iter.ChunksExact Std.U8 :=
  let result := List.toChunksExact 4 (by decide) s.val
  { chunks := result.1.attach.map fun ⟨c, hc⟩ => .from c (by
      have := chunks_four_length s.val c hc
      scalar_tac)
    remainder := .from result.2 (by
      have := List.toChunksExact_remainder_length (by decide : 0 < 4) s.val
      have := s.property
      dsimp only [result]
      omega) }

theorem chunks_exact_four (s : Slice Std.U8) :
    core.slice.Slice.chunks_exact s 4#usize = ok (splitFour s) := by
  simp only [core.slice.Slice.chunks_exact, splitFour]
  rfl

theorem splitFour_count (s : Slice Std.U8) :
    (splitFour s).chunks.length = s.length / 4 := by
  simpa [splitFour] using chunks_four_count s.val

theorem splitFour_chunk_length (s : Slice Std.U8) (j : Nat)
    (hj : j < (splitFour s).chunks.length) :
    ((splitFour s).chunks[j]'hj).length = 4 := by
  simp only [splitFour, List.getElem_map, List.getElem_attach, Slice.length,
    Slice.from_val]
  apply chunks_four_length
  apply List.getElem_mem

theorem splitFour_chunk_val (s : Slice Std.U8) (j : Nat)
    (hj : j < (splitFour s).chunks.length) :
    ((splitFour s).chunks[j]'hj).val = (s.val.drop (4 * j)).take 4 := by
  simp only [splitFour, List.getElem_map, List.getElem_attach, Slice.from_val]
  apply chunks_four_get

def toByte (b : Std.U8) : UInt8 := UInt8.ofBitVec b.bv

open SphincsCVerify.Spec.Sha256Impl

theorem fromBE_four (a b c d : BitVec 8) :
    (BitVec.fromBEBytes [a, b, c, d]).cast (by simp) =
      bytesToWordBE (UInt8.ofBitVec a) (UInt8.ofBitVec b)
        (UInt8.ofBitVec c) (UInt8.ofBitVec d) := by
  change (BitVec.fromLEBytes [d, c, b, a]).cast (by simp) = _
  apply BitVec.eq_of_getLsbD_eq
  intro i hi
  have hcases : i = 0 ∨ i = 1 ∨ i = 2 ∨ i = 3 ∨ i = 4 ∨ i = 5 ∨ i = 6 ∨ i = 7 ∨ i = 8 ∨ i = 9 ∨ i = 10 ∨ i = 11 ∨ i = 12 ∨ i = 13 ∨ i = 14 ∨ i = 15 ∨ i = 16 ∨ i = 17 ∨ i = 18 ∨ i = 19 ∨ i = 20 ∨ i = 21 ∨ i = 22 ∨ i = 23 ∨ i = 24 ∨ i = 25 ∨ i = 26 ∨ i = 27 ∨ i = 28 ∨ i = 29 ∨ i = 30 ∨ i = 31 := by omega
  rcases hcases with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
  all_goals
    simp [BitVec.fromLEBytes, bytesToWordBE, u8ToWord]

theorem decodeChunk_spec (chunk : Slice Std.U8) (h : chunk.length = 4) :
    (decodeChunk chunk h).bv = bytesToWordBE
      (toByte chunk.val[0]!) (toByte chunk.val[1]!)
      (toByte chunk.val[2]!) (toByte chunk.val[3]!) := by
  have hlen : chunk.val.length = 4 := h
  have hex : ∃ a b c d, chunk.val = [a, b, c, d] := by
    exact ⟨_, _, _, _, List.eq_getElem_of_length_eq_four chunk.val hlen⟩
  rcases hex with ⟨a, b, c, d, he⟩
  have ha : (Std.Array.from chunk.val (by simpa using h) : Std.Array Std.U8 4#usize) =
      Std.Array.from [a, b, c, d] (by rfl) := by
    apply Std.Array.ext
    simpa only [Std.Array.from_val] using he
  unfold decodeChunk
  rw [ha]
  simp only [he, List.getElem!_eq_getElem?_getD, List.getElem?_cons_zero,
    List.getElem?_cons_succ, Option.getD_some, toByte]
  exact fromBE_four a.bv b.bv c.bv d.bv

end Sha256Portable.Bytes
