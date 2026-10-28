import Extracted.Sha256Portable.Compression

open Aeneas Aeneas.Std Result ControlFlow
open sha256_portable PQ1Research.MutableZip

namespace Sha256Portable.Bytes

set_option maxHeartbeats 2000000
set_option maxRecDepth 4096

abbrev ByteState := PQ1Research.MutableZip.State Std.U32 Std.U8

def decodeChunk (chunk : Slice Std.U8) (h : chunk.length = 4) : Std.U32 :=
  core.num.U32.from_be_bytes (Std.Array.from chunk.val (by simpa using h))

theorem decodeChunk_result (chunk : Slice Std.U8) (h : chunk.length = 4) :
    (do
      let r ← core.array.TryFromArrayCopySlice.try_from 4#usize core.marker.CopyU8 chunk
      let a ← core.result.Result.unwrap core.fmt.DebugTryFromSliceError r
      lift (core.num.U32.from_be_bytes a)) = ok (decodeChunk chunk h) := by
  simp [core.array.TryFromArrayCopySlice.try_from, h,
    core.result.Result.unwrap, lift, decodeChunk, bind_ok]

theorem inner_body_done (z : ByteState) (back : ByteState → ByteState)
    (h : z.len ≤ z.index) :
    soft.compress_loop0_loop0.body z back = ok (done (z, back)) := by
  simp [soft.compress_loop0_loop0.body, next_exhausted _ _ z h, bind_ok]

theorem inner_loop_done (z : ByteState) (back : ByteState → ByteState)
    (h : z.len ≤ z.index) :
    soft.compress_loop0_loop0 z back = ok (z, back) := by
  unfold soft.compress_loop0_loop0 loop
  simp [inner_body_done z back h, bind_ok]

theorem inner_body_active (z : ByteState) (back : ByteState → ByteState)
    (hv : valid z) (hi : z.index < z.len)
    (hc : (z.snd.chunks[z.index]'(next_in_bounds z hv hi).2).length = 4) :
    soft.compress_loop0_loop0.body z back =
      let chunk := z.snd.chunks[z.index]'(next_in_bounds z hv hi).2
      ok (cont ({ z with index := z.index + 1 },
        fun future => back (putBack (z.fst.i + z.index) future
          (some (decodeChunk chunk hc, chunk))))) := by
  unfold soft.compress_loop0_loop0.body
  rw [next_active _ _ z hv hi]
  simp [core.array.TryFromArrayCopySlice.try_from, hc,
    core.result.Result.unwrap, lift, decodeChunk, bind_ok]

/-- Every chunk presented by this loop is exactly one four-byte word. -/
abbrev FourByteChunks (z : ByteState) : Prop :=
  ∀ i (hi : i < z.snd.chunks.length), (z.snd.chunks[i]'hi).length = 4

/-- The deferred writes, in the same order as the original mutable-borrow
    continuation. This total definition supplies a termination witness. -/
def writeBack (z : ByteState) (hv : valid z) (hc : FourByteChunks z)
    (future : ByteState) : ByteState :=
  if hi : z.index < z.len then
    let chunk := z.snd.chunks[z.index]'(next_in_bounds z hv hi).2
    putBack (z.fst.i + z.index)
      (writeBack { z with index := z.index + 1 }
        (next_preserves_valid z hv hi) hc future)
      (some (decodeChunk chunk (hc _ _), chunk))
  else future
termination_by z.len - z.index

/-- Exact total result of the unmodified generated inner loop, including its
    backward function, for every valid cursor and every four-byte chunk list. -/
theorem inner_loop_spec (z : ByteState) (back : ByteState → ByteState)
    (hv : valid z) (hc : FourByteChunks z) :
    soft.compress_loop0_loop0 z back =
      ok ({ z with index := z.len }, fun future => back (writeBack z hv hc future)) := by
  by_cases hi : z.index < z.len
  · unfold soft.compress_loop0_loop0
    rw [loop]
    dsimp only
    rw [inner_body_active z back hv hi (hc _ _)]
    simp only [bind_ok]
    change soft.compress_loop0_loop0 { z with index := z.index + 1 }
      (fun future => back (putBack (z.fst.i + z.index) future
        (some (decodeChunk _ (hc _ _), _)))) = _
    rw [inner_loop_spec _ _ (next_preserves_valid z hv hi) hc]
    congr 1
    apply Prod.ext
    · rfl
    · funext future
      dsimp only
      congr 1
      conv_rhs => rw [writeBack]
      simp only [dite_eq_left hi]
  · rw [inner_loop_done z back (by omega)]
    have he : z.index = z.len := by have := hv.2.2; omega
    conv_rhs => arg 1; arg 2; ext future; arg 1; rw [writeBack]
    simp only [dite_eq_right hi]
    cases z
    simp_all
termination_by z.len - z.index

theorem writeBack_length (z : ByteState) (hv : valid z) (hc : FourByteChunks z)
    (future : ByteState) :
    (writeBack z hv hc future).fst.slice.length = future.fst.slice.length := by
  rw [writeBack]
  split
  · rw [putBack_length]
    exact writeBack_length _ (next_preserves_valid z hv ‹_›) hc future
  · rfl
termination_by z.len - z.index

theorem writeBack_frame (z : ByteState) (hv : valid z) (hc : FourByteChunks z)
    (future : ByteState) :
    (writeBack z hv hc future).snd = future.snd ∧
    (writeBack z hv hc future).index = future.index ∧
    (writeBack z hv hc future).len = future.len ∧
    (writeBack z hv hc future).fst.i = future.fst.i := by
  rw [writeBack]
  split
  · simpa only [putBack] using
      writeBack_frame _ (next_preserves_valid z hv ‹_›) hc future
  · exact ⟨rfl, rfl, rfl, rfl⟩
termination_by z.len - z.index

/-- Each remaining output position receives its corresponding decoded chunk,
    independently of the previous array contents and of the later writes. -/
theorem writeBack_value (z : ByteState) (hv : valid z) (hc : FourByteChunks z)
    (future : ByteState) (j : Nat) (hj0 : z.index ≤ j) (hj1 : j < z.len)
    (hf : z.fst.i + j < future.fst.slice.length) :
    (writeBack z hv hc future).fst.slice.val[z.fst.i + j]! =
      decodeChunk (z.snd.chunks[j]'(by have := hv.2.1; omega)) (hc _ _) := by
  have hi : z.index < z.len := by omega
  rw [writeBack, dite_eq_left hi]
  dsimp only
  by_cases he : z.index = j
  · subst j
    apply putBack_value
    rw [writeBack_length]
    exact hf
  · rw [putBack_other _ _ _ _ _ (by omega)]
    exact writeBack_value _ (next_preserves_valid z hv hi) hc future j (by dsimp only; omega) hj1 hf
termination_by z.len - z.index

/-- Positions outside the interval touched by this loop retain their values. -/
theorem writeBack_other (z : ByteState) (hv : valid z) (hc : FourByteChunks z)
    (future : ByteState) (q : Nat)
    (hq : q < z.fst.i + z.index ∨ z.fst.i + z.len ≤ q) :
    (writeBack z hv hc future).fst.slice.val[q]! = future.fst.slice.val[q]! := by
  rw [writeBack]
  split
  · rw [putBack_other _ _ _ _ _ (by omega)]
    exact writeBack_other _ (next_preserves_valid z hv ‹_›) hc future q (by
      dsimp only; omega)
  · rfl
termination_by z.len - z.index

end Sha256Portable.Bytes
