import Extracted.Sha256Portable.ByteBlock

open Aeneas Aeneas.Std Result ControlFlow
open sha256_portable PQ1Research.MutableZip
open SphincsCVerify.Spec.Sha256Impl

namespace Sha256Portable.Bytes
set_option maxHeartbeats 2000000
set_option maxRecDepth 4096

abbrev HashState := Std.Array Std.U32 8#usize
abbrev BlockIter := core.slice.iter.Iter Block

def compressWordState (state : HashState) (words : Words) : HashState :=
  let initial := Working.ofArray (toWords state)
  packState (feedForward initial (rounds (toWords words) initial 64))

theorem word_compress_exact (state : HashState) (words : Words) :
    soft.sha256_digest_block_u32 state words = ok (compressWordState state words) := by
  simpa only [packState_unpack, compressWordState] using
    compression_packed (Working.ofArray (toWords state)) words

theorem outer_body_done (it : BlockIter) (words : Words) (state : HashState)
    (hi : it.slice.val.length ≤ it.i) :
    soft.compress_loop0.body it words state = ok (done state) := by
  simp [soft.compress_loop0.body, core.slice.iter.IteratorSliceIter.next,
    Nat.not_lt.mpr hi, bind_ok]

theorem outer_body_active (it : BlockIter) (words : Words) (state : HashState)
    (hi : it.i < it.slice.val.length) :
    soft.compress_loop0.body it words state =
      let decoded := blockWords words (it.slice[it.i]'hi)
      ok (cont ({ it with i := it.i + 1 }, decoded, compressWordState state decoded)) := by
  have hn : core.slice.iter.IteratorSliceIter.next it =
      ok (some (it.slice[it.i]'hi), { it with i := it.i + 1 }) := by
    simp [core.slice.iter.IteratorSliceIter.next, hi]
    rfl
  unfold soft.compress_loop0.body
  rw [hn]
  simp only [bind_tc_eq, bind_ok]
  simp only [lift, Std.Array.to_slice_mut, core.slice.Slice.iter_mut, bind_ok]
  change (do
    let ce ← core.slice.Slice.chunks_exact (it.slice[it.i]'hi).to_slice 4#usize
    let (zi, mkBack) ← make (iterMutWitness Std.U32)
      (core.iter.traits.collect.IntoIterator.Blanket (core.iter.traits.iterator.IteratorChunksExact Std.U8))
      ⟨words.to_slice, 0⟩ ce
    let (z, back) ← soft.compress_loop0_loop0 zi id
    let st ← soft.sha256_digest_block_u32 state (Std.Array.from_slice words (mkBack (back z)).slice)
    ok (cont ({ it with i := it.i + 1 }, Std.Array.from_slice words (mkBack (back z)).slice, st))) = _
  erw [chunks_exact_four]
  simp only [bind_tc_eq, bind_ok]
  erw [make_actual]
  simp only [bind_tc_eq, bind_ok]
  change (do
    let (z, back) ← soft.compress_loop0_loop0 (blockState words (it.slice[it.i]'hi)) id
    let st ← soft.sha256_digest_block_u32 state (Std.Array.from_slice words (back z).fst.slice)
    ok (cont ({ it with i := it.i + 1 }, Std.Array.from_slice words (back z).fst.slice, st))) = _
  rw [inner_loop_spec _ _ (blockState_valid _ _) (blockState_four _ _)]
  simp only [bind_tc_eq, bind_ok, id_eq]
  change (do
    let st ← soft.sha256_digest_block_u32 state (blockWords words (it.slice[it.i]'hi))
    ok (cont ({ it with i := it.i + 1 }, blockWords words (it.slice[it.i]'hi), st))) = _
  rw [word_compress_exact]
  simp only [bind_tc_eq, bind_ok]

theorem word_compress_spec (state : HashState) (words : Words) :
    toWords (compressWordState state words) = compress (toWords state) (toWords words) := by
  apply Result.ok_injective
  simpa only [word_compress_exact, bind_ok] using compression_spec state words

theorem outer_loop_done (it : BlockIter) (words : Words) (state : HashState)
    (hi : it.slice.val.length ≤ it.i) :
    soft.compress_loop0 it words state = ok state := by
  rw [soft.compress_loop0, loop]
  dsimp only
  rw [outer_body_done _ _ _ hi, bind_ok]

theorem outer_loop_step (it : BlockIter) (words : Words) (state : HashState)
    (hi : it.i < it.slice.val.length) :
    soft.compress_loop0 it words state =
      let decoded := blockWords words (it.slice[it.i]'hi)
      soft.compress_loop0 { it with i := it.i + 1 } decoded (compressWordState state decoded) := by
  rw [soft.compress_loop0, loop]
  dsimp only
  rw [outer_body_active _ _ _ hi, bind_ok]
  rfl

def foldBlocks (blocks : List Block) (state : _root_.Array Word) : _root_.Array Word :=
  blocks.foldl (fun st block => compress st (bytesToWords (sliceBytes block.to_slice))) state

/-- Every remaining block is processed in order. The theorem covers every
    starting state, scratch buffer and cursor, including empty input. -/
theorem outer_loop_spec (it : BlockIter) (words : Words) (state : HashState) :
    (do let st ← soft.compress_loop0 it words state; ok (toWords st)) =
      ok (foldBlocks (it.slice.val.drop it.i) (toWords state)) := by
  by_cases hi : it.i < it.slice.val.length
  · rw [outer_loop_step _ _ _ hi]
    rw [outer_loop_spec]
    congr 1
    rw [List.drop_eq_getElem_cons hi]
    simp only [foldBlocks, List.foldl_cons, word_compress_spec, blockWords_spec]
    rfl
  · rw [outer_loop_done _ _ _ (by omega), bind_ok]
    have he : it.slice.val.drop it.i = [] := List.drop_eq_nil_of_le (by omega)
    rw [he]
    rfl
termination_by it.slice.val.length - it.i

/-- Complete original portable byte/block compression: arbitrary eight-word
    state and arbitrary bounded slice of complete 64-byte blocks, with no
    desired-output or termination premise. The standard SHA word specification
    and standard byte conversion are unchanged. -/
theorem original_compress_spec (state : HashState) (blocks : Slice Block) :
    (do let st ← soft.compress state blocks; ok (toWords st)) =
      ok (foldBlocks blocks.val (toWords state)) := by
  unfold soft.compress
  simp only [SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter, bind_ok]
  rw [outer_loop_spec]
  rfl

end Sha256Portable.Bytes
