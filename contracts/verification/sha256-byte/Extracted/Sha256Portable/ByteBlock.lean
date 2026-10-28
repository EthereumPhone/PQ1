import Extracted.Sha256Portable.ByteWords

open Aeneas Aeneas.Std Result ControlFlow
open sha256_portable PQ1Research.MutableZip
open SphincsCVerify.Spec.Sha256Impl

namespace Sha256Portable.Bytes
set_option maxHeartbeats 2000000
set_option maxRecDepth 4096

abbrev Words := Std.Array Std.U32 16#usize
abbrev Block := Std.Array Std.U8 64#usize

def blockState (words : Words) (block : Block) : ByteState :=
  ⟨⟨words.to_slice, 0⟩, splitFour block.to_slice, 0,
    min (words.to_slice.length - 0) (splitFour block.to_slice).chunks.length⟩

theorem blockState_valid (words : Words) (block : Block) : valid (blockState words block) := by
  exact make_state_valid _ _ (Nat.zero_le _)

theorem blockState_four (words : Words) (block : Block) : FourByteChunks (blockState words block) := by
  intro i hi
  exact splitFour_chunk_length block.to_slice i hi

theorem blockState_len (words : Words) (block : Block) : (blockState words block).len = 16 := by
  simp [blockState, splitFour_count]

def completedState (words : Words) (block : Block) : ByteState :=
  { blockState words block with index := (blockState words block).len }

def blockWords (words : Words) (block : Block) : Words :=
  Std.Array.from_slice words
    (writeBack (blockState words block) (blockState_valid words block)
      (blockState_four words block) (completedState words block)).fst.slice

theorem blockWords_val (words : Words) (block : Block) :
    (blockWords words block).val =
      (writeBack (blockState words block) (blockState_valid words block)
        (blockState_four words block) (completedState words block)).fst.slice.val := by
  unfold blockWords
  apply Std.Array.from_slice_val
  change (writeBack _ _ _ _).fst.slice.length = _
  rw [writeBack_length]
  simp [completedState, blockState]

theorem blockWords_get (words : Words) (block : Block) (j : Nat) (hj : j < 16) :
    (blockWords words block).val[j]!.bv = wordAt (sliceBytes block.to_slice) j := by
  rw [blockWords_val]
  have hv := writeBack_value (blockState words block) (blockState_valid words block)
    (blockState_four words block) (completedState words block) j (Nat.zero_le _)
    (by simpa only [blockState_len] using hj)
    (by simpa [blockState, completedState] using hj)
  have hjc : j < (splitFour block.to_slice).chunks.length := by
    simpa [splitFour_count] using hj
  trans (decodeChunk ((splitFour block.to_slice).chunks[j]'hjc)
    (splitFour_chunk_length block.to_slice j hjc)).bv
  · simpa only [blockState, Nat.zero_add] using congrArg Std.U32.bv hv
  · exact splitFour_decode block.to_slice j hjc

/-- The exact backward function from the original inner loop overwrites all
    sixteen words with the unchanged standard byte-to-word conversion. -/
theorem blockWords_spec (words : Words) (block : Block) :
    toWords (blockWords words block) = bytesToWords (sliceBytes block.to_slice) := by
  apply _root_.Array.ext
  · simp [toWords_size, bytesToWords_size, sliceBytes_size]
  · intro j hj hj'
    rw [bytesToWords_get]
    have hj16 : j < 16 := by simpa [toWords_size] using hj
    simpa [toWords, List.getElem!_eq_getElem?_getD, hj16,
      (blockWords words block).property] using blockWords_get words block j hj16

end Sha256Portable.Bytes
