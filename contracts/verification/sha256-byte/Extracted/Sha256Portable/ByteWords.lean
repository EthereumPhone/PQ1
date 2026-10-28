import Extracted.Sha256Portable.ByteDecode

open Aeneas Aeneas.Std Result
open SphincsCVerify.Spec.Sha256Impl

namespace Sha256Portable.Bytes
set_option maxHeartbeats 2000000
set_option maxRecDepth 4096

def wordAt (bytes : _root_.Array UInt8) (i : Nat) : Word :=
  bytesToWordBE (bytes.getD (4 * i) 0) (bytes.getD (4 * i + 1) 0)
    (bytes.getD (4 * i + 2) 0) (bytes.getD (4 * i + 3) 0)

theorem bytesToWords_go_eq (bytes : _root_.Array UInt8) (n i : Nat)
    (acc : _root_.Array Word) :
    bytesToWords.go bytes n i acc =
      (acc.toList ++ (List.range' i (n-i)).map (wordAt bytes)).toArray := by
  rw [bytesToWords.go]
  split
  · have hzero : n-i = 0 := by omega
    simp only [hzero, List.range'_zero, List.map_nil, List.append_nil, Array.toArray_toList]
  · rw [bytesToWords_go_eq bytes n (i+1)]
    have hlen : n-i = (n-(i+1))+1 := by omega
    rw [hlen, List.range'_succ]
    simp [wordAt, List.append_assoc]
termination_by n-i

theorem bytesToWords_eq (bytes : _root_.Array UInt8) :
    bytesToWords bytes = ((List.range' 0 (bytes.size / 4)).map (wordAt bytes)).toArray := by
  unfold bytesToWords
  rw [bytesToWords_go_eq]
  simp

theorem bytesToWords_size (bytes : _root_.Array UInt8) :
    (bytesToWords bytes).size = bytes.size / 4 := by
  simp [bytesToWords_eq]

theorem bytesToWords_get (bytes : _root_.Array UInt8) (j : Nat)
    (hj : j < (bytesToWords bytes).size) :
    (bytesToWords bytes)[j] = wordAt bytes j := by
  simp only [bytesToWords_eq, List.getElem_toArray, List.getElem_map, List.getElem_range',
    Nat.one_mul, Nat.zero_add]

def sliceBytes (s : Slice Std.U8) : _root_.Array UInt8 :=
  (s.val.map toByte).toArray

theorem sliceBytes_size (s : Slice Std.U8) : (sliceBytes s).size = s.length := by
  simp [sliceBytes]

theorem sliceBytes_getD (s : Slice Std.U8) (i : Nat) (hi : i < s.length) :
    (sliceBytes s).getD i 0 = toByte s.val[i]! := by
  simp [sliceBytes, Array.getD, List.getElem!_eq_getElem?_getD, hi]

theorem splitFour_byte (s : Slice Std.U8) (j : Nat)
    (hj : j < (splitFour s).chunks.length) (k : Nat) (hk : k < 4) :
    ((splitFour s).chunks[j]'hj).val[k]! = s.val[4*j+k]! := by
  rw [splitFour_chunk_val, List.getElem!_take_of_lt _ _ _ hk, List.getElem!_drop]

theorem splitFour_decode (s : Slice Std.U8) (j : Nat)
    (hj : j < (splitFour s).chunks.length) :
    (decodeChunk ((splitFour s).chunks[j]'hj) (splitFour_chunk_length s j hj)).bv =
      wordAt (sliceBytes s) j := by
  have hjb : j < s.length / 4 := by simpa only [splitFour_count] using hj
  rw [decodeChunk_spec]
  simp only [splitFour_byte s j hj 0 (by decide), splitFour_byte s j hj 1 (by decide),
    splitFour_byte s j hj 2 (by decide), splitFour_byte s j hj 3 (by decide), wordAt]
  rw [sliceBytes_getD s (4*j) (by omega), sliceBytes_getD s (4*j+1) (by omega),
    sliceBytes_getD s (4*j+2) (by omega), sliceBytes_getD s (4*j+3) (by omega)]
  rfl

end Sha256Portable.Bytes
