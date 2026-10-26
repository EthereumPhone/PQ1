import Extracted.Sha256Portable.Model

open Aeneas Aeneas.Std Result
open SphincsCVerify.Spec.Sha256Impl
open sha256_portable

namespace Sha256Portable

set_option maxHeartbeats 2000000
set_option maxRecDepth 4096

def packABEF (s : Working) : Std.Array Std.U32 4#usize := pack4 s.a s.b s.e s.f
def packCDGH (s : Working) : Std.Array Std.U32 4#usize := pack4 s.c s.d s.g s.h

def packState (s : Working) : Std.Array Std.U32 8#usize :=
  Std.Array.make 8#usize [⟨s.a⟩, ⟨s.b⟩, ⟨s.c⟩, ⟨s.d⟩, ⟨s.e⟩, ⟨s.f⟩, ⟨s.g⟩, ⟨s.h⟩]

def toWords {n : Std.Usize} (a : Std.Array Std.U32 n) : _root_.Array Word :=
  (a.val.map (fun x => x.bv)).toArray

theorem toWords_size {n : Std.Usize} (a : Std.Array Std.U32 n) :
    (toWords a).size = n.val := by
  simp [toWords, a.property]

theorem toWords_packState (s : Working) : toWords (packState s) = s.toArray := by
  simp [toWords, packState, Std.Array.make, Working.toArray]

def wordGroup (block : _root_.Array Word) (t : Nat) : Std.Array Std.U32 4#usize :=
  pack4 (scheduledWord block (t + 3)) (scheduledWord block (t + 2))
    (scheduledWord block (t + 1)) (scheduledWord block t)

def constantGroup (t : Nat) : Std.Array Std.U32 4#usize :=
  pack4 (K.getD (t + 3) 0) (K.getD (t + 2) 0) (K.getD (t + 1) 0) (K.getD t 0)

theorem nextWord_scheduled (block : _root_.Array Word) (t : Nat) :
    nextWord (scheduledWord block t) (scheduledWord block (t + 1))
      (scheduledWord block (t + 9)) (scheduledWord block (t + 14)) =
      scheduledWord block (t + 16) := by
  have h0 : t + 16 - 16 = t := by omega
  have h1 : t + 16 - 15 = t + 1 := by omega
  have h9 : t + 16 - 7 = t + 9 := by omega
  have h14 : t + 16 - 2 = t + 14 := by omega
  simpa only [h0, h1, h9, h14] using (scheduledWord_next block (t + 16) (by omega)).symm

theorem schedule_group (block : _root_.Array Word) (t : Nat) :
    soft.schedule (wordGroup block t) (wordGroup block (t + 4))
      (wordGroup block (t + 8)) (wordGroup block (t + 12)) =
      ok (wordGroup block (t + 16)) := by
  simp only [wordGroup, schedule_eq, nextWord_scheduled]

theorem add_constants_eq (w0 w1 w2 w3 k0 k1 k2 k3 : Word) :
    soft.add (pack4 w3 w2 w1 w0) (pack4 k3 k2 k1 k0) =
      ok (pack4 (k3 + w3) (k2 + w2) (k1 + w1) (k0 + w0)) := by
  simp [add_eq, BitVec.add_comm]

theorem round2_packed (s : Working) (k0 w0 k1 w1 unused0 unused1 : Word) :
    soft.sha256_digest_round_x2 (packCDGH s) (packABEF s)
      (pack4 unused0 unused1 (k1 + w1) (k0 + w0)) =
      ok (packABEF (round (round s k0 w0) k1 w1)) :=
  round2_eq s k0 w0 k1 w1 unused0 unused1

theorem round2_cdgh (s : Working) (k0 w0 k1 w1 : Word) :
    packCDGH (round (round s k0 w0) k1 w1) = packABEF s := by rfl

/-- One unrolled four-round segment, with its entire continuation retained. -/
theorem round4_bind {α : Type} (s : Working) (w0 w1 w2 w3 k0 k1 k2 k3 : Word)
    (cont : Std.Array Std.U32 4#usize → Std.Array Std.U32 4#usize → Result α) :
    (do
      let t1 ← soft.add (pack4 w3 w2 w1 w0) (pack4 k3 k2 k1 k0)
      let cdgh ← soft.sha256_digest_round_x2 (packCDGH s) (packABEF s) t1
      let t2 ← soft.sha256swap t1
      let abef ← soft.sha256_digest_round_x2 (packABEF s) cdgh t2
      cont abef cdgh) =
    let s4 := round4 s k0 w0 k1 w1 k2 w2 k3 w3
    cont (packABEF s4) (packCDGH s4) := by
  simp only [add_constants_eq, bind_tc_ok, round2_packed, swap_eq]
  rw [← round2_cdgh s k0 w0 k1 w1, round2_packed]
  simp only [bind_tc_ok, round4, round2_cdgh]

theorem round4_group_bind {α : Type} (block : _root_.Array Word) (initial : Working)
    (t : Nat) (cont : Std.Array Std.U32 4#usize → Std.Array Std.U32 4#usize → Result α) :
    (do
      let t1 ← soft.add (wordGroup block t) (constantGroup t)
      let cdgh ← soft.sha256_digest_round_x2
        (packCDGH (rounds block initial t)) (packABEF (rounds block initial t)) t1
      let t2 ← soft.sha256swap t1
      let abef ← soft.sha256_digest_round_x2 (packABEF (rounds block initial t)) cdgh t2
      cont abef cdgh) =
    cont (packABEF (rounds block initial (t + 4)))
      (packCDGH (rounds block initial (t + 4))) := by
  simpa only [wordGroup, constantGroup, rounds_four] using
    round4_bind (rounds block initial t)
      (scheduledWord block t) (scheduledWord block (t + 1))
      (scheduledWord block (t + 2)) (scheduledWord block (t + 3))
      (K.getD t 0) (K.getD (t + 1) 0) (K.getD (t + 2) 0) (K.getD (t + 3) 0) cont

theorem index_block (block : Std.Array Std.U32 16#usize) (i : Std.Usize)
    (hi : i.val < 16) :
    Std.Array.index_usize block i =
      ok (⟨scheduledWord (toWords block) i.val⟩ : Std.U32) := by
  have hb : i.val < block.val.length := by simpa only [block.property] using hi
  simp only [Std.Array.index_usize, Std.Array.getElem?_Usize_eq, getElem?_pos block.val i.val hb]
  rw [scheduledWord_initial _ _ hi]
  simp [toWords, _root_.Array.getD, hi]

def constantGroups : Std.Array (Std.Array Std.U32 4#usize) 16#usize :=
  Std.Array.make 16#usize [constantGroup 0, constantGroup 4, constantGroup 8,
    constantGroup 12, constantGroup 16, constantGroup 20, constantGroup 24,
    constantGroup 28, constantGroup 32, constantGroup 36, constantGroup 40,
    constantGroup 44, constantGroup 48, constantGroup 52, constantGroup 56,
    constantGroup 60]

theorem constants_eq : consts.K32X4 = ok constantGroups := by
  unfold consts.K32X4 consts.K32 constantGroups constantGroup pack4 K
  rfl

theorem index_constants (i : Std.Usize) (hi : i.val < 16) :
    Std.Array.index_usize constantGroups i = ok (constantGroup (4 * i.val)) := by
  have hc : i.val = 0 ∨ i.val = 1 ∨ i.val = 2 ∨ i.val = 3 ∨ i.val = 4 ∨ i.val = 5 ∨ i.val = 6 ∨ i.val = 7 ∨ i.val = 8 ∨ i.val = 9 ∨ i.val = 10 ∨ i.val = 11 ∨ i.val = 12 ∨ i.val = 13 ∨ i.val = 14 ∨ i.val = 15 := by omega
  rcases hc with h | h | h | h | h | h | h | h | h | h | h | h | h | h | h | h <;>
    simp [constantGroups, Std.Array.index_usize, Std.Array.make, h]

theorem index_state (s : Working) (i : Std.Usize) (hi : i.val < 8) :
    Std.Array.index_usize (packState s) i =
      ok (⟨s.toArray.getD i.val 0⟩ : Std.U32) := by
  have hc : i.val = 0 ∨ i.val = 1 ∨ i.val = 2 ∨ i.val = 3 ∨ i.val = 4 ∨ i.val = 5 ∨ i.val = 6 ∨ i.val = 7 := by omega
  rcases hc with h | h | h | h | h | h | h | h <;>
    simp [packState, Working.toArray, Std.Array.index_usize, Std.Array.make, h]

def feedForward (initial done : Working) : Working :=
  { a := initial.a + done.a, b := initial.b + done.b,
    c := initial.c + done.c, d := initial.d + done.d,
    e := initial.e + done.e, f := initial.f + done.f,
    g := initial.g + done.g, h := initial.h + done.h }

theorem stateAdd_eq (initial done : Working) :
    stateAdd initial.toArray done.toArray = (feedForward initial done).toArray := by
  simp [stateAdd, stateAdd.go, Working.toArray, feedForward]

/-- The extracted final word reads and updates preserve the full feed-forward state. -/
theorem finish_state (initial done : Working) :
    (do
      let a17 ← Std.Array.index_usize (packABEF done) 0#usize
      let b ← Std.Array.index_usize (packABEF done) 1#usize
      let e ← Std.Array.index_usize (packABEF done) 2#usize
      let f ← Std.Array.index_usize (packABEF done) 3#usize
      let c ← Std.Array.index_usize (packCDGH done) 0#usize
      let d ← Std.Array.index_usize (packCDGH done) 1#usize
      let g ← Std.Array.index_usize (packCDGH done) 2#usize
      let h ← Std.Array.index_usize (packCDGH done) 3#usize
      let i24 ← lift (core.num.U32.wrapping_add (⟨initial.a⟩ : Std.U32) a17)
      let state1 ← Std.Array.update (packState initial) 0#usize i24
      let i25 ← Std.Array.index_usize state1 1#usize
      let i26 ← lift (core.num.U32.wrapping_add i25 b)
      let state2 ← Std.Array.update state1 1#usize i26
      let i27 ← Std.Array.index_usize state2 2#usize
      let i28 ← lift (core.num.U32.wrapping_add i27 c)
      let state3 ← Std.Array.update state2 2#usize i28
      let i29 ← Std.Array.index_usize state3 3#usize
      let i30 ← lift (core.num.U32.wrapping_add i29 d)
      let state4 ← Std.Array.update state3 3#usize i30
      let i31 ← Std.Array.index_usize state4 4#usize
      let i32 ← lift (core.num.U32.wrapping_add i31 e)
      let state5 ← Std.Array.update state4 4#usize i32
      let i33 ← Std.Array.index_usize state5 5#usize
      let i34 ← lift (core.num.U32.wrapping_add i33 f)
      let state6 ← Std.Array.update state5 5#usize i34
      let i35 ← Std.Array.index_usize state6 6#usize
      let i36 ← lift (core.num.U32.wrapping_add i35 g)
      let state7 ← Std.Array.update state6 6#usize i36
      let i37 ← Std.Array.index_usize state7 7#usize
      let i38 ← lift (core.num.U32.wrapping_add i37 h)
      Std.Array.update state7 7#usize i38
) = ok (packState (feedForward initial done)) := by
  rfl

/-- Total result of the actual unrolled word kernel, including all 64 rounds
    and all eight feed-forward additions. -/
theorem compression_packed (initial : Working) (block : Std.Array Std.U32 16#usize) :
    soft.sha256_digest_block_u32 (packState initial) block =
      ok (packState (feedForward initial (rounds (toWords block) initial 64))) := by
  unfold soft.sha256_digest_block_u32
  simp [index_state, index_block, constants_eq, index_constants, Working.toArray]
  erw [
    round4_group_bind (toWords block) initial 0,
    round4_group_bind (toWords block) initial 4,
    round4_group_bind (toWords block) initial 8,
    round4_group_bind (toWords block) initial 12
  ]
  erw [schedule_group (toWords block) 0]
  simp only [bind_tc_ok]
  erw [round4_group_bind (toWords block) initial 16]
  erw [schedule_group (toWords block) 4]
  simp only [bind_tc_ok]
  erw [round4_group_bind (toWords block) initial 20]
  erw [schedule_group (toWords block) 8]
  simp only [bind_tc_ok]
  erw [round4_group_bind (toWords block) initial 24]
  erw [schedule_group (toWords block) 12]
  simp only [bind_tc_ok]
  erw [round4_group_bind (toWords block) initial 28]
  erw [schedule_group (toWords block) 16]
  simp only [bind_tc_ok]
  erw [round4_group_bind (toWords block) initial 32]
  erw [schedule_group (toWords block) 20]
  simp only [bind_tc_ok]
  erw [round4_group_bind (toWords block) initial 36]
  erw [schedule_group (toWords block) 24]
  simp only [bind_tc_ok]
  erw [round4_group_bind (toWords block) initial 40]
  erw [schedule_group (toWords block) 28]
  simp only [bind_tc_ok]
  erw [round4_group_bind (toWords block) initial 44]
  erw [schedule_group (toWords block) 32]
  simp only [bind_tc_ok]
  erw [round4_group_bind (toWords block) initial 48]
  erw [schedule_group (toWords block) 36]
  simp only [bind_tc_ok]
  erw [round4_group_bind (toWords block) initial 52]
  erw [schedule_group (toWords block) 40]
  simp only [bind_tc_ok]
  erw [round4_group_bind (toWords block) initial 56]
  erw [schedule_group (toWords block) 44]
  simp only [bind_tc_ok]
  erw [round4_group_bind (toWords block) initial 60]
  exact finish_state initial (rounds (toWords block) initial 64)

theorem working_of_toArray (s : Working) : Working.ofArray s.toArray = s := by
  cases s
  rfl

theorem packState_unpack (state : Std.Array Std.U32 8#usize) :
    packState (Working.ofArray (toWords state)) = state := by
  have hs : state.val.length = 8 := by simpa using state.property
  apply Subtype.ext
  apply List.ext_getElem
  · simp [packState, Std.Array.make, hs]
  · intro i hi hi'
    have hi8 : i < 8 := by simpa only [hs] using hi'
    have hc : i = 0 ∨ i = 1 ∨ i = 2 ∨ i = 3 ∨ i = 4 ∨ i = 5 ∨ i = 6 ∨ i = 7 := by omega
    rcases hc with h | h | h | h | h | h | h | h <;>
      subst i <;>
      simp [packState, Working.ofArray, toWords, Std.Array.make, _root_.Array.getD, hs]

theorem compression_packed_spec (initial : Working) (block : Std.Array Std.U32 16#usize) :
    (do
      let result ← soft.sha256_digest_block_u32 (packState initial) block
      ok (toWords result)) =
    ok (compress (toWords (packState initial)) (toWords block)) := by
  have hb : (toWords block).size = 16 := by simpa using toWords_size block
  simp only [compression_packed, bind_tc_ok, toWords_packState, compress,
    working_of_toArray, runRounds_eq _ hb, stateAdd_eq]

/-- For every complete eight-word state and sixteen-word block, the actual
    portable RustCrypto word kernel terminates successfully and its full result
    equals the unchanged vendored SHA-256 compression specification. -/
theorem compression_spec (state : Std.Array Std.U32 8#usize)
    (block : Std.Array Std.U32 16#usize) :
    (do
      let result ← soft.sha256_digest_block_u32 state block
      ok (toWords result)) =
    ok (compress (toWords state) (toWords block)) := by
  simpa only [packState_unpack] using
    compression_packed_spec (Working.ofArray (toWords state)) block

end Sha256Portable
