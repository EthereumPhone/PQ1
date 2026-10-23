/- §33 axiom-collapse — `hash.chain_hash` spec: the extracted loop over `th`'s
   96-byte preimage (`chain_buf` = seed ‖ adrs ‖ pad16 val, built once; each
   step writes the chain position at bytes [56..60) — ADRS bytes [24..28) —
   hashes the buffer with `sha256_bytes`, and writes the digest's first N bytes
   back as the value at [64..80); `chain_value` reads it out) computes exactly
   `chain_hash_pure`'s fold, for `start + steps ≤ u32::MAX` (the per-step
   `start_pos + step` would panic past that; the WOTS+C caller passes
   start = digit ≤ 7, steps = 7 − digit). -/
import Extracted.HashSpecs.Th
import Extracted.HashSpecs.WotsDigest

set_option linter.unusedSimpArgs false
set_option linter.unusedTactic false
set_option maxHeartbeats 8000000

open Aeneas Aeneas.Std Result
open Extracted.SetSlice

namespace sphincs_c10

/-- `Range<u32>` iterator step — clone of `Extracted.Equiv.next_usize_spec`
    for the extraction-local `U32.Insts.CoreIterRangeStep` instance. -/
theorem next_u32_spec (it : core.ops.range.Range Std.U32) :
    core.iter.range.IteratorRange.next U32.Insts.CoreIterRangeStep it
      ⦃ r => (r.1 = none ∧ it.«end».val ≤ it.start.val) ∨
             (∃ b it', r = (some b, it') ∧ b = it.start ∧ it.start.val < it.«end».val ∧
                it'.«end» = it.«end» ∧ it'.start.val = it.start.val + 1) ⦄ := by
  unfold core.iter.range.IteratorRange.next
  simp only [U32.Insts.CoreIterRangeStep, core.cmp.PartialOrdU32,
             core.clone.CloneU32, U32.Insts.CoreIterRangeStep.forward_checked,
             core.clone.impls.CloneU32.clone, core.cmp.impls.PartialOrdU32.lt,
             liftFun1, liftFun2, bind_tc_ok]
  have hb : it.«end».val ≤ U32.max := by scalar_tac
  have h1v : (1#usize).val = 1 := by scalar_tac
  split
  · rename_i hlt
    simp only [decide_eq_true_eq] at hlt
    have hfits : it.start.val + (1#usize).val ≤ U32.max := by
      rw [h1v]; omega
    split
    · -- forward_checked = none: contradicts hfits
      rename_i hnone
      rw [if_pos hfits] at hnone
      simp at hnone
    · rename_i n hsome
      rw [if_pos hfits] at hsome
      injection hsome with hn
      simp only [WP.spec_ok]
      right
      refine ⟨it.start, _, rfl, rfl, by scalar_tac, rfl, ?_⟩
      show n.val = it.start.val + 1
      rw [← hn]
      show (BitVec.ofNat 32 (it.start.val + (1#usize).val)).toNat = it.start.val + 1
      rw [BitVec.toNat_ofNat, h1v]
      exact Nat.mod_eq_of_lt (by scalar_tac)
  · rename_i hge
    simp only [decide_eq_true_eq] at hge
    simp only [WP.spec_ok]
    left
    refine ⟨?_, ?_⟩ <;> first | trivial | rfl | scalar_tac

/-- Local (non-`@[step]`) pad16 spec against `pad16Pure` — applied
    explicitly so it cannot race the `pad16p`-valued `@[step] pad16_spec`
    in `MerkleVerifySpec.lean`. -/
theorem pad16_pure_spec (v : Std.Array Std.U8 16#usize) :
    hash.pad16 v ⦃ r => r = pad16Pure v ⦄ := by
  have hv : v.val.length = 16 := by have := v.property; simp_all
  unfold hash.pad16
  step* <;>
    first
    | scalar_tac
    | (simp only [params.N, Slice.length, Array.length_to_slice]; scalar_tac)
    | (simp only [params.N, Slice.length, Array.length_to_slice] at *; scalar_tac)
    | skip
  apply Subtype.ext
  rw [pad16Pure_val]
  have h := setSlice!_append_replicate ([] : List Std.U8) 32 v.val 0#u8
    (by rw [hv]; omega)
  simp only [List.nil_append, List.length_nil, hv] at h
  simp_all [params.N]

/-- `setSlice!` of 4 bytes at offset 24 in a 32-byte list, decomposed. -/
theorem setSlice24 (l w : List Std.U8) (hl : l.length = 32) (hw : w.length = 4) :
    l.setSlice! 24 w = l.take 24 ++ w ++ l.drop 28 := by
  apply List.ext_getElem!
  · simp [List.length_setSlice!, hl, hw]
  intro j
  by_cases h0 : j < 24
  · simp_lists [*]
  by_cases h1 : j < 28
  · simp_lists [*] <;> simp [Nat.min_def]
  by_cases h2 : j < 32
  · simp_lists [*]
    have hlw : (List.take 24 l ++ w).length = 28 := by simp [hl, hw]
    simp only [hlw]
    congr 1
    omega
  · simp_lists [*]

/-- `u32beBytes` is 4 bytes long. -/
theorem u32beBytes_length (n : Nat) : (u32beBytes n).length = 4 := by
  simp [u32beBytes]

/-- `chainAdrs` preserves the first 24 bytes. -/
theorem chainAdrs_take24 (adrs : Std.Array Std.U8 32#usize) (p : Nat) :
    (chainAdrs adrs p).val.take 24 = adrs.val.take 24 := by
  have h : adrs.val.length = 32 := by have := adrs.property; simp_all
  have h24 : (adrs.val.take 24).length = 24 := by simp [h]
  rw [chainAdrs_val, List.append_assoc, List.take_left' h24]

/-- `chainAdrs` preserves the last 4 bytes. -/
theorem chainAdrs_drop28 (adrs : Std.Array Std.U8 32#usize) (p : Nat) :
    (chainAdrs adrs p).val.drop 28 = adrs.val.drop 28 := by
  have h : adrs.val.length = 32 := by have := adrs.property; simp_all
  have h28 : (adrs.val.take 24 ++ u32beBytes p).length = 28 := by
    simp [h, u32beBytes_length]
  rw [chainAdrs_val, List.drop_left' h28]

set_option maxRecDepth 16384 in
/-- The hoisted 96-byte chain buffer as `chain_hash` builds it: seed at 0,
    ADRS at 32, the 16-byte value at 64, over a fresh zero buffer. -/
theorem chainBuf_init (a b c : List Std.U8) (ha : a.length = 32)
    (hb : b.length = 32) (hc : c.length = 16) :
    (((List.replicate 96 0#u8).setSlice! 0 a).setSlice! 32 b).setSlice! 64 c
      = a ++ b ++ (c ++ List.replicate 16 0#u8) := by
  apply List.ext_getElem!
  · simp [List.length_setSlice!, List.length_append, List.length_replicate, *]
  intro j
  by_cases h0 : j < 32
  · simp_lists [List.length_replicate, List.length_append, *]
  by_cases h1 : j < 64
  · simp_lists [List.length_replicate, List.length_append, *]
  by_cases h2 : j < 80
  · simp_lists [List.length_replicate, List.length_append, *]
  by_cases h3 : j < 96
  · simp_lists [List.length_replicate, List.length_append, *]
  · simp_lists [List.length_replicate, List.length_append, *]

/-- Writing a word over the middle segment of `pre ++ mid ++ post`, at
    `pre`'s end and of `mid`'s length, replaces exactly that segment. -/
theorem setSlice!_mid {α} (pre mid post w : List α) (hw : w.length = mid.length) :
    (pre ++ mid ++ post).setSlice! pre.length w = pre ++ w ++ post := by
  simp only [List.setSlice!, List.length_append]
  have e1 : List.take pre.length (pre ++ mid ++ post) = pre := by
    simp [List.append_assoc, List.take_append]
  have e2 : min w.length (pre.length + mid.length + post.length - pre.length) = w.length := by
    omega
  rw [e1, e2, List.take_of_length_le (le_refl _)]
  have e3 : List.drop (pre.length + w.length) (pre ++ mid ++ post) = post := by
    rw [hw, List.append_assoc, List.drop_append, List.drop_append]
    simp
  rw [e3]

/-- A step's chain-position write: 4 bytes at 56 replace the ADRS's
    bytes [24..28) and nothing else. -/
theorem chainBuf_pos (s a w v p : List Std.U8) (hs : s.length = 32)
    (ha : a.length = 32) (hw : w.length = 4) (hp : p.length = 4) :
    (s ++ (a.take 24 ++ w ++ a.drop 28) ++ v).setSlice! 56 p
      = s ++ (a.take 24 ++ p ++ a.drop 28) ++ v := by
  have hpre : (s ++ a.take 24).length = 56 := by simp [hs, ha]
  have e : s ++ (a.take 24 ++ w ++ a.drop 28) ++ v
      = (s ++ a.take 24) ++ w ++ (a.drop 28 ++ v) := by simp [List.append_assoc]
  rw [e, ← hpre, setSlice!_mid _ _ _ _ (by rw [hp, hw])]
  simp [List.append_assoc]

/-- A step's value write: the digest's 16 bytes at 64 over a padded value
    give the next padded value. -/
theorem chainBuf_val (s m q r : List Std.U8) (hs : s.length = 32)
    (hm : m.length = 32) (hq : q.length = 16) (hr : r.length = 16) :
    (s ++ m ++ (r ++ List.replicate 16 0#u8)).setSlice! 64 q
      = s ++ m ++ (q ++ List.replicate 16 0#u8) := by
  apply List.ext_getElem!
  · simp [List.length_setSlice!, List.length_append, List.length_replicate, *]
  intro j
  by_cases h0 : j < 64
  · simp_lists [List.length_append, List.length_replicate, *]
  by_cases h1 : j < 80
  · simp_lists [List.length_append, List.length_replicate, *]
  · simp_lists [List.length_append, List.length_replicate, *]

/-- Every chain value the fold produces is a right-zero-padded 16-byte value. -/
theorem chainFold_padded (seed adrs0 : Std.Array Std.U8 32#usize)
    (x : Std.Array Std.U8 16#usize) (start : Nat) (k : Nat) :
    ∃ y : Std.Array Std.U8 16#usize,
      (List.range k).foldl
        (fun cur i => pad16Pure (th_pure seed (chainAdrs adrs0 (start + i)) cur))
        (pad16Pure x) = pad16Pure y := by
  cases k with
  | zero => exact ⟨x, rfl⟩
  | succ k =>
    rw [List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil]
    exact ⟨_, rfl⟩

/-- Chain loop over the hoisted buffer: at step `k` the buffer is
    `seed ‖ ADRS-with-some-chain-pos ‖ F k`, where `F k` is
    `chain_hash_pure`'s fold prefix and the ADRS side fields are `adrs0`'s.
    One step writes BE(start+k) into the chain-pos field — making the
    middle third `chainAdrs adrs0 (start+k)`, so the hashed buffer is exactly
    `th_pure`'s preimage — and copies the digest's first 16 bytes over the
    padded value, which is `F (k+1)`. -/
theorem chain_hash_loop_value
    (seed adrs0 : Std.Array Std.U8 32#usize) (x : Std.Array Std.U8 16#usize)
    (start_pos steps : Std.U32) (iter : core.ops.range.Range Std.U32)
    (buf : Std.Array Std.U8 96#usize)
    (hend : iter.«end» = steps)
    (hle : iter.start.val ≤ steps.val)
    (hovf : start_pos.val + steps.val ≤ U32.max)
    (hbuf : ∃ w : List Std.U8, w.length = 4 ∧
      buf.val = seed.val ++ (adrs0.val.take 24 ++ w ++ adrs0.val.drop 28) ++
        ((List.range iter.start.val).foldl
          (fun cur i => pad16Pure (th_pure seed (chainAdrs adrs0 (start_pos.val + i)) cur))
          (pad16Pure x)).val) :
    hash.chain_hash_loop iter start_pos buf
      ⦃ r => ∃ w : List Std.U8, w.length = 4 ∧
          r.val = seed.val ++ (adrs0.val.take 24 ++ w ++ adrs0.val.drop 28) ++
            ((List.range steps.val).foldl
              (fun cur i => pad16Pure (th_pure seed (chainAdrs adrs0 (start_pos.val + i)) cur))
              (pad16Pure x)).val ⦄ := by
  have l_seed : seed.val.length = 32 := by have := seed.property; simp_all
  have l_adrs : adrs0.val.length = 32 := by have := adrs0.property; simp_all
  unfold hash.chain_hash_loop
  apply Aeneas.Std.loop.spec_decr_nat
    (measure := fun (s : core.ops.range.Range Std.U32 × Std.Array Std.U8 96#usize) =>
       s.1.«end».val - s.1.start.val)
    (inv := fun (s : core.ops.range.Range Std.U32 × Std.Array Std.U8 96#usize) =>
       s.1.«end» = steps ∧ s.1.start.val ≤ steps.val ∧
       ∃ w : List Std.U8, w.length = 4 ∧
         s.2.val = seed.val ++ (adrs0.val.take 24 ++ w ++ adrs0.val.drop 28) ++
           ((List.range s.1.start.val).foldl
             (fun cur i => pad16Pure (th_pure seed (chainAdrs adrs0 (start_pos.val + i)) cur))
             (pad16Pure x)).val)
  · rintro ⟨it, bv⟩ ⟨hbnd, hsle, w, hw, hbv⟩
    simp only at hbnd hsle hbv
    unfold hash.chain_hash_loop.body
    let* ⟨ob, iter1, hpost⟩ ← next_u32_spec it
    rcases hpost with ⟨ho, hge⟩ | ⟨stp, it', heq, hstp, hlt, hend', hstart'⟩
    · subst ho
      simp only [WP.spec_ok]
      have hbv' : it.«end».val = steps.val := by rw [hbnd]
      refine ⟨w, hw, ?_⟩
      rw [hbv, show it.start.val = steps.val from by omega]
    · simp only [Prod.mk.injEq] at heq
      obtain ⟨rfl, rfl⟩ := heq
      subst hstp
      have hklt : it.start.val < steps.val := by
        have hbv' : it.«end».val = steps.val := by rw [hbnd]
        omega
      obtain ⟨y, hy⟩ := chainFold_padded seed adrs0 x start_pos.val it.start.val
      simp only [params.N]
      step* <;> first | scalar_tac | skip
      have ly : y.val.length = 16 := by have := y.property; simp_all
      have hwr : (index_mut_back s2).val
          = seed.val ++ (adrs0.val.take 24 ++ u32beBytes i.val ++ adrs0.val.drop 28) ++
            (pad16Pure y).val := by
        rw [s_post3, s2_post, s1_post, Array.val_to_slice, a_post, u32_toBEBytes_map_mk i,
          hbv, hy]
        exact chainBuf_pos _ _ _ _ _ l_seed l_adrs hw (u32beBytes_length _)
      have hd : d = sha256_pure (seed.val ++ (chainAdrs adrs0 i.val).val ++ (pad16Pure y).val) := by
        rw [d_post, s3_post, Array.val_to_slice, hwr, chainAdrs_val]
      have hs5 : s5.val = d.val.take 16 := by
        rw [s5_post1, Array.val_to_slice]
        simp [List.slice]
      have hebv : iter1.«end».val = it.«end».val := by rw [hend']
      refine ⟨by rw [hend']; exact hbnd, by omega,
        ⟨u32beBytes i.val, u32beBytes_length _, ?_⟩, by omega⟩
      have lm : (adrs0.val.take 24 ++ u32beBytes i.val ++ adrs0.val.drop 28).length = 32 := by
        simp [l_adrs, u32beBytes_length]
      have ld : (d.val.take 16).length = 16 := by have := d.property; simp_all
      rw [s4_post3, s6_post, hs5, hwr, pad16Pure_val,
        chainBuf_val _ _ _ _ l_seed lm ld ly]
      rw [hstart', List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil, hy,
        pad16Pure_val, th_pure_def, truncate16_val, ← i_post, ← hd]
  · exact ⟨hend, hle, hbuf⟩

set_option maxRecDepth 16384 in
/-- `chain_buf`: the 96-byte preimage `seed ‖ adrs ‖ pad16(val)`. -/
theorem hash.chain_buf_spec (seed adrs : Std.Array Std.U8 32#usize)
    (x : Std.Array Std.U8 16#usize) :
    hash.chain_buf seed adrs x ⦃ r => r.val = seed.val ++ adrs.val ++ (pad16Pure x).val ⦄ := by
  have l_seed : seed.val.length = 32 := by have := seed.property; simp_all
  have l_adrs : adrs.val.length = 32 := by have := adrs.property; simp_all
  have l_x : x.val.length = 16 := by have := x.property; simp_all
  unfold hash.chain_buf
  simp only [params.N]
  step* <;> first | scalar_tac | skip
  rw [s6_post3, s8_post, s7_post, s3_post3, s5_post, s4_post, s_post3, s2_post, s1_post,
    Array.val_to_slice, Array.val_to_slice, Array.val_to_slice, Array.repeat_val, pad16Pure_val]
  norm_num
  simpa [List.append_assoc] using chainBuf_init _ _ _ l_seed l_adrs l_x

/-- `chain_value`: the 16 value bytes at [64..80) of a chain buffer. -/
theorem hash.chain_value_spec (buf : Std.Array Std.U8 96#usize) :
    hash.chain_value buf ⦃ r => r.val = (buf.val.drop 64).take 16 ⦄ := by
  unfold hash.chain_value
  simp only [params.N]
  step* <;> first | scalar_tac | skip
  simp_all [Array.from_slice, List.slice]

set_option maxRecDepth 16384 in
/-- **`chain_hash` spec** — for `start + steps ≤ u32::MAX` (the WOTS+C caller
    passes start = digit ≤ 7, steps = 7 − digit), the extracted body computes
    exactly `chain_hash_pure`'s `th`-fold with the per-step ADRS tweak. -/
@[step] theorem hash.chain_hash_spec (seed adrs : Std.Array Std.U8 32#usize)
    (x : Std.Array Std.U8 16#usize) (start steps : Std.U32)
    (hovf : start.val + steps.val ≤ U32.max) :
    hash.chain_hash seed adrs x start steps
      ⦃ r => r = chain_hash_pure seed adrs x start steps ⦄ := by
  have l_seed : seed.val.length = 32 := by have := seed.property; simp_all
  have l_adrs : adrs.val.length = 32 := by have := adrs.property; simp_all
  have hsplit : adrs.val
      = List.take 24 adrs.val ++ List.take 4 (List.drop 24 adrs.val) ++ List.drop 28 adrs.val := by
    rw [List.append_assoc,
      show List.drop 28 adrs.val = List.drop 4 (List.drop 24 adrs.val) by rw [List.drop_drop],
      List.take_append_drop, List.take_append_drop]
  have h0 : (({ start := 0#u32, «end» := steps } : core.ops.range.Range Std.U32).start).val = 0 :=
    rfl
  unfold hash.chain_hash
  let* ⟨b0, hb0⟩ ← hash.chain_buf_spec
  let* ⟨w4, r4, hw4, hr4⟩ ← chain_hash_loop_value seed adrs x start steps
    { start := 0#u32, «end» := steps } b0 rfl (by rw [h0]; exact Nat.zero_le _) hovf
    ⟨(adrs.val.drop 24).take 4, by
      simp only [List.length_take, List.length_drop, l_adrs]; omega, by
      rw [hb0, h0, List.range_zero, List.foldl_nil, ← hsplit]⟩
  let* ⟨out, hout⟩ ← hash.chain_value_spec
  have lA : (List.take 24 adrs.val ++ w4 ++ List.drop 28 adrs.val).length = 32 := by
    simp only [List.length_append, List.length_take, List.length_drop, l_adrs, hw4]
    omega
  apply Subtype.ext
  rw [chain_hash_pure_def, truncate16_val, hout, hr4,
    List.drop_left' (by rw [List.length_append, l_seed, lA])]

end sphincs_c10
