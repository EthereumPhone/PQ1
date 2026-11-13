/- §33 axiom-collapse — `hash.th_multi` spec: the extracted body (prefix
   writes + per-value loop into a 1440-byte buffer + subslice) computes
   exactly `th_multi_pure` = sha256(seed ‖ adrs ‖ pad16(v₀) ‖ …)[0..16],
   for `|vals| ≤ 43` (the `massert` bound; both Rust call sites pass
   compile-time 43 or 13). -/
import Extracted.HashSpecs.Truncate
import Extracted.ForsLoop

set_option linter.unusedSimpArgs false
set_option linter.unusedTactic false
set_option maxHeartbeats 8000000

open Aeneas Aeneas.Std Result
open Extracted.SetSlice

namespace sphincs_c10

open Extracted.Equiv in
/-- Loop: writes `vals[i]` into bytes `[64+32i, 64+32i+16)` of a buffer whose
    tail is still all-zero; each written slot's upper 16 bytes stay zero, so
    the processed prefix is exactly the `pad16`-flattened values. -/
theorem th_multi_loop_value (vals : Slice (Std.Array Std.U8 16#usize))
    (base : List Std.U8) (iter : core.ops.range.Range Std.Usize)
    (buf : Std.Array Std.U8 1440#usize)
    (hbase : base.length = 64)
    (hn : vals.val.length ≤ 43)
    (hend : iter.«end».val = vals.val.length)
    (hle : iter.start.val ≤ vals.val.length)
    (hbuf : buf.val = base
        ++ ((vals.val.take iter.start.val).map
              (fun v => v.val ++ List.replicate 16 0#u8)).flatten
        ++ List.replicate (1376 - 32 * iter.start.val) 0#u8) :
    hash.th_multi_loop iter vals buf
      ⦃ r => r.val = base
          ++ (vals.val.map (fun v => v.val ++ List.replicate 16 0#u8)).flatten
          ++ List.replicate (1376 - 32 * vals.val.length) 0#u8 ⦄ := by
  unfold hash.th_multi_loop
  apply Aeneas.Std.loop.spec_decr_nat
    (measure := fun (s : core.ops.range.Range Std.Usize × Std.Array Std.U8 1440#usize) =>
       s.1.«end».val - s.1.start.val)
    (inv := fun (s : core.ops.range.Range Std.Usize × Std.Array Std.U8 1440#usize) =>
       s.1.«end».val = vals.val.length ∧ s.1.start.val ≤ vals.val.length ∧
       s.2.val = base
         ++ ((vals.val.take s.1.start.val).map
               (fun v => v.val ++ List.replicate 16 0#u8)).flatten
         ++ List.replicate (1376 - 32 * s.1.start.val) 0#u8)
  · rintro ⟨it, b⟩ ⟨hbnd, hsle, hinv⟩
    simp only at hbnd hsle hinv
    unfold hash.th_multi_loop.body
    let* ⟨ob, iter1, hpost⟩ ← next_usize_spec it
    rcases hpost with ⟨ho, hge⟩ | ⟨i, it', heq, hi, hlt, hend', hstart'⟩
    · subst ho
      simp only [WP.spec_ok]
      rw [hinv, show it.start.val = vals.val.length from by omega,
          List.take_length]
    · simp only [Prod.mk.injEq] at heq
      obtain ⟨rfl, rfl⟩ := heq
      subst hi
      have hilt : it.start.val < vals.val.length := by omega
      -- the flattened processed prefix has length 32·start
      have hflat : (((vals.val.take it.start.val).map
          (fun v => v.val ++ List.replicate 16 0#u8)).flatten).length
            = 32 * it.start.val := by
        rw [List.length_flatten]
        rw [List.map_map]
        have hc : ∀ x ∈ vals.val.take it.start.val,
            (List.length ∘ fun v => v.val ++ List.replicate 16 0#u8) x = 32 := by
          intro x _
          have := x.property; simp_all
        rw [List.map_congr_left hc, List.map_const', List.sum_replicate,
            List.length_take, smul_eq_mul]
        have hm : min it.start.val vals.val.length = it.start.val := by omega
        rw [hm, Nat.mul_comm]
      step* <;>
        first
        | scalar_tac
        | (simp only [params.N]; scalar_tac)
        | (simp_all only [params.N, Slice.length, Array.length_to_slice]; scalar_tac)
        | skip
      refine ⟨by rw [hend']; exact hbnd, by omega, ?_, by rw [hend']; omega⟩
      -- the write-back is a setSlice! at the exact boundary of the prefix
      rw [s_post3, s2_post, s1_post, a_post, Array.val_to_slice]
      have hval16 : ((vals.val)[it.start.val]'hilt).val.length = 16 := by
        have := ((vals.val)[it.start.val]'hilt).property; simp_all
      have hofflen : off.val
          = (base ++ ((vals.val.take it.start.val).map
              (fun v => v.val ++ List.replicate 16 0#u8)).flatten).length := by
        simp only [List.length_append, hbase, hflat, off_post, i1_post]
      -- reassociate the invariant to (pre ++ replicate) shape and write
      have hb' : b.val = (base ++ ((vals.val.take it.start.val).map
            (fun v => v.val ++ List.replicate 16 0#u8)).flatten)
          ++ List.replicate (1376 - 32 * it.start.val) 0#u8 := by
        rw [hinv, List.append_assoc]
      rw [hb', hofflen,
          setSlice!_append_replicate _ _ _ _ (by rw [hval16]; omega)]
      -- now pure list algebra: fold the written slot into the prefix
      have htake : vals.val.take (it.start.val + 1)
          = vals.val.take it.start.val ++ [(vals.val)[it.start.val]'hilt] :=
        List.take_succ_eq_append_getElem hilt
      have hrep : List.replicate (1376 - 32 * it.start.val - 16) 0#u8
          = List.replicate 16 0#u8 ++ List.replicate (1376 - 32 * (it.start.val + 1)) 0#u8 := by
        rw [← List.replicate_add]
        congr 1
        omega
      rw [hstart', htake, List.map_append, List.flatten_append, hval16, hrep]
      simp [List.append_assoc]
  · exact ⟨hend, hle, hbuf⟩

set_option maxRecDepth 16384 in
/-- The `pad16`-flattened full value list has length `32·|vals|`. -/
theorem flatten_pad16_length (vals : Slice (Std.Array Std.U8 16#usize)) :
    ((vals.val.map (fun v => v.val ++ List.replicate 16 0#u8)).flatten).length
      = 32 * vals.val.length := by
  rw [List.length_flatten, List.map_map]
  have hc : ∀ x ∈ vals.val,
      (List.length ∘ fun v => v.val ++ List.replicate 16 0#u8) x = 32 := by
    intro x _
    have := x.property; simp_all
  rw [List.map_congr_left hc, List.map_const', List.sum_replicate, smul_eq_mul,
      Nat.mul_comm]

/-- **`th_multi` spec** — for `|vals| ≤ 43` (the `massert` bound; both Rust
    call sites pass 43 or 13), the extracted body computes exactly
    `th_multi_pure` = sha256(seed ‖ adrs ‖ pad16(v₀) ‖ …)[0..16]. -/
@[step] theorem hash.th_multi_spec (seed adrs : Std.Array Std.U8 32#usize)
    (vals : Slice (Std.Array Std.U8 16#usize)) (hn : vals.val.length ≤ 43) :
    hash.th_multi seed adrs vals ⦃ r => r = th_multi_pure seed adrs vals ⦄ := by
  have hseed : seed.val.length = 32 := by have := seed.property; simp_all
  have hadrs : adrs.val.length = 32 := by have := adrs.property; simp_all
  unfold hash.th_multi
  step* <;>
    first
    | scalar_tac
    | (simp only [hash.TH_MULTI_MAX, params.N, Slice.length, Slice.len]; scalar_tac)
    | (simp_all only [hash.TH_MULTI_MAX, params.N, Slice.length,
         Array.length_to_slice]; scalar_tac)
    | skip
  -- the two prefix writes leave (seed ++ adrs) ++ zeros
  have h1 := setSlice!_append_replicate ([] : List Std.U8) 1440 seed.val 0#u8
    (by rw [hseed]; omega)
  simp only [List.nil_append, List.length_nil, hseed] at h1
  have h2 := setSlice!_append_replicate seed.val 1408 adrs.val 0#u8
    (by rw [hadrs]; omega)
  rw [hseed, hadrs] at h2
  have hbuf2 : (index_mut_back1 s5).val
      = (seed.val ++ adrs.val)
        ++ ((vals.val.take 0).map (fun v => v.val ++ List.replicate 16 0#u8)).flatten
        ++ List.replicate (1376 - 32 * 0) 0#u8 := by
    rw [s3_post3, s5_post, s4_post, Array.val_to_slice, s_post3, s2_post, s1_post,
        Array.val_to_slice, Array.repeat_val]
    norm_num
    rw [h1, h2]
    simp only [List.take_zero, List.map_nil, List.flatten_nil, List.append_nil,
               List.nil_append, List.append_assoc]
  have hbase' : (seed.val ++ adrs.val).length = 64 := by
    simp [hseed, hadrs]
  have hend' : ({ start := 0#usize, «end» := vals.len } :
      core.ops.range.Range Std.Usize).«end».val = vals.val.length := by
    simp [Slice.len_val]
  have hle' : ({ start := 0#usize, «end» := vals.len } :
      core.ops.range.Range Std.Usize).start.val ≤ vals.val.length := by
    simp
  let* ⟨buf3, hbuf3⟩ ← th_multi_loop_value vals (seed.val ++ adrs.val) _ _
    hbase' hn hend' hle' hbuf2
  step* <;>
    first
    | scalar_tac
    | (simp only [hash.TH_MULTI_MAX, params.N, Slice.length, Slice.len]; scalar_tac)
    | skip
  -- the subslice take recovers exactly (seed ++ adrs) ++ flatten
  have hlen : ((seed.val ++ adrs.val)
      ++ (vals.val.map (fun v => v.val ++ List.replicate 16 0#u8)).flatten).length
        = 64 + 32 * vals.val.length := by
    rw [List.length_append, List.length_append, hseed, hadrs, flatten_pad16_length]
  have hi4 : i4.val = 64 + 32 * vals.val.length := by
    rw [i4_post, i3_post]; simp [Slice.len_val]
  have hs6 : s6.val = (seed.val ++ adrs.val)
      ++ (vals.val.map (fun v => v.val ++ List.replicate 16 0#u8)).flatten := by
    rw [s6_post1, Array.val_to_slice]
    have hsl : List.slice 0 i4.val buf3.val = buf3.val.take i4.val := by
      simp [List.slice]
    rw [hsl, hbuf3, List.take_left' (by rw [hlen, hi4])]
  -- fold into th_multi_pure
  rw [r_post, hs6, th_multi_pure_def,
      show (vals.val.map (fun v => (pad16Pure v).val))
        = (vals.val.map (fun v => v.val ++ List.replicate 16 0#u8)) from
        List.map_congr_left (fun v _ => pad16Pure_val v),
      List.append_assoc]

end sphincs_c10
