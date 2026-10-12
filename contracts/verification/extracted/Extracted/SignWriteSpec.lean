/- Actual signature writes: exact changed bytes and preservation outside the
   destination range. All bounds are discharged by the concrete callers. -/
import Extracted.SignForest.Funs
import Extracted.SignatureDecodeSpec
open Aeneas Aeneas.Std Result ControlFlow
namespace Extracted.Equiv
open sphincs_c10
set_option maxHeartbeats 1000000
set_option maxRecDepth 8192

/-- A complete byte-level write contract, including the untouched frame. -/
def SignatureWrites (initial out : C10Signature) (base len : Nat)
    (bytes : Nat → Std.U8) : Prop :=
  ∀ j : Fin 4008, out.val[j.val]! =
    if base ≤ j.val ∧ j.val < base + len then bytes (j.val-base)
    else initial.val[j.val]!

theorem signatureWrites_empty (sig : C10Signature) (base : Nat)
    (bytes : Nat → Std.U8) : SignatureWrites sig sig base 0 bytes := by
  intro j
  rw [if_neg (by omega)]

theorem signatureWrites_append (initial mid out : C10Signature)
    (base len extra : Nat) (bytes : Nat → Std.U8)
    (hfirst : SignatureWrites initial mid base len bytes)
    (hnext : SignatureWrites mid out (base+len) extra (fun i => bytes (len+i))) :
    SignatureWrites initial out base (len+extra) bytes := by
  intro j
  rw [hnext j, hfirst j]
  split <;> rename_i h
  · rw [if_pos (by omega)]
    exact congrArg bytes (by omega)
  · by_cases hbefore : base ≤ j.val ∧ j.val < base+len
    · rw [if_pos hbefore, if_pos (by omega)]
    · rw [if_neg hbefore, if_neg (by omega)]

@[step] theorem firmware_write16 (sig : C10Signature) (offset : Std.Usize)
    (block : Std.Array Std.U8 16#usize) (h : offset.val + 16 ≤ 4008) :
    hypertree.write16 sig offset
      block ⦃ out => SignatureWrites sig out offset.val 16 (fun i => block.val[i]!) ⦄ := by
  unfold hypertree.write16
  simp only [params.N]
  step* <;> first | scalar_tac | skip
  refine fun j => ?_
  rw [s_post3, s2_post, s1_post]
  simp only [Array.val_to_slice]
  have hb : block.val.length = 16 := by simp
  have hs : sig.val.length = 4008 := by simp
  split <;> rename_i hj
  · exact List.getElem!_setSlice!_middle _ _ _ _ ⟨hj.1, by omega, by have := j.isLt; omega⟩
  · by_cases hp : j.val < offset.val
    · exact List.getElem!_setSlice!_prefix _ _ _ _ hp
    · exact List.getElem!_setSlice!_suffix _ _ _ _ (by omega)

theorem signatureWrites_congr (initial out : C10Signature) (base len : Nat)
    (bytes bytes' : Nat → Std.U8) (h : SignatureWrites initial out base len bytes)
    (heq : ∀ i, i < len → bytes i = bytes' i) :
    SignatureWrites initial out base len bytes' := by
  intro j
  rw [h j]
  split <;> rename_i hj
  · exact heq _ (by omega)
  · rfl

def blockBytes (rows : Nat → Std.Array Std.U8 16#usize) (i : Nat) : Std.U8 :=
  (rows (i/16)).val[i%16]!

theorem blockBytes_at (rows : Nat → Std.Array Std.U8 16#usize) (k i : Nat)
    (hi : i < 16) : blockBytes rows (16*k+i) = (rows k).val[i]! := by
  have hd : (16*k+i)/16 = k := by omega
  have hm : (16*k+i)%16 = i := by omega
  simp only [blockBytes, hd, hm]

abbrev SignWriteState := C10Signature × Std.Usize × Std.Usize
abbrev SignWriteResult := ControlFlow SignWriteState (C10Signature × Std.Usize)

/-- The one-step contract is discharged for each actual extracted loop below. -/
def SignWriteStep (rows : Nat → Std.Array Std.U8 16#usize) (n : Nat)
    (s : SignWriteState) : SignWriteResult → Prop
  | .cont (out, offset, k) =>
      s.2.2.val < n ∧ offset.val = s.2.1.val+16 ∧ k.val = s.2.2.val+1 ∧
      SignatureWrites s.1 out s.2.1.val 16 (fun i => (rows s.2.2.val).val[i]!)
  | .done (out, offset) => n ≤ s.2.2.val ∧ out = s.1 ∧ offset = s.2.1

/-- A shared invariant theorem for the actual block-writing loops. It includes
    termination; callers prove the step contract from their generated bodies. -/
theorem sign_write_loop (body : SignWriteState → Result SignWriteResult)
    (rows : Nat → Std.Array Std.U8 16#usize) (n base : Nat)
    (initial : C10Signature) (offset : Std.Usize) (hoff : offset.val = base)
    (hbody : ∀ sig off k, k.val ≤ n → off.val = base+16*k.val →
      body (sig,off,k) ⦃ r => SignWriteStep rows n (sig,off,k) r ⦄) :
    loop body (initial,offset,0#usize) ⦃ r => r.2.val = base+16*n ∧
      SignatureWrites initial r.1 base (16*n) (blockBytes rows) ⦄ := by
  apply loop.spec_decr_nat
    (measure := fun s : SignWriteState => n-s.2.2.val)
    (inv := fun s : SignWriteState => s.2.2.val ≤ n ∧ s.2.1.val = base+16*s.2.2.val ∧
      SignatureWrites initial s.1 base (16*s.2.2.val) (blockBytes rows))
  · rintro ⟨sig,off,k⟩ ⟨hk,ho,hw⟩
    simp only at hk ho hw
    apply WP.spec_mono (hbody sig off k hk ho)
    intro result hr
    cases result with
    | done value =>
      rcases value with ⟨out,off'⟩
      simp only [SignWriteStep] at hr
      rcases hr with ⟨hn,rfl,rfl⟩
      simp only
      have he : k.val = n := by omega
      exact ⟨by omega, by simpa only [he] using hw⟩
    | cont value =>
      rcases value with ⟨out,off',k'⟩
      simp only [SignWriteStep] at hr
      rcases hr with ⟨hlt,ho',hk',hw'⟩
      simp only
      refine ⟨⟨by omega, by omega, ?_⟩, by omega⟩
      have hh := signatureWrites_congr sig out off.val 16 _
        (fun i => blockBytes rows (16*k.val+i)) hw'
        (fun i hi => (blockBytes_at rows k.val i hi).symm)
      rw [ho] at hh
      have ha := signatureWrites_append initial sig out base (16*k.val) 16
        (blockBytes rows) hw hh
      simpa only [show 16*k'.val = 16*k.val+16 by omega] using ha
  · exact ⟨by simp, by simpa using hoff, by simpa using signatureWrites_empty initial base (blockBytes rows)⟩

@[step] theorem firmware_write_fors_secrets (sig : C10Signature) (offset : Std.Usize)
    (secrets : ForsSecrets) (hb : offset.val+208 ≤ 4008) :
    hypertree.sign_inner_loop1 sig offset secrets 0#usize ⦃ r =>
      r.2.val = offset.val+208 ∧ SignatureWrites sig r.1 offset.val 208
        (blockBytes (fun i => secrets.val[i]!)) ⦄ := by
  unfold hypertree.sign_inner_loop1
  apply sign_write_loop _ (fun i => secrets.val[i]!) 13 offset.val sig offset rfl
  intro current off k hk hoff
  unfold hypertree.sign_inner_loop1.body
  simp only [params.K, params.N, lift]
  split
  · rename_i hlt
    have hkv : k.val < 13 := by scalar_tac
    step* <;> first | scalar_tac | skip
    refine ⟨hkv, offset1_post, t1_post, ?_⟩
    have hr : row = secrets.val[k.val]! := by
      rw [row_post, getElem!_pos secrets.val k.val (by simp; omega)]
    simpa only [hr] using sig1_post
  · rename_i hge
    simp [WP.spec_ok, SignWriteStep]
    scalar_tac

@[step] theorem firmware_write_fors_path (sig : C10Signature) (offset t : Std.Usize)
    (paths : ForsAuthPaths) (ht : t.val < 12) (hb : offset.val+176 ≤ 4008) :
    hypertree.sign_inner_loop2_loop0 sig offset paths t 0#usize ⦃ r =>
      r.2.val = offset.val+176 ∧ SignatureWrites sig r.1 offset.val 176
        (blockBytes (fun i => (paths.val[t.val]!).val[i]!)) ⦄ := by
  unfold hypertree.sign_inner_loop2_loop0
  apply sign_write_loop _ (fun i => (paths.val[t.val]!).val[i]!) 11 offset.val sig offset rfl
  intro current off k hk hoff
  unfold hypertree.sign_inner_loop2_loop0.body
  simp only [params.A, params.N]
  split
  · rename_i hlt
    have hkv : k.val < 11 := by scalar_tac
    step* <;> first | scalar_tac | skip
    refine ⟨hkv, offset1_post, h1_post, ?_⟩
    have ha : a = paths.val[t.val]! := by
      rw [a_post, getElem!_pos paths.val t.val (by simp; omega)]
    have hr : row = (paths.val[t.val]!).val[k.val]! := by
      rw [row_post, ← getElem!_pos a.val k.val (by simp; omega), ha]
    simpa only [hr] using sig1_post
  · simp [WP.spec_ok, SignWriteStep]
    scalar_tac

@[step] theorem firmware_write_wots_chains (sig : C10Signature) (offset : Std.Usize)
    (chains : WotsChains) (hb : offset.val+688 ≤ 4008) :
    hypertree.sign_inner_loop3_loop0 sig offset chains 0#usize ⦃ r =>
      r.2.val = offset.val+688 ∧ SignatureWrites sig r.1 offset.val 688
        (blockBytes (fun i => chains.val[i]!)) ⦄ := by
  unfold hypertree.sign_inner_loop3_loop0
  apply sign_write_loop _ (fun i => chains.val[i]!) 43 offset.val sig offset rfl
  intro current off k hk hoff
  unfold hypertree.sign_inner_loop3_loop0.body
  simp only [params.L, params.N]
  split
  · rename_i hlt
    have hkv : k.val < 43 := by scalar_tac
    step* <;> first | scalar_tac | skip
    refine ⟨hkv, offset1_post, i1_post, ?_⟩
    have hr : row = chains.val[k.val]! := by
      rw [row_post, getElem!_pos chains.val k.val (by simp; omega)]
    simpa only [hr] using sig1_post
  · simp [WP.spec_ok, SignWriteStep]
    scalar_tac

@[step] theorem firmware_write_xmss_path (sig : C10Signature) (offset : Std.Usize)
    (path : XmssAuth) (hb : offset.val+144 ≤ 4008) :
    hypertree.sign_inner_loop3_loop1 9#usize sig offset path 0#usize ⦃ r =>
      r.2.val = offset.val+144 ∧ SignatureWrites sig r.1 offset.val 144
        (blockBytes (fun i => path.val[i]!)) ⦄ := by
  unfold hypertree.sign_inner_loop3_loop1
  apply sign_write_loop _ (fun i => path.val[i]!) 9 offset.val sig offset rfl
  intro current off k hk hoff
  unfold hypertree.sign_inner_loop3_loop1.body
  simp only [params.N]
  split
  · rename_i hlt
    have hkv : k.val < 9 := by scalar_tac
    step* <;> first | scalar_tac | skip
    refine ⟨hkv, offset1_post, h1_post, ?_⟩
    have hr : row = path.val[k.val]! := by
      rw [row_post, getElem!_pos path.val k.val (by simp; omega)]
    simpa only [hr] using sig1_post
  · simp [WP.spec_ok, SignWriteStep]
    scalar_tac

/-- The unique complete signature described by a byte-write contract. -/
def signatureOverwrite (sig : C10Signature) (base len : Nat)
    (bytes : Nat → Std.U8) : C10Signature :=
  ⟨List.ofFn (fun j : Fin 4008 =>
    if base ≤ j.val ∧ j.val < base+len then bytes (j.val-base)
    else sig.val[j.val]!), by rw [List.length_ofFn]; rfl⟩

theorem signatureOverwrite_spec (sig : C10Signature) (base len : Nat)
    (bytes : Nat → Std.U8) :
    SignatureWrites sig (signatureOverwrite sig base len bytes) base len bytes := by
  intro j
  simp only [signatureOverwrite, List.getElem!_ofFn _ _ j.isLt]

theorem signatureWrites_eq (sig out : C10Signature) (base len : Nat)
    (bytes : Nat → Std.U8) (h : SignatureWrites sig out base len bytes) :
    out = signatureOverwrite sig base len bytes := by
  apply Subtype.ext
  apply List.ext_getElem! (by simp)
  intro j
  by_cases hj : j < 4008
  · simpa only [signatureOverwrite, List.getElem!_ofFn _ _ hj] using h ⟨j,hj⟩
  · simp [getElem!_neg, hj]

theorem signatureNode_get (sig : C10Signature) (offset : Fin 3993) (i : Fin 16) :
    (signatureNode sig offset).val[i.val]! = sig.val[offset.val+i.val]! := by
  have ho := offset.isLt
  have hi := i.isLt
  simp only [signatureNode, List.slice, Nat.add_sub_cancel_left]
  simp_lists

theorem signatureNode_eq (sig : C10Signature) (offset : Fin 3993)
    (node : Std.Array Std.U8 16#usize)
    (h : ∀ i : Fin 16, sig.val[offset.val+i.val]! = node.val[i.val]!) :
    signatureNode sig offset = node := by
  apply Subtype.ext
  apply List.ext_getElem! (by simp)
  intro j
  by_cases hj : j < 16
  · rw [signatureNode_get sig offset ⟨j,hj⟩]
    exact h ⟨j,hj⟩
  · simp [getElem!_neg, hj]

end Extracted.Equiv
