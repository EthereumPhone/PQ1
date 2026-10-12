/- Byte-exact FORS prefix parsing by the actual verifier. -/
import Extracted.ForsRejectSpec
open Aeneas Aeneas.Std Result ControlFlow
namespace Extracted.Equiv
open sphincs_c10
set_option maxHeartbeats 4000000
set_option maxRecDepth 8192

abbrev C10Signature := Std.Array Std.U8 4008#usize
abbrev ForsSecrets := Std.Array (Std.Array Std.U8 16#usize) 13#usize
abbrev ForsAuthPaths := Std.Array (Std.Array (Std.Array Std.U8 16#usize) 11#usize) 12#usize

/-- Only complete, in-range sixteen-byte windows have this representation. -/
def signatureNode (sig : C10Signature) (offset : Fin 3993) : Std.Array Std.U8 16#usize :=
  ⟨List.slice offset.val (offset.val + 16) sig.val, by
    have hlen : sig.val.length = 4008 := by simpa using sig.property
    have ho := offset.isLt
    simp only [List.slice, List.length_take, List.length_drop, Nat.add_sub_cancel_left, hlen]
    simp only [Nat.min_eq_left (by omega : 16 ≤ 4008 - offset.val)]
    rfl⟩

def forsSecretBytes (sig : C10Signature) (t : Fin 13) : Std.Array Std.U8 16#usize :=
  signatureNode sig ⟨16 + 16*t.val, by have := t.isLt; omega⟩

def forsAuthBytes (sig : C10Signature) (t : Fin 12) (h : Fin 11) : Std.Array Std.U8 16#usize :=
  signatureNode sig ⟨224 + 176*t.val + 16*h.val, by have := t.isLt; have := h.isLt; omega⟩

/-- All thirteen secrets occupy bytes 16..223, before the authentication paths. -/
theorem firmware_parse_fors_secrets (sig : C10Signature) (initial : ForsSecrets) :
    hypertree.verify_loop0 {start := 0#usize, «end» := 13#usize} sig 16#usize initial
      ⦃ r => r.1.val = 224 ∧ ∀ t : Fin 13, r.2.val[t.val]! = forsSecretBytes sig t ⦄ := by
  unfold hypertree.verify_loop0
  apply loop.spec_decr_nat
    (measure := fun s : core.ops.range.Range Std.Usize × Std.Usize × ForsSecrets =>
      13 - s.1.start.val)
    (inv := fun s : core.ops.range.Range Std.Usize × Std.Usize × ForsSecrets =>
      s.1.«end».val = 13 ∧ s.1.start.val ≤ 13 ∧ s.2.1.val = 16 + 16*s.1.start.val ∧
      ∀ t : Fin 13, t.val < s.1.start.val → s.2.2.val[t.val]! = forsSecretBytes sig t)
  · rintro ⟨it, offset, secrets⟩ ⟨hend, hle, hoff, hinv⟩
    simp only at hend hle hoff hinv
    unfold hypertree.verify_loop0.body
    let* ⟨ob, iter1, hpost⟩ ← next_usize_spec it
    rcases hpost with ⟨ho, hge⟩ | ⟨t, it', heq, ht, hlt, hend', hstart'⟩
    · subst ho
      simp only [WP.spec_ok]
      exact ⟨by omega, fun t => hinv t (by have := t.isLt; omega)⟩
    · simp only [Prod.mk.injEq] at heq
      obtain ⟨rfl, rfl⟩ := heq
      have htv : t.val = it.start.val := by rw [ht]
      have ht13 : t.val < 13 := by omega
      simp only [params.N]
      step* <;> first | scalar_tac | skip
      refine ⟨by rw [hend']; exact hend, by omega, by omega, ?_, by omega⟩
      intro q hq
      rw [a_post2, Array.set_val_eq]
      have hslen : secrets.val.length = 13 := by simpa using secrets.property
      by_cases hqt : q.val = t.val
      · rw [List.set_getElem!_eq _ _ _ _ ⟨by omega, hqt.symm⟩]
        apply Subtype.ext
        rw [s_post2, s2_post, Array.from_slice_val a s1 (by
          simpa only [Slice.length, i_post, Nat.add_sub_cancel_left] using s1_post2)]
        simp only [s1_post1, Array.val_to_slice, forsSecretBytes, signatureNode]
        congr 1 <;> omega
      · rw [List.set_getElem!_ne _ _ _ _ (by simp only [Nat.not_eq]; omega)]
        exact hinv q (by omega)
  · refine ⟨rfl, by simp, rfl, ?_⟩
    intro t h
    simp at h

/-- One tree's eleven siblings are read consecutively; every other tree is
    preserved. This is the actual nested parser, not a hand-written loop. -/
theorem firmware_parse_fors_path (sig : C10Signature) (initial : ForsAuthPaths)
    (t offset : Std.Usize) (ht : t.val < 12) (hoff : offset.val = 224 + 176*t.val) :
    hypertree.verify_loop1_loop0 {start := 0#usize, «end» := 11#usize} sig offset initial t
      ⦃ r => r.1.val = 224 + 176*(t.val+1) ∧
        ∀ (q : Fin 12) (j : Fin 11), (r.2.val[q.val]!).val[j.val]! =
          if q.val = t.val then forsAuthBytes sig q j else (initial.val[q.val]!).val[j.val]! ⦄ := by
  unfold hypertree.verify_loop1_loop0
  apply loop.spec_decr_nat
    (measure := fun s : core.ops.range.Range Std.Usize × Std.Usize × ForsAuthPaths =>
      11 - s.1.start.val)
    (inv := fun s : core.ops.range.Range Std.Usize × Std.Usize × ForsAuthPaths =>
      s.1.«end».val = 11 ∧ s.1.start.val ≤ 11 ∧
      s.2.1.val = 224 + 176*t.val + 16*s.1.start.val ∧
      ∀ (q : Fin 12) (j : Fin 11), (s.2.2.val[q.val]!).val[j.val]! =
        if q.val = t.val ∧ j.val < s.1.start.val then forsAuthBytes sig q j
        else (initial.val[q.val]!).val[j.val]!)
  · rintro ⟨it, offset, paths⟩ ⟨hend, hle, hoffset, hinv⟩
    simp only at hend hle hoffset hinv
    unfold hypertree.verify_loop1_loop0.body
    let* ⟨ob, iter1, hpost⟩ ← next_usize_spec it
    rcases hpost with ⟨ho, hge⟩ | ⟨h, it', heq, hh, hlt, hend', hstart'⟩
    · subst ho
      simp only [WP.spec_ok]
      refine ⟨by omega, ?_⟩
      intro q j
      have h11 : it.start.val = 11 := by omega
      simpa only [h11, j.isLt, and_true] using hinv q j
    · simp only [Prod.mk.injEq] at heq
      obtain ⟨rfl, rfl⟩ := heq
      have hhv : h.val = it.start.val := by rw [hh]
      have hh11 : h.val < 11 := by omega
      simp only [params.N]
      step* <;> first | scalar_tac | skip
      refine ⟨by rw [hend']; exact hend, by omega, by omega, ?_, by omega⟩
      intro q j
      rw [a_post2, Array.set_val_eq]
      have hpaths : paths.val.length = 12 := by simpa using paths.property
      have ha11 : a.val.length = 11 := by simpa using a.property
      by_cases hqt : q.val = t.val
      · rw [List.set_getElem!_eq _ _ _ _ ⟨by omega, hqt.symm⟩,
          a1_post2, Array.set_val_eq]
        by_cases hjh : j.val = h.val
        · rw [List.set_getElem!_eq _ _ _ _ ⟨by omega, hjh.symm⟩,
            if_pos ⟨hqt, by omega⟩]
          apply Subtype.ext
          rw [s_post2, s2_post, Array.from_slice_val a1 s1 (by
            simpa only [Slice.length, i_post, Nat.add_sub_cancel_left] using s1_post2)]
          simp only [s1_post1, Array.val_to_slice, forsAuthBytes, signatureNode]
          congr 1 <;> omega
        · rw [List.set_getElem!_ne _ _ _ _ (by simp only [Nat.not_eq]; omega)]
          have haq : a = paths.val[q.val]! := by
            rw [a_post1, ← getElem!_pos paths.val t.val (by omega), ← hqt]
          rw [haq, hinv q j]
          have hjiff : j.val < it.start.val ↔ j.val < iter1.start.val := by omega
          simp only [hjiff]
      · rw [List.set_getElem!_ne _ _ _ _ (by simp only [Nat.not_eq]; omega), hinv q j]
        simp only [hqt, false_and, if_false]
  · refine ⟨rfl, by simp, by simpa using hoff, ?_⟩
    intro q j
    simp

/-- The complete authentication-path block ends at byte 2336, the first WOTS
    signature byte; tree-major and height-major ordering are preserved. -/
theorem firmware_parse_fors_auth (sig : C10Signature) (initial : ForsAuthPaths) :
    hypertree.verify_loop1 {start := 0#usize, «end» := 12#usize} sig 224#usize initial
      ⦃ r => r.1.val = 2336 ∧ ∀ (q : Fin 12) (j : Fin 11),
        (r.2.val[q.val]!).val[j.val]! = forsAuthBytes sig q j ⦄ := by
  unfold hypertree.verify_loop1
  apply loop.spec_decr_nat
    (measure := fun s : core.ops.range.Range Std.Usize × Std.Usize × ForsAuthPaths =>
      12 - s.1.start.val)
    (inv := fun s : core.ops.range.Range Std.Usize × Std.Usize × ForsAuthPaths =>
      s.1.«end».val = 12 ∧ s.1.start.val ≤ 12 ∧ s.2.1.val = 224 + 176*s.1.start.val ∧
      ∀ (q : Fin 12), q.val < s.1.start.val → ∀ j : Fin 11,
        (s.2.2.val[q.val]!).val[j.val]! = forsAuthBytes sig q j)
  · rintro ⟨it, offset, paths⟩ ⟨hend, hle, hoff, hinv⟩
    simp only at hend hle hoff hinv
    unfold hypertree.verify_loop1.body
    let* ⟨ob, iter1, hpost⟩ ← next_usize_spec it
    rcases hpost with ⟨ho, hge⟩ | ⟨t, it', heq, ht, hlt, hend', hstart'⟩
    · subst ho
      simp only [WP.spec_ok]
      exact ⟨by omega, fun q j => hinv q (by have := q.isLt; omega) j⟩
    · simp only [Prod.mk.injEq] at heq
      obtain ⟨rfl, rfl⟩ := heq
      have htv : t.val = it.start.val := by rw [ht]
      have ht12 : t.val < 12 := by omega
      simp only [params.A]
      let* ⟨offset1, paths1, hoff1, hparsed⟩ ← firmware_parse_fors_path sig paths t offset ht12 (by omega)
      refine ⟨by rw [hend']; exact hend, by omega, by omega, ?_, by omega⟩
      intro q hq j
      rw [hparsed q j]
      by_cases hqt : q.val = t.val
      · simp only [hqt, if_true]
      · rw [if_neg hqt]
        exact hinv q (by omega) j
  · refine ⟨rfl, by simp, rfl, ?_⟩
    intro q h
    simp at h

def parsedForsSecrets (sig : C10Signature) : ForsSecrets :=
  ⟨List.ofFn (forsSecretBytes sig), by simp⟩

def parsedForsAuth (sig : C10Signature) : ForsAuthPaths :=
  ⟨List.ofFn (fun q : Fin 12 =>
    (⟨List.ofFn (forsAuthBytes sig q), by simp⟩ : Std.Array (Std.Array Std.U8 16#usize) 11#usize)),
    by simp⟩

theorem parsedForsSecrets_get (sig : C10Signature) (q : Fin 13) :
    (parsedForsSecrets sig).val[q.val]! = forsSecretBytes sig q := by
  simp only [parsedForsSecrets, List.getElem!_ofFn _ _ q.isLt]

theorem parsedForsAuth_get (sig : C10Signature) (q : Fin 12) (j : Fin 11) :
    ((parsedForsAuth sig).val[q.val]!).val[j.val]! = forsAuthBytes sig q j := by
  simp only [parsedForsAuth, List.getElem!_ofFn _ _ q.isLt, List.getElem!_ofFn _ _ j.isLt]

theorem fixedArray_ext {α : Type} [Inhabited α] {n : Std.Usize}
    (a b : Std.Array α n) (h : ∀ q : Fin n.val, a.val[q.val]! = b.val[q.val]!) : a = b := by
  apply Subtype.ext
  apply List.ext_getElem
  · rw [a.property, b.property]
  · intro i ha hb
    rw [← getElem!_pos a.val i ha, ← getElem!_pos b.val i hb]
    exact h ⟨i, by rw [← a.property]; exact ha⟩

theorem firmware_parse_fors_secrets_value (sig : C10Signature) (initial : ForsSecrets) :
    hypertree.verify_loop0 {start := 0#usize, «end» := 13#usize} sig 16#usize initial
      ⦃ r => r.1 = 224#usize ∧ r.2 = parsedForsSecrets sig ⦄ := by
  let* ⟨offset, secrets, ho, hs⟩ ← firmware_parse_fors_secrets sig initial
  refine ⟨UScalar.eq_of_val_eq ho, ?_⟩
  apply fixedArray_ext
  intro q
  rw [hs q, parsedForsSecrets_get]

theorem firmware_parse_fors_auth_value (sig : C10Signature) (initial : ForsAuthPaths) :
    hypertree.verify_loop1 {start := 0#usize, «end» := 12#usize} sig 224#usize initial
      ⦃ r => r.1 = 2336#usize ∧ r.2 = parsedForsAuth sig ⦄ := by
  let* ⟨offset, paths, ho, hp⟩ ← firmware_parse_fors_auth sig initial
  refine ⟨UScalar.eq_of_val_eq ho, ?_⟩
  apply fixedArray_ext
  intro q
  apply fixedArray_ext
  intro j
  have hj : j.val < 11 := by simpa using j.isLt
  exact (hp q ⟨j.val, hj⟩).trans (parsedForsAuth_get sig q ⟨j.val, hj⟩).symm
end Extracted.Equiv
