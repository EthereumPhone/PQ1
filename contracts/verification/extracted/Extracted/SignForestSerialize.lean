/- Actual FORS wire serialization, including the tree-major path ordering. -/
import Extracted.SignWriteSpec
import Extracted.SignForestFactor
open Aeneas Aeneas.Std Result ControlFlow
namespace Extracted.Equiv
open sphincs_c10
set_option maxHeartbeats 1000000
set_option maxRecDepth 8192

def forestPathBytes (paths : ForsAuthPaths) (i : Nat) : Std.U8 :=
  blockBytes (fun h => (paths.val[i/176]!).val[h]!) (i%176)

theorem forestPathBytes_at (paths : ForsAuthPaths) (t i : Nat) (hi : i < 176) :
    forestPathBytes paths (176*t+i) =
      blockBytes (fun h => (paths.val[t]!).val[h]!) i := by
  have hd : (176*t+i)/176 = t := by omega
  have hm : (176*t+i)%176 = i := by omega
  simp only [forestPathBytes, hd, hm]

@[step] theorem firmware_write_fors_auth (sig : C10Signature) (offset : Std.Usize)
    (paths : ForsAuthPaths) (hb : offset.val+2112 ≤ 4008) :
    hypertree.sign_inner_loop2 12#usize sig offset paths 0#usize ⦃ r =>
      r.2.val = offset.val+2112 ∧
      SignatureWrites sig r.1 offset.val 2112 (forestPathBytes paths) ⦄ := by
  unfold hypertree.sign_inner_loop2
  apply loop.spec_decr_nat
    (measure := fun s : SignWriteState => 12-s.2.2.val)
    (inv := fun s : SignWriteState => s.2.2.val ≤ 12 ∧
      s.2.1.val = offset.val+176*s.2.2.val ∧
      SignatureWrites sig s.1 offset.val (176*s.2.2.val) (forestPathBytes paths))
  · rintro ⟨current,off,t⟩ ⟨ht,ho,hw⟩
    simp only at ht ho hw
    dsimp only
    unfold hypertree.sign_inner_loop2.body
    split
    · rename_i hlt
      have htv : t.val < 12 := by scalar_tac
      let* ⟨out,off',ho',hw'⟩ ← firmware_write_fors_path current off t paths htv (by omega)
      step* <;> first | scalar_tac | skip
      refine ⟨by omega, by omega, ?_, by omega⟩
      have hh := signatureWrites_congr current out off.val 176 _
        (fun i => forestPathBytes paths (176*t.val+i)) hw'
        (fun i hi => (forestPathBytes_at paths t.val i hi).symm)
      rw [ho] at hh
      have ha := signatureWrites_append sig current out offset.val (176*t.val) 176
        (forestPathBytes paths) hw hh
      simpa only [show 176*t1.val = 176*t.val+176 by omega] using ha
    · rename_i hge
      have he : t.val = 12 := by scalar_tac
      simp only [WP.spec_ok]
      exact ⟨by omega, by simpa only [he] using hw⟩
  · exact ⟨by simp, by simp, by simpa using signatureWrites_empty sig offset.val (forestPathBytes paths)⟩

def forestBytes (secrets : ForsSecrets) (paths : ForsAuthPaths) (i : Nat) : Std.U8 :=
  if i < 208 then blockBytes (fun t => secrets.val[t]!) i
  else forestPathBytes paths (i-208)

def serializedForest (sig : C10Signature) (secrets : ForsSecrets) (paths : ForsAuthPaths) :
    C10Signature := signatureOverwrite sig 16 2320 (forestBytes secrets paths)

/-- This is precisely the two consecutive loop calls in the actual signer. -/
def signerSerializeForest (sig : C10Signature) (secrets : ForsSecrets) (paths : ForsAuthPaths) :
    Result (C10Signature × Std.Usize) := do
  let (sig1,off1) ← hypertree.sign_inner_loop1 sig 16#usize secrets 0#usize
  hypertree.sign_inner_loop2 12#usize sig1 off1 paths 0#usize

@[step] theorem firmware_serialize_forest (sig : C10Signature)
    (secrets : ForsSecrets) (paths : ForsAuthPaths) :
    signerSerializeForest sig secrets paths ⦃ r =>
      r = (serializedForest sig secrets paths, 2336#usize) ⦄ := by
  unfold signerSerializeForest
  let* ⟨mid,off1,ho1,hw1⟩ ← firmware_write_fors_secrets sig 16#usize secrets (by decide)
  let* ⟨out,off2,ho2,hw2⟩ ← firmware_write_fors_auth mid off1 paths (by scalar_tac)
  have first := signatureWrites_congr sig mid 16 208 _ (forestBytes secrets paths) hw1
    (fun i hi => by simp only [forestBytes, if_pos hi])
  have next := signatureWrites_congr mid out off1.val 2112 _
    (fun i => forestBytes secrets paths (208+i)) hw2
    (fun i _ => by simp only [forestBytes, if_neg (by omega : ¬208+i < 208), Nat.add_sub_cancel_left])
  have ho1' : off1.val = 224 := by simpa using ho1
  rw [ho1'] at next
  have all := signatureWrites_append sig mid out 16 208 2112 (forestBytes secrets paths) first next
  have hs := signatureWrites_eq sig out 16 2320 (forestBytes secrets paths) all
  have hoff : off2 = 2336#usize := by apply UScalar.eq_of_val_eq; scalar_tac
  exact ⟨hs, hoff⟩

theorem serializedForest_secret (sig : C10Signature) (secrets : ForsSecrets)
    (paths : ForsAuthPaths) (t : Fin 13) :
    forsSecretBytes (serializedForest sig secrets paths) t = secrets.val[t.val]! := by
  unfold forsSecretBytes
  apply signatureNode_eq
  intro i
  have ht := t.isLt
  have hi := i.isLt
  have hpos : 16+16*t.val+i.val < 4008 := by omega
  have h := signatureOverwrite_spec sig 16 2320 (forestBytes secrets paths)
    ⟨16+16*t.val+i.val,hpos⟩
  change (serializedForest sig secrets paths).val[16+16*t.val+i.val]! = _
  unfold serializedForest
  dsimp only at h
  rw [h, if_pos (by constructor <;> omega)]
  simp only [forestBytes, show 16+16*t.val+i.val-16 = 16*t.val+i.val by omega,
    if_pos (by omega : 16*t.val+i.val < 208), blockBytes_at _ _ _ hi]

theorem serializedForest_path (sig : C10Signature) (secrets : ForsSecrets)
    (paths : ForsAuthPaths) (t : Fin 12) (h : Fin 11) :
    forsAuthBytes (serializedForest sig secrets paths) t h = (paths.val[t.val]!).val[h.val]! := by
  unfold forsAuthBytes
  apply signatureNode_eq
  intro i
  have ht := t.isLt
  have hh := h.isLt
  have hi := i.isLt
  have hpos : 224+176*t.val+16*h.val+i.val < 4008 := by omega
  have hw := signatureOverwrite_spec sig 16 2320 (forestBytes secrets paths)
    ⟨224+176*t.val+16*h.val+i.val,hpos⟩
  change (serializedForest sig secrets paths).val[224+176*t.val+16*h.val+i.val]! = _
  unfold serializedForest
  dsimp only at hw
  rw [hw, if_pos (by constructor <;> omega)]
  simp only [forestBytes, if_neg (by omega : ¬224+176*t.val+16*h.val+i.val-16 < 208),
    show 224+176*t.val+16*h.val+i.val-16-208 = 176*t.val+(16*h.val+i.val) by omega,
    forestPathBytes_at _ _ _ (by omega : 16*h.val+i.val < 176), blockBytes_at _ _ _ hi]

theorem serializedForest_preserves (sig : C10Signature) (secrets : ForsSecrets)
    (paths : ForsAuthPaths) (j : Fin 4008) (hj : j.val < 16 ∨ 2336 ≤ j.val) :
    (serializedForest sig secrets paths).val[j.val]! = sig.val[j.val]! := by
  unfold serializedForest
  rw [signatureOverwrite_spec sig 16 2320 (forestBytes secrets paths) j, if_neg (by omega)]

theorem serializedForest_fields (sig : C10Signature) (secrets : ForsSecrets)
    (paths : ForsAuthPaths) :
    parsedForsSecrets (serializedForest sig secrets paths) = secrets ∧
    parsedForsAuth (serializedForest sig secrets paths) = paths := by
  constructor
  · apply fixedArray_ext
    intro t
    rw [parsedForsSecrets_get, serializedForest_secret]
  · apply fixedArray_ext
    intro t
    apply fixedArray_ext
    intro h
    rw [parsedForsAuth_get, serializedForest_path]

end Extracted.Equiv
