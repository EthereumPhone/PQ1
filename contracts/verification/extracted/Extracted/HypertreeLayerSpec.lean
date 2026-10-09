/- The actual layer transition, preserving Rust's zero-sentinel behavior. -/
import Extracted.HypertreeParseSpec
open Aeneas Aeneas.Std Result ControlFlow
namespace Extracted.Equiv
open sphincs_c10 SphincsCVerify.Spec
set_option maxHeartbeats 4000000
set_option maxRecDepth 8192

/-- A specification-level layer using the faithful WOTS and XMSS definitions.
    A rejected WOTS computation contributes the same zero node as Rust. -/
def rawLayerRoot (seed : Std.Array Std.U8 32#usize) (sig : C10Signature)
    (layer : Fin 2) (idx : Nat) (current : ByteVec 16) : ByteVec 16 :=
  let leaf := idx % 512
  let tree := idx / 512
  let wotsPk := (Wots.pkFromSig (toSpecDigest seed) (UInt32.ofNat layer.val)
    (UInt64.ofNat tree) (UInt32.ofNat leaf) current
    (toSpecSigma (parsedLayerChains sig layer) (parsedLayerCount sig layer))).getD (ByteVec.zero 16)
  Hypertree.verifyAuthPath (toSpecDigest seed) (UInt32.ofNat layer.val)
    (UInt64.ofNat tree) wotsPk leaf ((parsedLayerAuth sig layer).val.map toSpecNode).toArray

/-- Every represented layer input terminates and advances exactly one layer.
    This is computation correspondence, including invalid WOTS target sums. -/
theorem firmware_verify_layer_body (sig : C10Signature) (seed : Std.Array Std.U8 32#usize)
    (iter : core.ops.range.Range Std.U32) (offset : Std.Usize)
    (current : Std.Array Std.U8 16#usize) (idx : Std.U32) (layer : Fin 2)
    (hstart : iter.start.val = layer.val) (hend : iter.«end».val = 2)
    (hoff : offset.val = 2336 + 836*layer.val) :
    hypertree.verify_loop3.body sig seed iter offset current idx ⦃ r =>
      ∃ it off node tree, r = .cont (it, off, node, tree) ∧
        it.start.val = layer.val + 1 ∧ it.«end».val = 2 ∧
        off.val = 3172 + 836*layer.val ∧ tree.val = idx.val / 512 ∧
        toSpecNode node = rawLayerRoot seed sig layer idx.val (toSpecNode current) ⦄ := by
  have hlayer := layer.isLt
  unfold hypertree.verify_loop3.body
  let* ⟨ob, iter1, hpost⟩ ← next_u32_spec iter
  rcases hpost with ⟨ho, hge⟩ | ⟨l, it', heq, hl, hlt, hend', hstart'⟩
  · omega
  · simp only [Prod.mk.injEq] at heq
    obtain ⟨rfl, rfl⟩ := heq
    have hlv : l.val = layer.val := by rw [hl, hstart]
    simp only [params.SUBTREE_H, params.H, params.D]
    step <;> first | scalar_tac | skip
    have hie : i = 9#usize := by apply UScalar.eq_of_val_eq; scalar_tac
    subst i
    step <;> first | scalar_tac | skip
    have hi1e : i1 = 512#u32 := by apply UScalar.eq_of_val_eq; scalar_tac
    subst i1
    step <;> first | scalar_tac | skip
    have hi2e : i2 = 511#u32 := by apply UScalar.eq_of_val_eq; scalar_tac
    subst i2
    simp only [lift]
    let* ⟨nextTree, hnextTree, _⟩ ← Std.U32.ShiftRight_spec idx 9#usize (by scalar_tac)
    have htree : nextTree.val = idx.val / 512 := by
      rw [hnextTree, Nat.shiftRight_eq_div_pow]
    have hleaf : (idx &&& 511#u32).val = idx.val % 512 := by
      rw [UScalar.val_and]
      exact Nat.and_two_pow_sub_one_eq_mod idx.val 9
    simp only [params.L]
    let* ⟨off1, chains, hoff1, hchains⟩ ← firmware_parse_layer_wots_value sig layer offset
      (Array.repeat 43#usize (Array.repeat 16#usize 0#u8)) hoff
    subst chains
    let* ⟨b0, hb0⟩ ← Array.index_usize_spec sig off1 (by scalar_tac)
    let* ⟨p1, hp1⟩ ← Std.Usize.add_spec (x := off1) (y := 1#usize) (by scalar_tac)
    let* ⟨b1, hb1⟩ ← Array.index_usize_spec sig p1 (by scalar_tac)
    let* ⟨p2, hp2⟩ ← Std.Usize.add_spec (x := off1) (y := 2#usize) (by scalar_tac)
    let* ⟨b2, hb2⟩ ← Array.index_usize_spec sig p2 (by scalar_tac)
    let* ⟨p3, hp3⟩ ← Std.Usize.add_spec (x := off1) (y := 3#usize) (by scalar_tac)
    let* ⟨b3, hb3⟩ ← Array.index_usize_spec sig p3 (by scalar_tac)
    let* ⟨authStart, hauthStart⟩ ← Std.Usize.add_spec (x := off1) (y := 4#usize) (by scalar_tac)
    let* ⟨off3, auth, hoff3, hauth⟩ ← firmware_parse_layer_xmss_value sig layer authStart
      (Array.repeat 9#usize (Array.repeat 16#usize 0#u8)) (by scalar_tac)
    subst auth
    have hcount : core.num.U32.from_be_bytes (Array.make 4#usize [b0,b1,b2,b3]) =
        parsedLayerCount sig layer := by
      unfold parsedLayerCount
      apply congrArg core.num.U32.from_be_bytes
      apply Subtype.ext
      change [b0,b1,b2,b3] = [sig.val[3024+836*layer.val]!, sig.val[3024+836*layer.val+1]!,
        sig.val[3024+836*layer.val+2]!, sig.val[3024+836*layer.val+3]!]
      rw [hb0, hb1, hb2, hb3]
      rw [← getElem!_pos sig.val off1.val (by have := sig.property; scalar_tac),
        ← getElem!_pos sig.val p1.val (by have := sig.property; scalar_tac),
        ← getElem!_pos sig.val p2.val (by have := sig.property; scalar_tac),
        ← getElem!_pos sig.val p3.val (by have := sig.property; scalar_tac)]
      rw [hoff1, hp1, hp2, hp3, hoff1]
    rw [hcount]
    let* ⟨wpk, hwpk⟩ ← firmware_pk_from_sig_matches_vendored seed l
      (UScalar.cast .U64 nextTree) (idx &&& 511#u32) current
      (parsedLayerChains sig layer) (parsedLayerCount sig layer)
    let* ⟨node, hnode⟩ ← firmware_verify_auth_path_matches_vendored seed l
      (UScalar.cast .U64 nextTree) wpk (idx &&& 511#u32) (parsedLayerAuth sig layer)
    refine ⟨iter1, off3, node, nextTree, rfl, by omega, by rw [hend']; exact hend,
      hoff3, htree, ?_⟩
    have hwide : (UScalar.cast .U64 nextTree).val = nextTree.val := by
      rw [UScalar.cast_val_eq]
      exact Nat.mod_eq_of_lt (by have h := nextTree.hBounds; scalar_tac)
    rw [hnode, hwpk, hlv, hwide, htree, hleaf]
    rfl
end Extracted.Equiv
