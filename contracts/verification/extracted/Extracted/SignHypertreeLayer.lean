/- The actual signer layer, including its field offsets and bounded failure. -/
import Extracted.SignLayerCrypto

open Aeneas Aeneas.Std Result ControlFlow
namespace Extracted.Equiv
open sphincs_c10
noncomputable section
set_option maxHeartbeats 200000
set_option maxRecDepth 8192
set_option pp.explicit true
attribute [local irreducible] pureWotsSign xmssRootNode xmssSigningPath
  wots.sign_with_shuffle wots.pk_from_sig merkle.build_subtree_with_auth
  merkle.verify_auth_path shuffle.ShuffleSeed.derive serializedLayer
  SphincsCVerify.Spec.Sha256Impl.sha256Bytes

def signIteration (n : Nat) : core.ops.range.Range Std.U32 :=
  { start := ⟨BitVec.ofNat 32 n⟩, «end» := 2#u32 }
def signOffset (n : Nat) : Std.Usize :=
  ⟨BitVec.ofNat UScalarTy.Usize.numBits (2336 + 836*n)⟩
def signLayerId (layer : Fin 2) : Std.U32 := ⟨BitVec.ofNat 32 layer.val⟩
def signNextTree (idx : Std.U32) : Std.U32 := ⟨BitVec.ofNat 32 (idx.val / 512)⟩
def signLeaf (idx : Std.U32) : Std.U32 := idx &&& 511#u32

theorem sign_offset_val (n : Nat) (hn : n ≤ 2) :
    (signOffset n).val = 2336 + 836*n := by
  unfold signOffset
  change (2336 + 836*n) % 2^UScalarTy.Usize.numBits = _
  apply Nat.mod_eq_of_lt
  have := System.Platform.numBits_eq
  rcases this with h | h <;> simp only [UScalarTy.numBits, h] <;> omega

theorem sign_leaf_val (idx : Std.U32) : (signLeaf idx).val = idx.val % 512 := by
  rw [signLeaf, UScalar.val_and]
  exact Nat.and_two_pow_sub_one_eq_mod idx.val 9

theorem sign_next_tree_val (idx : Std.U32) : (signNextTree idx).val = idx.val / 512 := by
  unfold signNextTree
  change (idx.val / 512) % 2^32 = _
  exact Nat.mod_eq_of_lt (lt_of_le_of_lt (Nat.div_le_self _ _) idx.hBounds)

private theorem next_sign_iteration (layer : Fin 2) :
    core.iter.range.IteratorRange.next U32.Insts.CoreIterRangeStep (signIteration layer.val) =
      .ok (some (signLayerId layer), signIteration (layer.val+1)) := by
  have hs : (signIteration layer.val).start.val = layer.val := by
    change layer.val % 2^32 = layer.val
    exact Nat.mod_eq_of_lt (by have := layer.isLt; omega)
  obtain ⟨⟨ob,it⟩,hr,hp⟩ := WP.spec_imp_exists (next_u32_spec (signIteration layer.val))
  dsimp only at hp
  rcases hp with ⟨ho,hge⟩ | ⟨j,it',heq,hj,hlt,he,hn⟩
  · have hb := layer.isLt
    change (signIteration layer.val).start.val ≥ 2 at hge
    omega
  · simp only [Prod.mk.injEq] at heq
    obtain ⟨rfl,rfl⟩ := heq
    have hj' : j = signLayerId layer := by rw [hj]; rfl
    have hi : it = signIteration (layer.val+1) := by
      cases it with
      | mk a b =>
        have ha : a = (signIteration (layer.val+1)).start := by
          apply UScalar.eq_of_val_eq
          rw [hn, hs]
          change layer.val+1 = (layer.val+1) % 2^32
          exact (Nat.mod_eq_of_lt (by have := layer.isLt; omega)).symm
        have hb : b = 2#u32 := he
        rw [ha, hb]
        rfl
    simpa only [hj', hi] using hr

private theorem sign_tree_shift (idx : Std.U32) :
    (idx >>> 9#usize) = .ok (signNextTree idx) := by
  obtain ⟨r,hr,hv,_⟩ := WP.spec_imp_exists
    (Std.U32.ShiftRight_spec idx 9#usize (by scalar_tac))
  have he : r = signNextTree idx := by
    apply UScalar.eq_of_val_eq
    rw [hv, sign_next_tree_val, Nat.shiftRight_eq_div_pow]
    simp
  simpa only [he] using hr

def pureSignLayer (seed sk : Std.Array Std.U8 32#usize) (layer : Fin 2)
    (sig : C10Signature) (current : Std.Array Std.U8 16#usize) (idx : Std.U32) :
    Result (C10Signature × Std.Array Std.U8 16#usize) := do
  let tree := UScalar.cast .U64 (signNextTree idx)
  let leaf := signLeaf idx
  let (chains,count) ← pureWotsSign seed sk (signLayerId layer) tree leaf current
  .ok (serializedLayer sig (2336+836*layer.val) chains count
      (xmssSigningPath seed sk (signLayerId layer) tree leaf),
    xmssRootNode seed sk (signLayerId layer) tree 9 0)

abbrev SignLayerTail (α : Type) := Std.Usize → Std.U32 → Std.U32 → XmssAuth →
  WotsChains → Std.U32 → Result α

def signLayerCompute {α : Type} (sk seed : Std.Array Std.U8 32#usize)
    (progress : hypertree.ProgressSink) (shuffle : sphincs_c10.shuffle.ShuffleSeed)
    (layer : Std.U32) (current : Std.Array Std.U8 16#usize) (idx_tree : Std.U32)
    (tail : SignLayerTail α) : Result α := do
  let i ← params.SUBTREE_H
  let i1 ← 1#u32 <<< i
  let i2 ← i1 - 1#u32
  let idx_leaf ← lift (idx_tree &&& i2)
  let idx_tree1 ← idx_tree >>> i
  let i3 ← layer * 33#u32
  let i4 ← 32#u32 + i3
  let pct_lo ← lift (UScalar.cast .U8 i4)
  let i5 ← layer + 1#u32
  let i6 ← i5 * 33#u32
  let i7 ← 32#u32 + i6
  let pct_hi ← lift (UScalar.cast .U8 i7)
  let i8 ← lift (UScalar.cast .U64 idx_tree1)
  let (auth_path, _) ←
    merkle.build_subtree_with_auth seed sk layer i8 idx_leaf progress
      pct_lo pct_hi
  hypertree.report progress pct_hi
  let wots_label ←
    match layer with
    | 0#uscalar =>
      ok
        (Array.make 7#usize [
           119#u8, 111#u8, 116#u8, 115#u8, 45#u8, 48#u8, 0#u8
           ] : Array Std.U8 7#usize)
    | _ =>
      ok
        (Array.make 7#usize [
           119#u8, 111#u8, 116#u8, 115#u8, 45#u8, 49#u8, 0#u8
           ] : Array Std.U8 7#usize)
  let s ← lift (Array.to_slice wots_label)
  let wots_shuffle_seed ← sphincs_c10.shuffle.ShuffleSeed.derive shuffle s
  let i9 ← lift (UScalar.cast .U64 idx_tree1)
  let (wots_sigma, count) ←
    wots.sign_with_shuffle seed sk layer i9 idx_leaf current
      wots_shuffle_seed progress pct_hi
  tail i idx_leaf idx_tree1 auth_path wots_sigma count

def signLayerFinish (seed : Std.Array Std.U8 32#usize) (layer : Std.U32)
    (sig : C10Signature) (offset : Std.Usize) (current : Std.Array Std.U8 16#usize)
    (it : core.ops.range.Range Std.U32) : SignLayerTail SignLayerResult :=
  fun height leaf tree path chains count =>
    provenLayerSerialization height sig offset chains count path (uncurry fun out off => do
      let pk ← wots.pk_from_sig seed layer (UScalar.cast .U64 tree) leaf current chains count
      let node ← merkle.verify_auth_path seed layer (UScalar.cast .U64 tree) pk leaf path
      .ok (.cont (it,out,off,node,tree)))

def signerBodyUsingCompute
    (sk seed : Std.Array Std.U8 32#usize) (progress : hypertree.ProgressSink)
    (shuffle : sphincs_c10.shuffle.ShuffleSeed) (iter : core.ops.range.Range Std.U32)
    (sig : C10Signature) (offset : Std.Usize) (current : Std.Array Std.U8 16#usize)
    (idx : Std.U32) : Result SignLayerResult := do
  let (o,it) ← core.iter.range.IteratorRange.next U32.Insts.CoreIterRangeStep iter
  match o with
  | none => .ok (.done (sig,offset,current))
  | some layer =>
    signLayerCompute sk seed progress shuffle layer current idx
      (signLayerFinish seed layer sig offset current it)

private theorem signer_body_compute_factor
    (sk seed : Std.Array Std.U8 32#usize) (progress : hypertree.ProgressSink)
    (shuffle : sphincs_c10.shuffle.ShuffleSeed) (iter : core.ops.range.Range Std.U32)
    (sig : C10Signature) (offset : Std.Usize) (current : Std.Array Std.U8 16#usize)
    (idx : Std.U32) :
    signerLayerWithSerializedFields sk progress shuffle seed iter sig offset current idx =
      signerBodyUsingCompute sk seed progress shuffle iter sig offset current idx := by
  unfold signerLayerWithSerializedFields signerLayerUsingSerialization signerBodyUsingCompute signLayerCompute signLayerFinish
  delta Aeneas.Std.uncurry
  try delta signerLayerUsingSerialization.match_1
  try delta signerLayerUsingSerialization.match_3
  try delta signerBodyUsingCompute.match_1
  try delta signLayerCompute.match_1
  simp only [lift, bind_tc_ok]

private theorem sign_layer_compute_pure {α : Type}
    (sk seed : Std.Array Std.U8 32#usize) (progress : hypertree.ProgressSink)
    (shuffle : sphincs_c10.shuffle.ShuffleSeed) (layer : Fin 2)
    (current : Std.Array Std.U8 16#usize) (idx : Std.U32) (tail : SignLayerTail α) :
    signLayerCompute sk seed progress shuffle (signLayerId layer) current idx tail =
      (do let (chains,count) ← pureWotsSign seed sk (signLayerId layer)
            (UScalar.cast .U64 (signNextTree idx)) (signLeaf idx) current
          tail 9#usize (signLeaf idx) (signNextTree idx)
            (xmssSigningPath seed sk (signLayerId layer)
              (UScalar.cast .U64 (signNextTree idx)) (signLeaf idx)) chains count) := by
  unfold signLayerCompute
  rw [serialization_subtree_height]
  simp only [bind_tc_ok]
  have hshift : (1#u32 <<< 9#usize) = .ok 512#u32 := by rfl
  have hsub : (512#u32 - 1#u32 : Result Std.U32) = .ok (511#u32) := by rfl
  rw [hshift]
  simp only [bind_tc_ok]
  rw [hsub]
  simp only [bind_tc_ok, lift]
  rw [sign_tree_shift]
  simp only [bind_tc_ok]
  have hl : (signLayerId layer).val < 2 := by
    change layer.val % 2^32 < 2
    have hb := layer.isLt
    rw [Nat.mod_eq_of_lt (by omega)]
    exact hb
  obtain ⟨i3, hi3, hv3⟩ := WP.spec_imp_exists
    (Std.U32.mul_spec (x := signLayerId layer) (y := 33#u32) (by scalar_tac))
  rw [hi3]
  simp only [bind_tc_ok]
  obtain ⟨i4, hi4, hv4⟩ := WP.spec_imp_exists
    (Std.U32.add_spec (x := 32#u32) (y := i3) (by scalar_tac))
  rw [hi4]
  simp only [bind_tc_ok]
  obtain ⟨i5, hi5, hv5⟩ := WP.spec_imp_exists
    (Std.U32.add_spec (x := signLayerId layer) (y := 1#u32) (by scalar_tac))
  rw [hi5]
  simp only [bind_tc_ok]
  obtain ⟨i6, hi6, hv6⟩ := WP.spec_imp_exists
    (Std.U32.mul_spec (x := i5) (y := 33#u32) (by scalar_tac))
  rw [hi6]
  simp only [bind_tc_ok]
  obtain ⟨i7, hi7, hv7⟩ := WP.spec_imp_exists
    (Std.U32.add_spec (x := 32#u32) (y := i6) (by scalar_tac))
  rw [hi7]
  simp only [bind_tc_ok]
  have hleaf : (signLeaf idx).val < 512 := by rw [sign_leaf_val]; omega
  have hpath := firmware_xmss_signing_path seed sk (signLayerId layer) (signLeaf idx)
    (UScalar.cast .U64 (signNextTree idx)) progress (UScalar.cast .U8 i4) (UScalar.cast .U8 i7) hleaf
  unfold signLeaf at hpath
  rw [hpath]
  simp only [bind_tc_ok, uncurry_apply_pair, hypertree.report]
  split <;> simp only [bind_tc_ok]
  all_goals
    rw [derived_wots_sign_bind]
    rfl

private theorem sign_layer_finish_pure (seed sk : Std.Array Std.U8 32#usize)
    (sig : C10Signature) (current : Std.Array Std.U8 16#usize) (idx : Std.U32)
    (layer : Fin 2) (chains : WotsChains) (count : Std.U32)
    (hcount : pureWotsSign seed sk (signLayerId layer) (UScalar.cast .U64 (signNextTree idx))
      (idx &&& 511#u32) current = .ok (chains,count)) :
    signLayerFinish seed (signLayerId layer) sig (signOffset layer.val) current
      (signIteration (layer.val+1)) 9#usize (idx &&& 511#u32) (signNextTree idx)
      (xmssSigningPath seed sk (signLayerId layer) (UScalar.cast .U64 (signNextTree idx))
        (idx &&& 511#u32)) chains count =
      .ok (.cont (signIteration (layer.val+1),
        serializedLayer sig (2336+836*layer.val) chains count
          (xmssSigningPath seed sk (signLayerId layer) (UScalar.cast .U64 (signNextTree idx))
            (idx &&& 511#u32)),
        signOffset (layer.val+1),xmssRootNode seed sk (signLayerId layer)
          (UScalar.cast .U64 (signNextTree idx)) 9 0,signNextTree idx)) := by
  unfold signLayerFinish
  simp only [provenLayerSerialization]
  have hleaf : (idx &&& 511#u32).val < 512 := by
    change (signLeaf idx).val < 512
    rw [sign_leaf_val]
    omega
  have hb : (signOffset layer.val).val + 836 ≤ 4008 := by
    rw [sign_offset_val layer.val (by have := layer.isLt; omega)]
    have := layer.isLt
    omega
  obtain ⟨⟨out,off⟩,hserialize,hoff,hout⟩ := WP.spec_imp_exists
    (firmware_serialize_layer sig (signOffset layer.val) chains count
      (xmssSigningPath seed sk (signLayerId layer) (UScalar.cast .U64 (signNextTree idx))
        (idx &&& 511#u32)) hb)
  dsimp only at hoff hout
  have hoff' : off = signOffset (layer.val+1) := by
    apply UScalar.eq_of_val_eq
    rw [hoff, sign_offset_val layer.val (by have := layer.isLt; omega),
      sign_offset_val (layer.val+1) (by have := layer.isLt; omega)]
    omega
  simp only [signerSerializeLayerHeight_nine]
  rw [hserialize]
  simp only [bind_tc_ok, uncurry_apply_pair]
  rw [pure_wots_recovery seed sk (signLayerId layer) (UScalar.cast .U64 (signNextTree idx))
    (idx &&& 511#u32) current chains count hcount]
  simp only [bind_tc_ok]
  rw [xmss_signing_path_recovery seed sk (signLayerId layer) (UScalar.cast .U64 (signNextTree idx))
    (idx &&& 511#u32) hleaf]
  simp only [bind_tc_ok, hout, hoff', sign_offset_val layer.val (by have := layer.isLt; omega)]


private theorem signer_body_start (sk seed : Std.Array Std.U8 32#usize)
    (progress : hypertree.ProgressSink) (shuffle : sphincs_c10.shuffle.ShuffleSeed)
    (sig : C10Signature) (current : Std.Array Std.U8 16#usize) (idx : Std.U32)
    (layer : Fin 2) :
    signerBodyUsingCompute sk seed progress shuffle (signIteration layer.val)
      sig (signOffset layer.val) current idx =
    signLayerCompute sk seed progress shuffle (signLayerId layer) current idx
      (signLayerFinish seed (signLayerId layer) sig (signOffset layer.val) current
        (signIteration (layer.val+1))) := by
  unfold signerBodyUsingCompute
  delta Aeneas.Std.uncurry
  try delta signerBodyUsingCompute.match_1
  try delta signerLayerUsingSerialization.match_1
  rw [next_sign_iteration]
  simp only [bind_tc_ok]

private theorem signer_body_compute_pure (sk seed : Std.Array Std.U8 32#usize)
    (progress : hypertree.ProgressSink) (shuffle : sphincs_c10.shuffle.ShuffleSeed)
    (sig : C10Signature) (current : Std.Array Std.U8 16#usize) (idx : Std.U32)
    (layer : Fin 2) :
    signerBodyUsingCompute sk seed progress shuffle (signIteration layer.val)
      sig (signOffset layer.val) current idx =
      (do let (out,node) ← pureSignLayer seed sk layer sig current idx
          .ok (.cont (signIteration (layer.val+1),out,signOffset (layer.val+1),node,signNextTree idx))) := by
  apply Eq.trans (signer_body_start sk seed progress shuffle sig current idx layer)
  apply Eq.trans (sign_layer_compute_pure sk seed progress shuffle layer current idx
    (signLayerFinish seed (signLayerId layer) sig (signOffset layer.val) current
      (signIteration (layer.val+1))))
  simp only [pureSignLayer, signLeaf, bind_assoc_eq]
  rw [bind_eq_iff]
  rintro ⟨chains,count⟩ hcount
  simp only [uncurry_apply_pair, bind_tc_ok]
  exact sign_layer_finish_pure seed sk sig current idx layer chains count hcount


theorem firmware_sign_layer_body (sk seed : Std.Array Std.U8 32#usize)
    (progress : hypertree.ProgressSink) (shuffle : sphincs_c10.shuffle.ShuffleSeed)
    (sig : C10Signature) (current : Std.Array Std.U8 16#usize) (idx : Std.U32)
    (layer : Fin 2) :
    hypertree.sign_inner_loop3.body sk progress shuffle seed (signIteration layer.val)
      sig (signOffset layer.val) current idx =
      (do let (out,node) ← pureSignLayer seed sk layer sig current idx
          .ok (.cont (signIteration (layer.val+1),out,signOffset (layer.val+1),node,signNextTree idx))) := by
  exact (signer_layer_serialization_factor sk seed progress shuffle (signIteration layer.val)
    sig (signOffset layer.val) current idx).trans
    ((signer_body_compute_factor sk seed progress shuffle (signIteration layer.val)
      sig (signOffset layer.val) current idx).trans
      (signer_body_compute_pure sk seed progress shuffle sig current idx layer))

end
end Extracted.Equiv
