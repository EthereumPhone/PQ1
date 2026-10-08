/- XMSS authentication-path correspondence to the verifier specification.
   This proves computation, not membership or cryptographic hardness. -/
import Extracted.MerkleVerifySpec
import Extracted.WotsRecoveryBridge
import Extracted.MerkleRecoveryVendored

set_option maxRecDepth 8192
set_option maxHeartbeats 800000
open Aeneas Aeneas.Std Result
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes

namespace Extracted.Equiv
open SphincsCVerify.Spec

private theorem byteVec_ext {n : Nat} {a b : ByteVec n} (h : a.data = b.data) : a = b := by
  cases a; cases b; cases h; rfl

private theorem merkle_sha (data : List Std.U8) :
    (toSpecDigest (sha256_pure data)).data =
      Sha256Impl.sha256Bytes (Sha256Pure.toUInt8Array data) := by
  have roundtrip (bytes : Array UInt8) :
      (bytes.toList.map Sha256Pure.ofUInt8 |>.map (fun b => UInt8.ofNat b.val)).toArray = bytes := by
    rw [List.map_map]
    have h : (fun b : UInt8 => UInt8.ofNat (Sha256Pure.ofUInt8 b).val) = id := by
      funext b
      simp [Sha256Pure.ofUInt8, UScalar.val]
    simp only [Function.comp_def]
    rw [h]
    simp
  change ((sha256_pure data).val.map (fun b => UInt8.ofNat b.val)).toArray = _
  rw [sha256_pure_val]
  exact roundtrip _

theorem merkle_th_pair (seed adrs left right : Std.Array Std.U8 32#usize) :
    toSpecNode (th_pair_pure seed adrs left right) =
      thPair (toSpecDigest seed) (toSpecDigest adrs) (toSpecDigest left) (toSpecDigest right) := by
  rw [th_pair_pure_def, recovery_truncate]
  unfold thPair
  congr 1
  apply byteVec_ext
  rw [merkle_sha, sha256_eq_impl]
  simp [sha256_impl, ByteSeg.flatten, ByteSeg.ofByteVec, toSpecDigest,
    Sha256Pure.toUInt8Array, List.map_append, List.append_assoc]

theorem firmware_th_pair_matches_vendored (seed adrs left right : Std.Array Std.U8 32#usize) :
    sphincs_c10.hash.th_pair seed adrs left right ⦃ r =>
      toSpecNode r = thPair (toSpecDigest seed) (toSpecDigest adrs)
        (toSpecDigest left) (toSpecDigest right) ⦄ := by
  let* ⟨r, hr⟩ ← sphincs_c10.hash.th_pair_spec seed adrs left right
  rw [hr]
  exact merkle_th_pair seed adrs left right

attribute [local irreducible] Adrs.make

private theorem merkle_tree_adrs (layer : Std.U32) (tree : Std.U64) (h pidx : Nat)
    (hh : h + 1 < 2^32) (hi : pidx < 2^32) :
    toSpecDigest (treeAdrs layer tree h pidx) =
      Adrs.treeNode (UInt32.ofNat layer.val) (UInt64.ofNat tree.val)
        (UInt32.ofNat (h + 1)) (UInt32.ofNat pidx) := by
  have hx := specMakeAdrs_eq_vendored (UInt32.ofNat layer.val) 2 0 0
    (UInt32.ofNat (h+1)) (UInt32.ofNat pidx) (UInt64.ofNat tree.val)
  have hl : (UInt32.ofNat layer.val).toNat = layer.val := by
    change layer.val % 2^32 = layer.val
    exact Nat.mod_eq_of_lt layer.hBounds
  have ht : (UInt64.ofNat tree.val).toNat = tree.val := by
    change tree.val % 2^64 = tree.val
    exact Nat.mod_eq_of_lt tree.hBounds
  have hh' : (UInt32.ofNat (h+1)).toNat = h+1 := Nat.mod_eq_of_lt hh
  have hi' : (UInt32.ofNat pidx).toNat = pidx := Nat.mod_eq_of_lt hi
  simp only [hl, ht, hh', hi'] at hx
  change _ = specMakeAdrs layer.val tree.val 2 0 0 (h+1) pidx at hx
  apply byteVec_ext
  apply _root_.Array.toList_inj.mp
  change (specMakeAdrs layer.val tree.val 2 0 0 (h+1) pidx).map
    (fun n => UInt8.ofNat (⟨BitVec.ofNat 8 n⟩ : Std.U8).val) = _
  rw [← hx, List.map_map]
  have roundtrip (x : UInt8) : UInt8.ofNat (⟨BitVec.ofNat 8 x.toNat⟩ : Std.U8).val = x := by
    apply UInt8.toNat_inj.mp
    change (x.toNat % 256) % 256 = x.toNat
    have hx : x.toNat < 256 := x.toFin.isLt
    omega
  simp only [Function.comp_def, roundtrip, List.map_id']
  simp only [Adrs.treeNode, ADRS_TREE, show UInt32.ofNat 2 = 2 from rfl]

-- Congruence uses the fold theorem rather than expanding symbolic hash loops.
attribute [local irreducible] thPair Adrs.treeNode
  List.foldl List.forIn' ByteVec.pad16

def merkleStep (seed : ByteVec 32) (layer : UInt32) (tree : UInt64)
    (authPath : Array (ByteVec 16)) (acc : MProd Nat (ByteVec 16)) (h : Nat) :
    MProd Nat (ByteVec 16) :=
  let pathIdx := acc.fst
  let node := acc.snd
  let parentIdx := pathIdx / 2
  let adrs := SphincsCVerify.Spec.Adrs.treeNode layer tree (UInt32.ofNat (h + 1)) (UInt32.ofNat parentIdx)
  let sibling := authPath.getD h (ByteVec.zero 16)
  if pathIdx % 2 == 0 then
    ⟨parentIdx, SphincsCVerify.Spec.thPair seed adrs (ByteVec.pad16 node) (ByteVec.pad16 sibling)⟩
  else
    ⟨parentIdx, SphincsCVerify.Spec.thPair seed adrs (ByteVec.pad16 sibling) (ByteVec.pad16 node)⟩

/-- **`verifyAuthPath` as a fold.** The spec XMSS subtree-root reconstruction is the
    second component (`.snd` = node) of folding `merkleStep` over `[0, SubtreeH)` from
    `⟨leafIdx, leafNode⟩` (the WOTS public key as the leaf). Same `forIn → foldl`
    collapse as `reconstructRoot_eq_foldl`. -/
theorem merkle_verifyAuthPath_eq_foldl
    (seed : ByteVec 32) (layer : UInt32) (tree : UInt64)
    (leafNode : ByteVec 16) (leafIdx : Nat) (authPath : Array (ByteVec 16)) :
    SphincsCVerify.Spec.Hypertree.verifyAuthPath seed layer tree leafNode leafIdx authPath
      = ((List.range' 0 SphincsCVerify.Spec.SubtreeH).foldl (merkleStep seed layer tree authPath)
          ⟨leafIdx, leafNode⟩).snd := by
  rw [SphincsCVerify.Spec.Hypertree.verifyAuthPath]
  set_option linter.deprecated false in
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, Nat.sub_zero, Nat.add_sub_cancel,
    Nat.div_one, Id.run, Bind.bind, Pure.pure, Id.instMonad]
  have hf := List.forIn_pure_yield_eq_foldl (m := Id) (l := List.range' 0 SubtreeH)
    (fun h r => merkleStep seed layer tree authPath r h) (⟨leafIdx, leafNode⟩ : MProd Nat (ByteVec 16))
  have hn := congrArg MProd.snd hf
  simpa only [merkleStep, apply_ite, Bind.bind, Pure.pure, Id.instMonad] using hn


private theorem merkle_pad (v : Std.Array Std.U8 16#usize) :
    toSpecDigest (pad16p v) = ByteVec.pad16 (toSpecNode v) := by
  have h : pad16p v = pad16Pure v := by unfold pad16Pure; rfl
  rw [h, recovery_pad]

private theorem merkle_pair_pad (seed : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (h pidx : Nat)
    (hh : h + 1 < 2^32) (hi : pidx < 2^32)
    (left right : Std.Array Std.U8 16#usize) :
    toSpecNode (th_pair_pure seed (treeAdrs layer tree h pidx) (pad16p left) (pad16p right)) =
      thPair (toSpecDigest seed)
        (Adrs.treeNode (UInt32.ofNat layer.val) (UInt64.ofNat tree.val)
          (UInt32.ofNat (h+1)) (UInt32.ofNat pidx))
        (ByteVec.pad16 (toSpecNode left)) (ByteVec.pad16 (toSpecNode right)) := by
  rw [merkle_th_pair, merkle_tree_adrs _ _ _ _ hh hi, merkle_pad, merkle_pad]

private theorem merkle_fold (seed : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64)
    (auth : Std.Array (Std.Array Std.U8 16#usize) 9#usize)
    (n h : Nat) (node : Std.Array Std.U8 16#usize) (idx : Nat)
    (hb : h + n ≤ 9) (hi : idx < 2^32) :
    ((List.range' h n).foldl
      (merkleStep (toSpecDigest seed) (UInt32.ofNat layer.val) (UInt64.ofNat tree.val)
        (auth.val.map toSpecNode).toArray) ⟨idx, toSpecNode node⟩).snd =
      toSpecNode (authFold seed layer tree ((auth.val.drop h).take n) node idx h) := by
  have hlen : auth.val.length = 9 := by simpa using auth.property
  induction n generalizing h node idx with
  | zero => simp [authFold]
  | succ n ih =>
    have hh : h < auth.val.length := by omega
    have hd : (auth.val.drop h).take (n+1) =
        auth.val[h] :: (auth.val.drop (h+1)).take n := by
      rw [← List.cons_getElem_drop_succ (l := auth.val) (n := h) (h := hh)]
      rfl
    have hsib : (auth.val.map toSpecNode).toArray.getD h (ByteVec.zero 16) =
        toSpecNode auth.val[h] := by
      simp [Array.getD_eq_getD_getElem?, List.getElem?_eq_getElem hh, hh]
    let next := if idx % 2 = 0 then
      th_pair_pure seed (treeAdrs layer tree h (idx/2)) (pad16p node) (pad16p auth.val[h])
      else th_pair_pure seed (treeAdrs layer tree h (idx/2)) (pad16p auth.val[h]) (pad16p node)
    have hstep : merkleStep (toSpecDigest seed) (UInt32.ofNat layer.val) (UInt64.ofNat tree.val)
        (auth.val.map toSpecNode).toArray ⟨idx, toSpecNode node⟩ h =
        ⟨idx/2, toSpecNode next⟩ := by
      have hx : idx/2 < 2^32 := by omega
      have hh32 : h+1 < 2^32 := by omega
      by_cases hp : idx % 2 = 0
      · simp only [merkleStep, Nat.beq_eq_true_eq, hp, if_true, hsib, next]
        rw [merkle_pair_pad _ _ _ _ _ hh32 hx]
      · simp only [merkleStep, Nat.beq_eq_true_eq, hp, if_false, hsib, next]
        rw [merkle_pair_pad _ _ _ _ _ hh32 hx]
    rw [List.range'_succ, List.foldl_cons, hstep, hd]
    exact ih (h+1) next (idx/2) (by omega) (by omega)

/-- The actual extracted nine-level recovery agrees for every represented input.
    Indices outside 0..511 are computations, not claims of subtree membership. -/
theorem firmware_verify_auth_path_matches_vendored (seed : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (leaf : Std.Array Std.U8 16#usize)
    (idx : Std.U32) (auth : Std.Array (Std.Array Std.U8 16#usize) 9#usize) :
    sphincs_c10.merkle.verify_auth_path seed layer tree leaf idx auth ⦃ r =>
      toSpecNode r = Hypertree.verifyAuthPath (toSpecDigest seed)
        (UInt32.ofNat layer.val) (UInt64.ofNat tree.val) (toSpecNode leaf) idx.val
        (auth.val.map toSpecNode).toArray ⦄ := by
  let* ⟨r, hr⟩ ← verify_auth_path_spec seed layer tree leaf idx auth
  rw [hr, merkle_verifyAuthPath_eq_foldl]
  have hlen : auth.val.length = 9 := by simpa using auth.property
  have h := merkle_fold seed layer tree auth 9 0 leaf idx.val (by omega) idx.hBounds
  simpa only [List.drop_zero, List.take_of_length_le (by omega : auth.val.length ≤ 9),
    SubtreeH] using h.symm


end Extracted.Equiv
