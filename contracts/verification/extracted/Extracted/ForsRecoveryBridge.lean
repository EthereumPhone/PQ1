/- FORS leaf and eleven-sibling recovery correspondence; computation only. -/
import Extracted.ForsRecoverySpec
import Extracted.MerkleRecoveryBridge
import Extracted.ForsRecoveryVendored
set_option maxRecDepth 8192
set_option maxHeartbeats 800000
open Aeneas Aeneas.Std Result
namespace Extracted.Equiv
open SphincsCVerify.Spec

private theorem byteVec_ext {n : Nat} {a b : ByteVec n} (h : a.data = b.data) : a = b := by
  cases a; cases b; cases h; rfl

attribute [local irreducible] Adrs.make
theorem fors_recovery_adrs (ht tree : Std.U32) (h idx : Nat)
    (hh : h < 2^32) (hi : idx < 2^32) :
    toSpecDigest (forsRecoveryAdrs ht tree h idx) =
      Adrs.forsNode (UInt64.ofNat ht.val) (UInt32.ofNat tree.val)
        (UInt32.ofNat h) (UInt32.ofNat idx) := by
  have hx := specMakeAdrs_eq_vendored 0 3 (UInt32.ofNat tree.val) 0
    (UInt32.ofNat h) (UInt32.ofNat idx) (UInt64.ofNat ht.val)
  have ht' : (UInt64.ofNat ht.val).toNat = ht.val :=
    Nat.mod_eq_of_lt (by have hb : ht.val < 2^32 := ht.hBounds; omega)
  have tr' : (UInt32.ofNat tree.val).toNat = tree.val := Nat.mod_eq_of_lt tree.hBounds
  have hh' : (UInt32.ofNat h).toNat = h := Nat.mod_eq_of_lt hh
  have hi' : (UInt32.ofNat idx).toNat = idx := Nat.mod_eq_of_lt hi
  simp only [ht', tr', hh', hi'] at hx
  change _ = specMakeAdrs 0 ht.val 3 tree.val 0 h idx at hx
  apply byteVec_ext
  apply _root_.Array.toList_inj.mp
  change (specMakeAdrs 0 ht.val 3 tree.val 0 h idx).map
    (fun n => UInt8.ofNat (⟨BitVec.ofNat 8 n⟩ : Std.U8).val) = _
  rw [← hx, List.map_map]
  have roundtrip (x : UInt8) : UInt8.ofNat (⟨BitVec.ofNat 8 x.toNat⟩ : Std.U8).val = x := by
    apply UInt8.toNat_inj.mp
    change (x.toNat % 256) % 256 = x.toNat
    have hx : x.toNat < 256 := x.toFin.isLt
    omega
  simp only [Function.comp_def, roundtrip, List.map_id']
  simp only [Adrs.forsNode, ADRS_FORS_TREE, show UInt32.ofNat 3 = 3 from rfl]

-- Keep wrong-input controls from unfolding symbolic hash and array computations.
attribute [local irreducible] th thPair Adrs.forsNode ByteVec.pad16 List.foldl List.forIn'

def forsRecoveryStep (seed : ByteVec 32) (ht : UInt64) (tree : UInt32)
    (auth : Array (ByteVec 16)) (r : MProd (ByteVec 16) Nat) (h : Nat) :
    MProd (ByteVec 16) Nat :=
  let a := Adrs.forsNode ht tree (UInt32.ofNat (h+1)) (UInt32.ofNat (r.snd/2))
  let sibling := auth.getD h (ByteVec.zero 16)
  if r.snd % 2 == 0 then
    ⟨thPair seed a (ByteVec.pad16 r.fst) (ByteVec.pad16 sibling), r.snd/2⟩
  else
    ⟨thPair seed a (ByteVec.pad16 sibling) (ByteVec.pad16 r.fst), r.snd/2⟩

theorem fors_recovery_eq_foldl (seed : ByteVec 32) (ht : UInt64) (tree idx : UInt32)
    (secret : ByteVec 16) (auth : Array (ByteVec 16)) :
    Fors.reconstructRoot seed ht tree idx secret auth =
      ((List.range' 0 A).foldl (forsRecoveryStep seed ht tree auth)
        ⟨th seed (Adrs.forsNode ht tree 0 idx) (ByteVec.pad16 secret), idx.toNat⟩).fst := by
  rw [Fors.reconstructRoot]
  set_option linter.deprecated false in
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, Nat.sub_zero,
    Nat.add_sub_cancel, Nat.div_one, Id.run, Bind.bind, Pure.pure, Id.instMonad]
  have hf := List.forIn_pure_yield_eq_foldl (m := Id) (l := List.range' 0 A)
    (fun h r => forsRecoveryStep seed ht tree auth r h)
    (⟨th seed (Adrs.forsNode ht tree 0 idx) (ByteVec.pad16 secret), idx.toNat⟩ : MProd (ByteVec 16) Nat)
  have hn := congrArg MProd.fst hf
  simpa only [forsRecoveryStep, apply_ite, Bind.bind, Pure.pure, Id.instMonad] using hn

private theorem fors_recovery_pad (v : Std.Array Std.U8 16#usize) :
    toSpecDigest (pad16p v) = ByteVec.pad16 (toSpecNode v) := by
  have h : pad16p v = pad16Pure v := by unfold pad16Pure; rfl
  rw [h, recovery_pad]

private theorem fors_recovery_pair (seed : Std.Array Std.U8 32#usize)
    (ht tree : Std.U32) (h idx : Nat) (hh : h+1 < 2^32) (hi : idx < 2^32)
    (left right : Std.Array Std.U8 16#usize) :
    toSpecNode (th_pair_pure seed (forsRecoveryAdrs ht tree (h+1) idx) (pad16p left) (pad16p right)) =
      thPair (toSpecDigest seed)
        (Adrs.forsNode (UInt64.ofNat ht.val) (UInt32.ofNat tree.val)
          (UInt32.ofNat (h+1)) (UInt32.ofNat idx))
        (ByteVec.pad16 (toSpecNode left)) (ByteVec.pad16 (toSpecNode right)) := by
  rw [merkle_th_pair, fors_recovery_adrs _ _ _ _ hh hi, fors_recovery_pad, fors_recovery_pad]

private theorem fors_recovery_fold (seed : Std.Array Std.U8 32#usize)
    (ht tree : Std.U32)
    (auth : Std.Array (Std.Array Std.U8 16#usize) 11#usize)
    (n h : Nat) (node : Std.Array Std.U8 16#usize) (idx : Nat)
    (hb : h + n ≤ 11) (hi : idx < 2^32) :
    ((List.range' h n).foldl
      (forsRecoveryStep (toSpecDigest seed) (UInt64.ofNat ht.val) (UInt32.ofNat tree.val)
        (auth.val.map toSpecNode).toArray) ⟨toSpecNode node, idx⟩).fst =
      toSpecNode (forsRecoveryFold seed ht tree ((auth.val.drop h).take n) node idx h) := by
  have hlen : auth.val.length = 11 := by simpa using auth.property
  induction n generalizing h node idx with
  | zero => simp [forsRecoveryFold]
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
      th_pair_pure seed (forsRecoveryAdrs ht tree (h+1) (idx/2)) (pad16p node) (pad16p auth.val[h])
      else th_pair_pure seed (forsRecoveryAdrs ht tree (h+1) (idx/2)) (pad16p auth.val[h]) (pad16p node)
    have hstep : forsRecoveryStep (toSpecDigest seed) (UInt64.ofNat ht.val) (UInt32.ofNat tree.val)
        (auth.val.map toSpecNode).toArray ⟨toSpecNode node, idx⟩ h =
        ⟨toSpecNode next, idx/2⟩ := by
      have hx : idx/2 < 2^32 := by omega
      have hh32 : h+1 < 2^32 := by omega
      by_cases hp : idx % 2 = 0
      · simp only [forsRecoveryStep, Nat.beq_eq_true_eq, hp, if_true, hsib, next]
        rw [fors_recovery_pair _ _ _ _ _ hh32 hx]
      · simp only [forsRecoveryStep, Nat.beq_eq_true_eq, hp, if_false, hsib, next]
        rw [fors_recovery_pair _ _ _ _ _ hh32 hx]
    rw [List.range'_succ, List.foldl_cons, hstep, hd]
    exact ih (h+1) next (idx/2) (by omega) (by omega)

/-- All represented inputs agree; out-of-range leaf indices are computation claims. -/
theorem firmware_fors_recovery_matches_vendored (seed : Std.Array Std.U8 32#usize)
    (ht tree idx : Std.U32) (secret : Std.Array Std.U8 16#usize)
    (auth : Std.Array (Std.Array Std.U8 16#usize) 11#usize) :
    sphincs_c10.hypertree.reconstruct_fors_root seed ht tree idx secret auth ⦃ r =>
      toSpecNode r = Fors.reconstructRoot (toSpecDigest seed) (UInt64.ofNat ht.val)
        (UInt32.ofNat tree.val) (UInt32.ofNat idx.val) (toSpecNode secret)
        (auth.val.map toSpecNode).toArray ⦄ := by
  let* ⟨r, hr⟩ ← fors_recovery_spec seed ht tree idx secret auth
  rw [hr, fors_recovery_eq_foldl]
  have hi : (UInt32.ofNat idx.val).toNat = idx.val := Nat.mod_eq_of_lt idx.hBounds
  have leaf : toSpecNode (th_pure seed (forsRecoveryAdrs ht tree 0 idx.val) (pad16p secret)) =
      th (toSpecDigest seed) (Adrs.forsNode (UInt64.ofNat ht.val) (UInt32.ofNat tree.val)
        0 (UInt32.ofNat idx.val)) (ByteVec.pad16 (toSpecNode secret)) := by
    rw [recovery_th, fors_recovery_adrs _ _ _ _ (by decide) idx.hBounds, fors_recovery_pad]
    rfl
  rw [hi, ← leaf]
  have hlen : auth.val.length = 11 := by simpa using auth.property
  have h := fors_recovery_fold seed ht tree auth 11 0
    (th_pure seed (forsRecoveryAdrs ht tree 0 idx.val) (pad16p secret)) idx.val (by omega) idx.hBounds
  simpa only [List.drop_zero, List.take_of_length_le (by omega : auth.val.length ≤ 11), A] using h.symm

end Extracted.Equiv
