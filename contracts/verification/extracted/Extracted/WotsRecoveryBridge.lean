/- WOTS recovery correspondence, preserving the verifier's explicit rejection
   and Rust's zero-node sentinel. The supplied SHA backend remains a boundary. -/
import Extracted.PkFromSigSpec
import Extracted.WotsSpecBridge
import Extracted.SpecBridge
import Extracted.WotsRecoveryVendored

set_option maxRecDepth 8192
set_option maxHeartbeats 800000

open Aeneas Aeneas.Std Result
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes

namespace Extracted.Equiv
open SphincsCVerify.Spec

def toSpecNode (node : Std.Array Std.U8 16#usize) : ByteVec 16 :=
  ⟨(node.val.map (fun b => UInt8.ofNat b.val)).toArray, by
    simpa using node.property⟩

private theorem byteVec_ext {n : Nat} {a b : ByteVec n} (h : a.data = b.data) : a = b := by
  cases a; cases b; cases h; rfl

theorem recovery_pad (x : Std.Array Std.U8 16#usize) :
    toSpecDigest (pad16Pure x) = ByteVec.pad16 (toSpecNode x) := by
  apply byteVec_ext
  simp [toSpecDigest, pad16Pure_val, toSpecNode, ByteVec.pad16,
    ByteVec.cast, ByteVec.append, ByteVec.zero]

theorem recovery_truncate (x : Std.Array Std.U8 32#usize) :
    toSpecNode (_root_.truncate16 x) = ByteVec.truncate16 (toSpecDigest x) := by
  apply byteVec_ext
  simp [toSpecNode, truncate16_val, ByteVec.truncate16, ByteVec.take, toSpecDigest]

private theorem recovery_sha (data : List Std.U8) :
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

theorem recovery_th (seed adrs x : Std.Array Std.U8 32#usize) :
    toSpecNode (th_pure seed adrs x) =
      th (toSpecDigest seed) (toSpecDigest adrs) (toSpecDigest x) := by
  rw [th_pure_def, recovery_truncate]
  unfold th
  congr 1
  apply byteVec_ext
  rw [recovery_sha, sha256_eq_impl]
  simp [sha256_impl, ByteSeg.flatten, ByteSeg.ofByteVec, toSpecDigest,
    Sha256Pure.toUInt8Array, List.map_append, List.append_assoc]

private theorem flatten_segments (vs : List (Std.Array Std.U8 16#usize)) :
    ByteSeg.flatten (vs.map (fun v => ByteSeg.ofByteVec (ByteVec.pad16 (toSpecNode v)))) =
      Sha256Pure.toUInt8Array ((vs.map (fun v => (pad16Pure v).val)).flatten) := by
  have aux (xs : List (Std.Array Std.U8 16#usize)) (acc : Array UInt8) :
      (xs.map (fun v => ByteSeg.ofByteVec (ByteVec.pad16 (toSpecNode v)))).foldl
        (fun a seg => a ++ seg.bytes.data) acc =
      acc ++ Sha256Pure.toUInt8Array ((xs.map (fun v => (pad16Pure v).val)).flatten) := by
    induction xs generalizing acc with
    | nil => simp [Sha256Pure.toUInt8Array]
    | cons v vs ih =>
      simp only [List.map_cons, List.foldl_cons, List.flatten_cons]
      rw [ih]
      simp only [ByteSeg.ofByteVec]
      rw [← recovery_pad]
      simp [toSpecDigest, Sha256Pure.toUInt8Array, List.map_append, Array.append_assoc]
  simpa [ByteSeg.flatten] using aux vs #[]

theorem recovery_th_multi (seed adrs : Std.Array Std.U8 32#usize)
    (vs : Slice (Std.Array Std.U8 16#usize)) :
    toSpecNode (th_multi_pure seed adrs vs) =
      thMulti (toSpecDigest seed) (toSpecDigest adrs) (vs.val.map toSpecNode) := by
  rw [th_multi_pure_def, recovery_truncate]
  unfold thMulti
  congr 1
  apply byteVec_ext
  rw [recovery_sha, sha256_eq_impl]
  unfold sha256_impl
  apply congrArg Sha256Impl.sha256Bytes
  simp only [List.map_map, Function.comp_def]
  rw [show ByteSeg.flatten
      ([ByteSeg.ofByteVec (toSpecDigest seed), ByteSeg.ofByteVec (toSpecDigest adrs)] ++
       vs.val.map (fun v => ByteSeg.ofByteVec (ByteVec.pad16 (toSpecNode v)))) =
      (toSpecDigest seed).data ++ (toSpecDigest adrs).data ++
       ByteSeg.flatten (vs.val.map (fun v => ByteSeg.ofByteVec (ByteVec.pad16 (toSpecNode v)))) from by
        unfold ByteSeg.flatten
        simp only [List.foldl_append, List.foldl_cons, List.foldl_nil, ByteSeg.ofByteVec,
          Array.empty_append]
        generalize (vs.val.map (fun v => ByteSeg.ofByteVec (ByteVec.pad16 (toSpecNode v)))) = xs
        have h (xs : List ByteSeg) (acc : Array UInt8) :
            xs.foldl (fun a seg => a ++ seg.bytes.data) acc =
              acc ++ xs.foldl (fun a seg => a ++ seg.bytes.data) #[] := by
          induction xs generalizing acc with
          | nil => simp
          | cons x xs ih => simp only [List.foldl_cons, Array.empty_append]; rw [ih, ih x.bytes.data]; simp [Array.append_assoc]
        exact h _ _]
  rw [flatten_segments]
  simp [Sha256Pure.toUInt8Array, toSpecDigest, List.map_append]

private theorem recovery_u32be (n : Nat) (hn : n < 2^32) :
    ((u32beBytes n).map (fun b => UInt8.ofNat b.val)).toArray =
      (ByteVec.ofU32BE (UInt32.ofNat n)).data := by
  have byte (m : Nat) : UInt8.ofNat (m % 256) = UInt8.ofNat m &&& 255 := by
    apply UInt8.toNat_inj.mp
    change (m % 256) % 256 = (m % 256) &&& 255
    rw [show (255 : Nat) = 2^8 - 1 from rfl, Nat.and_two_pow_sub_one_eq_mod]
  have hn' : n < 4294967296 := hn
  have scalar_byte (m : Nat) : (⟨BitVec.ofNat 8 m⟩ : Std.U8).val = m % 256 := rfl
  simp [u32beBytes, ByteVec.ofU32BE, scalar_byte, Nat.mod_eq_of_lt hn', byte]

theorem recovery_chain_adrs (a : Std.Array Std.U8 32#usize) (pos : Nat)
    (hp : pos < 2^32) :
    toSpecDigest (chainAdrs a pos) = Adrs.setChainPos (toSpecDigest a) (UInt32.ofNat pos) := by
  apply byteVec_ext
  have hlen : a.val.length = 32 := by simpa using a.property
  have hbytes := congrArg _root_.Array.toList (recovery_u32be pos hp)
  simp only [List.toList_toArray] at hbytes
  simp [toSpecDigest, chainAdrs_val, List.map_append, Adrs.setChainPos,
    ByteVec.cast, ByteVec.append, hbytes, List.take_of_length_le (show
      (List.drop 28 (List.map (fun b => UInt8.ofNat b.val) a.val)).length ≤ 4 by
        simp [hlen])]

def wotsChainFwdStep (seed : ByteVec 32) (a : SphincsCVerify.Spec.Adrs) (startPos : Nat)
    (cur : ByteVec 16) (j : Nat) : ByteVec 16 :=
  SphincsCVerify.Spec.th seed (SphincsCVerify.Spec.Adrs.setChainPos a (UInt32.ofNat (startPos + j))) (ByteVec.pad16 cur)

/-- **`chainHash.aux` is a forward window fold.** Running the back-peel `aux m current`
    equals folding `wotsChainFwdStep` over the forward window `[steps-m, steps)`. By
    induction on `m` using the FRONT-cons of `range'` (`range'_succ`): `aux`'s front step
    (`pos = startPos + (steps-1-m)` for the `m+1` call) lines up with `range' (steps-m-1)
    (m+1)`'s head `steps-m-1`. Both index identities are `omega`. -/
theorem chainHash_aux_eq_fwd (seed : ByteVec 32) (a : SphincsCVerify.Spec.Adrs) (startPos steps : Nat) :
    ∀ m, m ≤ steps → ∀ current,
      SphincsCVerify.Spec.chainHash.aux seed a startPos steps m current
        = (List.range' (steps - m) m).foldl (wotsChainFwdStep seed a startPos) current := by
  intro m
  induction m with
  | zero =>
      intro _ current
      show current = _
      simp only [List.range'_zero, List.foldl_nil]
  | succ m ih =>
      intro hm current
      have hth : SphincsCVerify.Spec.th seed (SphincsCVerify.Spec.Adrs.setChainPos a (UInt32.ofNat (startPos + (steps - 1 - m))))
            (ByteVec.pad16 current)
          = wotsChainFwdStep seed a startPos current (steps - m - 1) := by
        unfold wotsChainFwdStep
        congr 3
        omega
      show SphincsCVerify.Spec.chainHash.aux seed a startPos steps m
            (SphincsCVerify.Spec.th seed (SphincsCVerify.Spec.Adrs.setChainPos a (UInt32.ofNat (startPos + (steps - 1 - m))))
              (ByteVec.pad16 current))
          = _
      rw [hth, ih (by omega)]
      have hstart : steps - (m + 1) = steps - m - 1 := by omega
      have hstep : steps - m - 1 + 1 = steps - m := by omega
      rw [hstart, List.range'_succ, List.foldl_cons, hstep]

/-- **`chainHash` as a forward fold.** `chainHash seed a val startPos steps` is the
    forward fold of `wotsChainFwdStep` over `[0, steps)` from `val`. Instantiates
    `chainHash_aux_eq_fwd` at `m = steps` (`range' 0 steps`). The `forsAcc`/`reconstructRoot_eq_foldl`
    analogue for the WOTS chain; the inner step loop refines AGAINST this. -/
theorem chainHash_eq_fwd (seed : ByteVec 32) (a : SphincsCVerify.Spec.Adrs) (val : ByteVec 16)
    (startPos steps : Nat) :
    SphincsCVerify.Spec.chainHash seed a val startPos steps
      = (List.range' 0 steps).foldl (wotsChainFwdStep seed a startPos) val := by
  show SphincsCVerify.Spec.chainHash.aux seed a startPos steps steps val = _
  rw [chainHash_aux_eq_fwd seed a startPos steps steps (Nat.le_refl steps) val, Nat.sub_self]


private theorem recovery_chain_succ (seed : ByteVec 32) (a : Adrs)
    (x : ByteVec 16) (start n : Nat) :
    chainHash seed a x start (n + 1) =
      th seed (Adrs.setChainPos a (UInt32.ofNat (start + n)))
        (ByteVec.pad16 (chainHash seed a x start n)) := by
  rw [chainHash_eq_fwd, chainHash_eq_fwd, List.range'_1_concat, List.foldl_append,
    Nat.zero_add]
  rfl

private def recovery_node_fold (seed adrs : Std.Array Std.U8 32#usize)
    (x : Std.Array Std.U8 16#usize) (start n : Nat) :=
  (List.range n).foldl (fun cur i =>
    th_pure seed (chainAdrs adrs (start + i)) (pad16Pure cur)) x

private theorem recovery_node_fold_matches (seed adrs : Std.Array Std.U8 32#usize)
    (x : Std.Array Std.U8 16#usize) (start n : Nat) (hb : start + n ≤ 2^32) :
    toSpecNode (recovery_node_fold seed adrs x start n) =
      chainHash (toSpecDigest seed) (toSpecDigest adrs) (toSpecNode x) start n := by
  induction n with
  | zero => rfl
  | succ n ih =>
    have hi := ih (by omega)
    unfold recovery_node_fold
    rw [List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil,
      recovery_th, recovery_pad, recovery_chain_adrs _ _ (by omega), recovery_chain_succ]
    exact congrArg (fun v => th (toSpecDigest seed)
      (Adrs.setChainPos (toSpecDigest adrs) (UInt32.ofNat (start + n)))
      (ByteVec.pad16 v)) hi

private theorem truncate_pad (x : Std.Array Std.U8 16#usize) :
    _root_.truncate16 (pad16Pure x) = x := by
  apply Subtype.ext
  rw [truncate16_val, pad16Pure_val, List.take_left' (by simpa using x.property)]

/-- All non-overflowing chain walks agree, including zero steps. -/
theorem recovery_chain (seed adrs : Std.Array Std.U8 32#usize)
    (x : Std.Array Std.U8 16#usize) (start steps : Std.U32)
    (hb : start.val + steps.val ≤ U32.max) :
    toSpecNode (chain_hash_pure seed adrs x start steps) =
      chainHash (toSpecDigest seed) (toSpecDigest adrs) (toSpecNode x)
        start.val steps.val := by
  rw [chain_hash_pure_def]
  have fold := List.foldl_hom pad16Pure
    (g₁ := fun cur i => th_pure seed (chainAdrs adrs (start.val + i)) (pad16Pure cur))
    (g₂ := fun cur i => pad16Pure (th_pure seed (chainAdrs adrs (start.val + i)) cur))
    (l := List.range steps.val) (init := x) (fun _ _ => rfl)
  rw [fold, truncate_pad]
  exact recovery_node_fold_matches seed adrs x start.val steps.val (by scalar_tac)

/-- The actual extracted chain implementation refines the verifier chain walk. -/
theorem firmware_chain_hash_matches_vendored (seed adrs : Std.Array Std.U8 32#usize)
    (x : Std.Array Std.U8 16#usize) (start steps : Std.U32)
    (hb : start.val + steps.val ≤ U32.max) :
    sphincs_c10.hash.chain_hash seed adrs x start steps ⦃ r =>
      toSpecNode r = chainHash (toSpecDigest seed) (toSpecDigest adrs)
        (toSpecNode x) start.val steps.val ⦄ := by
  let* ⟨r, hr⟩ ← sphincs_c10.hash.chain_hash_spec seed adrs x start steps hb
  rw [hr]
  exact recovery_chain seed adrs x start steps hb

/-- The actual extracted compression preserves every endpoint and its position. -/
theorem firmware_th_multi_matches_vendored (seed adrs : Std.Array Std.U8 32#usize)
    (vs : Slice (Std.Array Std.U8 16#usize)) (hlen : vs.val.length ≤ 43) :
    sphincs_c10.hash.th_multi seed adrs vs ⦃ r =>
      toSpecNode r = thMulti (toSpecDigest seed) (toSpecDigest adrs)
        (vs.val.map toSpecNode) ⦄ := by
  let* ⟨r, hr⟩ ← sphincs_c10.hash.th_multi_spec seed adrs vs hlen
  rw [hr]
  exact recovery_th_multi seed adrs vs

private theorem recovery_adrs (layer : Std.U32) (tree : Std.U64)
    (atype kp ci cp ha : Std.U32) :
    toSpecDigest (adrsArr layer tree atype.val kp.val ci.val cp.val ha.val) =
      Adrs.make (UInt32.ofNat layer.val) (UInt64.ofNat tree.val)
        (UInt32.ofNat atype.val) (UInt32.ofNat kp.val) (UInt32.ofNat ci.val)
        (UInt32.ofNat cp.val) (UInt32.ofNat ha.val) := by
  have h := specMakeAdrs_eq_vendored (UInt32.ofNat layer.val) (UInt32.ofNat atype.val)
    (UInt32.ofNat kp.val) (UInt32.ofNat ci.val) (UInt32.ofNat cp.val)
    (UInt32.ofNat ha.val) (UInt64.ofNat tree.val)
  have hx (v : Std.U32) : (UInt32.ofNat v.val).toNat = v.val := by
    change v.val % 2^32 = v.val
    exact Nat.mod_eq_of_lt v.hBounds
  have ht : (UInt64.ofNat tree.val).toNat = tree.val := by
    change tree.val % 2^64 = tree.val
    exact Nat.mod_eq_of_lt tree.hBounds
  simp only [hx, ht] at h
  apply byteVec_ext
  apply _root_.Array.toList_inj.mp
  change (specMakeAdrs layer.val tree.val atype.val kp.val ci.val cp.val ha.val).map
    (fun n => UInt8.ofNat (⟨BitVec.ofNat 8 n⟩ : Std.U8).val) = _
  rw [← h, List.map_map]
  have roundtrip (x : UInt8) : UInt8.ofNat (⟨BitVec.ofNat 8 x.toNat⟩ : Std.U8).val = x := by
    apply UInt8.toNat_inj.mp
    change (x.toNat % 256) % 256 = x.toNat
    have hx : x.toNat < 256 := x.toFin.isLt
    omega
  simp only [Function.comp_def, roundtrip, List.map_id']

private theorem recovery_adrs_wots (layer : Std.U32) (tree : Std.U64) (kp : Std.U32) :
    toSpecDigest (adrsArr layer tree 0 kp.val 0 0 0) =
      Adrs.wots (UInt32.ofNat layer.val) (UInt64.ofNat tree.val) (UInt32.ofNat kp.val) := by
  exact recovery_adrs layer tree 0#u32 kp 0#u32 0#u32 0#u32

private theorem recovery_adrs_pk (layer : Std.U32) (tree : Std.U64) (kp : Std.U32) :
    toSpecDigest (adrsArr layer tree 1 kp.val 0 0 0) =
      Adrs.wotsPk (UInt32.ofNat layer.val) (UInt64.ofNat tree.val) (UInt32.ofNat kp.val) := by
  exact recovery_adrs layer tree 1#u32 kp 0#u32 0#u32 0#u32

private theorem recovery_adrs_index (layer : Std.U32) (tree : Std.U64) (kp : Std.U32)
    (j : Nat) (hj : j < 43) :
    toSpecDigest (adrsArr layer tree 0 kp.val j 0 0) =
      Adrs.setChainIndex
        (Adrs.wots (UInt32.ofNat layer.val) (UInt64.ofNat tree.val) (UInt32.ofNat kp.val))
        (UInt32.ofNat j) := by
  have hn : (⟨BitVec.ofNat 32 j⟩ : Std.U32).val = j := by
    change j % 2^32 = j; exact Nat.mod_eq_of_lt (by omega)
  have hmake := recovery_adrs layer tree 0#u32 kp (⟨BitVec.ofNat 32 j⟩ : Std.U32) 0#u32 0#u32
  simp only [hn, UScalar.ofNatCore_val_eq] at hmake
  rw [hmake]
  apply byteVec_ext
  simp [Adrs.wots, Adrs.make, Adrs.setChainIndex, ByteVec.cast, ByteVec.append,
    ByteVec.ofU32BE, ByteVec.ofU64BE, ADRS_WOTS]

def toSpecSigma (sigma : Std.Array (Std.Array Std.U8 16#usize) 43#usize)
    (count : Std.U32) : Wots.Sigma :=
  ⟨(sigma.val.map toSpecNode).toArray, by simpa [L] using sigma.property,
    UInt32.ofNat count.val⟩

attribute [local irreducible] sphincs_c10.hash.wots_digest

private theorem recovery_digest (seed adrs padded : Std.Array Std.U8 32#usize)
    (count : Std.U32) :
    toSpecDigest (wots_digest_pure seed adrs padded count) =
      wotsDigest (toSpecDigest seed) (toSpecDigest adrs) (toSpecDigest padded)
        (UInt32.ofNat count.val) := by
  obtain ⟨d, heq, hd⟩ := WP.spec_imp_exists
    (sphincs_c10.hash.wots_digest_spec seed adrs padded count)
  have hv := firmware_wots_digest_matches_vendored seed adrs padded count
  rw [heq, WP.spec_ok, hd] at hv
  exact hv

private theorem recovery_digits (d : Std.Array Std.U8 32#usize) :
    SphincsCVerify.Util.extractDigits (toSpecDigest d) =
      ((List.range 43).map (wotsDigit d)).toArray := by
  apply _root_.Array.ext
  · simp [SphincsCVerify.Util.extractDigits, L]
  intro j h1 h2
  have hj : j < 43 := by simpa using h2
  simp only [SphincsCVerify.Util.extractDigits, Array.getElem_ofFn,
    List.getElem_toArray, List.getElem_map, List.getElem_range]
  exact vendored_readBitsLe_eq_digestWord d _ _ (by simp [LogW]; omega)

attribute [local irreducible] SphincsCVerify.Spec.thMulti SphincsCVerify.Spec.chainHash
  wotsDigit Adrs.wots Adrs.wotsPk

/-- Exact verifier branch and node formula used by the extracted recovery bridge.
    A valid zero hash remains `some zero`; only a rejected sum yields `none`. -/
theorem vendored_wots_recovery_outcome (seed : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32)
    (message : Std.Array Std.U8 16#usize)
    (sigma : Std.Array (Std.Array Std.U8 16#usize) 43#usize) (count : Std.U32) :
    let d := wots_digest_pure seed (adrsArr layer tree 0 kp.val 0 0 0) (pad16p message) count
    Wots.pkFromSig (toSpecDigest seed) (UInt32.ofNat layer.val) (UInt64.ofNat tree.val)
      (UInt32.ofNat kp.val) (toSpecNode message) (toSpecSigma sigma count) =
      if ((List.range 43).map (wotsDigit d)).sum = 205 then
        some (toSpecNode (th_multi_pure seed (adrsArr layer tree 1 kp.val 0 0 0)
          ⟨pkChains seed layer tree kp sigma d, by simp [pkChains]; scalar_tac⟩))
      else none := by
  dsimp only
  have hp : pad16p message = pad16Pure message := by unfold pad16Pure; rfl
  unfold Wots.pkFromSig
  simp only [toSpecSigma]
  rw [← recovery_adrs_wots, ← recovery_pad, ← recovery_digest, ← hp, recovery_digits]
  generalize hd : wots_digest_pure seed (adrsArr layer tree 0 kp.val 0 0 0) (pad16p message) count = d
  simp only [SphincsCVerify.Util.digitSum, List.foldl_toArray', ← List.sum_eq_foldl,
    TargetSum, L]
  split
  · rename_i hy
    simp only [if_neg hy]
  · rename_i hy
    simp only [not_not] at hy
    simp only [if_pos hy]
    have hcomp := recovery_th_multi seed (adrsArr layer tree 1 kp.val 0 0 0)
      (⟨pkChains seed layer tree kp sigma d, by simp [pkChains]; scalar_tac⟩ : Slice (Std.Array Std.U8 16#usize))
    rw [hcomp, recovery_adrs_pk]
    apply congrArg some
    apply congrArg (thMulti (toSpecDigest seed)
      (Adrs.wotsPk (UInt32.ofNat layer.val) (UInt64.ofNat tree.val) (UInt32.ofNat kp.val)))
    simp only [pkChains, List.map_map, Function.comp_def]
    apply List.map_congr_left
    intro j hj
    have hj43 : j < 43 := List.mem_range.mp hj
    have hsiglen : sigma.val.length = 43 := by simpa using sigma.property
    have hjd : j < ((List.range 43).map (wotsDigit d)).length := by
      simpa using hj43
    have hdj : ((List.range 43).map (wotsDigit d))[j]! = wotsDigit d j := by
      rw [getElem!_pos ((List.range 43).map (wotsDigit d)) j hjd]
      simp
    have hdlt := wotsDigit_lt d j
    have scalar32 (n : Nat) (hn : n < 2^32) : (⟨BitVec.ofNat 32 n⟩ : Std.U32).val = n := by
      change n % 2^32 = n
      exact Nat.mod_eq_of_lt hn
    have hstart := scalar32 (wotsDigit d j) (by omega)
    have hsteps := scalar32 (7 - wotsDigit d j) (by omega)
    have hb : (⟨BitVec.ofNat 32 (wotsDigit d j)⟩ : Std.U32).val +
        (⟨BitVec.ofNat 32 (7 - wotsDigit d j)⟩ : Std.U32).val ≤ U32.max := by
      rw [hstart, hsteps]
      scalar_tac
    simp only [List.size_toArray, List.length_map, dif_pos (show j < sigma.val.length by omega),
      List.getElem_toArray, List.getElem_map, List.getElem!_toArray, hdj,
      SphincsCVerify.Spec.W]
    rw [recovery_chain _ _ _ _ _ hb, recovery_adrs_index layer tree kp j hj43,
      recovery_adrs_wots, hstart, hsteps, getElem!_pos sigma.val j (by omega)]

attribute [local irreducible] sphincs_c10.wots.pk_from_sig Wots.pkFromSig

/-- Full-counter WOTS recovery: a successful verifier result is the identical
    node; verifier rejection maps to the Rust zero sentinel. A zero node alone
    is not claimed to distinguish rejection from a valid zero-valued hash. -/
theorem firmware_pk_from_sig_matches_vendored (seed : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32)
    (message : Std.Array Std.U8 16#usize)
    (sigma : Std.Array (Std.Array Std.U8 16#usize) 43#usize) (count : Std.U32) :
    sphincs_c10.wots.pk_from_sig seed layer tree kp message sigma count ⦃ r =>
      toSpecNode r =
        (Wots.pkFromSig (toSpecDigest seed) (UInt32.ofNat layer.val) (UInt64.ofNat tree.val)
          (UInt32.ofNat kp.val) (toSpecNode message) (toSpecSigma sigma count)).getD
          (ByteVec.zero 16) ⦄ := by
  let* ⟨r, hr⟩ ← pk_from_sig_spec seed layer tree kp message sigma count
  rw [vendored_wots_recovery_outcome]
  split <;> rename_i h
  · rw [if_pos h] at hr
    simp only [Option.getD_some]
    exact congrArg toSpecNode hr
  · rw [if_neg h] at hr
    simp only [Option.getD_none]
    apply byteVec_ext
    simp [toSpecNode, hr, ByteVec.zero]
    rfl

end Extracted.Equiv
