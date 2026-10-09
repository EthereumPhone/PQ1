/- Compose the actual shuffled signer with actual verification and keygen. -/
import Extracted.WotsSignSpec
import Extracted.WotsKeygenBridge

open Aeneas Aeneas.Std Result
set_option maxHeartbeats 3000000
set_option maxRecDepth 8192
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes
namespace Extracted.Equiv
open sphincs_c10 SphincsCVerify.Spec
attribute [local irreducible] wotsSignChain wotsSignChains wotsKeygenChain wotsKeygenChains wotsKeygenPure

private theorem sign_node_injective {a b : Std.Array Std.U8 16#usize}
    (h : toSpecNode a = toSpecNode b) : a = b := by
  apply Subtype.ext
  have hm := congrArg (fun v : ByteVec 16 => v.data.toList) h
  simp only [toSpecNode, List.toList_toArray] at hm
  have hf : Function.Injective (fun x : Std.U8 => UInt8.ofNat x.val) := by
    intro x y hxy
    apply UScalar.eq_of_val_eq
    have hx : x.val < 256 := x.hBounds
    have hy : y.val < 256 := y.hBounds
    have hn := congrArg UInt8.toNat hxy
    change x.val % 256 = y.val % 256 at hn
    omega
  exact (List.map_inj_right (fun x y hxy => hf hxy)).mp hm

private theorem sign_chain_succ (seed : ByteVec 32) (a : Adrs) (x : ByteVec 16)
    (s n : Nat) :
    chainHash seed a x s (n+1) = th seed (Adrs.setChainPos a (UInt32.ofNat (s+n)))
      (ByteVec.pad16 (chainHash seed a x s n)) := by
  rw [chainHash_eq_fwd, chainHash_eq_fwd, List.range'_1_concat, List.foldl_append, Nat.zero_add]
  rfl

private theorem sign_chain_compose (seed : ByteVec 32) (a : Adrs) (x : ByteVec 16)
    (s m n : Nat) :
    chainHash seed a (chainHash seed a x s m) (s+m) n = chainHash seed a x s (m+n) := by
  induction n with
  | zero => rfl
  | succ n ih => rw [sign_chain_succ, ih, Nat.add_succ, sign_chain_succ, Nat.add_assoc]

/-- Exact chain composition, including digits0and7, with fixed address fields. -/
theorem wots_sign_chain_roundtrip (seed adrs : Std.Array Std.U8 32#usize)
    (x : Std.Array Std.U8 16#usize) (digit : Nat) (hd : digit < 8) :
    chain_hash_pure seed adrs
      (chain_hash_pure seed adrs x 0#u32 ⟨BitVec.ofNat 32 digit⟩)
      ⟨BitVec.ofNat 32 digit⟩ ⟨BitVec.ofNat 32 (7-digit)⟩ =
      chain_hash_pure seed adrs x 0#u32 7#u32 := by
  have hv : (⟨BitVec.ofNat 32 digit⟩ : Std.U32).val = digit := by
    change digit % 2^32 = digit
    exact Nat.mod_eq_of_lt (by omega)
  have hw : (⟨BitVec.ofNat 32 (7-digit)⟩ : Std.U32).val = 7-digit := by
    change (7-digit) % 2^32 = 7-digit
    exact Nat.mod_eq_of_lt (by omega)
  apply sign_node_injective
  rw [recovery_chain seed adrs
      (chain_hash_pure seed adrs x 0#u32 ⟨BitVec.ofNat 32 digit⟩)
      ⟨BitVec.ofNat 32 digit⟩ ⟨BitVec.ofNat 32 (7-digit)⟩ (by rw [hv, hw]; scalar_tac),
    recovery_chain seed adrs x 0#u32 ⟨BitVec.ofNat 32 digit⟩ (by rw [hv]; scalar_tac),
    recovery_chain seed adrs x 0#u32 7#u32 (by scalar_tac), hv, hw]
  change chainHash _ _ (chainHash _ _ _ 0 digit) digit (7-digit) = chainHash _ _ _ 0 7
  have h := sign_chain_compose (toSpecDigest seed) (toSpecDigest adrs) (toSpecNode x) 0 digit (7-digit)
  simpa only [Nat.zero_add, Nat.add_sub_cancel' (show digit ≤ 7 by omega)] using h

theorem wots_sign_endpoints (seed sk d : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32) :
    pkChains seed layer tree kp (wotsSignChains seed sk d layer tree kp) d =
      wotsKeygenChains seed sk layer tree kp := by
  unfold pkChains wotsKeygenChains
  apply List.map_congr_left
  intro j hj
  have hj43 := List.mem_range.mp hj
  have hs : (wotsSignChains seed sk d layer tree kp).val[j]! =
      wotsSignChain seed sk d layer tree kp j := by
    unfold wotsSignChains
    rw [getElem!_pos _ j (by simpa using hj43)]
    simp
  rw [hs, wotsSignChain, wotsKeygenChain]
  exact wots_sign_chain_roundtrip seed _ _ _ (wotsDigit_lt d j)

theorem wots_honest_signature_recovery (seed sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32)
    (message : Std.Array Std.U8 16#usize) (c : Std.U32)
    (ha : grindAccept seed (adrsArr layer tree 0 kp.val 0 0 0) (pad16p message) c) :
    wots.pk_from_sig seed layer tree kp message
      (wotsSignChains seed sk (wots_digest_pure seed (adrsArr layer tree 0 kp.val 0 0 0)
        (pad16p message) c) layer tree kp) c ⦃ r => r = wotsKeygenPure seed sk layer tree kp ⦄ := by
  let* ⟨r, hr⟩ ← pk_from_sig_spec seed layer tree kp message _ c
  have hs : ((List.range 43).map (wotsDigit
      (wots_digest_pure seed (adrsArr layer tree 0 kp.val 0 0 0) (pad16p message) c))).sum = 205 := ha
  simp only [if_pos hs] at hr
  rw [hr, wotsKeygenPure]
  exact congrArg (th_multi_pure seed (adrsArr layer tree 1 kp.val 0 0 0))
    (Subtype.ext (wots_sign_endpoints seed sk _ layer tree kp))

/-- Every actual successful shuffled signature recovers the actual generated
    WOTS public key. Failure and randomness assumptions are not hidden. -/
theorem firmware_wots_sign_recovers_keygen (seed sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32)
    (message : Std.Array Std.U8 16#usize) (shuffle_seed : Std.Array Std.U8 32#usize)
    (progress : hypertree.ProgressSink) (pct : Std.U8)
    (sigma : Std.Array (Std.Array Std.U8 16#usize) 43#usize) (c : Std.U32)
    (hsign : wots.sign_with_shuffle seed sk layer tree kp message shuffle_seed progress pct = .ok (sigma,c)) :
    wots.pk_from_sig seed layer tree kp message sigma c
      ⦃ r => wots.keygen_pk seed sk layer tree kp = .ok r ⦄ := by
  rcases wots_sign_total seed sk layer tree kp message shuffle_seed progress pct with
    ⟨c',he,hb,ha,hf⟩ | ⟨he,hr⟩
  · rw [he] at hsign
    have hp := Result.ok.inj hsign
    have hcount : c' = c := congrArg Prod.snd hp
    have hsigma : wotsSignChains seed sk
        (wots_digest_pure seed (adrsArr layer tree 0 kp.val 0 0 0) (pad16p message) c') layer tree kp = sigma :=
      congrArg Prod.fst hp
    rw [← hcount, ← hsigma]
    let* ⟨r, hr⟩ ← wots_honest_signature_recovery seed sk layer tree kp message c' ha
    obtain ⟨pk, hk, hv⟩ := WP.spec_imp_exists (wots_keygen_pk_spec seed sk layer tree kp)
    rw [hr, hk, hv]
  · rw [he] at hsign
    cases hsign
end Extracted.Equiv
