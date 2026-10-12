/- The actual signer's positional chain values agree with the source-checked
   reference chain, secret, address, digest and digit definitions. -/
import Extracted.WotsSignRecovery

open Aeneas Aeneas.Std Result
set_option maxHeartbeats 2000000
set_option maxRecDepth 8192
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes
namespace Extracted.Equiv
open SphincsCVerify.Spec
attribute [local irreducible] wotsSignChain wotsSignChains

private theorem sign_digit_matches (d : Std.Array Std.U8 32#usize) (j : Nat) (hj : j < 43) :
    wotsDigit d j = (SphincsCVerify.Util.extractDigits (toSpecDigest d)).getD j 0 := by
  obtain ⟨digits, he, hd⟩ := WP.spec_imp_exists (extract_digits_spec d)
  have h := firmware_extract_digits_matches_vendored d
  rw [he, WP.spec_ok] at h
  rw [← h j hj]
  exact (hd j hj).symm

theorem wots_sign_chain_matches_vendored (seed sk d : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32) (j : Nat) (hj : j < 43) :
    toSpecNode (wotsSignChain seed sk d layer tree kp j) =
      chainHash (toSpecDigest seed)
        (Adrs.setChainIndex (Adrs.wots (UInt32.ofNat layer.val) (UInt64.ofNat tree.val)
          (UInt32.ofNat kp.val)) (UInt32.ofNat j))
        (wotsSecret (toSpecDigest sk) (UInt32.ofNat layer.val) (UInt64.ofNat tree.val)
          (UInt32.ofNat kp.val) (UInt32.ofNat j)) 0
        ((SphincsCVerify.Util.extractDigits (toSpecDigest d)).getD j 0) := by
  have hj32 : (⟨BitVec.ofNat 32 j⟩ : Std.U32).val = j := by
    change j % 2^32 = j
    exact Nat.mod_eq_of_lt (by omega)
  have hd32 : (⟨BitVec.ofNat 32 (wotsDigit d j)⟩ : Std.U32).val = wotsDigit d j := by
    change wotsDigit d j % 2^32 = wotsDigit d j
    exact Nat.mod_eq_of_lt (by have := wotsDigit_lt d j; omega)
  rw [wotsSignChain, recovery_chain seed _ _ 0#u32
      (⟨BitVec.ofNat 32 (wotsDigit d j)⟩ : Std.U32)
      (by rw [hd32]; have := wotsDigit_lt d j; scalar_tac),
    recovery_adrs_index layer tree kp j hj, wots_secret_pure_matches_vendored, hj32, hd32,
    sign_digit_matches d j hj]
  rfl

private theorem sign_digest_matches (seed adrs padded : Std.Array Std.U8 32#usize) (c : Std.U32) :
    toSpecDigest (wots_digest_pure seed adrs padded c) =
      wotsDigest (toSpecDigest seed) (toSpecDigest adrs) (toSpecDigest padded) (UInt32.ofNat c.val) := by
  obtain ⟨d, he, hd⟩ := WP.spec_imp_exists (sphincs_c10.hash.wots_digest_spec seed adrs padded c)
  have h := firmware_wots_digest_matches_vendored seed adrs padded c
  rw [he, WP.spec_ok, hd] at h
  exact h

private abbrev SignSigma := Std.Array (Std.Array Std.U8 16#usize) 43#usize

/-- No desired-output premise: any actual successful result has all43 exact
    reference chains, in wire position order despite its shuffled execution. -/
theorem firmware_wots_sign_matches_vendored (seed sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32)
    (message : Std.Array Std.U8 16#usize) (shuffle_seed : Std.Array Std.U8 32#usize)
    (progress : sphincs_c10.hypertree.ProgressSink) (pct : Std.U8)
    (sigma : SignSigma) (c : Std.U32)
    (hsign : sphincs_c10.wots.sign_with_shuffle seed sk layer tree kp message shuffle_seed progress pct = .ok (sigma,c)) :
    ∀ j, j < 43 → toSpecNode (sigma.val[j]!) =
      chainHash (toSpecDigest seed)
        (Adrs.setChainIndex (Adrs.wots (UInt32.ofNat layer.val) (UInt64.ofNat tree.val)
          (UInt32.ofNat kp.val)) (UInt32.ofNat j))
        (wotsSecret (toSpecDigest sk) (UInt32.ofNat layer.val) (UInt64.ofNat tree.val)
          (UInt32.ofNat kp.val) (UInt32.ofNat j)) 0
        ((SphincsCVerify.Util.extractDigits
          (wotsDigest (toSpecDigest seed)
            (Adrs.wots (UInt32.ofNat layer.val) (UInt64.ofNat tree.val) (UInt32.ofNat kp.val))
            (ByteVec.pad16 (toSpecNode message)) (UInt32.ofNat c.val))).getD j 0) := by
  rcases wots_sign_total seed sk layer tree kp message shuffle_seed progress pct with
    ⟨c',he,hb,ha,hf⟩ | ⟨he,hr⟩
  · rw [he] at hsign
    have hp := Result.ok.inj hsign
    have hcount : c' = c := congrArg Prod.snd hp
    have hsigma : wotsSignChains seed sk
        (wots_digest_pure seed (adrsArr layer tree 0 kp.val 0 0 0) (pad16p message) c') layer tree kp = sigma :=
      congrArg Prod.fst hp
    rw [← hcount, ← hsigma]
    intro j hj
    have hv : (wotsSignChains seed sk
        (wots_digest_pure seed (adrsArr layer tree 0 kp.val 0 0 0) (pad16p message) c') layer tree kp).val[j]! =
        wotsSignChain seed sk
          (wots_digest_pure seed (adrsArr layer tree 0 kp.val 0 0 0) (pad16p message) c') layer tree kp j := by
      unfold wotsSignChains
      rw [getElem!_pos _ j (by simpa using hj)]
      all_goals simp
    have hpad : pad16p message = pad16Pure message := by unfold pad16Pure <;> rfl
    rw [hv, wots_sign_chain_matches_vendored seed sk _ layer tree kp j hj,
      sign_digest_matches, recovery_adrs_wots, hpad, recovery_pad]
  · rw [he] at hsign <;> cases hsign
end Extracted.Equiv
