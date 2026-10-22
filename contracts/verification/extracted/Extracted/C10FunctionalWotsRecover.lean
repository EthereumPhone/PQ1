/- Actual WOTS recovery, including rejection, against the paired expression.
   Verification accepts the full u32 counter domain, not only signer counters. -/
import Extracted.C10FunctionalWotsSign

open Aeneas Aeneas.Std Result
open Extracted.C10HashInputBridge C10Representation
open Extracted.C10FunctionalWots Extracted.C10FunctionalWotsSign
set_option maxRecDepth 8192
set_option maxHeartbeats 1000000
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes

namespace Extracted.C10FunctionalWotsRecover

theorem recover_nodes_value (seed d : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32)
    (sigma : Std.Array (Std.Array Std.U8 16#usize) 43#usize) :
    (Equiv.pkChains seed layer tree kp sigma d).map (fun v => byteInts v.val) =
      wots_recover_nodes suppliedBackend (byteInts seed.val)
        (Int.ofNat layer.val) (Int.ofNat tree.val) (Int.ofNat kp.val) (byteInts d.val)
        (sigma.val.map (fun v => byteInts v.val)) := by
  simp only [Equiv.pkChains, wots_recover_nodes, List.map_map]
  apply List.map_congr_left
  intro j hj
  have hj43 : j < 43 := List.mem_range.mp hj
  have hs : j < sigma.val.length := by simpa using hj43
  have hd := Equiv.wotsDigit_lt d j
  have hdval : (⟨BitVec.ofNat 32 (Equiv.wotsDigit d j)⟩ : Std.U32).val = Equiv.wotsDigit d j := by
    change Equiv.wotsDigit d j % 2^32 = Equiv.wotsDigit d j
    exact Nat.mod_eq_of_lt (by omega)
  have hnval : (⟨BitVec.ofNat 32 (7-Equiv.wotsDigit d j)⟩ : Std.U32).val = 7-Equiv.wotsDigit d j := by
    change (7-Equiv.wotsDigit d j) % 2^32 = 7-Equiv.wotsDigit d j
    exact Nat.mod_eq_of_lt (by omega)
  simp only [Function.comp_def]
  rw [chain_pure_value, pure_address_value, hdval, hnval, digit_value]
  rw [getElem!_pos sigma.val j hs, List.getD_eq_getElem _ _ (by simpa using hs), List.getElem_map]
  congr 1
  simp only [Int.ofNat_eq_natCast]
  omega

/-- Complete actual recovery result, including the 16-byte rejection sentinel. -/
theorem extracted_recover_value (seed : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32)
    (message : Std.Array Std.U8 16#usize)
    (sigma : Std.Array (Std.Array Std.U8 16#usize) 43#usize) (nonce : Std.U32) :
    sphincs_c10.wots.pk_from_sig seed layer tree kp message sigma nonce ⦃ r =>
      byteInts r.val = wots_recover_value suppliedBackend (byteInts seed.val)
        (Int.ofNat layer.val) (Int.ofNat tree.val) (Int.ofNat kp.val) (byteInts message.val)
        (sigma.val.map (fun v => byteInts v.val)) (Int.ofNat nonce.val) ⦄ := by
  let* ⟨r, hr⟩ ← Equiv.pk_from_sig_spec seed layer tree kp message sigma nonce
  have hp : Equiv.pad16p message = pad16Pure message := by unfold pad16Pure; rfl
  rw [hp] at hr
  let d := wots_digest_pure seed (Equiv.adrsArr layer tree 0 kp.val 0 0 0) (pad16Pure message) nonce
  have hd : byteInts d.val = suppliedBackend (wots_preimage (byteInts seed.val)
      (address_words (Int.ofNat layer.val) (Int.ofNat tree.val) 0 (Int.ofNat kp.val) 0 0 0)
      (pad_node (byteInts message.val)) (Int.ofNat nonce.val)) := by
    rw [digest_pure_value, pure_address_value, pad_node_value]
    rfl
  rw [wots_recover_value, ← hd]
  have hsum : wots_sum (byteInts d.val) = Int.ofNat (((List.range 43).map (Equiv.wotsDigit d)).sum) :=
    C10AcceptanceBridge.wots_sum_value d
  by_cases ha : ((List.range 43).map (Equiv.wotsDigit d)).sum = 205
  · have htest : wots_sum (byteInts d.val) - wots_target = 0 := by rw [hsum, ha]; rfl
    rw [if_pos htest]
    rw [if_pos ha] at hr
    rw [hr, multi_pure_value, pure_address_value, recover_nodes_value]
    rfl
  · have htest : wots_sum (byteInts d.val) - wots_target ≠ 0 := by
      rw [hsum]; unfold wots_target
      simp only [Int.ofNat_eq_natCast]
      omega
    rw [if_neg htest]
    rw [if_neg ha] at hr
    simp [byteInts, hr]

end Extracted.C10FunctionalWotsRecover
