/- Actual shuffled signing against the shared functional chain values.
   Both bounded-search branches are retained; no success premise is imposed. -/
import Extracted.C10FunctionalWots
import Extracted.C10FunctionalSearch
import Extracted.WotsSignSpec

open Aeneas Aeneas.Std Result
open Extracted.C10HashInputBridge C10Representation
open Extracted.C10FunctionalWots Extracted.C10FunctionalSearch
set_option maxRecDepth 8192
set_option maxHeartbeats 1000000
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes

namespace Extracted.C10FunctionalWotsSign

theorem digest_pure_value (seed address message : Std.Array Std.U8 32#usize) (nonce : Std.U32) :
    byteInts (wots_digest_pure seed address message nonce).val =
      suppliedBackend (wots_preimage (byteInts seed.val) (byteInts address.val)
        (byteInts message.val) (Int.ofNat nonce.val)) := by
  unfold suppliedBackend
  rw [← wots_input_value, bytesOfInts_byteInts, wots_digest_pure_def]

def functional_schedule (f : List Int → List Int) (seed : List Int)
    (layer tree kp : Int) (message : List Int) (n : Nat) : List (List Int) :=
  (List.range n).map (fun i => f (wots_preimage seed (address_words layer tree 0 kp 0 0 0)
    (pad_node message) (Int.ofNat i)))

theorem functional_schedule_value (seed : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32)
    (message : Std.Array Std.U8 16#usize) (n : Nat) (hn : n ≤ 4294967296) :
    wotsSchedule seed (Equiv.adrsArr layer tree 0 kp.val 0 0 0) (pad16Pure message) n =
      functional_schedule suppliedBackend (byteInts seed.val) (Int.ofNat layer.val)
        (Int.ofNat tree.val) (Int.ofNat kp.val) (byteInts message.val) n := by
  simp only [wotsSchedule, functional_schedule]
  apply List.map_congr_left
  intro i hi
  have hi32 : i < 4294967296 := by have := List.mem_range.mp hi; omega
  change byteInts (wots_digest_pure _ _ _ _).val = _
  rw [digest_pure_value, pure_address_value, pad_node_value, searchCounter_val i hi32]
  rfl

theorem digit_value (d : Std.Array Std.U8 32#usize) (j : Nat) :
    wots_field (byteInts d.val) j = Int.ofNat (Equiv.wotsDigit d j) := by
  simp only [byteInts, wots_field, C10RepresentationBridge.digest_word_window,
    Equiv.wotsDigit, show (2:Nat)^3=8 by decide, Nat.mul_comm]

theorem sign_nodes_value (seed secret d : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32) :
    (Equiv.wotsSignChains seed secret d layer tree kp).val.map (fun v => byteInts v.val) =
      wots_sign_values suppliedBackend (byteInts seed.val) (byteInts secret.val)
        (Int.ofNat layer.val) (Int.ofNat tree.val) (Int.ofNat kp.val) (byteInts d.val) := by
  simp only [Equiv.wotsSignChains, wots_sign_values, List.map_map]
  apply List.map_congr_left
  intro j hj
  have hj43 : j < 43 := List.mem_range.mp hj
  have hjval : (⟨BitVec.ofNat 32 j⟩ : Std.U32).val = j := by
    change j % 2^32 = j
    exact Nat.mod_eq_of_lt (by omega)
  have hdval : (⟨BitVec.ofNat 32 (Equiv.wotsDigit d j)⟩ : Std.U32).val = Equiv.wotsDigit d j := by
    change Equiv.wotsDigit d j % 2^32 = Equiv.wotsDigit d j
    exact Nat.mod_eq_of_lt (by have := Equiv.wotsDigit_lt d j; omega)
  simp only [Function.comp_def, Equiv.wotsSignChain]
  rw [chain_pure_value, secret_pure_value, pure_address_value, hjval, hdval, digit_value]
  rfl

/-- All 43 positional outputs, despite shuffled execution, or exact exhaustion.
    The accepted digest and counter are selected by the paired first-hit form. -/
theorem extracted_sign_value (seed secret : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32)
    (message : Std.Array Std.U8 16#usize) (shuffle : Std.Array Std.U8 32#usize)
    (progress : sphincs_c10.hypertree.ProgressSink) (pct : Std.U8) :
    (∃ (sigma : Std.Array (Std.Array Std.U8 16#usize) 43#usize) (nonce : Std.U32),
      sphincs_c10.wots.sign_with_shuffle seed secret layer tree kp message shuffle progress pct = .ok (sigma,nonce) ∧
      nonce.val < 10000000 ∧
      wots_first_slot (functional_schedule suppliedBackend (byteInts seed.val) (Int.ofNat layer.val)
        (Int.ofNat tree.val) (Int.ofNat kp.val) (byteInts message.val) 10000000) = nonce.val+1 ∧
      sigma.val.map (fun v => byteInts v.val) =
        wots_sign_values suppliedBackend (byteInts seed.val) (byteInts secret.val)
          (Int.ofNat layer.val) (Int.ofNat tree.val) (Int.ofNat kp.val)
          (suppliedBackend (wots_preimage (byteInts seed.val)
            (address_words (Int.ofNat layer.val) (Int.ofNat tree.val) 0 (Int.ofNat kp.val) 0 0 0)
            (pad_node (byteInts message.val)) (Int.ofNat nonce.val)))) ∨
    (sphincs_c10.wots.sign_with_shuffle seed secret layer tree kp message shuffle progress pct = .fail .assertionFailure ∧
      wots_first_slot (functional_schedule suppliedBackend (byteInts seed.val) (Int.ofNat layer.val)
        (Int.ofNat tree.val) (Int.ofNat kp.val) (byteInts message.val) 10000000) = 0) := by
  rw [← functional_schedule_value seed layer tree kp message 10000000 (by decide)]
  have hp : Equiv.pad16p message = pad16Pure message := by unfold pad16Pure; rfl
  rcases Equiv.wots_sign_total seed secret layer tree kp message shuffle progress pct with
    ⟨nonce, he, hn, ha, hpre⟩ | ⟨he, hpre⟩
  · rw [hp] at he ha hpre
    refine Or.inl ⟨_, nonce, he, hn, ?_, ?_⟩
    · apply wots_schedule_hit _ _ _ nonce hn
      · exact (C10AcceptanceBridge.wots_accept_common _ _ _ _).mp ha
      · intro earlier hb
        exact fun hh => hpre earlier hb ((C10AcceptanceBridge.wots_accept_common _ _ _ _).mpr hh)
    · rw [sign_nodes_value, digest_pure_value, pure_address_value, pad_node_value]
      rfl
  · rw [hp] at hpre
    refine Or.inr ⟨he, wots_schedule_exhausted _ _ _ ?_⟩
    intro nonce hn hh
    exact hpre nonce hn ((C10AcceptanceBridge.wots_accept_common _ _ _ _).mpr hh)

end Extracted.C10FunctionalWotsSign
