/- Complete signer header under the supplied deterministic backend. Both
   OptRand encodings and the actual bounded exhaustion result are retained. -/
import Extracted.C10FunctionalWotsSign
import Extracted.SignNoncePure

open Aeneas Aeneas.Std Result
open Extracted.C10HashInputBridge C10Representation
open Extracted.C10FunctionalWots Extracted.C10FunctionalSearch
set_option maxRecDepth 8192
set_option maxHeartbeats 1000000
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes
attribute [local irreducible] List.range C10Representation.fors_first_slot

namespace Extracted.C10FunctionalSignerHeader

theorem randomizer_value (secret message : Std.Array Std.U8 32#usize)
    (random : Option (Std.Array Std.U8 16#usize)) (nonce : Std.U32) :
    byteInts (Equiv.forsRandomizer secret message random nonce).val =
      signer_randomizer suppliedBackend (byteInts secret.val)
        (byteInts (optionalBytes random)) (byteInts message.val) (Int.ofNat nonce.val) := by
  rw [randomizer_input, truncate16_val]
  simp only [signer_randomizer, hash_bytes_node, suppliedBackend, byteInts, List.map_take]

theorem digest_value (secret seed root message : Std.Array Std.U8 32#usize)
    (random : Option (Std.Array Std.U8 16#usize)) (nonce : Std.U32) :
    byteInts (Equiv.forsGrindDigest secret seed root message random nonce).val =
      signer_digest suppliedBackend (byteInts seed.val) (byteInts root.val)
        (byteInts secret.val) (byteInts (optionalBytes random)) (byteInts message.val)
        (Int.ofNat nonce.val) := by
  unfold signer_digest verifier_digest
  rw [← randomizer_value, ← pad_node_value, suppliedBackend,
    ← hmsg_input_value, bytesOfInts_byteInts]
  rfl

theorem schedule_value (secret seed root message : Std.Array Std.U8 32#usize)
    (random : Option (Std.Array Std.U8 16#usize)) :
    forsSchedule secret seed root message random 10000000 =
      signer_search_digests suppliedBackend (byteInts seed.val) (byteInts root.val)
        (byteInts secret.val) (byteInts (optionalBytes random)) (byteInts message.val) := by
  unfold forsSchedule signer_search_digests
  apply List.map_congr_left
  intro i hi
  have hb : i < 4294967296 := by have := List.mem_range.mp hi; omega
  change byteInts (Equiv.forsGrindDigest _ _ _ _ _ _).val = _
  rw [digest_value, searchCounter_val i hb]

def headerResult (f : List Int → List Int) (seed root secret random message : List Int) :
    Result (List Int × List Int) :=
  let slot := signer_nonce_slot f seed root secret random message
  if slot = 0 then .fail .assertionFailure else
    .ok (signer_randomizer f secret random message (Int.ofNat (slot-1)),
      signer_digest f seed root secret random message (Int.ofNat (slot-1)))

/-- Equality of Results has no successful-search premise and no final-root
    assumption. The two real OptRand encodings enter the common expression. -/
theorem extracted_header_result (secret message : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (random : Option (Std.Array Std.U8 16#usize)) :
    (do let (r,d) ← sphincs_c10.fors.grind_r secret seed root message random
        .ok (byteInts r.val, byteInts d.val)) =
      headerResult suppliedBackend (byteInts (pad16Pure seed).val)
        (byteInts (pad16Pure root).val) (byteInts secret.val)
        (byteInts (optionalBytes random)) (byteInts message.val) := by
  have hs := schedule_value secret (pad16Pure seed) (pad16Pure root) message random
  rcases extracted_fors_first_slot secret message seed root random with
    ⟨c, hc, hslot, he⟩ | ⟨he, hslot⟩
  · rw [hs] at hslot
    simp only [headerResult, signer_nonce_slot, hslot, he, bind_tc_ok,
      uncurry_apply_pair, Nat.add_sub_cancel, Nat.add_eq_zero_iff, Nat.one_ne_zero,
      and_false, if_false]
    rw [randomizer_value, digest_value]
  · rw [hs] at hslot
    simp only [headerResult, signer_nonce_slot, hslot, he, bind_tc_fail, if_true]

theorem pure_header_result (secret message : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (random : Option (Std.Array Std.U8 16#usize)) :
    (do let (r,d) ← Equiv.pureGrindR secret message seed root random
        .ok (byteInts r.val, byteInts d.val)) =
      headerResult suppliedBackend (byteInts (pad16Pure seed).val)
        (byteInts (pad16Pure root).val) (byteInts secret.val)
        (byteInts (optionalBytes random)) (byteInts message.val) := by
  rw [← Equiv.firmware_grind_r_pure]
  exact extracted_header_result secret message seed root random

end Extracted.C10FunctionalSignerHeader
