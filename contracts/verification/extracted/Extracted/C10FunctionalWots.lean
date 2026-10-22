/- Functional WOTS components against the generated common expressions.
   The supplied SHA model and paired-printer interpretation remain boundaries;
   this does not identify concrete SHA with a sampled random oracle. -/
import Extracted.C10AddressInputBridge
import Extracted.WotsRecoveryBridge
import Extracted.WotsKeygenSpec

open Aeneas Aeneas.Std Result
open Extracted.C10HashInputBridge Extracted.C10AddressInputBridge C10Representation
set_option maxRecDepth 8192
set_option maxHeartbeats 1000000
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes

namespace Extracted.C10FunctionalWots

def suppliedBackend (bs : List Int) : List Int :=
  byteInts (sha256_pure (bytesOfInts bs)).val

theorem supplied_backend_width (bs : List Int) : (suppliedBackend bs).length = 32 := by
  simp only [suppliedBackend, byteInts, List.length_map]
  simpa using (sha256_pure (bytesOfInts bs)).property

theorem chain_zero (f : List Int → List Int) seed address current start :
    wots_chain_value f seed address current start 0 = current := rfl

theorem chain_succ (f : List Int → List Int) seed address current start n :
    wots_chain_value f seed address current start (n+1) =
      hash_bytes_node f (th_preimage seed (chain_position_words address (start + Int.ofNat n))
        (pad_node (wots_chain_value f seed address current start n))) := by
  simp [wots_chain_value, List.range_succ, List.foldl_append]

theorem hash_step_value (seed address : Std.Array Std.U8 32#usize)
    (current : Std.Array Std.U8 16#usize) :
    byteInts (th_pure seed address (pad16Pure current)).val =
      hash_bytes_node suppliedBackend (th_preimage (byteInts seed.val) (byteInts address.val)
        (pad_node (byteInts current.val))) := by
  unfold hash_bytes_node suppliedBackend
  rw [← pad_node_value current, ← th_input_value seed address (pad16Pure current),
    bytesOfInts_byteInts, th_pure_def, truncate16_val]
  simp [byteInts]

private theorem truncate_pad (x : Std.Array Std.U8 16#usize) :
    truncate16 (pad16Pure x) = x := by
  apply Subtype.ext
  rw [truncate16_val, pad16Pure_val, List.take_left' (by simpa using x.property)]

theorem chain_pure_value (seed address : Std.Array Std.U8 32#usize)
    (x : Std.Array Std.U8 16#usize) (start steps : Std.U32) :
    byteInts (chain_hash_pure seed address x start steps).val =
      wots_chain_value suppliedBackend (byteInts seed.val) (byteInts address.val) (byteInts x.val)
        (Int.ofNat start.val) steps.val := by
  let step := fun (cur : Std.Array Std.U8 16#usize) (i : Nat) =>
    th_pure seed (chainAdrs address (start.val + i)) (pad16Pure cur)
  have hp := List.foldl_hom pad16Pure
    (g₁ := step)
    (g₂ := fun cur i => pad16Pure (th_pure seed (chainAdrs address (start.val + i)) cur))
    (l := List.range steps.val) (init := x) (fun _ _ => rfl)
  rw [chain_hash_pure_def, hp, truncate_pad]
  have hb := List.foldl_hom (fun v : Std.Array Std.U8 16#usize => byteInts v.val)
    (g₁ := step)
    (g₂ := fun cur i => hash_bytes_node suppliedBackend (th_preimage (byteInts seed.val)
      (chain_position_words (byteInts address.val) (Int.ofNat start.val + Int.ofNat i))
      (pad_node cur)))
    (l := List.range steps.val) (init := x) (by
      intro cur i
      dsimp [step]
      rw [hash_step_value, chain_position_value]
      simp)
  simpa [wots_chain_value] using hb.symm

/-- Actual extraction, including zero steps and every non-overflowing u32 window. -/
theorem extracted_chain_value (seed address : Std.Array Std.U8 32#usize)
    (x : Std.Array Std.U8 16#usize) (start steps : Std.U32)
    (hb : start.val + steps.val ≤ U32.max) :
    sphincs_c10.hash.chain_hash seed address x start steps ⦃ r =>
      byteInts r.val = wots_chain_value suppliedBackend (byteInts seed.val) (byteInts address.val)
        (byteInts x.val) (Int.ofNat start.val) steps.val ⦄ := by
  let* ⟨r, hr⟩ ← sphincs_c10.hash.chain_hash_spec seed address x start steps hb
  rw [hr]
  exact chain_pure_value seed address x start steps

theorem secret_pure_value (secret : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp ci : Std.U32) :
    byteInts (Equiv.wotsSecretPure secret layer tree kp ci).val =
      wots_secret_value suppliedBackend (byteInts secret.val) (Int.ofNat layer.val)
        (Int.ofNat tree.val) (Int.ofNat kp.val) (Int.ofNat ci.val) := by
  unfold wots_secret_value hash_bytes_node suppliedBackend
  rw [← wots_private_input_value, bytesOfInts_byteInts, Equiv.wotsSecretPure, truncate16_val]
  simp [byteInts]

theorem extracted_secret_value (secret : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp ci : Std.U32) :
    sphincs_c10.hash.wots_secret secret layer tree kp ci ⦃ r =>
      byteInts r.val = wots_secret_value suppliedBackend (byteInts secret.val) (Int.ofNat layer.val)
        (Int.ofNat tree.val) (Int.ofNat kp.val) (Int.ofNat ci.val) ⦄ := by
  let* ⟨r, hr⟩ ← Equiv.wots_secret_spec secret layer tree kp ci
  rw [hr]
  exact secret_pure_value secret layer tree kp ci

theorem multi_pure_value (seed address : Std.Array Std.U8 32#usize)
    (values : Slice (Std.Array Std.U8 16#usize)) :
    byteInts (th_multi_pure seed address values).val =
      hash_bytes_node suppliedBackend (multi_preimage (byteInts seed.val) (byteInts address.val)
        (values.val.map (fun v => byteInts v.val))) := by
  unfold hash_bytes_node suppliedBackend
  rw [← multi_input_value, bytesOfInts_byteInts, th_multi_pure_def, truncate16_val]
  simp [byteInts]

theorem extracted_multi_value (seed address : Std.Array Std.U8 32#usize)
    (values : Slice (Std.Array Std.U8 16#usize)) (hn : values.val.length ≤ 43) :
    sphincs_c10.hash.th_multi seed address values ⦃ r =>
      byteInts r.val = hash_bytes_node suppliedBackend (multi_preimage (byteInts seed.val)
        (byteInts address.val) (values.val.map (fun v => byteInts v.val))) ⦄ := by
  let* ⟨r, hr⟩ ← sphincs_c10.hash.th_multi_spec seed address values hn
  rw [hr]
  exact multi_pure_value seed address values

theorem pure_address_value (layer : Std.U32) (tree : Std.U64)
    (kind kp ci cp ha : Nat) :
    byteInts (Equiv.adrsArr layer tree kind kp ci cp ha).val =
      address_words (Int.ofNat layer.val) (Int.ofNat tree.val) (Int.ofNat kind)
        (Int.ofNat kp) (Int.ofNat ci) (Int.ofNat cp) (Int.ofNat ha) := by
  have hb : (Equiv.adrsArr layer tree kind kp ci cp ha).val.map (·.val) =
      Equiv.specMakeAdrs layer.val tree.val kind kp ci cp ha := by
    have hu8 (n : Nat) : (⟨BitVec.ofNat 8 n⟩ : Std.U8).val = n % 256 := rfl
    simp [Equiv.adrsArr, Equiv.specMakeAdrs, Equiv.u32be, Equiv.u64be, hu8]
  rw [byteInts_as_nat, hb, address_value]

theorem keygen_nodes_value (seed secret : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32) :
    (Equiv.wotsKeygenChains seed secret layer tree kp).map (fun v => byteInts v.val) =
      wots_keygen_nodes suppliedBackend (byteInts seed.val) (byteInts secret.val)
        (Int.ofNat layer.val) (Int.ofNat tree.val) (Int.ofNat kp.val) := by
  simp only [Equiv.wotsKeygenChains, wots_keygen_nodes, List.map_map]
  apply List.map_congr_left
  intro j hj
  have hj43 : j < 43 := List.mem_range.mp hj
  have hjval : (⟨BitVec.ofNat 32 j⟩ : Std.U32).val = j := by
    change j % 2^32 = j
    exact Nat.mod_eq_of_lt (by omega)
  simp only [Function.comp_def, Equiv.wotsKeygenChain]
  rw [chain_pure_value, secret_pure_value, pure_address_value, hjval]
  rfl

theorem keygen_pure_value (seed secret : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32) :
    byteInts (Equiv.wotsKeygenPure seed secret layer tree kp).val =
      wots_keygen_value suppliedBackend (byteInts seed.val) (byteInts secret.val)
        (Int.ofNat layer.val) (Int.ofNat tree.val) (Int.ofNat kp.val) := by
  rw [Equiv.wotsKeygenPure, multi_pure_value, pure_address_value, keygen_nodes_value]
  rfl

/-- Complete actual key generation: all 43 chain ends and their compression. -/
theorem extracted_keygen_value (seed secret : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32) :
    sphincs_c10.wots.keygen_pk seed secret layer tree kp ⦃ r =>
      byteInts r.val = wots_keygen_value suppliedBackend (byteInts seed.val) (byteInts secret.val)
        (Int.ofNat layer.val) (Int.ofNat tree.val) (Int.ofNat kp.val) ⦄ := by
  let* ⟨r, hr⟩ ← Equiv.wots_keygen_pk_spec seed secret layer tree kp
  rw [hr]
  exact keygen_pure_value seed secret layer tree kp

end Extracted.C10FunctionalWots
