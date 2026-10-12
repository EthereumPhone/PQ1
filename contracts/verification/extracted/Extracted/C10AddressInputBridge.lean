/- Paired full-width address and private-derivation input endpoints.
   These are byte equalities before hashing, under the existing extraction
   and hash models. Shared generation and cross-tool interpretation remain TCB. -/
import Extracted.C10Representation
import Extracted.C10HashInputBridge
import Extracted.AdrsEquiv
import Extracted.WotsSecretSpec
import Extracted.ForsSecretSpec

open Aeneas Aeneas.Std Result
namespace Extracted.C10AddressInputBridge
open C10Representation C10HashInputBridge
set_option maxRecDepth 8192

theorem byteInts_as_nat (bs : List Std.U8) :
    byteInts bs = (bs.map (fun b => b.val)).map Int.ofNat := by
  simp [byteInts, List.map_map, Function.comp_def]

theorem u32_nat_value (n : Nat) :
    (Equiv.u32be n).map Int.ofNat = u32_bytes (Int.ofNat n) := by
  simp [Equiv.u32be, u32_bytes, List.range_succ,
    Int.natCast_ediv, Int.natCast_emod]

theorem u64_nat_value (n : Nat) :
    (Equiv.u64be n).map Int.ofNat = u64_bytes (Int.ofNat n) := by
  simp [Equiv.u64be, u64_bytes, List.range_succ,
    Int.natCast_ediv, Int.natCast_emod]

theorem u64_bytes_value (n : Std.U64) :
    byteInts (n.bv.toBEBytes.map (@UScalar.mk .U8)) =
      u64_bytes (Int.ofNat n.val) := by
  rw [byteInts_as_nat, Equiv.map_val_mk, Equiv.toBEBytes64_map_toNat]
  exact u64_nat_value n.val

theorem address_value (layer tree kind kp ci cp ha : Nat) :
    (Equiv.specMakeAdrs layer tree kind kp ci cp ha).map Int.ofNat =
      address_words (Int.ofNat layer) (Int.ofNat tree) (Int.ofNat kind)
        (Int.ofNat kp) (Int.ofNat ci) (Int.ofNat cp) (Int.ofNat ha) := by
  simp only [Equiv.specMakeAdrs, List.map_append, u32_nat_value,
    u64_nat_value, address_words]

/-- The actual address constructor consumes all bits of every machine field. -/
theorem extracted_address_input (layer : Std.U32) (tree : Std.U64)
    (kind kp ci cp ha : Std.U32) :
    sphincs_c10.address.make_adrs layer tree kind kp ci cp ha ⦃ a =>
      byteInts a.val = address_words (Int.ofNat layer.val) (Int.ofNat tree.val)
        (Int.ofNat kind.val) (Int.ofNat kp.val) (Int.ofNat ci.val)
        (Int.ofNat cp.val) (Int.ofNat ha.val) ⦄ := by
  let* ⟨a, h⟩ ← Equiv.make_adrs_spec layer tree kind kp ci cp ha
  rw [byteInts_as_nat, h, address_value]

theorem chain_index_value (a : List Nat) (ci : Nat) :
    (Equiv.specSetChainIndex a ci).map Int.ofNat =
      chain_index_words (a.map Int.ofNat) (Int.ofNat ci) := by
  simp [Equiv.specSetChainIndex, chain_index_words, u32_nat_value]

theorem extracted_chain_index_input (a : Std.Array Std.U8 32#usize) (ci : Std.U32) :
    sphincs_c10.address.set_chain_index a ci ⦃ b =>
      byteInts b.val = chain_index_words (byteInts a.val) (Int.ofNat ci.val) ⦄ := by
  let* ⟨b, h⟩ ← Equiv.set_chain_index_spec a ci
  rw [byteInts_as_nat, h, chain_index_value, ← byteInts_as_nat]

theorem chain_position_value (a : Std.Array Std.U8 32#usize) (cp : Nat) :
    byteInts (chainAdrs a cp).val =
      chain_position_words (byteInts a.val) (Int.ofNat cp) := by
  simp only [chainAdrs_val, byteInts_append, u32_bytes_value, chain_position_words]
  simp [byteInts]

theorem wots_tree_value (tree : Std.U64) :
    byteInts (Equiv.wotsTreeBytes tree) =
      List.replicate 24 0 ++ u64_bytes (Int.ofNat tree.val) := by
  simp only [Equiv.wotsTreeBytes, byteInts_append, u64_bytes_value]
  simp [byteInts]

theorem wots_private_input_value (secret : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp ci : Std.U32) :
    byteInts (Equiv.wotsSecretPreimage secret layer tree kp ci) =
      wots_private_preimage (byteInts secret.val) (Int.ofNat layer.val)
        (Int.ofNat tree.val) (Int.ofNat kp.val) (Int.ofNat ci.val) := by
  simp only [Equiv.wotsSecretPreimage, byteInts_append, u32_bytes_value,
    wots_tree_value, wots_private_preimage]
  simp [byteInts, List.append_assoc]

theorem fors_private_input_value (secret : Std.Array Std.U8 32#usize)
    (ht tree leaf : Std.U32) :
    byteInts (Equiv.forsSecretPreimage secret ht tree leaf) =
      fors_private_preimage (byteInts secret.val) (Int.ofNat ht.val)
        (Int.ofNat tree.val) (Int.ofNat leaf.val) := by
  simp only [Equiv.forsSecretPreimage, byteInts_append, u32_bytes_value,
    fors_private_preimage]
  simp [byteInts]

theorem extracted_wots_private_input (secret : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp ci : Std.U32) :
    sphincs_c10.hash.wots_secret secret layer tree kp ci ⦃ r =>
      r = truncate16 (sha256_pure (bytesOfInts
        (wots_private_preimage (byteInts secret.val) (Int.ofNat layer.val)
          (Int.ofNat tree.val) (Int.ofNat kp.val) (Int.ofNat ci.val)))) ⦄ := by
  rw [← wots_private_input_value, bytesOfInts_byteInts]
  simpa only [Equiv.wotsSecretPure] using Equiv.wots_secret_spec secret layer tree kp ci

theorem extracted_fors_private_input (secret : Std.Array Std.U8 32#usize)
    (ht tree leaf : Std.U32) :
    sphincs_c10.hash.fors_secret secret ht tree leaf ⦃ r =>
      r = truncate16 (sha256_pure (bytesOfInts
        (fors_private_preimage (byteInts secret.val) (Int.ofNat ht.val)
          (Int.ofNat tree.val) (Int.ofNat leaf.val)))) ⦄ := by
  rw [← fors_private_input_value, bytesOfInts_byteInts]
  simpa only [Equiv.forsSecretPure] using Equiv.fors_secret_spec secret ht tree leaf

end Extracted.C10AddressInputBridge
