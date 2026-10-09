/- Compose actual secret generation, chain walking, positional assembly and
   compression with the faithfully copied verifier key-generation function. -/
import Extracted.WotsKeygenSpec
import Extracted.WotsSecretBridge

open Aeneas Aeneas.Std Result
set_option maxHeartbeats 1500000
set_option maxRecDepth 8192
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes

namespace Extracted.Equiv
open SphincsCVerify.Spec

theorem wots_keygen_pure_matches_vendored (seed sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32) :
    toSpecNode (wotsKeygenPure seed sk layer tree kp) =
      Wots.keygenPk (toSpecDigest seed) (toSpecDigest sk) (UInt32.ofNat layer.val)
        (UInt64.ofNat tree.val) (UInt32.ofNat kp.val) := by
  rw [wotsKeygenPure, recovery_th_multi, recovery_adrs_pk]
  unfold Wots.keygenPk
  congr 1
  simp only [wotsKeygenChains, List.map_map, L]
  apply List.map_congr_left
  intro j hj
  have hj43 : j < 43 := List.mem_range.mp hj
  have hn : (⟨BitVec.ofNat 32 j⟩ : Std.U32).val = j := by
    change j % 2^32 = j
    exact Nat.mod_eq_of_lt (by omega)
  simp only [Function.comp_def, wotsKeygenChain]
  rw [recovery_chain seed _ _ 0#u32 7#u32 (by scalar_tac),
    recovery_adrs_index layer tree kp j hj43,
    wots_secret_pure_matches_vendored, hn]
  rfl

/-- Actual Rust extraction agrees with the reference WOTS public key for every
    seed and full-width address. No success or hardness premise is required. -/
theorem firmware_wots_keygen_matches_vendored (seed sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32) :
    sphincs_c10.wots.keygen_pk seed sk layer tree kp ⦃ r =>
      toSpecNode r = Wots.keygenPk (toSpecDigest seed) (toSpecDigest sk)
        (UInt32.ofNat layer.val) (UInt64.ofNat tree.val) (UInt32.ofNat kp.val) ⦄ := by
  let* ⟨r, hr⟩ ← wots_keygen_pk_spec seed sk layer tree kp
  rw [hr]
  exact wots_keygen_pure_matches_vendored seed sk layer tree kp

end Extracted.Equiv
