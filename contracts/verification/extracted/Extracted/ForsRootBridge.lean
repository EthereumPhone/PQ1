/- FORS tree-root construction and the final emitted signer slot. -/
import Extracted.ForsRootSpec
import Extracted.ForsRootVendored
import Extracted.ForsSecretBridge
import Extracted.ForsRecoveryBridge

open Aeneas Aeneas.Std Result
set_option maxHeartbeats 1500000
set_option maxRecDepth 8192
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes

namespace Extracted.Equiv
open SphincsCVerify.Spec

private theorem fors_root_pad (v : Std.Array Std.U8 16#usize) :
    toSpecDigest (pad16p v) = ByteVec.pad16 (toSpecNode v) := by
  have h : pad16p v = pad16Pure v := by unfold pad16Pure; rfl
  rw [h, recovery_pad]

attribute [local irreducible] th thPair Adrs.forsNode ByteVec.pad16

theorem fors_root_node_matches_vendored (seed sk : Std.Array Std.U8 32#usize)
    (ht tree : Std.U32) (h idx : Nat) (hh : h ≤ 11)
    (hi : (idx+1)*2^h ≤ 2048) :
    toSpecNode (forsRootNode seed sk ht tree h idx) =
      forsMtNode (toSpecDigest seed) (UInt64.ofNat ht.val) (UInt32.ofNat tree.val)
        (fun j => forsSecret (toSpecDigest sk) (UInt32.ofNat ht.val)
          (UInt32.ofNat tree.val) (UInt32.ofNat j)) h idx := by
  have hidx : idx < 2^32 := by
    have hp : 0 < 2^h := by positivity
    nlinarith
  induction h generalizing idx with
  | zero =>
    rw [forsRootNode, forsMtNode, recovery_th, fors_recovery_adrs _ _ _ _ (by norm_num) hidx,
      fors_root_pad, fors_secret_pure_matches_vendored]
    have hv : (⟨BitVec.ofNat 32 idx⟩ : Std.U32).val = idx := Nat.mod_eq_of_lt hidx
    rw [hv]
    rfl
  | succ h ih =>
    rw [forsRootNode, forsMtNode, merkle_th_pair,
      fors_recovery_adrs _ _ _ _ (by omega) hidx, fors_root_pad, fors_root_pad]
    have hpow : 2^(h+1) = 2^h * 2 := by rw [pow_succ]
    rw [hpow] at hi
    have hp : 0 < 2^h := by positivity
    rw [ih (2*idx) (by omega) (by nlinarith) (by nlinarith),
      ih (2*idx+1) (by omega) (by nlinarith) (by nlinarith)]

/-- The actual Rust stack algorithm equals the independent recursive reference
    tree at deployed height 11, for all seeds and full-width indices. -/
theorem firmware_fors_root_matches_vendored (seed sk : Std.Array Std.U8 32#usize)
    (ht tree : Std.U32) :
    sphincs_c10.fors.compute_fors_root seed sk ht tree ⦃ r =>
      toSpecNode r = forsMtNode (toSpecDigest seed) (UInt64.ofNat ht.val)
        (UInt32.ofNat tree.val)
        (fun j => forsSecret (toSpecDigest sk) (UInt32.ofNat ht.val)
          (UInt32.ofNat tree.val) (UInt32.ofNat j)) A 0 ⦄ := by
  let* ⟨r, hr⟩ ← fors_compute_root_spec seed sk ht tree
  rw [hr]
  exact fors_root_node_matches_vendored seed sk ht tree 11 0 (by decide) (by decide)

/-- The reference final signature slot carries this full tree root. Its value
    is independent of a purported final leaf index; forced-zero enforcement
    remains the verifier/grinding obligation. -/
theorem firmware_fors_final_slot_matches_vendored (seed sk : Std.Array Std.U8 32#usize)
    (ht : Std.U32) (leaf : Nat) :
    sphincs_c10.fors.compute_fors_root seed sk ht 12#u32 ⦃ r =>
      toSpecNode r = Signer.forsSigningValue (toSpecDigest seed) (toSpecDigest sk)
        ht.val (K-1) leaf ⦄ := by
  let* ⟨r, hr⟩ ← firmware_fors_root_matches_vendored seed sk ht 12#u32
  simpa only [Signer.forsSigningValue, if_pos rfl, K] using hr

end Extracted.Equiv
