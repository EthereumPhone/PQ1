/- Every generated FORS secret and sibling agrees with the reference signer. -/
import Extracted.ForsAuthSpec
import Extracted.ForsAuthVendored
import Extracted.ForsRootBridge

open Aeneas Aeneas.Std Result
set_option maxHeartbeats 1500000
set_option maxRecDepth 8192
namespace Extracted.Equiv
open SphincsCVerify.Spec
attribute [local irreducible] forsRootNode forsRootSlots forsAuthEnd forsAuthSibling

theorem fors_auth_path_matches_vendored (seed sk : Std.Array Std.U8 32#usize)
    (ht tree leaf : Std.U32) (path : Std.Array (Std.Array Std.U8 16#usize) 11#usize)
    (hleaf : leaf.val < 2048)
    (hp : ∀ k, k < 11 → path.val[k]! = forsRootNode seed sk ht tree k (forsAuthSibling leaf.val k)) :
    (path.val.map toSpecNode).toArray =
      forsMtAuthPath (toSpecDigest seed) (UInt64.ofNat ht.val) (UInt32.ofNat tree.val)
        (fun j => forsSecret (toSpecDigest sk) (UInt32.ofNat ht.val)
          (UInt32.ofNat tree.val) (UInt32.ofNat j)) leaf.val := by
  have hlen : path.val.length = 11 := by simpa using path.property
  apply _root_.Array.ext
  · simp [hlen, forsMtAuthPath, A]
  intro i hi1 hi2
  have hi : i < 11 := by simpa [hlen] using hi1
  simp only [forsMtAuthPath, _root_.Array.getElem_ofFn, List.getElem_toArray, List.getElem_map]
  rw [← getElem!_pos path.val i (by omega), hp i hi]
  have hsched := fors_auth_leaf_schedule ⟨leaf.val, hleaf⟩ ⟨i, hi⟩
  simp only [forsAuthLeafAt] at hsched
  obtain ⟨_, _, _, _, _, hsib, _, hfoot⟩ := hsched
  have hx := fors_root_node_matches_vendored seed sk ht tree i (forsAuthSibling leaf.val i)
    (by omega) hfoot
  simpa only [sibIdx, hsib] using hx

/-- The actual Rust helper terminates and emits the faithful secret and all
    eleven siblings. The valid-leaf precondition is explicit; full signer
    control flow, randomization and concrete backend refinement are separate. -/
theorem firmware_fors_auth_matches_vendored (seed sk : Std.Array Std.U8 32#usize)
    (ht tree leaf : Std.U32) (hleaf : leaf.val < 2048) :
    sphincs_c10.fors.sign_fors_tree seed sk ht tree leaf ⦃ r =>
      toSpecNode r.1 = forsSecret (toSpecDigest sk) (UInt32.ofNat ht.val)
        (UInt32.ofNat tree.val) (UInt32.ofNat leaf.val) ∧
      (r.2.val.map toSpecNode).toArray =
        forsMtAuthPath (toSpecDigest seed) (UInt64.ofNat ht.val) (UInt32.ofNat tree.val)
          (fun j => forsSecret (toSpecDigest sk) (UInt32.ofNat ht.val)
            (UInt32.ofNat tree.val) (UInt32.ofNat j)) leaf.val ⦄ := by
  let* ⟨secret, path, hsecret, hpath⟩ ← fors_sign_tree_spec seed sk ht tree leaf hleaf
  constructor
  · rw [hsecret, fors_secret_pure_matches_vendored]
  · exact fors_auth_path_matches_vendored seed sk ht tree leaf path hleaf hpath

end Extracted.Equiv
