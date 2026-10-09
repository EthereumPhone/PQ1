/- The actual FORS signing path recovers the actual constructed tree root. -/
import Extracted.ForsAuthBridge

open Aeneas Aeneas.Std Result
set_option maxHeartbeats 1500000
set_option maxRecDepth 8192

namespace Extracted.Equiv

attribute [local irreducible] forsRootNode forsAuthSibling

/-- Folding canonical siblings from any level reaches the corresponding ancestor.
    The only shape hypothesis is the actual signer's proved path invariant. -/
theorem fors_auth_recovery_fold (seed sk : Std.Array Std.U8 32#usize)
    (ht tree : Std.U32) (leaf : Nat) (hleaf : leaf < 2048)
    (path : Std.Array (Std.Array Std.U8 16#usize) 11#usize)
    (hp : ∀ k, k < 11 → path.val[k]! = forsRootNode seed sk ht tree k (forsAuthSibling leaf k))
    (n h : Nat) (hb : h + n ≤ 11) :
    forsRecoveryFold seed ht tree ((path.val.drop h).take n)
      (forsRootNode seed sk ht tree h (leaf / 2^h)) (leaf / 2^h) h =
      forsRootNode seed sk ht tree (h+n) (leaf / 2^(h+n)) := by
  have hlen : path.val.length = 11 := by simpa using path.property
  induction n generalizing h with
  | zero => simp [forsRecoveryFold]
  | succ n ih =>
    have hh : h < 11 := by omega
    have hhpath : h < path.val.length := by omega
    have hd : (path.val.drop h).take (n+1) =
        path.val[h] :: (path.val.drop (h+1)).take n := by
      rw [← List.cons_getElem_drop_succ (l := path.val) (n := h) (h := hhpath)]
      rfl
    have hvalue : path.val[h] = forsRootNode seed sk ht tree h (forsAuthSibling leaf h) := by
      rw [← getElem!_pos path.val h hhpath, hp h hh]
    have hs := fors_auth_leaf_schedule ⟨leaf, hleaf⟩ ⟨h, hh⟩
    simp only [forsAuthLeafAt, Fin.val_mk] at hs
    obtain ⟨_, _, _, _, _, hsib, _, _⟩ := hs
    have hdiv : leaf / 2^h / 2 = leaf / 2^(h+1) := by
      rw [Nat.div_div_eq_div_mul, pow_succ]
    have hstep :
        (if (leaf / 2^h) % 2 = 0 then
          th_pair_pure seed (forsRecoveryAdrs ht tree (h+1) (leaf / 2^h / 2))
            (pad16p (forsRootNode seed sk ht tree h (leaf / 2^h)))
            (pad16p (forsRootNode seed sk ht tree h (forsAuthSibling leaf h)))
        else
          th_pair_pure seed (forsRecoveryAdrs ht tree (h+1) (leaf / 2^h / 2))
            (pad16p (forsRootNode seed sk ht tree h (forsAuthSibling leaf h)))
            (pad16p (forsRootNode seed sk ht tree h (leaf / 2^h)))) =
        forsRootNode seed sk ht tree (h+1) (leaf / 2^(h+1)) := by
      by_cases heven : (leaf / 2^h) % 2 = 0
      · have hleft : leaf / 2^h = 2 * (leaf / 2^(h+1)) := by omega
        rw [if_pos heven, hsib, if_pos heven, hdiv, hleft, forsRootNode]
      · have hright : leaf / 2^h = 2 * (leaf / 2^(h+1)) + 1 := by omega
        have hsib' : forsAuthSibling leaf h = 2 * (leaf / 2^(h+1)) := by
          rw [hsib, if_neg heven, hright]
          omega
        rw [if_neg heven, hsib', hdiv, hright, forsRootNode]
    rw [hd, forsRecoveryFold, hvalue, hstep, hdiv]
    simpa only [Nat.add_assoc, Nat.add_comm, Nat.add_left_comm] using ih (h+1) (by omega)

/-- A secret and all eleven siblings proved by the signer recover its root. -/
theorem fors_auth_recovery_root (seed sk : Std.Array Std.U8 32#usize)
    (ht tree leaf : Std.U32) (hleaf : leaf.val < 2048)
    (secret : Std.Array Std.U8 16#usize)
    (path : Std.Array (Std.Array Std.U8 16#usize) 11#usize)
    (hsecret : secret = forsSecretPure sk ht tree leaf)
    (hp : ∀ k, k < 11 → path.val[k]! = forsRootNode seed sk ht tree k (forsAuthSibling leaf.val k)) :
    forsRecoveryFold seed ht tree path.val
      (th_pure seed (forsRecoveryAdrs ht tree 0 leaf.val) (pad16p secret)) leaf.val 0 =
      forsRootNode seed sk ht tree 11 0 := by
  have hlen : path.val.length = 11 := by simpa using path.property
  have hu : (⟨BitVec.ofNat 32 leaf.val⟩ : Std.U32) = leaf := by
    apply UScalar.eq_of_val_eq
    exact Nat.mod_eq_of_lt leaf.hBounds
  have hstart : th_pure seed (forsRecoveryAdrs ht tree 0 leaf.val) (pad16p secret) =
      forsRootNode seed sk ht tree 0 leaf.val := by
    rw [forsRootNode, hu, hsecret]
  have hroot : leaf.val / 2^11 = 0 := Nat.div_eq_of_lt hleaf
  have h := fors_auth_recovery_fold seed sk ht tree leaf.val hleaf path hp 11 0 (by decide)
  simpa only [List.drop_zero, List.take_of_length_le (by omega : path.val.length ≤ 11),
    Nat.zero_add, pow_zero, Nat.div_one, hroot, hstart] using h

/-- All three actual helpers terminate, and reconstruction equals construction.
    This is their composition, not a theorem about the complete signer loop. -/
theorem firmware_fors_sign_recover_root (seed sk : Std.Array Std.U8 32#usize)
    (ht tree leaf : Std.U32) (hleaf : leaf.val < 2048) :
    sphincs_c10.fors.sign_fors_tree seed sk ht tree leaf ⦃ signed =>
      sphincs_c10.hypertree.reconstruct_fors_root seed ht tree leaf signed.1 signed.2 ⦃ recovered =>
        sphincs_c10.fors.compute_fors_root seed sk ht tree ⦃ expected => recovered = expected ⦄ ⦄ ⦄ := by
  let* ⟨secret, path, hsecret, hpath⟩ ← fors_sign_tree_spec seed sk ht tree leaf hleaf
  let* ⟨recovered, hr⟩ ← fors_recovery_spec seed ht tree leaf secret path
  let* ⟨expected, he⟩ ← fors_compute_root_spec seed sk ht tree
  rw [hr, he]
  exact fors_auth_recovery_root seed sk ht tree leaf hleaf secret path hsecret hpath

/-- The recovered value is also the faithful reference tree root. -/
theorem firmware_fors_sign_recover_matches_vendored (seed sk : Std.Array Std.U8 32#usize)
    (ht tree leaf : Std.U32) (hleaf : leaf.val < 2048) :
    sphincs_c10.fors.sign_fors_tree seed sk ht tree leaf ⦃ signed =>
      sphincs_c10.hypertree.reconstruct_fors_root seed ht tree leaf signed.1 signed.2 ⦃ recovered =>
        toSpecNode recovered = SphincsCVerify.Spec.forsMtNode (toSpecDigest seed)
          (UInt64.ofNat ht.val) (UInt32.ofNat tree.val)
          (fun j => SphincsCVerify.Spec.forsSecret (toSpecDigest sk) (UInt32.ofNat ht.val)
            (UInt32.ofNat tree.val) (UInt32.ofNat j)) 11 0 ⦄ ⦄ := by
  let* ⟨secret, path, hsecret, hpath⟩ ← fors_sign_tree_spec seed sk ht tree leaf hleaf
  let* ⟨recovered, hr⟩ ← fors_recovery_spec seed ht tree leaf secret path
  rw [hr, fors_auth_recovery_root seed sk ht tree leaf hleaf secret path hsecret hpath]
  exact fors_root_node_matches_vendored seed sk ht tree 11 0 (by decide) (by decide)

end Extracted.Equiv
