/- Compose the actual FORS component calls; the full verifier-prefix proof
   ties this wrapper back to its extracted call site. -/
import Extracted.ForsParseSpec
import Extracted.ForsPrefixVendored
open Aeneas Aeneas.Std Result ControlFlow
namespace Extracted.Equiv
open sphincs_c10 SphincsCVerify.Spec
set_option maxHeartbeats 4000000
set_option maxRecDepth 8192

def toSpecForsSig (secrets : ForsSecrets) (paths : ForsAuthPaths) : Fors.ForsSig :=
  { secrets := (secrets.val.map toSpecNode).toArray
    secretsLen := by simpa [K] using secrets.property
    authPaths := (paths.val.map (fun p => (p.val.map toSpecNode).toArray)).toArray
    authPathsLen := by simpa [K] using paths.property }

theorem toSpecForsSig_secret (secrets : ForsSecrets) (paths : ForsAuthPaths)
    (j : Nat) (hj : j < 13) :
    (toSpecForsSig secrets paths).secrets.getD j (ByteVec.zero 16) = toSpecNode (secrets.val[j]!) := by
  have hs : j < secrets.val.length := by rw [secrets.property]; exact hj
  simp [toSpecForsSig, Array.getD_eq_getD_getElem?, List.getElem?_eq_getElem hs,
    getElem!_pos secrets.val j hs]

theorem toSpecForsSig_auth (secrets : ForsSecrets) (paths : ForsAuthPaths)
    (j : Nat) (hj : j < 12) :
    (toSpecForsSig secrets paths).authPaths.getD j #[] =
      ((paths.val[j]!).val.map toSpecNode).toArray := by
  have hs : j < paths.val.length := by rw [paths.property]; exact hj
  simp [toSpecForsSig, Array.getD_eq_getD_getElem?, List.getElem?_eq_getElem hs,
    getElem!_pos paths.val j hs]

/-- Straight-line FORS block from the already extracted verifier. It has no
    new opaque calls; the caller correspondence is a separate theorem. -/
def forsForestPhase (seed : Std.Array Std.U8 32#usize) (ht : Std.U32)
    (indices : Std.Array Std.U32 13#usize) (secrets : ForsSecrets) (paths : ForsAuthPaths) :
    Result (Std.Array Std.U8 16#usize) := do
  let roots ← hypertree.verify_loop2 {start := 0#usize, «end» := 12#usize}
    seed indices ht secrets (Array.repeat 13#usize (Array.repeat 16#usize 0#u8)) paths
  let wide ← lift (core.convert.num.FromU64U32.from ht)
  let adrs ← address.make_adrs 0#u32 wide params.ADRS_FORS_TREE 12#u32 0#u32 0#u32 0#u32
  let last ← Array.index_usize secrets 12#usize
  let padded ← hash.pad16 last
  let lastRoot ← hash.th seed adrs padded
  let allRoots ← Array.update roots 12#usize lastRoot
  fors.compute_fors_pk seed ht allRoots

attribute [local irreducible] Fors.reconstructRoot th thMulti Adrs.forsNode

theorem forsForestPhase_matches_vendored (seed digest : Std.Array Std.U8 32#usize)
    (ht : Std.U32) (indices : Std.Array Std.U32 13#usize)
    (secrets : ForsSecrets) (paths : ForsAuthPaths)
    (hht : ht.val = SphincsCVerify.Util.extractHtIndex (toSpecDigest digest))
    (hi : ∀ j, j < 13 → (indices.val[j]!).val =
      (SphincsCVerify.Util.extractForsIndices (toSpecDigest digest)).getD j 0)
    (hzero : (SphincsCVerify.Util.extractForsIndices (toSpecDigest digest)).getD 12 0 = 0) :
    forsForestPhase seed ht indices secrets paths ⦃ r =>
      Fors.reconstructForsPk (toSpecDigest seed) (toSpecDigest digest)
        (toSpecForsSig secrets paths) = some (toSpecNode r) ⦄ := by
  unfold forsForestPhase
  let* ⟨roots, hroots⟩ ← firmware_fors_normal_roots seed ht indices secrets
    (Array.repeat 13#usize (Array.repeat 16#usize 0#u8)) paths
  simp only [lift, core.convert.num.FromU64U32.from]
  let* ⟨adrs, hadrs⟩ ← make_adrs_spec 0#u32
    (⟨BitVec.setWidth 64 ht.bv⟩ : Std.U64) params.ADRS_FORS_TREE 12#u32 0#u32 0#u32 0#u32
  have hwide : (⟨BitVec.setWidth 64 ht.bv⟩ : Std.U64).val = ht.val :=
    BitVec.toNat_setWidth_of_le (by decide)
  have ha : forsRecoveryAdrs ht 12#u32 0 0 = adrs := by
    apply forsRecoveryAdrs_eq_of_map_val
    simpa only [params.ADRS_FORS_TREE, hwide] using hadrs
  let* ⟨last, hl⟩ ← Array.index_usize_spec secrets 12#usize (by scalar_tac)
  let* ⟨padded, hp⟩ ← pad16_pure_spec last
  let* ⟨lastRoot, hlast⟩ ← hash.th_spec seed adrs padded
  let* ⟨allRoots, hall⟩ ← Array.update_spec roots 12#usize lastRoot (by scalar_tac)
  let* ⟨pk, hpk⟩ ← firmware_fors_pk_matches_vendored seed ht allRoots
  have hlastSpec : toSpecNode lastRoot =
      th (toSpecDigest seed) (Adrs.forsNode (UInt64.ofNat ht.val) 12 0 0)
        (ByteVec.pad16 (toSpecNode (secrets.val[12]!))) := by
    rw [hlast, hp, ← ha, recovery_th, recovery_pad,
      fors_recovery_adrs _ _ _ _ (by decide) (by decide)]
    rw [hl, ← getElem!_pos secrets.val 12 (by have h := secrets.property; simp_all)]
    rfl
  rw [hpk]
  simp only [Fors.reconstructForsPk, K, hzero, ne_eq, not_true_eq_false, if_false]
  rw [← hht]
  apply congrArg some
  apply congrArg (Fors.computeForsPk (toSpecDigest seed) (UInt64.ofNat ht.val))
  apply _root_.Array.ext
  · simp [allRoots.property]
  · intro j hj hj'
    have hj13 : j < 13 := by simpa using hj
    have har : j < allRoots.val.length := by rw [allRoots.property]; exact hj13
    simp only [List.getElem_toArray, List.getElem_map]
    rw [← getElem!_pos allRoots.val j har, hall, Array.set_val_eq]
    simp only [show (12#usize).val = 12 from rfl, Array.getElem_push, Array.size_ofFn]
    by_cases hj12 : j < 12
    · rw [dif_pos hj12]
      simp only [Array.getElem_ofFn]
      rw [List.set_getElem!_ne _ _ _ _ (by simp only [Nat.not_eq]; omega),
        hroots j hj13, if_pos hj12]
      rw [toSpecForsSig_secret _ _ _ (by omega), toSpecForsSig_auth _ _ _ hj12]
      unfold forsNormalRoot
      rw [hi j hj13]
    · rw [dif_neg hj12]
      have hjEq : j = 12 := by omega
      subst j
      rw [List.set_getElem!_eq _ _ _ _ ⟨by have h := roots.property; simp_all, rfl⟩,
        hlastSpec, toSpecForsSig_secret _ _ _ (by decide)]
      rfl
end Extracted.Equiv
