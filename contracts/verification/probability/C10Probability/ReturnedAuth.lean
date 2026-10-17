import C10Probability.AuthReplay
import C10Probability.AuthKeepLaw

/-! Certificates for the arrays returned by the actual two tree builders.
Target bounds are needed when consuming the certificate as a complete path. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

def MerkleAuthCertificate (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree target : ℕ) (auth : List Randomizer) (root : Randomizer) : Prop :=
  auth.length = 9 ∧ CollectedTreeNode table
    (fun kp => replayProgram table (wotsLeafProgram encode seed layer tree kp))
    (fun kp h l r => encode (.inl (treePairInput seed layer tree kp h l r)))
    randomizerOfDigest target auth 9 512 root

def ForsAuthCertificate (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree target : ℕ) (auth : List Randomizer) (root : Randomizer) : Prop :=
  auth.length = 11 ∧ CollectedTreeNode table
    (fun kp => replayProgram table (forsLeafProgram encode seed ht tree kp))
    (fun kp h l r => encode (.inl (forsTreePairInput seed ht tree kp h l r)))
    randomizerOfDigest target auth 11 2048 root

set_option maxRecDepth 20000 in
theorem replay_subtree_auth_certificate (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree target : ℕ) (out : List (Randomizer × ℕ) × AuthKeep)
    (recorded : replayProgram table
      (subtreeProgram encode seed layer tree (authRemember target) emptyAuthKeep) = some out) :
    MerkleAuthCertificate encode table seed layer tree target out.2.nodes (treeRoot out.1) := by
  rw [subtreeProgram, replay_program_cast, replay_program_map_return] at recorded
  have cert := replay_complete_tree_collected table 345 (wotsLeafProgram encode seed layer tree)
    (fun kp h l r => encode (.inl (treePairInput seed layer tree kp h l r))) randomizerOfDigest
    target 9 AuthKeep.nodes (AuthKeepValid table _ _ randomizerOfDigest target 9)
    (authRemember target) (merkle_remember_auth_law table _ _ randomizerOfDigest target 9)
    512 9 emptyAuthKeep 0 out (initial_auth_keep_valid table _ _ randomizerOfDigest target)
    merkle_auth_schedule subtree_shape recorded
  exact ⟨cert.1.1, cert.2⟩

theorem replay_merkle_auth_certificate (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree target : ℕ) (out : List Randomizer × Randomizer)
    (recorded : replayProgram table (merkleBuildProgram encode seed layer tree target) = some out) :
    MerkleAuthCertificate encode table seed layer tree target out.1 out.2 := by
  rw [merkleBuildProgram, replay_program_map_return] at recorded
  cases hr : replayProgram table
      (subtreeProgram encode seed layer tree (authRemember target) emptyAuthKeep) with
  | none => simp only [hr, Option.map_none] at recorded; cases recorded
  | some result =>
    simp only [hr, Option.map_some, Option.some.injEq] at recorded
    subst out
    exact replay_subtree_auth_certificate encode table seed layer tree target result hr

set_option maxRecDepth 80000 in
theorem replay_fors_state_auth_certificate (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree target : ℕ) (out : List (Randomizer × ℕ) × List Randomizer)
    (recorded : replayProgram table (forsTreeStateProgram encode seed ht tree
      (forsRemember target) (List.replicate 11 0)) = some out) :
    ForsAuthCertificate encode table seed ht tree target out.2 (treeRoot out.1) := by
  rw [forsTreeStateProgram, replay_program_cast, replay_program_map_return] at recorded
  exact replay_complete_tree_collected table 2 (forsLeafProgram encode seed ht tree)
    (fun kp h l r => encode (.inl (forsTreePairInput seed ht tree kp h l r))) randomizerOfDigest
    target 11 id (fun auth => auth.length = 11) (forsRemember target)
    (fors_remember_auth_law table _ _ randomizerOfDigest target 11)
    2048 11 (List.replicate 11 0) 0 out (by simp) fors_auth_schedule fors_tree_shape recorded

theorem replay_fors_auth_certificate (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree target : ℕ) (out : Randomizer × List Randomizer)
    (recorded : replayProgram table (forsTreeProgram encode seed ht tree target) = some out) :
    ForsAuthCertificate encode table seed ht tree target out.2 out.1 := by
  rw [forsTreeProgram, replay_program_map_return] at recorded
  cases hr : replayProgram table
      (forsTreeStateProgram encode seed ht tree (forsRemember target) (List.replicate 11 0)) with
  | none => simp only [hr, Option.map_none] at recorded; cases recorded
  | some result =>
    simp only [hr, Option.map_some, Option.some.injEq] at recorded
    subst out
    exact replay_fors_state_auth_certificate encode table seed ht tree target result hr

theorem merkle_build_auth_certificate [DecidableEq K] (encode : WotsQuery → K)
    (table : Memo K Digest) (seed : ByteKey) (layer tree target : ℕ)
    (out : (List Randomizer × Randomizer) × Memo K Digest)
    (supported : out ∈ (merkleBuild encode table seed layer tree target).support) :
    MerkleAuthCertificate encode out.2 seed layer tree target out.1.1 out.1.2 := by
  exact replay_merkle_auth_certificate encode out.2 seed layer tree target out.1
    (eval_program_replay digestDraw _ table out (by rwa [merkle_build_eval]))

theorem fors_tree_auth_certificate [DecidableEq K] (encode : WotsQuery → K)
    (table : Memo K Digest) (seed : ByteKey) (ht tree target : ℕ)
    (out : (Randomizer × List Randomizer) × Memo K Digest)
    (supported : out ∈ (forsTree encode table seed ht tree target).support) :
    ForsAuthCertificate encode out.2 seed ht tree target out.1.2 out.1.1 := by
  exact replay_fors_auth_certificate encode out.2 seed ht tree target out.1
    (eval_program_replay digestDraw _ table out (by rwa [fors_tree_eval]))

end
end C10Probability
