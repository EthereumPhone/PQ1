import C10Probability.TreeCertificate
import C10Probability.MerkleBuild
import C10Probability.ForsTree

/-! The actual 512-leaf Merkle and 2048-leaf FORS stack builders supply complete
root certificates. Authentication bookkeeping is retained without assuming
that its returned array is already a correct reference path. -/
namespace C10Probability
noncomputable section

variable {K S : Type*}

def MerkleTreeCertificate (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree : ℕ) (root : Randomizer) : Prop :=
  RecordedTreeNode table (fun kp => replayProgram table (wotsLeafProgram encode seed layer tree kp))
    (fun kp h l r => encode (.inl (treePairInput seed layer tree kp h l r)))
    randomizerOfDigest 9 512 root

def ForsTreeCertificate (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree : ℕ) (root : Randomizer) : Prop :=
  RecordedTreeNode table (fun kp => replayProgram table (forsLeafProgram encode seed ht tree kp))
    (fun kp h l r => encode (.inl (forsTreePairInput seed ht tree kp h l r)))
    randomizerOfDigest 11 2048 root

set_option maxRecDepth 20000 in
theorem replay_subtree_certificate (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree : ℕ)
    (remember : ℕ → ℕ → Randomizer → Randomizer → S → S) (initial : S)
    (out : List (Randomizer × ℕ) × S)
    (recorded : replayProgram table (subtreeProgram encode seed layer tree remember initial) = some out) :
    MerkleTreeCertificate encode table seed layer tree (treeRoot out.1) := by
  rw [subtreeProgram, replay_program_cast, replay_program_map_return] at recorded
  exact replay_complete_tree_recorded table 345 (wotsLeafProgram encode seed layer tree)
    (fun kp h l r => encode (.inl (treePairInput seed layer tree kp h l r)))
    randomizerOfDigest remember 512 9 initial 0 out subtree_shape recorded

theorem replay_subtree_root_certificate (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree : ℕ) (root : Randomizer)
    (recorded : replayProgram table (subtreeRootProgram encode seed layer tree) = some root) :
    MerkleTreeCertificate encode table seed layer tree root := by
  rw [subtreeRootProgram, replay_program_map_return] at recorded
  cases hr : replayProgram table
      (subtreeProgram encode seed layer tree (fun _ _ _ _ (_ : Unit) => ()) ()) with
  | none => simp only [hr, Option.map_none] at recorded; cases recorded
  | some out =>
      simp only [hr, Option.map_some, Option.some.injEq] at recorded
      exact recorded ▸ replay_subtree_certificate encode table seed layer tree _ () out hr

theorem replay_merkle_build_certificate (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree target : ℕ) (out : List Randomizer × Randomizer)
    (recorded : replayProgram table (merkleBuildProgram encode seed layer tree target) = some out) :
    MerkleTreeCertificate encode table seed layer tree out.2 := by
  rw [merkleBuildProgram, replay_program_map_return] at recorded
  cases hr : replayProgram table
      (subtreeProgram encode seed layer tree (authRemember target) emptyAuthKeep) with
  | none => simp only [hr, Option.map_none] at recorded; cases recorded
  | some result =>
      simp only [hr, Option.map_some, Option.some.injEq] at recorded
      subst out
      exact replay_subtree_certificate encode table seed layer tree _ _ result hr

set_option maxRecDepth 80000 in
theorem replay_fors_tree_state_certificate (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree : ℕ)
    (remember : ℕ → ℕ → Randomizer → Randomizer → S → S) (initial : S)
    (out : List (Randomizer × ℕ) × S)
    (recorded : replayProgram table (forsTreeStateProgram encode seed ht tree remember initial) = some out) :
    ForsTreeCertificate encode table seed ht tree (treeRoot out.1) := by
  rw [forsTreeStateProgram, replay_program_cast, replay_program_map_return] at recorded
  exact replay_complete_tree_recorded table 2 (forsLeafProgram encode seed ht tree)
    (fun kp h l r => encode (.inl (forsTreePairInput seed ht tree kp h l r)))
    randomizerOfDigest remember 2048 11 initial 0 out fors_tree_shape recorded

theorem replay_fors_tree_certificate (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree target : ℕ) (out : Randomizer × List Randomizer)
    (recorded : replayProgram table (forsTreeProgram encode seed ht tree target) = some out) :
    ForsTreeCertificate encode table seed ht tree out.1 := by
  rw [forsTreeProgram, replay_program_map_return] at recorded
  cases hr : replayProgram table
      (forsTreeStateProgram encode seed ht tree (forsRemember target) (List.replicate 11 0)) with
  | none => simp only [hr, Option.map_none] at recorded; cases recorded
  | some result =>
      simp only [hr, Option.map_some, Option.some.injEq] at recorded
      subst out
      exact replay_fors_tree_state_certificate encode table seed ht tree _ _ result hr

theorem replay_fors_root_certificate (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree : ℕ) (root : Randomizer)
    (recorded : replayProgram table (forsRootProgram encode seed ht tree) = some root) :
    ForsTreeCertificate encode table seed ht tree root := by
  rw [forsRootProgram, replay_program_map_return] at recorded
  cases hr : replayProgram table (forsTreeProgram encode seed ht tree 0) with
  | none => simp only [hr, Option.map_none] at recorded; cases recorded
  | some result =>
      simp only [hr, Option.map_some, Option.some.injEq] at recorded
      exact recorded ▸ replay_fors_tree_certificate encode table seed ht tree 0 result hr

theorem merkle_tree_certificate_extends (encode : WotsQuery → K) (before after : Memo K Digest)
    (seed : ByteKey) (layer tree : ℕ) (root : Randomizer)
    (extension : MemoExtends before after)
    (recorded : MerkleTreeCertificate encode before seed layer tree root) :
    MerkleTreeCertificate encode after seed layer tree root := by
  exact recorded_tree_node_extends before after _ _ _ _ extension
    (fun kp value h => replay_program_extends _ before after value extension h) recorded

theorem fors_tree_certificate_extends (encode : WotsQuery → K) (before after : Memo K Digest)
    (seed : ByteKey) (ht tree : ℕ) (root : Randomizer)
    (extension : MemoExtends before after)
    (recorded : ForsTreeCertificate encode before seed ht tree root) :
    ForsTreeCertificate encode after seed ht tree root := by
  exact recorded_tree_node_extends before after _ _ _ _ extension
    (fun kp value h => replay_program_extends _ before after value extension h) recorded

end
end C10Probability
