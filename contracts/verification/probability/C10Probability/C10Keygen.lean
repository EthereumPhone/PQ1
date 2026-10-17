import C10Probability.Subtree
import C10Probability.PrivateSecret

/-! KeygenPreparation's actual public-seed normalization and layer1/tree0
root. The public input digest is supplied independently of the hidden secret;
this client does not assert the origin or freshness of real hardware entropy. -/
namespace C10Probability
noncomputable section

variable {K L : Type*}

def c10KeygenProgram (encode : WotsQuery → K) (publicSeed : Digest) :
    QueryProgram K Digest (ByteKey × ByteKey) 177151 :=
  let seed := nodeBlock (randomizerOfDigest publicSeed)
  mapReturnProgram (fun root => (seed, nodeBlock root)) (subtreeRootProgram encode seed 1 0)

def c10Keygen [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (publicSeed : Digest) : PMF ((ByteKey × ByteKey) × Memo K Digest) :=
  let seed := nodeBlock (randomizerOfDigest publicSeed)
  (subtreeRoot encode table seed 1 0).map (fun root => ((seed, nodeBlock root.1), root.2))

theorem c10_keygen_eval [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (publicSeed : Digest) :
    evalProgram digestDraw (c10KeygenProgram encode publicSeed) table =
      c10Keygen encode table publicSeed := by
  simp only [c10KeygenProgram, evalProgram_mapReturn, subtree_root_eval, c10Keygen]

theorem c10_keygen_map (encode : K → L) (labels : WotsQuery → K) (publicSeed : Digest) :
    mapProgram encode (c10KeygenProgram labels publicSeed) =
      c10KeygenProgram (encode ∘ labels) publicSeed := by
  simp only [c10KeygenProgram, mapProgram_mapReturn, subtree_root_map]

theorem c10_keygen_public (publicSeed : Digest) :
    PublicBudget (c10KeygenProgram id publicSeed) 155135 := by
  rw [c10KeygenProgram, publicBudget_mapReturn]
  exact subtree_root_public _ _ _

theorem c10_keygen_widths [DecidableEq K] (encode : WotsQuery → K)
    (table : Memo K Digest) (publicSeed : Digest) (out : (ByteKey × ByteKey) × Memo K Digest)
    (ho : out ∈ (c10Keygen encode table publicSeed).support) :
    out.1.1.length = 32 ∧ out.1.2.length = 32 := by
  rw [c10Keygen, PMF.mem_support_map_iff] at ho
  obtain ⟨root, _, rfl⟩ := ho
  exact ⟨node_block_length _, node_block_length _⟩

theorem c10_keygen_physical_eval (secret publicSeed : Digest) (table : Memo ByteKey Digest) :
    evalProgram digestDraw
      (mapProgram (privateKey prefixedPrivateInput secret) (c10KeygenProgram id publicSeed)) table =
      c10Keygen (privateKey prefixedPrivateInput secret) table publicSeed := by
  rw [c10_keygen_map]
  exact c10_keygen_eval _ _ _

theorem c10_keygen_prefix_error (publicSeed : Digest) (event : Set (ByteKey × ByteKey)) :
    |((privateShared digestDraw digestDraw prefixedPrivateInput
        (PMF.pure (c10KeygenProgram id publicSeed))).toOuterMeasure event).toReal -
      ((privateIndependent digestDraw
        (PMF.pure (c10KeygenProgram id publicSeed))).toOuterMeasure event).toReal| ≤
      (155135 : ℝ) / 2 ^ 256 := by
  apply private_secret_event_error_real _ 155135
  intro program hp
  have he : program = c10KeygenProgram id publicSeed := by simpa using hp
  rw [he]
  exact c10_keygen_public publicSeed

end
end C10Probability
