import C10Probability.ForsInputs

/-! One actual private derivation followed by its public leaf hash, sharing
the complete memo table. The secret query is retained even when cached. -/
namespace C10Probability
noncomputable section

variable {K L : Type*}

def forsLeafProgram (encode : WotsQuery → K) (seed : ByteKey) (ht tree leaf : ℕ) :
    QueryProgram K Digest Randomizer 2 :=
  .query (encode (.inr (forsPrivateTail ht tree leaf))) (fun secret =>
    .query (encode (.inl (forsLeafInput seed ht tree leaf (randomizerOfDigest secret))))
      (fun reply => .done (randomizerOfDigest reply)))

def forsLeaf [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree leaf : ℕ) : PMF (Randomizer × Memo K Digest) :=
  (memoQuery digestDraw table (encode (.inr (forsPrivateTail ht tree leaf)))).bind
    (fun secret => (memoQuery digestDraw secret.2
      (encode (.inl (forsLeafInput seed ht tree leaf (randomizerOfDigest secret.1))))).map
        (fun reply => (randomizerOfDigest reply.1, reply.2)))

theorem fors_leaf_eval [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree leaf : ℕ) :
    evalProgram digestDraw (forsLeafProgram encode seed ht tree leaf) table =
      forsLeaf encode table seed ht tree leaf := by
  rfl

theorem fors_leaf_map (encode : K → L) (labels : WotsQuery → K)
    (seed : ByteKey) (ht tree leaf : ℕ) :
    mapProgram encode (forsLeafProgram labels seed ht tree leaf) =
      forsLeafProgram (encode ∘ labels) seed ht tree leaf := by
  rfl

theorem fors_leaf_public (seed : ByteKey) (ht tree leaf : ℕ) :
    PublicBudget (forsLeafProgram id seed ht tree leaf) 1 := by
  intro secret
  exact publicBudget_total _

theorem fors_leaf_cached [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree leaf : ℕ) (secret reply : Digest)
    (hsecret : table (encode (.inr (forsPrivateTail ht tree leaf))) = some secret)
    (hleaf : table (encode (.inl (forsLeafInput seed ht tree leaf
      (randomizerOfDigest secret)))) = some reply) :
    forsLeaf encode table seed ht tree leaf = PMF.pure (randomizerOfDigest reply, table) := by
  rw [forsLeaf, memoQuery_cached _ _ _ _ hsecret, PMF.pure_bind,
    memoQuery_cached _ _ _ _ hleaf, PMF.pure_map]

end
end C10Probability
