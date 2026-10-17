import C10Probability.ForestFill

/-! Actual forest recovery, with twelve secret/authentication calls followed
by the special zero-index last leaf and ordered compression. Forced-zero
digest rejection belongs to the outer verifier, not this RawForest procedure. -/
namespace C10Probability
noncomputable section

variable {K L : Type*}

def forestRecoveryStep (encode : ByteKey → K) (seed : ByteKey) (ht : ℕ)
    (digest : Digest) (secrets : List Randomizer) (auths : List (List Randomizer))
    (tree : Fin 12) (roots : List Randomizer) : QueryProgram K Digest (List Randomizer) 12 :=
  mapReturnProgram (fun root => roots ++ [root])
    (forsRecoverProgram encode seed ht tree.val (forestIndex digest tree.val)
      ((secrets[tree.val]?).getD 0) ((auths[tree.val]?).getD []))

def forestRecoveryProgram (encode : ByteKey → K) (seed : ByteKey) (ht : ℕ)
    (digest : Digest) (secrets : List Randomizer) (auths : List (List Randomizer))
    (indices : List (Fin 12)) (roots : List Randomizer) :
    QueryProgram K Digest (List Randomizer) (collectionSteps (fun _ => 12) indices) :=
  stateFoldProgram (fun _ => 12) (forestRecoveryStep encode seed ht digest secrets auths) indices roots

def forestRecoveryLoop [DecidableEq K] (encode : ByteKey → K) (seed : ByteKey) (ht : ℕ)
    (digest : Digest) (secrets : List Randomizer) (auths : List (List Randomizer)) :
    List (Fin 12) → List Randomizer → Memo K Digest → PMF (List Randomizer × Memo K Digest)
  | [], roots, table => PMF.pure (roots, table)
  | tree :: rest, roots, table =>
      (forsRecover encode table seed ht tree.val (forestIndex digest tree.val)
        ((secrets[tree.val]?).getD 0) ((auths[tree.val]?).getD [])).bind
          (fun out => forestRecoveryLoop encode seed ht digest secrets auths rest
            (roots ++ [out.1]) out.2)

theorem forest_recovery_program_eval [DecidableEq K] (encode : ByteKey → K) (seed : ByteKey)
    (ht : ℕ) (digest : Digest) (secrets : List Randomizer) (auths : List (List Randomizer))
    (indices : List (Fin 12)) (roots : List Randomizer) (table : Memo K Digest) :
    evalProgram digestDraw (forestRecoveryProgram encode seed ht digest secrets auths indices roots)
      table = forestRecoveryLoop encode seed ht digest secrets auths indices roots table := by
  induction indices generalizing roots table with
  | nil => rfl
  | cons tree rest ih =>
    simp only [forestRecoveryProgram, stateFoldProgram, evalProgram_cast, evalProgram_bind,
      forestRecoveryStep, evalProgram_mapReturn, fors_recover_eval, PMF.bind_map,
      forestRecoveryLoop] at ih ⊢
    congr 1
    funext out
    exact ih _ _

theorem forest_recovery_program_map (encode : K → L) (labels : ByteKey → K)
    (seed : ByteKey) (ht : ℕ) (digest : Digest) (secrets : List Randomizer)
    (auths : List (List Randomizer)) (indices : List (Fin 12)) (roots : List Randomizer) :
    mapProgram encode (forestRecoveryProgram labels seed ht digest secrets auths indices roots) =
      forestRecoveryProgram (encode ∘ labels) seed ht digest secrets auths indices roots := by
  simp only [forestRecoveryProgram, mapProgram_stateFold, forestRecoveryStep,
    mapProgram_mapReturn, fors_recover_map]
  rfl

theorem forest_recovery_loop_calls : collectionSteps (fun _ => 12) forestTreeIndices = 144 := by
  rw [collection_steps_constant, forest_tree_indices_length]

def forestRecoverProgram (encode : ByteKey → K) (seed : ByteKey) (ht : ℕ)
    (digest : Digest) (secrets : List Randomizer) (auths : List (List Randomizer)) :
    QueryProgram K Digest Randomizer 146 :=
  bindProgram (castProgram forest_recovery_loop_calls
    (forestRecoveryProgram encode seed ht digest secrets auths forestTreeIndices [])) (fun roots =>
      .query (encode (forsLeafInput seed ht 12 0 ((secrets[12]?).getD 0))) (fun last =>
        .query (encode (forsPkInput seed ht (roots ++ [randomizerOfDigest last])))
          (fun reply => .done (randomizerOfDigest reply))))

def forestRecover [DecidableEq K] (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (ht : ℕ) (digest : Digest) (secrets : List Randomizer)
    (auths : List (List Randomizer)) : PMF (Randomizer × Memo K Digest) :=
  (forestRecoveryLoop encode seed ht digest secrets auths forestTreeIndices [] table).bind
    (fun roots => (memoQuery digestDraw roots.2
      (encode (forsLeafInput seed ht 12 0 ((secrets[12]?).getD 0)))).bind
        (fun last => (memoQuery digestDraw last.2
          (encode (forsPkInput seed ht (roots.1 ++ [randomizerOfDigest last.1])))).map
            (fun reply => (randomizerOfDigest reply.1, reply.2))))

theorem forest_recover_eval [DecidableEq K] (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (ht : ℕ) (digest : Digest) (secrets : List Randomizer)
    (auths : List (List Randomizer)) :
    evalProgram digestDraw (forestRecoverProgram encode seed ht digest secrets auths) table =
      forestRecover encode table seed ht digest secrets auths := by
  rw [forestRecoverProgram, evalProgram_bind, evalProgram_cast, forest_recovery_program_eval]
  rfl

theorem forest_recover_map (encode : K → L) (labels : ByteKey → K) (seed : ByteKey)
    (ht : ℕ) (digest : Digest) (secrets : List Randomizer) (auths : List (List Randomizer)) :
    mapProgram encode (forestRecoverProgram labels seed ht digest secrets auths) =
      forestRecoverProgram (encode ∘ labels) seed ht digest secrets auths := by
  simp only [forestRecoverProgram, mapProgram_bind, mapProgram_cast,
    forest_recovery_program_map, mapProgram, Function.comp_def]

end
end C10Probability
