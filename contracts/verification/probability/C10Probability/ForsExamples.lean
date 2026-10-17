import C10Probability.ForestSign
import C10Probability.ForestRecover

/-! Independent byte, digest-field, authentication-update and actual query
order witnesses. These do not replace universal compiler or probability laws. -/
namespace C10Probability
noncomputable section

set_option maxRecDepth 4096

theorem fors_private_byte_vector :
    forsPrivateTail 258 772 1286 =
      [102,111,114,115,0,0,1,2,0,0,3,4,0,0,5,6] := by decide +kernel

theorem fors_private_prefix_vector :
    prefixedPrivateInput (2 ^ 255) (forsPrivateTail 1 2 3) =
      [128] ++ List.replicate 31 0 ++ [102,111,114,115,0,0,0,1,0,0,0,2,0,0,0,3] := by
  decide +kernel

theorem fors_leaf_byte_vector :
    forsLeafInput [] 16909060 84281096 151653132 1 =
      List.replicate 8 0 ++ [1,2,3,4,0,0,0,3,5,6,7,8] ++ List.replicate 8 0 ++
      [9,10,11,12] ++ List.replicate 15 0 ++ [1] ++ List.replicate 16 0 := by
  decide +kernel

theorem fors_pair_byte_vector :
    forsPairInput [] 258 772 7 1286 1 2 =
      List.replicate 8 0 ++ [0,0,1,2,0,0,0,3,0,0,3,4] ++
      List.replicate 7 0 ++ [8,0,0,5,6] ++
      List.replicate 15 0 ++ [1] ++ List.replicate 31 0 ++ [2] ++ List.replicate 16 0 := by
  decide +kernel

theorem fors_tree_pair_parent_vector :
    forsTreePairInput [] 1 2 2047 7 3 4 = forsPairInput [] 1 2 7 7 3 4 := by
  decide +kernel

theorem fors_compression_byte_vector :
    forsPkInput [] 258 [1,2] =
      List.replicate 8 0 ++ [0,0,1,2,0,0,0,4] ++ List.replicate 31 0 ++
      [1] ++ List.replicate 31 0 ++ [2] ++ List.replicate 16 0 := by
  decide +kernel

theorem forest_digest_field_vector :
    let digest : Digest := 3 + 9 * 2 ^ 11 + 7 * 2 ^ 121 + 2047 * 2 ^ 132
    [forestIndex digest 0, forestIndex digest 1, forestIndex digest 11, forestIndex digest 12] =
      [3,9,7,2047] := by decide +kernel

theorem forest_digest_upper_boundary : forestIndex (2 ^ 143) 12 = 0 := by decide +kernel

theorem fors_remember_left_vector :
    forsRemember 1 1 0 11 22 (List.replicate 11 0) = [11] ++ List.replicate 10 0 := by
  decide +kernel

theorem fors_remember_right_vector :
    forsRemember 0 1 0 11 22 (List.replicate 11 0) = [22] ++ List.replicate 10 0 := by
  decide +kernel

theorem fors_remember_high_vector :
    forsRemember 0 2047 10 11 22 (List.replicate 11 0) = List.replicate 10 0 ++ [22] := by
  decide +kernel

theorem fors_remember_irrelevant_vector :
    forsRemember 4 1 0 11 22 (List.replicate 11 0) = List.replicate 11 0 := by
  decide +kernel

theorem fors_remember_overwrite_vector :
    forsRemember 1 1 0 33 44 (forsRemember 1 1 0 11 22 (List.replicate 11 0)) =
      [33] ++ List.replicate 10 0 := by decide +kernel

theorem fors_recovery_even_vector :
    forsRecoveryInput [] 1 2 1 6 [3,4,5] 9 = forsPairInput [] 1 2 1 3 9 4 := by decide +kernel

theorem fors_recovery_odd_vector :
    forsRecoveryInput [] 1 2 1 7 [3,4,5] 9 = forsPairInput [] 1 2 1 3 4 9 := by decide +kernel

theorem fors_recovery_default_vector :
    forsRecoveryInput [] 1 2 2 6 [3] 9 = forsPairInput [] 1 2 2 3 9 0 := by decide +kernel

theorem fors_leaf_query_order :
    (traceProgram digestDraw (forsLeafProgram id [] 1 2 3)
      (fun _ => some (2 ^ 128))).map (fun out => out.queries) =
      PMF.pure [Sum.inr (forsPrivateTail 1 2 3), Sum.inl (forsLeafInput [] 1 2 3 1)] := by
  have hp : randomizerOfDigest (2 ^ 128 : Digest) = 1 := by decide +kernel
  simp [forsLeafProgram, traceProgram, memoQuery, PMF.pure_bind, PMF.pure_map, hp]

theorem fors_recovery_query_order :
    (traceProgram digestDraw (forsRecoverProgram id [] 1 2 2047 2 [3,4,5,6,7,8,9,10,11,12,13])
      (fun _ => some (2 ^ 128))).map (fun out => out.queries) = PMF.pure
      [forsLeafInput [] 1 2 2047 2,
       forsPairInput [] 1 2 0 1023 3 1,
       forsPairInput [] 1 2 1 511 4 1,
       forsPairInput [] 1 2 2 255 5 1,
       forsPairInput [] 1 2 3 127 6 1,
       forsPairInput [] 1 2 4 63 7 1,
       forsPairInput [] 1 2 5 31 8 1,
       forsPairInput [] 1 2 6 15 9 1,
       forsPairInput [] 1 2 7 7 10 1,
       forsPairInput [] 1 2 8 3 11 1,
       forsPairInput [] 1 2 9 1 12 1,
       forsPairInput [] 1 2 10 0 13 1] := by
  have hp : randomizerOfDigest (2 ^ 128 : Digest) = 1 := by decide +kernel
  simp [forsRecoverProgram, forsRecoveryProgram, traceProgram, memoQuery,
    PMF.pure_bind, PMF.pure_map, hp, forsRecoveryInput]

theorem forest_shuffle_tag_ascii : shuffleTag.map Fin.val =
    "sphincs-c10-shuffle-v1".toUTF8.toList.map UInt8.toNat := by decide +kernel

theorem forest_shuffle_derive_vector :
    shuffleDeriveInput (List.replicate 32 9) forsTag =
      [115,112,104,105,110,99,115,45,99,49,48,45,115,104,117,102,102,108,101,45,118,49] ++
      List.replicate 32 9 ++ [102,111,114,115] := by decide +kernel

theorem forest_shuffle_patterned_order :
    (forestShuffleLoop (List.ofFn (fun i : Fin 128 =>
      (⟨(37 * i.val + 11) % 256, Nat.mod_lt _ (by decide)⟩ : Fin 256)))
      11 0 forestTreeIndices).map Fin.val = [6,8,3,9,1,10,4,11,0,7,5,2] := by
  decide +kernel

theorem forest_shuffle_zero_stream :
    (forestShuffleOrder (List.replicate 128 0)).val.map Fin.val = [1,2,3,4,5,6,7,8,9,10,11,0] := by
  decide +kernel

theorem forest_shuffle_max_stream :
    (forestShuffleOrder (List.replicate 128 255)).val = forestTreeIndices := by decide +kernel

theorem forest_permutation_query_order :
    (traceProgram digestDraw (forestPermutationProgram id [1]) (fun _ => some 0)).map
      (fun out => out.queries) = PMF.pure
        [shuffleBlockInput [1] 0, shuffleBlockInput [1] 1,
          shuffleBlockInput [1] 2, shuffleBlockInput [1] 3] := by
  simp only [forestPermutationProgram, show ([1] : ByteKey) ≠ List.replicate 32 0 by decide,
    ↓reduceIte, shuffleBlocksProgram, mapReturnProgram, traceProgram, id_eq,
    memoQuery, PMF.pure_bind, PMF.pure_map]

theorem forest_shuffle_full_query_order :
    (traceProgram digestDraw (forestShuffleProgram id (List.replicate 32 9))
      (fun _ => some 1)).map (fun out => out.queries) = PMF.pure
      [shuffleDeriveInput (List.replicate 32 9) forsTag,
       shuffleBlockInput (secretBytes 1) 0, shuffleBlockInput (secretBytes 1) 1,
       shuffleBlockInput (secretBytes 1) 2, shuffleBlockInput (secretBytes 1) 3] := by
  have hs : (List.replicate 32 9 : ByteKey) ≠ List.replicate 32 0 := by decide +kernel
  have hd : secretBytes (1 : Digest) ≠ List.replicate 32 0 := by decide +kernel
  simp only [forestShuffleProgram, shuffleDeriveProgram, hs, ↓reduceIte,
    bindProgram, forestPermutationProgram, hd, castProgram, reserveProgram,
    shuffleBlocksProgram, mapReturnProgram, traceProgram, id_eq,
    memoQuery, PMF.pure_bind, PMF.pure_map]

theorem forest_shuffle_zero_query_trace :
    (traceProgram digestDraw (forestShuffleProgram id (List.replicate 32 0))
      (fun _ => some 1)).map (fun out => out.queries) = PMF.pure [] := by
  simp only [forestShuffleProgram, shuffleDeriveProgram, ↓reduceIte,
    bindProgram, forestPermutationProgram, castProgram, reserveProgram,
    traceProgram, PMF.pure_map]

theorem forest_positional_write_vector :
    forestWrite emptyForestState 5 ⟨7,[8,9],10⟩ =
      ⟨List.replicate 5 0 ++ [7] ++ List.replicate 7 0,
        List.replicate 5 (List.replicate 11 0) ++ [[8,9]] ++ List.replicate 6 (List.replicate 11 0),
        List.replicate 5 0 ++ [10] ++ List.replicate 7 0⟩ := by decide +kernel

theorem forest_last_cached {K : Type*} [DecidableEq K] (encode : WotsQuery → K)
    (table : Memo K Digest) (seed : ByteKey) (ht : ℕ) (state : ForestState)
    (last : Randomizer) (leaf reply : Digest)
    (hl : table (encode (.inl (forsLeafInput seed ht 12 0 last))) = some leaf)
    (hp : table (encode (.inl (forsPkInput seed ht
      (state.roots.set 12 (randomizerOfDigest leaf))))) = some reply) :
    forestLast encode table seed ht state last =
      PMF.pure (⟨state.secrets.set 12 last, state.auths, randomizerOfDigest reply⟩, table) := by
  rw [forestLast, memoQuery_cached _ _ _ _ hl, PMF.pure_bind,
    memoQuery_cached _ _ _ _ hp, PMF.pure_map]

theorem forest_last_query_order :
    (traceProgram digestDraw (forestLastProgram id [] 1 emptyForestState 7)
      (fun _ => some (9 * 2 ^ 128))).map (fun out => out.queries) = PMF.pure
      [Sum.inl (forsLeafInput [] 1 12 0 7),
       Sum.inl (forsPkInput [] 1 (List.replicate 12 0 ++ [9]))] := by
  have hp : randomizerOfDigest (9 * 2 ^ 128 : Digest) = 9 := by decide +kernel
  simp [forestLastProgram, traceProgram, memoQuery, PMF.pure_bind, PMF.pure_map,
    emptyForestState, hp]

theorem forest_last_transmitted_root :
    forestLast id (fun _ => some (9 * 2 ^ 128)) [] 1 emptyForestState 7 =
      PMF.pure (⟨List.replicate 12 0 ++ [7], List.replicate 12 (List.replicate 11 0),9⟩,
        fun _ => some (9 * 2 ^ 128)) := by
  have hp : randomizerOfDigest (9 * 2 ^ 128 : Digest) = 9 := by decide +kernel
  simp [forestLast, memoQuery, PMF.pure_bind, PMF.pure_map, emptyForestState, hp]

def forestExampleSelect : WotsQuery → Bool
  | .inl input => decide (input.length = 96)
  | .inr _ => false

def forestExampleCache (leaf : Bool) : Option Digest :=
  some (if leaf then 9 * 2 ^ 128 else 11 * 2 ^ 128)

theorem forest_last_distinct_roles :
    forestLast forestExampleSelect forestExampleCache (List.replicate 32 0) 1 emptyForestState 7 =
      PMF.pure (⟨List.replicate 12 0 ++ [7], List.replicate 12 (List.replicate 11 0),11⟩,
        forestExampleCache) := by
  have hlw : (forsLeafInput (List.replicate 32 0) 1 12 0 7).length = 96 :=
    fors_leaf_input_length _ _ _ _ _ (by simp)
  have hpw : (forsPkInput (List.replicate 32 0) 1
      (emptyForestState.roots.set 12 (randomizerOfDigest (9 * 2 ^ 128)))).length = 480 :=
    fors_pk_input_length _ _ _ (by simp) (by simp [emptyForestState])
  have hl : forestExampleCache (forestExampleSelect (.inl
      (forsLeafInput (List.replicate 32 0) 1 12 0 7))) = some (9 * 2 ^ 128) := by
    simp only [forestExampleSelect, hlw]
    rfl
  have hp : forestExampleCache (forestExampleSelect (.inl
      (forsPkInput (List.replicate 32 0) 1
        (emptyForestState.roots.set 12 (randomizerOfDigest (9 * 2 ^ 128)))))) =
      some (11 * 2 ^ 128) := by
    simp only [forestExampleSelect, hpw]
    rfl
  rw [forest_last_cached _ _ _ _ _ _ (9 * 2 ^ 128) (11 * 2 ^ 128) hl hp]
  have hnode : randomizerOfDigest (11 * 2 ^ 128 : Digest) = 11 := by decide +kernel
  simp [emptyForestState, hnode]

theorem fors_recovery_one_fresh_populated :
    (forsRecoveryLoop (fun _ => false) [] 1 2 [3] 1 0 0 4 (fun _ => none)).map
      (fun out => (out.2 false).isSome) = PMF.pure true := by
  simp [forsRecoveryLoop, memoQuery, PMF.map_bind, PMF.bind_map, PMF.pure_map]

end
end C10Probability
