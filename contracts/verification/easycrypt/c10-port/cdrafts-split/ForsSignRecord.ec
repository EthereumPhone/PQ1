(* The real signature contains its actual retained secret/leaf/path witness. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors RawSignature.
require import PathReplay RawForsPathReplay BuilderTotality ForsSignWitness.

lemma fors_sign_recorded seed0 ht0 tree0 target0 :
  hoare [RawFors(PreparationView(Independent)).sign :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\ 0 <= target0 < 2048 ==>
    size res.`1 = 16 /\ rows_width 11 res.`2 /\ exists d,
      Independent.rawhistory.[fors_leaf_input seed0 ht0 tree0 target0 res.`1] = Some d /\
      path_recorded Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (node d,0,target0) res.`2].
proof.
  conseq (fors_sign_witness_projection (PreparationView(Independent)))
    (fors_sign_witness_path seed0 ht0 tree0 target0).
  + move=> &m hm.
    exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},ht{m},tree{m},target{m}); smt().
  smt().
qed.

lemma fors_independent_sign_ll : islossless RawFors(PreparationView(Independent)).sign.
proof. proc; call fors_independent_tree_ll; wp; call preparation_fors_ll; auto. qed.

lemma total_fors_sign_recorded seed0 ht0 tree0 target0 :
  phoare [RawFors(PreparationView(Independent)).sign :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\ 0 <= target0 < 2048 ==>
    size res.`1 = 16 /\ rows_width 11 res.`2 /\ exists d,
      Independent.rawhistory.[fors_leaf_input seed0 ht0 tree0 target0 res.`1] = Some d /\
      path_recorded Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (node d,0,target0) res.`2] = 1%r.
proof.
  conseq fors_independent_sign_ll (fors_sign_recorded seed0 ht0 tree0 target0); smt().
qed.
