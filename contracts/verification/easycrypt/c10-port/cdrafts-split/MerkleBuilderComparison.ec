(* Actual Merkle construction supplies the retained witness used by recovery. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawMerkle RawSignature.
require import PathReplay PathCollision PathInputs RawPathReplay RawPathComparison RecoveryHistory.
require import RawBuilderReference BuilderTotality.

lemma merkle_recover_comparison_retained seed0 layer0 tree0 leaf0 target0 auth0
    reference_leaf reference_auth reference_root :
  hoare [RawMerkle(PreparationView(Independent)).recover :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ leaf = leaf0 /\ index = target0 /\
    auth = auth0 /\ rows_width 9 auth0 /\ rows_width 9 reference_auth /\
    size leaf0 = 16 /\ size reference_leaf = 16 /\
    path_recorded Independent.rawhistory (merkle_pair seed0 layer0 tree0)
      (reference_leaf,0,target0) reference_auth /\
    (path_value Independent.rawhistory (merkle_pair seed0 layer0 tree0)
      (reference_leaf,0,target0) reference_auth).`1 = reference_root ==>
    path_recorded Independent.rawhistory (merkle_pair seed0 layer0 tree0)
      (reference_leaf,0,target0) reference_auth /\
    (path_value Independent.rawhistory (merkle_pair seed0 layer0 tree0)
      (reference_leaf,0,target0) reference_auth).`1 = reference_root /\
    (res = reference_root => leaf0 = reference_leaf \/
      path_input_collision Independent.rawhistory (merkle_pair seed0 layer0 tree0))].
proof.
  conseq (merkle_recover_leaf_or_collision seed0 layer0 tree0 leaf0 target0 auth0
    reference_leaf reference_auth reference_root)
    (merkle_recovery_keeps_path_root RawMerkle (merkle_pair seed0 layer0 tree0)
      (reference_leaf,0,target0) reference_auth reference_root);
    rewrite /rows_width; smt().
qed.

module MerkleBuildCompare = {
  proc run(seed : raw_input, layer tree target : int, leaf : raw_input,
      auth : raw_input list) : raw_input * raw_input * raw_input list = {
    var reference, recovered;
    reference <@ RawMerkle(PreparationView(Independent)).build(seed,layer,tree,target);
    recovered <@ RawMerkle(PreparationView(Independent)).recover(seed,layer,tree,leaf,target,auth);
    return (reference.`2,recovered,reference.`1);
  }
}.

lemma actual_merkle_builder_comparison seed0 layer0 tree0 target0 leaf0 auth0 :
  hoare [MerkleBuildCompare.run :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ target = target0 /\
    leaf = leaf0 /\ auth = auth0 /\
    0 <= target0 < 512 /\ size leaf0 = 16 /\ rows_width 9 auth0 ==>
    rows_width 9 res.`3 /\ exists reference_leaf, size reference_leaf = 16 /\
      path_recorded Independent.rawhistory (merkle_pair seed0 layer0 tree0)
        (reference_leaf,0,target0) res.`3 /\
      (path_value Independent.rawhistory (merkle_pair seed0 layer0 tree0)
        (reference_leaf,0,target0) res.`3).`1 = res.`1 /\
      (res.`2 = res.`1 => leaf0 = reference_leaf \/
        path_input_collision Independent.rawhistory (merkle_pair seed0 layer0 tree0))].
proof.
  proc; seq 1 : (exists reference_leaf,
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ target = target0 /\
    leaf = leaf0 /\ auth = auth0 /\ rows_width 9 auth0 /\
    size leaf0 = 16 /\ rows_width 9 reference.`1 /\ size reference_leaf = 16 /\
    path_recorded Independent.rawhistory (merkle_pair seed0 layer0 tree0)
      (reference_leaf,0,target0) reference.`1 /\
    (path_value Independent.rawhistory (merkle_pair seed0 layer0 tree0)
      (reference_leaf,0,target0) reference.`1).`1 = reference.`2).
  + call (merkle_build_reference seed0 layer0 tree0 target0); auto; smt().
  elim* => reference_leaf.
  exists* reference; elim* => reference0.
  wp; call (merkle_recover_comparison_retained seed0 layer0 tree0 leaf0 target0 auth0
    reference_leaf reference0.`1 reference0.`2).
  auto; smt().
qed.

lemma merkle_builder_comparison_ll : islossless MerkleBuildCompare.run.
proof. proc; call merkle_independent_recover_ll; call merkle_independent_build_ll; auto. qed.

lemma total_actual_merkle_builder_comparison seed0 layer0 tree0 target0 leaf0 auth0 :
  phoare [MerkleBuildCompare.run :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ target = target0 /\
    leaf = leaf0 /\ auth = auth0 /\
    0 <= target0 < 512 /\ size leaf0 = 16 /\ rows_width 9 auth0 ==>
    rows_width 9 res.`3 /\ exists reference_leaf, size reference_leaf = 16 /\
      path_recorded Independent.rawhistory (merkle_pair seed0 layer0 tree0)
        (reference_leaf,0,target0) res.`3 /\
      (path_value Independent.rawhistory (merkle_pair seed0 layer0 tree0)
        (reference_leaf,0,target0) res.`3).`1 = res.`1 /\
      (res.`2 = res.`1 => leaf0 = reference_leaf \/
        path_input_collision Independent.rawhistory (merkle_pair seed0 layer0 tree0))] = 1%r.
proof.
  conseq merkle_builder_comparison_ll (actual_merkle_builder_comparison seed0 layer0 tree0 target0 leaf0 auth0); smt().
qed.
