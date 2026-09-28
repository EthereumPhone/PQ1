(* A concrete recovery call compared with a retained reference path. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawMerkle.
require import PathReplay PathCollision PathInputs RawPathReplay RecoveryHistory.

lemma merkle_recover_leaf_or_collision seed0 layer0 tree0 leaf0 index0 auth0
  reference_leaf reference_auth reference_root :
  hoare[RawMerkle(PreparationView(Independent)).recover :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\
    leaf = leaf0 /\ index = index0 /\ auth = auth0 /\
    size auth0 = 9 /\ size reference_auth = 9 /\
    all (fun x => size x = 16) auth0 /\ all (fun x => size x = 16) reference_auth /\
    size leaf0 = 16 /\ size reference_leaf = 16 /\
    path_recorded Independent.rawhistory (merkle_pair seed0 layer0 tree0)
      (reference_leaf,0,index0) reference_auth /\
    (path_value Independent.rawhistory (merkle_pair seed0 layer0 tree0)
      (reference_leaf,0,index0) reference_auth).`1 = reference_root ==>
    res = reference_root =>
      leaf0 = reference_leaf \/
      path_input_collision Independent.rawhistory (merkle_pair seed0 layer0 tree0)].
proof.
  conseq (merkle_recover_recorded seed0 layer0 tree0 leaf0 index0 auth0)
    (merkle_recovery_keeps_path_root RawMerkle (merkle_pair seed0 layer0 tree0)
      (reference_leaf,0,index0) reference_auth reference_root);
    smt(path_leaf_or_input_collision merkle_pair_injective).
qed.

lemma merkle_recover_recorded_repeat seed0 layer0 tree0 leaf0 index0 auth0 root0 :
  hoare[RawMerkle(PreparationView(Independent)).recover :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\
    leaf = leaf0 /\ index = index0 /\ auth = auth0 /\ size auth0 = 9 /\
    path_recorded Independent.rawhistory (merkle_pair seed0 layer0 tree0)
      (leaf0,0,index0) auth0 /\
    (path_value Independent.rawhistory (merkle_pair seed0 layer0 tree0)
      (leaf0,0,index0) auth0).`1 = root0 ==>
    res = root0].
proof.
  conseq (merkle_recover_recorded seed0 layer0 tree0 leaf0 index0 auth0)
    (merkle_recovery_keeps_path_root RawMerkle (merkle_pair seed0 layer0 tree0)
      (leaf0,0,index0) auth0 root0); smt().
qed.
