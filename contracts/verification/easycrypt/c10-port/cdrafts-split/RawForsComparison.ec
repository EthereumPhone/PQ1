(* An actual FORS recovery call compared with a retained leaf/path witness. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors.
require import PathReplay PathCollision PathInputs RawForsPathReplay RecoveryHistory ForsLeafInputs.

lemma fors_recover_secret_or_collision seed0 ht0 tree0 target0 secret0 auth0
  reference_secret reference_digest reference_auth reference_root :
  hoare[RawFors(PreparationView(Independent)).recover :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\
    secret = secret0 /\ auth = auth0 /\
    size auth0 = 11 /\ size reference_auth = 11 /\
    all (fun x => size x = 16) auth0 /\ all (fun x => size x = 16) reference_auth /\
    size secret0 = 16 /\ size reference_secret = 16 /\
    Independent.rawhistory.[fors_leaf_input seed0 ht0 tree0 target0 reference_secret] = Some reference_digest /\
    path_recorded Independent.rawhistory (fors_pair seed0 ht0 tree0)
      (node reference_digest,0,target0) reference_auth /\
    (path_value Independent.rawhistory (fors_pair seed0 ht0 tree0)
      (node reference_digest,0,target0) reference_auth).`1 = reference_root ==>
    res = reference_root =>
      secret0 = reference_secret \/
      fors_leaf_collision Independent.rawhistory seed0 ht0 tree0 target0 \/
      path_input_collision Independent.rawhistory (fors_pair seed0 ht0 tree0)].
proof.
  conseq (fors_recover_recorded seed0 ht0 tree0 target0 secret0 auth0)
    (fors_recovery_keeps_path_root_entry RawFors (fors_pair seed0 ht0 tree0)
      (node reference_digest,0,target0) reference_auth reference_root
      (fors_leaf_input seed0 ht0 tree0 target0 reference_secret) reference_digest);
    smt(path_leaf_or_input_collision fors_pair_injective fors_leaf_equal_or_collision node_width).
qed.

lemma fors_recover_recorded_repeat seed0 ht0 tree0 target0 secret0 auth0 d0 root0 :
  hoare[RawFors(PreparationView(Independent)).recover :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\
    secret = secret0 /\ auth = auth0 /\ size auth0 = 11 /\
    Independent.rawhistory.[fors_leaf_input seed0 ht0 tree0 target0 secret0] = Some d0 /\
    path_recorded Independent.rawhistory (fors_pair seed0 ht0 tree0)
      (node d0,0,target0) auth0 /\
    (path_value Independent.rawhistory (fors_pair seed0 ht0 tree0)
      (node d0,0,target0) auth0).`1 = root0 ==>
    res = root0].
proof.
  conseq (fors_recover_recorded seed0 ht0 tree0 target0 secret0 auth0)
    (fors_recovery_keeps_path_root_entry RawFors (fors_pair seed0 ht0 tree0)
      (node d0,0,target0) auth0 root0
      (fors_leaf_input seed0 ht0 tree0 target0 secret0) d0); smt().
qed.
