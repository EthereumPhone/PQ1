(* The checked actual builder witness is sufficient for the recovery comparison. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors RawSignature.
require import PathReplay PathCollision PathInputs RawForsPathReplay RawForsComparison RecoveryHistory ForsLeafInputs.
require import ForsBuilderSecret BuilderTotality.

lemma fors_recover_comparison_retained seed0 ht0 tree0 target0 secret0 auth0
    reference_secret reference_digest reference_auth reference_root :
  hoare[RawFors(PreparationView(Independent)).recover :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\
    secret = secret0 /\ auth = auth0 /\ rows_width 11 auth0 /\ rows_width 11 reference_auth /\
    size secret0 = 16 /\ size reference_secret = 16 /\
    Independent.rawhistory.[fors_leaf_input seed0 ht0 tree0 target0 reference_secret] = Some reference_digest /\
    path_recorded Independent.rawhistory (fors_pair seed0 ht0 tree0)
      (node reference_digest,0,target0) reference_auth /\
    (path_value Independent.rawhistory (fors_pair seed0 ht0 tree0)
      (node reference_digest,0,target0) reference_auth).`1 = reference_root ==>
    Independent.rawhistory.[fors_leaf_input seed0 ht0 tree0 target0 reference_secret] = Some reference_digest /\
    path_recorded Independent.rawhistory (fors_pair seed0 ht0 tree0)
      (node reference_digest,0,target0) reference_auth /\
    (path_value Independent.rawhistory (fors_pair seed0 ht0 tree0)
      (node reference_digest,0,target0) reference_auth).`1 = reference_root /\
    (res = reference_root =>
      secret0 = reference_secret \/
      fors_leaf_collision Independent.rawhistory seed0 ht0 tree0 target0 \/
      path_input_collision Independent.rawhistory (fors_pair seed0 ht0 tree0))].
proof.
  conseq (fors_recover_secret_or_collision seed0 ht0 tree0 target0 secret0 auth0
    reference_secret reference_digest reference_auth reference_root)
    (fors_recovery_keeps_path_root_entry RawFors (fors_pair seed0 ht0 tree0)
      (node reference_digest,0,target0) reference_auth reference_root
      (fors_leaf_input seed0 ht0 tree0 target0 reference_secret) reference_digest);
    rewrite /rows_width; smt().
qed.

module ForsBuildCompare = {
  proc run(seed : raw_input, ht tree target : int, secret : raw_input,
      auth : raw_input list) : raw_input * raw_input * raw_input list = {
    var reference, recovered;
    reference <@ RawFors(PreparationView(Independent)).tree(seed,ht,tree,target);
    recovered <@ RawFors(PreparationView(Independent)).recover(seed,ht,tree,target,secret,auth);
    return (reference.`1,recovered,reference.`2);
  }
}.

lemma actual_fors_builder_comparison seed0 ht0 tree0 target0 secret0 auth0 :
  hoare [ForsBuildCompare.run :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\
    secret = secret0 /\ auth = auth0 /\
    0 <= target0 < 2048 /\ size secret0 = 16 /\ rows_width 11 auth0 ==>
    rows_width 11 res.`3 /\ exists reference_secret reference_digest,
      size reference_secret = 16 /\
      Independent.rawhistory.[fors_leaf_input seed0 ht0 tree0 target0 reference_secret] = Some reference_digest /\
      path_recorded Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (node reference_digest,0,target0) res.`3 /\
      (path_value Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (node reference_digest,0,target0) res.`3).`1 = res.`1 /\
      (res.`2 = res.`1 =>
        secret0 = reference_secret \/
        fors_leaf_collision Independent.rawhistory seed0 ht0 tree0 target0 \/
        path_input_collision Independent.rawhistory (fors_pair seed0 ht0 tree0))].
proof.
  proc; seq 1 : (exists reference_secret reference_digest,
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\
    secret = secret0 /\ auth = auth0 /\ rows_width 11 auth0 /\
    size secret0 = 16 /\ rows_width 11 reference.`2 /\ size reference_secret = 16 /\
    Independent.rawhistory.[fors_leaf_input seed0 ht0 tree0 target0 reference_secret] = Some reference_digest /\
    path_recorded Independent.rawhistory (fors_pair seed0 ht0 tree0)
      (node reference_digest,0,target0) reference.`2 /\
    (path_value Independent.rawhistory (fors_pair seed0 ht0 tree0)
      (node reference_digest,0,target0) reference.`2).`1 = reference.`1).
  + call (fors_tree_secret_path seed0 ht0 tree0 target0); auto; smt().
  elim* => reference_secret reference_digest.
  exists* reference; elim* => reference0.
  wp; call (fors_recover_comparison_retained seed0 ht0 tree0 target0 secret0 auth0
    reference_secret reference_digest reference0.`2 reference0.`1).
  auto; smt().
qed.

lemma fors_builder_comparison_ll : islossless ForsBuildCompare.run.
proof. proc; call fors_independent_recover_ll; call fors_independent_tree_ll; auto. qed.

lemma total_actual_fors_builder_comparison seed0 ht0 tree0 target0 secret0 auth0 :
  phoare [ForsBuildCompare.run :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\
    secret = secret0 /\ auth = auth0 /\
    0 <= target0 < 2048 /\ size secret0 = 16 /\ rows_width 11 auth0 ==>
    rows_width 11 res.`3 /\ exists reference_secret reference_digest,
      size reference_secret = 16 /\
      Independent.rawhistory.[fors_leaf_input seed0 ht0 tree0 target0 reference_secret] = Some reference_digest /\
      path_recorded Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (node reference_digest,0,target0) res.`3 /\
      (path_value Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (node reference_digest,0,target0) res.`3).`1 = res.`1 /\
      (res.`2 = res.`1 =>
        secret0 = reference_secret \/
        fors_leaf_collision Independent.rawhistory seed0 ht0 tree0 target0 \/
        path_input_collision Independent.rawhistory (fors_pair seed0 ht0 tree0))] = 1%r.
proof.
  conseq fors_builder_comparison_ll (actual_fors_builder_comparison seed0 ht0 tree0 target0 secret0 auth0); smt().
qed.
