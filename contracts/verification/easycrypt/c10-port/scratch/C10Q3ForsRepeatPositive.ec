require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors.
require import PathReplay RawForsPathReplay RawForsComparison.

module DoubleFors = {
  proc run(seed : raw_input, ht tree target : int, secret : raw_input,
    auth : raw_input list) : bool = {
    var r1, r2;
    r1 <@ RawFors(PreparationView(Independent)).recover(seed,ht,tree,target,secret,auth);
    r2 <@ RawFors(PreparationView(Independent)).recover(seed,ht,tree,target,secret,auth);
    return r1 = r2;
  }
}.

lemma repeated_fors seed0 ht0 tree0 target0 secret0 auth0 :
  hoare[DoubleFors.run :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\
    secret = secret0 /\ auth = auth0 /\ size auth0 = 11 ==> res].
proof.
  proc; seq 1 : (seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\
    secret = secret0 /\ auth = auth0 /\ size auth0 = 11 /\
    exists d, Independent.rawhistory.[fors_leaf_input seed0 ht0 tree0 target0 secret0] = Some d /\
      path_recorded Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (node d,0,target0) auth0 /\
      (path_value Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (node d,0,target0) auth0).`1 = r1).
  + call (fors_recover_recorded seed0 ht0 tree0 target0 secret0 auth0); auto; smt().
  exists* r1; elim* => root0.
  move=> d0.
  call (fors_recover_recorded_repeat seed0 ht0 tree0 target0 secret0 auth0
    d0 root0).
  auto; smt().
qed.
