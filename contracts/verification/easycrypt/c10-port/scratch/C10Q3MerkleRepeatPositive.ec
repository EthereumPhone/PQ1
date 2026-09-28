require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawMerkle.
require import PathReplay RawPathReplay RawPathComparison.

module DoubleMerkle = {
  proc run(seed : raw_input, layer tree : int, leaf : raw_input, index : int,
    auth : raw_input list) : bool = {
    var r1, r2;
    r1 <@ RawMerkle(PreparationView(Independent)).recover(seed,layer,tree,leaf,index,auth);
    r2 <@ RawMerkle(PreparationView(Independent)).recover(seed,layer,tree,leaf,index,auth);
    return r1 = r2;
  }
}.

lemma repeated_merkle seed0 layer0 tree0 leaf0 index0 auth0 :
  hoare[DoubleMerkle.run :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ leaf = leaf0 /\
    index = index0 /\ auth = auth0 /\ size auth0 = 9 ==> res].
proof.
  proc; seq 1 : (seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ leaf = leaf0 /\
    index = index0 /\ auth = auth0 /\ size auth0 = 9 /\
    path_recorded Independent.rawhistory (merkle_pair seed0 layer0 tree0)
      (leaf0,0,index0) auth0 /\
    (path_value Independent.rawhistory (merkle_pair seed0 layer0 tree0)
      (leaf0,0,index0) auth0).`1 = r1).
  + call (merkle_recover_recorded seed0 layer0 tree0 leaf0 index0 auth0); auto.
  exists* r1; elim* => root0.
  call (merkle_recover_recorded_repeat seed0 layer0 tree0 leaf0 index0 auth0 root0).
  auto.
qed.
