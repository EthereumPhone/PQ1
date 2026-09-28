require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawMerkle RawFors.
require import PathReplay PathOracle PathCollision PathInputs RawPathReplay RawForsPathReplay RecoveryHistory ForsLeafInputs RawPathComparison RawForsComparison.
lemma without_reference seed0 layer0 tree0 leaf0 index0 auth0
  reference_leaf reference_auth reference_root :
  hoare[RawMerkle(PreparationView(Independent)).recover :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\
    leaf = leaf0 /\ index = index0 /\ auth = auth0 /\
    size auth0 = 9 /\ size reference_auth = 9 /\
    all (fun x => size x = 16) auth0 /\ all (fun x => size x = 16) reference_auth /\
    size leaf0 = 16 /\ size reference_leaf = 16 /\
    (path_value Independent.rawhistory (merkle_pair seed0 layer0 tree0)
      (reference_leaf,0,index0) reference_auth).`1 = reference_root ==>
    res = reference_root =>
      leaf0 = reference_leaf \/
      path_input_collision Independent.rawhistory (merkle_pair seed0 layer0 tree0)].
proof. exact (merkle_recover_leaf_or_collision seed0 layer0 tree0 leaf0 index0 auth0 reference_leaf reference_auth reference_root). qed.
