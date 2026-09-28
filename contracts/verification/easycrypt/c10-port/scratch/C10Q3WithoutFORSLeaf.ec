require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawMerkle RawFors.
require import PathReplay PathOracle PathCollision PathInputs RawPathReplay RawForsPathReplay RecoveryHistory ForsLeafInputs RawPathComparison RawForsComparison.
lemma without_leaf_entry seed0 ht0 tree0 target0 secret0 auth0
  reference_secret reference_digest reference_auth reference_root :
  hoare[RawFors(PreparationView(Independent)).recover :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\
    secret = secret0 /\ auth = auth0 /\
    size auth0 = 11 /\ size reference_auth = 11 /\
    all (fun x => size x = 16) auth0 /\ all (fun x => size x = 16) reference_auth /\
    size secret0 = 16 /\ size reference_secret = 16 /\
    path_recorded Independent.rawhistory (fors_pair seed0 ht0 tree0)
      (node reference_digest,0,target0) reference_auth /\
    (path_value Independent.rawhistory (fors_pair seed0 ht0 tree0)
      (node reference_digest,0,target0) reference_auth).`1 = reference_root ==>
    res = reference_root =>
      secret0 = reference_secret \/
      fors_leaf_collision Independent.rawhistory seed0 ht0 tree0 target0 \/
      path_input_collision Independent.rawhistory (fors_pair seed0 ht0 tree0)].
proof. exact (fors_recover_secret_or_collision seed0 ht0 tree0 target0 secret0 auth0 reference_secret reference_digest reference_auth reference_root). qed.
