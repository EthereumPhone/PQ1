require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawForest.
require import PersistentGrind RawForsPathReplay ForsOpening ForestOpenings ForestWitness.
require import ForestRecoveryReplay ForestSignRecorded ActualForestCorrect.
lemma forest_special_recorded h seed ht digest secrets auths roots finalsecret d :
  forest_openings h seed ht digest secrets auths roots (range 0 12) =>
  h.[fors_leaf_input seed ht 11 0 finalsecret]=Some d =>
  forest_witness h seed ht digest (put secrets 12 finalsecret) auths (put roots 12 (node d)).
proof. exact (forest_special_recorded h seed ht digest secrets auths roots finalsecret d). qed.
