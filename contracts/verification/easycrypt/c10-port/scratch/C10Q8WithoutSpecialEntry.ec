require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawForest.
require import PersistentGrind RawForsPathReplay ForsOpening ForestOpenings ForestWitness.
require import ForestRecoveryReplay ForestSignRecorded ActualForestCorrect.
lemma forest_recover_fixed seed0 ht0 digest0 secrets0 auths0 roots0 lastd finald s0 h0 :
  hoare [RawForest(PreparationView(Independent)).recover :
    seed=seed0 /\ ht=ht0 /\ digest=digest0 /\ secrets=secrets0 /\ auths=auths0 /\
    forest_openings h0 seed0 ht0 digest0 secrets0 auths0 roots0 (range 0 12) /\
    nth (nseq 16 0) roots0 12=node lastd /\
    h0.[forest_compress_input seed0 ht0 roots0]=Some finald /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    res=node finald /\ extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof. exact (forest_recover_fixed seed0 ht0 digest0 secrets0 auths0 roots0 lastd finald s0 h0). qed.
