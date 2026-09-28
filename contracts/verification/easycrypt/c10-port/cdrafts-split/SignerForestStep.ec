(* Forest signing records an opening without losing the earlier public root. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawForest.
require import PersistentGrind AcceptedContexts MerkleRootWitness ForestOpening SignerComponentHistory.

lemma forest_sign_history_opening seed0 ht0 digest0 s0 h0 :
  hoare [RawForest(PreparationView(Independent)).sign :
    seed=seed0 /\ ht=ht0 /\ digest=digest0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    forest_opening Independent.rawhistory seed0 ht0 digest0 res.`1 res.`2 res.`3 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  conseq (raw_forest_sign_opening seed0 ht0 digest0) (forest_sign_extends RawForest s0 h0); smt().
qed.

lemma forest_sign_keeps_top seed0 ht0 digest0 root0 :
  hoare [RawForest(PreparationView(Independent)).sign :
    seed=seed0 /\ ht=ht0 /\ digest=digest0 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0 ==>
    forest_opening Independent.rawhistory seed0 ht0 digest0 res.`1 res.`2 res.`3 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0].
proof.
  exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  conseq (forest_sign_history_opening seed0 ht0 digest0 s0 h0); smt(extends_refl merkle_root_witness_extends).
qed.
