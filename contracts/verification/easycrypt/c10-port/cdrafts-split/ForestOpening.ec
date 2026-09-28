(* A complete returned forest signature retains its compression and paths. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawForest.
require import PersistentGrind AcceptedContexts ForestWitness ForestSignRecorded ForestRecoveryReplay.

op forest_opening h seed ht digest secrets auths root =
  exists roots d, forest_witness h seed ht digest secrets auths roots /\
    h.[forest_compress_input seed ht roots]=Some d /\ root=node d.

lemma forest_opening_extends h h' seed ht digest secrets auths root :
  extends h h' => forest_opening h seed ht digest secrets auths root =>
  forest_opening h' seed ht digest secrets auths root.
proof.
  move=> he [roots d [hw [hd hr]]].
  have hw' := forest_witness_extends h h' seed ht digest secrets auths roots he hw.
  rewrite /forest_opening; exists roots d; move: he; rewrite /extends; smt().
qed.

lemma raw_forest_sign_opening seed0 ht0 digest0 :
  hoare [RawForest(PreparationView(Independent)).sign :
    seed=seed0 /\ ht=ht0 /\ digest=digest0 ==>
    forest_opening Independent.rawhistory seed0 ht0 digest0 res.`1 res.`2 res.`3].
proof. conseq (forest_sign_recorded seed0 ht0 digest0); rewrite /forest_opening; smt(). qed.

lemma raw_forest_replays_opening seed0 ht0 digest0 secrets0 auths0 root0 :
  hoare [RawForest(PreparationView(Independent)).recover :
    seed=seed0 /\ ht=ht0 /\ digest=digest0 /\ secrets=secrets0 /\ auths=auths0 /\
    forest_opening Independent.rawhistory seed0 ht0 digest0 secrets0 auths0 root0 ==> res=root0].
proof.
  conseq (_ : exists roots d,
    seed=seed0 /\ ht=ht0 /\ digest=digest0 /\ secrets=secrets0 /\ auths=auths0 /\
    forest_witness Independent.rawhistory seed0 ht0 digest0 secrets0 auths0 roots /\
    Independent.rawhistory.[forest_compress_input seed0 ht0 roots]=Some d /\ root0=node d ==> res=root0).
  + rewrite /forest_opening; smt().
  elim* => roots d.
  exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  conseq (forest_recover_witness seed0 ht0 digest0 secrets0 auths0 roots d s0 h0); smt(extends_refl).
qed.
