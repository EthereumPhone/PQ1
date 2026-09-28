(* Oracle and component calls retain all earlier forest openings. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawFors RawForest.
require import PersistentGrind AcceptedContexts ForestOpenings ForestWitness ForsComponentHistory.

lemma hash_records_forest seed0 ht0 digest0 secrets0 auths0 roots0 visited x0 :
  hoare [Independent.hash :
    forest_openings Independent.rawhistory seed0 ht0 digest0 secrets0 auths0 roots0 visited /\ x=x0 ==>
    forest_openings Independent.rawhistory seed0 ht0 digest0 secrets0 auths0 roots0 visited /\
    Independent.rawhistory.[x0]=Some res].
proof. proc; sp 1; if; auto; smt(forest_openings_extends extends_insert get_set_sameE domE). qed.

lemma hash_records_forest_witness seed0 ht0 digest0 secrets0 auths0 roots0 x0 :
  hoare [Independent.hash :
    forest_witness Independent.rawhistory seed0 ht0 digest0 secrets0 auths0 roots0 /\ x=x0 ==>
    forest_witness Independent.rawhistory seed0 ht0 digest0 secrets0 auths0 roots0 /\
    Independent.rawhistory.[x0]=Some res].
proof. proc; sp 1; if; auto; smt(forest_witness_extends extends_insert get_set_sameE domE). qed.

lemma one_keeps_forest seed0 ht0 digest0 secrets0 auths0 roots0 visited :
  hoare [RawForest(PreparationView(Independent)).one :
    forest_openings Independent.rawhistory seed0 ht0 digest0 secrets0 auths0 roots0 visited ==>
    forest_openings Independent.rawhistory seed0 ht0 digest0 secrets0 auths0 roots0 visited].
proof.
  exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  conseq (fors_one_extends RawForest s0 h0); smt(extends_refl forest_openings_extends).
qed.

lemma root_keeps_forest seed0 ht0 digest0 secrets0 auths0 roots0 visited :
  hoare [RawFors(PreparationView(Independent)).root :
    forest_openings Independent.rawhistory seed0 ht0 digest0 secrets0 auths0 roots0 visited ==>
    forest_openings Independent.rawhistory seed0 ht0 digest0 secrets0 auths0 roots0 visited].
proof.
  exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  conseq (fors_root_extends RawFors s0 h0); smt(extends_refl forest_openings_extends).
qed.
