(* Adding one actual per-tree result retains the rest of the forest. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawForest.
require import ForsOpening ForsOneRecorded ForestOpenings ForestOracle.

lemma forest_one_step seed0 ht0 digest0 t0 secrets0 auths0 roots0 visited :
  hoare [RawForest(PreparationView(Independent)).one :
    seed=seed0 /\ ht=ht0 /\ tree=t0 /\ leaf=forest_index digest0 t0 /\
    forest_openings Independent.rawhistory seed0 ht0 digest0 secrets0 auths0 roots0 visited ==>
    forest_openings Independent.rawhistory seed0 ht0 digest0 secrets0 auths0 roots0 visited /\
    fors_opening Independent.rawhistory seed0 ht0 t0 (forest_index digest0 t0) res.`1 res.`2 res.`3].
proof.
  conseq (forest_one_recorded seed0 ht0 t0 (forest_index digest0 t0))
    (one_keeps_forest seed0 ht0 digest0 secrets0 auths0 roots0 visited); smt().
qed.
