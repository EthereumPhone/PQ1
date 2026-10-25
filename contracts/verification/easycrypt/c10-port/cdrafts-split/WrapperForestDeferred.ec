(* A checked public planning/materialization split for the actual forest.
   The split preserves results and memo tables under arbitrary prehistory.
   It deliberately does not assert equality of trusted replay query logs. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawForest.
require import ForsLeafView WrapperForestMemo WrapperForestPlan WrapperForestRelease.

module WrapperForestDirect (O : PreparationOracle) = {
  proc sign(seed : raw_input, ht : int, digest : digest, shuffle : raw_input) : raw_input list * raw_input list list * raw_input = {
    var result; result <@ RawForest(O).sign(seed,ht,digest,shuffle); return result;
  }
}.
module WrapperForestDeferred (O : PreparationOracle) (F : ForsLeafOracle) = {
  proc sign(seed : raw_input, ht : int, digest : digest, shuffle : raw_input) : raw_input list * raw_input list list * raw_input = {
    var plan, secrets;
    plan <@ WrapperForestPlan(O,F).sign(seed,ht,digest,shuffle);
    secrets <@ WrapperForestRelease(F).values(ht,digest,plan.`1);
    return (secrets,plan.`2,plan.`3);
  }
}.

lemma wrapper_forest_deferred_projection seed_ref ht_ref digest_ref :
  equiv [RawForest(PreparationView(Independent)).sign ~
    WrapperForestDeferred(PreparationView(Independent),ConcreteForsLeaf(PreparationView(Independent))).sign :
    seed{1}=seed_ref /\ ht{1}=ht_ref /\ digest{1}=digest_ref /\
    ={arg,Independent.rawhistory,Independent.secrethistory} ==>
    ={res,Independent.rawhistory,Independent.secrethistory}].
proof.
  transitivity WrapperForestDirect(PreparationView(Independent)).sign
    (={arg,glob Independent} ==> ={res,glob Independent})
    (seed{1}=seed_ref /\ ht{1}=ht_ref /\ digest{1}=digest_ref /\
      ={arg,Independent.rawhistory,Independent.secrethistory} ==>
      ={res,Independent.rawhistory,Independent.secrethistory}) => //.
  + smt().
  + proc*; inline{2} WrapperForestDirect(PreparationView(Independent)).sign.
    wp; call (_ : ={glob Independent}); first by sim.
    auto.
  proc; seq 1 1 : (ht{2}=ht_ref /\ digest{2}=digest_ref /\
    ={Independent.rawhistory,Independent.secrethistory} /\
    result{1}.`2=plan{2}.`2 /\ result{1}.`3=plan{2}.`3 /\
    nth (nseq 16 0) result{1}.`1 12=plan{2}.`1 /\
    wrapper_fors_memo_prefix Independent.secrethistory{1} ht_ref digest_ref result{1}.`1 (range 0 12)).
  + call (wrapper_forest_public_plan seed_ref ht_ref digest_ref); auto.
  exists* result{1},Independent.secrethistory{2},Independent.rawhistory{2},Independent.queries{2};
    elim* => result_ref s_ref h_ref q_ref.
  call{2} (wrapper_forest_release_total ht_ref digest_ref result_ref.`1 s_ref h_ref q_ref).
  auto; smt().
qed.
