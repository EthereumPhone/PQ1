(* Ordinary FORS openings occur only after the wrapper's final release guard.
   Both internal signing attempts still execute public construction and WOTS
   work. The projection retains refusal/retry semantics and both oracle maps. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawForest RawSigner RawWrapper.
require import ForsLeafView MerkleRootWitness WrapperForestMemo WrapperForestRelease.
require import WrapperSigningPlan WrapperPlanSigner WrapperPlanComparison WrapperInternalVerify.

module WrapperReleasedFors (O : PrefixOracle) (F : ForsLeafOracle) = {
  proc sign(seed root random message shuffle_a shuffle_b : raw_input,
            ready final_guard : bool) : raw_signature option = {
    var first, second, secrets, result;
    result <- None;
    if (ready) {
      first <@ WrapperPlanSigner(O,F).sign(seed,root,random,message,shuffle_a);
      if (first<>None) {
        second <@ WrapperPlanSigner(O,F).sign(seed,root,random,message,shuffle_b);
        if (second<>None /\ wrapper_plan_equal (oget first) (oget second)) {
          if ((final_guard)) {
            secrets <@ WrapperForestRelease(F).values(hypertree_index (oget first).`2,(oget first).`2,(oget first).`3);
            result <- Some ((oget first).`1,secrets,(oget first).`4,(oget first).`5);
          }
        }
      }
    }
    return result;
  }
}.

lemma wrapper_release_plan_projection seed_ref root_ref message_ref :
  equiv [WrapperWithoutInternalVerify(Independent).sign ~
    WrapperReleasedFors(Independent,ConcreteForsLeaf(PreparationView(Independent))).sign :
    seed{1}=seed_ref /\ root{1}=root_ref /\ message{1}=message_ref /\
    ={arg,Independent.rawhistory,Independent.secrethistory} ==>
    ={res,Independent.rawhistory,Independent.secrethistory}].
proof.
  proc; sp 1 1; if => //.
  seq 1 1 : (seed{1}=seed_ref /\ root{1}=root_ref /\ message{1}=message_ref /\
    ={seed,root,random,message,shuffle_b,final_guard,result,Independent.rawhistory,Independent.secrethistory} /\
    wrapper_plan_supported Independent.rawhistory{1} Independent.secrethistory{1} seed_ref root_ref message_ref first{1} first{2}).
  + call (wrapper_plan_signer_projection seed_ref root_ref message_ref); auto.
  if.
  + move=> &1 &2; rewrite /wrapper_plan_supported /wrapper_planned_result; smt().
  + exists* first{1},first{2}; elim* => sig_ref plan_ref.
    seq 1 1 : (seed{1}=seed_ref /\ root{1}=root_ref /\ message{1}=message_ref /\
      ={seed,root,message,final_guard,result,Independent.rawhistory,Independent.secrethistory} /\
      first{1}=sig_ref /\ first{2}=plan_ref /\ sig_ref<>None /\ plan_ref<>None /\
      wrapper_plan_supported Independent.rawhistory{1} Independent.secrethistory{1} seed_ref root_ref message_ref sig_ref plan_ref /\
      wrapper_plan_supported Independent.rawhistory{1} Independent.secrethistory{1} seed_ref root_ref message_ref second{1} second{2}).
    - call (_ : seed{1}=seed_ref /\ root{1}=root_ref /\ message{1}=message_ref /\
        ={arg,Independent.rawhistory,Independent.secrethistory} /\
        wrapper_plan_supported Independent.rawhistory{1} Independent.secrethistory{1} seed_ref root_ref message_ref sig_ref plan_ref ==>
        ={Independent.rawhistory,Independent.secrethistory} /\
        wrapper_plan_supported Independent.rawhistory{1} Independent.secrethistory{1} seed_ref root_ref message_ref sig_ref plan_ref /\
        wrapper_plan_supported Independent.rawhistory{1} Independent.secrethistory{1} seed_ref root_ref message_ref res{1} res{2}).
      * conseq (wrapper_plan_signer_projection seed_ref root_ref message_ref)
          (wrapper_signer_plan_preserved RawSigner seed_ref root_ref message_ref sig_ref plan_ref); smt().
      auto; rewrite /wrapper_plan_supported /wrapper_planned_result; smt().
    if.
    - move=> &1 &2 hp.
      have hc := wrapper_supported_comparison Independent.rawhistory{1} Independent.secrethistory{1}
        seed_ref root_ref message_ref first{1} second{1} first{2} second{2}.
      smt().
    - if => //.
      exists* Independent.rawhistory{2},Independent.secrethistory{2},Independent.queries{2}; elim* => h_ref s_ref q_ref.
      wp; call{2} (wrapper_forest_release_total (hypertree_index (oget plan_ref).`2) (oget plan_ref).`2
        (oget sig_ref).`2 s_ref h_ref q_ref).
      auto; rewrite /wrapper_plan_supported /wrapper_planned_result /wrapper_planned_signature; smt().
    auto.
  auto.
qed.

lemma wrapper_released_fors_projection seed_ref root_ref message_ref :
  equiv [RawWrapper(Independent).sign ~
    WrapperReleasedFors(Independent,ConcreteForsLeaf(PreparationView(Independent))).sign :
    seed{1}=seed_ref /\ root{1}=pad root_ref /\ message{1}=message_ref /\
    ={arg,Independent.rawhistory,Independent.secrethistory} /\
    merkle_root_witness Independent.rawhistory{1} Independent.secrethistory{1} seed_ref 1 0 root_ref ==>
    ={res,Independent.rawhistory,Independent.secrethistory}].
proof.
  transitivity WrapperWithoutInternalVerify(Independent).sign
    (seed{1}=seed_ref /\ root{1}=pad root_ref /\ message{1}=message_ref /\
      ={arg,Independent.rawhistory,Independent.secrethistory} /\
      merkle_root_witness Independent.rawhistory{1} Independent.secrethistory{1} seed_ref 1 0 root_ref ==>
      ={res,Independent.rawhistory,Independent.secrethistory})
    (seed{1}=seed_ref /\ root{1}=pad root_ref /\ message{1}=message_ref /\
      ={arg,Independent.rawhistory,Independent.secrethistory} ==>
      ={res,Independent.rawhistory,Independent.secrethistory}) => //.
  + smt().
  + exact (wrapper_internal_verify_projection seed_ref root_ref message_ref).
  exact (wrapper_release_plan_projection seed_ref (pad root_ref) message_ref).
qed.
