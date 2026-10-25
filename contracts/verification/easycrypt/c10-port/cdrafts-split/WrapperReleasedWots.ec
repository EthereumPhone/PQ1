(* WOTS values are materialized only beyond the wrapper final release guard.
   Both internal attempts retain their exact optional outcomes and comparison;
   refused attempts can be followed by later attempts in the session. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawForest RawSigner RawWrapper.
require import ChainValueView MerkleRootWitness WrapperWotsRelease.
require import WrapperWotsSigningPlan WrapperWotsPlanSigner WrapperWotsPlanComparison WrapperInternalVerify.

module WrapperReleasedWots (O : PrefixOracle) (C : ChainOracle) = {
  proc sign(seed root random message shuffle_a shuffle_b : raw_input,
            ready final_guard : bool) : raw_signature option = {
    var first, second, signature, result;
    result <- None;
    if (ready) {
      first <@ WrapperWotsPlanSigner(O).sign(seed,root,random,message,shuffle_a);
      if (first<>None) {
        second <@ WrapperWotsPlanSigner(O).sign(seed,root,random,message,shuffle_b);
        if (second<>None /\ first=second) {
          if (final_guard) {
            signature <@ WrapperWotsRelease(C).run(seed,oget first);
            result <- Some signature;
          }
        }
      }
    }
    return result;
  }
}.

lemma wrapper_wots_release_plan_projection seed_ref root_ref message_ref :
  equiv [WrapperWithoutInternalVerify(Independent).sign ~
    WrapperReleasedWots(Independent,ConcreteChain(Independent)).sign :
    seed{1}=seed_ref /\ root{1}=root_ref /\ message{1}=message_ref /\
    ={arg,Independent.rawhistory,Independent.secrethistory} ==>
    ={res,Independent.rawhistory,Independent.secrethistory}].
proof.
  proc; sp 1 1; if => //.
  seq 1 1 : (seed{1}=seed_ref /\ root{1}=root_ref /\ message{1}=message_ref /\
    ={seed,root,random,message,shuffle_b,final_guard,result,Independent.rawhistory,Independent.secrethistory} /\
    wrapper_wots_signer_supported Independent.rawhistory{1} Independent.secrethistory{1} seed_ref root_ref message_ref first{1} first{2}).
  + call (wrapper_wots_plan_signer_projection seed_ref root_ref message_ref); auto.
  if.
  + move=> &1 &2; rewrite /wrapper_wots_signer_supported /wrapper_wots_result_planned; smt().
  + exists* first{1},first{2}; elim* => sig_ref plan_ref.
    seq 1 1 : (seed{1}=seed_ref /\ root{1}=root_ref /\ message{1}=message_ref /\
      ={seed,root,message,final_guard,result,Independent.rawhistory,Independent.secrethistory} /\
      first{1}=sig_ref /\ first{2}=plan_ref /\ sig_ref<>None /\ plan_ref<>None /\
      wrapper_wots_signer_supported Independent.rawhistory{1} Independent.secrethistory{1} seed_ref root_ref message_ref sig_ref plan_ref /\
      wrapper_wots_signer_supported Independent.rawhistory{1} Independent.secrethistory{1} seed_ref root_ref message_ref second{1} second{2}).
    - call (_ : seed{1}=seed_ref /\ root{1}=root_ref /\ message{1}=message_ref /\
        ={arg,Independent.rawhistory,Independent.secrethistory} /\
        wrapper_wots_signer_supported Independent.rawhistory{1} Independent.secrethistory{1} seed_ref root_ref message_ref sig_ref plan_ref ==>
        ={Independent.rawhistory,Independent.secrethistory} /\
        wrapper_wots_signer_supported Independent.rawhistory{1} Independent.secrethistory{1} seed_ref root_ref message_ref sig_ref plan_ref /\
        wrapper_wots_signer_supported Independent.rawhistory{1} Independent.secrethistory{1} seed_ref root_ref message_ref res{1} res{2}).
      * conseq (wrapper_wots_plan_signer_projection seed_ref root_ref message_ref)
          (wrapper_wots_signer_plan_preserved RawSigner seed_ref root_ref message_ref sig_ref plan_ref); smt().
      auto; rewrite /wrapper_wots_signer_supported /wrapper_wots_result_planned; smt().
    if.
    - move=> &1 &2 hp.
      have hc := wrapper_wots_supported_comparison Independent.rawhistory{1} Independent.secrethistory{1}
        seed_ref root_ref message_ref first{1} second{1} first{2} second{2}.
      smt().
    - if => //.
      exists* Independent.rawhistory{2},Independent.secrethistory{2}; elim* => h_ref s_ref.
      wp; call{2} (wrapper_wots_release_total seed_ref (oget sig_ref) (oget plan_ref) h_ref s_ref).
      auto; rewrite /wrapper_wots_signer_supported /wrapper_wots_result_planned /wrapper_wots_signature_planned; smt().
    auto.
  auto.
qed.

lemma wrapper_released_wots_projection seed_ref root_ref message_ref :
  equiv [RawWrapper(Independent).sign ~
    WrapperReleasedWots(Independent,ConcreteChain(Independent)).sign :
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
  exact (wrapper_wots_release_plan_projection seed_ref (pad root_ref) message_ref).
qed.
