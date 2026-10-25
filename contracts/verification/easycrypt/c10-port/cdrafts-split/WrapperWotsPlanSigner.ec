(* The original bounded message search selects the same randomizer/digest for
   the WOTS plan. Refused searches and either refused layer remain refused. *)
require import AllCore List FMap.
require import C10RawOracle C10RawGrind C10HashDomains PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RoleGrind RawSigner.
require import GrindReturned SignerReturned WrapperDeferredSign WrapperWotsSigningPlan.

op wrapper_wots_hmsg_entry h seed root message (plan : wrapper_wots_signature_plan) =
  h.[hmsg_input seed root (pad plan.`1) message]=Some plan.`2 /\ accept_digest plan.`2.

op wrapper_wots_signer_supported h s seed root message signed planned =
  wrapper_wots_result_planned h s seed signed planned /\
  (planned<>None => wrapper_wots_hmsg_entry h seed root message (oget planned)).

module WrapperWotsPlanSigner (O : PrefixOracle) = {
  proc sign(seed root random message shuffle : raw_input) : wrapper_wots_signature_plan option = {
    var accepted, result;
    accepted <@ RoleGrind(O).run(random,message,seed,root);
    result <- None;
    if (accepted<>None) {
      result <@ WrapperWotsSigningPlan(O).finish(seed,(oget accepted).`1,(oget accepted).`2,shuffle);
    }
    return result;
  }
}.

lemma wrapper_wots_plan_signer_projection seed_ref root_ref message_ref :
  equiv [RawSigner(Independent).sign ~ WrapperWotsPlanSigner(Independent).sign :
    seed{1}=seed_ref /\ root{1}=root_ref /\ message{1}=message_ref /\
    ={arg,Independent.rawhistory,Independent.secrethistory} ==>
    ={Independent.rawhistory,Independent.secrethistory} /\
    wrapper_wots_signer_supported Independent.rawhistory{1} Independent.secrethistory{1}
      seed_ref root_ref message_ref res{1} res{2}].
proof.
  proc; seq 1 1 : (seed{1}=seed_ref /\ root{1}=root_ref /\ message{1}=message_ref /\
    ={seed,root,random,message,shuffle,accepted,Independent.rawhistory,Independent.secrethistory} /\
    returned_digest_entry Independent.rawhistory{1} seed_ref root_ref message_ref accepted{1}).
  + call (_ : seed{1}=seed_ref /\ root{1}=root_ref /\ message{1}=message_ref /\
      ={arg,Independent.rawhistory,Independent.secrethistory} ==>
      ={res,Independent.rawhistory,Independent.secrethistory} /\
      returned_digest_entry Independent.rawhistory{1} seed_ref root_ref message_ref res{1}).
    - conseq (wrapper_grind_table_projection WrapperConcreteGrind)
        (grind_returned_entry seed_ref root_ref message_ref); smt().
    auto.
  sp 1 1; if.
  + auto.
  + exists* accepted{1}; elim* => acc.
    call (_ : seed{1}=seed_ref /\ randomizer{1}=(oget acc).`1 /\ digest{1}=(oget acc).`2 /\
      ={arg,Independent.rawhistory,Independent.secrethistory} /\
      Independent.rawhistory{1}.[hmsg_input seed_ref root_ref (pad (oget acc).`1) message_ref]=Some (oget acc).`2 ==>
      ={Independent.rawhistory,Independent.secrethistory} /\
      wrapper_wots_result_planned Independent.rawhistory{1} Independent.secrethistory{1} seed_ref res{1} res{2} /\
      (res{2}<>None => (oget res{2}).`2=(oget acc).`2) /\
      Independent.rawhistory{1}.[hmsg_input seed_ref root_ref (pad (oget acc).`1) message_ref]=Some (oget acc).`2 /\
      (res{1}<>None => (oget res{1}).`1=(oget acc).`1)).
    - conseq (wrapper_wots_signing_plan_finish_projection seed_ref (oget acc).`2)
        (finish_keeps_randomizer_entry (oget acc).`1
          (hmsg_input seed_ref root_ref (pad (oget acc).`1) message_ref) (oget acc).`2); smt().
    auto; rewrite /wrapper_wots_signer_supported /wrapper_wots_result_planned /wrapper_wots_signature_planned
      /wrapper_wots_hmsg_entry /returned_digest_entry /pad; smt().
  auto; rewrite /wrapper_wots_signer_supported /wrapper_wots_result_planned; smt().
qed.
