(* Complete bounded search supplies the plan's actual accepted H_msg entry.
   Both success and refusal are coupled to the original signer. *)
require import AllCore List FMap.
require import C10RawOracle C10RawGrind C10HashDomains PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RoleGrind RawSigner.
require import ForsLeafView GrindReturned SignerReturned WrapperDeferredSign WrapperSigningPlan.

op wrapper_plan_entry h seed root message (plan : wrapper_signature_plan) =
  h.[hmsg_input seed root (pad plan.`1) message]=Some plan.`2 /\ accept_digest plan.`2.

op wrapper_plan_supported h s seed root message signed planned =
  wrapper_planned_result s signed planned /\
  (planned<>None => wrapper_plan_entry h seed root message (oget planned)).

module WrapperPlanSigner (O : PrefixOracle) (F : ForsLeafOracle) = {
  proc sign(seed root random message shuffle : raw_input) : wrapper_signature_plan option = {
    var accepted, result;
    accepted <@ RoleGrind(O).run(random,message,seed,root);
    result <- None;
    if (accepted<>None) {
      result <@ WrapperSigningPlan(O,F).finish(seed,(oget accepted).`1,(oget accepted).`2,shuffle);
    }
    return result;
  }
}.

lemma wrapper_plan_signer_projection seed_ref root_ref message_ref :
  equiv [RawSigner(Independent).sign ~
    WrapperPlanSigner(Independent,ConcreteForsLeaf(PreparationView(Independent))).sign :
    seed{1}=seed_ref /\ root{1}=root_ref /\ message{1}=message_ref /\
    ={arg,Independent.rawhistory,Independent.secrethistory} ==>
    ={Independent.rawhistory,Independent.secrethistory} /\
    wrapper_plan_supported Independent.rawhistory{1} Independent.secrethistory{1} seed_ref root_ref message_ref res{1} res{2}].
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
      wrapper_planned_result Independent.secrethistory{1} res{1} res{2} /\
      (res{2}<>None => (oget res{2}).`2=(oget acc).`2) /\
      Independent.rawhistory{1}.[hmsg_input seed_ref root_ref (pad (oget acc).`1) message_ref]=Some (oget acc).`2 /\
      (res{1}<>None => (oget res{1}).`1=(oget acc).`1)).
    - conseq (wrapper_signing_plan_finish_projection seed_ref (oget acc).`2)
        (finish_keeps_randomizer_entry (oget acc).`1
          (hmsg_input seed_ref root_ref (pad (oget acc).`1) message_ref) (oget acc).`2); smt().
    auto; rewrite /wrapper_plan_supported /wrapper_planned_result /wrapper_planned_signature
      /wrapper_plan_entry /returned_digest_entry /pad; smt().
  auto; rewrite /wrapper_plan_supported /wrapper_planned_result; smt().
qed.
