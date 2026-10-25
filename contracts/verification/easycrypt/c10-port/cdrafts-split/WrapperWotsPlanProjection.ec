(* Exact success/refusal and table projection from actual WOTS signing to its
   public plan. The omitted signature is fixed by the recorded accepted digest. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots.
require import ChainValueView WotsReference WotsReferenceRoot WotsSignatureValue.
require import WrapperMemoProjection WrapperWotsPlan.

op wrapper_wots_planned h s seed layer tree kp
    (signed : (raw_input list * int) option) (planned : (int * digest) option) =
  (signed=None)=(planned=None) /\
  (signed<>None => (oget signed).`2=(oget planned).`1 /\
    wots_prefix h s seed layer tree kp 43 /\
    wots_signature h s seed layer tree kp (oget planned).`2 (oget signed).`1).

lemma wrapper_wots_count_table_projection :
  equiv [RawWots(PreparationView(Independent)).count ~ RawWots(PreparationView(Independent)).count :
    ={arg,Independent.rawhistory,Independent.secrethistory} ==>
    ={res,Independent.rawhistory,Independent.secrethistory}].
proof.
  proc; while (={seed,layer,tree,kp,message,i,result,Independent.rawhistory,Independent.secrethistory}).
  + wp; call wrapper_memo_hash_projection; auto.
  auto.
qed.

lemma wrapper_wots_factor_projection (O <: PrefixOracle) :
  equiv [RawWots(PreparationView(O)).sign ~ WrapperWotsPlan(O).sign :
    ={arg,glob O} ==> ={res,glob O}].
proof.
  transitivity ChainWots(ConcreteChain(O)).sign
    (={arg,glob O} ==> ={res,glob O}) (={arg,glob O} ==> ={res,glob O}) => //.
  + smt().
  + exact (chain_wots_sign_projection O).
  exact (wrapper_wots_sign_factor O).
qed.

lemma wrapper_wots_factored_plan seed0 layer0 tree0 kp0 root0 :
  equiv [WrapperWotsPlan(Independent).sign ~ WrapperWotsPlan(Independent).plan :
    seed{1}=seed0 /\ layer{1}=layer0 /\ tree{1}=tree0 /\ kp{1}=kp0 /\
    ={arg,Independent.rawhistory,Independent.secrethistory} /\
    wots_root Independent.rawhistory{1} Independent.secrethistory{1} seed0 layer0 tree0 kp0 root0 ==>
    ={Independent.rawhistory,Independent.secrethistory} /\
    wrapper_wots_planned Independent.rawhistory{1} Independent.secrethistory{1}
      seed0 layer0 tree0 kp0 res{1} res{2}].
proof.
  proc; seq 1 1 : (seed{1}=seed0 /\ layer{1}=layer0 /\ tree{1}=tree0 /\ kp{1}=kp0 /\
    ={seed,layer,tree,kp,message,shuffle,accepted,Independent.rawhistory,Independent.secrethistory} /\
    wots_root Independent.rawhistory{1} Independent.secrethistory{1} seed0 layer0 tree0 kp0 root0).
  + call (_ : ={arg,Independent.rawhistory,Independent.secrethistory} /\
      wots_root Independent.rawhistory{1} Independent.secrethistory{1} seed0 layer0 tree0 kp0 root0 ==>
      ={res,Independent.rawhistory,Independent.secrethistory} /\
      wots_root Independent.rawhistory{1} Independent.secrethistory{1} seed0 layer0 tree0 kp0 root0).
    - conseq wrapper_wots_count_table_projection (count_keeps_wots_root seed0 layer0 tree0 kp0 root0); smt().
    auto.
  sp 1 0; if; first by auto.
  + exists* accepted{1}; elim* => acc.
    wp; call (wrapper_wots_fill_plan seed0 layer0 tree0 kp0 (oget acc).`2).
    auto; rewrite /wots_root /wrapper_wots_planned; smt().
  auto; rewrite /wrapper_wots_planned; smt().
qed.

lemma wrapper_wots_plan_projection seed0 layer0 tree0 kp0 root0 :
  equiv [RawWots(PreparationView(Independent)).sign ~ WrapperWotsPlan(Independent).plan :
    seed{1}=seed0 /\ layer{1}=layer0 /\ tree{1}=tree0 /\ kp{1}=kp0 /\
    ={arg,Independent.rawhistory,Independent.secrethistory} /\
    wots_root Independent.rawhistory{1} Independent.secrethistory{1} seed0 layer0 tree0 kp0 root0 ==>
    ={Independent.rawhistory,Independent.secrethistory} /\
    wrapper_wots_planned Independent.rawhistory{1} Independent.secrethistory{1}
      seed0 layer0 tree0 kp0 res{1} res{2}].
proof.
  transitivity WrapperWotsPlan(Independent).sign
    (={arg,glob Independent} ==> ={res,glob Independent})
    (seed{1}=seed0 /\ layer{1}=layer0 /\ tree{1}=tree0 /\ kp{1}=kp0 /\
      ={arg,Independent.rawhistory,Independent.secrethistory} /\
      wots_root Independent.rawhistory{1} Independent.secrethistory{1} seed0 layer0 tree0 kp0 root0 ==>
      ={Independent.rawhistory,Independent.secrethistory} /\
      wrapper_wots_planned Independent.rawhistory{1} Independent.secrethistory{1}
        seed0 layer0 tree0 kp0 res{1} res{2}) => //.
  + smt().
  + exact (wrapper_wots_factor_projection Independent).
  exact (wrapper_wots_factored_plan seed0 layer0 tree0 kp0 root0).
qed.
