(* Valid signer coordinates expose a selected chain only at the requested digit. *)
require import AllCore List IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots WotsReference.
require import ChainValueView ChainStageSampling CachedChainOracle WotsInputSeparation.

op valid_chain_address layer tree kp index =
  0<=layer<2 /\ 0<=tree<512 /\ 0<=kp<512 /\ 0<=index<43.

lemma valid_chain_key_unique layer tree kp index layer' tree' kp' index' :
  valid_chain_address layer tree kp index => valid_chain_address layer' tree' kp' index' =>
  wots_key layer tree kp index=wots_key layer' tree' kp' index' =>
  (layer,tree,kp,index)=(layer',tree',kp',index').
proof.
  rewrite /valid_chain_address; move=> hv hv' he.
  have h:=wots_key_injective layer tree kp index layer' tree' kp' index' _ _ _ _ _ _ _ _ he;
    smt().
qed.
lemma observed_value_opening seed0 layer0 tree0 kp0 index0 stop0 opened0 :
  hoare[ObservedChain(Independent).value :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ index=index0 /\ stop=stop0 /\
    ChainStage.seed=seed0 /\ valid_chain_address layer0 tree0 kp0 index0 /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    0<=stop0<=7 /\ ChainRevelation.opened=opened0 ==>
    ChainRevelation.opened=(opened0 \/
      ((layer0,tree0,kp0,index0)=(ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index) /\
       stop0<=ChainCut.cut))].
proof.
  proc; if.
  + call (_ : true ==> true); first by trivial.
    auto; smt().
  inline ConcreteChain(ChainObservedPrefix(Independent)).value.
  wp; call (_ : true ==> true); first by trivial.
  wp; inline PreparationView(ChainObservedPrefix(Independent)).wots ChainObservedPrefix(Independent).derive.
  wp; call (_ : true ==> true); first by trivial.
  auto; smt(valid_chain_key_unique).
qed.
