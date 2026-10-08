(* Passive chain-opening observation preserves the actual component results and tables. *)
require import AllCore List.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawShuffle RawFors RawForest.
require import ChainValueView ChainKeygenView ChainMerkleView ChainLayerView ChainSignerView.
require import ChainStageSampling SignerComponentHistory RoleGrind CachedChainOracle ChainObserverProjection.

lemma observed_forest_client_projection
  (S <: ForestSigning {-Independent,-ChainStage,-ChainRevelation}) :
  equiv [S(PreparationView(Independent)).sign ~
    S(PreparationView(ChainPrefix(ObservedChain(Independent)))).sign :
    ={arg,glob S,glob Independent} ==> ={res,glob S,glob Independent}].
proof.
  proc (={glob Independent}) => //.
  + by sim.
  proc; inline ChainObservedPrefix(Independent).derive.
  wp; call (_ : ={glob Independent}); first by sim. auto.
qed.
lemma observed_forest_projection :
  equiv [RawForest(PreparationView(Independent)).sign ~
    RawForest(PreparationView(ChainPrefix(ObservedChain(Independent)))).sign :
    ={arg,glob Independent} ==> ={res,glob Independent}].
proof. conseq (observed_forest_client_projection RawForest); smt(). qed.
lemma observed_chain_forest_client_projection
  (S <: ForestSigning {-Independent,-ChainStage,-ChainRevelation}) :
  equiv [S(PreparationView(ChainPrefix(ConcreteChain(Independent)))).sign ~
    S(PreparationView(ChainPrefix(ObservedChain(Independent)))).sign :
    ={arg,glob S,glob Independent} ==> ={res,glob S,glob Independent}].
proof.
  proc (={glob Independent}) => //.
  + by sim.
  proc; inline ChainObservedPrefix(Independent).derive.
  wp; call (_ : ={glob Independent}); first by sim. auto.
qed.
lemma observed_chain_forest_projection :
  equiv [RawForest(PreparationView(ChainPrefix(ConcreteChain(Independent)))).sign ~
    RawForest(PreparationView(ChainPrefix(ObservedChain(Independent)))).sign :
    ={arg,glob Independent} ==> ={res,glob Independent}].
proof. conseq (observed_chain_forest_client_projection RawForest); smt(). qed.
lemma observed_grind_projection :
  equiv [RoleGrind(Independent).run ~ RoleGrind(ChainPrefix(ObservedChain(Independent))).run :
    ={arg,glob Independent} ==> ={res,glob Independent}].
proof.
  proc; while (={i,result,random,message,seed,root,glob Independent}).
  + wp; call (_ : ={glob Independent}); first by sim.
    wp; call observed_private_projection; auto.
  auto.
qed.

lemma observed_chain_grind_projection :
  equiv [RoleGrind(ChainPrefix(ConcreteChain(Independent))).run ~ RoleGrind(ChainPrefix(ObservedChain(Independent))).run :
    ={arg,glob Independent} ==> ={res,glob Independent}].
proof.
  proc; while (={i,result,random,message,seed,root,glob Independent}).
  + wp; call (_ : ={glob Independent}); first by sim.
    wp; call observed_private_projection; auto.
  auto.
qed.

lemma observed_wots_projection :
  equiv [ChainWots(ConcreteChain(Independent)).sign ~ ChainWots(ObservedChain(Independent)).sign :
    ={arg,glob Independent} ==> ={res,glob Independent}].
proof.
  proc; seq 1 1 : (={seed,layer,tree,kp,message,shuffle,accepted,glob Independent}).
  + call (_ : ={glob Independent}); first by sim. auto.
  sp 1 1; if; auto.
  wp; while (={seed,layer,tree,kp,accepted,order,step,sigma,glob Independent}).
  + wp; call observed_value_projection; auto.
  wp; call (_ : ={glob Independent}); first by sim. auto.
qed.
lemma observed_leaf_projection :
  equiv [ChainKeygen(ConcreteChain(Independent)).leaf ~ ChainKeygen(ObservedChain(Independent)).leaf :
    ={arg,glob Independent} ==> ={res,glob Independent}].
proof.
  proc; wp; call (_ : ={glob Independent}); first by sim.
  wp; while (={seed,layer,tree,kp,i,elements,glob Independent}).
  + wp; call observed_value_projection; auto.
  auto.
qed.
lemma observed_root_projection :
  equiv [ChainKeygen(ConcreteChain(Independent)).root ~ ChainKeygen(ObservedChain(Independent)).root :
    ={arg,glob Independent} ==> ={res,glob Independent}].
proof.
  proc; wp; while (={seed,layer,tree,kp,stack,glob Independent}).
  + wp; while (={seed,layer,tree,kp,current,height,stack,glob Independent}); first by sim.
    wp; call observed_leaf_projection; auto.
  auto.
qed.
lemma observed_merkle_projection :
  equiv [ChainMerkle(ConcreteChain(Independent)).build ~ ChainMerkle(ObservedChain(Independent)).build :
    ={arg,glob Independent} ==> ={res,glob Independent}].
proof.
  proc; wp; while (={seed,layer,tree,target,kp,stack,keep,kept,glob Independent}).
  + wp; while (={seed,layer,tree,target,kp,current,height,stack,keep,kept,glob Independent}); first by sim.
    wp; call observed_leaf_projection; auto.
  auto.
qed.
lemma observed_layer_projection :
  equiv [ChainLayer(ConcreteChain(Independent)).sign ~ ChainLayer(ObservedChain(Independent)).sign :
    ={arg,glob Independent} ==> ={res,glob Independent}].
proof.
  proc; seq 3 3 : (={seed,layer,tree,leaf,message,signed,built,glob Independent}).
  + call observed_wots_projection.
    call (_ : ={glob Independent}); first by sim.
    call observed_merkle_projection; auto.
  sp 1 1; if; auto; wp; call (_ : ={glob Independent}); first by sim. auto.
qed.
lemma observed_finish_projection :
  equiv [ChainSigner(ConcreteChain(Independent)).finish ~ ChainSigner(ObservedChain(Independent)).finish :
    ={arg,glob Independent} ==> ={res,glob Independent}].
proof.
  proc; wp; while (={seed,randomizer,forest,current,idx_tree,layer,layers,ok,shuffle,glob Independent}).
  + wp; call observed_layer_projection; auto.
  wp; call observed_chain_forest_projection; auto.
qed.
lemma observed_sign_projection :
  equiv [ChainSigner(ConcreteChain(Independent)).sign ~ ChainSigner(ObservedChain(Independent)).sign :
    ={arg,glob Independent} ==> ={res,glob Independent}].
proof.
  proc; seq 1 1 : (={seed,root,random,message,shuffle,accepted,glob Independent}).
  + call observed_chain_grind_projection; auto.
  sp 1 1; if; auto; call observed_finish_projection; auto.
qed.
