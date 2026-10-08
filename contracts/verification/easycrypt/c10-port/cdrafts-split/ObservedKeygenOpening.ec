(* Trusted endpoint construction never opens a selected proper chain cut. *)
require import AllCore List IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid RawKeygen.
require import ChainValueView ChainStageSampling CachedChainOracle ChainKeygenView ChainMerkleView.
require import ObservedValueOpening.

lemma observed_leaf_unopened seed0 layer0 tree0 kp0 opened0 :
  hoare[ChainKeygen(ObservedChain(Independent)).leaf :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\
    ChainStage.seed=seed0 /\ valid_chain_address layer0 tree0 kp0 0 /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\ ChainRevelation.opened=opened0 ==>
    ChainRevelation.opened=opened0].
proof.
  proc; wp; call (_ : true ==> true); first by trivial.
  wp; while (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ 0<=i<=43 /\
    ChainStage.seed=seed0 /\ valid_chain_address layer0 tree0 kp0 0 /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\ ChainRevelation.opened=opened0).
  + wp; exists* i; elim* => i0.
    call (observed_value_opening seed0 layer0 tree0 kp0 i0 7 opened0).
    auto; rewrite /valid_chain_address; smt().
  auto; smt().
qed.
lemma observed_root_unopened seed0 layer0 tree0 opened0 :
  hoare[ChainKeygen(ObservedChain(Independent)).root :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\
    ChainStage.seed=seed0 /\ valid_chain_address layer0 tree0 0 0 /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\ ChainRevelation.opened=opened0 ==>
    ChainRevelation.opened=opened0].
proof.
  proc; while (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ 0<=kp<=512 /\
    ChainStage.seed=seed0 /\ valid_chain_address layer0 tree0 0 0 /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\ ChainRevelation.opened=opened0).
  + wp; while (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ 0<=kp<512 /\
      ChainStage.seed=seed0 /\ valid_chain_address layer0 tree0 0 0 /\
      valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
      ChainCut.cut<7 /\ ChainRevelation.opened=opened0).
    - wp; call (_ : true ==> true); first by trivial.
      auto.
    wp; exists* kp; elim* => kp0.
    call (observed_leaf_unopened seed0 layer0 tree0 kp0 opened0).
    auto; rewrite /valid_chain_address; smt().
  auto; smt().
qed.
lemma observed_merkle_unopened seed0 layer0 tree0 opened0 :
  hoare[ChainMerkle(ObservedChain(Independent)).build :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\
    ChainStage.seed=seed0 /\ valid_chain_address layer0 tree0 0 0 /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\ ChainRevelation.opened=opened0 ==>
    ChainRevelation.opened=opened0].
proof.
  proc; while (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ 0<=kp<=512 /\
    ChainStage.seed=seed0 /\ valid_chain_address layer0 tree0 0 0 /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\ ChainRevelation.opened=opened0).
  + wp; while (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ 0<=kp<512 /\
      ChainStage.seed=seed0 /\ valid_chain_address layer0 tree0 0 0 /\
      valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
      ChainCut.cut<7 /\ ChainRevelation.opened=opened0).
    - wp; call (_ : true ==> true); first by trivial.
      auto.
    wp; exists* kp; elim* => kp0.
    call (observed_leaf_unopened seed0 layer0 tree0 kp0 opened0).
    auto; rewrite /valid_chain_address; smt().
  auto; smt().
qed.
