require import AllCore List C10RawOracle PrefixGuess RawKeygen ChainStageSampling CachedChainOracle.
lemma selected_value_flag :
  hoare[CachedChain.value :
    seed=ChainStage.seed /\ layer=ChainStage.layer /\ tree=ChainStage.tree /\
    kp=ChainStage.kp /\ index=ChainStage.index /\ stop=3 /\
    ChainCut.cut=3 /\ !ChainRevelation.opened ==> !ChainRevelation.opened].
proof. proc; rcondt 1; first by auto. by auto. qed.
