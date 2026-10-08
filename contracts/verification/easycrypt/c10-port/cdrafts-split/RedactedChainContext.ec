(* Adaptive opening redaction is exact for the event that no opening occurred. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid RawKeygen.
require import ChainValueView ChainStageSampling CachedChainOracle RedactedChainOracle.
require import RedactedChainCoupling ChainOpeningMonotone.

lemma redact_chain_context
  (A <: ChainContext {-Independent,-ChainStage,-ChainCut,-ChainRevelation,-ChainRedaction,
    -CachedChain,-RedactedCachedChain,-RedactedChainPrefix}) :
  (forall (O <: ChainOracle {-A}), islossless O.hash => islossless O.derive =>
    islossless O.value => islossless A(O).run) =>
  equiv [A(CachedChain).run ~ A(RedactedCachedChain).run :
    ={glob A,glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,
      ChainStage.kp,ChainStage.index,ChainStage.values} /\
    !ChainRevelation.opened{1} /\ !ChainRedaction.opened{2} ==>
    if ChainRedaction.opened{2} then ChainRevelation.opened{1}
    else ={res,glob A,glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,
      ChainStage.kp,ChainStage.index,ChainStage.values} /\ !ChainRevelation.opened{1}].
proof.
  move=> hll.
  proc (ChainRedaction.opened)
    (={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,
      ChainStage.kp,ChainStage.index,ChainStage.values} /\ !ChainRevelation.opened{1})
    ChainRevelation.opened{1}.
  + smt().
  + smt().
  + exact hll.
  + proc*; call (_ : ={glob Independent}); first by sim. auto; smt().
  + move=> &2 _; proc*; call independent_hash_ll; auto.
  + move=> &1; proc*; call independent_hash_ll; auto.
  + proc*; call redacted_chain_derive_coupling; auto; smt().
  + move=> &2 _; conseq observed_derive_opened_sure; smt().
  + move=> &1; conseq redacted_derive_opened_sure; smt().
  + proc*; call redacted_cached_value_coupling; auto; smt().
  + move=> &2 _; conseq cached_value_opened_sure; smt().
  + move=> &1; conseq redacted_value_opened_sure; smt().
qed.
