(* The unreturned condition in the actual output implies the observed cut stayed unopened. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawKeygen FullSession ByteSession.
require import ExposureLog ClientQueryLog ExposureSupport.
require import ChainValueView ChainStageSampling CachedChainOracle ChainByteCandidates.
require import ObservedValueOpening ObservedGameOpening ObservedCandidateHistory ExposureCutEvidence ActualWotsCoordinate.

lemma observed_actual_cut_unopened
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,
    -ChainStage,-ChainCut,-ChainRevelation,-CachedChain,-ObservedChain}) qs0 :
  0<=qs0 =>
  hoare[ChainByteCandidates(A,ObservedChain(Independent)).run :
    FullLimits.sign_cap=qs0 /\ ChainStage.seed=pad(node KeygenInputs.public_seed) /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\ !ChainRevelation.opened ==>
    selected_wots_cut Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
      ExposureLog.entries res (ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index,ChainCut.cut) =>
    !ChainRevelation.opened].
proof.
  move=> hqs.
  conseq (observed_candidates_cut_accounted A) (observed_wots_candidates_supported A qs0 hqs).
  + smt().
  rewrite /selected_wots_cut /=; smt(exposure_cut_conflicts_unreturned).
qed.
