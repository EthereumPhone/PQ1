(* Selected-cut probability for the actual initialized byte wrapper. *)
require import AllCore List Distr StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawKeygen.
require import WrapperSession WrapperByteSession ExposureLog ClientQueryLog.
require import ChainValueView ChainStageSampling CachedChainOracle ChainByteCandidates WrapperWotsChainContext.
require import PublicTargetSampling PrivateValueSampling ChainVectorInstall DualDigestSampling RedactedChainOracle ChainPublicHybrid.
require import WrapperSelectedChainSampling WrapperLateSelectedPreservation WrapperEarlyObservedWots WrapperEarlySelectedCharge.
require import FreshChainGuess WrapperWotsFreshBound WrapperWotsCandidateBudget ObservedValueOpening.
require import WotsCoordinateUniverse WotsCoordinateValidity ActualWotsCoordinate.
import RealOrder.

require import WrapperSelectedWotsBound.

module WrapperOriginalWotsCandidateGame (A : WrapperByteClient) = {
  proc run() : raw_input list = {
    var outputs; Independent.init(); outputs <@ WrapperOriginalWotsCandidates(A,Independent).run(); return outputs;
  }
}.
module WrapperConfiguredSelectedWotsGame (A : WrapperByteClient) = {
  proc run(coordinate : wots_coordinate) : bool = {
    var result;
    ChainStage.seed <- pad(node KeygenInputs.public_seed);
    ChainStage.layer <- coordinate.`1; ChainStage.tree <- coordinate.`2; ChainStage.kp <- coordinate.`3;
    ChainStage.index <- coordinate.`4; ChainCut.cut <- coordinate.`5;
    result <@ WrapperSelectedWotsGame(A).run(); return result;
  }
}.

lemma wrapper_selected_wots_phoare
  (A <: WrapperByteClient {-Independent,-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -WrapperWotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,-CachedChain,
    -SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,
    -ChainRedaction,-ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,
    -ChainGuess,-ChainHybridPrefix,-HybridCachedChain}) qr qs :
  (forall (V <: WrapperByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0<=qr => 0<=qs =>
  phoare[WrapperSelectedWotsGame(A).run :
    WrapperLimits.raw_cap=qr /\ WrapperLimits.sign_cap=qs /\
    ChainStage.seed=pad(node KeygenInputs.public_seed) /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\ 0<=ChainCut.cut<7
    ==> res] <= (8%r*(wrapper_wots_candidate_budget qr qs+88)%r*(1%r/2%r)^128).
proof.
  move=> ha hr hs; bypr => &m [hqr [hqs [hseed [hc hcut]]]].
  have hb:=wrapper_selected_wots_bound A &m ha hseed hc hcut _ _; smt().
qed.
lemma wrapper_configured_selected_wots_bound
  (A <: WrapperByteClient {-Independent,-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -WrapperWotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,-CachedChain,
    -SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,
    -ChainRedaction,-ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,
    -ChainGuess,-ChainHybridPrefix,-HybridCachedChain}) qr qs c0 :
  (forall (V <: WrapperByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0<=qr => 0<=qs => valid_wots_coordinate c0 =>
  phoare[WrapperConfiguredSelectedWotsGame(A).run :
    WrapperLimits.raw_cap=qr /\ WrapperLimits.sign_cap=qs /\ coordinate=c0 ==> res] <=
    (8%r*(wrapper_wots_candidate_budget qr qs+88)%r*(1%r/2%r)^128).
proof.
  move=> ha hr hs hc; proc; call (wrapper_selected_wots_phoare A qr qs ha hr hs); auto.
  move: hc; rewrite /valid_wots_coordinate; smt().
qed.
lemma wrapper_original_wots_coordinate_bound
  (A <: WrapperByteClient {-Independent,-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -WrapperWotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,-CachedChain,
    -SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,
    -ChainRedaction,-ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,
    -ChainGuess,-ChainHybridPrefix,-HybridCachedChain}) qr qs c &m :
  (forall (V <: WrapperByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs => valid_wots_coordinate c =>
  Pr[WrapperOriginalWotsCandidateGame(A).run() @ &m :
    selected_wots_cut Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
      ExposureLog.entries res c] <= 8%r*(wrapper_wots_candidate_budget qr qs+88)%r*(1%r/2%r)^128.
proof.
  move=> ha hr hs hqr hqs hc.
  have he : Pr[WrapperOriginalWotsCandidateGame(A).run() @ &m :
      selected_wots_cut Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
        ExposureLog.entries res c] = Pr[WrapperConfiguredSelectedWotsGame(A).run(c) @ &m : res].
  + byequiv (_ : ={glob A,glob Independent,glob WrapperLimits,glob KeygenInputs,glob WrapperSession,
      glob ExposureLog,glob ClientQueryLog} /\ coordinate{2}=c ==> _) => //.
    proc; inline WrapperSelectedWotsGame(A).run WrapperLoggingWotsContext(A,Independent).run.
    wp; call (_ : ={glob A,glob Independent,glob WrapperLimits,glob KeygenInputs,glob WrapperSession,
      glob ExposureLog,glob ClientQueryLog}); first by sim.
    inline Independent.init; auto; smt().
  rewrite he; byphoare (wrapper_configured_selected_wots_bound A qr qs c ha hr hs hc) => //.
qed.
