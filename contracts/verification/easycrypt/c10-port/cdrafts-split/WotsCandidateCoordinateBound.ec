(* Fixed-coordinate WOTS charge for the unchanged initialized adaptive byte candidate game. *)
require import AllCore List Distr StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawKeygen FullPrefix.
require import FullSession ByteSession ExposureLog ClientQueryLog.
require import ChainValueView ChainStageSampling CachedChainOracle ChainByteCandidates.
require import PublicTargetSampling PrivateValueSampling ChainVectorInstall DualDigestSampling RedactedChainOracle ChainPublicHybrid.
require import SelectedChainSampling LateSelectedPreservation EarlyObservedWots EarlySelectedCharge FreshChainGuess FreshCandidateByteBound.
require import ObservedValueOpening.
require import SelectedWotsCandidateBound WotsCoordinateUniverse WotsCoordinateValidity ActualWotsCoordinate.
require import ChainVariableSessionCost ChainCandidateMass ChainCandidateBound OriginalWotsCoordinateBound.
import RealOrder.


lemma selected_wots_candidate_phoare
  (A <: ByteClient {-Independent,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -WotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,-CachedChain,
    -SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,
    -ChainRedaction,-ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,
    -ChainGuess,-ChainHybridPrefix,-HybridCachedChain}) qr qs :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0<=qr => 0<=qs =>
  phoare[SelectedWotsGame(A).run :
    FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs /\
    ChainStage.seed=pad(node KeygenInputs.public_seed) /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\ 0<=ChainCut.cut<7
    ==> res] <= (8%r*(chain_candidate_budget qr qs+86+2)%r*(1%r/2%r)^128).
proof.
  move=> ha hr hs; bypr => &m [hqr [hqs [hseed [hc hcut]]]].
  have hb:=selected_wots_candidate_bound A &m ha hseed hc hcut _ _; smt().
qed.
lemma configured_selected_wots_candidate_bound
  (A <: ByteClient {-Independent,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -WotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,-CachedChain,
    -SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,
    -ChainRedaction,-ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,
    -ChainGuess,-ChainHybridPrefix,-HybridCachedChain}) qr qs c0 :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0<=qr => 0<=qs => valid_wots_coordinate c0 =>
  phoare[ConfiguredSelectedWotsGame(A).run :
    FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs /\ coordinate=c0 ==> res] <=
    (8%r*(chain_candidate_budget qr qs+86+2)%r*(1%r/2%r)^128).
proof.
  move=> ha hr hs hc; proc; call (selected_wots_candidate_phoare A qr qs ha hr hs); auto.
  move: hc; rewrite /valid_wots_coordinate; smt().
qed.
lemma original_wots_candidate_coordinate_bound
  (A <: ByteClient {-Independent,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -WotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,-CachedChain,
    -SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,
    -ChainRedaction,-ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,
    -ChainGuess,-ChainHybridPrefix,-HybridCachedChain}) qr qs c &m :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs => valid_wots_coordinate c =>
  Pr[OriginalWotsCandidateGame(A).run() @ &m :
    selected_wots_cut Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
      ExposureLog.entries res c] <= 8%r*(chain_candidate_budget qr qs+86+2)%r*(1%r/2%r)^128.
proof.
  move=> ha hr hs hqr hqs hc.
  have he : Pr[OriginalWotsCandidateGame(A).run() @ &m :
      selected_wots_cut Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
        ExposureLog.entries res c] = Pr[ConfiguredSelectedWotsGame(A).run(c) @ &m : res].
  + byequiv (_ : ={glob A,glob Independent,glob FullLimits,glob KeygenInputs,glob FullSession,
      glob ExposureLog,glob ClientQueryLog} /\ coordinate{2}=c ==> _) => //.
    proc; inline SelectedWotsGame(A).run LoggingWotsContext(A,Independent).run.
    wp; call (_ : ={glob A,glob Independent,glob FullLimits,glob KeygenInputs,glob FullSession,
      glob ExposureLog,glob ClientQueryLog}); first by sim.
    inline Independent.init; auto; smt().
  rewrite he; byphoare (configured_selected_wots_candidate_bound A qr qs c ha hr hs hc) => //.
qed.
