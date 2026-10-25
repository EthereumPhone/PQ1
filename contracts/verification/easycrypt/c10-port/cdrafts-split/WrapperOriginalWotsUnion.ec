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

require import WrapperOriginalWotsCoordinateBound.

lemma wrapper_original_wots_union_bound
  (A <: WrapperByteClient {-Independent,-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -WrapperWotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,-CachedChain,
    -SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,
    -ChainRedaction,-ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,
    -ChainGuess,-ChainHybridPrefix,-HybridCachedChain}) qr qs (coordinates : wots_coordinate list) &m :
  (forall (V <: WrapperByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  (forall c, mem coordinates c => valid_wots_coordinate c) =>
  Pr[WrapperOriginalWotsCandidateGame(A).run() @ &m : exists c, mem coordinates c /\
    selected_wots_cut Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
      ExposureLog.entries res c] <=
    (size coordinates)%r*(8%r*(wrapper_wots_candidate_budget qr qs+88)%r*(1%r/2%r)^128).
proof.
  move=> ha hr hs hqr hqs; elim coordinates => [|c rest ih] hv.
  + simplify; byphoare (_ : true ==> false) => //; hoare; trivial.
  have hc:=wrapper_original_wots_coordinate_bound A qr qs c &m ha hr hs hqr hqs _.
  + apply hv; smt().
  have hb:=ih _; first by move=> x hx; apply hv; smt().
  have he : Pr[WrapperOriginalWotsCandidateGame(A).run() @ &m : exists x, mem (c::rest) x /\
      selected_wots_cut Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
        ExposureLog.entries res x] =
    Pr[WrapperOriginalWotsCandidateGame(A).run() @ &m :
      selected_wots_cut Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
        ExposureLog.entries res c \/ exists x, mem rest x /\
      selected_wots_cut Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
        ExposureLog.entries res x].
  + rewrite Pr[mu_eq]; smt().
  rewrite he Pr[mu_or]; smt(ge0_mu).
qed.
lemma wrapper_original_wots_universe_bound
  (A <: WrapperByteClient {-Independent,-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -WrapperWotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,-CachedChain,
    -SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,
    -ChainRedaction,-ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,
    -ChainGuess,-ChainHybridPrefix,-HybridCachedChain}) qr qs &m :
  (forall (V <: WrapperByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[WrapperOriginalWotsCandidateGame(A).run() @ &m : exists c, mem wots_coordinates c /\
    selected_wots_cut Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
      ExposureLog.entries res c] <=
    632475648%r*((wrapper_wots_candidate_budget qr qs+88)%r*(1%r/2%r)^128).
proof.
  move=> ha hr hs hqr hqs.
  have hb:=wrapper_original_wots_union_bound A qr qs wots_coordinates &m ha hr hs hqr hqs wots_coordinates_valid.
  rewrite wots_coordinates_size in hb; smt(RField.mulrA).
qed.
