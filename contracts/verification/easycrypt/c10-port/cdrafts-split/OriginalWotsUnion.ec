(* Fixed-coordinate WOTS charge for the unchanged initialized adaptive byte candidate game. *)
require import AllCore List Distr StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawKeygen FullPrefix.
require import FullSession ByteSession ExposureLog ClientQueryLog.
require import ChainValueView ChainStageSampling CachedChainOracle ChainByteCandidates.
require import PublicTargetSampling PrivateValueSampling ChainVectorInstall DualDigestSampling RedactedChainOracle ChainPublicHybrid.
require import SelectedChainSampling LateSelectedPreservation EarlyObservedWots EarlySelectedCharge FreshChainGuess FreshByteBound.
require import ObservedValueOpening.
require import SelectedWotsBound WotsCoordinateUniverse WotsCoordinateValidity ActualWotsCoordinate.
require import OriginalWotsCoordinateBound.
import RealOrder.



lemma original_wots_union_bound
  (A <: ByteClient {-Independent,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -WotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,-CachedChain,
    -SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,
    -ChainRedaction,-ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,
    -ChainGuess,-ChainHybridPrefix,-HybridCachedChain}) qr qs (coordinates : wots_coordinate list) &m :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  (forall c, mem coordinates c => valid_wots_coordinate c) =>
  Pr[OriginalWotsCandidateGame(A).run() @ &m : exists c, mem coordinates c /\
    selected_wots_cut Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
      ExposureLog.entries res c] <=
    (size coordinates)%r*(8%r*(full_public_budget qr qs+86)%r*(1%r/2%r)^128).
proof.
  move=> ha hr hs hqr hqs; elim coordinates => [|c rest ih] hv.
  + simplify; byphoare (_ : true ==> false) => //; hoare; trivial.
  have hc:=original_wots_coordinate_bound A qr qs c &m ha hr hs hqr hqs _.
  + apply hv; smt().
  have hb:=ih _; first by move=> x hx; apply hv; smt().
  have he : Pr[OriginalWotsCandidateGame(A).run() @ &m : exists x, mem (c::rest) x /\
      selected_wots_cut Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
        ExposureLog.entries res x] =
    Pr[OriginalWotsCandidateGame(A).run() @ &m :
      selected_wots_cut Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
        ExposureLog.entries res c \/ exists x, mem rest x /\
      selected_wots_cut Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
        ExposureLog.entries res x].
  + rewrite Pr[mu_eq]; smt().
  rewrite he Pr[mu_or]; smt(ge0_mu).
qed.
lemma original_wots_universe_bound
  (A <: ByteClient {-Independent,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -WotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,-CachedChain,
    -SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,
    -ChainRedaction,-ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,
    -ChainGuess,-ChainHybridPrefix,-HybridCachedChain}) qr qs &m :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[OriginalWotsCandidateGame(A).run() @ &m : exists c, mem wots_coordinates c /\
    selected_wots_cut Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
      ExposureLog.entries res c] <=
    632475648%r*((full_public_budget qr qs+86)%r*(1%r/2%r)^128).
proof.
  move=> ha hr hs hqr hqs.
  have hb:=original_wots_union_bound A qr qs wots_coordinates &m ha hr hs hqr hqs wots_coordinates_valid.
  rewrite wots_coordinates_size in hb; smt(RField.mulrA).
qed.
