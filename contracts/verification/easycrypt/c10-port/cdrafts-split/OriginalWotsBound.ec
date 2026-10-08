(* Fixed-coordinate WOTS charge for the unchanged initialized adaptive byte candidate game. *)
require import AllCore List Distr FMap StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawKeygen FullPrefix.
require import FullSession ByteSession ExposureLog ClientQueryLog.
require import ChainValueView ChainStageSampling CachedChainOracle ChainByteCandidates.
require import PublicTargetSampling PrivateValueSampling ChainVectorInstall DualDigestSampling RedactedChainOracle ChainPublicHybrid.
require import SelectedChainSampling LateSelectedPreservation EarlyObservedWots EarlySelectedCharge FreshChainGuess FreshByteBound.
require import ObservedValueOpening.
require import SelectedWotsBound WotsCoordinateUniverse WotsCoordinateValidity ActualWotsCoordinate.
require import PrefixIdeal ClientQueryDriver OriginalWotsCutBound ActualWotsCut.
require import RawSigner RawForest C10HashDomains ExposureComponents ExposurePartition ByteEncodingCharge EncodingMemoOracle EncodingCollisionState EncodingBirthday.
import RealOrder.



op actual_new_wots_component h s seed root entries (output : raw_input * raw_signature) =
  exists accepted, h.[hmsg_input seed root (pad output.`2.`1) output.`1]=Some accepted /\
    (new_top_component h s seed root entries accepted output.`2 \/
     new_bottom_component h s seed root entries accepted output.`2).
lemma actual_new_wots_cases h s seed root entries output :
  actual_new_wots_component h s seed root entries output =>
  wots_encoding_collision h \/ actual_top_cut h s seed root entries output \/
    actual_bottom_cut h s seed root entries output.
proof.
  move=> [accepted [hd hn]]; case (wots_encoding_collision h) => he; first smt().
  smt(actual_new_top_cut actual_new_bottom_cut).
qed.
lemma original_byte_new_wots_bound
  (A <: ByteClient {-Independent,-Physical,-EncodingMemo,-EncodingSamples,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -WotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,-CachedChain,
    -SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,
    -ChainRedaction,-ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,
    -ChainGuess,-ChainHybridPrefix,-HybridCachedChain}) qr qs &m :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : res /\
    actual_new_wots_component Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
      ExposureLog.entries ClientQueryLog.output] <=
    ((full_public_budget qr qs)*(full_public_budget qr qs-1))%r/2%r*(1%r/2%r)^129 +
    632475648%r*((full_public_budget qr qs+86)%r*(1%r/2%r)^128).
proof.
  move=> ha hr hs hqr hqs.
  have he : Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : res /\
      actual_new_wots_component Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
        ExposureLog.entries ClientQueryLog.output] <=
    Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m :
      wots_encoding_collision Independent.rawhistory \/ (res /\
      (actual_top_cut Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
        ExposureLog.entries ClientQueryLog.output \/
       actual_bottom_cut Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
        ExposureLog.entries ClientQueryLog.output))].
  + rewrite Pr[mu_sub]; smt(actual_new_wots_cases).
  have hc:=original_byte_wots_cut_bound A qr qs &m ha hr hs hqr hqs.
  have hb:=query_byte_wots_encoding_collision A qr qs &m hr hs hqr hqs.
  move: he; rewrite Pr[mu_or]; smt(ge0_mu).
qed.
