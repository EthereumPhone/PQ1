(* Numerical classical ideal-oracle EUF bound for the initialized byte game.
   This is a conservative reduction bound, not a concrete SHA-256 or QROM claim. *)
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
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal RawKeygen ForsPrivateLeaves FullSession FullPrefix ByteSession.
require import KeygenPrefixes KeygenExhaustion ExposureLog ClientQueryLog ClientQueryDriver.
require import LeafCommitmentHybrid LeafOpeningBound PrivateTargetSampling.
require import TargetOracleSplit TargetTableProjection TargetByteView OriginalTargetEvent OriginalCandidateUnion.
require import ForsCoordinateUniverse ActualForsOpening.
require import OriginalWotsCutBound OriginalForsOpeningBound OriginalCoverageBound.
require import ProjectedBirthday ProjectedMemoOracle HmsgMemoOracle AcceptedPrefixSampling.
require import MemoNodeCollision PublicNodeZero QueryPublicCharges CoveredOutputPool PoolCoverageBound NumericalByteCases ByteBound PrefixGames.
import RealOrder.

op independent_euf_charge qr qs =
  ((full_public_budget qr qs)*(full_public_budget qr qs-1))%r/2%r*(1%r/2%r)^128 +
  (full_public_budget qr qs)%r*(1%r/2%r)^128 +
  ((full_public_budget qr qs)*(full_public_budget qr qs-1))%r/2%r*(1%r/2%r)^129 +
  632475648%r*((full_public_budget qr qs+86)%r*(1%r/2%r)^128) +
  6442450944%r*((full_public_budget qr qs+12)%r*(1%r/2%r)^128) +
  coverage_charge (qr+qs+1).
op physical_euf_charge qr qs = independent_euf_charge qr qs +
  (full_public_budget qr qs)%r*(1%r/2%r)^256.

lemma original_byte_euf_bound
  (A <: ByteClient {-Independent,-Physical,-EncodingMemo,-EncodingSamples,-FullSession,-FullLimits,-KeygenInputs,
    -ExposureLog,-ClientQueryLog,-WotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,
    -CachedChain,-SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,-ChainRedaction,
    -ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,-ChainGuess,-ChainHybridPrefix,-HybridCachedChain,
    -Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,-TargetConfig,-PrivateTargetSample,
    -LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState,-ProjectedMemo,-ProjectedSamples,-HmsgMemo,
    -AcceptedSamples,-Hybrid}) qr qs &m :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : res] <= independent_euf_charge qr qs.
proof.
  move=> ha hr hs hqr hqs.
  have hc := query_byte_public_collision A qr qs &m hr hs hqr hqs.
  have hz := query_byte_public_zero A qr qs &m hr hs hqr hqs.
  have he := query_byte_wots_encoding_collision A qr qs &m hr hs hqr hqs.
  have hw := original_byte_wots_cut_bound A qr qs &m ha hr hs hqr hqs.
  have hf := original_byte_fors_opening_bound A qr qs &m ha hr hs hqr hqs.
  have hp := original_byte_coverage_bound A qr qs &m hr hs hqr hqs.
  have hbad : Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m :
    res /\ !numerical_output_cases Independent.rawhistory Independent.secrethistory
      FullSession.seed FullSession.root ExposureLog.entries ClientQueryLog.output res]=0%r.
  + byphoare (_ : FullLimits.sign_cap=qs ==> _) => //.
    hoare; conseq (query_byte_numerical_cases A qs hs); smt().
  have hsplit : Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : res] <=
    Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m :
      numerical_output_cases Independent.rawhistory Independent.secrethistory
        FullSession.seed FullSession.root ExposureLog.entries ClientQueryLog.output res].
  + rewrite Pr[mu_split (numerical_output_cases Independent.rawhistory Independent.secrethistory
      FullSession.seed FullSession.root ExposureLog.entries ClientQueryLog.output res)] hbad /=.
    rewrite Pr[mu_sub]; smt().
  move: hsplit; rewrite /numerical_output_cases Pr[mu_or] Pr[mu_or] Pr[mu_or] Pr[mu_or] Pr[mu_or] /independent_euf_charge; smt(ge0_mu).
qed.

lemma physical_byte_euf_bound
  (A <: ByteClient {-Independent,-Physical,-EncodingMemo,-EncodingSamples,-FullSession,-FullLimits,-KeygenInputs,
    -ExposureLog,-ClientQueryLog,-WotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,
    -CachedChain,-SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,-ChainRedaction,
    -ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,-ChainGuess,-ChainHybridPrefix,-HybridCachedChain,
    -Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,-TargetConfig,-PrivateTargetSample,
    -LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState,-ProjectedMemo,-ProjectedSamples,-HmsgMemo,
    -AcceptedSamples,-Hybrid}) qr qs &m :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[RealGame(ByteContext(A)).run() @ &m : res] <= physical_euf_charge qr qs.
proof.
  move=> ha hr hs hqr hqs.
  have hh := byte_physical_to_independent A qr qs &m ha hr hs hqr hqs.
  have hb := original_byte_euf_bound A qr qs &m ha hr hs hqr hqs.
  rewrite (query_byte_success_projection A &m) in hh.
  rewrite /physical_euf_charge; smt().
qed.
