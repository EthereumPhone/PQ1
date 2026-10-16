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
require import StirlingCoverageBound OriginalStirlingCoverage StirlingNumericalBound.
require import WotsAcceptanceMass AcceptedEncodingPool AcceptedEncodingCases AcceptedWotsCollision ByteAcceptedEncodingCharge FullDigestPrefixSampling.
require import C10Counter.
require import AcceptedEncodingNumericalBound DomainQueryCount DomainSessionCost DomainNodeCases DomainMemoOracle ByteDomainCollision DomainNumericalBound.
require import LeafTargetSessionCost LeafForsOpeningBound.
require import ForsCandidateNumericalBound ChainVariableSessionCost WotsCandidateCutBound.
import RealOrder.

op wots_candidate_cut_charge qr qs =
  let previous = 632475648%r*((full_public_budget qr qs+86)%r*(1%r/2%r)^128) in
  let refined = 632475648%r*((chain_candidate_budget qr qs+86+2)%r*(1%r/2%r)^128) in
  if previous <= refined then previous else refined.

op wots_candidate_independent_euf_charge qr qs =
  ((node_public_budget qr qs)*(node_public_budget qr qs-1))%r/2%r*(1%r/2%r)^128 +
  (full_public_budget qr qs)%r*(1%r/2%r)^128 +
  accepted_encoding_charge (full_public_budget qr qs) +
  wots_candidate_cut_charge qr qs +
  fors_candidate_opening_charge qr qs +
  stirling_coverage_charge (qr+qs+1).
op wots_candidate_physical_euf_charge qr qs = wots_candidate_independent_euf_charge qr qs +
  (full_public_budget qr qs)%r*(1%r/2%r)^256.

lemma original_byte_wots_candidate_euf_bound
  (A <: ByteClient {-Independent,-Physical,-EncodingMemo,-EncodingSamples,-FullSession,-FullLimits,-KeygenInputs,
    -ExposureLog,-ClientQueryLog,-WotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,
    -CachedChain,-SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,-ChainRedaction,
    -ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,-ChainGuess,-ChainHybridPrefix,-HybridCachedChain,
    -Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,-TargetConfig,-PrivateTargetSample,
    -LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState,-ProjectedMemo,-ProjectedSamples,-HmsgMemo,
    -AcceptedSamples,-FullDigestSamples,-DomainMemo,-Hybrid}) qr qs &m :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : res] <= wots_candidate_independent_euf_charge qr qs.
proof.
  move=> ha hr hs hqr hqs.
  have hc := query_byte_domain_collision A qr qs &m hr hs hqr hqs.
  have hz := query_byte_public_zero A qr qs &m hr hs hqr hqs.
  have he := query_byte_accepted_encoding_collision A qr qs &m hr hs hqr hqs.
  have hw := original_byte_wots_cut_bound A qr qs &m ha hr hs hqr hqs.
  have hwc := original_byte_wots_candidate_cut_bound A qr qs &m ha hr hs hqr hqs.
  have hf := original_byte_fors_opening_bound A qr qs &m ha hr hs hqr hqs.
  have hfc := original_byte_fors_candidate_bound A qr qs &m ha hr hs hqr hqs.
  have hp := original_byte_stirling_coverage_bound A qr qs &m hr hs hqr hqs.
  have hbad : Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m :
    res /\ !domain_node_output_cases Independent.rawhistory Independent.secrethistory
      FullSession.seed FullSession.root ExposureLog.entries ClientQueryLog.output res]=0%r.
  + byphoare (_ : FullLimits.sign_cap=qs ==> _) => //.
    hoare; conseq (query_byte_domain_node_cases A qs hs); smt().
  have hsplit : Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : res] <=
    Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m :
      domain_node_output_cases Independent.rawhistory Independent.secrethistory
        FullSession.seed FullSession.root ExposureLog.entries ClientQueryLog.output res].
  + rewrite Pr[mu_split (domain_node_output_cases Independent.rawhistory Independent.secrethistory
      FullSession.seed FullSession.root ExposureLog.entries ClientQueryLog.output res)] hbad /=.
    rewrite Pr[mu_sub]; smt().
  move: hsplit; rewrite /domain_node_output_cases Pr[mu_or] Pr[mu_or] Pr[mu_or] Pr[mu_or] Pr[mu_or] /wots_candidate_independent_euf_charge /fors_candidate_opening_charge /wots_candidate_cut_charge; smt(ge0_mu).
qed.

lemma physical_byte_wots_candidate_euf_bound
  (A <: ByteClient {-Independent,-Physical,-EncodingMemo,-EncodingSamples,-FullSession,-FullLimits,-KeygenInputs,
    -ExposureLog,-ClientQueryLog,-WotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,
    -CachedChain,-SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,-ChainRedaction,
    -ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,-ChainGuess,-ChainHybridPrefix,-HybridCachedChain,
    -Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,-TargetConfig,-PrivateTargetSample,
    -LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState,-ProjectedMemo,-ProjectedSamples,-HmsgMemo,
    -AcceptedSamples,-FullDigestSamples,-DomainMemo,-Hybrid}) qr qs &m :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[RealGame(ByteContext(A)).run() @ &m : res] <= wots_candidate_physical_euf_charge qr qs.
proof.
  move=> ha hr hs hqr hqs.
  have hh := byte_physical_to_independent A qr qs &m ha hr hs hqr hqs.
  have hb := original_byte_wots_candidate_euf_bound A qr qs &m ha hr hs hqr hqs.
  rewrite (query_byte_success_projection A &m) in hh.
  rewrite /wots_candidate_physical_euf_charge; smt().
qed.

lemma wots_candidate_independent_charge_tighter qr qs :
  wots_candidate_independent_euf_charge qr qs <= fors_candidate_independent_euf_charge qr qs.
proof.
  rewrite /wots_candidate_independent_euf_charge /fors_candidate_independent_euf_charge
    /fors_candidate_opening_charge /wots_candidate_cut_charge; smt().
qed.

lemma wots_candidate_physical_charge_tighter qr qs :
  wots_candidate_physical_euf_charge qr qs <= fors_candidate_physical_euf_charge qr qs.
proof.
  have h := wots_candidate_independent_charge_tighter qr qs.
  rewrite /wots_candidate_physical_euf_charge /fors_candidate_physical_euf_charge; smt().
qed.
