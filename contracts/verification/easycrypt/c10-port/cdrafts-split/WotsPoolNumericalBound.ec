(* Accepted-WOTS-pool refinement of the same initialized byte-game EUF bound.
   Every other term is retained. This remains a classical ideal-oracle
   reduction bound, not a concrete SHA-256, QROM, or attack-cost claim. *)
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
require import AcceptedEncodingNumericalBound DomainQueryCount DomainSessionCost DomainNodeCases DomainMemoOracle ByteDomainCollision.
require import DomainNumericalBound WotsCandidateNumericalBound ForsCandidateNumericalBound.
require import LeafTargetSessionCost LeafForsOpeningBound ChainVariableSessionCost WotsCandidateCutBound.
require import SelectedEncodingCases AddressedByteCollision AddressedAudit.
require import AddressedNumericalBound WotsEncodingCharge WotsEncodingBound WotsMemoOracle WotsAcceptedPrefix.
import RealOrder.

op wots_pool_independent_euf_charge qr qs =
  best_addressed_node_charge qr qs +
  (full_public_budget qr qs)%r*(1%r/2%r)^128 +
  best_wots_encoding_charge (full_public_budget qr qs) (qr+4*qs+2) +
  wots_candidate_cut_charge qr qs +
  fors_candidate_opening_charge qr qs +
  stirling_coverage_charge (qr+qs+1).
op wots_pool_physical_euf_charge qr qs = wots_pool_independent_euf_charge qr qs +
  (full_public_budget qr qs)%r*(1%r/2%r)^256.

lemma original_byte_wots_pool_euf_bound
  (A <: ByteClient {-Independent,-AddressedAudit,-Physical,-EncodingMemo,-EncodingSamples,-FullSession,-FullLimits,-KeygenInputs,
    -ExposureLog,-ClientQueryLog,-WotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,
    -CachedChain,-SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,-ChainRedaction,
    -ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,-ChainGuess,-ChainHybridPrefix,-HybridCachedChain,
    -Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,-TargetConfig,-PrivateTargetSample,
    -LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState,-ProjectedMemo,-ProjectedSamples,-HmsgMemo,
    -AcceptedSamples,-FullDigestSamples,-DomainMemo,-Hybrid,-WotsMemo,-WotsAcceptedSamples}) qr qs &m :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : res] <= wots_pool_independent_euf_charge qr qs.
proof.
  move=> ha hr hs hqr hqs.
  have hc := query_byte_addressed_collision_best A qr qs &m hr hs hqr hqs.
  have hz := query_byte_public_zero A qr qs &m hr hs hqr hqs.
  have he := original_byte_best_wots_encoding_bound A qr qs &m hr hs hqr hqs.
  have hw := original_byte_wots_cut_bound A qr qs &m ha hr hs hqr hqs.
  have hwc := original_byte_wots_candidate_cut_bound A qr qs &m ha hr hs hqr hqs.
  have hf := original_byte_fors_opening_bound A qr qs &m ha hr hs hqr hqs.
  have hfc := original_byte_fors_candidate_bound A qr qs &m ha hr hs hqr hqs.
  have hp := original_byte_stirling_coverage_bound A qr qs &m hr hs hqr hqs.
  have hbad : Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m :
    res /\ !selected_encoding_output_cases Independent.rawhistory Independent.secrethistory
      FullSession.seed FullSession.root ExposureLog.entries ClientQueryLog.output res]=0%r.
  + byphoare (_ : FullLimits.sign_cap=qs ==> _) => //.
    hoare; conseq (query_byte_selected_encoding_cases A qs hs); smt().
  have hsplit : Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : res] <=
    Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m :
      selected_encoding_output_cases Independent.rawhistory Independent.secrethistory
        FullSession.seed FullSession.root ExposureLog.entries ClientQueryLog.output res].
  + rewrite Pr[mu_split (selected_encoding_output_cases Independent.rawhistory Independent.secrethistory
      FullSession.seed FullSession.root ExposureLog.entries ClientQueryLog.output res)] hbad /=.
    rewrite Pr[mu_sub]; smt().
  move: hsplit; rewrite /selected_encoding_output_cases Pr[mu_or] Pr[mu_or] Pr[mu_or] Pr[mu_or] Pr[mu_or] /wots_pool_independent_euf_charge /fors_candidate_opening_charge /wots_candidate_cut_charge; smt(ge0_mu).
qed.

lemma physical_byte_wots_pool_euf_bound
  (A <: ByteClient {-Independent,-AddressedAudit,-Physical,-EncodingMemo,-EncodingSamples,-FullSession,-FullLimits,-KeygenInputs,
    -ExposureLog,-ClientQueryLog,-WotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,
    -CachedChain,-SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,-ChainRedaction,
    -ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,-ChainGuess,-ChainHybridPrefix,-HybridCachedChain,
    -Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,-TargetConfig,-PrivateTargetSample,
    -LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState,-ProjectedMemo,-ProjectedSamples,-HmsgMemo,
    -AcceptedSamples,-FullDigestSamples,-DomainMemo,-Hybrid,-WotsMemo,-WotsAcceptedSamples}) qr qs &m :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[RealGame(ByteContext(A)).run() @ &m : res] <= wots_pool_physical_euf_charge qr qs.
proof.
  move=> ha hr hs hqr hqs.
  have hh := byte_physical_to_independent A qr qs &m ha hr hs hqr hqs.
  have hb := original_byte_wots_pool_euf_bound A qr qs &m ha hr hs hqr hqs.
  rewrite (query_byte_success_projection A &m) in hh.
  rewrite /wots_pool_physical_euf_charge; smt().
qed.

lemma wots_pool_independent_charge_tighter qr qs :
  wots_pool_independent_euf_charge qr qs<=addressed_node_independent_euf_charge qr qs.
proof.
  have h := best_wots_encoding_charge_retains (full_public_budget qr qs) (qr+4*qs+2).
  rewrite /wots_pool_independent_euf_charge /addressed_node_independent_euf_charge; smt().
qed.

lemma wots_pool_physical_charge_tighter qr qs :
  wots_pool_physical_euf_charge qr qs<=addressed_node_physical_euf_charge qr qs.
proof.
  rewrite /wots_pool_physical_euf_charge /addressed_node_physical_euf_charge;
    smt(wots_pool_independent_charge_tighter).
qed.
