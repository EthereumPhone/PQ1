(* Combined accepted-encoding, ordinary-FORS and exact coverage refinement.
   The same initialized wrapper adversary retains every cap, refusal and retry.
   The addressed-node, zero, WOTS-chain and physical-prefix charges remain. *)
require import AllCore List Distr FMap StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal PrefixGames KeygenPrefixes KeygenExhaustion RawKeygen.
require import WrapperSession WrapperByteSession WrapperQueryDriver WrapperPrefixBound.
require import ExposureLog ClientQueryLog ChainValueView ChainStageSampling CachedChainOracle.
require import PublicTargetSampling PrivateValueSampling ChainVectorInstall DualDigestSampling RedactedChainOracle ChainPublicHybrid.
require import WrapperSelectedChainSampling WrapperOriginalWotsCutBound WrapperWotsCandidateBudget.
require import WrapperForsOpeningBound WrapperCoverageBound WrapperPublicCharges WrapperActualPartition.
require import EncodingMemoOracle EncodingCollisionState EncodingBirthday ProjectedMemoOracle ProjectedBirthday.
require import PrivateTargetSampling TargetOracleSplit TargetTableProjection TargetByteView OriginalTargetEvent.
require import LeafCommitmentHybrid LeafOpeningBound HmsgMemoOracle AcceptedPrefixSampling.
require import MemoNodeCollision PublicNodeZero ByteEncodingCharge ActualWotsCut ActualForsOpening CoveredOutputPool.
require import PoolCoverageBound NumericalByteCases.
require import AddressedAudit AddressedWrapperByteCollision AddressedWrapperActualPartition WrapperNumericalBound.
require import WrapperStirlingCoverage WrapperAcceptedEncodingCharge WrapperAcceptedEncodingCases.
require import WrapperLeafOpeningBound AddressedWrapperNumericalBound.
require import AcceptedEncodingPool FullDigestPrefixSampling StirlingCoverageBound CanonicalCoverageBound.
import RealOrder.

op wrapper_refined_independent_euf_charge qr qs =
  best_wrapper_addressed_node_charge qr qs +
  (wrapper_total_public_budget qr qs)%r*(1%r/2%r)^128 +
  accepted_encoding_charge (wrapper_total_public_budget qr qs) +
  632475648%r*((wrapper_wots_candidate_budget qr qs+88)%r*(1%r/2%r)^128) +
  best_wrapper_leaf_charge qr qs +
  stirling_coverage_charge (qr+3*qs+1).
op wrapper_refined_physical_euf_charge qr qs = wrapper_refined_independent_euf_charge qr qs +
  (wrapper_total_public_budget qr qs)%r*(1%r/2%r)^256.

lemma wrapper_query_byte_refined_euf_bound
  (A <: WrapperByteClient {-Independent,-AddressedAudit,-Physical,-EncodingMemo,-EncodingSamples,-FullDigestSamples,-WrapperSession,-WrapperLimits,-KeygenInputs,
    -ExposureLog,-ClientQueryLog,-WrapperWotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,
    -CachedChain,-SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,-ChainRedaction,
    -ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,-ChainGuess,-ChainHybridPrefix,-HybridCachedChain,
    -Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,-TargetConfig,-PrivateTargetSample,
    -LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState,-ProjectedMemo,-ProjectedSamples,-HmsgMemo,
    -AcceptedSamples,-Hybrid}) qr qs &m :
  (forall (V <: WrapperByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m : res] <= wrapper_refined_independent_euf_charge qr qs.
proof.
  move=> ha hr hs hqr hqs.
  have hc := wrapper_query_byte_addressed_collision_best A qr qs &m hr hs hqr hqs.
  have hz := wrapper_query_byte_public_zero A qr qs &m hr hs hqr hqs.
  have he := wrapper_query_byte_accepted_encoding_collision A qr qs &m hr hs hqr hqs.
  have hw := wrapper_byte_wots_cut_bound A qr qs &m ha hr hs hqr hqs.
  have hf := wrapper_byte_fors_opening_best A qr qs &m ha hr hs hqr hqs.
  have hp := wrapper_byte_stirling_coverage_bound A qr qs &m hr hs hqr hqs.
  have hbad : Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m :
    res /\ !wrapper_accepted_encoding_output_cases Independent.rawhistory Independent.secrethistory
      WrapperSession.seed WrapperSession.root ExposureLog.entries ClientQueryLog.output res]=0%r.
  + byphoare (_ : WrapperLimits.sign_cap=qs ==> _) => //.
    hoare; conseq (wrapper_byte_accepted_encoding_cases A qs hs); smt().
  have hsplit : Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m : res] <=
    Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m :
      wrapper_accepted_encoding_output_cases Independent.rawhistory Independent.secrethistory
        WrapperSession.seed WrapperSession.root ExposureLog.entries ClientQueryLog.output res].
  + rewrite Pr[mu_split (wrapper_accepted_encoding_output_cases Independent.rawhistory Independent.secrethistory
      WrapperSession.seed WrapperSession.root ExposureLog.entries ClientQueryLog.output res)] hbad /=.
    rewrite Pr[mu_sub]; smt().
  move: hsplit; rewrite /wrapper_accepted_encoding_output_cases Pr[mu_or] Pr[mu_or] Pr[mu_or] Pr[mu_or] Pr[mu_or] /wrapper_refined_independent_euf_charge; smt(ge0_mu).
qed.

lemma wrapper_independent_byte_refined_euf_bound
  (A <: WrapperByteClient {-Independent,-AddressedAudit,-Physical,-EncodingMemo,-EncodingSamples,-FullDigestSamples,-WrapperSession,-WrapperLimits,-KeygenInputs,
    -ExposureLog,-ClientQueryLog,-WrapperWotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,
    -CachedChain,-SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,-ChainRedaction,
    -ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,-ChainGuess,-ChainHybridPrefix,-HybridCachedChain,
    -Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,-TargetConfig,-PrivateTargetSample,
    -LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState,-ProjectedMemo,-ProjectedSamples,-HmsgMemo,
    -AcceptedSamples,-Hybrid}) qr qs &m :
  (forall (V <: WrapperByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(WrapperByteContext(A)).run() @ &m : res] <= wrapper_refined_independent_euf_charge qr qs.
proof.
  move=> ha hr hs hqr hqs.
  rewrite (wrapper_byte_query_probability A &m).
  exact (wrapper_query_byte_refined_euf_bound A qr qs &m ha hr hs hqr hqs).
qed.

lemma wrapper_physical_byte_refined_euf_bound
  (A <: WrapperByteClient {-Independent,-AddressedAudit,-Physical,-EncodingMemo,-EncodingSamples,-FullDigestSamples,-WrapperSession,-WrapperLimits,-KeygenInputs,
    -ExposureLog,-ClientQueryLog,-WrapperWotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,
    -CachedChain,-SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,-ChainRedaction,
    -ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,-ChainGuess,-ChainHybridPrefix,-HybridCachedChain,
    -Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,-TargetConfig,-PrivateTargetSample,
    -LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState,-ProjectedMemo,-ProjectedSamples,-HmsgMemo,
    -AcceptedSamples,-Hybrid}) qr qs &m :
  (forall (V <: WrapperByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[RealGame(WrapperByteContext(A)).run() @ &m : res] <= wrapper_refined_physical_euf_charge qr qs.
proof.
  move=> ha hr hs hqr hqs.
  have hh := wrapper_byte_physical_to_independent A qr qs &m ha hr hs hqr hqs.
  have hb := wrapper_query_byte_refined_euf_bound A qr qs &m ha hr hs hqr hqs.
  rewrite (wrapper_byte_query_probability A &m) in hh.
  rewrite /wrapper_refined_physical_euf_charge; smt().
qed.

lemma wrapper_refined_independent_charge_tighter qr qs :
  0<=qr => 0<=qs =>
  wrapper_refined_independent_euf_charge qr qs<=wrapper_addressed_independent_euf_charge qr qs.
proof.
  move=> hr hs.
  have hq : 0<=wrapper_total_public_budget qr qs
    by rewrite /wrapper_total_public_budget /wrapper_public_budget /signing_budget; smt().
  have he := accepted_encoding_charge_tighter (wrapper_total_public_budget qr qs) hq.
  have hf : best_wrapper_leaf_charge qr qs<=retained_wrapper_fors_charge qr qs
    by rewrite /best_wrapper_leaf_charge; smt().
  have hc := stirling_coverage_charge_tighter (qr+3*qs+1) _; first smt().
  have hp := canonical_coverage_charge_tighter (qr+3*qs+1) _; first smt().
  move: hf; rewrite /retained_wrapper_fors_charge /wrapper_refined_independent_euf_charge
    /wrapper_addressed_independent_euf_charge; smt().
qed.

lemma wrapper_refined_physical_charge_tighter qr qs :
  0<=qr => 0<=qs =>
  wrapper_refined_physical_euf_charge qr qs<=wrapper_addressed_physical_euf_charge qr qs.
proof.
  move=> hr hs; have h := wrapper_refined_independent_charge_tighter qr qs hr hs.
  rewrite /wrapper_refined_physical_euf_charge /wrapper_addressed_physical_euf_charge; smt().
qed.
