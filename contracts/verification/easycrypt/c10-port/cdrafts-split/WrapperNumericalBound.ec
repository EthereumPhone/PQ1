(* Classical ideal-oracle forgery bound for the actual initialized byte
   wrapper, including refusals, retries and freshness over released outputs.
   This is not a concrete hash-backend, hardware or QROM statement. *)
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
import RealOrder.

op wrapper_independent_euf_charge qr qs =
  ((wrapper_total_public_budget qr qs)*(wrapper_total_public_budget qr qs-1))%r/2%r*(1%r/2%r)^128 +
  (wrapper_total_public_budget qr qs)%r*(1%r/2%r)^128 +
  ((wrapper_total_public_budget qr qs)*(wrapper_total_public_budget qr qs-1))%r/2%r*(1%r/2%r)^129 +
  632475648%r*((wrapper_wots_candidate_budget qr qs+88)%r*(1%r/2%r)^128) +
  6442450944%r*((wrapper_total_public_budget qr qs+12)%r*(1%r/2%r)^128) +
  coverage_charge (qr+3*qs+1).
op wrapper_physical_euf_charge qr qs = wrapper_independent_euf_charge qr qs +
  (wrapper_total_public_budget qr qs)%r*(1%r/2%r)^256.

lemma wrapper_query_byte_euf_bound
  (A <: WrapperByteClient {-Independent,-Physical,-EncodingMemo,-EncodingSamples,-WrapperSession,-WrapperLimits,-KeygenInputs,
    -ExposureLog,-ClientQueryLog,-WrapperWotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,
    -CachedChain,-SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,-ChainRedaction,
    -ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,-ChainGuess,-ChainHybridPrefix,-HybridCachedChain,
    -Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,-TargetConfig,-PrivateTargetSample,
    -LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState,-ProjectedMemo,-ProjectedSamples,-HmsgMemo,
    -AcceptedSamples,-Hybrid}) qr qs &m :
  (forall (V <: WrapperByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m : res] <= wrapper_independent_euf_charge qr qs.
proof.
  move=> ha hr hs hqr hqs.
  have hc := wrapper_query_byte_public_collision A qr qs &m hr hs hqr hqs.
  have hz := wrapper_query_byte_public_zero A qr qs &m hr hs hqr hqs.
  have he := wrapper_query_byte_wots_encoding_collision A qr qs &m hr hs hqr hqs.
  have hw := wrapper_byte_wots_cut_bound A qr qs &m ha hr hs hqr hqs.
  have hf := wrapper_byte_fors_opening_bound A qr qs &m ha hr hs hqr hqs.
  have hp := wrapper_byte_coverage_bound A qr qs &m hr hs hqr hqs.
  have hbad : Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m :
    res /\ !numerical_output_cases Independent.rawhistory Independent.secrethistory
      WrapperSession.seed WrapperSession.root ExposureLog.entries ClientQueryLog.output res]=0%r.
  + byphoare (_ : WrapperLimits.sign_cap=qs ==> _) => //.
    hoare; conseq (wrapper_byte_numerical_cases A qs hs); smt().
  have hsplit : Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m : res] <=
    Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m :
      numerical_output_cases Independent.rawhistory Independent.secrethistory
        WrapperSession.seed WrapperSession.root ExposureLog.entries ClientQueryLog.output res].
  + rewrite Pr[mu_split (numerical_output_cases Independent.rawhistory Independent.secrethistory
      WrapperSession.seed WrapperSession.root ExposureLog.entries ClientQueryLog.output res)] hbad /=.
    rewrite Pr[mu_sub]; smt().
  move: hsplit; rewrite /numerical_output_cases Pr[mu_or] Pr[mu_or] Pr[mu_or] Pr[mu_or] Pr[mu_or] /wrapper_independent_euf_charge; smt(ge0_mu).
qed.

lemma wrapper_independent_byte_euf_bound
  (A <: WrapperByteClient {-Independent,-Physical,-EncodingMemo,-EncodingSamples,-WrapperSession,-WrapperLimits,-KeygenInputs,
    -ExposureLog,-ClientQueryLog,-WrapperWotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,
    -CachedChain,-SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,-ChainRedaction,
    -ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,-ChainGuess,-ChainHybridPrefix,-HybridCachedChain,
    -Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,-TargetConfig,-PrivateTargetSample,
    -LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState,-ProjectedMemo,-ProjectedSamples,-HmsgMemo,
    -AcceptedSamples,-Hybrid}) qr qs &m :
  (forall (V <: WrapperByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(WrapperByteContext(A)).run() @ &m : res] <= wrapper_independent_euf_charge qr qs.
proof.
  move=> ha hr hs hqr hqs.
  rewrite (wrapper_byte_query_probability A &m).
  exact (wrapper_query_byte_euf_bound A qr qs &m ha hr hs hqr hqs).
qed.

lemma wrapper_physical_byte_euf_bound
  (A <: WrapperByteClient {-Independent,-Physical,-EncodingMemo,-EncodingSamples,-WrapperSession,-WrapperLimits,-KeygenInputs,
    -ExposureLog,-ClientQueryLog,-WrapperWotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,
    -CachedChain,-SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,-ChainRedaction,
    -ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,-ChainGuess,-ChainHybridPrefix,-HybridCachedChain,
    -Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,-TargetConfig,-PrivateTargetSample,
    -LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState,-ProjectedMemo,-ProjectedSamples,-HmsgMemo,
    -AcceptedSamples,-Hybrid}) qr qs &m :
  (forall (V <: WrapperByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[RealGame(WrapperByteContext(A)).run() @ &m : res] <= wrapper_physical_euf_charge qr qs.
proof.
  move=> ha hr hs hqr hqs.
  have hh := wrapper_byte_physical_to_independent A qr qs &m ha hr hs hqr hqs.
  have hb := wrapper_query_byte_euf_bound A qr qs &m ha hr hs hqr hqs.
  rewrite (wrapper_byte_query_probability A &m) in hh.
  rewrite /wrapper_physical_euf_charge; smt().
qed.
