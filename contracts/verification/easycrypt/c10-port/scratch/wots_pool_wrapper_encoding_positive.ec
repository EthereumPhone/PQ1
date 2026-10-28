require import WrapperWotsPoolNumericalBound.
(* Conditional-pool encoding refinement, retaining ordinary-FORS and exact coverage.
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
require import WrapperStirlingCoverage WrapperWotsEncodingBound WrapperSelectedEncodingCases.
require import WrapperRefinedNumericalBound WotsEncodingCharge WotsMemoOracle WotsAcceptedPrefix.
require import WrapperLeafOpeningBound AddressedWrapperNumericalBound.
require import AcceptedEncodingPool FullDigestPrefixSampling StirlingCoverageBound CanonicalCoverageBound.
import RealOrder.

op wrapper_wots_pool_independent_euf_charge qr qs =
  best_wrapper_addressed_node_charge qr qs +
  (wrapper_total_public_budget qr qs)%r*(1%r/2%r)^128 +
  best_wots_encoding_charge (wrapper_total_public_budget qr qs) (qr+10*qs+2) +
  632475648%r*((wrapper_wots_candidate_budget qr qs+88)%r*(1%r/2%r)^128) +
  best_wrapper_leaf_charge qr qs +
  stirling_coverage_charge (qr+3*qs+1).
op wrapper_wots_pool_physical_euf_charge qr qs = wrapper_wots_pool_independent_euf_charge qr qs +
  (wrapper_total_public_budget qr qs)%r*(1%r/2%r)^256.

lemma wrapper_query_byte_wots_pool_euf_bound
  (A <: WrapperByteClient {-Independent,-AddressedAudit,-Physical,-EncodingMemo,-EncodingSamples,-FullDigestSamples,-WrapperSession,-WrapperLimits,-KeygenInputs,
    -ExposureLog,-ClientQueryLog,-WrapperWotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,
    -CachedChain,-SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,-ChainRedaction,
    -ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,-ChainGuess,-ChainHybridPrefix,-HybridCachedChain,
    -Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,-TargetConfig,-PrivateTargetSample,
    -LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState,-ProjectedMemo,-ProjectedSamples,-HmsgMemo,
    -AcceptedSamples,-Hybrid,-WotsMemo,-WotsAcceptedSamples}) qr qs &m :
  (forall (V <: WrapperByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m : res] <= wrapper_wots_pool_independent_euf_charge qr qs.
proof. move=> ha hr hs hqr hqs; exact (WrapperWotsPoolNumericalBound.wrapper_query_byte_wots_pool_euf_bound A qr qs &m ha hr hs hqr hqs). qed.
