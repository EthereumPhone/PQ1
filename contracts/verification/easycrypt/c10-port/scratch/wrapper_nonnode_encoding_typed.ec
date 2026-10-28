require import WrapperRefinedNumericalBound.
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
  0%r +
  632475648%r*((wrapper_wots_candidate_budget qr qs+88)%r*(1%r/2%r)^128) +
  best_wrapper_leaf_charge qr qs +
  stirling_coverage_charge (qr+3*qs+1).
op wrapper_refined_physical_euf_charge qr qs = wrapper_refined_independent_euf_charge qr qs +
  (wrapper_total_public_budget qr qs)%r*(1%r/2%r)^256.
