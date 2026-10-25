require import WrapperNumericalBound.
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
  0%r*(1%r/2%r)^256.


