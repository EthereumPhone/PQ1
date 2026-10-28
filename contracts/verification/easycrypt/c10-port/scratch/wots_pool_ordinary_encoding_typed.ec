require import WotsPoolNumericalBound.
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
  0%r +
  wots_candidate_cut_charge qr qs +
  fors_candidate_opening_charge qr qs +
  stirling_coverage_charge (qr+qs+1).
op wots_pool_physical_euf_charge qr qs = wots_pool_independent_euf_charge qr qs +
  (full_public_budget qr qs)%r*(1%r/2%r)^256.
