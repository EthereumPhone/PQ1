require import AllCore List Distr FMap StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal RawKeygen ForsPrivateLeaves FullSession FullPrefix ByteSession.
require import KeygenPrefixes KeygenExhaustion ExposureLog ClientQueryLog ClientQueryDriver.
require import LeafCommitmentHybrid LeafOpeningBound PrivateTargetSampling.
require import TargetOracleSplit TargetTableProjection TargetByteView OriginalTargetEvent LeafCandidateUnion.
require import ForsCoordinateUniverse ActualForsOpening.
require import LeafTargetSessionCost OriginalByteTargetBound.
import RealOrder.
require import LeafForsOpeningBound.

lemma checked (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -Independent,-Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,
    -TargetConfig,-PrivateTargetSample,-LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState})
  qr qs &m :
  (forall (O <: ByteClientOracle {-A}), islossless O.hash => islossless O.sign => islossless A(O).run) =>
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : res /\
    actual_output_unreturned Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
      ExposureLog.entries ClientQueryLog.output] <=
    6442450944%r*((leaf_candidate_budget qr qs+2+12)%r*(1%r/2%r)^128).
proof.
  move=> ha hqr hqs hr hs; exact (original_byte_fors_candidate_bound A qr qs &m ha hqr hqs hr hs).
qed.
