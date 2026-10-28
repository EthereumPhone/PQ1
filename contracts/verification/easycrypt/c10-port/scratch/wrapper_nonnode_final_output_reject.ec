require import AllCore List Distr FMap.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion.
require import RawWrapperCost WrapperSession WrapperByteSession WrapperPrefixBound ExposureLog ClientQueryLog.
require import LeafCommitmentHybrid LeafOpeningBound LeafBoundState PrivateTargetSampling.
require import TargetOracleSplit TargetPrivateBound TargetTableProjection TargetTableGames OriginalTargetBound.
require import WrapperTargetContext WrapperTargetLossless WrapperSelectedTargetBound.
require import WrapperLeafSessionCost OriginalLeafCandidateBound.
require import WrapperSelectedLeafBound.
lemma checked
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -Independent,-Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,
    -TargetConfig,-PrivateTargetSample,-LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState})
  qr qs &m :
  (forall (O <: WrapperByteClientOracle {-A}), islossless O.hash => islossless O.sign => islossless A(O).run) =>
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[OriginalObservedPrivateGuess(TargetWrapperByteCandidates(A)).run() @ &m : res] <=
    ((wrapper_leaf_candidate_budget qr qs+2)%r*(1%r/2%r)^128).
proof. exact (wrapper_selected_leaf_candidate_bound A qr qs &m). qed.
