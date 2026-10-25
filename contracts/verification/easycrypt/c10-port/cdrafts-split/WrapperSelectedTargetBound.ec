(* The selected ordinary-FORS hiding bound, with the actual transformed
   wrapper's query budget and termination obligations discharged. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion.
require import RawWrapperCost WrapperSession WrapperByteSession WrapperPrefixBound ExposureLog ClientQueryLog.
require import LeafCommitmentHybrid LeafOpeningBound LeafBoundState PrivateTargetSampling.
require import TargetOracleSplit TargetPrivateBound TargetTableProjection TargetTableGames OriginalTargetBound.
require import WrapperTargetContext WrapperTargetLossless WrapperTargetSessionCost.

lemma wrapper_selected_target_bound
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -Independent,-Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,
    -TargetConfig,-PrivateTargetSample,-LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState})
  qr qs &m :
  (forall (O <: WrapperByteClientOracle {-A}), islossless O.hash => islossless O.sign => islossless A(O).run) =>
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[OriginalObservedPrivateGuess(TargetWrapperByteCandidates(A)).run() @ &m : res] <=
    ((wrapper_total_public_budget qr qs+12)%r*(1%r/2%r)^128).
proof.
  move=> ha hqr hqs hr hs.
  apply (original_observed_private_guess_bound (TargetWrapperByteCandidates(A)) (wrapper_total_public_budget qr qs) 12 &m).
  + move=> O hh hd hl ho; exact (wrapper_target_candidates_lossless A O ha hh hd hl ho).
  + rewrite /wrapper_total_public_budget /wrapper_public_budget /signing_budget; smt().
  + smt().
  conseq (wrapper_target_byte_cost A qr qs hqr hqs); auto; smt().
qed.

module SelectedWrapperTargetGuess (A : WrapperByteClient) = {
  proc run(target : raw_input) : bool = {
    var result; TargetConfig.input <- target;
    result <@ OriginalObservedPrivateGuess(TargetWrapperByteCandidates(A)).run(); return result;
  }
}.

lemma wrapper_selected_target_probability
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -Independent,-Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,
    -TargetConfig,-PrivateTargetSample,-LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState}) qr qs :
  (forall (O <: WrapperByteClientOracle {-A}), islossless O.hash => islossless O.sign => islossless A(O).run) =>
  0<=qr => 0<=qs =>
  phoare [SelectedWrapperTargetGuess(A).run : WrapperLimits.raw_cap=qr /\ WrapperLimits.sign_cap=qs ==> res] <=
    ((wrapper_total_public_budget qr qs+12)%r*(1%r/2%r)^128).
proof.
  move=> ha hqr hqs.
  have hb : phoare [OriginalObservedPrivateGuess(TargetWrapperByteCandidates(A)).run :
    WrapperLimits.raw_cap=qr /\ WrapperLimits.sign_cap=qs ==> res] <=
    ((wrapper_total_public_budget qr qs+12)%r*(1%r/2%r)^128).
  + bypr => &m [hr hs]; exact (wrapper_selected_target_bound A qr qs &m ha hqr hqs hr hs).
  proc; call hb; auto.
qed.
