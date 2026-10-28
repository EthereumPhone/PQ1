(* Selected ordinary-FORS bound with both fixed suffix guesses retained.
   The variable budget is proved for the actual transformed wrapper session. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion.
require import RawWrapperCost WrapperSession WrapperByteSession WrapperPrefixBound ExposureLog ClientQueryLog.
require import LeafCommitmentHybrid LeafOpeningBound LeafBoundState PrivateTargetSampling.
require import TargetOracleSplit TargetPrivateBound TargetTableProjection TargetTableGames OriginalTargetBound.
require import WrapperTargetContext WrapperTargetLossless WrapperSelectedTargetBound.
require import WrapperLeafSessionCost OriginalLeafCandidateBound.

lemma wrapper_selected_leaf_candidate_bound
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -Independent,-Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,
    -TargetConfig,-PrivateTargetSample,-LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState})
  qr qs &m :
  (forall (O <: WrapperByteClientOracle {-A}), islossless O.hash => islossless O.sign => islossless A(O).run) =>
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[OriginalObservedPrivateGuess(TargetWrapperByteCandidates(A)).run() @ &m : res] <=
    ((wrapper_leaf_candidate_budget qr qs+2+12)%r*(1%r/2%r)^128).
proof.
  move=> ha hqr hqs hr hs.
  apply (original_observed_leaf_candidate_bound (TargetWrapperByteCandidates(A)) (wrapper_leaf_candidate_budget qr qs) 12 &m).
  + move=> O hh hd hl ho; exact (wrapper_target_candidates_lossless A O ha hh hd hl ho).
  + rewrite /wrapper_leaf_candidate_budget /wrapper_leaf_public_budget /signing_budget; smt().
  + smt().
  conseq (wrapper_leaf_byte_cost A qr qs hqr hqs); auto; smt().
qed.

lemma wrapper_selected_leaf_candidate_probability
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -Independent,-Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,
    -TargetConfig,-PrivateTargetSample,-LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState}) qr qs :
  (forall (O <: WrapperByteClientOracle {-A}), islossless O.hash => islossless O.sign => islossless A(O).run) =>
  0<=qr => 0<=qs =>
  phoare [SelectedWrapperTargetGuess(A).run : WrapperLimits.raw_cap=qr /\ WrapperLimits.sign_cap=qs ==> res] <=
    ((wrapper_leaf_candidate_budget qr qs+2+12)%r*(1%r/2%r)^128).
proof.
  move=> ha hqr hqs.
  have hb : phoare [OriginalObservedPrivateGuess(TargetWrapperByteCandidates(A)).run :
    WrapperLimits.raw_cap=qr /\ WrapperLimits.sign_cap=qs ==> res] <=
    ((wrapper_leaf_candidate_budget qr qs+2+12)%r*(1%r/2%r)^128).
  + bypr => &m [hr hs]; exact (wrapper_selected_leaf_candidate_bound A qr qs &m ha hqr hqs hr hs).
  proc; call hb; auto.
qed.
