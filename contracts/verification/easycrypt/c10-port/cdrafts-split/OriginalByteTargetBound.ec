(* The byte-client selected bound with its transformed resource premise discharged. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid FullSession FullPrefix ByteSession.
require import KeygenPrefixes KeygenExhaustion ExposureLog ClientQueryLog.
require import LeafCommitmentHybrid LeafOpeningBound LeafBoundState PrivateTargetSampling.
require import TargetOracleSplit TargetPrivateBound TargetTableProjection TargetTableGames OriginalTargetBound.
require import TargetByteView TargetByteLossless TargetAdapterCost TargetSessionCost.

lemma original_byte_target_bound
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -Independent,-Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,
    -TargetConfig,-PrivateTargetSample,-LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState})
  qr qs &m :
  (forall (O <: ByteClientOracle {-A}), islossless O.hash => islossless O.sign => islossless A(O).run) =>
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[OriginalObservedPrivateGuess(TargetByteCandidates(A)).run() @ &m : res] <=
    ((full_public_budget qr qs+12)%r*(1%r/2%r)^128).
proof.
  move=> ha hqr hqs hr hs.
  apply (original_observed_private_guess_bound (TargetByteCandidates(A)) (full_public_budget qr qs) 12 &m).
  + move=> O hh hd hl ho; exact (target_byte_candidates_lossless A O ha hh hd hl ho).
  + rewrite /full_public_budget /signing_budget; smt().
  + smt().
  conseq (target_byte_public_cost A qr qs hqr hqs); auto; smt().
qed.

module SelectedByteTargetGuess (A : ByteClient) = {
  proc run(target : raw_input) : bool = {
    var result; TargetConfig.input <- target;
    result <@ OriginalObservedPrivateGuess(TargetByteCandidates(A)).run(); return result;
  }
}.
lemma selected_byte_target_bound
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -Independent,-Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,
    -TargetConfig,-PrivateTargetSample,-LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState})
  qr qs :
  (forall (O <: ByteClientOracle {-A}), islossless O.hash => islossless O.sign => islossless A(O).run) =>
  0<=qr => 0<=qs =>
  phoare [SelectedByteTargetGuess(A).run : FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs ==> res] <=
    ((full_public_budget qr qs+12)%r*(1%r/2%r)^128).
proof.
  move=> ha hqr hqs.
  have hb : phoare [OriginalObservedPrivateGuess(TargetByteCandidates(A)).run :
    FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs ==> res] <=
    ((full_public_budget qr qs+12)%r*(1%r/2%r)^128).
  + bypr => &m [hr hs]; exact (original_byte_target_bound A qr qs &m ha hqr hqs hr hs).
  proc; call hb; auto.
qed.
