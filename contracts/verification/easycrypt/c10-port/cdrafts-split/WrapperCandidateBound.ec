(* A fixed-coordinate charge on the original initialized wrapper candidate game. *)
require import AllCore List Distr FMap StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal RawKeygen ForsPrivateLeaves.
require import WrapperSession WrapperByteSession WrapperPrefixBound WrapperQueryDriver.
require import KeygenPrefixes KeygenExhaustion ExposureLog ClientQueryLog ReturnedPrivateInputs.
require import LeafCommitmentHybrid LeafOpeningBound PrivateTargetSampling.
require import TargetOracleSplit TargetTableProjection TargetTableGames TargetByteView OriginalTargetEvent.
require import WrapperSelectedTargetBound WrapperCandidateProjection WrapperTargetEvent.
import RealOrder.

lemma wrapper_unreturned_coordinate_bound
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -Independent,-Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,
    -TargetConfig,-PrivateTargetSample,-LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState})
  qr qs ht tree index &m :
  (forall (O <: WrapperByteClientOracle {-A}), islossless O.hash => islossless O.sign => islossless A(O).run) =>
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[WrapperCandidateGame(A).run() @ &m :
    unreturned_candidate_guess Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
      ExposureLog.entries res (fors_private_key ht tree index)] <=
    (wrapper_total_public_budget qr qs+12)%r*(1%r/2%r)^128.
proof.
  move=> ha hqr hqs hr hs.
  have he : Pr[WrapperCandidateGame(A).run() @ &m :
      unreturned_candidate_guess Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
        ExposureLog.entries res (fors_private_key ht tree index)] =
    Pr[SelectedWrapperUnreturnedCandidate(A).run(fors_private_key ht tree index) @ &m : res].
  + byequiv (_ : ={glob A,glob WrapperLimits,glob KeygenInputs,glob WrapperSession,glob ExposureLog,glob ClientQueryLog} /\
      target{2}=fors_private_key ht tree index ==> _) => //.
    proc*; inline SelectedWrapperUnreturnedCandidate(A).run.
    wp; call (wrapper_initialized_candidate_observer A); auto.
  have hl : Pr[SelectedWrapperUnreturnedCandidate(A).run(fors_private_key ht tree index) @ &m : res] <=
    Pr[SelectedWrapperTargetGuess(A).run(fors_private_key ht tree index) @ &m : res]
    by byequiv (wrapper_selected_unreturned_implies_unopened A ht tree index) => //.
  have hb : Pr[SelectedWrapperTargetGuess(A).run(fors_private_key ht tree index) @ &m : res] <=
    (wrapper_total_public_budget qr qs+12)%r*(1%r/2%r)^128.
  + byphoare (wrapper_selected_target_probability A qr qs ha hqr hqs) => //.
  smt().
qed.
