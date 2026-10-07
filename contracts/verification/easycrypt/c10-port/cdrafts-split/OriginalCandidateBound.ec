(* A pointwise bound in the original initialized byte game, with no hidden-budget premise. *)
require import AllCore List Distr FMap StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid RawKeygen ForsPrivateLeaves FullSession FullPrefix ByteSession.
require import KeygenPrefixes KeygenExhaustion ExposureLog ClientQueryLog ReturnedPrivateInputs.
require import LeafCommitmentHybrid LeafOpeningBound PrivateTargetSampling.
require import TargetOracleSplit TargetTableProjection TargetTableGames TargetByteView.
require import OriginalByteTargetBound OriginalTargetEvent.
import RealOrder.

lemma original_unreturned_coordinate_bound
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -Independent,-Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,
    -TargetConfig,-PrivateTargetSample,-LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState})
  qr qs ht tree index &m :
  (forall (O <: ByteClientOracle {-A}), islossless O.hash => islossless O.sign => islossless A(O).run) =>
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[ByteCandidateGame(A).run() @ &m :
    unreturned_candidate_guess Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
      ExposureLog.entries res (fors_private_key ht tree index)] <=
    (full_public_budget qr qs+12)%r*(1%r/2%r)^128.
proof.
  move=> ha hqr hqs hr hs.
  have he : Pr[ByteCandidateGame(A).run() @ &m :
      unreturned_candidate_guess Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
        ExposureLog.entries res (fors_private_key ht tree index)] =
    Pr[SelectedUnreturnedCandidate(A).run(fors_private_key ht tree index) @ &m : res].
  + byequiv (_ : ={glob A,glob FullLimits,glob KeygenInputs,glob FullSession,glob ExposureLog,glob ClientQueryLog} /\
      target{2}=fors_private_key ht tree index ==> _) => //.
    proc*; inline SelectedUnreturnedCandidate(A).run.
    wp; call (initialized_candidate_observer A); auto.
  have hl : Pr[SelectedUnreturnedCandidate(A).run(fors_private_key ht tree index) @ &m : res] <=
    Pr[SelectedByteTargetGuess(A).run(fors_private_key ht tree index) @ &m : res]
    by byequiv (selected_unreturned_implies_unopened A ht tree index) => //.
  have hb : Pr[SelectedByteTargetGuess(A).run(fors_private_key ht tree index) @ &m : res] <=
    (full_public_budget qr qs+12)%r*(1%r/2%r)^128.
  + byphoare (selected_byte_target_bound A qr qs ha hqr hqs) => //.
  smt().
qed.
