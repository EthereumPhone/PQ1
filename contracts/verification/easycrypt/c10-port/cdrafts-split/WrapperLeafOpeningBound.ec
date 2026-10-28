(* Fixed candidates, finite union and the actual accepted wrapper output.
   The two fixed suffix guesses and all twelve final output slots are retained. *)
require import AllCore List Distr FMap StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal RawKeygen ForsPrivateLeaves.
require import WrapperSession WrapperByteSession WrapperPrefixBound WrapperQueryDriver.
require import KeygenPrefixes KeygenExhaustion ExposureLog ClientQueryLog ReturnedPrivateInputs.
require import LeafCommitmentHybrid LeafOpeningBound PrivateTargetSampling.
require import TargetOracleSplit TargetTableProjection TargetTableGames TargetByteView OriginalTargetEvent.
require import WrapperSelectedTargetBound WrapperCandidateProjection WrapperTargetEvent.
require import WrapperSelectedLeafBound WrapperLeafSessionCost.
require import ForsCoordinateUniverse ActualForsOpening WrapperForsOpeningBound.
import RealOrder.

op wrapper_leaf_opening_charge qr qs =
  6442450944%r*((wrapper_leaf_candidate_budget qr qs+2+12)%r*(1%r/2%r)^128).
op retained_wrapper_fors_charge qr qs =
  6442450944%r*((wrapper_total_public_budget qr qs+12)%r*(1%r/2%r)^128).
op best_wrapper_leaf_charge qr qs =
  if retained_wrapper_fors_charge qr qs<=wrapper_leaf_opening_charge qr qs
  then retained_wrapper_fors_charge qr qs else wrapper_leaf_opening_charge qr qs.


lemma wrapper_leaf_unreturned_coordinate_bound
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -Independent,-Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,
    -TargetConfig,-PrivateTargetSample,-LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState})
  qr qs ht tree index &m :
  (forall (O <: WrapperByteClientOracle {-A}), islossless O.hash => islossless O.sign => islossless A(O).run) =>
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[WrapperCandidateGame(A).run() @ &m :
    unreturned_candidate_guess Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
      ExposureLog.entries res (fors_private_key ht tree index)] <=
    (wrapper_leaf_candidate_budget qr qs+2+12)%r*(1%r/2%r)^128.
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
    (wrapper_leaf_candidate_budget qr qs+2+12)%r*(1%r/2%r)^128.
  + byphoare (wrapper_selected_leaf_candidate_probability A qr qs ha hqr hqs) => //.
  smt().
qed.

lemma wrapper_leaf_unreturned_union_bound
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -Independent,-Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,
    -TargetConfig,-PrivateTargetSample,-LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState})
  qr qs (coordinates : (int * int * int) list) &m :
  (forall (O <: WrapperByteClientOracle {-A}), islossless O.hash => islossless O.sign => islossless A(O).run) =>
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[WrapperCandidateGame(A).run() @ &m : exists c, mem coordinates c /\
    unreturned_candidate_guess Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
      ExposureLog.entries res (fors_private_key c.`1 c.`2 c.`3)] <=
    (size coordinates)%r*((wrapper_leaf_candidate_budget qr qs+2+12)%r*(1%r/2%r)^128).
proof.
  move=> ha hqr hqs hr hs; elim coordinates => [|c rest ih].
  + simplify; byphoare (_ : true ==> false) => //; hoare; trivial.
  have hc := wrapper_leaf_unreturned_coordinate_bound A qr qs c.`1 c.`2 c.`3 &m ha hqr hqs hr hs.
  have he : Pr[WrapperCandidateGame(A).run() @ &m : exists x, mem (c::rest) x /\
      unreturned_candidate_guess Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
        ExposureLog.entries res (fors_private_key x.`1 x.`2 x.`3)] =
    Pr[WrapperCandidateGame(A).run() @ &m :
      unreturned_candidate_guess Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
        ExposureLog.entries res (fors_private_key c.`1 c.`2 c.`3) \/
      exists x, mem rest x /\ unreturned_candidate_guess Independent.rawhistory Independent.secrethistory
        WrapperSession.seed WrapperSession.root ExposureLog.entries res (fors_private_key x.`1 x.`2 x.`3)].
  + rewrite Pr[mu_eq]; smt().
  rewrite he Pr[mu_or]; smt(ge0_mu).
qed.

lemma wrapper_byte_leaf_opening_bound
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -Independent,-Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,
    -TargetConfig,-PrivateTargetSample,-LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState})
  qr qs &m :
  (forall (O <: WrapperByteClientOracle {-A}), islossless O.hash => islossless O.sign => islossless A(O).run) =>
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m : res /\
    actual_output_unreturned Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
      ExposureLog.entries ClientQueryLog.output] <=
    6442450944%r*((wrapper_leaf_candidate_budget qr qs+2+12)%r*(1%r/2%r)^128).
proof.
  move=> ha hqr hqs hr hs.
  have he : Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m : res /\
      actual_output_unreturned Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
        ExposureLog.entries ClientQueryLog.output] <=
    Pr[WrapperCandidateGame(A).run() @ &m : exists c, mem ordinary_fors_coordinates c /\
      unreturned_candidate_guess Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
        ExposureLog.entries res (fors_private_key c.`1 c.`2 c.`3)].
  + byequiv (_ : ={glob A,glob WrapperLimits,glob KeygenInputs,glob WrapperSession,glob ExposureLog,glob ClientQueryLog} ==> _) => //.
    proc; inline OriginalWrapperCandidates(A,Independent).run.
    wp; call (_ : ={glob A,glob Independent,glob WrapperLimits,glob KeygenInputs,glob WrapperSession,glob ExposureLog,glob ClientQueryLog}); first by sim.
    inline Independent.init; auto; smt(actual_unreturned_candidates).
  have hb := wrapper_leaf_unreturned_union_bound A qr qs ordinary_fors_coordinates &m ha hqr hqs hr hs.
  rewrite ordinary_fors_universe_size in hb; smt().
qed.

lemma wrapper_byte_fors_opening_best
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -Independent,-Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,
    -TargetConfig,-PrivateTargetSample,-LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState})
  qr qs &m :
  (forall (O <: WrapperByteClientOracle {-A}), islossless O.hash => islossless O.sign => islossless A(O).run) =>
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m : res /\
    actual_output_unreturned Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
      ExposureLog.entries ClientQueryLog.output] <= best_wrapper_leaf_charge qr qs.
proof.
  move=> ha hr hs hqr hqs.
  have hn := wrapper_byte_leaf_opening_bound A qr qs &m ha hr hs hqr hqs.
  have ho := wrapper_byte_fors_opening_bound A qr qs &m ha hr hs hqr hqs.
  rewrite /best_wrapper_leaf_charge /retained_wrapper_fors_charge /wrapper_leaf_opening_charge; smt().
qed.
