(* Ordinary-FORS opening probability for the actual accepted byte-wrapper output. *)
require import AllCore List Distr FMap StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal RawKeygen ForsPrivateLeaves.
require import WrapperSession WrapperByteSession WrapperPrefixBound WrapperQueryDriver.
require import KeygenPrefixes KeygenExhaustion ExposureLog ClientQueryLog ReturnedPrivateInputs.
require import LeafCommitmentHybrid LeafOpeningBound PrivateTargetSampling.
require import TargetOracleSplit TargetTableProjection TargetTableGames TargetByteView OriginalTargetEvent.
require import WrapperSelectedTargetBound WrapperCandidateProjection WrapperTargetEvent.
require import ForsCoordinateUniverse ActualForsOpening WrapperCandidateUnion.
import RealOrder.

lemma wrapper_byte_fors_opening_bound
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -Independent,-Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,
    -TargetConfig,-PrivateTargetSample,-LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState})
  qr qs &m :
  (forall (O <: WrapperByteClientOracle {-A}), islossless O.hash => islossless O.sign => islossless A(O).run) =>
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m : res /\
    actual_output_unreturned Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
      ExposureLog.entries ClientQueryLog.output] <=
    6442450944%r*((wrapper_total_public_budget qr qs+12)%r*(1%r/2%r)^128).
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
  have hb := wrapper_unreturned_union_bound A qr qs ordinary_fors_coordinates &m ha hqr hqs hr hs.
  rewrite ordinary_fors_universe_size in hb; smt().
qed.
