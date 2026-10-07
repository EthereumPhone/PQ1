(* Numerical ordinary-FORS private-opening charge for the original accepted byte output. *)
require import AllCore List Distr FMap StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal RawKeygen ForsPrivateLeaves FullSession FullPrefix ByteSession.
require import KeygenPrefixes KeygenExhaustion ExposureLog ClientQueryLog ClientQueryDriver.
require import LeafCommitmentHybrid LeafOpeningBound PrivateTargetSampling.
require import TargetOracleSplit TargetTableProjection TargetByteView OriginalTargetEvent OriginalCandidateUnion.
require import ForsCoordinateUniverse ActualForsOpening.
import RealOrder.

lemma original_byte_fors_opening_bound
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -Independent,-Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,
    -TargetConfig,-PrivateTargetSample,-LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState})
  qr qs &m :
  (forall (O <: ByteClientOracle {-A}), islossless O.hash => islossless O.sign => islossless A(O).run) =>
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : res /\
    actual_output_unreturned Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
      ExposureLog.entries ClientQueryLog.output] <=
    6442450944%r*((full_public_budget qr qs+12)%r*(1%r/2%r)^128).
proof.
  move=> ha hqr hqs hr hs.
  have he : Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : res /\
      actual_output_unreturned Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
        ExposureLog.entries ClientQueryLog.output] <=
    Pr[ByteCandidateGame(A).run() @ &m : exists c, mem ordinary_fors_coordinates c /\
      unreturned_candidate_guess Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
        ExposureLog.entries res (fors_private_key c.`1 c.`2 c.`3)].
  + byequiv (_ : ={glob A,glob FullLimits,glob KeygenInputs,glob FullSession,glob ExposureLog,glob ClientQueryLog} ==> _) => //.
    proc; inline OriginalByteCandidates(A,Independent).run.
    wp; call (_ : ={glob A,glob Independent,glob FullLimits,glob KeygenInputs,glob FullSession,glob ExposureLog,glob ClientQueryLog}); first by sim.
    inline Independent.init; auto; smt(actual_unreturned_candidates).
  have hb := original_unreturned_union_bound A qr qs ordinary_fors_coordinates &m ha hqr hqs hr hs.
  rewrite ordinary_fors_universe_size in hb; smt().
qed.
