(* A finite union of fixed-coordinate charges in the same original game. *)
require import AllCore List Distr FMap StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid RawKeygen ForsPrivateLeaves FullSession FullPrefix ByteSession.
require import KeygenPrefixes KeygenExhaustion ExposureLog ClientQueryLog.
require import LeafCommitmentHybrid LeafOpeningBound PrivateTargetSampling.
require import TargetOracleSplit TargetTableProjection TargetTableGames OriginalTargetEvent OriginalCandidateBound.
require import ForsCoordinateUniverse.
import RealOrder.

lemma original_unreturned_union_bound
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -Independent,-Shared,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,-OriginalTargetState,
    -TargetConfig,-PrivateTargetSample,-LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState})
  qr qs (coordinates : (int * int * int) list) &m :
  (forall (O <: ByteClientOracle {-A}), islossless O.hash => islossless O.sign => islossless A(O).run) =>
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[ByteCandidateGame(A).run() @ &m : exists c, mem coordinates c /\
    unreturned_candidate_guess Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
      ExposureLog.entries res (fors_private_key c.`1 c.`2 c.`3)] <=
    (size coordinates)%r*((full_public_budget qr qs+12)%r*(1%r/2%r)^128).
proof.
  move=> ha hqr hqs hr hs; elim coordinates => [|c rest ih].
  + simplify; byphoare (_ : true ==> false) => //; hoare; trivial.
  have hc := original_unreturned_coordinate_bound A qr qs c.`1 c.`2 c.`3 &m ha hqr hqs hr hs.
  have he : Pr[ByteCandidateGame(A).run() @ &m : exists x, mem (c::rest) x /\
      unreturned_candidate_guess Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
        ExposureLog.entries res (fors_private_key x.`1 x.`2 x.`3)] =
    Pr[ByteCandidateGame(A).run() @ &m :
      unreturned_candidate_guess Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
        ExposureLog.entries res (fors_private_key c.`1 c.`2 c.`3) \/
      exists x, mem rest x /\ unreturned_candidate_guess Independent.rawhistory Independent.secrethistory
        FullSession.seed FullSession.root ExposureLog.entries res (fors_private_key x.`1 x.`2 x.`3)].
  + rewrite Pr[mu_eq]; smt().
  rewrite he Pr[mu_or]; smt(ge0_mu).
qed.
