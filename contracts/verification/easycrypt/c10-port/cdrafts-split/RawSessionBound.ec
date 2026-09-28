(* Availability bound for the actual shared raw R/H_msg loops after keygen.
   Complete signatures, WOTS grinding, and forgery reductions are not this game. *)
require import AllCore List Distr StdOrder StdBigop.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixGames.
require import RSession SessionKeygen SessionPhysical RawSession GrindExhaustion.
import RealOrder Bigreal BRA.

lemma raw_session_exhaustion
  (A <: RClient {-RSession,-Independent,-SessionLimits,-Physical,-Hybrid,-Shared}) qr qs &m :
  (forall (V <: RClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0 <= qr => 0 <= qs => SessionLimits.raw_cap{m} = qr => SessionLimits.sign_cap{m} = qs =>
  Pr[RawSessionGame(A).run() @ &m : res] <=
    bigi predT (fun _ => exhaustion_charge (155135+qr+qs*signing_budget)) 0 qs +
    (155135+qr+qs*signing_budget)%r * (1%r/2%r)^256.
proof.
  move=> ha hqr hqs hraw hsign.
  have he : Pr[RawSessionGame(A).run() @ &m : res] =
    Pr[RealGame(SessionKeygenContext(A)).run() @ &m : res]
    by byequiv (raw_session_game_refinement A) => //.
  rewrite he; exact (whole_physical_session_exhaustion A qr qs &m ha hqr hqs hraw hsign).
qed.
