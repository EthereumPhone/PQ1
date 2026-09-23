(* Explicit classical availability terms; these are not forgery security bits. *)
require import AllCore List Distr StdOrder StdBigop.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid.
require import RSession SessionKeygen RawSession RawSessionBound GrindTail GrindExhaustion.
import RField RealOrder Bigreal BRA.

lemma revisit_closed q :
  revisit_charge q =
    ((signing_budget*q)%r + (signing_budget*(signing_budget-1))%r/2%r) * (1%r/2%r)^128.
proof.
  have hb : 0 <= signing_budget by rewrite /signing_budget.
  rewrite /revisit_charge -BRA.mulr_suml.
  have hs : bigi predT (fun i => (q+i)%r) 0 signing_budget =
      bigi predT (fun _ => q%r) 0 signing_budget + bigi predT (fun i => i%r) 0 signing_budget.
  + rewrite BRA.sumrD; apply eq_big => // i _; smt(fromintD).
  rewrite hs Bigreal.sumri_const 1:hb Bigreal.sumidE 1:hb /= fromintM.
  ring.
qed.

op session_availability_bound qr qs =
  qs%r * (reject_mass^signing_budget +
    ((signing_budget*(155135+qr+qs*signing_budget))%r +
      (signing_budget*(signing_budget-1))%r/2%r) * (1%r/2%r)^128) +
    (155135+qr+qs*signing_budget)%r * (1%r/2%r)^256.

lemma raw_session_exhaustion_explicit
  (A <: RClient {-RSession,-Independent,-SessionLimits,-Physical,-Hybrid,-Shared}) qr qs &m :
  (forall (V <: RClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0 <= qr => 0 <= qs => SessionLimits.raw_cap{m} = qr => SessionLimits.sign_cap{m} = qs =>
  Pr[RawSessionGame(A).run() @ &m : res] <= session_availability_bound qr qs.
proof.
  move=> ha hqr hqs hraw hsign.
  have h := raw_session_exhaustion A qr qs &m ha hqr hqs hraw hsign.
  move: h; rewrite Bigreal.sumri_const 1:hqs /= /exhaustion_charge revisit_closed.
  by rewrite /session_availability_bound.
qed.
