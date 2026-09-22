(* Certified conservative exhaustion bound in the classical search experiment.
   This is not a numerical forgery bound or a running-time bound for the
   existing total reductions, whose pure hash operators carry no cost model. *)
require import AllCore List Distr StdOrder.
require import C10SharedSearch C10BoundedIID C10Encoding C10Surface SharedROBounded.
import RField RealOrder.
import SPHINCS_PLUS FSSLXMTWES FSSLXMTWES.WTWES.

lemma reciprocal_tail (x : real) (n : int) :
  0%r <= x <= 1%r => 0 <= n =>
  (1%r-x)^n * (1%r+n%r*x) <= 1%r.
proof.
  move=> hx; elim: n => [|n hn ih]; first by rewrite expr0.
  have hp : 0%r <= (1%r-x)^n by apply expr_ge0; smt().
  have hs : (1%r-x) * (1%r+(n+1)%r*x) <= 1%r+n%r*x.
  + rewrite fromintD /=.
    have hsq : 0%r <= (n%r+1%r)*x*x by smt(mulr_ge0).
    have he : (1%r-x)*(1%r+(n%r+1%r)*x)
      = (1%r+n%r*x) - (n%r+1%r)*x*x by ring.
    smt().
  rewrite exprSr 1:hn -mulrA.
  have hm : (1%r-x)^n * ((1%r-x) * (1%r+(n+1)%r*x)) <=
    (1%r-x)^n * (1%r+n%r*x) by apply ler_wpmul2l.
  smt().
qed.

lemma one_block_half (x : real) :
  1%r/32768%r <= x <= 1%r => (1%r-x)^32768 <= 1%r/2%r.
proof.
  move=> hx.
  have hx0 : 0%r <= x <= 1%r by smt().
  have h := reciprocal_tail x 32768 hx0 _; first by [].
  have hp : 0%r <= (1%r-x)^32768 by apply expr_ge0; smt().
  smt().
qed.

lemma acceptance_lower : 1%r/32768%r <= acceptance <= 1%r.
proof. by rewrite /acceptance pow8_43; smt(). qed.

lemma fresh_trials_bound (fresh : int) :
  9994240 <= fresh => (1%r-acceptance)^fresh <= (1%r/2%r)^305.
proof.
  move=> hf; have hx := acceptance_lower.
  apply (ler_trans ((1%r-acceptance)^(32768*305))).
  + apply ler_wiexpn2l; smt().
  rewrite exprM.
  apply ler_pexp; first smt(expr_ge0).
  split.
  + apply expr_ge0; smt().
  by move=> _; exact (one_block_half acceptance hx).
qed.

lemma shared_exhaustion_305_bits (seed address : int list) (m : dgstblock)
  (history : (int list * msgWOTS) list) :
  9994240 <= fresh_count history (counter_inputs seed address m) =>
  mu1 (shared_search seed address m history) None <= (1%r/2%r)^305.
proof.
  move=> hf.
  apply (ler_trans ((1%r-acceptance)^fresh_count history (counter_inputs seed address m))).
  + exact (shared_history_exhaustion seed address m history).
  exact (fresh_trials_bound _ hf).
qed.

lemma shared_search_known_budget (seed address : int list) (m : dgstblock)
  (history : (int list * msgWOTS) list) :
  size (counter_inputs seed address m) -
    fresh_count history (counter_inputs seed address m) <= 5760 =>
  mu1 (shared_search seed address m history) None <= (1%r/2%r)^305.
proof.
  rewrite counter_inputs_size /C10Counter.signing_budget => hb.
  apply shared_exhaustion_305_bits; smt().
qed.
