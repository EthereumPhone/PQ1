(* Research only. Each recursive step draws independently from d.
   This premise is not a model of the firmware's deterministic SHA transcript
   until a separate oracle/coupling and resource-bound argument is supplied. *)
require import AllCore List Distr RealSeries.
import RField.

(* r2026.02 cannot export this recursive distribution after the FORS clone.
   Keep its definition available for checked rewriting, but expose only the
   operator signature to SMT. Proven lemmas supply the needed properties. *)
op [smt_opaque] bounded ['a] (d : 'a distr) (p : 'a -> bool)
  (fuel : unit list) : 'a option distr =
  with fuel = [] => dunit None
  with fuel = _ :: rest =>
    dlet d (fun x => if p x then dunit (Some x) else bounded d p rest).

lemma bounded_step ['a] (d : 'a distr) (p : 'a -> bool)
  (fuel : unit list) (e : 'a option -> bool) :
  mu (bounded d p (tt :: fuel)) e =
    mu d (fun x => p x /\ e (Some x))
    + mu d (predC p) * mu (bounded d p fuel) e.
proof.
  rewrite /= dletE.
  rewrite (@eq_sum _ (fun x =>
    (if p x /\ e (Some x) then mu1 d x else 0%r)
    + (if !p x then mu1 d x else 0%r) * mu (bounded d p fuel) e)).
  + by move=> x; case: (p x) => hp; rewrite hp /= ?dunitE /b2r; case: (e (Some x)).
  rewrite sumD.
  + exact summable_mu1_cond.
  + rewrite (eq_summable _ (fun x => mu (bounded d p fuel) e *
      (if !p x then mu1 d x else 0%r))).
    - by move=> x /=; rewrite mulrC.
    apply summableZ; exact summable_mu1_cond.
  by rewrite sumZr -!muE.
qed.

(* Exhaustion remains explicit, including zero-acceptance distributions. *)
lemma bounded_exhaustion ['a] (d : 'a distr) (p : 'a -> bool)
  (fuel : unit list) :
  is_lossless d =>
  mu1 (bounded d p fuel) None = (1%r - mu d p) ^ (size fuel).
proof.
  move=> dll; elim: fuel => [|u fuel ih].
  + by rewrite /= dunit1E expr0.
  case: u.
  rewrite (bounded_step d p fuel (pred1 None)) /= mu0 mu_not dll /= ih.
  by rewrite (addzC 1) exprS 1:size_ge0.
qed.

lemma bounded_as_conditioned_mixture ['a] (d : 'a distr) (p : 'a -> bool)
  (fuel : unit list) (e : 'a option -> bool) :
  is_lossless d => 0%r < mu d p =>
  mu (bounded d p fuel) e =
    (1%r - mu d p) ^ (size fuel) * b2r (e None)
    + (1%r - (1%r - mu d p) ^ (size fuel))
      * mu (dcond d p) (fun x => e (Some x)).
proof.
  move=> dll posp.
  elim: fuel => [|u fuel ih].
  + by rewrite /= dunitE expr0.
  case: u.
  rewrite bounded_step ih mu_not dll /=.
  clear ih.
  rewrite (addzC 1) exprS 1:size_ge0.
  rewrite dcondE /predI.
  field; smt().
qed.

lemma bounded_success_mass ['a] (d : 'a distr) (p : 'a -> bool)
  (fuel : unit list) (e : 'a -> bool) :
  is_lossless d => 0%r < mu d p =>
  mu (bounded d p fuel) (fun r => oapp e false r) =
    (1%r - (1%r - mu d p) ^ (size fuel)) * mu (dcond d p) e.
proof.
  by move=> dll posp; rewrite bounded_as_conditioned_mixture //=.
qed.

lemma bounded_ll ['a] (d : 'a distr) (p : 'a -> bool) (fuel : unit list) :
  is_lossless d => is_lossless (bounded d p fuel).
proof.
  move=> dll; elim: fuel => [|u fuel ih].
  + by rewrite /=; exact dunit_ll.
  case: u; rewrite /=; apply dlet_ll => // x hx.
  by case: (p x) => hp; rewrite hp /=; [exact dunit_ll | exact ih].
qed.
