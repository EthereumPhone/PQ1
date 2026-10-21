(* The finite WOTS rejection bound directly in the physical prefix game.
   Both private derivations and arbitrary public queries use Shared; no cached
   event is transported across the physical/independent comparison. *)
require import AllCore List Distr FMap Xreal StdOrder.
require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid PrefixGames.
require import RawWots WotsAcceptanceMass MemoRejectCompletion WotsRejectDomain.
import RField RealOrder.

lemma physical_reject_client_potential
    (A <: PrefixContext {-Physical,-Shared}) accept xs : uniq xs =>
  ehoare[A(Physical).run : (memo_reject_completion accept Shared.history xs)%xr ==>
    (memo_reject_completion accept Shared.history xs)%xr].
proof.
  move=> hu; proc ((memo_reject_completion accept Shared.history xs)%xr);
    first 2 by auto.
  + proc; call (memo_reject_hash_potential accept xs hu); auto.
  proc; call (memo_reject_hash_potential accept xs hu); auto.
qed.

lemma physical_reject_client_complete
    (A <: PrefixContext {-Physical,-Shared}) accept xs : uniq xs =>
  ehoare[A(Physical).run : (memo_reject_completion accept Shared.history xs)%xr ==>
    (memo_complete_rejection accept Shared.history xs)%xr].
proof.
  move=> hu; conseq (_ : _ ==> (memo_reject_completion accept Shared.history xs)%xr).
  + move=> &hr; apply xle_cxr_l.
    - by move=> h; apply memo_reject_completion_dominates.
    by [].
  + move=> &hr; apply xle_cxr_r => h; exact (h Shared.history{hr}).
  exact (physical_reject_client_potential A accept xs hu).
qed.

lemma physical_reject_initialized_complete
    (A <: PrefixContext {-Physical,-Shared}) accept xs : uniq xs =>
  ehoare[RealGame(A).run : (memo_reject_mass accept ^ size xs)%xr ==>
    (memo_complete_rejection accept Shared.history xs)%xr].
proof.
  move=> hu; proc; call (physical_reject_client_complete A accept xs hu).
  by inline Shared.init; auto; rewrite memo_reject_completion_empty EpC full_digest_ll /=.
qed.

lemma physical_reject_initialized_bound
    (A <: PrefixContext {-Physical,-Shared}) accept xs &m : uniq xs =>
  Pr[RealGame(A).run() @ &m : memo_complete_rejection accept Shared.history xs] <=
    memo_reject_mass accept ^ size xs.
proof.
  move=> hu; have hb : 0%r <= memo_reject_mass accept ^ size xs
    by apply expr_ge0; smt(memo_reject_mass_bounds).
  by byehoare (physical_reject_initialized_complete A accept xs hu) => //.
qed.

lemma physical_wots_fixed_schedule (A <: PrefixContext {-Physical,-Shared}) stem n &m :
  0<=n<=2^256 =>
  Pr[RealGame(A).run() @ &m :
    memo_complete_rejection count_accepts Shared.history (wots_count_schedule stem n)] <=
    (1%r-wots_acceptance_mass)^n.
proof.
  move=> hn; have hu := wots_count_schedule_unique stem n hn.
  have h := physical_reject_initialized_bound A count_accepts (wots_count_schedule stem n) &m hu.
  by move: h; rewrite wots_rejection_mass_exact wots_count_schedule_size 1:/#.
qed.

lemma physical_wots_context_union
    (A <: PrefixContext {-Physical,-Shared}) seed n (contexts : int list) &m :
  0<=n<=2^256 =>
  Pr[RealGame(A).run() @ &m : exists c, List.mem contexts c /\
    memo_complete_rejection count_accepts Shared.history
      (wots_count_schedule (wots_context_stem seed (RawKeygen.be 32 c)) n)] <=
    (size contexts)%r * (1%r-wots_acceptance_mass)^n.
proof.
  move=> hn; elim: contexts => [|c rest ih].
  + simplify; byphoare (_ : true ==> false) => //; hoare; trivial.
  have hc := physical_wots_fixed_schedule A (wots_context_stem seed (RawKeygen.be 32 c)) n &m hn.
  have he : Pr[RealGame(A).run() @ &m : exists x, List.mem (c::rest) x /\
      memo_complete_rejection count_accepts Shared.history
        (wots_count_schedule (wots_context_stem seed (RawKeygen.be 32 x)) n)] =
    Pr[RealGame(A).run() @ &m :
      memo_complete_rejection count_accepts Shared.history
        (wots_count_schedule (wots_context_stem seed (RawKeygen.be 32 c)) n) \/
      exists x, List.mem rest x /\ memo_complete_rejection count_accepts Shared.history
        (wots_count_schedule (wots_context_stem seed (RawKeygen.be 32 x)) n)].
  + rewrite Pr[mu_eq]; smt().
  rewrite he Pr[mu_or]; smt(ge0_mu).
qed.

lemma physical_wots_domain_bound
    (A <: PrefixContext {-Physical,-Shared}) seed n &m : 0<=n<=2^256 =>
  Pr[RealGame(A).run() @ &m : wots_domain_exhausted seed n Shared.history] <=
    wots_domain_charge n.
proof.
  move=> hn; have h := physical_wots_context_union A seed n wots_context_indices &m hn.
  by move: h; rewrite wots_context_cardinality /wots_domain_exhausted /wots_domain_charge.
qed.
