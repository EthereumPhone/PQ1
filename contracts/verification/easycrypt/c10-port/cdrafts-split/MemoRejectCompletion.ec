(* Rejection of a fixed, distinct finite set of inputs under the actual shared
   oracle. Cached replies retain their observed value; absent inputs retain
   their fresh rejection mass. No freshness premise is imposed on the client. *)
require import AllCore List Distr FMap Xreal StdOrder.
require import C10RawOracle C10Randomizer.
import RField RealOrder.

op memo_reject_mass (accept : digest -> bool) =
  mu full_digest (fun d => !accept d).
op memo_reject_weight accept (h : (raw_input,digest) fmap) x =
  if x \in h then b2r (!accept (oget h.[x])) else memo_reject_mass accept.
op memo_reject_completion accept h (xs : raw_input list) : real =
  with xs = [] => 1%r
  with xs = x :: rest =>
    memo_reject_weight accept h x * memo_reject_completion accept h rest.
op memo_complete_rejection accept (h : (raw_input,digest) fmap) xs =
  all (fun x => x \in h /\ !accept (oget h.[x])) xs.

lemma memo_reject_mass_bounds accept : 0%r <= memo_reject_mass accept <= 1%r.
proof. exact (mu_bounded full_digest (fun d => !accept d)). qed.

lemma memo_reject_weight_bounds accept h x :
  0%r <= memo_reject_weight accept h x <= 1%r.
proof. rewrite /memo_reject_weight; smt(memo_reject_mass_bounds). qed.

lemma memo_reject_completion_bounds accept h xs :
  0%r <= memo_reject_completion accept h xs <= 1%r.
proof.
  elim: xs => [|x xs ih] //=.
  have hw := memo_reject_weight_bounds accept h x.
  split; first by apply mulr_ge0; smt().
  have := ler_pmul (memo_reject_weight accept h x)
    (memo_reject_completion accept h xs) 1%r 1%r; smt().
qed.

lemma memo_reject_completion_empty accept xs :
  memo_reject_completion accept empty xs = memo_reject_mass accept ^ size xs.
proof.
  elim: xs => [|x xs ih] /=; first by rewrite expr0.
  rewrite /memo_reject_weight mem_empty /= ih (_ : 1+size xs = size xs+1) 1:/# exprSr 1:size_ge0.
  by ring.
qed.

lemma memo_reject_weight_other accept h x y d : x <> y =>
  memo_reject_weight accept h.[x <- d] y = memo_reject_weight accept h y.
proof. move=> hxy; rewrite /memo_reject_weight mem_set get_setE; smt(). qed.

lemma memo_reject_completion_unqueried accept h xs x d : !List.mem xs x =>
  memo_reject_completion accept h.[x <- d] xs = memo_reject_completion accept h xs.
proof.
  elim: xs => [|y xs ih] //=.
  by move=> hx; rewrite memo_reject_weight_other 1:/# ih 1:/#.
qed.

lemma memo_reject_completion_complete accept h xs :
  memo_complete_rejection accept h xs => memo_reject_completion accept h xs = 1%r.
proof.
  elim: xs => [|x xs ih] //=.
  rewrite /memo_complete_rejection /= => [#] hx ha hr.
  by rewrite /memo_reject_weight hx ha /= ih.
qed.

lemma memo_reject_completion_dominates accept h xs :
  (memo_complete_rejection accept h xs)%xr <= (memo_reject_completion accept h xs)%xr.
proof.
  case (memo_complete_rejection accept h xs) => hc.
  + by rewrite (memo_reject_completion_complete accept h xs hc).
  smt(to_realP of_realdK).
qed.

lemma memo_reject_scaled s (v : real) : 0%r <= s => 0%r <= v =>
  (s*v)%xr = s ** v%xr.
proof.
  move=> hs hv; rewrite /( ** ).
  case (s%rp = of_reald 0%r) => hz.
  + have -> : s = 0%r by smt(of_realdK to_realP).
    by rewrite /=.
  by rewrite /= of_realM.
qed.

lemma memo_reject_completion_step accept h xs x : uniq xs => x \notin h =>
  Ep full_digest (fun d => (memo_reject_completion accept h.[x <- d] xs)%xr) =
    (memo_reject_completion accept h xs)%xr.
proof.
  elim: xs => [|y xs ih] /=.
  + by move=> _; rewrite EpC full_digest_ll /=.
  move=> [#] hy hu hx.
  case (x = y) => hxy.
  + subst y; rewrite (eq_Ep _ _ (fun d =>
      (memo_reject_completion accept h xs) ** (!accept d)%xr)).
    - move=> d _ /=.
      rewrite (memo_reject_completion_unqueried accept h xs x d hy).
      rewrite /memo_reject_weight mem_set get_set_sameE /=.
      by case (accept d); rewrite /=.
    rewrite EpsZ Ep_mu -/memo_reject_mass.
    rewrite -memo_reject_scaled; first 2 by smt(memo_reject_completion_bounds memo_reject_mass_bounds).
    by rewrite /memo_reject_weight hx /= mulrC.
  rewrite (eq_Ep _ _ (fun d => (memo_reject_weight accept h y) **
      (memo_reject_completion accept h.[x <- d] xs)%xr)).
  + move=> d _ /=; rewrite (memo_reject_weight_other accept h x y d hxy).
    apply of_realM; smt(memo_reject_weight_bounds memo_reject_completion_bounds).
  rewrite EpsZ (ih hu hx) -memo_reject_scaled.
  + smt(memo_reject_weight_bounds).
  + smt(memo_reject_completion_bounds).
  by [].
qed.

lemma memo_reject_hash_potential accept xs : uniq xs =>
  ehoare[Shared.hash : (memo_reject_completion accept Shared.history xs)%xr ==>
    (memo_reject_completion accept Shared.history xs)%xr].
proof.
  move=> hu; proc; wp; skip => &hr.
  case (x{hr} \in Shared.history{hr}) => hx; first by [].
  rewrite /= (memo_reject_completion_step accept Shared.history{hr} xs x{hr} hu hx).
  by [].
qed.

lemma memo_reject_client_potential (A <: Context {-Shared}) accept xs : uniq xs =>
  ehoare[A(Shared).run : (memo_reject_completion accept Shared.history xs)%xr ==>
    (memo_reject_completion accept Shared.history xs)%xr].
proof.
  move=> hu; proc ((memo_reject_completion accept Shared.history xs)%xr);
    first 2 by auto.
  exact (memo_reject_hash_potential accept xs hu).
qed.

lemma memo_reject_client_complete (A <: Context {-Shared}) accept xs : uniq xs =>
  ehoare[A(Shared).run : (memo_reject_completion accept Shared.history xs)%xr ==>
    (memo_complete_rejection accept Shared.history xs)%xr].
proof.
  move=> hu; conseq (_ : _ ==> (memo_reject_completion accept Shared.history xs)%xr).
  + move=> &hr; apply xle_cxr_l.
    - by move=> h; apply memo_reject_completion_dominates.
    by [].
  + move=> &hr; apply xle_cxr_r => h; exact (h Shared.history{hr}).
  exact (memo_reject_client_potential A accept xs hu).
qed.

lemma memo_reject_prefilled_bound (A <: Context {-Shared}) accept xs &m : uniq xs =>
  Pr[A(Shared).run() @ &m : memo_complete_rejection accept Shared.history xs] <=
    memo_reject_completion accept Shared.history{m} xs.
proof.
  move=> hu; have hb := memo_reject_completion_bounds accept Shared.history{m} xs.
  by byehoare (memo_reject_client_complete A accept xs hu) => //.
qed.

module MemoRejectGame (A : Context) = {
  proc run() : bool = {
    var result;
    Shared.init(); result <@ A(Shared).run(); return result;
  }
}.

lemma memo_reject_initialized_complete (A <: Context {-Shared}) accept xs : uniq xs =>
  ehoare[MemoRejectGame(A).run : (memo_reject_mass accept ^ size xs)%xr ==>
    (memo_complete_rejection accept Shared.history xs)%xr].
proof.
  move=> hu; proc; call (memo_reject_client_complete A accept xs hu).
  by inline Shared.init; auto; rewrite memo_reject_completion_empty.
qed.

lemma memo_reject_initialized_bound (A <: Context {-Shared}) accept xs &m : uniq xs =>
  Pr[MemoRejectGame(A).run() @ &m : memo_complete_rejection accept Shared.history xs] <=
    memo_reject_mass accept ^ size xs.
proof.
  move=> hu; have hb : 0%r <= memo_reject_mass accept ^ size xs
    by apply expr_ge0; smt(memo_reject_mass_bounds).
  by byehoare (memo_reject_initialized_complete A accept xs hu) => //.
qed.
