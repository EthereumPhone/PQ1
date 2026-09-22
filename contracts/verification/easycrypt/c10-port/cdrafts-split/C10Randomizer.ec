(* Truncating a uniform 256-bit draw to its high 128 bits preserves uniformity.
   Bit lists follow EasyCrypt's least-significant-bit-first convention.
   This is a distribution calculation, not a property assumed of SHA-256. *)
require import AllCore List Distr DList DBool StdOrder StdBigop.
require C10Counter Birthday.
import RField RealOrder.

op full_digest : bool list distr = dlist dbool 256.
op randomizer : bool list distr = dlist dbool 128.
op truncate_r (bits : bool list) = drop 128 bits.

lemma randomizer_ll : is_lossless randomizer.
proof. by rewrite /randomizer; apply dlist_ll; exact dbool_ll. qed.

lemma truncate_uniform : dmap full_digest truncate_r = randomizer.
proof.
  rewrite /full_digest /randomizer (_ : 256 = 128 + 128) 1://
    dlist_add 1,2:// dmap_comp.
  rewrite (eq_dmap_in _ _ (fun xy : bool list * bool list => xy.`2)).
  + move=> [lo hi] /= /supp_dprod [hlo hhi]; rewrite /(\o) /truncate_r /=
      drop_cat (supp_dlist_size dbool 128 lo _ hlo) 1:// /= drop0.
    by [].
  by rewrite (dprod_marginalR _ _ idfun) (dlist_ll _ _ dbool_ll)
    /idfun dmap_id dscalar1.
qed.

(* Duplicates in history deliberately count more than once. This is a union
   bound, so callers need not pretend an adaptive transcript is unique. *)
lemma one_draw_history_bound (history : bool list list) (atom : real) :
  (forall r, mu1 randomizer r <= atom) =>
  mu randomizer (mem history) <= (size history)%r * atom.
proof. exact (mu_mem_le_mu1 randomizer history atom). qed.

lemma bool_word_mass (r : bool list) :
  mu1 (dlist dbool (size r)) r = (1%r / 2%r) ^ size r.
proof.
  elim: r => [|b r ih].
  + by rewrite /= dlist01E 1:// expr0.
  by rewrite dlistS1E dbool1E ih /= (addzC 1) exprS 1:size_ge0.
qed.

lemma randomizer_atom_bound (r : bool list) :
  mu1 randomizer r <= (1%r / 2%r) ^ 128.
proof.
  case (size r = 128) => hs.
  + by rewrite /randomizer -hs bool_word_mass.
  have hn : !(r \in randomizer).
  + rewrite /randomizer supp_dlist 1:// /=; smt().
  rewrite supportPn in hn.
  by rewrite hn; apply expr_ge0; smt().
qed.

lemma randomizer_history_bound (history : bool list list) :
  mu randomizer (mem history) <= (size history)%r * (1%r / 2%r) ^ 128.
proof. by apply one_draw_history_bound; exact randomizer_atom_bound. qed.

(* Standard birthday theorem instantiated at this distribution. The budget
   here is for the WHOLE experiment, not silently per signing call. *)
clone Birthday as RDraws with
  type T <- bool list,
  op uT <- randomizer,
  op q <- C10Counter.signing_budget
  proof *.
realize ge0_q by rewrite /C10Counter.signing_budget.

lemma adaptive_randomizer_collisions
  (A <: RDraws.Adv {-RDraws.Sample}) &m :
  (forall (S <: RDraws.ASampler {-A}), islossless S.s => islossless A(S).a) =>
  hoare[A(RDraws.Sample).a : size RDraws.Sample.l = 0 ==>
    size RDraws.Sample.l <= C10Counter.signing_budget] =>
  Pr[RDraws.Exp(RDraws.Sample,A).main() @ &m : !uniq RDraws.Sample.l] <=
    (C10Counter.signing_budget * (C10Counter.signing_budget - 1))%r / 2%r *
      (1%r / 2%r) ^ 128.
proof.
  move=> hll hb.
  have hc := RDraws.pr_collision A hll hb &m.
  have ha := randomizer_atom_bound RDraws.maxu.
  move: hc ha; rewrite /C10Counter.signing_budget; smt().
qed.
