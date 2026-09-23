(* External Q research: entropy of a fresh raw digest projection only.
   This is not a full C10 forgery bound or a freshness claim for cached input. *)
require import AllCore List Distr DList DProd DBool StdOrder.
require import C10RawOracle C10Randomizer.
import RealOrder.

lemma digest_prefix_uniform n : 0 <= n <= 256 =>
  dmap full_digest (take n) = dlist dbool n.
proof.
  move=> hn; rewrite /full_digest (_ : 256 = n+(256-n)) 1:/#
    dlist_add 1,2:/# dmap_comp.
  rewrite (eq_dmap_in _ _ (fun xy : bool list * bool list => xy.`1)).
  + move=> [lo hi] /= /supp_dprod [hlo hhi].
    by rewrite /(\o) /= take_cat (supp_dlist_size dbool n lo _ hlo) 1:/# /= take0 cats0.
  by rewrite (dprod_marginalL _ _ idfun) (dlist_ll _ _ dbool_ll) /idfun dmap_id dscalar1.
qed.

lemma prefix_atom_bound n (t : bool list) : 0 <= n =>
  mu1 (dlist dbool n) t <= (1%r/2%r)^n.
proof.
  move=> hn; case (size t = n) => hs.
  + by rewrite -hs bool_word_mass.
  have hx : !(t \in dlist dbool n) by rewrite supp_dlist 1:hn /=; smt().
  rewrite supportPn in hx; rewrite hx; apply expr_ge0; smt().
qed.

lemma digest_prefix_list n (targets : bool list list) : 0 <= n <= 256 =>
  mu full_digest (fun d => take n d \in targets) <=
    (size targets)%r * (1%r/2%r)^n.
proof.
  move=> hn.
  have ha : forall t, mu1 (dlist dbool n) t <= (1%r/2%r)^n
    by move=> t; apply prefix_atom_bound; smt().
  have h := mu_mem_le_mu1 (dlist dbool n) targets ((1%r/2%r)^n) ha.
  rewrite -(digest_prefix_uniform n hn) dmapE /pred_o /(\o) in h.
  exact h.
qed.
