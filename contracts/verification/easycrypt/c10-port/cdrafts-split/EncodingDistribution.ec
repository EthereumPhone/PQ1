(* The encoding projection is uniform on 129 bits; unlike the high node half. *)
require import AllCore List Distr DList DBool StdOrder.
require import C10RawOracle C10Randomizer WotsDigitOrder.
import RField RealOrder.

op encoding_distribution = dlist dbool 129.

lemma encoding_uniform : dmap full_digest encoding_bits=encoding_distribution.
proof.
  rewrite /full_digest /encoding_distribution (_ : 256=129+127) 1://
    dlist_add 1,2:// dmap_comp.
  rewrite (eq_dmap_in _ _ (fun xy : bool list * bool list => xy.`1)).
  + move=> [lo hi] /= /supp_dprod [hlo hhi]; rewrite /(\o) /encoding_bits /=.
    have hs : size lo=129 by exact (supp_dlist_size dbool 129 lo _ hlo).
    apply (eq_from_nth false); first by rewrite size_mkseq hs.
    move=> j; rewrite size_mkseq /= => hj.
    by rewrite nth_mkseq 1:/# /= nth_cat hs (: j<129) 1:/#.
  by rewrite (dprod_marginalL _ _ idfun) (dlist_ll _ _ dbool_ll)
    /idfun dmap_id dscalar1.
qed.

lemma encoding_atom_bound (word : digest) :
  mu1 encoding_distribution word <= (1%r/2%r)^129.
proof.
  case (size word=129) => hs.
  + by rewrite /encoding_distribution -hs bool_word_mass.
  have hn : !(word \in encoding_distribution).
  + rewrite /encoding_distribution supp_dlist 1:// /=; smt().
  rewrite supportPn in hn; rewrite hn; apply expr_ge0; smt().
qed.

lemma encoding_history_mass (words : digest list) :
  mu full_digest (fun d => mem words (encoding_bits d)) <= (size words)%r*(1%r/2%r)^129.
proof.
  have hm := mu_mem_le_mu1 encoding_distribution words ((1%r/2%r)^129) encoding_atom_bound.
  by move: hm; rewrite -encoding_uniform dmapE /(\o).
qed.
