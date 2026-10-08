(* A finite independent node vector meets a fixed candidate list only with its union-bound mass. *)
require import AllCore List Distr DList DProd FMap StdOrder.
require import C10RawOracle C10Randomizer RawKeygen NodeDistribution.
import RealOrder.

lemma full_vector_coordinate n i (p : digest -> bool) :
  0<=i<n =>
  mu (dlist full_digest n) (fun ds => p (nth (nseq 256 false) ds i))=mu full_digest p.
proof.
  move=> hi.
  have hn : 0<=n-1 by smt().
  have hi' : 0<=i<=n-1 by smt().
  have he := dlist_insert (nseq 256 false) i (n-1) full_digest hn hi'.
  have he' : n-1+1=n by smt(); rewrite he' in he.
  rewrite he dmapE.
  have hm : mu (full_digest `*` dlist full_digest (n-1))
    (fun (z : digest * digest list) => p (nth (nseq 256 false) (insert z.`1 z.`2 i) i)) =
    mu (full_digest `*` dlist full_digest (n-1)) (fun (z : digest * digest list) => p z.`1).
  + apply mu_eq_support => z hz /=.
    have hz2 : z.`2 \in dlist full_digest (n-1) by move: hz; rewrite supp_dprod; smt().
    have hs := supp_dlist_size full_digest (n-1) z.`2 hn hz2.
    rewrite nth_insert 1:/#; smt().
  rewrite /(\o).
  rewrite hm dprodEl.
  have hw : weight (dlist full_digest (n-1))=1%r by apply dlist_ll; exact full_digest_ll.
  by rewrite hw.
qed.

op node_vector_hit ds candidates = has (fun d => mem candidates (node d)) ds.
lemma node_vector_mass candidates :
  mu (dlist full_digest 8) (fun ds => node_vector_hit ds candidates) <=
    8%r*(size candidates)%r*(1%r/2%r)^128.
proof.
  have he : mu (dlist full_digest 8) (fun ds => node_vector_hit ds candidates)=
    mu (dlist full_digest 8) (fun ds => has
      (fun i => mem candidates (node (nth (nseq 256 false) ds i))) (range 0 8)).
  + apply mu_eq_support => ds hs /=.
    have hn : 0<=8 by smt().
    have hsize := supp_dlist_size full_digest 8 ds hn hs.
    rewrite /node_vector_hit !hasP eq_iff; split.
    - move=> [d [hd hc]].
      have [i [hi heq]] : exists i, 0<=i<size ds /\ nth (nseq 256 false) ds i=d
        by move: hd; rewrite (nthP (nseq 256 false)).
      exists i; rewrite /= mem_range heq; smt().
    move=> [i [hi hc]].
    exists (nth (nseq 256 false) ds i); split; last exact hc.
    apply mem_nth; move: hi; rewrite mem_range; smt().
  rewrite he.
  have hb := mu_has_leM
    (fun ds i => mem candidates (node (nth (nseq 256 false) ds i)))
    (dlist full_digest 8) (range 0 8) ((size candidates)%r*(1%r/2%r)^128) _.
  + move=> i hi /=.
    have hi' : 0<=i<8 by move: hi; rewrite mem_range.
    have hc := full_vector_coordinate 8 i (fun d => mem candidates (node d)) hi'.
    rewrite hc; exact (node_history_mass candidates).
  by move: hb; rewrite size_range /= RField.mulrA.
qed.

lemma node_vector_has_coordinate hidden candidates j :
  0<=j<size hidden => mem candidates (node (nth (nseq 256 false) hidden j)) =>
  node_vector_hit hidden candidates.
proof.
  move=> hj hm; rewrite /node_vector_hit hasP.
  exists (nth (nseq 256 false) hidden j); split; first exact (mem_nth _ hidden j hj).
  exact hm.
qed.
