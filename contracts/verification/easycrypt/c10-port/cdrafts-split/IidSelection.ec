(* Distinct positions selected from an iid list remain iid, in selection order. *)
require import AllCore List Distr DList.

op shrink_index (i k : int) = if k<i then k else k-1.
lemma shrink_index_bounds i n k : 0<=i<n => 0<=k<n => k<>i => 0<=shrink_index i k<n-1.
proof. rewrite /shrink_index; smt(). qed.
lemma shrink_index_injective i k l : k<>i => l<>i => shrink_index i k=shrink_index i l => k=l.
proof. rewrite /shrink_index; smt(). qed.
lemma nth_insert_other ['a] (x0 x : 'a) xs i k :
  0<=i<=size xs => 0<=k<size xs+1 => k<>i =>
  nth x0 (insert x xs i) k = nth x0 xs (shrink_index i k).
proof.
  move=> hi hk hki; rewrite /insert nth_cat size_take 1:/#.
  rewrite (: (if i<size xs then i else size xs)=i) 1:/#.
  case (k<i)=> hlt.
  + by rewrite nth_take 1:/# 1:/# /shrink_index hlt.
  rewrite /= (: k-i<>0) 1:/# /= nth_drop 1:/# 1:/# /shrink_index hlt /=.
  congr; smt().
qed.
lemma selection_insert ['a] (x0 x : 'a) xs i (indices : int list) :
  0<=i<=size xs => !List.mem indices i =>
  all (fun k => 0<=k<size xs+1) indices =>
  map (nth x0 (insert x xs i)) (i::indices) =
    x :: map (nth x0 xs) (map (shrink_index i) indices).
proof.
  move=> hi hn ha; rewrite /= nth_insert // -map_comp.
  split=> //; apply (eq_in_map _ _ indices) => k hk /=.
  apply nth_insert_other => //; smt(allP).
qed.
lemma iid_distinct_selection ['a] (x0 : 'a) (d : 'a distr) n indices :
  is_lossless d => 0<=n => uniq indices => all (fun i=>0<=i<n) indices =>
  dmap (dlist d n) (fun xs => map (nth x0 xs) indices) = dlist d (size indices).
proof.
  move=> hd; elim/natind: n indices => [n hn|n hn ih] indices hn0 hu hb.
  + have he : indices=[] by case: indices hu hb=> // k ks /=; smt().
    rewrite he /= (dlist0 d 0) // dmap_cst //; exact (dlist_ll d n hd).
  case: indices hu hb => [|i indices] /=.
  + rewrite (dlist0 d 0) // dmap_cst //; exact (dlist_ll d (n+1) hd).
  move=> [hi hu] [hib hb].
  have hui : uniq (map (shrink_index i) indices).
  + rewrite map_inj_in_uniq //; move=> k l hk hl; apply shrink_index_injective; smt().
  have hbi : all (fun k=>0<=k<n) (map (shrink_index i) indices).
  + apply/allP=> k /mapP [l [hl ->]]; have h := shrink_index_bounds i (n+1) l hib; smt(allP).
  rewrite (dlist_insert x0 i n d hn) 1:/# dmap_comp.
  rewrite (eq_dmap_in _ _ (fun p : 'a * 'a list =>
    p.`1 :: map (nth x0 p.`2) (map (shrink_index i) indices))).
  + move=> [x xs] /supp_dprod [_ /(supp_dlist _ _ _ hn) [hs ha]].
    rewrite /(\o) /=.
    have h := selection_insert x0 x xs i indices.
    smt(allP).
  rewrite dmap_dprodE /=.
  rewrite (: 1+size indices=size indices+1) 1:/# dlistS 1:size_ge0 /=.
  rewrite dmap_dprodE /=.
  apply eq_dlet=> // x.
  have hiid := ih (map (shrink_index i) indices) hn hui hbi.
  rewrite size_map in hiid.
  rewrite -hiid dmap_comp.
  by apply eq_dmap=> xs; rewrite /(\o).
qed.
