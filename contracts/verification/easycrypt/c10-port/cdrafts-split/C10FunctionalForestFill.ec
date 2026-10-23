(* Positional forest rows and exact queried sets under the actual permutation. *)
require import AllCore List FMap.
require import C10RawOracle RawForest C10OuterCallerBridge C10FixedBackend C10FunctionalBuildHistory.
require import C10FunctionalForestOne.

op forest_covered ['a] (default : 'a) n (values : 'a list) (value : int -> 'a) order visited =
  size values = n /\ forall j, j \in take visited order => nth default values j = value j.

lemma forest_covered_zero ['a] (default : 'a) n value order : 0 <= n =>
  forest_covered default n (nseq n default) value order 0.
proof. move=> hn; rewrite /forest_covered size_nseq take0; smt(). qed.

lemma forest_covered_next ['a] (default : 'a) n values value order visited :
  12 <= n => perm_eq order (range 0 12) => 0 <= visited < 12 =>
  forest_covered default n values value order visited =>
  forest_covered default n (put values (nth 0 order visited) (value (nth 0 order visited))) value order (visited+1).
proof.
  move=> hn hp hv [hs he].
  have hlen : size order = 12 by smt(perm_eq_size size_range).
  have hi := outer_shuffle_index order visited 12 hp hv.
  rewrite /forest_covered size_put hs /= (take_nth 0 visited order) 1:/#.
  move=> j hj; rewrite nth_put 1:/#; move: hj; rewrite mem_rcons; smt().
qed.

lemma forest_covered_complete ['a] (default : 'a) values value order :
  perm_eq order (range 0 12) => forest_covered default 12 values value order 12 =>
  values = mkseq value 12.
proof.
  move=> hp [hs he].
  have hlen : size order = 12 by smt(perm_eq_size size_range).
  have ht : take 12 order = order by rewrite -hlen take_size.
  apply (eq_from_nth default); first by rewrite hs size_mkseq.
  move=> j hj; rewrite nth_mkseq 1:/#; apply he; rewrite ht; smt(perm_eq_mem mem_range).
qed.

lemma forest_covered_last ['a] (default : 'a) values value order final_value :
  perm_eq order (range 0 12) => forest_covered default 13 values value order 12 =>
  put values 12 final_value = mkseq value 12 ++ [final_value].
proof.
  move=> hp [hs he].
  have hlen : size order = 12 by smt(perm_eq_size size_range).
  have ht : take 12 order = order by rewrite -hlen take_size.
  apply (eq_from_nth default); first by rewrite size_put hs size_cat size_mkseq /=.
  move=> j hj; have hj13 : 0 <= j < 13 by move: hj; rewrite size_put hs.
  rewrite nth_put 1:/# nth_cat size_mkseq /=.
  case (j = 12) => hj12; first by rewrite hj12 /=.
  have hjb : 0 <= j < 12 by smt().
  have hjm : j \in take 12 order by rewrite ht; smt(perm_eq_mem mem_range).
  have hv := he j hjm.
  by rewrite (_ : j < 12) 1:/# nth_mkseq 1:hjb; smt().
qed.

op functional_forest_visited f key seed ht (d : digest) (order : int list) visited x =
  exists t, t \in take visited order /\ functional_forest_one_queried f key seed ht t (forest_index d t) x.
op functional_forest_normal_queried f key seed ht (d : digest) x =
  exists t, 0 <= t < 12 /\ functional_forest_one_queried f key seed ht t (forest_index d t) x.

lemma functional_forest_visited_zero f key seed ht d order x :
  !functional_forest_visited f key seed ht d order 0 x.
proof. rewrite /functional_forest_visited take0; smt(). qed.

lemma functional_forest_visited_next f key seed ht d order visited x : 0 <= visited < size order =>
  functional_forest_visited f key seed ht d order (visited+1) x <=>
    functional_forest_visited f key seed ht d order visited x \/
      functional_forest_one_queried f key seed ht (nth 0 order visited)
        (forest_index d (nth 0 order visited)) x.
proof. move=> hv; rewrite /functional_forest_visited (take_nth 0 visited order hv); smt(mem_rcons). qed.

lemma functional_forest_visited_complete f key seed ht d order x : perm_eq order (range 0 12) =>
  functional_forest_visited f key seed ht d order 12 x <=> functional_forest_normal_queried f key seed ht d x.
proof.
  move=> hp; have hlen : size order = 12 by smt(perm_eq_size size_range).
  rewrite /functional_forest_visited -hlen take_size /functional_forest_normal_queried;
    smt(perm_eq_mem mem_range).
qed.

lemma functional_forest_history_initial f history key seed ht d order :
  functional_history_exact f history history (functional_forest_visited f key seed ht d order 0).
proof. rewrite /functional_history_exact; smt(functional_forest_visited_zero). qed.

lemma functional_forest_history_complete f initial history key seed ht d order :
  perm_eq order (range 0 12) =>
  functional_history_exact f initial history (functional_forest_visited f key seed ht d order 12) =>
  functional_history_exact f initial history (functional_forest_normal_queried f key seed ht d).
proof. rewrite /functional_history_exact; smt(functional_forest_visited_complete). qed.

lemma functional_forest_history_step f initial middle final key seed ht d order visited :
  0 <= visited < size order =>
  functional_history_exact f initial middle (functional_forest_visited f key seed ht d order visited) =>
  functional_history_exact f middle final (functional_forest_one_queried f key seed ht
    (nth 0 order visited) (forest_index d (nth 0 order visited))) =>
  functional_history_exact f initial final (functional_forest_visited f key seed ht d order (visited+1)).
proof.
  move=> hv hm hf.
  have hc := functional_history_compose f initial middle final _ _ hm hf.
  move: hc; rewrite /functional_history_exact; smt(functional_forest_visited_next).
qed.
