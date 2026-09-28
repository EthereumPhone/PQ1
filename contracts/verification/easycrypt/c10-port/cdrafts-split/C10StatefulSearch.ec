(* A persistent-history refinement of the existing finite shared-oracle search. *)
require import AllCore List Distr SharedROBounded.

(* Persistent history version of SharedROBounded. Each invocation returns its
   final table, including a successful fresh answer, for the next invocation. *)

op search_state ['x 'y] (d : 'y distr) (p : 'y -> bool)
  (history : ('x * 'y) list) (inputs : 'x list) : ('y option * ('x * 'y) list) distr =
  with inputs = [] => dunit (None,history)
  with inputs = x :: rest =>
    if assoc history x <> None then
      if p (oget (assoc history x)) then dunit (assoc history x,history)
      else search_state d p history rest
    else dlet d (fun y => if p y then dunit (Some y,(x,y)::history)
      else search_state d p ((x,y)::history) rest).

lemma result_projection ['x 'y] (d : 'y distr) (p : 'y -> bool)
  (inputs : 'x list) : forall (history : ('x * 'y) list),
  dmap (search_state d p history inputs) fst = ro_search d p history inputs.
proof.
  elim: inputs => [|x xs ih] history /=; first by rewrite dmap_dunit.
  case (assoc history x <> None) => hk /=.
  + by case (p (oget (assoc history x))) => hp /=; rewrite ?dmap_dunit ?ih.
  rewrite dmap_dlet; apply eq_dlet => // y.
  by case (p y) => hp; rewrite hp /= ?dmap_dunit ?ih.
qed.

lemma repeated_success ['x 'y] (d : 'y distr) (p : 'y -> bool)
  (history : ('x * 'y) list) (x : 'x) (y : 'y) :
  assoc history x = Some y => p y =>
  search_state d p history [x] = dunit (Some y,history).
proof. by move=> hy hp; rewrite /search_state /= hy /= ?hp. qed.

lemma repeated_failure ['x 'y] (d : 'y distr) (p : 'y -> bool)
  (history : ('x * 'y) list) (x : 'x) (y : 'y) :
  assoc history x = Some y => !p y =>
  search_state d p history [x] = dunit (None,history).
proof. by move=> hy hp; rewrite /search_state /= hy /= ?hp. qed.
