require import AllCore List Distr StdOrder.
require import BoundedIID.
import RField RealOrder.
require import SharedROBounded DBool BoundedIID.

lemma checked_history_search_exhaustion ['x 'y] (d : 'y distr) (p : 'y -> bool)
  (inputs : 'x list) :
  is_lossless d => uniq inputs => forall (history : ('x * 'y) list),
  mu1 (ro_search d p history inputs) None <=
    (1%r - mu d p) ^ fresh_count history inputs.
proof. exact history_search_exhaustion. qed.

lemma cached_failure : mu1 (ro_search dbool idfun [(0,false)] [0]) None = 1%r.
proof. by rewrite replay_failed_answer 1:// dunit1E. qed.
lemma repeated_input_replays : ro_search dbool idfun [] [0;0] = bounded dbool idfun [tt].
proof.
  rewrite /ro_search /bounded /= !assoc_nil ?assoc_cons /=.
  apply eq_dlet => // b.
  by case: b.
qed.
lemma repeated_input_one_trial : mu1 (ro_search dbool idfun [] [0;0]) None = 1%r/2%r.
proof. by rewrite repeated_input_replays bounded_exhaustion 1:dbool_ll /= dboolE /idfun /= RField.expr1. qed.
