require import AllCore List Distr DBool BoundedIID.
import RField.
lemma exhaustion : mu1 (bounded dbool idfun [tt]) None = 0%r.
proof. by rewrite bounded_exhaustion 1:dbool_ll /= dboolE /idfun /= expr1. qed.
lemma success : mu (bounded dbool idfun [tt]) (fun r => r <> None) = 1%r/2%r.
proof. by rewrite bounded_step dboolE /= /bounded dunitE. qed.
