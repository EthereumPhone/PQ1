require import AllCore List Distr.
require FORS_C10.
clone import FORS_C10.FORSC10 as F.
lemma erased_exhaustion (m : msg) : mu1 (bounded_r m []) None = 0%r.
proof. by rewrite bounded_r_exhaustion /= RField.expr0. qed.
