require import AllCore List Distr.
require FORS_C10.
clone import FORS_C10.FORSC10 as F.
lemma checked_bounded_r_conditioned_mixture (m : msg) (fuel : unit list)
  (event : mkey option -> bool) :
  mu (bounded_r m fuel) event =
    (1%r - mu dmkey (good m)) ^ size fuel * b2r (event None) +
    (1%r - (1%r - mu dmkey (good m)) ^ size fuel) *
      mu (dcond dmkey (good m)) (fun r => event (Some r)).
proof. exact bounded_r_conditioned_mixture. qed.
