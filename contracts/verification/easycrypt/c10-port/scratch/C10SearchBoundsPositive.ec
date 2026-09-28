require import AllCore List Distr StdOrder.
require import C10SharedSearch C10BoundedIID C10Encoding C10Surface SharedROBounded.
import RField RealOrder.
import SPHINCS_PLUS FSSLXMTWES FSSLXMTWES.WTWES.
require import C10SearchBounds.

lemma checked_shared_search_known_budget (seed address : int list) (m : dgstblock)
  (history : (int list * msgWOTS) list) :
  size (counter_inputs seed address m) -
    fresh_count history (counter_inputs seed address m) <= 5760 =>
  mu1 (shared_search seed address m history) None <= (1%r/2%r)^305.
proof. exact shared_search_known_budget. qed.
