require import AllCore List Distr.
require import C10BoundedIID C10BoundedGrind C10DeployedInstance SharedROBounded C10Encoding WOTS_C_Real.
import SPHINCS_PLUS FSSLXMTWES FSSLXMTWES.WTWES C10Counter.
require import C10SharedSearch.

lemma checked_shared_history_exhaustion (seed address : int list) (m : dgstblock)
  (history : (int list * msgWOTS) list) :
  mu1 (shared_search seed address m history) None <=
    (1%r - acceptance) ^ fresh_count history (counter_inputs seed address m).
proof. exact shared_history_exhaustion. qed.
