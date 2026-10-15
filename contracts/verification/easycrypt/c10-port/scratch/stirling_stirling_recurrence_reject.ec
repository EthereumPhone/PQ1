require import AllCore List StdOrder.
require import RestrictedGrowthWords.


lemma checked : stirling 3 2=stirling 2 2+stirling 2 1.
proof.
  have h:=stirling_recurrence 2 2 _; first smt().
  exact h.
qed.
