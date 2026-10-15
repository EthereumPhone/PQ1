require import AllCore List StdOrder.
require import RestrictedGrowthWords ReverseGrowthEncoding.


lemma checked : mem (exact_growth_words 12 12) (reverse_labels (range 0 12)).
proof.
  have h:=reverse_labels_enumerated (range 0 12).
  rewrite undup_id 1:range_uniq size_range /= in h.
  exact h.
qed.
