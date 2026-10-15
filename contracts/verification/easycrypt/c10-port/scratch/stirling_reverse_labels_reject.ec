require import AllCore List StdOrder.
require import ReverseGrowthEncoding.


lemma checked : reverse_labels [7;3;7]=[1;0;1].
proof.
  have h : reverse_labels [7;3;7]=[0;1;0] by rewrite /reverse_labels /=.
  exact h.
qed.
