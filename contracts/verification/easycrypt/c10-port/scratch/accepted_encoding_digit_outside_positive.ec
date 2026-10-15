require import AllCore List Distr FMap StdOrder.
require import WotsAcceptanceMass.

lemma checked : !(8 \in digit_distribution).
proof.
  have h : !(8 \in digit_distribution) by rewrite digit_distribution_support.
  exact h.
qed.
