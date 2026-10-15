require import AllCore List Distr FMap StdOrder.
require import WotsAcceptanceMass.

lemma checked : mu1 digit_distribution 0=(1%r/2%r)^3.
proof.
  have h := digit_distribution_mass 0 _; first done.
  exact h.
qed.
