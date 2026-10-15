require import AllCore List Distr FMap StdOrder.
require import C10Randomizer RawWots WotsAcceptanceMass.

lemma checked : mu full_digest count_accepts=wots_acceptance_mass.
proof.
  exact raw_wots_acceptance_mass.
qed.
