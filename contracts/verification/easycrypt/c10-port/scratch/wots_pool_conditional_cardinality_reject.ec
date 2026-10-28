require import AllCore List Distr DList DBool StdOrder Ring.
require import C10RawOracle C10RawGrind C10Randomizer RawWots WotsAcceptanceMass.
import RField RealOrder DBool.Biased.
require import WotsAcceptedDistribution.
lemma checked :
  accepted_word_mass=1%r/22169393903687611906220091621190389%r.
proof. exact accepted_word_mass_exact. qed.
