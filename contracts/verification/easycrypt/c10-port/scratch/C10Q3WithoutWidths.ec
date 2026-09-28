require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawMerkle RawFors.
require import PathReplay PathOracle PathCollision PathInputs RawPathReplay RawForsPathReplay RecoveryHistory ForsLeafInputs RawPathComparison RawForsComparison.
lemma without_widths prefix left1 right1 left2 right2 :
  prefix ++ pad left1 ++ pad right1 = prefix ++ pad left2 ++ pad right2 =>
  (left1,right1) = (left2,right2).
proof. exact (padded_pair_injective prefix left1 right1 left2 right2). qed.
