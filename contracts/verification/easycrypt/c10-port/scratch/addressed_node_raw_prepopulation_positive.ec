require import AllCore List FSet FMap.
require import C10RawOracle AddressedNodeCollision AddressedBuckets AddressedMemoCount AddressedControlFacts AddressedForsException AddressedForsExceptionCount.
lemma checked s seed : size seed=32 => 1<=nonordinary_count control_memo s seed.
proof. exact (control_raw_prepopulation s seed). qed.
