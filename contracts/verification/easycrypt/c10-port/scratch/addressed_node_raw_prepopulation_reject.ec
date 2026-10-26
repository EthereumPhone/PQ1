require import AllCore List FSet FMap.
require import C10RawOracle AddressedNodeCollision AddressedBuckets AddressedMemoCount AddressedControlFacts AddressedForsException AddressedForsExceptionCount.
lemma checked s seed : size seed=32 => nonordinary_count control_memo s seed=0.
proof. exact (control_raw_prepopulation s seed). qed.
