require import AllCore List FSet FMap.
require import C10RawOracle AddressedNodeCollision AddressedBuckets AddressedMemoCount AddressedControlFacts AddressedForsException AddressedForsExceptionCount.
lemma checked : addressed_label control_key0<>addressed_label control_key2.
proof. exact control_different_address. qed.
