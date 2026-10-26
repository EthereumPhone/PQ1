require import AllCore List FSet FMap.
require import C10RawOracle AddressedNodeCollision AddressedBuckets AddressedMemoCount AddressedControlFacts AddressedForsException AddressedForsExceptionCount.
lemma checked : exceptional_fors_count [control_exception;control_exception]=1.
proof. exact control_two_exception_calls. qed.
