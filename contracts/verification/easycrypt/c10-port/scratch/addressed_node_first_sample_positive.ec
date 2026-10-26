require import AllCore List FSet FMap.
require import C10RawOracle AddressedNodeCollision AddressedBuckets AddressedMemoCount AddressedControlFacts AddressedForsException AddressedForsExceptionCount.
lemma checked : !(1<=addressed_excess empty.[control_key0<-control_digest]).
proof. exact control_first_sample_no_excess. qed.
