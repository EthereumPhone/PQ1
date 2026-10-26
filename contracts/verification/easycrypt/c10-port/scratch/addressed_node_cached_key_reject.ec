require import AllCore List FSet FMap.
require import C10RawOracle AddressedNodeCollision AddressedBuckets AddressedMemoCount AddressedControlFacts AddressedForsException AddressedForsExceptionCount.
lemma checked : addressed_excess empty.[control_key0<-control_digest].[control_key0<-control_digest]=1.
proof. exact control_cached_key. qed.
