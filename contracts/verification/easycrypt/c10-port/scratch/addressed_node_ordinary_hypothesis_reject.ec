require import AllCore List FSet FMap.
require import C10RawOracle NodeQueryDomain AddressedNodeCollision.
require import AddressedOrdinaryInputs AddressedMemoCount.
require import AddressedBuckets.
lemma checked h s seed :
  addressed_excess h<=nonordinary_count h s seed.
proof. exact (addressed_excess_bound h s seed). qed.
