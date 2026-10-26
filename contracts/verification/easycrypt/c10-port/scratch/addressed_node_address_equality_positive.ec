require import AllCore List FMap.
require import C10RawOracle RawKeygen NodeQueryDomain PersistentGrind AcceptedContexts ForsInputSeparation.
require import AddressedNodeCollision AddressedInputFields AddressedInputKinds AddressedForsException.
require import AddressedWotsCanonicity AddressedMerkleCanonicity AddressedTreeLog AddressedForsCanonicity AddressedForestCanonicity.
require import AddressedOrdinaryInputs.
lemma checked h s seed x y :
  size seed=32 => node_query x => node_query y =>
  ordinary_public_input h s seed x => ordinary_public_input h s seed y =>
  same_node_address x y => x=y.
proof. exact (ordinary_public_node_unique h s seed x y). qed.
