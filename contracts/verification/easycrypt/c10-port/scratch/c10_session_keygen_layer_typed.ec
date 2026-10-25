require import AllCore List FMap C10RawOracle RawKeygen KeygenPrefixes KeygenExhaustion C10Representation PreparedGrind C10FixedBackend C10FixedCallerBridge C10FunctionalWotsValue C10FunctionalBuildContracts C10FunctionalBuildHistory C10FunctionalMerkleBuildHistory C10PairedKeygen.

op functional_public_seed (public : digest) = pad_node (node public).

op functional_public_root (f : raw_input -> digest) (key : raw_input) (public : digest) =
  pad_node (merkle_root_value (interpreted_backend f) (functional_public_seed public) key 0 0).
