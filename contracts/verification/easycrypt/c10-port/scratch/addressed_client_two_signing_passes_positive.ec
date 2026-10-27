require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawSigner RawWrapper IndependentWidths VerifierHistory WrapperExposureWidths.
require import AddressedMemoCount AddressedMemoCalls.
require import AddressedWrapperMemoCalls.
lemma checked seed0 q :
  hoare [RawWrapper(Independent).sign :
    seed=seed0 /\ size seed0=32 /\ size root=32 /\ size message=32 /\
    size shuffle_a=32 /\ size shuffle_b=32 /\
    nonordinary_count Independent.rawhistory Independent.secrethistory seed0<=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    nonordinary_count Independent.rawhistory Independent.secrethistory seed0<=q+775 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof. exact (nonordinary_wrapper_valid_count seed0 q). qed.
