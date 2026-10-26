require import AllCore List Distr IntDiv.
require import C10RawOracle C10RawGrind C10Randomizer C10HashDomains PrefixGuess PrefixHybrid.
require import RawKeygen RawForest RawLayer RawSigner RoleGrind IndependentWidths NodeQueryDomain.
require import AddressedForsException AddressedForsExceptionCount AddressedShuffleExceptions.
require import AddressedForestExceptionCount AddressedWotsExceptionCount AddressedLayerExceptionCount.
require import AddressedSignerExceptionCount.
lemma checked q :
  hoare [RawSigner(Independent).sign :
    size seed=32 /\ size root=32 /\ size message=32 /\ size shuffle=32 /\
    exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    exceptional_fors_count Independent.queries=q+2 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof. exact (raw_signer_sign_exception_bound q). qed.
