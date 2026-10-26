require import AllCore List FMap IntDiv.
require import C10RawOracle C10RawGrind C10Randomizer C10HashDomains PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawForest RawLayer RawSigner RoleGrind IndependentWidths NodeQueryDomain RawCompositeWidths SignerCoordinates.
require import AddressedOrdinaryInputs AddressedOrdinaryHistory AddressedOrdinaryForest AddressedOrdinaryLayer.
require import AddressedForsExceptionCount AddressedForestExceptionCount BuilderTotality AddressedCoordinateBounds.
require import AddressedOrdinarySigner.
lemma checked seed0 old :
  hoare [RawSigner(Independent).sign :
    seed=seed0 /\ size seed0=32 /\ size root=32 /\ size message=32 /\ size shuffle=32 /\
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    res<>None /\ ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof. exact (raw_signer_sign_ordinary_inputs seed0 old). qed.
