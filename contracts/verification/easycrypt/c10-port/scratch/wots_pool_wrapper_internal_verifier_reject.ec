require import AllCore List Distr FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawKeygen RawSigner RawSignature.
require import RawWrapper WrapperSession WrapperExposureLog WrapperQueryDriver.
require import ExposureLog ClientQueryLog IndependentWidths.
require import WotsAcceptedPrefix WotsMemoOracle WotsMemoFacts HmsgShapes WotsCountShapes WotsKeygenCount WotsSignerCount WotsSessionCount.
require import WrapperWotsCount.
lemma checked c :
  hoare[RawWrapper(WotsMemo(WotsAcceptedSamples)).sign :
    size seed=32 /\ size shuffle_a=32 /\ size shuffle_b=32 /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ c<=WotsMemo.accepted_calls<=c+8 /\
    (res<>None => signature_width (oget res))].
proof. exact (wots_census_raw_wrapper_count c). qed.
