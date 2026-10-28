require import AllCore List Distr FMap.
require import C10RawOracle RawWots C10Randomizer C10RawGrind PrefixGuess PrefixHybrid.
require import IndependentWidths WotsAcceptedDistribution WotsAcceptedPrefix WotsCountDomain WotsMemoOracle.
require import WotsMemoFacts.
lemma checked c marked :
  hoare [WotsMemo(WotsAcceptedSamples).hash : WotsMemo.accepted_calls=c /\ (wots_count_query x)=marked ==>
    WotsMemo.accepted_calls=c].
proof. exact (wots_hash_count c marked). qed.
