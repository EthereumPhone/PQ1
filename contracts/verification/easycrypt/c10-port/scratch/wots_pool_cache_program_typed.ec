require import AllCore List Distr FMap DBool.
require import C10RawOracle RawWots C10Randomizer C10RawGrind PrefixGuess PrefixHybrid.
require import WotsAcceptanceMass WotsAcceptedDistribution WotsAcceptedPrefix WotsCountDomain.
import DBool.Biased.
require import WotsMemoOracle.
module CachedWotsControl (S : WotsAcceptedSampler) = {
  var rawhistory, secrethistory : (raw_input,digest) fmap
  var queries, accepted_keys : raw_input list
  var accepted_calls : int
  proc init() : unit = {
    rawhistory <- empty; secrethistory <- empty; queries <- []; accepted_keys <- []; accepted_calls <- 0;
  }
  proc hash(x : raw_input) : digest = {
    var d;
    queries <- rcons queries x;
    if (x \notin rawhistory) {
      if (wots_count_query x) { d <@ SplitWotsAcceptedDigest(S).sample(); }
      else { d <$ full_digest; }
      rawhistory.[x] <- d;
      if (wots_count_query x /\ count_accepts d) { accepted_keys <- rcons accepted_keys x; }
    }
    d <- oget rawhistory.[x];
    if (wots_count_query x /\ count_accepts d) { accepted_calls <- accepted_calls+0; }
    return d;
  }
  proc derive(tail : raw_input) : digest = {
    var d;
    if (tail \notin secrethistory) { d <$ full_digest; secrethistory.[tail] <- d; }
    return oget secrethistory.[tail];
  }
}.
