(* Private collision observer over the unchanged independent memo oracle.
   The cap only gates its private flag/counter; every fresh call samples the
   original full_digest and every caller receives the original memo result. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10Randomizer RawKeygen PrefixGuess PrefixIdeal.
require import AddressedBuckets AddressedBucketHistory.

module AddressedAudit = {
  var rawhistory, secrethistory : (raw_input,digest) fmap
  var queries : raw_input list
  var bad : bool
  var calls, cap : int
  proc init(k : int) : unit = {
    rawhistory <- empty; secrethistory <- empty; queries <- [];
    bad <- false; calls <- 0; cap <- k;
  }
  proc hash(x : raw_input) : digest = {
    var hits, d;
    queries <- rcons queries x;
    if (x \notin rawhistory) {
      hits <- addressed_hits rawhistory (addressed_label x);
      d <$ full_digest;
      if (0<size hits /\ size hits<=cap) {
        bad <- bad \/ node d \in hits;
        calls <- calls+1;
      }
      rawhistory.[x] <- d;
    }
    return nseq 256 false;
  }
  proc derive(tail : raw_input) : digest = {
    var d;
    if (tail \notin secrethistory) { d <$ full_digest; secrethistory.[tail] <- d; }
    return oget secrethistory.[tail];
  }
}.

module AddressedAuditGame (A : PrefixContext) = {
  proc run(k : int) : bool = {
    var result;
    AddressedAudit.init(k); result <@ A(AddressedAudit).run();
    return result;
  }
}.

op addressed_audit_invariant h calls cap bad =
  calls<=addressed_excess h /\ (label_collision h => bad \/ oversized_bucket h cap).

