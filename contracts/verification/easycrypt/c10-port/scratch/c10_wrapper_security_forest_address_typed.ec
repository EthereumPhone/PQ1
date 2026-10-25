(* Materialization reads already recorded private nodes. This helper alone
   grants no release authority; its caller decides whether to return them. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawForest.
require import ForsPrivateLeaves ForsLeafView WrapperForestMemo WrapperForsPlan.

module WrapperForestRelease (F : ForsLeafOracle) = {
  proc values(ht : int, digest : digest, finalnode : raw_input) : raw_input list = {
    var t, secret, secrets;
    t <- 0; secrets <- [];
    while (t < 12) {
      secret <@ F.secret(ht,t+1,forest_index digest t);
      secrets <- rcons secrets secret; t <- t+1;
    }
    return rcons secrets finalnode;
  }
}.

