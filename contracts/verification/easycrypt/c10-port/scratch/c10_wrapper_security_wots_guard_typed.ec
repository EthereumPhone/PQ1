(* Chain-position interface for the complete release-guarded wrapper view.
   Internal plans request endpoints; signature positions are requested only
   after both plans agree and the final guard admits release. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawSigner RawWrapper.
require import MerkleRootWitness ChainValueView WrapperInternalVerify WrapperWotsRelease.
require import WrapperReleasedWots WrapperChainWotsPlanSigner.

module WrapperChainReleasedWots (O : ChainOracle) = {
  proc sign(seed root random message shuffle_a shuffle_b : raw_input,
            ready final_guard : bool) : raw_signature option = {
    var first, second, signature, result;
    result <- None;
    if (ready) {
      first <@ WrapperChainWotsPlanSigner(O).sign(seed,root,random,message,shuffle_a);
      if (first<>None) {
        second <@ WrapperChainWotsPlanSigner(O).sign(seed,root,random,message,shuffle_b);
        if (second<>None /\ first=second) {
          if (!final_guard) {
            signature <@ WrapperWotsRelease(O).run(seed,oget first);
            result <- Some signature;
          }
        }
      }
    }
    return result;
  }
}.

