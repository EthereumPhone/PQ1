(* Ordinary FORS openings occur only after the wrapper's final release guard.
   Both internal signing attempts still execute public construction and WOTS
   work. The projection retains refusal/retry semantics and both oracle maps. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawForest RawSigner RawWrapper.
require import ForsLeafView MerkleRootWitness WrapperForestMemo WrapperForestRelease.
require import WrapperSigningPlan WrapperPlanSigner WrapperPlanComparison WrapperInternalVerify.

module WrapperReleasedFors (O : PrefixOracle) (F : ForsLeafOracle) = {
  proc sign(seed root random message shuffle_a shuffle_b : raw_input,
            ready final_guard : bool) : raw_signature option = {
    var first, second, secrets, result;
    result <- None;
    if (ready) {
      first <@ WrapperPlanSigner(O,F).sign(seed,root,random,message,shuffle_a);
      if (first<>None) {
        second <@ WrapperPlanSigner(O,F).sign(seed,root,random,message,shuffle_b);
        if (second<>None /\ wrapper_plan_equal (oget first) (oget second)) {
          if (!final_guard) {
            secrets <@ WrapperForestRelease(F).values(hypertree_index (oget first).`2,(oget first).`2,(oget first).`3);
            result <- Some ((oget first).`1,secrets,(oget first).`4,(oget first).`5);
          }
        }
      }
    }
    return result;
  }
}.

