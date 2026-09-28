require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors RawSignature.
require import PathReplay RawForsPathReplay ForsPrivateLeaves.
require import ForsBuilderPrivate ForsKnownSecret ForsSignWitness ForsSignCorrect ForsSignRecord.

module SignRecoverFirst = {
  proc run() : (raw_input * raw_input list) * raw_input * raw_input = {
    var result;
    result <@ ForsObservedSignRecover(PreparationView(Independent)).run(nseq 32 0,0,0,0);
    return result;
  }
}.
lemma real_signature_recovers_internal_root :
  phoare [SignRecoverFirst.run : true ==>
    size res.`1.`1 = 16 /\ rows_width 11 res.`1.`2 /\ res.`2 = res.`3] = 1%r.
proof.
  proc; call (total_fors_observed_sign_correct (nseq 32 0) 0 0 0); auto.
qed.
