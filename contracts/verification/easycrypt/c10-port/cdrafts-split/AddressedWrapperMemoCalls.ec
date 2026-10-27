(* Actual wrapper calls retain one persistent oracle history. Each signing
   pass adds at most two exceptional keys; internal verification is conservatively
   charged its complete existing 771-call bound, including withheld results. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawSigner RawWrapper IndependentWidths VerifierHistory WrapperExposureWidths.
require import AddressedMemoCount AddressedMemoCalls.

lemma nonordinary_verifier_valid_count seed0 q :
  hoare [RawSigner(Independent).verify :
    nonordinary_count Independent.rawhistory Independent.secrethistory seed0<=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    nonordinary_count Independent.rawhistory Independent.secrethistory seed0<=q+771 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  conseq (nonordinary_verifier_count seed0 q) (wrapper_verifier_valid RawSigner); smt().
qed.

lemma nonordinary_wrapper_valid_count seed0 q :
  hoare [RawWrapper(Independent).sign :
    seed=seed0 /\ size seed0=32 /\ size root=32 /\ size message=32 /\
    size shuffle_a=32 /\ size shuffle_b=32 /\
    nonordinary_count Independent.rawhistory Independent.secrethistory seed0<=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    nonordinary_count Independent.rawhistory Independent.secrethistory seed0<=q+775 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  proc; sp 1; if; last by auto; smt().
  seq 1 : (seed=seed0 /\ size seed0=32 /\ size root=32 /\ size message=32 /\
    size shuffle_b=32 /\
    nonordinary_count Independent.rawhistory Independent.secrethistory seed0<=q+2 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory).
  + call (nonordinary_signer_valid_count seed0 q); auto.
  if; last by auto; smt().
  seq 1 : (nonordinary_count Independent.rawhistory Independent.secrethistory seed0<=q+4 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory).
  + call (nonordinary_signer_valid_count seed0 (q+2)); auto; smt().
  if; last by auto; smt().
  wp; call (nonordinary_verifier_valid_count seed0 (q+4)); auto; smt().
qed.
