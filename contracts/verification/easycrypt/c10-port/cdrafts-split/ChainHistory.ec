(* Existing public and private entries survive the actual chain loop. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots.
require import PersistentGrind AcceptedContexts MonotoneHistory LinearChain LinearOracle.

lemma raw_chain_extends s0 h0 :
  hoare [RawWots(PreparationView(Independent)).chain :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc; while (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory).
  + wp; call (independent_hash_extends s0 h0); auto.
  auto.
qed.

lemma raw_chain_keeps_linear f initial indices value0 :
  hoare [RawWots(PreparationView(Independent)).chain :
    linear_recorded Independent.rawhistory f initial indices /\
    linear_value Independent.rawhistory f initial indices = value0 ==>
    linear_recorded Independent.rawhistory f initial indices /\
    linear_value Independent.rawhistory f initial indices = value0].
proof.
  proc; while (linear_recorded Independent.rawhistory f initial indices /\
    linear_value Independent.rawhistory f initial indices = value0).
  + wp; call (hash_keeps_linear_value f initial indices value0); auto.
  auto.
qed.
