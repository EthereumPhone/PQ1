(* A public hash retains every recorded linear prefix and its computed value. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen.
require import PersistentGrind AcceptedContexts LinearChain.

lemma hash_preserves_linear f initial indices value0 x0 :
  hoare [Independent.hash :
    linear_recorded Independent.rawhistory f initial indices /\
    linear_value Independent.rawhistory f initial indices = value0 /\ x = x0 ==>
    linear_recorded Independent.rawhistory f initial indices /\
    linear_value Independent.rawhistory f initial indices = value0 /\
    Independent.rawhistory.[x0] = Some res].
proof.
  proc; sp 1; if; auto;
    smt(linear_recorded_extends extends_insert get_set_sameE domE).
qed.

lemma hash_keeps_linear_value f initial indices value0 :
  hoare [Independent.hash :
    linear_recorded Independent.rawhistory f initial indices /\
    linear_value Independent.rawhistory f initial indices = value0 ==>
    linear_recorded Independent.rawhistory f initial indices /\
    linear_value Independent.rawhistory f initial indices = value0].
proof.
  proc; sp 1; if; auto; smt(linear_recorded_extends extends_insert).
qed.
