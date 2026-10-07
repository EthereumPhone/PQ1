(* A real two-call adapter program; the mutant changes only its count claim. *)
require import AllCore List.
require import C10RawOracle PrefixGuess RoleGrindCost TargetAdapterCost.
module AdapterTwoHashes = {
 proc run(x : raw_input) : unit = {
  var d; d <@ IdealPrefix.hash(x); d <@ IdealPrefix.hash(x);
 }
}.
lemma adapter_public_calls_count :
 hoare [AdapterTwoHashes.run : Independent.queries=[] ==> size Independent.queries=1].
proof.
 proc; call (independent_hash_count 1); call (independent_hash_count 0); by auto.
qed.
