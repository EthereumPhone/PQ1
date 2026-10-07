(* The target oracle interface is internal to the original hash/sign byte client. *)
require import AllCore List.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion.
require import RawSigner FullSession ByteSession ExposureLog ClientQueryLog ClientQueryDriver.
require import ForsLeafView LeafForestView LeafSignerView LeafSessionView TargetOracleSplit.

module TargetPrefix (O : TargetOracle) = {
  proc hash = O.hash
  proc derive = O.derive
}.
module TargetLeaf (O : TargetOracle) = {
  proc hash = O.hash
  proc leaf = O.leaf
  proc secret = O.secret
}.
module ConcreteTarget (O : PrefixOracle) = {
  proc hash = O.hash
  proc derive = O.derive
  proc leaf = ConcreteForsLeaf(PreparationView(O)).leaf
  proc secret = ConcreteForsLeaf(PreparationView(O)).secret
}.
module TargetQueryContext (A : FullClient) (O : TargetOracle) = LeafQueryContext(A,TargetPrefix(O),TargetLeaf(O)).

lemma concrete_target_query_projection
  (A <: FullClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog})
  (O <: PrefixOracle {-A,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog}) :
  equiv [ConcreteLeafQueryContext(A,O).run ~ TargetQueryContext(A,ConcreteTarget(O)).run :
    ={glob A,glob O,glob FullLimits,glob KeygenInputs} ==>
    ={res,glob A,glob O,glob FullSession,glob ExposureLog,glob ClientQueryLog}].
proof. by sim. qed.

op ordinary_output_candidates (signature : raw_signature) =
  map (fun tree => nth (nseq 16 0) signature.`2 tree) (range 0 12).
lemma ordinary_output_candidates_size signature : size (ordinary_output_candidates signature)=12.
proof. by rewrite /ordinary_output_candidates size_map size_range /=. qed.

module TargetByteCandidates (A : ByteClient) (O : TargetOracle) = {
  proc run() : raw_input list = {
    var accepted, outputs;
    accepted <@ TargetQueryContext(ByteLift(A),O).run();
    outputs <- [];
    if (accepted) { outputs <- ordinary_output_candidates ClientQueryLog.output.`2; }
    return outputs;
  }
}.
module OriginalByteCandidates (A : ByteClient) (O : PrefixOracle) = {
  proc run() : raw_input list = {
    var accepted, outputs;
    accepted <@ ClientQueryContext(ByteLift(A),O).run();
    outputs <- [];
    if (accepted) { outputs <- ordinary_output_candidates ClientQueryLog.output.`2; }
    return outputs;
  }
}.
lemma target_byte_candidates_projection
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog})
  (O <: PrefixOracle {-A,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog}) :
  equiv [OriginalByteCandidates(A,O).run ~ TargetByteCandidates(A,ConcreteTarget(O)).run :
    ={glob A,glob O,glob FullLimits,glob KeygenInputs} ==>
    ={res,glob A,glob O,glob FullSession,glob ExposureLog,glob ClientQueryLog}].
proof.
  proc; wp.
  call (_ : ={glob A,glob O,glob FullLimits,glob KeygenInputs} ==>
    ={res,glob A,glob O,glob FullSession,glob ExposureLog,glob ClientQueryLog}).
  + transitivity ConcreteLeafQueryContext(ByteLift(A),O).run
      (={glob A,glob O,glob FullLimits,glob KeygenInputs} ==>
        ={res,glob A,glob O,glob FullSession,glob ExposureLog,glob ClientQueryLog})
      (={glob A,glob O,glob FullLimits,glob KeygenInputs} ==>
        ={res,glob A,glob O,glob FullSession,glob ExposureLog,glob ClientQueryLog}) => //.
    - smt().
    - exact (leaf_query_context_projection (ByteLift(A)) O).
    exact (concrete_target_query_projection (ByteLift(A)) O).
  auto; smt().
qed.
lemma target_byte_candidate_count
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog})
  (O <: TargetOracle {-A,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog}) :
  hoare [TargetByteCandidates(A,O).run : true ==> size res<=12].
proof.
  proc; wp; call (_ : true ==> true); first by trivial.
  auto; smt(ordinary_output_candidates_size).
qed.
