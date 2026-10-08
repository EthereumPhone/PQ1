(* The trusted chain backend is hidden behind the original byte hash/sign interface. *)
require import AllCore List.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawSigner FullSession ByteSession ExposureLog ClientQueryLog ClientQueryDriver.
require import ChainValueView ChainSessionView.

op wots_output_candidates (signature : raw_signature) =
  flatten (map (fun layer => map (fun i => nth (nseq 16 0) (nth ([],0,[]) signature.`4 layer).`1 i)
    (range 0 43)) (range 0 2)).

lemma wots_output_candidates_size signature : size (wots_output_candidates signature)=86.
proof.
  rewrite /wots_output_candidates (size_flatten_ctt 43).
  + move=> row /mapP [layer [hl ->]]; by rewrite size_map size_range /=.
  by rewrite size_map size_range /=.
qed.
lemma wots_output_candidate_mem signature layer i :
  0<=layer<2 => 0<=i<43 =>
  mem (wots_output_candidates signature) (nth (nseq 16 0) (nth ([],0,[]) signature.`4 layer).`1 i).
proof.
  move=> hl hi; rewrite /wots_output_candidates -flattenP.
  exists (map (fun j => nth (nseq 16 0) (nth ([],0,[]) signature.`4 layer).`1 j) (range 0 43)).
  split.
  + rewrite mapP; exists layer; rewrite mem_range; smt().
  rewrite mapP; exists i; rewrite mem_range; smt().
qed.

module ChainByteCandidates (A : ByteClient) (O : ChainOracle) = {
  proc run() : raw_input list = {
    var accepted, outputs;
    accepted <@ ChainQueryContext(ByteLift(A),O).run();
    outputs <- [];
    if (accepted) { outputs <- wots_output_candidates ClientQueryLog.output.`2; }
    return outputs;
  }
}.
module OriginalWotsCandidates (A : ByteClient) (O : PrefixOracle) = {
  proc run() : raw_input list = {
    var accepted, outputs;
    accepted <@ ClientQueryContext(ByteLift(A),O).run();
    outputs <- [];
    if (accepted) { outputs <- wots_output_candidates ClientQueryLog.output.`2; }
    return outputs;
  }
}.
lemma chain_byte_candidates_projection
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog})
  (O <: PrefixOracle {-A,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog}) :
  equiv [OriginalWotsCandidates(A,O).run ~ ChainByteCandidates(A,ConcreteChain(O)).run :
    ={glob A,glob O,glob FullLimits,glob KeygenInputs} ==>
    ={res,glob A,glob O,glob FullSession,glob ExposureLog,glob ClientQueryLog}].
proof. proc; wp; call (chain_query_context_projection (ByteLift(A)) O); auto. qed.

lemma chain_byte_candidate_count
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog})
  (O <: ChainOracle {-A,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog}) :
  hoare [ChainByteCandidates(A,O).run : true ==> size res<=86].
proof.
  proc; wp; call (_ : true ==> true); first by trivial.
  auto; smt(wots_output_candidates_size).
qed.
