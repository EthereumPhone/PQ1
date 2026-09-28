(* Adaptive birthday accounting for the 16-byte projection of full draws. *)
require import AllCore List Distr Ring StdRing StdOrder StdBigop FelTactic.
require import C10RawOracle C10Randomizer RawKeygen NodeDistribution.
import RField IntOrder RealOrder.

module ProjectedSamples = {
  var nodes : raw_input list
  proc init() : unit = { nodes <- []; }
  proc sample() : digest = {
    var d;
    d <$ full_digest;
    nodes <- node d :: nodes;
    return d;
  }
}.
module type ProjectedSampler = { proc sample() : digest }.
module type ProjectedClient (S : ProjectedSampler) = { proc run() : unit { S.sample } }.
module ProjectedGame (A : ProjectedClient) = {
  proc run() : unit = { ProjectedSamples.init(); A(ProjectedSamples).run(); }
}.

lemma projected_sample_lossless : islossless ProjectedSamples.sample.
proof. proc; auto; smt(full_digest_ll). qed.

lemma projected_birthday (A <: ProjectedClient {-ProjectedSamples}) q &m :
  0<=q =>
  Pr[ProjectedGame(A).run() @ &m : size ProjectedSamples.nodes<=q /\ !uniq ProjectedSamples.nodes] <=
    (q*(q-1))%r/2%r*(1%r/2%r)^128.
proof.
  move=> hq.
  fel 1 (size ProjectedSamples.nodes) (fun x => x%r*(1%r/2%r)^128) q (!uniq ProjectedSamples.nodes) [] => //.
  + rewrite -Bigreal.BRA.mulr_suml Bigreal.sumidE 1:hq; smt().
  + by inline*; auto.
  + proc; wp; rnd (fun d => mem ProjectedSamples.nodes (node d)); skip => // /> &hr ???.
    exact (node_history_mass ProjectedSamples.nodes{hr}).
  by move=> c; proc; auto=> /#.
qed.
