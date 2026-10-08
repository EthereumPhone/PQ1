(* Adaptive birthday accounting for the low 129 encoding bits of full draws. *)
require import AllCore List Distr Ring StdRing StdOrder StdBigop FelTactic.
require import C10RawOracle C10Randomizer RawKeygen WotsDigitOrder EncodingDistribution.
import RField IntOrder RealOrder.

module EncodingSamples = {
  var nodes : digest list
  proc init() : unit = { nodes <- []; }
  proc sample() : digest = {
    var d;
    d <$ full_digest;
    nodes <- encoding_bits d :: nodes;
    return d;
  }
}.
module type EncodingSampler = { proc sample() : digest }.
module type EncodingClient (S : EncodingSampler) = { proc run() : unit { S.sample } }.
module EncodingGame (A : EncodingClient) = {
  proc run() : unit = { EncodingSamples.init(); A(EncodingSamples).run(); }
}.

lemma encoding_projected_sample_lossless : islossless EncodingSamples.sample.
proof. proc; auto; smt(full_digest_ll). qed.

lemma encoding_projected_birthday (A <: EncodingClient {-EncodingSamples}) q &m :
  0<=q =>
  Pr[EncodingGame(A).run() @ &m : size EncodingSamples.nodes<=q /\ !uniq EncodingSamples.nodes] <=
    (q*(q-1))%r/2%r*(1%r/2%r)^129.
proof.
  move=> hq.
  fel 1 (size EncodingSamples.nodes) (fun x => x%r*(1%r/2%r)^129) q (!uniq EncodingSamples.nodes) [] => //.
  + rewrite -Bigreal.BRA.mulr_suml Bigreal.sumidE 1:hq; smt().
  + by inline*; auto.
  + proc; wp; rnd (fun d => mem EncodingSamples.nodes (encoding_bits d)); skip => // /> &hr ???.
    exact (encoding_history_mass EncodingSamples.nodes{hr}).
  by move=> c; proc; auto=> /#.
qed.
