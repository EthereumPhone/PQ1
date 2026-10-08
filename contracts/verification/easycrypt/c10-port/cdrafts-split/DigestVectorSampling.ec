(* Explicit eight-digest sampling agrees with the standard independent-list distribution. *)
require import AllCore List Distr DList.
require import C10RawOracle C10Randomizer.
clone import DList.Program as FullDigestLists with
  type t <- digest, op d <- full_digest proof *.
module EightDigests = {
  proc sample() : digest list = {
    var d0,d1,d2,d3,d4,d5,d6,d7;
    d0 <$ full_digest;
    d1 <$ full_digest;
    d2 <$ full_digest;
    d3 <$ full_digest;
    d4 <$ full_digest;
    d5 <$ full_digest;
    d6 <$ full_digest;
    d7 <$ full_digest;
    return [d0;d1;d2;d3;d4;d5;d6;d7];
  }
}.
module LoopEightDigests = {
  proc sample() : digest list = {
    var values; values <@ FullDigestLists.LoopSnoc.sample(8); return values;
  }
}.
module ListEightDigests = {
  proc sample() : digest list = {
    var values; values <@ FullDigestLists.Sample.sample(8); return values;
  }
}.
lemma eight_digests_loop :
  equiv [EightDigests.sample ~ LoopEightDigests.sample : true ==> ={res}].
proof.
  proc; inline FullDigestLists.LoopSnoc.sample.
  cfold{2} 1.
  swap{2} 1 1.
  unroll for{2} 3.
  auto=> />.
qed.
lemma eight_loop_list :
  equiv [LoopEightDigests.sample ~ ListEightDigests.sample : true ==> ={res}].
proof. symmetry; proc; call FullDigestLists.Sample_LoopSnoc_eq; auto. qed.

lemma eight_digests_list :
  equiv [EightDigests.sample ~ ListEightDigests.sample : true ==> ={res}].
proof.
  transitivity LoopEightDigests.sample (true ==> ={res}) (true ==> ={res}) => //.
  + exact eight_digests_loop.
  exact eight_loop_list.
qed.
