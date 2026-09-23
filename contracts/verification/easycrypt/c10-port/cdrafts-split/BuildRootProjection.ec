(* Authentication bookkeeping preserves the actual key-generation root and
   all oracle effects, for every target index. *)
require import AllCore List.
require import C10RawOracle KeygenPrefixes RawKeygen RawMerkle.

lemma merkle_build_root_projection (O <: PreparationOracle) :
  equiv[RawKeygen(O).root ~ RawMerkle(O).build :
    ={seed,layer,tree,glob O} ==>
    res{1} = res{2}.`2 /\ ={glob O}].
proof.
  proc; while (={seed,layer,tree,kp,stack,glob O}).
  + wp; while (={seed,layer,tree,kp,current,height,stack,glob O}).
    - wp; call (_ : ={arg,glob O} ==> ={res,glob O}).
      + by sim.
      auto.
    wp; call (_ : ={arg,glob O} ==> ={res,glob O}).
    - by sim.
    auto.
  auto.
qed.
