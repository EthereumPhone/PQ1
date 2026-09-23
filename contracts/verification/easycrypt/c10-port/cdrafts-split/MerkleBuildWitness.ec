(* Proof observer exposing the actual builder stack; exact projection below. *)
require import AllCore List Distr IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawMerkle RawFors DyadicStack StackProjection StackPowers.

module MerkleBuildWitness (O : PreparationOracle) = {
  proc build(seed : raw_input, layer tree target : int) : raw_input list * (raw_input * int) list = {
    var kp, current, height, stack, left, parent, d, keep, kept, target_h, sibling_h, pair_start, left_idx, right_idx;
    kp <- 0; stack <- []; keep <- nseq 9 (nseq 16 0); kept <- nseq 9 false;
    while (kp < 512) {
      current <@ RawKeygen(O).leaf(seed,layer,tree,kp);
      height <- 0;
      while (stack <> [] /\ (head ([],0) stack).`2 = height) {
        left <- (head ([],0) stack).`1;
        stack <- behead stack;
        if (!nth false kept height) {
          target_h <- target %/ (2^height); sibling_h <- sibling_index target_h;
          pair_start <- (kp %/ (2^(height+1))) * (2^(height+1));
          left_idx <- pair_start %/ (2^height); right_idx <- left_idx+1;
          if (left_idx = sibling_h) {
            keep <- put keep height left; kept <- put kept height true;
          } else {
            if (right_idx = sibling_h) {
              keep <- put keep height current; kept <- put kept height true;
            }
          }
        }
        parent <- kp %/ (2^(height+1));
        d <@ O.hash(seed ++ address layer tree 2 0 0 (height+1) parent ++ pad left ++ pad current);
        current <- node d; height <- height+1;
      }
      stack <- (current,height)::stack; kp <- kp+1;
    }
    return (keep,stack);
  }
}.

lemma merkle_build_witness_projection (O <: PreparationOracle) :
  equiv [RawMerkle(O).build ~ MerkleBuildWitness(O).build :
    ={seed,layer,tree,target,glob O} ==>
    res{1} = (res{2}.`1, (head (nseq 16 0,0) res{2}.`2).`1) /\ ={glob O}].
proof.
  proc; while (={seed,layer,tree,target,kp,stack,keep,kept,glob O}).
  + wp; while (={seed,layer,tree,target,kp,current,height,stack,keep,kept,glob O}).
    - wp; call (_ : ={arg,glob O} ==> ={res,glob O}).
      + by sim.
      auto.
    wp; call (_ : ={arg,glob O} ==> ={res,glob O}).
    - by sim.
    auto.
  auto.
qed.

lemma merkle_build_stack_height (O <: PreparationOracle) :
  hoare [MerkleBuildWitness(O).build : true ==>
    map snd res.`2 = [9]].
proof.
  proc; while (0 <= kp <= 512 /\ increasing_stack (map snd stack) /\
    stack_mass (map snd stack) = kp).
  + wp; while (0 <= kp < 512 /\ active_stack (map snd stack) height /\
      stack_mass (map snd stack) + 2^height = kp+1).
    - wp; call (_ : true ==> true); first by trivial.
      auto; smt(projected_carry_pop).
    wp; call (_ : true ==> true); first by trivial.
    auto; rewrite expr0.
    move=> &hr hi; split; first by smt(carry_initial).
    move=> h st hx [hkp [ha hm]].
    have hp := projected_carry_push st [] [] h ha _; first by smt().
    move: hp; rewrite /=; smt().
  auto; smt(stack_power_singleton stack_pow2_9).
qed.
