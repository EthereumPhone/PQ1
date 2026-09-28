(* Proof observer exposing the actual FORS tree stack; exact projection below. *)
require import AllCore List Distr IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors DyadicStack StackProjection StackPowers.

module ForsBuildWitness (O : PreparationOracle) = {
  proc tree(seed : raw_input, ht tree target : int) : (raw_input * int) list * raw_input list = {
    var j, current, height, stack, sibling, parent, d, auth, target_h, sibidx, left_start, right_start;
    j <- 0; stack <- []; auth <- nseq 11 (nseq 16 0);
    while (j < 2048) {
      d <@ O.fors(fors_tail ht tree j);
      current <- node d;
      d <@ O.hash(seed ++ address 0 ht 3 tree 0 0 j ++ pad current);
      current <- node d; height <- 0;
      while (stack <> [] /\ (head ([],0) stack).`2 = height) {
        sibling <- (head ([],0) stack).`1;
        stack <- behead stack;
        parent <- j %/ (2^(height+1));
        target_h <- target %/ (2^height);
        sibidx <- sibling_index target_h;
        left_start <- parent * (2^(height+1));
        right_start <- left_start + 2^height;
        if (sibidx %% 2 = 0) {
          if (sibidx * (2^height) = left_start) { auth <- put auth height sibling; }
        } else {
          if (sibidx * (2^height) = right_start) { auth <- put auth height current; }
        }
        d <@ O.hash(seed ++ address 0 ht 3 tree 0 (height+1) parent ++ pad sibling ++ pad current);
        current <- node d; height <- height+1;
      }
      stack <- (current,height)::stack; j <- j+1;
    }
    return (stack,auth);
  }
}.

lemma fors_tree_witness_projection (O <: PreparationOracle) :
  equiv [RawFors(O).tree ~ ForsBuildWitness(O).tree :
    ={seed,ht,tree,target,glob O} ==>
    res{1} = ((head (nseq 16 0,0) res{2}.`1).`1, res{2}.`2) /\ ={glob O}].
proof.
  proc; while (={seed,ht,tree,target,j,stack,auth,glob O}).
  + wp; while (={seed,ht,tree,target,j,current,height,stack,auth,glob O}).
    - wp; call (_ : ={arg,glob O} ==> ={res,glob O}).
      + by sim.
      auto.
    wp; call (_ : ={arg,glob O} ==> ={res,glob O}).
    - by sim.
    wp; call (_ : ={arg,glob O} ==> ={res,glob O}).
    - by sim.
    auto.
  auto.
qed.

lemma fors_tree_stack_height (O <: PreparationOracle) :
  hoare [ForsBuildWitness(O).tree : true ==>
    map snd res.`1 = [11]].
proof.
  proc; while (0 <= j <= 2048 /\ increasing_stack (map snd stack) /\
    stack_mass (map snd stack) = j).
  + wp; while (0 <= j < 2048 /\ active_stack (map snd stack) height /\
      stack_mass (map snd stack) + 2^height = j+1).
    - wp; call (_ : true ==> true); first by trivial.
      auto; smt(projected_carry_pop).
    wp; call (_ : true ==> true); first by trivial.
    wp; call (_ : true ==> true); first by trivial.
    auto; rewrite expr0.
    move=> &hr hi; split; first by smt(carry_initial).
    move=> h st hx [hj [ha hm]].
    have hp := projected_carry_push st [] [] h ha _; first by smt().
    move: hp; rewrite /=; smt().
  auto; smt(stack_power_singleton stack_pow2_11).
qed.
