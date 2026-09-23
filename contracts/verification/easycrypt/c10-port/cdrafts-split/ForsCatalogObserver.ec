(* Private proof catalog for the actual FORS tree builder. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors.
require import ForsBuildWitness DyadicStack StackProjection StackAlignment NodeCatalog NodeCatalogDomain CatalogStack StackPowers.

module ForsCatalogObserver (O : PreparationOracle) = {
  proc tree(seed : raw_input, ht tree target : int) : (raw_input * int) list * raw_input list * node_catalog = {
    var j, current, height, stack, sibling, parent, d, auth, target_h, sibidx, left_start, right_start;
    var catalog;
    catalog <- empty; j <- 0; stack <- []; auth <- nseq 11 (nseq 16 0);
    while (j < 2048) {
      d <@ O.fors(fors_tail ht tree j);
      current <- node d;
      d <@ O.hash(seed ++ address 0 ht 3 tree 0 0 j ++ pad current);
      current <- node d; catalog <- catalog.[(0,j) <- current]; height <- 0;
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
        current <- node d; catalog <- catalog.[(height+1,parent) <- current]; height <- height+1;
      }
      stack <- (current,height)::stack; j <- j+1;
    }
    return (stack,auth,catalog);
  }
}.

lemma fors_catalog_projection (O <: PreparationOracle) :
  equiv [ForsBuildWitness(O).tree ~ ForsCatalogObserver(O).tree :
    ={seed,ht,tree,target,glob O} ==>
    res{1} = (res{2}.`1, res{2}.`2) /\ ={glob O}].
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

lemma fors_catalog_complete (O <: PreparationOracle) :
  hoare [ForsCatalogObserver(O).tree : true ==>
    catalog_exact res.`3 2048 /\ map snd res.`1 = [11]].
proof.
  proc; while (0 <= j <= 2048 /\ increasing_stack (map snd stack) /\
    stack_mass (map snd stack) = j /\ catalog_exact catalog j).
  + wp; while (0 <= j < 2048 /\ active_stack (map snd stack) height /\
      stack_mass (map snd stack) + 2^height = j+1 /\
      catalog_partial catalog (j+1) height).
    - wp; call (_ : true ==> true); first by trivial.
      auto; move=> &hr hi.
      have hp := projected_catalog_pop stack{hr} [] height{hr} (j{hr}+1) catalog{hr}.
      smt().
    wp; call (_ : true ==> true); first by trivial.
    wp; call (_ : true ==> true); first by trivial.
    auto; rewrite expr0.
    move=> &hr hi result; split.
    - smt(carry_initial catalog_partial_leaf).
    move=> cat h st hx [hj [ha [hm hc]]].
    have hp := projected_carry_push st [] [] h ha _; first by smt().
    have hf := projected_catalog_finish st [] h (j{hr}+1) cat ha _ hm hc;
      first by smt().
    move: hp; rewrite /=; smt().
  auto; smt(catalog_exact_empty stack_power_singleton stack_pow2_11).
qed.
