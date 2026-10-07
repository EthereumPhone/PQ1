(* Separate the two uses of a private FORS node: its public leaf commitment
   and an explicit secret opening. This is an exact refactoring of RawFors. *)
require import AllCore List IntDiv.
require import C10RawOracle PrefixGuess KeygenPrefixes RawKeygen RawFors.

module type ForsLeafOracle = {
  proc hash(x : raw_input) : digest
  proc leaf(seed : raw_input, ht tree index : int) : raw_input
  proc secret(ht tree index : int) : raw_input
}.
module ConcreteForsLeaf (O : PreparationOracle) = {
  proc hash = O.hash
  proc leaf(seed : raw_input, ht tree index : int) : raw_input = {
    var sd, d;
    sd <@ O.fors(fors_tail ht tree index);
    d <@ O.hash(seed ++ address 0 ht 3 tree 0 0 index ++ pad (node sd));
    return node d;
  }
  proc secret(ht tree index : int) : raw_input = {
    var sd; sd <@ O.fors(fors_tail ht tree index); return node sd;
  }
}.
module LeafFors (F : ForsLeafOracle) = {
  proc tree(seed : raw_input, ht tree target : int) : raw_input * raw_input list = {
    var j, current, height, stack, sibling, parent, d, auth, target_h, sibidx, left_start, right_start;
    j <- 0; stack <- []; auth <- nseq 11 (nseq 16 0);
    while (j < 2048) {
      current <@ F.leaf(seed,ht,tree,j);
      height <- 0;
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
        d <@ F.hash(seed ++ address 0 ht 3 tree 0 (height+1) parent ++ pad sibling ++ pad current);
        current <- node d; height <- height+1;
      }
      stack <- (current,height)::stack; j <- j+1;
    }
    return ((head (nseq 16 0,0) stack).`1,auth);
  }
  proc root(seed : raw_input, ht tree : int) : raw_input = {
    var result; result <@ tree(seed,ht,tree,0); return result.`1;
  }
  proc sign(seed : raw_input, ht tree target : int) : raw_input * raw_input list = {
    var secret, result;
    secret <@ F.secret(ht,tree,target);
    result <@ tree(seed,ht,tree,target);
    return (secret,result.`2);
  }
}.

lemma leaf_fors_tree_projection (O <: PreparationOracle) :
  equiv [RawFors(O).tree ~ LeafFors(ConcreteForsLeaf(O)).tree :
    ={arg,glob O} ==> ={res,glob O}].
proof.
  proc; inline ConcreteForsLeaf(O).leaf.
  while (={seed,ht,tree,target,j,stack,auth,glob O}).
  + wp; while (={seed,ht,tree,target,j,current,height,stack,auth,glob O}).
    - conseq (_ : _ ==> ={seed,ht,tree,target,j,current,height,stack,auth,glob O}); first smt().
      by sim.
    conseq (_ : _ ==> ={seed,ht,tree,target,j,current,height,stack,auth,glob O}); first smt().
    wp; call (_ : true).
    wp; call (_ : true); auto.
  auto.
qed.

lemma leaf_fors_root_projection (O <: PreparationOracle) :
  equiv [RawFors(O).root ~ LeafFors(ConcreteForsLeaf(O)).root :
    ={arg,glob O} ==> ={res,glob O}].
proof. proc; call (leaf_fors_tree_projection O); auto. qed.

lemma leaf_fors_sign_projection (O <: PreparationOracle) :
  equiv [RawFors(O).sign ~ LeafFors(ConcreteForsLeaf(O)).sign :
    ={arg,glob O} ==> ={res,glob O}].
proof.
  proc; call (leaf_fors_tree_projection O); inline ConcreteForsLeaf(O).secret;
    wp; call (_ : true); auto.
qed.
