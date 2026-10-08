(* Exact key generation through the internal chain-position interface. *)
require import AllCore List IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots ChainValueView.

module ChainKeygen (O : ChainOracle) = {
  proc leaf(seed : raw_input, layer tree kp : int) : raw_input = {
    var i, current, elements, d;
    i <- 0; elements <- [];
    while (i < 43) {
      current <@ O.value(seed,layer,tree,kp,i,7);
      elements <- rcons elements (pad current); i <- i+1;
    }
    d <@ O.hash(seed ++ address layer tree 1 kp 0 0 0 ++ flatten elements);
    return node d;
  }
  proc root(seed : raw_input, layer tree : int) : raw_input = {
    var kp, current, height, stack, sibling, parent, d;
    kp <- 0; stack <- [];
    while (kp < 512) {
      current <@ leaf(seed,layer,tree,kp);
      height <- 0;
      while (stack <> [] /\ (head ([],0) stack).`2 = height) {
        sibling <- (head ([],0) stack).`1;
        stack <- behead stack;
        parent <- kp %/ (2^(height+1));
        d <@ O.hash(seed ++ address layer tree 2 0 0 (height+1) parent ++ pad sibling ++ pad current);
        current <- node d; height <- height+1;
      }
      stack <- (current,height)::stack; kp <- kp+1;
    }
    return (head (nseq 16 0,0) stack).`1;
  }
}.

lemma chain_keygen_leaf_projection (O <: PrefixOracle) :
  equiv [RawKeygen(PreparationView(O)).leaf ~ ChainKeygen(ConcreteChain(O)).leaf :
    ={arg,glob O} ==> ={res,glob O}].
proof.
  proc; wp; call (_ : true); wp.
  while (={seed,layer,tree,kp,i,elements,glob O}).
  + wp; inline ConcreteChain(O).value RawWots(PreparationView(O)).chain.
    wp; while (={seed,layer,tree,kp,i,elements,j,glob O} /\
      current{1}=current1{2} /\ seed1{2}=seed{2} /\ layer1{2}=layer{2} /\
      tree1{2}=tree{2} /\ kp1{2}=kp{2} /\ index0{2}=i{2} /\ stop0{2}=7).
    - wp; call (_ : true); auto; smt().
    wp; call (_ : ={glob O}); first by sim.
    auto.
  auto.
qed.

lemma chain_keygen_root_projection (O <: PrefixOracle) :
  equiv [RawKeygen(PreparationView(O)).root ~ ChainKeygen(ConcreteChain(O)).root :
    ={arg,glob O} ==> ={res,glob O}].
proof.
  proc; wp; while (={seed,layer,tree,kp,stack,glob O}).
  + wp; while (={seed,layer,tree,kp,current,height,stack,glob O}); first by sim.
    wp; call (chain_keygen_leaf_projection O); auto.
  auto.
qed.

lemma chain_keygen_leaf_lossless (O <: ChainOracle) :
  islossless O.hash => islossless O.value => islossless ChainKeygen(O).leaf.
proof.
  move=> hh hv; proc; wp; call hh; wp; while true (43-i).
  + move=> z; wp; call hv; auto; smt().
  auto; smt().
qed.
lemma chain_keygen_root_lossless (O <: ChainOracle) :
  islossless O.hash => islossless O.value => islossless ChainKeygen(O).root.
proof.
  move=> hh hv; proc; while true (512-kp).
  + move=> z; wp; while true (size stack).
    - move=> z'; wp; call hh; auto; smt(size_behead size_eq0 size_ge0).
    wp; call (chain_keygen_leaf_lossless O hh hv); auto; smt(size_ge0).
  auto; smt().
qed.
