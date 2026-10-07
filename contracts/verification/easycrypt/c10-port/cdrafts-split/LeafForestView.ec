(* Exact lifting of the leaf commitment/opening interface through FORS. *)
require import AllCore List Distr IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors RawShuffle RawForest ForsLeafView.

module LeafForest (O : PreparationOracle) (F : ForsLeafOracle) = {
  proc one(seed : raw_input, ht tree leaf : int) : raw_input * raw_input list * raw_input = {
    var sig, root;
    sig <@ LeafFors(F).sign(seed,ht,tree,leaf);
    root <@ RawFors(O).recover(seed,ht,tree,leaf,sig.`1,sig.`2);
    return (sig.`1,sig.`2,root);
  }
  proc sign(seed : raw_input, ht : int, digest : digest, shuffle : raw_input) : raw_input list * raw_input list list * raw_input = {
    var subseed, order, step, t, sig, last, d, secrets, auths, roots;
    secrets <- nseq 13 (nseq 16 0);
    auths <- nseq 12 (nseq 11 (nseq 16 0)); roots <- nseq 13 (nseq 16 0);
    subseed <@ RawShuffle(O).derive(shuffle,[102;111;114;115]);
    order <@ RawShuffle(O).permutation(subseed,12);
    step <- 0;
    while (step < 12) {
      t <- nth 0 order step;
      sig <@ one(seed,ht,t,forest_index digest t);
      secrets <- put secrets t sig.`1;
      auths <- put auths t sig.`2;
      roots <- put roots t sig.`3; step <- step+1;
    }
    last <@ LeafFors(F).root(seed,ht,12);
    secrets <- put secrets 12 last;
    d <@ O.hash(seed ++ address 0 ht 3 12 0 0 0 ++ pad last);
    roots <- put roots 12 (node d);
    d <@ O.hash(seed ++ address 0 ht 4 0 0 0 0 ++ flatten (map pad roots));
    return (secrets,auths,node d);
  }
  proc recover(seed : raw_input, ht : int, digest : digest, secrets : raw_input list, auths : raw_input list list) : raw_input = {
    var t, current, roots, d;
    t <- 0; roots <- [];
    while (t < 12) {
      current <@ RawFors(O).recover(seed,ht,t,forest_index digest t,nth (nseq 16 0) secrets t,nth [] auths t);
      roots <- rcons roots current; t <- t+1;
    }
    d <@ O.hash(seed ++ address 0 ht 3 12 0 0 0 ++ pad (nth (nseq 16 0) secrets 12));
    roots <- rcons roots (node d);
    d <@ O.hash(seed ++ address 0 ht 4 0 0 0 0 ++ flatten (map pad roots));
    return node d;
  }
}.

lemma leaf_forest_one_projection (O <: PreparationOracle) :
  equiv [RawForest(O).one ~ LeafForest(O,ConcreteForsLeaf(O)).one :
    ={arg,glob O} ==> ={res,glob O}].
proof.
  proc; call (_ : ={glob O}); first by sim.
  call (leaf_fors_sign_projection O); auto.
qed.
lemma leaf_forest_sign_projection (O <: PreparationOracle) :
  equiv [RawForest(O).sign ~ LeafForest(O,ConcreteForsLeaf(O)).sign :
    ={arg,glob O} ==> ={res,glob O}].
proof.
  proc; call (_ : true); wp; call (_ : true); wp.
  call (leaf_fors_root_projection O).
  while (={seed,ht,digest,order,step,secrets,auths,roots,glob O}).
  + wp; call (leaf_forest_one_projection O); auto.
  wp; call (_ : ={glob O}); first by sim.
  call (_ : ={glob O}); first by sim.
  auto.
qed.
lemma leaf_forest_recover_projection (O <: PreparationOracle) (F <: ForsLeafOracle) :
  equiv [RawForest(O).recover ~ LeafForest(O,F).recover :
    ={arg,glob O} ==> ={res,glob O}].
proof. by sim. qed.
