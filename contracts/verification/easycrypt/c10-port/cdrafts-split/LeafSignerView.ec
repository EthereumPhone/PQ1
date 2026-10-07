(* Exact signing projection; grinding, WOTS layers, and verification stay original. *)
require import AllCore List Distr IntDiv.
require import C10RawOracle C10RawGrind C10HashDomains.
require import PrefixGuess PrefixHybrid KeygenPrefixes PreparedGrind RoleGrind RoleGrindCost.
require import RawKeygen RawForest RawLayer RawSigner ForsLeafView LeafForestView.

module LeafSigner (O : PrefixOracle) (F : ForsLeafOracle) = {
  proc finish(seed : raw_input, randomizer : raw_input, digest : digest, shuffle : raw_input) : raw_signature option = {
    var ht, forest, current, idx_tree, layer, idx_leaf, signed, layers, ok, result;
    ht <- hypertree_index digest;
    forest <@ LeafForest(PreparationView(O),F).sign(seed,ht,digest,shuffle);
    current <- forest.`3; idx_tree <- ht; layer <- 0; layers <- []; ok <- true;
    while (layer < 2 /\ ok) {
      idx_leaf <- idx_tree %% 512; idx_tree <- idx_tree %/ 512;
      signed <@ RawLayer(PreparationView(O)).sign(seed,layer,idx_tree,idx_leaf,current,shuffle);
      if (signed = None) { ok <- false; } else {
        layers <- rcons layers (oget signed).`1; current <- (oget signed).`2;
      }
      layer <- layer+1;
    }
    result <- None;
    if (ok) { result <- Some (randomizer,forest.`1,forest.`2,layers); }
    return result;
  }
  proc sign(seed root random message shuffle : raw_input) : raw_signature option = {
    var accepted, result;
    accepted <@ RoleGrind(O).run(random,message,seed,root);
    result <- None;
    if (accepted <> None) {
      result <@ finish(seed,(oget accepted).`1,(oget accepted).`2,shuffle);
    }
    return result;
  }
  proc verify(seed root message : raw_input, sig : raw_signature) : bool = {
    var digest, ht, current, layer, idx_tree, idx_leaf, result;
    digest <@ O.hash(hmsg_input seed root (pad sig.`1) message);
    result <- false;
    if (accept_digest digest) {
      ht <- hypertree_index digest;
      current <@ RawForest(PreparationView(O)).recover(seed,ht,digest,sig.`2,sig.`3);
      idx_tree <- ht; layer <- 0;
      while (layer < 2) {
        idx_leaf <- idx_tree %% 512; idx_tree <- idx_tree %/ 512;
        current <@ RawLayer(PreparationView(O)).recover(seed,layer,idx_tree,idx_leaf,current,nth ([],0,[]) sig.`4 layer);
        layer <- layer+1;
      }
      result <- pad current = root;
    }
    return result;
  }
}.

lemma leaf_signer_finish_projection (O <: PrefixOracle) :
  equiv [RawSigner(O).finish ~ LeafSigner(O,ConcreteForsLeaf(PreparationView(O))).finish :
    ={arg,glob O} ==> ={res,glob O}].
proof.
  proc; wp; while (={seed,randomizer,forest,current,idx_tree,layer,layers,ok,shuffle,glob O}).
  + by sim.
  wp; call (leaf_forest_sign_projection (PreparationView(O))); auto.
qed.
lemma leaf_signer_sign_projection (O <: PrefixOracle) :
  equiv [RawSigner(O).sign ~ LeafSigner(O,ConcreteForsLeaf(PreparationView(O))).sign :
    ={arg,glob O} ==> ={res,glob O}].
proof.
  proc; seq 1 1 : (={seed,root,random,message,shuffle,accepted,glob O}).
  + call (_ : ={glob O}); first by sim.
    auto.
  sp 1 1; if; auto; call (leaf_signer_finish_projection O); auto.
qed.
lemma leaf_signer_verify_projection (O <: PrefixOracle) (F <: ForsLeafOracle) :
  equiv [RawSigner(O).verify ~ LeafSigner(O,F).verify :
    ={arg,glob O} ==> ={res,glob O}].
proof. by sim. qed.
