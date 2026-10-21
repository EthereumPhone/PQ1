require import AllCore List Distr IntDiv.
require import C10RawOracle C10RawGrind C10HashDomains.
require import PrefixGuess PrefixHybrid KeygenPrefixes PreparedGrind RoleGrind RoleGrindCost.
require import RawKeygen RawForest RawLayer.
require import AllCore List Distr FMap IntDiv.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes.
require import PreparedGrind KeygenExhaustion RObservedSigner RoleGrind.
require import RawWots RawLayer RawForest RawSigner RawCompositeWidths.
require import ByteSession RawByteValues RawCompositeBytes.
require import MemoRejectCompletion WotsRejectDomain WotsPhysicalFailure.
require import RawSigner WotsSignerFailure.

module ControlledTotalAvailability (O : PrefixOracle) = {
  proc finish(seed : raw_input, randomizer : raw_input, digest : digest, shuffle : raw_input) : raw_signature option = {
    var ht, forest, current, idx_tree, layer, idx_leaf, signed, layers, ok, result;
    ht <- hypertree_index digest;
    forest <@ RawForest(PreparationView(O)).sign(seed,ht,digest,shuffle);
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
    if (false) { result <- Some (randomizer,forest.`1,forest.`2,layers); }
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

lemma checked :
  equiv[ControlledTotalAvailability(Physical).finish ~ RawSigner(Physical).finish :
    ={arg,glob Physical,glob Shared} ==> ={res,glob Physical,glob Shared}].
proof.
  proc; wp; while (={seed,randomizer,shuffle,forest,current,idx_tree,layer,layers,ok,glob Physical,glob Shared}).
  + wp; call (_ : ={glob Physical,glob Shared}); first by sim.
    auto => />.
  wp; call (_ : ={glob Physical,glob Shared}); first by sim.
  auto => />.
qed.

lemma consumer_checked seed0 :
  hoare[ControlledTotalAvailability(Physical).finish : seed=seed0 ==>
    res=None => wots_domain_exhausted seed0 signing_budget Shared.history].
proof.
  proc; wp; while (seed=seed0 /\ 0<=layer<=2 /\
    (ok => size current=16 /\ byte_values current) /\
    (!ok => wots_domain_exhausted seed0 signing_budget Shared.history)).
  + exists* layer, idx_tree, current; elim* => l t m.
    wp; call (physical_layer_outcome seed0 l (t %/ 512) (t %% 512) m); auto; smt().
  wp; call physical_forest_node; auto; smt().
qed.
