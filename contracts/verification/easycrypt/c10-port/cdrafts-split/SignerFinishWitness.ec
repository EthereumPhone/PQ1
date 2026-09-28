(* The actual finish loop with a proof-only list of intermediate roots. *)
require import AllCore List IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawForest RawLayer RawSigner.

module SignerFinishWitness (O : PrefixOracle) = {
  proc finish(seed : raw_input, randomizer : raw_input, digest : digest, shuffle : raw_input) :
      raw_signature option * raw_input list = {
    var ht, forest, current, idx_tree, layer, idx_leaf, signed, layers, ok, result, values;
    ht <- hypertree_index digest;
    forest <@ RawForest(PreparationView(O)).sign(seed,ht,digest,shuffle);
    current <- forest.`3; idx_tree <- ht; layer <- 0; layers <- []; ok <- true;
    values <- [current];
    while (layer < 2 /\ ok) {
      idx_leaf <- idx_tree %% 512; idx_tree <- idx_tree %/ 512;
      signed <@ RawLayer(PreparationView(O)).sign(seed,layer,idx_tree,idx_leaf,current,shuffle);
      if (signed = None) { ok <- false; } else {
        layers <- rcons layers (oget signed).`1; current <- (oget signed).`2;
        values <- rcons values current;
      }
      layer <- layer+1;
    }
    result <- None;
    if (ok) { result <- Some (randomizer,forest.`1,forest.`2,layers); }
    return (result,values);
  }
}.

lemma signer_finish_witness_projection (O <: PrefixOracle) :
  equiv [RawSigner(O).finish ~ SignerFinishWitness(O).finish :
    ={seed,randomizer,digest,shuffle,glob O} ==> res{1}=res{2}.`1 /\ ={glob O}].
proof.
  proc; seq 7 8 : (={seed,randomizer,digest,shuffle,ht,forest,current,idx_tree,layer,layers,ok,glob O}).
  + wp; call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
    auto.
  wp; while (={seed,randomizer,digest,shuffle,ht,forest,current,idx_tree,layer,layers,ok,glob O}).
  + wp; call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
    auto.
  auto.
qed.
