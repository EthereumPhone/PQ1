(* Common-input composition of the actual forest, layer and signer callers.
   Preserve returned values, failures and the complete arbitrary oracle state.
   Shuffle derivation and permutation use the proved paired representation.
   Structured verification's
   two consumed counters are u32; the decoder discharges that wire boundary.
   No concrete-SHA, cross-kernel or whole-session interpretation is claimed. *)
require import AllCore List IntDiv.
require import C10Bytes C10Counter C10RawOracle C10RawGrind PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawFors RawMerkle RawShuffle RawWots RawForest RawLayer RawSigner.
require import RawSignature RawDecode ForestCoordinates SignerCoordinates.
require import C10Representation C10HashInputBridge C10AddressInputBridge.
require import C10CallerInputBridge C10PrivateCallerBridge C10TreeCallerBridge C10ShuffleBridge.

op outer_counters (sig : raw_signature) =
  forall i, 0 <= i < 2 => 0 <= (nth ([],0,[]) sig.`4 i).`2 < 4294967296.






module CommonInputForest (O : PrefixOracle) = {
  proc one(seed : raw_input, ht tree leaf : int) : raw_input * raw_input list * raw_input = {
    var sig, root;
    sig <@ CommonInputFors(O).sign(seed,ht,tree,leaf);
    root <@ CommonInputFors(O).recover(seed,ht,tree,leaf,sig.`1,sig.`2);
    return (sig.`1,sig.`2,root);
  }
  proc sign(seed : raw_input, ht : int, digest : digest, shuffle : raw_input) : raw_input list * raw_input list list * raw_input = {
    var subseed, order, step, t, sig, last, d, secrets, auths, roots;
    secrets <- nseq 13 (nseq 16 0);
    auths <- nseq 12 (nseq 11 (nseq 16 0)); roots <- nseq 13 (nseq 16 0);
    subseed <@ PairedShuffle(PreparationView(O)).derive(shuffle,shuffle_forest_label);
    order <@ PairedShuffle(PreparationView(O)).permutation(subseed,12);
    step <- 0;
    while (step < 12) {
      t <- nth 0 order step;
      sig <@ one(seed,ht,t,forest_index digest t);
      secrets <- put secrets t sig.`1;
      auths <- put auths t sig.`2;
      roots <- put roots t sig.`3; step <- step+1;
    }
    last <@ CommonInputFors(O).root(seed,ht,12);
    secrets <- put secrets 12 last;
    d <@ O.hash(th_preimage seed (address_words 0 ht 3 12 0 0 0) (pad_node last));
    roots <- put roots 12 (node d);
    d <@ O.hash(multi_preimage seed (address_words 0 ht 4 0 0 0 0) roots);
    return (secrets,auths,node d);
  }
  proc recover(seed : raw_input, ht : int, digest : digest, secrets : raw_input list, auths : raw_input list list) : raw_input = {
    var t, current, roots, d;
    t <- 0; roots <- [];
    while (t < 12) {
      current <@ CommonInputFors(O).recover(seed,ht,t,forest_index digest t,nth (nseq 16 0) secrets t,nth [] auths t);
      roots <- rcons roots current; t <- t+1;
    }
    d <@ O.hash(th_preimage seed (address_words 0 ht 3 12 0 0 0) (pad_node (nth (nseq 16 0) secrets 12)));
    roots <- rcons roots (node d);
    d <@ O.hash(multi_preimage seed (address_words 0 ht 4 0 0 0 0) roots);
    return node d;
  }
}.

module CommonInputLayer (O : PrefixOracle) = {
  proc recover(seed : raw_input, layer tree leaf : int, message : raw_input, sig : layer_signature) : raw_input = {
    var pk, root;
    pk <@ CommonInputWots(PreparationView(O)).recover(seed,layer,tree,leaf,message,sig.`1,sig.`2);
    root <@ CommonInputMerkle(O).recover(seed,layer,tree,pk,leaf,sig.`3);
    return root;
  }
  proc sign(seed : raw_input, layer tree leaf : int, message shuffle : raw_input) : (layer_signature * raw_input) option = {
    var built, subseed, signed, sig, root, result;
    built <@ CommonInputMerkle(O).build(seed,layer,tree,leaf);
    subseed <@ PairedShuffle(PreparationView(O)).derive(shuffle,shuffle_layer_label layer);
    signed <@ CommonPrivateWots(O).sign(seed,layer,tree,leaf,message,subseed);
    result <- Some (([],0,[]),[]);
    if (signed <> None) {
      sig <- ((oget signed).`1,(oget signed).`2,built.`1);
      root <@ recover(seed,layer,tree,leaf,message,sig);
      result <- Some (sig,root);
    }
    return result;
  }
}.

module CommonInputSigner (O : PrefixOracle) = {
  proc finish(seed : raw_input, randomizer : raw_input, digest : digest, shuffle : raw_input) : raw_signature option = {
    var ht, forest, current, idx_tree, layer, idx_leaf, signed, layers, ok, result;
    ht <- hypertree_index digest;
    forest <@ CommonInputForest(O).sign(seed,ht,digest,shuffle);
    current <- forest.`3; idx_tree <- ht; layer <- 0; layers <- []; ok <- true;
    while (layer < 2 /\ ok) {
      idx_leaf <- idx_tree %% 512; idx_tree <- idx_tree %/ 512;
      signed <@ CommonInputLayer(O).sign(seed,layer,idx_tree,idx_leaf,current,shuffle);
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
    accepted <@ CommonInputGrind(O).run(random,message,seed,root);
    result <- None;
    if (accepted <> None) {
      result <@ finish(seed,(oget accepted).`1,(oget accepted).`2,shuffle);
    }
    return result;
  }
  proc verify(seed root message : raw_input, sig : raw_signature) : bool = {
    var digest, ht, current, layer, idx_tree, idx_leaf, result;
    digest <@ O.hash(hmsg_preimage seed root (pad_node sig.`1) message);
    result <- false;
    if (accept_digest digest) {
      ht <- hypertree_index digest;
      current <@ CommonInputForest(O).recover(seed,ht,digest,sig.`2,sig.`3);
      idx_tree <- ht; layer <- 0;
      while (layer < 2) {
        idx_leaf <- idx_tree %% 512; idx_tree <- idx_tree %/ 512;
        current <@ CommonInputLayer(O).recover(seed,layer,idx_tree,idx_leaf,current,nth ([],0,[]) sig.`4 layer);
        layer <- layer+1;
      }
      result <- pad current = root;
    }
    return result;
  }
}.
