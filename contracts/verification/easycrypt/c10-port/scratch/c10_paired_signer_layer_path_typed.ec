(* Paired acceptance composed through complete EasyCrypt signer callers.
   The existing valid-history invariant is preserved through unchanged helper
   procedures. This does not identify the stateful oracle with pure Rust SHA. *)
require import AllCore List IntDiv.
require import C10Bytes C10RawOracle C10RawGrind C10Counter PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawWots RawLayer RawSigner RawSignature RawDecode.
require import RawForest.
require import C10Representation C10CallerInputBridge C10PrivateCallerBridge.
require import C10TreeCallerBridge C10OuterCallerBridge C10ShuffleBridge C10SearchAcceptance.






















module PairedSigningWots (O : PrefixOracle) = {
  proc fill = CommonPrivateWots(O).fill
  proc sign(seed : raw_input, layer tree kp : int, message shuffle : raw_input) : (raw_input list * int) option = {
    var accepted, sigma, result;
    accepted <@ PairedAcceptanceWots(PreparationView(O)).count(seed,layer,tree,kp,message);
    result <- None;
    if (accepted <> None) {
      sigma <@ fill(seed,layer,tree,kp,(oget accepted).`2,shuffle);
      result <- Some (sigma,(oget accepted).`1);
    }
    return result;
  }
}.

module PairedSigningLayer (O : PrefixOracle) = {
  proc recover(seed : raw_input, layer tree leaf : int, message : raw_input, sig : layer_signature) : raw_input = {
    var pk, root;
    pk <@ PairedAcceptanceWots(PreparationView(O)).recover(seed,layer,tree,leaf,message,sig.`1,sig.`2);
    root <@ CommonInputMerkle(O).recover(seed,layer,tree,pk,leaf,sig.`3);
    return root;
  }
  proc sign(seed : raw_input, layer tree leaf : int, message shuffle : raw_input) : (layer_signature * raw_input) option = {
    var built, subseed, signed, sig, root, result;
    built <@ CommonInputMerkle(O).build(seed,layer,tree,leaf);
    subseed <@ PairedShuffle(PreparationView(O)).derive(shuffle,shuffle_layer_label layer);
    signed <@ PairedSigningWots(O).sign(seed,layer,tree,leaf,message,subseed);
    result <- None;
    if (signed <> None) {
      sig <- ((oget signed).`1,(oget signed).`2,[]);
      root <@ recover(seed,layer,tree,leaf,message,sig);
      result <- Some (sig,root);
    }
    return result;
  }
}.

module PairedSigningSigner (O : PrefixOracle) = {
  proc finish(seed : raw_input, randomizer : raw_input, digest : digest, shuffle : raw_input) : raw_signature option = {
    var ht, forest, current, idx_tree, layer, idx_leaf, signed, layers, ok, result;
    ht <- hypertree_index digest;
    forest <@ CommonInputForest(O).sign(seed,ht,digest,shuffle);
    current <- forest.`3; idx_tree <- ht; layer <- 0; layers <- []; ok <- true;
    while (layer < 2 /\ ok) {
      idx_leaf <- idx_tree %% 512; idx_tree <- idx_tree %/ 512;
      signed <@ PairedSigningLayer(O).sign(seed,layer,idx_tree,idx_leaf,current,shuffle);
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
    accepted <@ PairedAcceptanceGrind(O).run(random,message,seed,root);
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
    if (fors_zero_field (bits_to_bytes digest) = 0) {
      ht <- hypertree_index digest;
      current <@ CommonInputForest(O).recover(seed,ht,digest,sig.`2,sig.`3);
      idx_tree <- ht; layer <- 0;
      while (layer < 2) {
        idx_leaf <- idx_tree %% 512; idx_tree <- idx_tree %/ 512;
        current <@ PairedSigningLayer(O).recover(seed,layer,idx_tree,idx_leaf,current,nth ([],0,[]) sig.`4 layer);
        layer <- layer+1;
      }
      result <- pad current = root;
    }
    return result;
  }
}.
