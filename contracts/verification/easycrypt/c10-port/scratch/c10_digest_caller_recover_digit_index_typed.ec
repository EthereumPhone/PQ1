(* Paired digest computations in signing and verification callers.
   Width and index premises are established by the actual search/hash/shuffle
   procedures. The stateful oracle is not identified with pure Rust SHA. *)
require import AllCore List IntDiv RadixEncoding.
require import C10Bytes C10RawOracle C10RawGrind C10Counter.
require import PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawShuffle.
require import RawWots RawForest RawLayer RawSigner RawSignature RawDecode.
require import ShuffleBytes C10Representation C10RepresentationBridge.
require import C10CallerInputBridge C10PrivateCallerBridge C10TreeCallerBridge.
require import C10OuterCallerBridge C10ShuffleBridge C10SearchAcceptance C10PairedSigner.









module PairedDigestWots (O : PrefixOracle) = {
  proc chain = CommonInputWots(PreparationView(O)).chain
  proc fill(seed : raw_input, layer tree kp : int, accepted : digest, shuffle : raw_input) : raw_input list = {
    var order, step, i, d, current, sigma;
    sigma <- nseq 43 (nseq 16 0);
    order <@ PairedShuffle(PreparationView(O)).permutation(shuffle,43);
    step <- 0;
    while (step < 43) {
      i <- nth 0 order step;
      d <@ O.derive(wots_private_preimage [] layer tree kp i);
      current <@ CommonInputWots(PreparationView(O)).chain(seed,layer,tree,kp,i,node d,0,wots_field (bits_to_bytes accepted) i);
      sigma <- put sigma i current; step <- step+1;
    }
    return sigma;
  }
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
  proc recover(seed : raw_input, layer tree kp : int, message : raw_input, sigma : raw_input list, count : int) : raw_input = {
    var d, result, i, current, elements;
    d <@ O.hash(wots_preimage seed (address_words layer tree 0 kp 0 0 0) (pad_node message) count);
    result <- nseq 16 0;
    if (wots_sum (bits_to_bytes d) = wots_target) {
      i <- 0; elements <- [];
      while (i < 43) {
        current <@ chain(seed,layer,tree,kp,i,nth (nseq 16 0) sigma i,wots_field (bits_to_bytes d) ((i+1) %% 43),7);
        elements <- rcons elements current; i <- i+1;
      }
      d <@ O.hash(multi_preimage seed (address_words layer tree 1 kp 0 0 0) elements);
      result <- node d;
    }
    return result;
  }
}.

module PairedDigestForest (O : PrefixOracle) = {
  proc one = CommonInputForest(O).one
  proc sign(seed : raw_input, ht : int, digest : digest, shuffle : raw_input) : raw_input list * raw_input list list * raw_input = {
    var subseed, order, step, t, sig, last, d, secrets, auths, roots;
    secrets <- nseq 13 (nseq 16 0);
    auths <- nseq 12 (nseq 11 (nseq 16 0)); roots <- nseq 13 (nseq 16 0);
    subseed <@ PairedShuffle(PreparationView(O)).derive(shuffle,shuffle_forest_label);
    order <@ PairedShuffle(PreparationView(O)).permutation(subseed,12);
    step <- 0;
    while (step < 12) {
      t <- nth 0 order step;
      sig <@ one(seed,ht,t,fors_field (bits_to_bytes digest) t);
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
      current <@ CommonInputFors(O).recover(seed,ht,t,fors_field (bits_to_bytes digest) t,nth (nseq 16 0) secrets t,nth [] auths t);
      roots <- rcons roots current; t <- t+1;
    }
    d <@ O.hash(th_preimage seed (address_words 0 ht 3 12 0 0 0) (pad_node (nth (nseq 16 0) secrets 12)));
    roots <- rcons roots (node d);
    d <@ O.hash(multi_preimage seed (address_words 0 ht 4 0 0 0 0) roots);
    return node d;
  }
}.

module PairedDigestLayer (O : PrefixOracle) = {
  proc recover(seed : raw_input, layer tree leaf : int, message : raw_input, sig : layer_signature) : raw_input = {
    var pk, root;
    pk <@ PairedDigestWots(O).recover(seed,layer,tree,leaf,message,sig.`1,sig.`2);
    root <@ CommonInputMerkle(O).recover(seed,layer,tree,pk,leaf,sig.`3);
    return root;
  }
  proc sign(seed : raw_input, layer tree leaf : int, message shuffle : raw_input) : (layer_signature * raw_input) option = {
    var built, subseed, signed, sig, root, result;
    built <@ CommonInputMerkle(O).build(seed,layer,tree,leaf);
    subseed <@ PairedShuffle(PreparationView(O)).derive(shuffle,shuffle_layer_label layer);
    signed <@ PairedDigestWots(O).sign(seed,layer,tree,leaf,message,subseed);
    result <- None;
    if (signed <> None) {
      sig <- ((oget signed).`1,(oget signed).`2,built.`1);
      root <@ recover(seed,layer,tree,leaf,message,sig);
      result <- Some (sig,root);
    }
    return result;
  }
}.


module PairedDigestSigner (O : PrefixOracle) = {
  proc finish(seed : raw_input, randomizer : raw_input, digest : digest, shuffle : raw_input) : raw_signature option = {
    var ht, forest, current, idx_tree, layer, idx_leaf, signed, layers, ok, result;
    ht <- ht_field (bits_to_bytes digest);
    forest <@ PairedDigestForest(O).sign(seed,ht,digest,shuffle);
    current <- forest.`3; idx_tree <- ht; layer <- 0; layers <- []; ok <- true;
    while (layer < 2 /\ ok) {
      idx_leaf <- idx_tree %% 512; idx_tree <- idx_tree %/ 512;
      signed <@ PairedDigestLayer(O).sign(seed,layer,idx_tree,idx_leaf,current,shuffle);
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
      ht <- ht_field (bits_to_bytes digest);
      current <@ PairedDigestForest(O).recover(seed,ht,digest,sig.`2,sig.`3);
      idx_tree <- ht; layer <- 0;
      while (layer < 2) {
        idx_leaf <- idx_tree %% 512; idx_tree <- idx_tree %/ 512;
        current <@ PairedDigestLayer(O).recover(seed,layer,idx_tree,idx_leaf,current,nth ([],0,[]) sig.`4 layer);
        layer <- layer+1;
      }
      result <- pad current = root;
    }
    return result;
  }
}.
