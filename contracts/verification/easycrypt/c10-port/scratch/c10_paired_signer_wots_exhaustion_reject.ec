(* Paired acceptance composed through complete EasyCrypt signer callers.
   The existing valid-history invariant is preserved through unchanged helper
   procedures. This does not identify the stateful oracle with pure Rust SHA. *)
require import AllCore List IntDiv.
require import C10Bytes C10RawOracle C10RawGrind C10Counter PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawWots RawLayer RawSigner RawSignature RawDecode.
require import RawForest.
require import C10Representation C10CallerInputBridge C10PrivateCallerBridge.
require import C10TreeCallerBridge C10OuterCallerBridge C10ShuffleBridge C10SearchAcceptance.

lemma paired_hash_history :
  hoare[Physical.hash :
    valid_history Shared.history ==> valid_history Shared.history].
proof.
  by proc; call hash_width; auto.
qed.

lemma paired_derive_history :
  hoare[Physical.derive :
    valid_history Shared.history ==> valid_history Shared.history].
proof.
  by proc; call hash_width; auto.
qed.

lemma paired_shuffle_derive_history :
  hoare[PairedShuffle(PreparationView(Physical)).derive :
    valid_history Shared.history ==> valid_history Shared.history].
proof.
  proc; sp 1; if; last by auto.
  by wp; call paired_hash_history; auto.
qed.

lemma paired_shuffle_permutation_history :
  hoare[PairedShuffle(PreparationView(Physical)).permutation :
    valid_history Shared.history ==> valid_history Shared.history].
proof.
  proc; sp 1; if; last by auto.
  wp; while (valid_history Shared.history).
  + by wp; call paired_hash_history; auto.
  by auto.
qed.

lemma paired_private_leaf_history :
  hoare[CommonPrivateWots(Physical).leaf :
    valid_history Shared.history ==> valid_history Shared.history].
proof.
  proc; call paired_hash_history; wp; while (valid_history Shared.history).
  + wp; call caller_chain_history; call paired_derive_history; auto.
  by auto.
qed.

lemma paired_private_fill_history :
  hoare[CommonPrivateWots(Physical).fill :
    valid_history Shared.history ==> valid_history Shared.history].
proof.
  proc; while (valid_history Shared.history).
  + wp; call caller_chain_history; call paired_derive_history; auto.
  wp; call paired_shuffle_permutation_history; auto.
qed.

lemma paired_fors_tree_history :
  hoare[CommonInputFors(Physical).tree :
    valid_history Shared.history ==> valid_history Shared.history].
proof.
  proc; while (valid_history Shared.history).
  + wp; while (valid_history Shared.history).
    - by wp; call paired_hash_history; auto.
    wp; call paired_hash_history; wp; call paired_derive_history; auto.
  by auto.
qed.

lemma paired_fors_root_history :
  hoare[CommonInputFors(Physical).root :
    valid_history Shared.history ==> valid_history Shared.history].
proof.
  by proc; call paired_fors_tree_history; auto.
qed.

lemma paired_fors_sign_history :
  hoare[CommonInputFors(Physical).sign :
    valid_history Shared.history ==> valid_history Shared.history].
proof.
  by proc; call paired_fors_tree_history; wp; call paired_derive_history; auto.
qed.

lemma paired_fors_recover_history :
  hoare[CommonInputFors(Physical).recover :
    valid_history Shared.history ==> valid_history Shared.history].
proof.
  proc; while (valid_history Shared.history).
  + by wp; call paired_hash_history; auto.
  wp; call paired_hash_history; auto.
qed.

lemma paired_merkle_build_history :
  hoare[CommonInputMerkle(Physical).build :
    valid_history Shared.history ==> valid_history Shared.history].
proof.
  proc; while (valid_history Shared.history).
  + wp; while (valid_history Shared.history).
    - by wp; call paired_hash_history; auto.
    wp; call paired_private_leaf_history; auto.
  by auto.
qed.

lemma paired_merkle_recover_history :
  hoare[CommonInputMerkle(Physical).recover :
    valid_history Shared.history ==> valid_history Shared.history].
proof.
  proc; while (valid_history Shared.history).
  + by wp; call paired_hash_history; auto.
  by auto.
qed.

lemma paired_forest_one_history :
  hoare[CommonInputForest(Physical).one :
    valid_history Shared.history ==> valid_history Shared.history].
proof.
  by proc; call paired_fors_recover_history; call paired_fors_sign_history; auto.
qed.

lemma paired_forest_sign_history :
  hoare[CommonInputForest(Physical).sign :
    valid_history Shared.history ==> valid_history Shared.history].
proof.
  proc; call paired_hash_history; wp; call paired_hash_history; wp.
  call paired_fors_root_history; wp; while (valid_history Shared.history).
  + by wp; call paired_forest_one_history; auto.
  wp; call paired_shuffle_permutation_history; call paired_shuffle_derive_history; auto.
qed.

lemma paired_forest_recover_history :
  hoare[CommonInputForest(Physical).recover :
    valid_history Shared.history ==> valid_history Shared.history].
proof.
  proc; call paired_hash_history; wp; call paired_hash_history; wp.
  while (valid_history Shared.history).
  + by wp; call paired_fors_recover_history; auto.
  by auto.
qed.

lemma paired_shuffle_derive_coupled :
  equiv[PairedShuffle(PreparationView(Physical)).derive ~ PairedShuffle(PreparationView(Physical)).derive :
    ={arg,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  conseq (_ : ={arg,glob Physical} ==> ={res,glob Physical})
    paired_shuffle_derive_history paired_shuffle_derive_history => //.
  by sim.
qed.

lemma paired_private_fill_coupled :
  equiv[CommonPrivateWots(Physical).fill ~ CommonPrivateWots(Physical).fill :
    ={arg,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  conseq (_ : ={arg,glob Physical} ==> ={res,glob Physical})
    paired_private_fill_history paired_private_fill_history => //.
  by sim.
qed.

lemma paired_merkle_build_coupled :
  equiv[CommonInputMerkle(Physical).build ~ CommonInputMerkle(Physical).build :
    ={arg,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  conseq (_ : ={arg,glob Physical} ==> ={res,glob Physical})
    paired_merkle_build_history paired_merkle_build_history => //.
  by sim.
qed.

lemma paired_merkle_recover_coupled :
  equiv[CommonInputMerkle(Physical).recover ~ CommonInputMerkle(Physical).recover :
    ={arg,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  conseq (_ : ={arg,glob Physical} ==> ={res,glob Physical})
    paired_merkle_recover_history paired_merkle_recover_history => //.
  by sim.
qed.

lemma paired_forest_sign_coupled :
  equiv[CommonInputForest(Physical).sign ~ CommonInputForest(Physical).sign :
    ={arg,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  conseq (_ : ={arg,glob Physical} ==> ={res,glob Physical})
    paired_forest_sign_history paired_forest_sign_history => //.
  by sim.
qed.

lemma paired_forest_recover_coupled :
  equiv[CommonInputForest(Physical).recover ~ CommonInputForest(Physical).recover :
    ={arg,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  conseq (_ : ={arg,glob Physical} ==> ={res,glob Physical})
    paired_forest_recover_history paired_forest_recover_history => //.
  by sim.
qed.

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
    return if result = None then Some ([],0) else result;
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
      sig <- ((oget signed).`1,(oget signed).`2,built.`1);
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

lemma paired_wots_sign :
  equiv[CommonPrivateWots(Physical).sign ~ PairedSigningWots(Physical).sign :
    ={seed,layer,tree,kp,message,shuffle,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  proc; seq 1 1 : (={seed,layer,tree,kp,message,shuffle,accepted,glob Physical} /\
    valid_history Shared.history{1}).
  + by call paired_wots_count; auto.
  sp 1 1; if; first by auto.
  + by wp; call paired_private_fill_coupled; auto.
  by auto.
qed.

lemma paired_layer_recover :
  equiv[CommonInputLayer(Physical).recover ~ PairedSigningLayer(Physical).recover :
    ={seed,layer,tree,leaf,message,sig,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  by proc; call paired_merkle_recover_coupled; call paired_wots_recover; auto.
qed.

lemma paired_layer_sign :
  equiv[CommonInputLayer(Physical).sign ~ PairedSigningLayer(Physical).sign :
    ={seed,layer,tree,leaf,message,shuffle,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  proc; seq 3 3 : (={seed,layer,tree,leaf,message,shuffle,built,subseed,signed,glob Physical} /\
    valid_history Shared.history{1}).
  + by call paired_wots_sign; call paired_shuffle_derive_coupled; call paired_merkle_build_coupled; auto.
  sp 1 1; if; first by auto.
  + by wp; call paired_layer_recover; auto.
  by auto.
qed.

lemma paired_signer_finish :
  equiv[CommonInputSigner(Physical).finish ~ PairedSigningSigner(Physical).finish :
    ={seed,randomizer,digest,shuffle,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  proc; wp; while (={seed,randomizer,digest,shuffle,forest,current,idx_tree,layer,layers,ok,glob Physical} /\
    valid_history Shared.history{1}).
  + seq 3 3 : (={seed,randomizer,digest,shuffle,forest,current,idx_tree,idx_leaf,layer,layers,ok,signed,glob Physical} /\
    valid_history Shared.history{1}).
    - by call paired_layer_sign; auto.
    by if; auto.
  by wp; call paired_forest_sign_coupled; auto.
qed.

lemma paired_signer_sign :
  equiv[CommonInputSigner(Physical).sign ~ PairedSigningSigner(Physical).sign :
    ={seed,root,random,message,shuffle,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  proc; seq 1 1 : (={seed,root,random,message,shuffle,accepted,glob Physical} /\
    valid_history Shared.history{1}).
  + by call paired_nonce_grind; auto.
  sp 1 1; if; first by auto.
  + by call paired_signer_finish; auto.
  by auto.
qed.

lemma paired_signer_verify :
  equiv[CommonInputSigner(Physical).verify ~ PairedSigningSigner(Physical).verify :
    ={seed,root,message,sig,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  proc; seq 1 1 : (={seed,root,message,sig,digest,glob Physical} /\
    valid_history Shared.history{1} /\ size digest{1} = 256).
  + by call physical_hash_paired; auto.
  sp 1 1; if; first by auto => /> &m hh hd; rewrite (fors_accept_bits digest{m} hd).
  + wp; while (={seed,root,message,sig,digest,ht,current,layer,idx_tree,glob Physical} /\
    valid_history Shared.history{1}).
    - by wp; call paired_layer_recover; auto.
    by wp; call paired_forest_recover_coupled; auto.
  by auto.
qed.

lemma raw_signer_finish_paired :
  equiv[RawSigner(Physical).finish ~ PairedSigningSigner(Physical).finish :
    ={seed,randomizer,digest,shuffle,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  transitivity CommonInputSigner(Physical).finish
    (={seed,randomizer,digest,shuffle,glob Physical} ==> ={res,glob Physical})
    (={seed,randomizer,digest,shuffle,glob Physical} /\ valid_history Shared.history{1} ==>
      ={res,glob Physical} /\ valid_history Shared.history{1}) => //.
  + smt().
  + exact (caller_signer_finish Physical).
  exact paired_signer_finish.
qed.

lemma raw_signer_sign_paired :
  equiv[RawSigner(Physical).sign ~ PairedSigningSigner(Physical).sign :
    ={seed,root,random,message,shuffle,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  transitivity CommonInputSigner(Physical).sign
    (={seed,root,random,message,shuffle,glob Physical} ==> ={res,glob Physical})
    (={seed,root,random,message,shuffle,glob Physical} /\ valid_history Shared.history{1} ==>
      ={res,glob Physical} /\ valid_history Shared.history{1}) => //.
  + smt().
  + exact (caller_signer_sign Physical).
  exact paired_signer_sign.
qed.

lemma raw_signer_verify_paired :
  equiv[RawSigner(Physical).verify ~ PairedSigningSigner(Physical).verify :
    ={seed,root,message,sig,glob Physical} /\ outer_counters sig{1} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  transitivity CommonInputSigner(Physical).verify
    (={seed,root,message,sig,glob Physical} /\ outer_counters sig{1} ==> ={res,glob Physical})
    (={seed,root,message,sig,glob Physical} /\ valid_history Shared.history{1} ==>
      ={res,glob Physical} /\ valid_history Shared.history{1}) => //.
  + smt().
  + exact (caller_signer_verify Physical).
  exact paired_signer_verify.
qed.

lemma raw_signer_verify_decoded_paired bytes :
  size bytes = 4008 =>
  equiv[RawSigner(Physical).verify ~ PairedSigningSigner(Physical).verify :
    ={seed,root,message,sig,glob Physical} /\ sig{1} = decode_signature bytes /\
    valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  move=> hs; conseq raw_signer_verify_paired; smt(outer_decoded_counters).
qed.
