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

lemma digest_wots_field d i : size d = 256 => 0 <= i < 43 =>
  digit 3 d i = wots_field (bits_to_bytes d) i.
proof.
  move=> hd hi.
  have hb := shuffle_bytes_valid d.
  have hs : size (bits_to_bytes d) = 32 by rewrite bits_to_bytes_size hd.
  have he := wots_common (bits_to_bytes d) i hs hi hb.
  by move: he; rewrite bits_bytes_roundtrip 1:hd.
qed.

lemma digest_fors_field d t : size d = 256 => 0 <= t =>
  forest_index d t = fors_field (bits_to_bytes d) t.
proof.
  move=> hd ht.
  have he := forest_common (bits_to_bytes d) t ht (shuffle_bytes_valid d).
  by move: he; rewrite bits_bytes_roundtrip 1:hd.
qed.

lemma digest_ht_field d : size d = 256 =>
  hypertree_index d = ht_field (bits_to_bytes d).
proof.
  move=> hd.
  have he := hypertree_common (bits_to_bytes d) (shuffle_bytes_valid d).
  by move: he; rewrite bits_bytes_roundtrip 1:hd.
qed.

lemma digest_shuffle_coupled n0 :
  equiv[PairedShuffle(PreparationView(Physical)).permutation ~
        PairedShuffle(PreparationView(Physical)).permutation :
    ={arg,glob Physical} /\ n{1}=n0 /\ 0 <= n0 <= 64 /\
    valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ perm_eq res{1} (range 0 n0) /\
    valid_history Shared.history{1}].
proof.
  conseq (_ : ={arg,glob Physical} /\ n{1}=n0 /\ 0 <= n0 <= 64 ==>
    ={res,glob Physical} /\ perm_eq res{1} (range 0 n0))
    paired_shuffle_permutation_history paired_shuffle_permutation_history => //.
  transitivity RawShuffle(PreparationView(Physical)).permutation
    (={arg,glob Physical} /\ n{1}=n0 /\ 0 <= n0 <= 64 ==> ={res,glob Physical})
    (={arg,glob Physical} /\ n{1}=n0 /\ 0 <= n0 <= 64 ==>
      ={res,glob Physical} /\ perm_eq res{1} (range 0 n0)) => //.
  + smt().
  + symmetry; conseq (shuffle_permutation_common (PreparationView(Physical))); smt().
  exact (caller_shuffle_paired (PreparationView(Physical)) n0).
qed.

lemma digest_count_width :
  hoare[PairedAcceptanceWots(PreparationView(Physical)).count :
    valid_history Shared.history ==>
    valid_history Shared.history /\ (res <> None => size (oget res).`2 = 256)].
proof.
  proc; while (valid_history Shared.history /\
    (result <> None => size (oget result).`2 = 256)).
  + wp; inline Physical.hash; wp; call hash_width; auto; smt().
  by auto.
qed.

lemma digest_nonce_width :
  hoare[PairedAcceptanceGrind(Physical).run :
    valid_history Shared.history ==>
    valid_history Shared.history /\ (res <> None => size (oget res).`2 = 256)].
proof.
  proc; while (valid_history Shared.history /\
    (result <> None => size (oget result).`2 = 256)).
  + wp; inline Physical.hash; wp; call hash_width; wp.
    call paired_derive_history; auto; smt().
  by auto.
qed.

lemma digest_count_coupled :
  equiv[PairedAcceptanceWots(PreparationView(Physical)).count ~
        PairedAcceptanceWots(PreparationView(Physical)).count :
    ={arg,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1} /\
    (res{1} <> None => size (oget res{1}).`2 = 256)].
proof.
  conseq (_ : ={arg,glob Physical} ==> ={res,glob Physical})
    digest_count_width digest_count_width => //.
  by sim.
qed.

lemma digest_nonce_coupled :
  equiv[PairedAcceptanceGrind(Physical).run ~ PairedAcceptanceGrind(Physical).run :
    ={arg,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1} /\
    (res{1} <> None => size (oget res{1}).`2 = 256)].
proof.
  conseq (_ : ={arg,glob Physical} ==> ={res,glob Physical})
    digest_nonce_width digest_nonce_width => //.
  by sim.
qed.

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
        current <@ chain(seed,layer,tree,kp,i,nth (nseq 16 0) sigma i,wots_field (bits_to_bytes d) i,7);
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
      idx_leaf <- idx_tree %% 512; idx_tree <- idx_tree %/ 256;
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

lemma digest_wots_fill :
  equiv[CommonPrivateWots(Physical).fill ~ PairedDigestWots(Physical).fill :
    ={seed,layer,tree,kp,accepted,shuffle,glob Physical} /\
    size accepted{1} = 256 /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  proc; while (={seed,layer,tree,kp,accepted,order,step,sigma,glob Physical} /\
    size accepted{1} = 256 /\ valid_history Shared.history{1} /\
    perm_eq order{1} (range 0 43) /\ 0 <= step{1} <= 43).
  + wp; call caller_chain_paired; wp; call physical_derive_paired.
    auto => /> &m hd hh hp hs0 hs hlt rd hist hhist hrd.
    have hi : 0 <= nth 0 order{m} step{m} < 43
      by apply caller_shuffle_index; smt().
    split; first by rewrite (digest_wots_field accepted{m} (nth 0 order{m} step{m}) hd hi).
    by smt().
  wp; call (digest_shuffle_coupled 43); by auto.
qed.

lemma digest_wots_sign :
  equiv[PairedSigningWots(Physical).sign ~ PairedDigestWots(Physical).sign :
    ={seed,layer,tree,kp,message,shuffle,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  proc; seq 1 1 : (={seed,layer,tree,kp,message,shuffle,accepted,glob Physical} /\
    valid_history Shared.history{1} /\
    (accepted{1} <> None => size (oget accepted{1}).`2 = 256)).
  + by call digest_count_coupled; auto.
  sp 1 1; if; first by auto.
  + by wp; call digest_wots_fill; auto; smt().
  by auto.
qed.

lemma digest_wots_recover :
  equiv[PairedAcceptanceWots(PreparationView(Physical)).recover ~ PairedDigestWots(Physical).recover :
    ={seed,layer,tree,kp,message,sigma,count,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  proc; seq 1 1 : (={seed,layer,tree,kp,message,sigma,count,d,glob Physical} /\
    valid_history Shared.history{1} /\ size d{1} = 256).
  + by call physical_hash_paired; auto.
  sp 1 1; if; first by auto.
  + wp; call physical_hash_paired; wp.
    while (={seed,layer,tree,kp,sigma,d,i,elements,glob Physical} /\
      valid_history Shared.history{1} /\ size d{1} = 256 /\ 0 <= i{1} <= 43).
    - wp; call caller_chain_paired; auto => /> &m hh hd hi0 hi hlt.
      have hir : 0 <= i{m} < 43 by smt().
      split; first by rewrite (digest_wots_field d{m} i{m} hd hir).
      by smt().
    by auto.
  by auto.
qed.

lemma digest_fors_root_coupled :
  equiv[CommonInputFors(Physical).root ~ CommonInputFors(Physical).root :
    ={arg,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  conseq (_ : ={arg,glob Physical} ==> ={res,glob Physical})
    paired_fors_root_history paired_fors_root_history => //.
  by sim.
qed.

lemma digest_fors_recover_coupled :
  equiv[CommonInputFors(Physical).recover ~ CommonInputFors(Physical).recover :
    ={arg,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  conseq (_ : ={arg,glob Physical} ==> ={res,glob Physical})
    paired_fors_recover_history paired_fors_recover_history => //.
  by sim.
qed.

lemma digest_forest_one_coupled :
  equiv[CommonInputForest(Physical).one ~ CommonInputForest(Physical).one :
    ={arg,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  conseq (_ : ={arg,glob Physical} ==> ={res,glob Physical})
    paired_forest_one_history paired_forest_one_history => //.
  by sim.
qed.

lemma digest_forest_sign :
  equiv[CommonInputForest(Physical).sign ~ PairedDigestForest(Physical).sign :
    ={seed,ht,digest,shuffle,glob Physical} /\ size digest{1} = 256 /\
    valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  proc; call physical_hash_paired; wp; call physical_hash_paired; wp.
  call digest_fors_root_coupled; wp.
  while (={seed,ht,digest,shuffle,order,step,secrets,auths,roots,glob Physical} /\
    size digest{1} = 256 /\ valid_history Shared.history{1} /\
    perm_eq order{1} (range 0 12) /\ 0 <= step{1} <= 12).
  + wp; call digest_forest_one_coupled; auto => /> &m hd hh hp hs0 hs hlt.
    have ht : 0 <= nth 0 order{m} step{m} by smt(outer_shuffle_index).
    split; first by rewrite (digest_fors_field digest{m} (nth 0 order{m} step{m}) hd ht).
    by smt().
  wp; call (digest_shuffle_coupled 12); call paired_shuffle_derive_coupled; by auto.
qed.

lemma digest_forest_recover :
  equiv[CommonInputForest(Physical).recover ~ PairedDigestForest(Physical).recover :
    ={seed,ht,digest,secrets,auths,glob Physical} /\ size digest{1} = 256 /\
    valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  proc; call physical_hash_paired; wp; call physical_hash_paired; wp.
  while (={seed,ht,digest,secrets,auths,t,roots,glob Physical} /\
    size digest{1} = 256 /\ valid_history Shared.history{1} /\ 0 <= t{1} <= 12).
  + wp; call digest_fors_recover_coupled; auto => /> &m hd hh ht0 ht hlt.
    split; first by rewrite (digest_fors_field digest{m} t{m} hd ht0).
    by smt().
  by auto.
qed.

lemma digest_layer_recover :
  equiv[PairedSigningLayer(Physical).recover ~ PairedDigestLayer(Physical).recover :
    ={seed,layer,tree,leaf,message,sig,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  by proc; call paired_merkle_recover_coupled; call digest_wots_recover; auto.
qed.

lemma digest_layer_sign :
  equiv[PairedSigningLayer(Physical).sign ~ PairedDigestLayer(Physical).sign :
    ={seed,layer,tree,leaf,message,shuffle,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  proc; seq 3 3 : (={seed,layer,tree,leaf,message,shuffle,built,subseed,signed,glob Physical} /\
    valid_history Shared.history{1}).
  + by call digest_wots_sign; call paired_shuffle_derive_coupled; call paired_merkle_build_coupled; auto.
  sp 1 1; if; first by auto.
  + by wp; call digest_layer_recover; auto.
  by auto.
qed.

lemma digest_signer_finish :
  equiv[PairedSigningSigner(Physical).finish ~ PairedDigestSigner(Physical).finish :
    ={seed,randomizer,digest,shuffle,glob Physical} /\ size digest{1} = 256 /\
    valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  proc; wp; while (={seed,randomizer,digest,shuffle,forest,current,idx_tree,layer,layers,ok,glob Physical} /\
    valid_history Shared.history{1}).
  + seq 3 3 : (={seed,randomizer,digest,shuffle,forest,current,idx_tree,idx_leaf,layer,layers,ok,signed,glob Physical} /\
    valid_history Shared.history{1}).
    - by call digest_layer_sign; auto.
    by if; auto.
  wp; call digest_forest_sign; auto => /> &m hd hh.
  by rewrite (digest_ht_field digest{m} hd).
qed.

lemma digest_signer_sign :
  equiv[PairedSigningSigner(Physical).sign ~ PairedDigestSigner(Physical).sign :
    ={seed,root,random,message,shuffle,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  proc; seq 1 1 : (={seed,root,random,message,shuffle,accepted,glob Physical} /\
    valid_history Shared.history{1} /\
    (accepted{1} <> None => size (oget accepted{1}).`2 = 256)).
  + by call digest_nonce_coupled; auto.
  sp 1 1; if; first by auto.
  + by call digest_signer_finish; auto; smt().
  by auto.
qed.

lemma digest_signer_verify :
  equiv[PairedSigningSigner(Physical).verify ~ PairedDigestSigner(Physical).verify :
    ={seed,root,message,sig,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  proc; seq 1 1 : (={seed,root,message,sig,digest,glob Physical} /\
    valid_history Shared.history{1} /\ size digest{1} = 256).
  + by call physical_hash_paired; auto.
  sp 1 1; if; first by auto.
  + wp; while (={seed,root,message,sig,digest,ht,current,layer,idx_tree,glob Physical} /\
    valid_history Shared.history{1}).
    - by wp; call digest_layer_recover; auto.
    wp; call digest_forest_recover; auto => /> &m hh hd hz.
    by rewrite (digest_ht_field digest{m} hd).
  by auto.
qed.

lemma raw_signer_finish_digest :
  equiv[RawSigner(Physical).finish ~ PairedDigestSigner(Physical).finish :
    ={seed,randomizer,digest,shuffle,glob Physical} /\ size digest{1} = 256 /\
    valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  transitivity PairedSigningSigner(Physical).finish
    (={seed,randomizer,digest,shuffle,glob Physical} /\ valid_history Shared.history{1} ==>
      ={res,glob Physical} /\ valid_history Shared.history{1})
    (={seed,randomizer,digest,shuffle,glob Physical} /\ size digest{1} = 256 /\
      valid_history Shared.history{1} ==>
      ={res,glob Physical} /\ valid_history Shared.history{1}) => //.
  + smt().
  + exact raw_signer_finish_paired.
  exact digest_signer_finish.
qed.

lemma raw_signer_sign_digest :
  equiv[RawSigner(Physical).sign ~ PairedDigestSigner(Physical).sign :
    ={seed,root,random,message,shuffle,glob Physical} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  transitivity PairedSigningSigner(Physical).sign
    (={seed,root,random,message,shuffle,glob Physical} /\ valid_history Shared.history{1} ==>
      ={res,glob Physical} /\ valid_history Shared.history{1})
    (={seed,root,random,message,shuffle,glob Physical} /\ valid_history Shared.history{1} ==>
      ={res,glob Physical} /\ valid_history Shared.history{1}) => //.
  + smt().
  + exact raw_signer_sign_paired.
  exact digest_signer_sign.
qed.

lemma raw_signer_verify_digest :
  equiv[RawSigner(Physical).verify ~ PairedDigestSigner(Physical).verify :
    ={seed,root,message,sig,glob Physical} /\ outer_counters sig{1} /\ valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  transitivity PairedSigningSigner(Physical).verify
    (={seed,root,message,sig,glob Physical} /\ outer_counters sig{1} /\ valid_history Shared.history{1} ==>
      ={res,glob Physical} /\ valid_history Shared.history{1})
    (={seed,root,message,sig,glob Physical} /\ valid_history Shared.history{1} ==>
      ={res,glob Physical} /\ valid_history Shared.history{1}) => //.
  + smt().
  + exact raw_signer_verify_paired.
  exact digest_signer_verify.
qed.

lemma raw_signer_verify_decoded_digest bytes :
  size bytes = 4008 =>
  equiv[RawSigner(Physical).verify ~ PairedDigestSigner(Physical).verify :
    ={seed,root,message,sig,glob Physical} /\ sig{1} = decode_signature bytes /\
    valid_history Shared.history{1} ==>
    ={res,glob Physical} /\ valid_history Shared.history{1}].
proof.
  move=> hs; conseq raw_signer_verify_digest; smt(outer_decoded_counters).
qed.
