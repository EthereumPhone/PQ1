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

lemma outer_shuffle_index order step n :
  perm_eq order (range 0 n) => 0 <= step < n =>
  0 <= nth 0 order step < n.
proof. smt(perm_eq_size size_range mem_nth perm_eq_mem mem_range).
qed.

lemma outer_forest_compression seed ht roots : 0 <= ht < 2^32 =>
  seed ++ address 0 ht 4 0 0 0 0 ++ flatten (map pad roots) =
    multi_preimage seed (address_words 0 ht 4 0 0 0 0) roots.
proof.
  move=> hht.
  have ha : address 0 ht 4 0 0 0 0 = address_words 0 ht 4 0 0 0 0
    by apply address_common; smt(caller_u32_size tree_u32_u64).
  by rewrite ha multi_input_common.
qed.

lemma outer_count_range (O <: PreparationOracle) :
  hoare [RawWots(O).count : true ==>
    res <> None => 0 <= (oget res).`1 < signing_budget].
proof.
  proc; while (0 <= i <= signing_budget /\
    (result <> None => 0 <= (oget result).`1 < signing_budget)).
  + wp; call (_ : true ==> true); first by trivial.
    auto; smt().
  auto; rewrite /signing_budget; smt().
qed.

lemma outer_sign_range (O <: PreparationOracle) :
  hoare [RawWots(O).sign : true ==>
    res <> None => 0 <= (oget res).`2 < signing_budget].
proof.
  proc; seq 1 : (accepted <> None => 0 <= (oget accepted).`1 < signing_budget).
  + call (outer_count_range O); auto.
  sp 1; if; last by auto.
  wp; while (0 <= (oget accepted).`1 < signing_budget).
  + wp; call (_ : true ==> true); first by trivial.
    call (_ : true ==> true); first by trivial.
    auto.
  wp; call (_ : true ==> true); first by trivial.
  auto.
qed.

lemma outer_wots_sign (O <: PrefixOracle) :
  equiv [RawWots(PreparationView(O)).sign ~ CommonPrivateWots(O).sign :
    ={seed,layer,tree,kp,message,shuffle,glob O} /\ caller_fields layer{1} tree{1} kp{1} ==>
    ={res,glob O} /\ (res{1} <> None => 0 <= (oget res{1}).`2 < signing_budget)].
proof.
  conseq (caller_wots_sign O) (outer_sign_range (PreparationView(O))) _.
qed.

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
    order <@ PairedShuffle(PreparationView(O)).permutation(shuffle,12);
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
    result <- None;
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

lemma caller_forest_one (O <: PrefixOracle) :
  equiv [RawForest(PreparationView(O)).one ~ CommonInputForest(O).one :
    ={seed,ht,tree,leaf,glob O} /\ fors_fields ht{1} tree{1} /\
    0 <= leaf{1} < 2^32 ==> ={res,glob O}].
proof.
  proc; call (caller_fors_recover O); call (caller_fors_sign O); auto.
qed.

lemma outer_forest_last seed ht last_root : 0 <= ht < 2^32 =>
  seed ++ address 0 ht 3 12 0 0 0 ++ pad last_root =
    th_preimage seed (address_words 0 ht 3 12 0 0 0) (pad_node last_root).
proof.
  move=> hht; apply tree_fors_leaf_query; rewrite /fors_fields;
    smt(caller_u32_size).
qed.

lemma caller_forest_sign (O <: PrefixOracle) :
  equiv [RawForest(PreparationView(O)).sign ~ CommonInputForest(O).sign :
    ={seed,ht,digest,shuffle,glob O} /\ 0 <= ht{1} < 2^32 ==>
    ={res,glob O}].
proof.
  proc; seq 5 5 :
    (={seed,ht,digest,order,secrets,auths,roots,glob O} /\
     0 <= ht{1} < 2^32 /\ perm_eq order{1} (range 0 12)).
  + call (caller_shuffle_paired (PreparationView(O)) 12).
    call (shuffle_derive_common (PreparationView(O))).
    by auto; rewrite /shuffle_forest_label.
  wp.
  call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
  wp; call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
  wp; call (caller_fors_root O).
  wp; while (={seed,ht,digest,order,step,secrets,auths,roots,glob O} /\
    0 <= ht{1} < 2^32 /\ perm_eq order{1} (range 0 12) /\
    0 <= step{1} <= 12).
  + wp; call (caller_forest_one O); auto => /> &m hh0 hh hp hs0 hs hlt.
    have [hi0 hi] : 0 <= nth 0 order{m} step{m} /\ nth 0 order{m} step{m} < 2^32.
    - have := outer_shuffle_index order{m} step{m} 12 hp _; first smt().
      rewrite caller_u32_size; smt().
    have [hd0 hd] : 0 <= forest_index digest{m} (nth 0 order{m} step{m}) /\
      forest_index digest{m} (nth 0 order{m} step{m}) < 2^32.
    - have := forest_index_range digest{m} (nth 0 order{m} step{m}).
      rewrite caller_u32_size; smt().
    have [hn0 hn] : 0 <= step{m}+1 /\ step{m}+1 <= 12 by smt().
    by split=> //.
  auto => /> &m hh0 hh hp roots step he1 he2 hs0 hs.
  have hf : 0 <= ht{m} < 2^32 by split=> //.
  split; first by rewrite caller_u32_size.
  move=> _ _ _ last_root; split.
  + exact (outer_forest_last _ _ _ hf).
  move=> _ d; exact (outer_forest_compression _ _ _ hf).
qed.

lemma caller_forest_recover (O <: PrefixOracle) :
  equiv [RawForest(PreparationView(O)).recover ~ CommonInputForest(O).recover :
    ={seed,ht,digest,secrets,auths,glob O} /\ 0 <= ht{1} < 2^32 ==>
    ={res,glob O}].
proof.
  proc; wp.
  call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
  wp; call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
  while (={seed,ht,digest,secrets,auths,roots,t,glob O} /\
    0 <= ht{1} < 2^32 /\ 0 <= t{1} <= 12).
  + wp; call (caller_fors_recover O); auto => /> &m hh0 hh ht0 ht hlt.
    have htu : t{m} < 2^32 by rewrite caller_u32_size; smt().
    have [hd0 hd] : 0 <= forest_index digest{m} t{m} /\ forest_index digest{m} t{m} < 2^32.
    - have := forest_index_range digest{m} t{m}; rewrite caller_u32_size; smt().
    have [hn0 hn] : 0 <= t{m}+1 /\ t{m}+1 <= 12 by smt().
    by split=> //.
  auto => /> &m hh0 hh roots t he1 he2 ht0 ht.
  have hf : 0 <= ht{m} < 2^32 by split=> //.
  split; first exact (outer_forest_last _ _ _ hf).
  move=> _ d; exact (outer_forest_compression _ _ _ hf).
qed.

lemma caller_layer_recover (O <: PrefixOracle) :
  equiv [RawLayer(PreparationView(O)).recover ~ CommonInputLayer(O).recover :
    ={seed,layer,tree,leaf,message,sig,glob O} /\
    caller_fields layer{1} tree{1} leaf{1} /\
    0 <= sig{1}.`2 < 4294967296 ==> ={res,glob O}].
proof.
  proc; call (caller_merkle_recover O).
  call (caller_wots_recover (PreparationView(O))).
  by auto; rewrite /caller_fields /tree_fields; progress.
qed.

lemma caller_layer_sign (O <: PrefixOracle) :
  equiv [RawLayer(PreparationView(O)).sign ~ CommonInputLayer(O).sign :
    ={seed,layer,tree,leaf,message,shuffle,glob O} /\
    caller_fields layer{1} tree{1} leaf{1} ==> ={res,glob O}].
proof.
  proc; seq 3 3 : (={seed,layer,tree,leaf,message,shuffle,built,subseed,signed,glob O} /\
    caller_fields layer{1} tree{1} leaf{1} /\
    (signed{1} <> None => 0 <= (oget signed{1}).`2 < signing_budget)).
  + call (outer_wots_sign O).
    call (shuffle_derive_common (PreparationView(O))).
    call (caller_merkle_build O); by auto;
      rewrite /caller_fields /tree_fields /layer_label /shuffle_layer_label; progress.
  sp 1 1; if; first by auto.
  + wp; call (caller_layer_recover O); auto => /> &m hl0 hl ht0 ht hf0 hf hc hs.
    have [hc0 hcb] := hc hs.
    have hcu : (oget signed{m}).`2 < 4294967296
      by move: hcb; rewrite /signing_budget; smt().
    by split=> //.
  by auto.
qed.

lemma outer_coordinates layer idx :
  0 <= layer < 2 => 0 <= idx < 262144 =>
  caller_fields layer (idx %/ 512) (idx %% 512) /\
  0 <= idx %/ 512 < 262144.
proof.
  move=> hl hi; rewrite /caller_fields;
    smt(divz_ge0 leq_div modz_ge0 ltz_pmod caller_u32_size tree_u32_u64).
qed.

lemma caller_signer_finish (O <: PrefixOracle) :
  equiv [RawSigner(O).finish ~ CommonInputSigner(O).finish :
    ={seed,randomizer,digest,shuffle,glob O} ==> ={res,glob O}].
proof.
  proc; wp.
  while (={seed,randomizer,digest,shuffle,forest,current,idx_tree,layer,layers,ok,glob O} /\
    0 <= idx_tree{1} < 262144 /\ 0 <= layer{1} <= 2).
  + seq 3 3 :
      (={seed,randomizer,digest,shuffle,forest,current,idx_tree,idx_leaf,layer,layers,ok,signed,glob O} /\
       0 <= idx_tree{1} < 262144 /\ 0 <= layer{1} < 2 /\
       0 <= layer{1}+1 <= 2).
    - call (caller_layer_sign O); auto => /> &m hi0 hi hl0 hl hlt hok.
      have hir : 0 <= idx_tree{m} < 262144 by split=> //.
      have hlr : 0 <= layer{m} < 2 by split=> //.
      have hc := outer_coordinates layer{m} idx_tree{m} hlr hir.
      move: hc; rewrite /caller_fields => [#] hl0' hlu hq0 hqu hf0 hfu hq0' hq.
      have [hn0 hn] : 0 <= layer{m}+1 /\ layer{m}+1 <= 2 by smt().
      by progress.
    by if; auto; progress.
  wp; call (caller_forest_sign O); auto => /> &m.
  have [hh0 hh] := hypertree_index_range digest{m}.
  have hhu : hypertree_index digest{m} < 2^32 by rewrite caller_u32_size; smt().
  by progress.
qed.

lemma caller_signer_sign (O <: PrefixOracle) :
  equiv [RawSigner(O).sign ~ CommonInputSigner(O).sign :
    ={seed,root,random,message,shuffle,glob O} ==> ={res,glob O}].
proof.
  proc; seq 1 1 : (={seed,root,random,message,shuffle,accepted,glob O}).
  + call (caller_nonce_grind O); auto.
  sp 1 1; if; first by auto.
  + call (caller_signer_finish O); auto.
  by auto.
qed.

lemma caller_signer_verify (O <: PrefixOracle) :
  equiv [RawSigner(O).verify ~ CommonInputSigner(O).verify :
    ={seed,root,message,sig,glob O} /\ outer_counters sig{1} ==>
    ={res,glob O}].
proof.
  proc; seq 1 1 : (={seed,root,message,sig,digest,glob O} /\ outer_counters sig{1}).
  + call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
    by auto; rewrite hmsg_input_common pad_common.
  sp 1 1; if; first by auto.
  + wp; while (={seed,root,message,sig,digest,ht,current,layer,idx_tree,glob O} /\
      outer_counters sig{1} /\ 0 <= idx_tree{1} < 262144 /\ 0 <= layer{1} <= 2).
    - wp; call (caller_layer_recover O); auto => /> &m hcs hi0 hi hl0 hl hlt.
      have hir : 0 <= idx_tree{m} < 262144 by split=> //.
      have hlr : 0 <= layer{m} < 2 by split=> //.
      have hc := outer_coordinates layer{m} idx_tree{m} hlr hir.
      move: hc; rewrite /caller_fields => [#] hl0' hlu hq0 hqu hf0 hfu hq0' hq.
      move: hcs; rewrite /outer_counters => hcs.
      have [hc0 hcu] := hcs layer{m} hlr.
      have [hn0 hn] : 0 <= layer{m}+1 /\ layer{m}+1 <= 2 by smt().
      by progress.
    wp; call (caller_forest_recover O); auto => /> &m.
    have [hh0 hh] := hypertree_index_range digest{m}.
    have hhu : hypertree_index digest{m} < 2^32 by rewrite caller_u32_size; smt().
    by progress.
  by auto.
qed.

lemma outer_decoded_counters bytes : size bytes = 4008 =>
  outer_counters (decode_signature bytes).
proof.
  move=> hs; have hw := decoded_signature_width bytes hs.
  have hn : size (decode_signature bytes).`4 = 2 by move: hw; rewrite /signature_width; smt().
  have ha : all layer_width (decode_signature bytes).`4 by move: hw; rewrite /signature_width; smt().
  rewrite /outer_counters; move=> i hi.
  have hl : layer_width (nth ([],0,[]) (decode_signature bytes).`4 i)
    by smt(allP mem_nth).
  move: hl; rewrite /layer_width; smt().
qed.

lemma caller_signer_verify_decoded (O <: PrefixOracle) bytes :
  size bytes = 4008 =>
  equiv [RawSigner(O).verify ~ CommonInputSigner(O).verify :
    ={seed,root,message,sig,glob O} /\ sig{1} = decode_signature bytes ==>
    ={res,glob O}].
proof.
  move=> hs; conseq (caller_signer_verify O); smt(outer_decoded_counters).
qed.
