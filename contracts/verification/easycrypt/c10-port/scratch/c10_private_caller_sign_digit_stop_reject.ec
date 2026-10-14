(* Common private inputs in the actual WOTS leaf and signing callers.
   The same arbitrary oracle runs on both sides, including its full state.
   Signing composes the paired shuffle representation with exact order and
   oracle-state preservation; no concrete-SHA interpretation is asserted here. *)
require import AllCore List IntDiv RadixEncoding.
require import C10Bytes C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawWots RawLeafChains RawWotsFill RawShuffle ShuffleBytes ShuffleSwap.
require import C10Representation C10AddressInputBridge C10CallerInputBridge C10ShuffleBridge.

lemma caller_private_query layer tree kp index :
  caller_fields layer tree kp => 0 <= index < 2^32 =>
  wots_tag ++ wots_tail layer tree kp index =
    wots_private_preimage [] layer tree kp index.
proof.
  move=> [hl [ht hk]] hi.
  by have := wots_private_common [] layer tree kp index hl ht hk hi; rewrite /=.
qed.

(* Partial correctness requires no losslessness premise on the shared oracle. *)
lemma caller_shuffle_permutation (O <: PreparationOracle) n0 :
  hoare [RawShuffle(O).permutation : n = n0 /\ 0 <= n0 ==> perm_eq res (range 0 n0)].
proof.
  proc; sp 1; if; last by auto; smt(perm_eq_refl).
  while (n=n0 /\ perm_eq order (range 0 n) /\ 0 <= i < n /\
    all (fun b => 0 <= b < 256) stream).
  + auto; move=> &m [hinv hguard].
    have hs : size order{m} = n{m} by smt(perm_eq_size size_range).
    have hlo := shuffle_nth_byte stream{m} pos{m} _; first smt().
    have hhi := shuffle_nth_byte stream{m} (pos{m}+1) _; first smt().
    have hj := shuffle_mulhi_range (nth 0 stream{m} pos{m})
      (nth 0 stream{m} (pos{m}+1)) i{m} hlo hhi _; first smt().
    have hp := swap_put_permutation 0 order{m} i{m}
      (((nth 0 stream{m} (pos{m}+1)*256+nth 0 stream{m} pos{m})*(i{m}+1)) %/ 65536) _ _;
      first 2 smt().
    smt(perm_eq_trans).
  wp; while (n=n0 /\ perm_eq order (range 0 n) /\ 1 < n /\
    all (fun b => 0 <= b < 256) stream).
  + wp; call (_ : true ==> true); first by trivial.
    auto; smt(all_cat shuffle_bytes_valid).
  auto; smt(perm_eq_refl).
qed.

module CommonPrivateWots (O : PrefixOracle) = {
  proc leaf(seed : raw_input, layer tree kp : int) : raw_input = {
    var i, d, current, elements;
    i <- 0; elements <- [];
    while (i < 43) {
      d <@ O.derive(wots_private_preimage [] layer tree kp i);
      current <@ CommonInputWots(PreparationView(O)).chain(seed,layer,tree,kp,i,node d,0,7);
      elements <- rcons elements current; i <- i+1;
    }
    d <@ O.hash(multi_preimage seed (address_words layer tree 1 kp 0 0 0) elements);
    return node d;
  }
  proc fill(seed : raw_input, layer tree kp : int, accepted : digest, shuffle : raw_input) : raw_input list = {
    var order, step, i, d, current, sigma;
    sigma <- nseq 43 (nseq 16 0);
    order <@ PairedShuffle(PreparationView(O)).permutation(shuffle,43);
    step <- 0;
    while (step < 43) {
      i <- nth 0 order step;
      d <@ O.derive(wots_private_preimage [] layer tree kp i);
      current <@ CommonInputWots(PreparationView(O)).chain(seed,layer,tree,kp,i,node d,0,7);
      sigma <- put sigma i current; step <- step+1;
    }
    return sigma;
  }
  proc sign(seed : raw_input, layer tree kp : int, message shuffle : raw_input) : (raw_input list * int) option = {
    var accepted, sigma, result;
    accepted <@ CommonInputWots(PreparationView(O)).count(seed,layer,tree,kp,message);
    result <- None;
    if (accepted <> None) {
      sigma <@ fill(seed,layer,tree,kp,(oget accepted).`2,shuffle);
      result <- Some (sigma,(oget accepted).`1);
    }
    return result;
  }
}.

lemma caller_leaf_chains (O <: PrefixOracle) :
  equiv [RawLeafChains(PreparationView(O)).leaf ~ CommonPrivateWots(O).leaf :
    ={seed,layer,tree,kp,glob O} /\ caller_fields layer{1} tree{1} kp{1} ==>
    ={res,glob O}].
proof.
  proc; call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
  wp; while (={seed,layer,tree,kp,i,glob O} /\
    caller_fields layer{1} tree{1} kp{1} /\ 0 <= i{1} <= 43 /\
    elements{1} = map pad elements{2}).
  + wp; call (caller_wots_chain (PreparationView(O))).
    inline PreparationView(O).wots; wp.
    call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
    auto => /> &m hl0 hl ht0 ht hk0 hk hi0 hi hlt.
    have hf : caller_fields layer{m} tree{m} kp{m} by rewrite /caller_fields; smt().
    have hindex : 0 <= i{m} < 2^32 by rewrite caller_u32_size; smt().
    have hseven : 7 <= 2^32 by rewrite caller_u32_size.
    split; first exact (caller_private_query layer{m} tree{m} kp{m} i{m} hf hindex).
    move=> _; split; first by smt().
    move=> _ _ out; split; first by smt().
    by rewrite map_rcons.
  auto => /> &m hl0 hl ht0 ht hk0 hk nodes i _ _ hi0 hi.
  have hf : caller_fields layer{m} tree{m} kp{m} by rewrite /caller_fields; smt().
  exact (caller_multi_query seed{m} layer{m} tree{m} kp{m} nodes hf).
qed.

lemma caller_keygen_leaf (O <: PrefixOracle) :
  equiv [RawKeygen(PreparationView(O)).leaf ~ CommonPrivateWots(O).leaf :
    ={seed,layer,tree,kp,glob O} /\ caller_fields layer{1} tree{1} kp{1} ==>
    ={res,glob O}].
proof.
  transitivity RawLeafChains(PreparationView(O)).leaf
    (={seed,layer,tree,kp,glob O} ==> ={res,glob O})
    (={seed,layer,tree,kp,glob O} /\ caller_fields layer{1} tree{1} kp{1} ==> ={res,glob O}) => //.
  + smt().
  + exact (raw_leaf_chain_projection (PreparationView(O))).
  exact (caller_leaf_chains O).
qed.

lemma caller_shuffle_paired (O <: PreparationOracle) n0 :
  equiv [RawShuffle(O).permutation ~ PairedShuffle(O).permutation :
    ={arg,glob O} /\ n{1}=n0 /\ 0 <= n0 <= 64 ==>
    ={res,glob O} /\ perm_eq res{1} (range 0 n0)].
proof.
  conseq (shuffle_permutation_common O)
    (caller_shuffle_permutation O n0) _; smt().
qed.

lemma caller_shuffle_index order step :
  perm_eq order (range 0 43) => 0 <= step < 43 =>
  0 <= nth 0 order step < 43.
proof. smt(perm_eq_size size_range mem_nth perm_eq_mem mem_range).
qed.

lemma caller_wots_fill (O <: PrefixOracle) :
  equiv [RawWotsFill(PreparationView(O)).fill ~ CommonPrivateWots(O).fill :
    ={seed,layer,tree,kp,accepted,shuffle,glob O} /\ caller_fields layer{1} tree{1} kp{1} ==>
    ={res,glob O}].
proof.
  proc; while (={seed,layer,tree,kp,accepted,order,step,sigma,glob O} /\
    caller_fields layer{1} tree{1} kp{1} /\
    perm_eq order{1} (range 0 43) /\ 0 <= step{1} <= 43).
  + wp; call (caller_wots_chain (PreparationView(O))).
    inline PreparationView(O).wots; wp.
    call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
    auto => /> &m hl0 hl ht0 ht hk0 hk hp hs0 hs hlt.
    have hf : caller_fields layer{m} tree{m} kp{m} by rewrite /caller_fields; smt().
    have hi : 0 <= nth 0 order{m} step{m} < 43 by apply caller_shuffle_index; smt().
    have hindex : 0 <= nth 0 order{m} step{m} < 2^32 by rewrite caller_u32_size; smt().
    have [hd0 hd] := raw_digit_bounds accepted{m} (nth 0 order{m} step{m}).
    have hstop : digit 3 accepted{m} (nth 0 order{m} step{m}) <= 2^32 by rewrite caller_u32_size; smt().
    split; first exact (caller_private_query layer{m} tree{m} kp{m} (nth 0 order{m} step{m}) hf hindex).
    have [hindex0 hindexhi] := hindex.
    move=> _; split.
    + split; first by split=> //.
      exact hstop.
    move=> _ _ _.
    have [hlo hhi] : 0 <= step{m}+1 /\ step{m}+1 <= 43 by smt().
    by split=> //.
  wp; call (caller_shuffle_paired (PreparationView(O)) 43).
  by auto.
qed.

lemma caller_wots_sign_factored (O <: PrefixOracle) :
  equiv [RawWotsFill(PreparationView(O)).sign ~ CommonPrivateWots(O).sign :
    ={seed,layer,tree,kp,message,shuffle,glob O} /\ caller_fields layer{1} tree{1} kp{1} ==>
    ={res,glob O}].
proof.
  proc; seq 1 1 : (={seed,layer,tree,kp,message,shuffle,accepted,glob O} /\
    caller_fields layer{1} tree{1} kp{1}).
  + call (caller_wots_count (PreparationView(O))); auto.
  sp 1 1; if; first by auto.
  + wp; call (caller_wots_fill O); auto.
  by auto.
qed.

lemma caller_wots_sign (O <: PrefixOracle) :
  equiv [RawWots(PreparationView(O)).sign ~ CommonPrivateWots(O).sign :
    ={seed,layer,tree,kp,message,shuffle,glob O} /\ caller_fields layer{1} tree{1} kp{1} ==>
    ={res,glob O}].
proof.
  transitivity RawWotsFill(PreparationView(O)).sign
    (={seed,layer,tree,kp,message,shuffle,glob O} ==> ={res,glob O})
    (={seed,layer,tree,kp,message,shuffle,glob O} /\ caller_fields layer{1} tree{1} kp{1} ==> ={res,glob O}) => //.
  + smt().
  + exact (raw_wots_fill_projection (PreparationView(O))).
  exact (caller_wots_sign_factored O).
qed.
