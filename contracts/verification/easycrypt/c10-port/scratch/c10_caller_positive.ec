(* Actual EasyCrypt callers consume the paired common preimages. The same
   arbitrary oracle runs on both sides; its entire global state is preserved.
   These are caller-component equivalences, not concrete-SHA idealizations or
   a cross-kernel Rust/session theorem. *)
require import AllCore List IntDiv Ring RadixEncoding.
require import C10Bytes C10Counter C10HashDomains C10RawOracle C10RawGrind.
require import PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RoleGrind.
require import C10Representation C10HashInputBridge C10AddressInputBridge.

op caller_fields layer tree kp =
  0 <= layer < 2^32 /\ 0 <= tree < 2^64 /\ 0 <= kp < 2^32.

lemma caller_u32_size : 2^32 = 4294967296.
proof. by rewrite (_ : 32=2*2*2*2*2) 1:// !IntID.exprM !IntID.expr2.
qed.

lemma caller_counter_slot c : 0 <= c < 4294967296 =>
  be 32 c = nseq 28 0 ++ u32_bytes c.
proof.
  move=> hc; have hv : U32.val (U32.insubd c) = c by exact (U32.insubdK c hc).
  by rewrite -{1}hv full_counter_word hv.
qed.

lemma caller_wots_query seed layer tree kp message c :
  caller_fields layer tree kp => 0 <= c < 4294967296 =>
  seed ++ address layer tree 0 kp 0 0 0 ++ pad message ++ be 32 c =
    wots_preimage seed (address_words layer tree 0 kp 0 0 0) (pad_node message) c.
proof.
  move=> hf hc.
  have ha : address layer tree 0 kp 0 0 0 = address_words layer tree 0 kp 0 0 0
    by apply address_common; move: hf; rewrite /caller_fields; smt(caller_u32_size).
  by rewrite ha (caller_counter_slot c hc) /wots_preimage /pad_node /pad !catA.
qed.

lemma caller_chain_query seed layer tree kp index j current :
  caller_fields layer tree kp => 0 <= index < 2^32 => 0 <= j < 2^32 =>
  seed ++ address layer tree 0 kp index j 0 ++ pad current =
    th_preimage seed (address_words layer tree 0 kp index j 0) (pad_node current).
proof.
  move=> hf hi hj.
  have ha : address layer tree 0 kp index j 0 = address_words layer tree 0 kp index j 0
    by apply address_common; move: hf; rewrite /caller_fields; smt(caller_u32_size).
  by rewrite ha /th_preimage /pad_node /pad.
qed.

lemma caller_multi_query seed layer tree kp nodes :
  caller_fields layer tree kp =>
  seed ++ address layer tree 1 kp 0 0 0 ++ flatten (map pad nodes) =
    multi_preimage seed (address_words layer tree 1 kp 0 0 0) nodes.
proof.
  move=> hf.
  have ha : address layer tree 1 kp 0 0 0 = address_words layer tree 1 kp 0 0 0
    by apply address_common; move: hf; rewrite /caller_fields; smt(caller_u32_size).
  by rewrite ha multi_input_common.
qed.

module CommonInputWots (O : PreparationOracle) = {
  proc count(seed : raw_input, layer tree kp : int, message : raw_input) : (int * digest) option = {
    var i, d, result;
    i <- 0; result <- None;
    while (i < signing_budget /\ result = None) {
      d <@ O.hash(wots_preimage seed (address_words layer tree 0 kp 0 0 0) (pad_node message) i);
      if (count_accepts d) { result <- Some (i,d); }
      i <- i+1;
    }
    return result;
  }
  proc chain(seed : raw_input, layer tree kp index : int, current : raw_input, start stop : int) : raw_input = {
    var j, d;
    j <- start;
    while (j < stop) {
      d <@ O.hash(th_preimage seed (address_words layer tree 0 kp index j 0) (pad_node current));
      current <- node d; j <- j+1;
    }
    return current;
  }
  proc recover(seed : raw_input, layer tree kp : int, message : raw_input, sigma : raw_input list, count : int) : raw_input = {
    var d, result, i, current, elements;
    d <@ O.hash(wots_preimage seed (address_words layer tree 0 kp 0 0 0) (pad_node message) count);
    result <- nseq 16 0;
    if (count_accepts d) {
      i <- 0; elements <- [];
      while (i < 43) {
        current <@ chain(seed,layer,tree,kp,i,nth (nseq 16 0) sigma i,RadixEncoding.digit 3 d i,7);
        elements <- rcons elements current; i <- i+1;
      }
      d <@ O.hash(multi_preimage seed (address_words layer tree 1 kp 0 0 0) elements);
      result <- node d;
    }
    return result;
  }
}.

lemma caller_wots_count (O <: PreparationOracle) :
  equiv [RawWots(O).count ~ CommonInputWots(O).count :
    ={seed,layer,tree,kp,message,glob O} /\ caller_fields layer{1} tree{1} kp{1} ==>
    ={res,glob O}].
proof.
  proc; while (={seed,layer,tree,kp,message,i,result,glob O} /\
    caller_fields layer{1} tree{1} kp{1} /\ 0 <= i{1} <= signing_budget).
  + wp; call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
    auto => /> &m hl0 hl ht0 ht hk0 hk hi0 hi hlt.
    have hf : caller_fields layer{m} tree{m} kp{m} by rewrite /caller_fields; smt().
    have hc : 0 <= i{m} < 4294967296 by move: hi0 hlt; rewrite /signing_budget; smt().
    have [hslo hshi] : 0 <= i{m}+1 /\ i{m}+1 <= signing_budget by smt().
    split; first exact (caller_wots_query seed{m} layer{m} tree{m} kp{m} message{m} i{m} hf hc).
    move=> _ dr; split=> _; by split=> //.
  by auto; rewrite /signing_budget.
qed.

lemma caller_wots_chain (O <: PreparationOracle) :
  equiv [RawWots(O).chain ~ CommonInputWots(O).chain :
    ={seed,layer,tree,kp,index,current,start,stop,glob O} /\
    caller_fields layer{1} tree{1} kp{1} /\ 0 <= index{1} < 2^32 /\
    0 <= start{1} /\ stop{1} <= 2^32 ==>
    ={res,glob O}].
proof.
  proc; while (={seed,layer,tree,kp,index,current,j,stop,glob O} /\
    caller_fields layer{1} tree{1} kp{1} /\ 0 <= index{1} < 2^32 /\
    0 <= j{1} /\ stop{1} <= 2^32).
  + wp; call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
    auto => /> &m hl0 hl ht0 ht hk0 hk hi0 hi hj0 hs hj.
    have hf : caller_fields layer{m} tree{m} kp{m} by rewrite /caller_fields; smt().
    have hindex : 0 <= index{m} < 2^32 by smt().
    have hpos : 0 <= j{m} < 2^32 by smt().
    have hnext : 0 <= j{m}+1 by smt().
    split; first exact (caller_chain_query seed{m} layer{m} tree{m} kp{m} index{m} j{m} current{m} hf hindex hpos).
    by auto.
  by auto.
qed.

lemma caller_wots_recover (O <: PreparationOracle) :
  equiv [RawWots(O).recover ~ CommonInputWots(O).recover :
    ={seed,layer,tree,kp,message,sigma,count,glob O} /\
    caller_fields layer{1} tree{1} kp{1} /\ 0 <= count{1} < 4294967296 ==>
    ={res,glob O}].
proof.
  proc; seq 1 1 : (={seed,layer,tree,kp,message,sigma,count,d,glob O} /\
    caller_fields layer{1} tree{1} kp{1}).
  + call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
    auto => /> &m hl0 hl ht0 ht hk0 hk hc0 hc.
    have hf : caller_fields layer{m} tree{m} kp{m} by rewrite /caller_fields; smt().
    have hcount : 0 <= count{m} < 4294967296 by smt().
    exact (caller_wots_query seed{m} layer{m} tree{m} kp{m} message{m} count{m} hf hcount).
  sp 1 1; if; first by auto.
  - wp; call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
  wp; while (={seed,layer,tree,kp,sigma,d,i,glob O} /\
    caller_fields layer{1} tree{1} kp{1} /\ 0 <= i{1} <= 43 /\
    elements{1} = map pad elements{2}).
  + wp; call (caller_wots_chain O).
    auto => /> &m hl0 hl ht0 ht hk0 hk hi0 hi hlt.
    have [hd _] := raw_digit_bounds d{m} i{m}.
    have hindex : i{m} < 2^32 by rewrite caller_u32_size; smt().
    have hseven : 7 <= 2^32 by rewrite caller_u32_size.
    have [hslo hshi] : 0 <= i{m}+1 /\ i{m}+1 <= 43 by smt().
    split; first by auto.
    move=> _ _ _ out; split; first by auto.
    by rewrite map_rcons.
  auto => />; smt(caller_multi_query).
  by auto.
qed.

module CommonInputGrind (O : PrefixOracle) = {
  proc run(random message seed root : int list) : (int list * bool list) option = {
    var i, rd, hd, r, result;
    i <- 0; result <- None;
    while (i < signing_budget /\ result = None) {
      rd <@ O.derive(r_preimage [] random message i);
      r <- compact_r rd;
      hd <@ O.hash(hmsg_preimage seed root (pad_node r) message);
      if (accept_digest hd) { result <- Some (r,hd); }
      i <- i+1;
    }
    return result;
  }
}.

lemma caller_r_tail random message i : 0 <= i < 4294967296 =>
  r_tail random message (U32.insubd i) = r_preimage [] random message i.
proof.
  move=> hi.
  by rewrite /r_tail /r_preimage counter_common (U32.insubdK i hi) /=.
qed.

lemma caller_nonce_grind (O <: PrefixOracle) :
  equiv [RoleGrind(O).run ~ CommonInputGrind(O).run :
    ={random,message,seed,root,glob O} ==> ={res,glob O}].
proof.
  proc; while (={random,message,seed,root,i,result,glob O} /\
    0 <= i{1} <= signing_budget).
  + wp; call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
    wp; call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
    auto => /> &m hi0 hi hlt.
    have hc : 0 <= i{m} < 4294967296 by move: hi0 hlt; rewrite /signing_budget; smt().
    have [hslo hshi] : 0 <= i{m}+1 /\ i{m}+1 <= signing_budget by smt().
    split; first exact (caller_r_tail random{m} message{m} i{m} hc).
    move=> _ rd _ hd; split=> _; by split=> //.
  by auto; rewrite /signing_budget.
qed.
