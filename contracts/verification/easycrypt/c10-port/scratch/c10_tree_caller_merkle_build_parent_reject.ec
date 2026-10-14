(* Common-input composition for the actual FORS and Merkle tree callers.
   Results and the full state of the same arbitrary oracle are preserved.
   This is neither a concrete-SHA interpretation nor a cross-kernel theorem. *)
require import AllCore List IntDiv StdOrder.
require import C10Bytes C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawFors RawMerkle DyadicStack StackProjection StackPowers.
require import C10Representation C10AddressInputBridge C10CallerInputBridge C10PrivateCallerBridge.
import IntOrder.

op tree_fields layer tree = 0 <= layer < 2^32 /\ 0 <= tree < 2^64.
op fors_fields ht tree = 0 <= ht < 2^32 /\ 0 <= tree < 2^32.

lemma tree_u32_u64 : 2^32 <= 2^64.
proof. by apply pow2_mono.
qed.

lemma tree_fors_private_query ht tree index :
  fors_fields ht tree => 0 <= index < 2^32 =>
  fors_tag ++ fors_tail ht tree index = fors_private_preimage [] ht tree index.
proof.
  move=> [hh htree] hi.
  by have := fors_private_common [] ht tree index hh htree hi; rewrite /=.
qed.

lemma tree_fors_leaf_query seed ht tree index secret :
  fors_fields ht tree => 0 <= index < 2^32 =>
  seed ++ address 0 ht 3 tree 0 0 index ++ pad secret =
    th_preimage seed (address_words 0 ht 3 tree 0 0 index) (pad_node secret).
proof.
  move=> hf hi.
  have ha : address 0 ht 3 tree 0 0 index = address_words 0 ht 3 tree 0 0 index
    by apply address_common; move: hf; rewrite /fors_fields; smt(caller_u32_size tree_u32_u64).
  by rewrite ha /th_preimage /pad_node /pad.
qed.

lemma tree_pair_query seed layer tree kind kp height parent left_node right_node :
  tree_fields layer tree => 0 <= kind < 2^32 => 0 <= kp < 2^32 =>
  0 <= height < 2^32 => 0 <= parent < 2^32 =>
  seed ++ address layer tree kind kp 0 height parent ++ pad left_node ++ pad right_node =
    pair_preimage seed (address_words layer tree kind kp 0 height parent)
      (pad_node left_node) (pad_node right_node).
proof.
  move=> hf hk hkp hh hp.
  have ha : address layer tree kind kp 0 height parent =
    address_words layer tree kind kp 0 height parent
    by apply address_common; move: hf; rewrite /tree_fields; smt(caller_u32_size).
  by rewrite ha /pair_preimage /pad_node /pad.
qed.

lemma tree_parent_bound j h : 0 <= j => 0 <= h =>
  0 <= j %/ (2^(h+1)) <= j.
proof.
  move=> hj hh.
  have hp : 0 < 2^(h+1) by apply pow2_pos; smt().
  smt(divz_ge0 leq_div).
qed.

lemma tree_stack_bounds (stack : (raw_input * int) list) h j :
  0 <= j < 2048 => active_stack (map snd stack) h =>
  stack_mass (map snd stack) + 2^h = j+1 =>
  0 <= h <= 11 /\ 0 <= j %/ (2^(h+1)) < 2^32.
proof.
  move=> hj ha hm.
  have hn : 0 <= h by move: ha; rewrite /active_stack; smt().
  have hs : increasing_stack (map snd stack) by move: ha; rewrite /active_stack; smt().
  have hnz := stack_mass_nonnegative (map snd stack) (increasing_nonnegative _ hs).
  have hle : h <= 11 by apply (ler_weexpn2r 2) => //; smt(stack_pow2_11).
  have hp := tree_parent_bound j h _ hn; first smt().
  by rewrite caller_u32_size; smt().
qed.

module CommonInputFors (O : PrefixOracle) = {
  proc tree(seed : raw_input, ht tree target : int) : raw_input * raw_input list = {
    var j, current, height, stack, sibling, parent, d, auth, target_h, sibidx, left_start, right_start;
    j <- 0; stack <- []; auth <- nseq 11 (nseq 16 0);
    while (j < 2048) {
      d <@ O.derive(fors_private_preimage [] ht tree j);
      current <- node d;
      d <@ O.hash(th_preimage seed (address_words 0 ht 3 tree 0 0 j) (pad_node current));
      current <- node d; height <- 0;
      while (stack <> [] /\ (head ([],0) stack).`2 = height) {
        sibling <- (head ([],0) stack).`1;
        stack <- behead stack;
        parent <- j %/ (2^(height+1));
        target_h <- target %/ (2^height);
        sibidx <- sibling_index target_h;
        left_start <- parent * (2^(height+1));
        right_start <- left_start + 2^height;
        if (sibidx %% 2 = 0) {
          if (sibidx * (2^height) = left_start) { auth <- put auth height sibling; }
        } else {
          if (sibidx * (2^height) = right_start) { auth <- put auth height current; }
        }
        d <@ O.hash(pair_preimage seed (address_words 0 ht 3 tree 0 (height+1) parent) (pad_node sibling) (pad_node current));
        current <- node d; height <- height+1;
      }
      stack <- (current,height)::stack; j <- j+1;
    }
    return ((head (nseq 16 0,0) stack).`1,auth);
  }
  proc root(seed : raw_input, ht tree : int) : raw_input = {
    var result; result <@ tree(seed,ht,tree,0); return result.`1;
  }
  proc sign(seed : raw_input, ht tree target : int) : raw_input * raw_input list = {
    var d, secret, result;
    d <@ O.derive(fors_private_preimage [] ht tree target); secret <- node d;
    result <@ tree(seed,ht,tree,target);
    return (secret,result.`2);
  }
  proc recover(seed : raw_input, ht tree target : int, secret : raw_input, auth : raw_input list) : raw_input = {
    var d, current, h, idx, sibling, parent, left, right;
    d <@ O.hash(th_preimage seed (address_words 0 ht 3 tree 0 0 target) (pad_node secret));
    current <- node d; h <- 0; idx <- target;
    while (h < 11) {
      sibling <- nth (nseq 16 0) auth h; parent <- idx %/ 2;
      left <- if idx %% 2 = 0 then current else sibling;
      right <- if idx %% 2 = 0 then sibling else current;
      d <@ O.hash(pair_preimage seed (address_words 0 ht 3 tree 0 (h+1) parent) (pad_node left) (pad_node right));
      current <- node d; idx <- parent; h <- h+1;
    }
    return current;
  }
}.

module CommonInputMerkle (O : PrefixOracle) = {
  proc build(seed : raw_input, layer tree target : int) : raw_input list * raw_input = {
    var kp, current, height, stack, left, parent, d, keep, kept, target_h, sibling_h, pair_start, left_idx, right_idx;
    kp <- 0; stack <- []; keep <- nseq 9 (nseq 16 0); kept <- nseq 9 false;
    while (kp < 512) {
      current <@ CommonPrivateWots(O).leaf(seed,layer,tree,kp);
      height <- 0;
      while (stack <> [] /\ (head ([],0) stack).`2 = height) {
        left <- (head ([],0) stack).`1;
        stack <- behead stack;
        if (!nth false kept height) {
          target_h <- target %/ (2^height); sibling_h <- sibling_index target_h;
          pair_start <- (kp %/ (2^(height+1))) * (2^(height+1));
          left_idx <- pair_start %/ (2^height); right_idx <- left_idx+1;
          if (left_idx = sibling_h) {
            keep <- put keep height left; kept <- put kept height true;
          } else {
            if (right_idx = sibling_h) {
              keep <- put keep height current; kept <- put kept height true;
            }
          }
        }
        parent <- kp %/ (2^height);
        d <@ O.hash(pair_preimage seed (address_words layer tree 2 0 0 (height+1) parent) (pad_node left) (pad_node current));
        current <- node d; height <- height+1;
      }
      stack <- (current,height)::stack; kp <- kp+1;
    }
    return (keep,(head (nseq 16 0,0) stack).`1);
  }
  proc recover(seed : raw_input, layer tree : int, leaf : raw_input, index : int, auth : raw_input list) : raw_input = {
    var current, idx, h, parent, sibling, left, right, d;
    current <- leaf; idx <- index; h <- 0;
    while (h < 9) {
      parent <- idx %/ 2; sibling <- nth (nseq 16 0) auth h;
      left <- if idx %% 2 = 0 then current else sibling;
      right <- if idx %% 2 = 0 then sibling else current;
      d <@ O.hash(pair_preimage seed (address_words layer tree 2 0 0 (h+1) parent) (pad_node left) (pad_node right));
      current <- node d; idx <- parent; h <- h+1;
    }
    return current;
  }
  proc root(seed : raw_input, layer tree : int) : raw_input = {
    var kp, current, height, stack, sibling, parent, d;
    kp <- 0; stack <- [];
    while (kp < 512) {
      current <@ CommonPrivateWots(O).leaf(seed,layer,tree,kp);
      height <- 0;
      while (stack <> [] /\ (head ([],0) stack).`2 = height) {
        sibling <- (head ([],0) stack).`1;
        stack <- behead stack;
        parent <- kp %/ (2^(height+1));
        d <@ O.hash(pair_preimage seed (address_words layer tree 2 0 0 (height+1) parent) (pad_node sibling) (pad_node current));
        current <- node d; height <- height+1;
      }
      stack <- (current,height)::stack; kp <- kp+1;
    }
    return (head (nseq 16 0,0) stack).`1;
  }
}.

lemma caller_merkle_recover (O <: PrefixOracle) :
  equiv [RawMerkle(PreparationView(O)).recover ~ CommonInputMerkle(O).recover :
    ={seed,layer,tree,leaf,index,auth,glob O} /\ tree_fields layer{1} tree{1} /\
    0 <= index{1} < 2^32 ==> ={res,glob O}].
proof.
  proc; while (={seed,layer,tree,current,idx,h,auth,glob O} /\
    tree_fields layer{1} tree{1} /\ 0 <= idx{1} < 2^32 /\ 0 <= h{1} <= 9).
  + wp; call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
    auto => /> &m hl0 hl ht0 ht hi0 hi hh0 hh hlt.
    have hf : tree_fields layer{m} tree{m} by rewrite /tree_fields; smt().
    have hp : 0 <= idx{m} %/ 2 < 2^32 by smt(divz_ge0 leq_div).
    have hc : 0 <= h{m}+1 < 2^32 by rewrite caller_u32_size; smt().
    have hk : 0 <= 2 < 2^32 by rewrite caller_u32_size.
    have hz : 0 <= 0 < 2^32 by rewrite caller_u32_size.
    split; first exact (tree_pair_query _ _ _ _ _ _ _ _ _ hf hk hz hc hp).
    by auto; smt().
  by auto.
qed.

lemma caller_fors_recover (O <: PrefixOracle) :
  equiv [RawFors(PreparationView(O)).recover ~ CommonInputFors(O).recover :
    ={seed,ht,tree,target,secret,auth,glob O} /\ fors_fields ht{1} tree{1} /\
    0 <= target{1} < 2^32 ==> ={res,glob O}].
proof.
  proc; while (={seed,ht,tree,current,idx,h,auth,glob O} /\
    fors_fields ht{1} tree{1} /\ 0 <= idx{1} < 2^32 /\ 0 <= h{1} <= 11).
  + wp; call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
    auto => /> &m hh0 hh ht0 ht hi0 hi h0 h hlt.
    have hf : tree_fields 0 ht{m} by rewrite /tree_fields; smt(caller_u32_size tree_u32_u64).
    have hp : 0 <= idx{m} %/ 2 < 2^32 by smt(divz_ge0 leq_div).
    have hc : 0 <= h{m}+1 < 2^32 by rewrite caller_u32_size; smt().
    have hk : 0 <= 3 < 2^32 by rewrite caller_u32_size.
    have htree : 0 <= tree{m} < 2^32 by smt().
    split; first exact (tree_pair_query _ _ _ _ _ _ _ _ _ hf hk htree hc hp).
    by auto; smt().
  wp; call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
  auto => /> &m hh0 hh ht0 ht hi0 hi.
  have hf : fors_fields ht{m} tree{m} by rewrite /fors_fields; smt().
  have hindex : 0 <= target{m} < 2^32 by smt().
  exact (tree_fors_leaf_query _ _ _ _ _ hf hindex).
qed.

lemma caller_fors_tree (O <: PrefixOracle) :
  equiv [RawFors(PreparationView(O)).tree ~ CommonInputFors(O).tree :
    ={seed,ht,tree,target,glob O} /\ fors_fields ht{1} tree{1} ==> ={res,glob O}].
proof.
  proc; while (={seed,ht,tree,target,j,stack,auth,glob O} /\
    fors_fields ht{1} tree{1} /\ 0 <= j{1} <= 2048 /\
    increasing_stack (map snd stack{1}) /\ stack_mass (map snd stack{1}) = j{1}).
  + wp; while (={seed,ht,tree,target,j,current,height,stack,auth,glob O} /\
      fors_fields ht{1} tree{1} /\ 0 <= j{1} < 2048 /\
      active_stack (map snd stack{1}) height{1} /\
      stack_mass (map snd stack{1}) + 2^height{1} = j{1}+1).
    - wp; call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
      auto => /> &m hh0 hh ht0 ht hj0 hj hhgt hs hall hm hn.
      have ha : active_stack (map snd stack{m}) (head ([],0) stack{m}).`2
        by rewrite /active_stack; smt().
      have hb := tree_stack_bounds stack{m} (head ([],0) stack{m}).`2 j{m} _ ha hm; first smt().
      have hf : tree_fields 0 ht{m} by rewrite /tree_fields; smt(caller_u32_size tree_u32_u64).
      have hk : 0 <= 3 < 2^32 by rewrite caller_u32_size.
      have htree : 0 <= tree{m} < 2^32 by smt().
      have hc : 0 <= (head ([],0) stack{m}).`2+1 < 2^32 by move: hb; rewrite caller_u32_size; smt().
      have hp : 0 <= j{m} %/ (2^((head ([],0) stack{m}).`2+1)) < 2^32 by smt().
      have pop := projected_carry_pop stack{m} [] (head ([],0) stack{m}).`2 ha hn _; first by trivial.
      have hq := tree_pair_query seed{m} 0 ht{m} 3 tree{m} ((head ([],0) stack{m}).`2+1)
        (j{m} %/ (2^((head ([],0) stack{m}).`2+1))) (head ([],0) stack{m}).`1 current{m} hf hk htree hc hp.
      move: pop => [hnext hmass].
      have hmass' : stack_mass (map snd (behead stack{m})) +
        2^((head ([],0) stack{m}).`2+1) = j{m}+1 by smt().
      have hnext0 : 0 <= (head ([],0) stack{m}).`2+1 by smt().
      have hnextinc : increasing_stack (map snd (behead stack{m}))
        by move: hnext; rewrite /active_stack; smt().
      have hnextall : all ((<=) ((head ([],0) stack{m}).`2+1)) (map snd (behead stack{m}))
        by move: hnext; rewrite /active_stack; smt().
      rewrite hq; by auto.
    wp; call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
    inline PreparationView(O).fors; wp.
    call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
    auto => /> &m hh0 hh ht0 ht hj0 hj hs hlt.
    have hf : fors_fields ht{m} tree{m} by rewrite /fors_fields; smt().
    have hi : 0 <= stack_mass (map snd stack{m}) < 2^32 by rewrite caller_u32_size; smt().
    split; first exact (tree_fors_private_query _ _ _ hf hi).
    move=> _ dr; split; first exact (tree_fors_leaf_query _ _ _ _ _ hf hi).
    move=> _; split; first by rewrite expr0; smt(increasing_nonnegative).
    move=> h st hn1 hn2 h0 hinc hall hm.
    have ha : active_stack (map snd st) h by rewrite /active_stack; smt().
    have hp := projected_carry_push st [] [] h ha _; first smt().
    move: hp; rewrite /=; smt().
  by auto.
qed.

lemma caller_fors_root (O <: PrefixOracle) :
  equiv [RawFors(PreparationView(O)).root ~ CommonInputFors(O).root :
    ={seed,ht,tree,glob O} /\ fors_fields ht{1} tree{1} ==> ={res,glob O}].
proof. proc; call (caller_fors_tree O); auto.
qed.

lemma caller_fors_sign (O <: PrefixOracle) :
  equiv [RawFors(PreparationView(O)).sign ~ CommonInputFors(O).sign :
    ={seed,ht,tree,target,glob O} /\ fors_fields ht{1} tree{1} /\
    0 <= target{1} < 2^32 ==> ={res,glob O}].
proof.
  proc; call (caller_fors_tree O); wp.
  inline PreparationView(O).fors; wp.
  call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
  auto => /> &m hh0 hh ht0 ht hi0 hi.
  have hf : fors_fields ht{m} tree{m} by rewrite /fors_fields; smt().
  have hindex : 0 <= target{m} < 2^32 by smt().
  exact (tree_fors_private_query _ _ _ hf hindex).
qed.

lemma caller_keygen_root (O <: PrefixOracle) :
  equiv [RawKeygen(PreparationView(O)).root ~ CommonInputMerkle(O).root :
    ={seed,layer,tree,glob O} /\ tree_fields layer{1} tree{1} ==> ={res,glob O}].
proof.
  proc; while (={seed,layer,tree,kp,stack,glob O} /\
    tree_fields layer{1} tree{1} /\ 0 <= kp{1} <= 512 /\
    increasing_stack (map snd stack{1}) /\ stack_mass (map snd stack{1}) = kp{1}).
  + wp; while (={seed,layer,tree,kp,current,height,stack,glob O} /\
      tree_fields layer{1} tree{1} /\ 0 <= kp{1} < 512 /\
      active_stack (map snd stack{1}) height{1} /\
      stack_mass (map snd stack{1}) + 2^height{1} = kp{1}+1).
    - wp; call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
      auto => /> &m hl0 hl ht0 ht hj0 hj hhgt hs hall hm hn.
      have ha : active_stack (map snd stack{m}) (head ([],0) stack{m}).`2
        by rewrite /active_stack; smt().
      have hb := tree_stack_bounds stack{m} (head ([],0) stack{m}).`2 kp{m} _ ha hm; first smt().
      have hf : tree_fields layer{m} tree{m} by rewrite /tree_fields; smt().
      have hk : 0 <= 2 < 2^32 by rewrite caller_u32_size.
      have hz : 0 <= 0 < 2^32 by rewrite caller_u32_size.
      have hc : 0 <= (head ([],0) stack{m}).`2+1 < 2^32 by move: hb; rewrite caller_u32_size; smt().
      have hp : 0 <= kp{m} %/ (2^((head ([],0) stack{m}).`2+1)) < 2^32 by smt().
      have pop := projected_carry_pop stack{m} [] (head ([],0) stack{m}).`2 ha hn _; first by trivial.
      have hq := tree_pair_query seed{m} layer{m} tree{m} 2 0 ((head ([],0) stack{m}).`2+1)
        (kp{m} %/ (2^((head ([],0) stack{m}).`2+1))) (head ([],0) stack{m}).`1 current{m} hf hk hz hc hp.
      move: pop => [hnext hmass].
      have hmass' : stack_mass (map snd (behead stack{m})) +
        2^((head ([],0) stack{m}).`2+1) = kp{m}+1 by smt().
      have hnext0 : 0 <= (head ([],0) stack{m}).`2+1 by smt().
      have hnextinc : increasing_stack (map snd (behead stack{m}))
        by move: hnext; rewrite /active_stack; smt().
      have hnextall : all ((<=) ((head ([],0) stack{m}).`2+1)) (map snd (behead stack{m}))
        by move: hnext; rewrite /active_stack; smt().
      rewrite hq; by auto.
    wp; call (caller_keygen_leaf O).
    auto => /> &m hl0 hl ht0 ht hj0 hj hs hlt.
    have hi : stack_mass (map snd stack{m}) < 2^32 by rewrite caller_u32_size; smt().
    split; first by move=> _; exact hi.
    move=> _ _ _ _ _ _; split; first by rewrite expr0; smt(increasing_nonnegative).
    move=> h st hn1 hn2 h0 hinc hall hm.
    have ha : active_stack (map snd st) h by rewrite /active_stack; smt().
    have hp := projected_carry_push st [] [] h ha _; first smt().
    move: hp; rewrite /=; smt().
  by auto.
qed.

lemma caller_merkle_build (O <: PrefixOracle) :
  equiv [RawMerkle(PreparationView(O)).build ~ CommonInputMerkle(O).build :
    ={seed,layer,tree,target,glob O} /\ tree_fields layer{1} tree{1} ==> ={res,glob O}].
proof.
  proc; while (={seed,layer,tree,target,kp,stack,keep,kept,glob O} /\
    tree_fields layer{1} tree{1} /\ 0 <= kp{1} <= 512 /\
    increasing_stack (map snd stack{1}) /\ stack_mass (map snd stack{1}) = kp{1}).
  + wp; while (={seed,layer,tree,target,kp,current,height,stack,keep,kept,glob O} /\
      tree_fields layer{1} tree{1} /\ 0 <= kp{1} < 512 /\
      active_stack (map snd stack{1}) height{1} /\
      stack_mass (map snd stack{1}) + 2^height{1} = kp{1}+1).
    - wp; call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
      auto => /> &m hl0 hl ht0 ht hj0 hj hhgt hs hall hm hn.
      have ha : active_stack (map snd stack{m}) (head ([],0) stack{m}).`2
        by rewrite /active_stack; smt().
      have hb := tree_stack_bounds stack{m} (head ([],0) stack{m}).`2 kp{m} _ ha hm; first smt().
      have hf : tree_fields layer{m} tree{m} by rewrite /tree_fields; smt().
      have hk : 0 <= 2 < 2^32 by rewrite caller_u32_size.
      have hz : 0 <= 0 < 2^32 by rewrite caller_u32_size.
      have hc : 0 <= (head ([],0) stack{m}).`2+1 < 2^32 by move: hb; rewrite caller_u32_size; smt().
      have hp : 0 <= kp{m} %/ (2^((head ([],0) stack{m}).`2+1)) < 2^32 by smt().
      have pop := projected_carry_pop stack{m} [] (head ([],0) stack{m}).`2 ha hn _; first by trivial.
      have hq := tree_pair_query seed{m} layer{m} tree{m} 2 0 ((head ([],0) stack{m}).`2+1)
        (kp{m} %/ (2^((head ([],0) stack{m}).`2+1))) (head ([],0) stack{m}).`1 current{m} hf hk hz hc hp.
      move: pop => [hnext hmass].
      have hmass' : stack_mass (map snd (behead stack{m})) +
        2^((head ([],0) stack{m}).`2+1) = kp{m}+1 by smt().
      have hnext0 : 0 <= (head ([],0) stack{m}).`2+1 by smt().
      have hnextinc : increasing_stack (map snd (behead stack{m}))
        by move: hnext; rewrite /active_stack; smt().
      have hnextall : all ((<=) ((head ([],0) stack{m}).`2+1)) (map snd (behead stack{m}))
        by move: hnext; rewrite /active_stack; smt().
      rewrite hq; by auto.
    wp; call (caller_keygen_leaf O).
    auto => /> &m hl0 hl ht0 ht hj0 hj hs hlt.
    have hi : stack_mass (map snd stack{m}) < 2^32 by rewrite caller_u32_size; smt().
    split; first by move=> _; exact hi.
    move=> _ _ _ _ _ _; split; first by rewrite expr0; smt(increasing_nonnegative).
    move=> h st hn1 hn2 h0 hinc hall hm.
    have ha : active_stack (map snd st) h by rewrite /active_stack; smt().
    have hp := projected_carry_push st [] [] h ha _; first smt().
    move: hp; rewrite /=; smt().
  by auto.
qed.
