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
    d <@ O.hash(th_preimage seed (address_words 0 ht 3 tree 0 0 (target %% 2048)) (pad_node secret));
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
        parent <- kp %/ (2^(height+1));
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







