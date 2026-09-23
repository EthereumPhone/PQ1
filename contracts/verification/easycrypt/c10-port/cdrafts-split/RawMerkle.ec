(* Manual list-stack transcription of build_subtree_with_auth and verify_auth_path. *)
require import AllCore List Distr IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawKeygenCost RawFors.

module RawMerkle (O : PreparationOracle) = {
  proc build(seed : raw_input, layer tree target : int) : raw_input list * raw_input = {
    var kp, current, height, stack, left, parent, d, keep, kept, target_h, sibling_h, pair_start, left_idx, right_idx;
    kp <- 0; stack <- []; keep <- nseq 9 (nseq 16 0); kept <- nseq 9 false;
    while (kp < 512) {
      current <@ RawKeygen(O).leaf(seed,layer,tree,kp);
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
        d <@ O.hash(seed ++ address layer tree 2 0 0 (height+1) parent ++ pad left ++ pad current);
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
      d <@ O.hash(seed ++ address layer tree 2 0 0 (h+1) parent ++ pad left ++ pad right);
      current <- node d; idx <- parent; h <- h+1;
    }
    return current;
  }
}.

lemma merkle_build_lossless (O <: PreparationOracle) :
  islossless O.hash => islossless O.wots => islossless RawMerkle(O).build.
proof.
  move=> hh hw; proc; while true (512-kp).
  + move=> z; wp; while true (size stack).
    - move=> z'; wp; call hh; auto; smt(size_behead size_ge0 size_eq0).
    wp; call (leaf_lossless O hh hw); auto; smt(size_ge0).
  auto; smt().
qed.
lemma merkle_recover_lossless (O <: PreparationOracle) :
  islossless O.hash => islossless RawMerkle(O).recover.
proof.
  move=> hh; proc; while true (9-h).
  + move=> z; wp; call hh; auto; smt().
  auto; smt().
qed.
