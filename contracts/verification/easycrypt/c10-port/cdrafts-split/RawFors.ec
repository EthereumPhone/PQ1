(* Manual transcription of FORS Treehash, authentication-path extraction and
   reconstruction. All secret derivations and public hashes use one interface.
   No extraction or correctness correspondence is asserted by this file. *)
require import AllCore List Distr IntDiv.
require import C10RawOracle C10RawGrind C10Counter.
require import PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen.

op fors_tail ht tree leaf = be 4 ht ++ be 4 tree ++ be 4 leaf.
op sibling_index x = if x %% 2 = 0 then x+1 else x-1.

module RawFors (O : PreparationOracle) = {
  proc tree(seed : raw_input, ht tree target : int) : raw_input * raw_input list = {
    var j, current, height, stack, sibling, parent, d, auth, target_h, sibidx, left_start, right_start;
    j <- 0; stack <- []; auth <- nseq 11 (nseq 16 0);
    while (j < 2048) {
      d <@ O.fors(fors_tail ht tree j);
      current <- node d;
      d <@ O.hash(seed ++ address 0 ht 3 tree 0 0 j ++ pad current);
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
        d <@ O.hash(seed ++ address 0 ht 3 tree 0 (height+1) parent ++ pad sibling ++ pad current);
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
    d <@ O.fors(fors_tail ht tree target); secret <- node d;
    result <@ tree(seed,ht,tree,target);
    return (secret,result.`2);
  }
  proc recover(seed : raw_input, ht tree target : int, secret : raw_input, auth : raw_input list) : raw_input = {
    var d, current, h, idx, sibling, parent, left, right;
    d <@ O.hash(seed ++ address 0 ht 3 tree 0 0 target ++ pad secret);
    current <- node d; h <- 0; idx <- target;
    while (h < 11) {
      sibling <- nth (nseq 16 0) auth h; parent <- idx %/ 2;
      left <- if idx %% 2 = 0 then current else sibling;
      right <- if idx %% 2 = 0 then sibling else current;
      d <@ O.hash(seed ++ address 0 ht 3 tree 0 (h+1) parent ++ pad left ++ pad right);
      current <- node d; idx <- parent; h <- h+1;
    }
    return current;
  }
}.

lemma fors_tree_lossless (O <: PreparationOracle) :
  islossless O.hash => islossless O.fors => islossless RawFors(O).tree.
proof.
  move=> hh hf; proc; while true (2048-j).
  + move=> z; wp; while true (size stack).
    - move=> z'; wp; call hh; auto; smt(size_behead size_ge0 size_eq0).
    wp; call hh; wp; call hf; auto; smt(size_ge0).
  auto; smt().
qed.

lemma fors_recover_lossless (O <: PreparationOracle) :
  islossless O.hash => islossless RawFors(O).recover.
proof.
  move=> hh; proc; while true (11-h).
  + move=> z; wp; call hh; auto; smt().
  wp; call hh; auto; smt().
qed.
