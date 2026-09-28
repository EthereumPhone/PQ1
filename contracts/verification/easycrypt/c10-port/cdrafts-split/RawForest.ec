(* FORS forest orchestration: twelve authenticated trees, the deployed special
   last-root-as-secret convention, and padded root compression. *)
require import AllCore List Distr IntDiv BitEncoding.
require import C10RawOracle C10Bytes PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors RawShuffle.
import BS2Int.

op forest_index d t = bs2int (take 11 (drop (11*t) d)).
op hypertree_index d = bs2int (take 18 (drop 143 d)).

module RawForest (O : PreparationOracle) = {
  proc one(seed : raw_input, ht tree leaf : int) : raw_input * raw_input list * raw_input = {
    var sig, root;
    sig <@ RawFors(O).sign(seed,ht,tree,leaf);
    root <@ RawFors(O).recover(seed,ht,tree,leaf,sig.`1,sig.`2);
    return (sig.`1,sig.`2,root);
  }
  proc sign(seed : raw_input, ht : int, digest : digest, shuffle : raw_input) : raw_input list * raw_input list list * raw_input = {
    var subseed, order, step, t, sig, last, d, secrets, auths, roots;
    secrets <- nseq 13 (nseq 16 0);
    auths <- nseq 12 (nseq 11 (nseq 16 0)); roots <- nseq 13 (nseq 16 0);
    subseed <@ RawShuffle(O).derive(shuffle,[102;111;114;115]);
    order <@ RawShuffle(O).permutation(subseed,12);
    step <- 0;
    while (step < 12) {
      t <- nth 0 order step;
      sig <@ one(seed,ht,t,forest_index digest t);
      secrets <- put secrets t sig.`1;
      auths <- put auths t sig.`2;
      roots <- put roots t sig.`3; step <- step+1;
    }
    last <@ RawFors(O).root(seed,ht,12);
    secrets <- put secrets 12 last;
    d <@ O.hash(seed ++ address 0 ht 3 12 0 0 0 ++ pad last);
    roots <- put roots 12 (node d);
    d <@ O.hash(seed ++ address 0 ht 4 0 0 0 0 ++ flatten (map pad roots));
    return (secrets,auths,node d);
  }
  proc recover(seed : raw_input, ht : int, digest : digest, secrets : raw_input list, auths : raw_input list list) : raw_input = {
    var t, current, roots, d;
    t <- 0; roots <- [];
    while (t < 12) {
      current <@ RawFors(O).recover(seed,ht,t,forest_index digest t,nth (nseq 16 0) secrets t,nth [] auths t);
      roots <- rcons roots current; t <- t+1;
    }
    d <@ O.hash(seed ++ address 0 ht 3 12 0 0 0 ++ pad (nth (nseq 16 0) secrets 12));
    roots <- rcons roots (node d);
    d <@ O.hash(seed ++ address 0 ht 4 0 0 0 0 ++ flatten (map pad roots));
    return node d;
  }
}.

lemma forest_one_lossless (O <: PreparationOracle) :
  islossless O.hash => islossless O.fors => islossless RawForest(O).one.
proof.
  move=> hh hf; proc; call (fors_recover_lossless O hh).
  inline RawFors(O).sign; wp; call (fors_tree_lossless O hh hf); wp; call hf; auto.
qed.
lemma forest_sign_lossless (O <: PreparationOracle) :
  islossless O.hash => islossless O.fors => islossless RawForest(O).sign.
proof.
  move=> hh hf; proc; call hh; wp; call hh; wp.
  inline RawFors(O).root; wp; call (fors_tree_lossless O hh hf); wp.
  while true (12-step).
  + move=> z; wp; call (forest_one_lossless O hh hf); auto; smt().
  wp; call (shuffle_permutation_lossless O hh); call (shuffle_derive_lossless O hh); auto; smt().
qed.
lemma forest_recover_lossless (O <: PreparationOracle) :
  islossless O.hash => islossless RawForest(O).recover.
proof.
  move=> hh; proc; call hh; wp; call hh.
  while true (12-t).
  + move=> z; wp; call (fors_recover_lossless O hh); auto; smt().
  auto; smt().
qed.
