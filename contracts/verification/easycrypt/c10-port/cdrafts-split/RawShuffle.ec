(* Software shuffle hashes are part of the same raw SHA oracle budget. *)
require import AllCore List Distr IntDiv.
require import C10RawOracle C10Bytes PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen.
require import PhysicalKeygenCost RoleGrindCost.

op shuffle_tag = [115;112;104;105;110;99;115;45;99;49;48;45;115;104;117;102;102;108;101;45;118;49].
op fisher_tag = [115;112;104;105;110;99;115;45;99;49;48;45;102;105;115;104;101;114;45;121;97;116;101;115;45;118;49].

module RawShuffle (O : PreparationOracle) = {
  proc derive(seed label : raw_input) : raw_input = {
    var d, result;
    result <- nseq 32 0;
    if (seed <> nseq 32 0) {
      d <@ O.hash(shuffle_tag ++ seed ++ label);
      result <- bits_to_bytes d;
    }
    return result;
  }
  proc permutation(seed : raw_input, n : int) : int list = {
    var order, stream, blk, d, i, pos, lo, hi, j, tmp;
    order <- range 0 n;
    if (seed <> nseq 32 0 /\ 1 < n) {
      blk <- 0; stream <- [];
      while (blk < 4) {
        d <@ O.hash(fisher_tag ++ seed ++ be 4 blk);
        stream <- stream ++ bits_to_bytes d; blk <- blk+1;
      }
      pos <- 0; i <- n-1;
      while (1 <= i) {
        lo <- nth 0 stream pos; hi <- nth 0 stream (pos+1); pos <- pos+2;
        j <- ((hi*256+lo)*(i+1)) %/ 65536;
        tmp <- nth 0 order i;
        order <- put order i (nth 0 order j);
        order <- put order j tmp; i <- i-1;
      }
    }
    return order;
  }
}.

lemma shuffle_derive_physical_cost c :
  hoare[RawShuffle(PreparationView(Physical)).derive : Shared.calls = c ==>
    c <= Shared.calls <= c+1].
proof. proc; sp 1; if.
  + wp; call (physical_hash_count c); auto; smt().
  auto; smt(). qed.
lemma shuffle_derive_public_cost q :
  hoare[RawShuffle(PreparationView(Independent)).derive : size Independent.queries = q ==>
    q <= size Independent.queries <= q+1].
proof. proc; sp 1; if.
  + wp; call (independent_hash_count q); auto; smt().
  auto; smt(). qed.
lemma shuffle_permutation_physical_cost c :
  hoare[RawShuffle(PreparationView(Physical)).permutation : Shared.calls = c ==>
    c <= Shared.calls <= c+4].
proof.
  proc; sp 1; if; last by auto; smt().
  while (Shared.calls = c+4); first by auto.
  wp; while (0 <= blk <= 4 /\ Shared.calls = c+blk).
  + exists* blk; elim* => b; wp; call (physical_hash_count (c+b)); auto; smt().
  auto; smt().
qed.
lemma shuffle_permutation_public_cost q :
  hoare[RawShuffle(PreparationView(Independent)).permutation : size Independent.queries = q ==>
    q <= size Independent.queries <= q+4].
proof.
  proc; sp 1; if; last by auto; smt().
  while (size Independent.queries = q+4); first by auto.
  wp; while (0 <= blk <= 4 /\ size Independent.queries = q+blk).
  + exists* blk; elim* => b; wp; call (independent_hash_count (q+b)); auto; smt().
  auto; smt().
qed.
lemma shuffle_derive_lossless (O <: PreparationOracle) :
  islossless O.hash => islossless RawShuffle(O).derive.
proof. move=> hh; proc; sp 1; if; auto; wp; call hh; auto. qed.
lemma shuffle_permutation_lossless (O <: PreparationOracle) :
  islossless O.hash => islossless RawShuffle(O).permutation.
proof.
  move=> hh; proc; sp 1; if; auto.
  while true (i); first by move=> z; auto; smt().
  wp; while true (4-blk).
  + move=> z; wp; call hh; auto; smt().
  auto; smt().
qed.
