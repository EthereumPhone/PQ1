(* Preserve authentication-path construction while abstracting trusted WOTS chain values. *)
require import AllCore List IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors RawMerkle.
require import ChainValueView ChainKeygenView.
module ChainMerkle (O : ChainOracle) = {
  proc build(seed : raw_input, layer tree target : int) : raw_input list * raw_input = {
    var kp, current, height, stack, left, parent, d, keep, kept, target_h, sibling_h, pair_start, left_idx, right_idx;
    kp <- 0; stack <- []; keep <- nseq 9 (nseq 16 0); kept <- nseq 9 false;
    while (kp < 512) {
      current <@ ChainKeygen(O).leaf(seed,layer,tree,kp);
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
  proc recover = RawMerkle(PreparationView(ChainPrefix(O))).recover
}.
lemma chain_merkle_build_projection (O <: PrefixOracle) :
  equiv [RawMerkle(PreparationView(O)).build ~ ChainMerkle(ConcreteChain(O)).build :
    ={arg,glob O} ==> ={res,glob O}].
proof.
  proc; wp; while (={seed,layer,tree,target,kp,stack,keep,kept,glob O}).
  + wp; while (={seed,layer,tree,target,kp,current,height,stack,keep,kept,glob O}); first by sim.
    wp; call (chain_keygen_leaf_projection O); auto.
  auto.
qed.
lemma chain_merkle_recover_projection (O <: PrefixOracle) :
  equiv [RawMerkle(PreparationView(O)).recover ~ ChainMerkle(ConcreteChain(O)).recover :
    ={arg,glob O} ==> ={res,glob O}].
proof. by sim. qed.
lemma chain_merkle_build_lossless (O <: ChainOracle) :
  islossless O.hash => islossless O.value => islossless ChainMerkle(O).build.
proof.
  move=> hh hv; proc; while true (512-kp).
  + move=> z; wp; while true (size stack).
    - move=> z'; wp; call hh; auto; smt(size_behead size_ge0 size_eq0).
    wp; call (chain_keygen_leaf_lossless O hh hv); auto; smt(size_ge0).
  auto; smt().
qed.
