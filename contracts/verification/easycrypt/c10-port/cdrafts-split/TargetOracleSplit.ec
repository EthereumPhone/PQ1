(* One selected private input, with all other private values memoized.
   The target is public configuration; its sampled digest is private state. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawFors ForsPrivateLeaves ForsLeafView.
require import LeafCommitmentHybrid LeafOpeningBound.

module type TargetOracle = {
  proc hash(x : raw_input) : digest
  proc derive(tail : raw_input) : digest
  proc leaf(seed : raw_input, ht tree index : int) : raw_input
  proc secret(ht tree index : int) : raw_input
}.
module type TargetContext (O : TargetOracle) = {
  proc run() : raw_input list { O.hash, O.derive, O.leaf, O.secret }
}.
module TargetConfig = { var input : raw_input }.
module OtherPrivate = {
  var history : (raw_input,digest) fmap
  proc derive(tail : raw_input) : digest = {
    var y;
    if (tail \notin history) { y <$ full_digest; history.[tail] <- y; }
    return oget history.[tail];
  }
}.
module RealTargetPrivate = { var value : digest }.
module RealTargetOracle = {
  var revealed : bool
  proc hash(x : raw_input) : digest = { var y; y <@ Shared.hash(x); return y; }
  proc derive(tail : raw_input) : digest = {
    var y;
    if (tail=TargetConfig.input) { revealed <- true; y <- RealTargetPrivate.value; }
    else { y <@ OtherPrivate.derive(tail); }
    return y;
  }
  proc leaf(seed : raw_input, ht tree index : int) : raw_input = {
    var tail, sd, d;
    tail <- fors_private_key ht tree index;
    if (tail=TargetConfig.input) { sd <- RealTargetPrivate.value; }
    else { sd <@ OtherPrivate.derive(tail); }
    d <@ Shared.hash(seed ++ address 0 ht 3 tree 0 0 index ++ pad (node sd));
    return node d;
  }
  proc secret(ht tree index : int) : raw_input = {
    var sd; sd <@ derive(fors_private_key ht tree index); return node sd;
  }
}.
module TargetKernelAdapter (O : LeafOpeningOracle) = {
  proc hash = O.hash
  proc derive(tail : raw_input) : digest = {
    var y, ignored;
    if (tail=TargetConfig.input) { ignored <@ O.reveal(); y <- nseq 256 false; }
    else { y <@ OtherPrivate.derive(tail); }
    return y;
  }
  proc leaf(seed : raw_input, ht tree index : int) : raw_input = {
    var tail, sd, d;
    tail <- fors_private_key ht tree index;
    if (tail=TargetConfig.input) {
      d <@ O.derive(seed ++ address 0 ht 3 tree 0 0 index);
    } else {
      sd <@ OtherPrivate.derive(tail);
      d <@ O.hash(seed ++ address 0 ht 3 tree 0 0 index ++ pad (node sd));
    }
    return node d;
  }
  proc secret(ht tree index : int) : raw_input = {
    var result, sd;
    if (fors_private_key ht tree index=TargetConfig.input) { result <@ O.reveal(); }
    else { sd <@ OtherPrivate.derive(fors_private_key ht tree index); result <- node sd; }
    return result;
  }
}.
lemma other_private_lossless : islossless OtherPrivate.derive.
proof. proc; if; auto; smt(full_digest_ll). qed.
lemma real_target_hash_lossless : islossless RealTargetOracle.hash.
proof. proc; call hash_ll; auto. qed.
lemma real_target_derive_lossless : islossless RealTargetOracle.derive.
proof. proc; if; auto; call other_private_lossless; auto. qed.
lemma real_target_leaf_lossless : islossless RealTargetOracle.leaf.
proof. proc; call hash_ll; sp 1; if; auto; call other_private_lossless; auto. qed.
lemma real_target_secret_lossless : islossless RealTargetOracle.secret.
proof. proc; call real_target_derive_lossless; auto. qed.

lemma target_oracle_opening_coupling
  (A <: TargetContext {-TargetConfig,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,
    -Shared,-LeafCommitmentReal,-RealLeafOpening}) :
  (forall (O <: TargetOracle {-A}), islossless O.hash => islossless O.derive =>
    islossless O.leaf => islossless O.secret => islossless A(O).run) =>
  equiv [A(RealTargetOracle).run ~ A(TargetKernelAdapter(RealLeafOpening)).run :
    ={glob A,glob Shared,glob OtherPrivate,glob TargetConfig} /\
    node RealTargetPrivate.value{1}=LeafCommitmentReal.key{2} /\
    !RealTargetOracle.revealed{1} /\ !RealLeafOpening.revealed{2} ==>
    if RealLeafOpening.revealed{2} then RealTargetOracle.revealed{1}
    else ={res,glob A,glob Shared,glob OtherPrivate,glob TargetConfig} /\
      node RealTargetPrivate.value{1}=LeafCommitmentReal.key{2} /\ !RealTargetOracle.revealed{1}].
proof.
  move=> hll.
  proc (RealLeafOpening.revealed)
    (={glob Shared,glob OtherPrivate,glob TargetConfig} /\
      node RealTargetPrivate.value{1}=LeafCommitmentReal.key{2} /\ !RealTargetOracle.revealed{1})
    RealTargetOracle.revealed{1}.
  + smt().
  + smt().
  + exact hll.
  + proc; call (_ : ={glob Shared}); first by sim.
    auto; smt().
  + move=> &2 _; proc; call hash_ll; auto.
  + move=> &1; proc; call hash_ll; auto.
  + proc; if.
    - auto; smt().
    - inline RealLeafOpening.reveal; auto.
    wp; call (_ : ={glob OtherPrivate}); first by sim.
    auto; smt().
  + move=> &2 _; proc; if; auto; call other_private_lossless; auto.
  + move=> &1; proc; if.
    - inline RealLeafOpening.reveal; auto.
    wp; call other_private_lossless; auto.
  + proc; sp 1 1; if{1}.
    - rcondt{2} 1; first by auto.
      inline LeafCommitmentReal.derive; wp; call (_ : ={glob Shared}); first by sim.
      auto; smt().
    rcondf{2} 1; first by auto.
    inline LeafCommitmentReal.hash; wp; call (_ : ={glob Shared}); first by sim.
    wp; call (_ : ={glob OtherPrivate}); first by sim.
    auto; smt().
  + move=> &2 _; proc; call hash_ll; sp 1; if; auto; call other_private_lossless; auto.
  + move=> &1; proc; sp 1; if; wp.
    - call leaf_commitment_real_derive_ll; auto.
    call (_ : true ==> true); first by proc; call hash_ll; auto.
    call other_private_lossless; auto.
  + proc; inline RealTargetOracle.derive; sp 1 0; if.
    - auto; smt().
    - inline RealLeafOpening.reveal; auto.
    wp; call (_ : ={glob OtherPrivate}); first by sim.
    auto; smt().
  + move=> &2 _; proc; inline RealTargetOracle.derive; sp 1; if; auto; call other_private_lossless; auto.
  + move=> &1; proc; if.
    - inline RealLeafOpening.reveal; auto.
    wp; call other_private_lossless; auto.
qed.
