(* Selective private-table guess bound. The selected input is fixed before
   initialization; opening that input disqualifies this experiment's success. *)
require import AllCore List Distr FMap StdOrder.
require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid RawKeygen.
require import LeafCommitmentHybrid LeafOpeningBound TargetOracleSplit.
import RealOrder.

module TargetKernelContext (A : TargetContext) (O : LeafOpeningOracle) = {
  proc run() : raw_input list = {
    var outputs;
    OtherPrivate.history <- empty;
    outputs <@ A(TargetKernelAdapter(O)).run();
    return outputs;
  }
}.
module SelectivePrivateGuess (A : TargetContext) = {
  proc run() : bool = {
    var key, outputs;
    key <$ full_digest; RealTargetPrivate.value <- key;
    RealTargetOracle.revealed <- false;
    Shared.init(); OtherPrivate.history <- empty;
    outputs <@ A(RealTargetOracle).run();
    return !RealTargetOracle.revealed /\ mem outputs (node key);
  }
}.
lemma selective_private_guess_projection
  (A <: TargetContext {-TargetConfig,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,
    -Shared,-LeafCommitmentReal,-RealLeafOpening}) :
  (forall (O <: TargetOracle {-A}), islossless O.hash => islossless O.derive =>
    islossless O.leaf => islossless O.secret => islossless A(O).run) =>
  equiv [SelectivePrivateGuess(A).run ~ RealUnopenedLeafGuess(TargetKernelContext(A)).run :
    ={glob A,glob TargetConfig} ==> ={res}].
proof.
  move=> hll; proc; inline TargetKernelContext(A,RealLeafOpening).run.
  wp; call (target_oracle_opening_coupling A hll); inline Shared.init; auto; smt().
qed.
lemma target_kernel_derive_lossless (O <: LeafOpeningOracle) :
  islossless O.reveal => islossless TargetKernelAdapter(O).derive.
proof. move=> hr; proc; if; wp; [call hr | call other_private_lossless]; auto. qed.
lemma target_kernel_leaf_lossless (O <: LeafOpeningOracle) :
  islossless O.hash => islossless O.derive => islossless TargetKernelAdapter(O).leaf.
proof.
  move=> hh hd; proc; sp 1; if; wp.
  + call hd; auto.
  call hh; call other_private_lossless; auto.
qed.
lemma target_kernel_secret_lossless (O <: LeafOpeningOracle) :
  islossless O.reveal => islossless TargetKernelAdapter(O).secret.
proof. move=> hr; proc; if; wp; [call hr | call other_private_lossless]; auto. qed.
lemma target_kernel_context_lossless
  (A <: TargetContext {-TargetConfig,-OtherPrivate}) (O <: LeafOpeningOracle {-A}) :
  (forall (V <: TargetOracle {-A}), islossless V.hash => islossless V.derive =>
    islossless V.leaf => islossless V.secret => islossless A(V).run) =>
  islossless O.hash => islossless O.derive => islossless O.reveal =>
  islossless TargetKernelContext(A,O).run.
proof.
  move=> ha hh hd hr; proc;
    call (ha (TargetKernelAdapter(O)) hh (target_kernel_derive_lossless O hr)
      (target_kernel_leaf_lossless O hh hd) (target_kernel_secret_lossless O hr)); auto.
qed.
lemma adaptive_selective_private_guess_bound
  (A <: TargetContext {-TargetConfig,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,
    -Shared,-Independent,-LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState}) q n &m :
  (forall (O <: TargetOracle {-A}), islossless O.hash => islossless O.derive =>
    islossless O.leaf => islossless O.secret => islossless A(O).run) =>
  0<=q => 0<=n =>
  hoare [A(TargetKernelAdapter(RedactedLeafOpening(Independent))).run :
    Independent.queries=[] /\ OtherPrivate.history=empty /\ !RedactedLeafState.revealed ==>
    size Independent.queries<=q /\ size res<=n] =>
  Pr[SelectivePrivateGuess(A).run() @ &m : res] <= (q+n)%r*(1%r/2%r)^128.
proof.
  move=> hll hq hn hb.
  have he : Pr[SelectivePrivateGuess(A).run() @ &m : res] =
    Pr[RealUnopenedLeafGuess(TargetKernelContext(A)).run() @ &m : res]
    by byequiv (selective_private_guess_projection A hll) => //.
  rewrite he; apply (adaptive_unopened_leaf_guess_bound (TargetKernelContext(A)) q n &m) => //.
  + move=> O hh hd hr; exact (target_kernel_context_lossless A O hll hh hd hr).
  proc; call hb; auto.
qed.
