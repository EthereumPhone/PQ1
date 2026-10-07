(* Opening may occur adaptively, but success requires that it never occurred.
   Redaction is an exact event equivalence, not an assumption of independence. *)
require import AllCore List Distr StdOrder.
require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid RawKeygen.
require import LeafCommitmentHybrid LeafCommitmentBound.
import RealOrder.

module type LeafOpeningOracle = {
  proc hash(x : raw_input) : digest
  proc derive(prefix : raw_input) : digest
  proc reveal() : raw_input
}.
module type LeafOpeningContext (O : LeafOpeningOracle) = {
  proc run() : raw_input list { O.hash, O.derive, O.reveal }
}.
module RealLeafOpening = {
  var revealed : bool
  proc hash = LeafCommitmentReal.hash
  proc derive = LeafCommitmentReal.derive
  proc reveal() : raw_input = {
    revealed <- true;
    return LeafCommitmentReal.key;
  }
}.
module RedactedLeafState = { var revealed : bool }.
module RedactedLeafOpening (O : PrefixOracle) = {
  proc hash = O.hash
  proc derive = O.derive
  proc reveal() : raw_input = {
    RedactedLeafState.revealed <- true;
    return nseq 16 0;
  }
}.
module RedactedLeafContext (A : LeafOpeningContext) (O : PrefixOracle) = {
  proc run() : raw_input list = {
    var outputs;
    RedactedLeafState.revealed <- false;
    outputs <@ A(RedactedLeafOpening(O)).run();
    if (RedactedLeafState.revealed) { outputs <- []; }
    return outputs;
  }
}.
module RealUnopenedLeafGuess (A : LeafOpeningContext) = {
  proc run() : bool = {
    var key, outputs;
    key <$ full_digest; LeafCommitmentReal.key <- node key;
    RealLeafOpening.revealed <- false;
    Shared.init(); outputs <@ A(RealLeafOpening).run();
    return !RealLeafOpening.revealed /\ mem outputs (node key);
  }
}.
lemma redact_leaf_opening_context
  (A <: LeafOpeningContext {-LeafCommitmentReal,-Shared,-RealLeafOpening,-RedactedLeafState}) :
  (forall (O <: LeafOpeningOracle {-A}), islossless O.hash => islossless O.derive =>
    islossless O.reveal => islossless A(O).run) =>
  equiv [A(RealLeafOpening).run ~ A(RedactedLeafOpening(LeafCommitmentReal)).run :
    ={glob A,glob Shared,LeafCommitmentReal.key} /\
    !RealLeafOpening.revealed{1} /\ !RedactedLeafState.revealed{2} ==>
    if RedactedLeafState.revealed{2} then RealLeafOpening.revealed{1}
    else ={res,glob A,glob Shared,LeafCommitmentReal.key} /\ !RealLeafOpening.revealed{1}].
proof.
  move=> hll.
  proc (RedactedLeafState.revealed)
    (={glob Shared,LeafCommitmentReal.key} /\ !RealLeafOpening.revealed{1})
    RealLeafOpening.revealed{1}.
  + smt().
  + smt().
  + exact hll.
  + proc; call (_ : ={glob Shared}); first by sim.
    auto; smt().
  + move=> &2 _; proc; call hash_ll; auto.
  + move=> &1; proc; call hash_ll; auto.
  + proc; call (_ : ={glob Shared}); first by sim.
    auto; smt().
  + move=> &2 _; proc; call hash_ll; auto.
  + move=> &1; proc; call hash_ll; auto.
  + proc; auto.
  + move=> &2 _; proc; auto.
  + move=> &1; proc; auto.
qed.
lemma redact_unopened_leaf_game
  (A <: LeafOpeningContext {-LeafCommitmentReal,-Shared,-RealLeafOpening,-RedactedLeafState}) :
  (forall (O <: LeafOpeningOracle {-A}), islossless O.hash => islossless O.derive =>
    islossless O.reveal => islossless A(O).run) =>
  equiv [RealUnopenedLeafGuess(A).run ~ RealLeafGuess(RedactedLeafContext(A)).run :
    ={glob A} ==> ={res}].
proof.
  move=> hll; proc; inline RedactedLeafContext(A,LeafCommitmentReal).run.
  wp; call (redact_leaf_opening_context A hll); inline Shared.init; auto; smt().
qed.
lemma redacted_leaf_context_lossless
  (A <: LeafOpeningContext {-RedactedLeafState}) (O <: PrefixOracle {-A,-RedactedLeafState}) :
  (forall (V <: LeafOpeningOracle {-A}), islossless V.hash => islossless V.derive =>
    islossless V.reveal => islossless A(V).run) =>
  islossless O.hash => islossless O.derive => islossless RedactedLeafContext(A,O).run.
proof.
  move=> ha hh hd; proc; wp.
  call (ha (RedactedLeafOpening(O)) hh hd _); first by proc; auto.
  auto.
qed.
lemma redacted_leaf_context_budget
  (A <: LeafOpeningContext {-Independent,-RedactedLeafState}) q n :
  0<=n =>
  hoare [A(RedactedLeafOpening(Independent)).run :
    Independent.queries=[] /\ !RedactedLeafState.revealed ==>
    size Independent.queries<=q /\ size res<=n] =>
  hoare [RedactedLeafContext(A,Independent).run : Independent.queries=[] ==>
    size Independent.queries<=q /\ size res<=n].
proof. move=> hn hb; proc; wp; call hb; auto; smt(). qed.
lemma adaptive_unopened_leaf_guess_bound
  (A <: LeafOpeningContext {-LeafCommitmentReal,-LeafCommitmentHybrid,-Shared,-Independent,
    -RealLeafOpening,-RedactedLeafState}) q n &m :
  (forall (O <: LeafOpeningOracle {-A}), islossless O.hash => islossless O.derive =>
    islossless O.reveal => islossless A(O).run) =>
  0<=q => 0<=n =>
  hoare [A(RedactedLeafOpening(Independent)).run :
    Independent.queries=[] /\ !RedactedLeafState.revealed ==>
    size Independent.queries<=q /\ size res<=n] =>
  Pr[RealUnopenedLeafGuess(A).run() @ &m : res] <= (q+n)%r*(1%r/2%r)^128.
proof.
  move=> hll hq hn hb.
  have he : Pr[RealUnopenedLeafGuess(A).run() @ &m : res] =
    Pr[RealLeafGuess(RedactedLeafContext(A)).run() @ &m : res]
    by byequiv (redact_unopened_leaf_game A hll) => //.
  rewrite he; apply (adaptive_hidden_leaf_guess_bound (RedactedLeafContext(A)) q n &m) => //.
  + move=> O hh hd; apply (redacted_leaf_context_lossless A O hll hh hd).
  exact (redacted_leaf_context_budget A q n hn hb).
qed.
