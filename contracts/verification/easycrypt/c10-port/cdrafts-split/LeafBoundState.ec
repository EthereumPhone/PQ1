(* Initial-state versions: runtime budgets need only cover this game's state. *)
require import AllCore List Distr FMap StdOrder.
require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid RawKeygen.
require import LeafCommitmentHybrid LeafCommitmentBound LeafOpeningBound TargetOracleSplit TargetPrivateBound.
import RealOrder.

lemma independent_leaf_guess_at_state (A <: LeafCommitmentContext {-Independent}) q n &m :
  0<=q => 0<=n =>
  hoare [A(Independent).run : Independent.queries=[] /\ (glob A)=(glob A){m} ==>
    size Independent.queries<=q /\ size res<=n] =>
  Pr[IndependentLeafGuess(A).run() @ &m : res] <= (q+n)%r*(1%r/2%r)^128.
proof.
  move=> hq hn hb.
  have he : Pr[IndependentLeafGuess(A).run() @ &m : res]=Pr[LateLeafGuess(A).run() @ &m : res]
    by byequiv (leaf_guess_late A) => //.
  rewrite he; byphoare (_ : (glob A)=(glob A){m} ==> res) => //.
  proc; rnd; call hb; inline Independent.init; auto => /> outputs queries hqs hos.
  have hm := leaf_commitment_candidate_mass queries outputs.
  have hp : 0%r <= (1%r/2%r)^128 by apply expr_ge0; smt().
  smt(le_fromint).
qed.
lemma adaptive_hidden_leaf_guess_at_state
  (A <: LeafCommitmentContext {-LeafCommitmentReal,-LeafCommitmentHybrid,-Shared,-Independent}) q n &m :
  (forall (O <: PrefixOracle {-A}), islossless O.hash => islossless O.derive => islossless A(O).run) =>
  0<=q => 0<=n =>
  hoare [A(Independent).run : Independent.queries=[] /\ (glob A)=(glob A){m} ==>
    size Independent.queries<=q /\ size res<=n] =>
  Pr[RealLeafGuess(A).run() @ &m : res] <= (q+n)%r*(1%r/2%r)^128.
proof.
  move=> hll hq hn hb.
  have he : Pr[RealLeafGuess(A).run() @ &m : res] <=
    Pr[HybridLeafGuess(A).run() @ &m : res \/ LeafCommitmentHybrid.bad].
  + byequiv (_ : ={glob A} ==> res{1} => res{2} \/ LeafCommitmentHybrid.bad{2}) => //.
    conseq (leaf_guess_games_upto A hll); smt().
  rewrite (hybrid_leaf_guess_is_independent A &m) in he.
  have hbnd := independent_leaf_guess_at_state A q n &m hq hn hb.
  smt().
qed.
lemma adaptive_unopened_leaf_guess_at_state
  (A <: LeafOpeningContext {-LeafCommitmentReal,-LeafCommitmentHybrid,-Shared,-Independent,
    -RealLeafOpening,-RedactedLeafState}) q n &m :
  (forall (O <: LeafOpeningOracle {-A}), islossless O.hash => islossless O.derive =>
    islossless O.reveal => islossless A(O).run) =>
  0<=q => 0<=n =>
  hoare [A(RedactedLeafOpening(Independent)).run :
    Independent.queries=[] /\ !RedactedLeafState.revealed /\ (glob A)=(glob A){m} ==>
    size Independent.queries<=q /\ size res<=n] =>
  Pr[RealUnopenedLeafGuess(A).run() @ &m : res] <= (q+n)%r*(1%r/2%r)^128.
proof.
  move=> hll hq hn hb.
  have he : Pr[RealUnopenedLeafGuess(A).run() @ &m : res] =
    Pr[RealLeafGuess(RedactedLeafContext(A)).run() @ &m : res]
    by byequiv (redact_unopened_leaf_game A hll) => //.
  rewrite he; apply (adaptive_hidden_leaf_guess_at_state (RedactedLeafContext(A)) q n &m) => //.
  + move=> O hh hd; apply (redacted_leaf_context_lossless A O hll hh hd).
  proc; wp; call hb; auto; smt().
qed.
lemma adaptive_selective_private_guess_at_state
  (A <: TargetContext {-TargetConfig,-OtherPrivate,-RealTargetPrivate,-RealTargetOracle,
    -Shared,-Independent,-LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState}) q n &m :
  (forall (O <: TargetOracle {-A}), islossless O.hash => islossless O.derive =>
    islossless O.leaf => islossless O.secret => islossless A(O).run) =>
  0<=q => 0<=n =>
  hoare [A(TargetKernelAdapter(RedactedLeafOpening(Independent))).run :
    Independent.queries=[] /\ OtherPrivate.history=empty /\ !RedactedLeafState.revealed /\ (glob A)=(glob A){m} ==>
    size Independent.queries<=q /\ size res<=n] =>
  Pr[SelectivePrivateGuess(A).run() @ &m : res] <= (q+n)%r*(1%r/2%r)^128.
proof.
  move=> hll hq hn hb.
  have he : Pr[SelectivePrivateGuess(A).run() @ &m : res] =
    Pr[RealUnopenedLeafGuess(TargetKernelContext(A)).run() @ &m : res]
    by byequiv (selective_private_guess_projection A hll) => //.
  rewrite he; apply (adaptive_unopened_leaf_guess_at_state (TargetKernelContext(A)) q n &m) => //.
  + move=> O hh hd hr; exact (target_kernel_context_lossless A O hll hh hd hr).
  proc; call hb; auto.
qed.
