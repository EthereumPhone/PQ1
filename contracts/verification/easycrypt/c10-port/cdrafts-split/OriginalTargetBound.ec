(* Transfer the selected hiding bound back to the original private table.
   The event still requires no explicit opening and a transformed query budget. *)
require import AllCore List Distr FMap StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid RawKeygen.
require import LeafCommitmentHybrid LeafOpeningBound LeafBoundState PrivateTargetSampling.
require import TargetOracleSplit TargetPrivateBound TargetTableProjection TargetTableGames.
import RealOrder.

lemma original_observed_private_guess_bound
  (A <: TargetContext {-Independent,-Shared,-OtherPrivate,-RealTargetPrivate,
    -RealTargetOracle,-OriginalTargetState,-TargetConfig,-PrivateTargetSample,
    -LeafCommitmentReal,-LeafCommitmentHybrid,-RealLeafOpening,-RedactedLeafState}) q n &m :
  (forall (O <: TargetOracle {-A}), islossless O.hash => islossless O.derive =>
    islossless O.leaf => islossless O.secret => islossless A(O).run) =>
  0<=q => 0<=n =>
  hoare [A(TargetKernelAdapter(RedactedLeafOpening(Independent))).run :
    Independent.queries=[] /\ OtherPrivate.history=empty /\ !RedactedLeafState.revealed /\
    (glob A)=(glob A){m} ==>
    size Independent.queries<=q /\ size res<=n] =>
  Pr[OriginalObservedPrivateGuess(A).run() @ &m : res] <= (q+n)%r*(1%r/2%r)^128.
proof.
  move=> ha hq hn hb.
  have hl : Pr[OriginalObservedPrivateGuess(A).run() @ &m : res] <=
    Pr[LateObservedPrivateGuess(A).run() @ &m : res]
    by byequiv (original_private_guess_late A) => //.
  have he : Pr[EarlyObservedPrivateGuess(A).run() @ &m : res] =
    Pr[LateObservedPrivateGuess(A).run() @ &m : res]
    by byequiv (observed_private_guess_early_late A) => //.
  have hs : Pr[EarlyObservedPrivateGuess(A).run() @ &m : res] =
    Pr[SelectivePrivateGuess(A).run() @ &m : res]
    by byequiv (early_private_guess_projection A) => //.
  have h := adaptive_selective_private_guess_at_state A q n &m ha hq hn hb.
  smt().
qed.
