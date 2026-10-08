(* Initialized memo game and its sampler-only projection. *)
require import AllCore List Distr FMap StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal IndependentWidths.
require import AcceptedPrefixSampling HmsgMemoOracle HmsgPoolRecords PoolCoverageEvent PoolCoverageBound.
import RealOrder.

module HmsgGame (C : PrefixContext) = {
  proc run() : bool = {
    var result;
    AcceptedSamples.init(); HmsgMemo(AcceptedSamples).init();
    result <@ C(HmsgMemo(AcceptedSamples)).run();
    return result;
  }
}.
module PoolContext (C : PrefixContext) (S : AcceptedSampler) = {
  proc run() : unit = {
    var result;
    HmsgMemo(S).init(); result <@ C(HmsgMemo(S)).run();
  }
}.
lemma hmsg_game_projection (C <: PrefixContext {-Independent,-HmsgMemo,-AcceptedSamples}) :
  equiv[IndependentGame(C).run ~ HmsgGame(C).run : ={glob C} ==>
    ={res,glob C} /\ Independent.rawhistory{1}=HmsgMemo.rawhistory{2} /\
    Independent.secrethistory{1}=HmsgMemo.secrethistory{2} /\ Independent.queries{1}=HmsgMemo.queries{2}].
proof.
  proc; call (hmsg_memo_context_refinement C).
  inline Independent.init HmsgMemo(AcceptedSamples).init AcceptedSamples.init; auto.
qed.
lemma hmsg_game_records (C <: PrefixContext {-HmsgMemo,-AcceptedSamples}) :
  hoare[HmsgGame(C).run : true ==>
    accepted_records HmsgMemo.rawhistory HmsgMemo.accepted_keys AcceptedSamples.nodes /\
    size AcceptedSamples.nodes<=HmsgMemo.accepted_calls].
proof.
  proc; call (hmsg_context_records C).
  inline HmsgMemo(AcceptedSamples).init AcceptedSamples.init; auto; smt(accepted_records_empty).
qed.
lemma hmsg_game_pool_bound (C <: PrefixContext {-HmsgMemo,-AcceptedSamples}) n &m :
  0<=n => Pr[HmsgGame(C).run() @ &m : size AcceptedSamples.nodes<=n /\ pool_coverage AcceptedSamples.nodes]
    <=coverage_charge n.
proof.
  move=> hn.
  have he : Pr[HmsgGame(C).run() @ &m : size AcceptedSamples.nodes<=n /\ pool_coverage AcceptedSamples.nodes]=
    Pr[AcceptedGame(PoolContext(C)).run() @ &m : size AcceptedSamples.nodes<=n /\ pool_coverage AcceptedSamples.nodes].
  + byequiv (_ : ={glob C} ==> ={glob AcceptedSamples}) => //.
    proc; inline PoolContext(C,AcceptedSamples).run.
    call (_ : ={glob HmsgMemo,glob AcceptedSamples}); first 2 by sim.
    inline HmsgMemo(AcceptedSamples).init AcceptedSamples.init; auto.
  rewrite he; exact (adaptive_pool_coverage_bound (PoolContext(C)) n &m hn).
qed.
