(* Initialized memo game and its sampler-only projection. *)
require import AllCore List Distr FMap StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal IndependentWidths.
require import WotsAcceptedPrefix WotsMemoOracle WotsPoolRecords WotsAcceptedPool AcceptedEncodingPool.
import RealOrder.

module WotsMemoGame (C : PrefixContext) = {
  proc run() : bool = {
    var result;
    WotsAcceptedSamples.init(); WotsMemo(WotsAcceptedSamples).init();
    result <@ C(WotsMemo(WotsAcceptedSamples)).run();
    return result;
  }
}.
module WotsPoolContext (C : PrefixContext) (S : WotsAcceptedSampler) = {
  proc run() : unit = {
    var result;
    WotsMemo(S).init(); result <@ C(WotsMemo(S)).run();
  }
}.
lemma wots_game_projection (C <: PrefixContext {-Independent,-WotsMemo,-WotsAcceptedSamples}) :
  equiv[IndependentGame(C).run ~ WotsMemoGame(C).run : ={glob C} ==>
    ={res,glob C} /\ Independent.rawhistory{1}=WotsMemo.rawhistory{2} /\
    Independent.secrethistory{1}=WotsMemo.secrethistory{2} /\ Independent.queries{1}=WotsMemo.queries{2}].
proof.
  proc; call (wots_memo_context_refinement C).
  inline Independent.init WotsMemo(WotsAcceptedSamples).init WotsAcceptedSamples.init; auto.
qed.
lemma wots_game_records (C <: PrefixContext {-WotsMemo,-WotsAcceptedSamples}) :
  hoare[WotsMemoGame(C).run : true ==>
    wots_accepted_records WotsMemo.rawhistory WotsMemo.accepted_keys WotsAcceptedSamples.nodes /\
    size WotsAcceptedSamples.nodes<=WotsMemo.accepted_calls].
proof.
  proc; call (wots_context_records C).
  inline WotsMemo(WotsAcceptedSamples).init WotsAcceptedSamples.init; auto; smt(wots_accepted_records_empty).
qed.
lemma wots_game_pool_bound (C <: PrefixContext {-WotsMemo,-WotsAcceptedSamples}) n &m :
  0<=n => Pr[WotsMemoGame(C).run() @ &m : size WotsAcceptedSamples.nodes<=n /\ accepted_encoding_pool_collision WotsAcceptedSamples.nodes]
    <=conditional_encoding_charge n.
proof.
  move=> hn.
  have he : Pr[WotsMemoGame(C).run() @ &m : size WotsAcceptedSamples.nodes<=n /\ accepted_encoding_pool_collision WotsAcceptedSamples.nodes]=
    Pr[WotsAcceptedGame(WotsPoolContext(C)).run() @ &m : size WotsAcceptedSamples.nodes<=n /\ accepted_encoding_pool_collision WotsAcceptedSamples.nodes].
  + byequiv (_ : ={glob C} ==> ={glob WotsAcceptedSamples}) => //.
    proc; inline WotsPoolContext(C,WotsAcceptedSamples).run.
    call (_ : ={glob WotsMemo,glob WotsAcceptedSamples}); first 2 by sim.
    inline WotsMemo(WotsAcceptedSamples).init WotsAcceptedSamples.init; auto.
  rewrite he; exact (wots_adaptive_conditional_encoding_bound (WotsPoolContext(C)) n &m hn).
qed.
