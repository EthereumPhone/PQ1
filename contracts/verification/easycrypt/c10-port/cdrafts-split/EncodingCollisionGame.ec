(* The actual independent-table collision event and a fresh-draw reduction. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess RawKeygen.
require import EncodingBirthday MemoEncodingCollision EncodingMemoOracle.

module IndependentEncodingCollision (A : PrefixContext) = {
  proc run() : bool = {
    var ignored;
    Independent.init();
    ignored <@ A(Independent).run();
    return encoding_public_node_collision Independent.rawhistory;
  }
}.
module EncodingDraws (A : PrefixContext) (S : EncodingSampler) = {
  proc run() : unit = {
    var ignored;
    EncodingMemo(S).init();
    ignored <@ A(EncodingMemo(S)).run();
  }
}.

lemma encoding_public_collision_refinement
  (A <: PrefixContext {-Independent,-EncodingMemo,-EncodingSamples}) :
  equiv [IndependentEncodingCollision(A).run ~ EncodingGame(EncodingDraws(A)).run :
    ={glob A} ==>
    res{1}=encoding_public_node_collision EncodingMemo.rawhistory{2} /\
    Independent.queries{1}=EncodingMemo.queries{2}].
proof.
  proc; inline EncodingDraws(A,EncodingSamples).run.
  call (encoding_memo_context_refinement A).
  inline Independent.init EncodingMemo(EncodingSamples).init EncodingSamples.init; auto.
qed.

lemma encoding_independent_collision_budget (A <: PrefixContext {-Independent}) q :
  hoare [A(Independent).run : Independent.queries=[] ==> size Independent.queries<=q] =>
  hoare [IndependentEncodingCollision(A).run : true ==> size Independent.queries<=q].
proof. move=> hb; proc; call hb; inline Independent.init; auto. qed.

lemma encoding_public_draws_recorded
  (A <: PrefixContext {-EncodingMemo,-EncodingSamples}) :
  hoare [EncodingGame(EncodingDraws(A)).run : true ==>
    encoding_memo_nodes_valid EncodingMemo.rawhistory EncodingSamples.nodes EncodingMemo.queries].
proof.
  proc; inline EncodingDraws(A,EncodingSamples).run.
  call (encoding_memo_context_records A).
  inline EncodingMemo(EncodingSamples).init EncodingSamples.init; auto;
    rewrite /encoding_memo_nodes_valid /=; smt(encoding_node_table_empty).
qed.
