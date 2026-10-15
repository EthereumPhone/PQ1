(* Accepted collision event in the actual independent oracle and its full-draw reduction. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess RawKeygen.
require import EncodingBirthday EncodingMemoOracle EncodingCollisionGame.
require import AcceptedWotsCollision AcceptedEncodingPool AcceptedEncodingMemo FullDigestPrefixSampling.

module IndependentAcceptedEncodingCollision (A : PrefixContext) = {
  proc run() : bool = {
    var ignored;
    Independent.init();
    ignored <@ A(Independent).run();
    return accepted_wots_encoding_collision Independent.rawhistory;
  }
}.
lemma accepted_public_collision_refinement
  (A <: PrefixContext {-Independent,-EncodingMemo,-FullDigestSamples}) :
  equiv [IndependentAcceptedEncodingCollision(A).run ~ FullDigestGame(EncodingDraws(A)).run :
    ={glob A} ==>
    res{1}=accepted_wots_encoding_collision EncodingMemo.rawhistory{2} /\
    Independent.queries{1}=EncodingMemo.queries{2}].
proof.
  proc; inline EncodingDraws(A,FullDigestSamples).run.
  call (accepted_memo_context_refinement A).
  inline Independent.init EncodingMemo(FullDigestSamples).init FullDigestSamples.init; auto.
qed.

lemma accepted_independent_collision_budget (A <: PrefixContext {-Independent}) q :
  hoare [A(Independent).run : Independent.queries=[] ==> size Independent.queries<=q] =>
  hoare [IndependentAcceptedEncodingCollision(A).run : true ==> size Independent.queries<=q].
proof. move=> hb; proc; call hb; inline Independent.init; auto. qed.

lemma accepted_public_draws_recorded
  (A <: PrefixContext {-EncodingMemo,-FullDigestSamples}) :
  hoare [FullDigestGame(EncodingDraws(A)).run : true ==>
    accepted_memo_nodes_valid EncodingMemo.rawhistory FullDigestSamples.nodes EncodingMemo.queries].
proof.
  proc; inline EncodingDraws(A,FullDigestSamples).run.
  call (accepted_memo_context_records A).
  inline EncodingMemo(FullDigestSamples).init FullDigestSamples.init; auto;
    rewrite /accepted_memo_nodes_valid /accepted_encoding_words /=; smt(accepted_table_empty).
qed.
