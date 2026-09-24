(* The actual independent-table collision event and a fresh-draw reduction. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess RawKeygen.
require import ProjectedBirthday MemoNodeCollision ProjectedMemoOracle.

module IndependentNodeCollision (A : PrefixContext) = {
  proc run() : bool = {
    var ignored;
    Independent.init();
    ignored <@ A(Independent).run();
    return public_node_collision Independent.rawhistory;
  }
}.
module PublicDraws (A : PrefixContext) (S : ProjectedSampler) = {
  proc run() : unit = {
    var ignored;
    ProjectedMemo(S).init();
    ignored <@ A(ProjectedMemo(S)).run();
  }
}.

lemma public_collision_refinement
  (A <: PrefixContext {-Independent,-ProjectedMemo,-ProjectedSamples}) :
  equiv [IndependentNodeCollision(A).run ~ ProjectedGame(PublicDraws(A)).run :
    ={glob A} ==>
    res{1}=public_node_collision ProjectedMemo.rawhistory{2} /\
    Independent.queries{1}=ProjectedMemo.queries{2}].
proof.
  proc; inline PublicDraws(A,ProjectedSamples).run.
  call (memo_context_refinement A).
  inline Independent.init ProjectedMemo(ProjectedSamples).init ProjectedSamples.init; auto.
qed.

lemma independent_collision_budget (A <: PrefixContext {-Independent}) q :
  hoare [A(Independent).run : Independent.queries=[] ==> size Independent.queries<=q] =>
  hoare [IndependentNodeCollision(A).run : true ==> size Independent.queries<=q].
proof. move=> hb; proc; call hb; inline Independent.init; auto. qed.

lemma public_draws_recorded
  (A <: PrefixContext {-ProjectedMemo,-ProjectedSamples}) :
  hoare [ProjectedGame(PublicDraws(A)).run : true ==>
    memo_nodes_valid ProjectedMemo.rawhistory ProjectedSamples.nodes ProjectedMemo.queries].
proof.
  proc; inline PublicDraws(A,ProjectedSamples).run.
  call (memo_context_records A).
  inline ProjectedMemo(ProjectedSamples).init ProjectedSamples.init; auto;
    rewrite /memo_nodes_valid /=; smt(node_table_empty).
qed.
