(* The actual independent-table collision event and a fresh-draw reduction. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess RawKeygen.
require import ProjectedBirthday DomainNodeCollision NodeQueryDomain DomainQueryCount DomainNodeTable DomainMemoOracle.

module IndependentDomainCollision (A : PrefixContext) = {
  proc run() : bool = {
    var ignored;
    Independent.init();
    ignored <@ A(Independent).run();
    return domain_node_collision Independent.rawhistory;
  }
}.
module DomainPublicDraws (A : PrefixContext) (S : ProjectedSampler) = {
  proc run() : unit = {
    var ignored;
    DomainMemo(S).init();
    ignored <@ A(DomainMemo(S)).run();
  }
}.

lemma domain_collision_refinement
  (A <: PrefixContext {-Independent,-DomainMemo,-ProjectedSamples}) :
  equiv [IndependentDomainCollision(A).run ~ ProjectedGame(DomainPublicDraws(A)).run :
    ={glob A} ==>
    res{1}=domain_node_collision DomainMemo.rawhistory{2} /\
    Independent.queries{1}=DomainMemo.queries{2}].
proof.
  proc; inline DomainPublicDraws(A,ProjectedSamples).run.
  call (domain_memo_context_refinement A).
  inline Independent.init DomainMemo(ProjectedSamples).init ProjectedSamples.init; auto.
qed.

lemma domain_public_draws_recorded
  (A <: PrefixContext {-DomainMemo,-ProjectedSamples}) :
  hoare [ProjectedGame(DomainPublicDraws(A)).run : true ==>
    domain_memo_nodes_valid DomainMemo.rawhistory ProjectedSamples.nodes DomainMemo.queries].
proof.
  proc; inline DomainPublicDraws(A,ProjectedSamples).run.
  call (domain_memo_context_records A).
  inline DomainMemo(ProjectedSamples).init ProjectedSamples.init; auto;
    rewrite /domain_memo_nodes_valid /node_query_count /=; smt(domain_table_empty).
qed.
