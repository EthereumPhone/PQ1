(* A same-context adaptive probability charge, including both private and public draws. *)
require import AllCore List Distr StdOrder.
require import C10RawOracle PrefixGuess PrefixIdeal RawKeygen.
require import ProjectedBirthday JointNodeCollision JointMemoOracle.
import RField RealOrder.

module JointDraws (A : PrefixContext) (S : ProjectedSampler) = {
  proc run() : unit = {
    var ignored;
    JointMemo(S).init();
    ignored <@ A(JointMemo(S)).run();
  }
}.

lemma joint_game_refinement
  (A <: PrefixContext {-Independent,-JointMemo,-ProjectedSamples}) :
  equiv [IndependentGame(A).run ~ ProjectedGame(JointDraws(A)).run :
    ={glob A} ==>
    Independent.rawhistory{1}=JointMemo.rawhistory{2} /\
    Independent.secrethistory{1}=JointMemo.secrethistory{2} /\
    Independent.queries{1}=JointMemo.queries{2}].
proof.
  proc; inline JointDraws(A,ProjectedSamples).run.
  call (joint_memo_context_refinement A).
  inline Independent.init JointMemo(ProjectedSamples).init ProjectedSamples.init; auto.
qed.

lemma joint_draws_recorded
  (A <: PrefixContext {-JointMemo,-ProjectedSamples}) :
  hoare [ProjectedGame(JointDraws(A)).run : true ==>
    joint_memo_valid JointMemo.rawhistory JointMemo.secrethistory ProjectedSamples.nodes JointMemo.calls].
proof.
  proc; inline JointDraws(A,ProjectedSamples).run.
  call (joint_memo_context_records A).
  inline JointMemo(ProjectedSamples).init ProjectedSamples.init; auto;
    rewrite /joint_memo_valid /=; smt(joint_nodes_empty).
qed.

lemma private_alias_bounded_draws
  (A <: PrefixContext {-Independent,-JointMemo,-ProjectedSamples}) q &m :
  0<=q =>
  Pr[IndependentGame(A).run() @ &m :
    joint_draws Independent.rawhistory Independent.secrethistory<=q /\
    private_node_alias Independent.rawhistory Independent.secrethistory] <=
    (q*(q-1))%r/2%r*(1%r/2%r)^128.
proof.
  move=> hq.
  have he : Pr[IndependentGame(A).run() @ &m :
      joint_draws Independent.rawhistory Independent.secrethistory<=q /\
      private_node_alias Independent.rawhistory Independent.secrethistory] <=
    Pr[ProjectedGame(JointDraws(A)).run() @ &m :
      size ProjectedSamples.nodes<=q /\ !uniq ProjectedSamples.nodes].
  + byequiv (_ : ={glob A} ==>
      (joint_draws Independent.rawhistory{1} Independent.secrethistory{1}<=q /\
       private_node_alias Independent.rawhistory{1} Independent.secrethistory{1}) =>
      size ProjectedSamples.nodes{2}<=q /\ !uniq ProjectedSamples.nodes{2}) => //.
    conseq (joint_game_refinement A) (_ : true ==> true) (joint_draws_recorded A).
    - rewrite /joint_memo_valid /joint_nodes_valid /joint_node_collision; smt().
    by trivial.
  have hp := projected_birthday (JointDraws(A)) q &m hq.
  exact (ler_trans _ _ _ he hp).
qed.

lemma joint_call_budget_at_state (A <: PrefixContext {-JointMemo,-ProjectedSamples}) q &m :
  hoare [A(JointMemo(ProjectedSamples)).run : JointMemo.calls=0 /\ (glob A)=(glob A){m} ==>
    JointMemo.calls<=q] =>
  hoare [ProjectedGame(JointDraws(A)).run : (glob A)=(glob A){m} ==> JointMemo.calls<=q].
proof.
  move=> hb; proc; inline JointDraws(A,ProjectedSamples).run; call hb;
    inline JointMemo(ProjectedSamples).init ProjectedSamples.init; auto.
qed.

lemma private_alias_at_state
  (A <: PrefixContext {-Independent,-JointMemo,-ProjectedSamples}) q &m :
  0<=q =>
  hoare [A(JointMemo(ProjectedSamples)).run : JointMemo.calls=0 /\ (glob A)=(glob A){m} ==>
    JointMemo.calls<=q] =>
  Pr[IndependentGame(A).run() @ &m : private_node_alias Independent.rawhistory Independent.secrethistory] <=
    (q*(q-1))%r/2%r*(1%r/2%r)^128.
proof.
  move=> hq hb.
  have hrec : hoare [ProjectedGame(JointDraws(A)).run : (glob A)=(glob A){m} ==>
    JointMemo.calls<=q /\
    joint_memo_valid JointMemo.rawhistory JointMemo.secrethistory ProjectedSamples.nodes JointMemo.calls].
  + conseq (joint_call_budget_at_state A q &m hb) (joint_draws_recorded A); smt().
  have he : Pr[IndependentGame(A).run() @ &m :
      private_node_alias Independent.rawhistory Independent.secrethistory] <=
    Pr[ProjectedGame(JointDraws(A)).run() @ &m :
      size ProjectedSamples.nodes<=q /\ !uniq ProjectedSamples.nodes].
  + byequiv (_ : ={glob A} /\ (glob A){1}=(glob A){m} ==>
      private_node_alias Independent.rawhistory{1} Independent.secrethistory{1} =>
      size ProjectedSamples.nodes{2}<=q /\ !uniq ProjectedSamples.nodes{2}) => //.
    conseq (joint_game_refinement A) (_ : true ==> true) hrec.
    - smt().
    - rewrite /joint_memo_valid /joint_nodes_valid /joint_node_collision; smt().
    by trivial.
  have hp := projected_birthday (JointDraws(A)) q &m hq.
  exact (ler_trans _ _ _ he hp).
qed.
