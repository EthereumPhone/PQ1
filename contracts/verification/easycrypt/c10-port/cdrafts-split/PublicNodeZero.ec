(* The invalid-sum zero sentinel is a possible node, with an explicit charge. *)
require import AllCore List FMap Distr StdOrder StdBigop FelTactic.
require import C10RawOracle RawKeygen NodeDistribution ProjectedBirthday.
require import PrefixGuess MemoNodeCollision ProjectedMemoOracle PublicCollisionGame.
import RField RealOrder.

op public_node_zero (h : (raw_input,digest) fmap) =
  exists x d, h.[x]=Some d /\ node d=nseq 16 0.

lemma recorded_zero_implies_seen h nodes :
  node_table_recorded h nodes => public_node_zero h => mem nodes (nseq 16 0).
proof. rewrite /node_table_recorded /nodes_cover /public_node_zero; smt(). qed.

lemma projected_zero_probability (A <: ProjectedClient {-ProjectedSamples}) q &m :
  0<=q =>
  Pr[ProjectedGame(A).run() @ &m : size ProjectedSamples.nodes<=q /\
    mem ProjectedSamples.nodes (nseq 16 0)] <= q%r*(1%r/2%r)^128.
proof.
  move=> hq.
  fel 1 (size ProjectedSamples.nodes) (fun _ => (1%r/2%r)^128) q
    (mem ProjectedSamples.nodes (nseq 16 0)) [] => //.
  + by rewrite Bigreal.sumri_const 1:hq.
  + by inline*; auto.
  + proc; wp; rnd (fun d => node d=nseq 16 0); skip => // /> &hr ???.
    have h := node_atom_mass (nseq 16 0); smt().
  by move=> c; proc; auto=> /#.
qed.

module IndependentNodeZero (A : PrefixContext) = {
  proc run() : bool = {
    var ignored;
    Independent.init(); ignored <@ A(Independent).run();
    return public_node_zero Independent.rawhistory;
  }
}.

lemma public_zero_refinement
  (A <: PrefixContext {-Independent,-ProjectedMemo,-ProjectedSamples}) :
  equiv [IndependentNodeZero(A).run ~ ProjectedGame(PublicDraws(A)).run :
    ={glob A} ==>
    res{1}=public_node_zero ProjectedMemo.rawhistory{2} /\
    Independent.queries{1}=ProjectedMemo.queries{2}].
proof.
  proc; inline PublicDraws(A,ProjectedSamples).run.
  call (memo_context_refinement A).
  inline Independent.init ProjectedMemo(ProjectedSamples).init ProjectedSamples.init; auto.
qed.

lemma zero_budget_at_state (A <: PrefixContext {-Independent}) q &m :
  hoare [A(Independent).run : Independent.queries=[] /\ (glob A)=(glob A){m} ==>
    size Independent.queries<=q] =>
  hoare [IndependentNodeZero(A).run : (glob A)=(glob A){m} ==>
    size Independent.queries<=q].
proof. move=> hb; proc; call hb; inline Independent.init; auto. qed.

lemma public_node_zero_at_state
  (A <: PrefixContext {-Independent,-ProjectedMemo,-ProjectedSamples}) q &m :
  0<=q =>
  hoare [A(Independent).run : Independent.queries=[] /\ (glob A)=(glob A){m} ==>
    size Independent.queries<=q] =>
  Pr[IndependentNodeZero(A).run() @ &m : res] <= q%r*(1%r/2%r)^128.
proof.
  move=> hq hb.
  have he : Pr[IndependentNodeZero(A).run() @ &m : res] <=
    Pr[ProjectedGame(PublicDraws(A)).run() @ &m :
      size ProjectedSamples.nodes<=q /\ mem ProjectedSamples.nodes (nseq 16 0)].
  + byequiv (_ : ={glob A} /\ (glob A){1}=(glob A){m} ==>
      res{1} => size ProjectedSamples.nodes{2}<=q /\ mem ProjectedSamples.nodes{2} (nseq 16 0)) => //.
    conseq (public_zero_refinement A) (zero_budget_at_state A q &m hb) (public_draws_recorded A);
      rewrite /memo_nodes_valid; smt(recorded_zero_implies_seen).
  have hp := projected_zero_probability (PublicDraws(A)) q &m hq.
  exact (ler_trans _ _ _ he hp).
qed.
