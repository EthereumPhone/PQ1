(* Exactly the independent memoized oracle with public draws instrumented. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid RawKeygen.
require import ProjectedBirthday MemoNodeCollision.

module ProjectedMemo (S : ProjectedSampler) = {
  var rawhistory : (raw_input,digest) fmap
  var secrethistory : (raw_input,digest) fmap
  var queries : raw_input list
  proc init() : unit = { rawhistory <- empty; secrethistory <- empty; queries <- []; }
  proc hash(x : raw_input) : digest = {
    var d;
    queries <- rcons queries x;
    if (x\notin rawhistory) { d <@ S.sample(); rawhistory.[x] <- d; }
    return oget rawhistory.[x];
  }
  proc derive(tail : raw_input) : digest = {
    var d;
    if (tail\notin secrethistory) { d <$ full_digest; secrethistory.[tail] <- d; }
    return oget secrethistory.[tail];
  }
}.

lemma projected_memo_hash_lossless (S <: ProjectedSampler) :
  islossless S.sample => islossless ProjectedMemo(S).hash.
proof. move=> hs; proc; sp 1; if; auto; wp; call hs; auto. qed.
lemma projected_memo_derive_lossless (S <: ProjectedSampler) : islossless ProjectedMemo(S).derive.
proof. proc; if; auto; smt(full_digest_ll). qed.

lemma memo_hash_refinement :
  equiv [Independent.hash ~ ProjectedMemo(ProjectedSamples).hash :
    ={x} /\ Independent.rawhistory{1}=ProjectedMemo.rawhistory{2} /\
    Independent.secrethistory{1}=ProjectedMemo.secrethistory{2} /\
    Independent.queries{1}=ProjectedMemo.queries{2} ==>
    ={res} /\ Independent.rawhistory{1}=ProjectedMemo.rawhistory{2} /\
    Independent.secrethistory{1}=ProjectedMemo.secrethistory{2} /\
    Independent.queries{1}=ProjectedMemo.queries{2}].
proof. proc; inline ProjectedSamples.sample; sp 1 1; if; auto. qed.
lemma memo_derive_refinement :
  equiv [Independent.derive ~ ProjectedMemo(ProjectedSamples).derive :
    ={tail} /\ Independent.rawhistory{1}=ProjectedMemo.rawhistory{2} /\
    Independent.secrethistory{1}=ProjectedMemo.secrethistory{2} /\
    Independent.queries{1}=ProjectedMemo.queries{2} ==>
    ={res} /\ Independent.rawhistory{1}=ProjectedMemo.rawhistory{2} /\
    Independent.secrethistory{1}=ProjectedMemo.secrethistory{2} /\
    Independent.queries{1}=ProjectedMemo.queries{2}].
proof. proc; if; auto. qed.

lemma memo_context_refinement
  (A <: PrefixContext {-Independent,-ProjectedMemo,-ProjectedSamples}) :
  equiv [A(Independent).run ~ A(ProjectedMemo(ProjectedSamples)).run :
    ={glob A} /\ Independent.rawhistory{1}=ProjectedMemo.rawhistory{2} /\
    Independent.secrethistory{1}=ProjectedMemo.secrethistory{2} /\
    Independent.queries{1}=ProjectedMemo.queries{2} ==>
    ={res,glob A} /\ Independent.rawhistory{1}=ProjectedMemo.rawhistory{2} /\
    Independent.secrethistory{1}=ProjectedMemo.secrethistory{2} /\
    Independent.queries{1}=ProjectedMemo.queries{2}].
proof.
  proc (Independent.rawhistory{1}=ProjectedMemo.rawhistory{2} /\
    Independent.secrethistory{1}=ProjectedMemo.secrethistory{2} /\
    Independent.queries{1}=ProjectedMemo.queries{2}) => //.
  + exact memo_hash_refinement.
  exact memo_derive_refinement.
qed.

op memo_nodes_valid public nodes (queries : raw_input list) =
  node_table_recorded public nodes /\ size nodes<=size queries.

lemma memo_hash_records :
  hoare [ProjectedMemo(ProjectedSamples).hash :
    memo_nodes_valid ProjectedMemo.rawhistory ProjectedSamples.nodes ProjectedMemo.queries ==>
    memo_nodes_valid ProjectedMemo.rawhistory ProjectedSamples.nodes ProjectedMemo.queries].
proof.
  proc; inline ProjectedSamples.sample; sp 1; if; auto;
    rewrite /memo_nodes_valid /=; smt(size_rcons node_table_insert).
qed.
lemma memo_derive_records :
  hoare [ProjectedMemo(ProjectedSamples).derive :
    memo_nodes_valid ProjectedMemo.rawhistory ProjectedSamples.nodes ProjectedMemo.queries ==>
    memo_nodes_valid ProjectedMemo.rawhistory ProjectedSamples.nodes ProjectedMemo.queries].
proof. proc; if; auto. qed.
lemma memo_context_records
  (A <: PrefixContext {-ProjectedMemo,-ProjectedSamples}) :
  hoare [A(ProjectedMemo(ProjectedSamples)).run :
    memo_nodes_valid ProjectedMemo.rawhistory ProjectedSamples.nodes ProjectedMemo.queries ==>
    memo_nodes_valid ProjectedMemo.rawhistory ProjectedSamples.nodes ProjectedMemo.queries].
proof.
  proc (memo_nodes_valid ProjectedMemo.rawhistory ProjectedSamples.nodes ProjectedMemo.queries) => //.
  + exact memo_hash_records.
  exact memo_derive_records.
qed.
