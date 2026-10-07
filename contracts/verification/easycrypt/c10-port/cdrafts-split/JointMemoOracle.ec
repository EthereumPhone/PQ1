(* Independent memoized oracle with all fresh draws and all calls instrumented. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid RawKeygen.
require import ProjectedBirthday MemoNodeCollision JointNodeCollision.

module JointMemo (S : ProjectedSampler) = {
  var rawhistory : (raw_input,digest) fmap
  var secrethistory : (raw_input,digest) fmap
  var queries : raw_input list
  var calls : int
  proc init() : unit = { rawhistory <- empty; secrethistory <- empty; queries <- []; calls <- 0; }
  proc hash(x : raw_input) : digest = {
    var d;
    calls <- calls+1; queries <- rcons queries x;
    if (x\notin rawhistory) { d <@ S.sample(); rawhistory.[x] <- d; }
    return oget rawhistory.[x];
  }
  proc derive(tail : raw_input) : digest = {
    var d;
    calls <- calls+1;
    if (tail\notin secrethistory) { d <@ S.sample(); secrethistory.[tail] <- d; }
    return oget secrethistory.[tail];
  }
}.

lemma projected_joint_memo_hash_lossless (S <: ProjectedSampler) :
  islossless S.sample => islossless JointMemo(S).hash.
proof. move=> hs; proc; sp 2; if; auto; wp; call hs; auto. qed.
lemma projected_joint_memo_derive_lossless (S <: ProjectedSampler) :
  islossless S.sample => islossless JointMemo(S).derive.
proof. move=> hs; proc; sp 1; if; auto; wp; call hs; auto. qed.

lemma joint_memo_hash_refinement :
  equiv [Independent.hash ~ JointMemo(ProjectedSamples).hash :
    ={x} /\ Independent.rawhistory{1}=JointMemo.rawhistory{2} /\
    Independent.secrethistory{1}=JointMemo.secrethistory{2} /\
    Independent.queries{1}=JointMemo.queries{2} ==>
    ={res} /\ Independent.rawhistory{1}=JointMemo.rawhistory{2} /\
    Independent.secrethistory{1}=JointMemo.secrethistory{2} /\
    Independent.queries{1}=JointMemo.queries{2}].
proof. proc; inline ProjectedSamples.sample; sp 1 2; if; auto. qed.
lemma joint_memo_derive_refinement :
  equiv [Independent.derive ~ JointMemo(ProjectedSamples).derive :
    ={tail} /\ Independent.rawhistory{1}=JointMemo.rawhistory{2} /\
    Independent.secrethistory{1}=JointMemo.secrethistory{2} /\
    Independent.queries{1}=JointMemo.queries{2} ==>
    ={res} /\ Independent.rawhistory{1}=JointMemo.rawhistory{2} /\
    Independent.secrethistory{1}=JointMemo.secrethistory{2} /\
    Independent.queries{1}=JointMemo.queries{2}].
proof. proc; inline ProjectedSamples.sample; sp 0 1; if; auto. qed.

lemma joint_memo_context_refinement
  (A <: PrefixContext {-Independent,-JointMemo,-ProjectedSamples}) :
  equiv [A(Independent).run ~ A(JointMemo(ProjectedSamples)).run :
    ={glob A} /\ Independent.rawhistory{1}=JointMemo.rawhistory{2} /\
    Independent.secrethistory{1}=JointMemo.secrethistory{2} /\
    Independent.queries{1}=JointMemo.queries{2} ==>
    ={res,glob A} /\ Independent.rawhistory{1}=JointMemo.rawhistory{2} /\
    Independent.secrethistory{1}=JointMemo.secrethistory{2} /\
    Independent.queries{1}=JointMemo.queries{2}].
proof.
  proc (Independent.rawhistory{1}=JointMemo.rawhistory{2} /\
    Independent.secrethistory{1}=JointMemo.secrethistory{2} /\
    Independent.queries{1}=JointMemo.queries{2}) => //.
  + exact joint_memo_hash_refinement.
  exact joint_memo_derive_refinement.
qed.


lemma joint_hash_count c :
  hoare [JointMemo(ProjectedSamples).hash : JointMemo.calls=c ==> JointMemo.calls=c+1].
proof. proc; inline ProjectedSamples.sample; sp 2; if; auto. qed.
lemma joint_derive_count c :
  hoare [JointMemo(ProjectedSamples).derive : JointMemo.calls=c ==> JointMemo.calls=c+1].
proof. proc; inline ProjectedSamples.sample; sp 1; if; auto. qed.

op joint_memo_valid h s nodes calls = joint_nodes_valid h s nodes /\ size nodes<=calls.
lemma joint_memo_hash_records :
  hoare [JointMemo(ProjectedSamples).hash :
    joint_memo_valid JointMemo.rawhistory JointMemo.secrethistory ProjectedSamples.nodes JointMemo.calls ==>
    joint_memo_valid JointMemo.rawhistory JointMemo.secrethistory ProjectedSamples.nodes JointMemo.calls].
proof.
  proc; inline ProjectedSamples.sample; sp 2; if; auto;
    rewrite /joint_memo_valid /=; smt(joint_nodes_public_insert).
qed.
lemma joint_memo_derive_records :
  hoare [JointMemo(ProjectedSamples).derive :
    joint_memo_valid JointMemo.rawhistory JointMemo.secrethistory ProjectedSamples.nodes JointMemo.calls ==>
    joint_memo_valid JointMemo.rawhistory JointMemo.secrethistory ProjectedSamples.nodes JointMemo.calls].
proof.
  proc; inline ProjectedSamples.sample; sp 1; if; auto;
    rewrite /joint_memo_valid /=; smt(joint_nodes_private_insert).
qed.
lemma joint_memo_context_records
  (A <: PrefixContext {-JointMemo,-ProjectedSamples}) :
  hoare [A(JointMemo(ProjectedSamples)).run :
    joint_memo_valid JointMemo.rawhistory JointMemo.secrethistory ProjectedSamples.nodes JointMemo.calls ==>
    joint_memo_valid JointMemo.rawhistory JointMemo.secrethistory ProjectedSamples.nodes JointMemo.calls].
proof.
  proc (joint_memo_valid JointMemo.rawhistory JointMemo.secrethistory ProjectedSamples.nodes JointMemo.calls) => //.
  + exact joint_memo_hash_records.
  exact joint_memo_derive_records.
qed.
