(* Exactly the independent memoized oracle with public draws instrumented. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid RawKeygen.
require import EncodingBirthday MemoEncodingCollision.

module EncodingMemo (S : EncodingSampler) = {
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

lemma encoding_projected_memo_hash_lossless (S <: EncodingSampler) :
  islossless S.sample => islossless EncodingMemo(S).hash.
proof. move=> hs; proc; sp 1; if; auto; wp; call hs; auto. qed.
lemma encoding_projected_memo_derive_lossless (S <: EncodingSampler) : islossless EncodingMemo(S).derive.
proof. proc; if; auto; smt(full_digest_ll). qed.

lemma encoding_memo_hash_refinement :
  equiv [Independent.hash ~ EncodingMemo(EncodingSamples).hash :
    ={x} /\ Independent.rawhistory{1}=EncodingMemo.rawhistory{2} /\
    Independent.secrethistory{1}=EncodingMemo.secrethistory{2} /\
    Independent.queries{1}=EncodingMemo.queries{2} ==>
    ={res} /\ Independent.rawhistory{1}=EncodingMemo.rawhistory{2} /\
    Independent.secrethistory{1}=EncodingMemo.secrethistory{2} /\
    Independent.queries{1}=EncodingMemo.queries{2}].
proof. proc; inline EncodingSamples.sample; sp 1 1; if; auto. qed.
lemma encoding_memo_derive_refinement :
  equiv [Independent.derive ~ EncodingMemo(EncodingSamples).derive :
    ={tail} /\ Independent.rawhistory{1}=EncodingMemo.rawhistory{2} /\
    Independent.secrethistory{1}=EncodingMemo.secrethistory{2} /\
    Independent.queries{1}=EncodingMemo.queries{2} ==>
    ={res} /\ Independent.rawhistory{1}=EncodingMemo.rawhistory{2} /\
    Independent.secrethistory{1}=EncodingMemo.secrethistory{2} /\
    Independent.queries{1}=EncodingMemo.queries{2}].
proof. proc; if; auto. qed.

lemma encoding_memo_context_refinement
  (A <: PrefixContext {-Independent,-EncodingMemo,-EncodingSamples}) :
  equiv [A(Independent).run ~ A(EncodingMemo(EncodingSamples)).run :
    ={glob A} /\ Independent.rawhistory{1}=EncodingMemo.rawhistory{2} /\
    Independent.secrethistory{1}=EncodingMemo.secrethistory{2} /\
    Independent.queries{1}=EncodingMemo.queries{2} ==>
    ={res,glob A} /\ Independent.rawhistory{1}=EncodingMemo.rawhistory{2} /\
    Independent.secrethistory{1}=EncodingMemo.secrethistory{2} /\
    Independent.queries{1}=EncodingMemo.queries{2}].
proof.
  proc (Independent.rawhistory{1}=EncodingMemo.rawhistory{2} /\
    Independent.secrethistory{1}=EncodingMemo.secrethistory{2} /\
    Independent.queries{1}=EncodingMemo.queries{2}) => //.
  + exact encoding_memo_hash_refinement.
  exact encoding_memo_derive_refinement.
qed.

op encoding_memo_nodes_valid public nodes (queries : raw_input list) =
  encoding_node_table_recorded public nodes /\ size nodes<=size queries.

lemma encoding_memo_hash_records :
  hoare [EncodingMemo(EncodingSamples).hash :
    encoding_memo_nodes_valid EncodingMemo.rawhistory EncodingSamples.nodes EncodingMemo.queries ==>
    encoding_memo_nodes_valid EncodingMemo.rawhistory EncodingSamples.nodes EncodingMemo.queries].
proof.
  proc; inline EncodingSamples.sample; sp 1; if; auto;
    rewrite /encoding_memo_nodes_valid /=; smt(size_rcons encoding_node_table_insert).
qed.
lemma encoding_memo_derive_records :
  hoare [EncodingMemo(EncodingSamples).derive :
    encoding_memo_nodes_valid EncodingMemo.rawhistory EncodingSamples.nodes EncodingMemo.queries ==>
    encoding_memo_nodes_valid EncodingMemo.rawhistory EncodingSamples.nodes EncodingMemo.queries].
proof. proc; if; auto. qed.
lemma encoding_memo_context_records
  (A <: PrefixContext {-EncodingMemo,-EncodingSamples}) :
  hoare [A(EncodingMemo(EncodingSamples)).run :
    encoding_memo_nodes_valid EncodingMemo.rawhistory EncodingSamples.nodes EncodingMemo.queries ==>
    encoding_memo_nodes_valid EncodingMemo.rawhistory EncodingSamples.nodes EncodingMemo.queries].
proof.
  proc (encoding_memo_nodes_valid EncodingMemo.rawhistory EncodingSamples.nodes EncodingMemo.queries) => //.
  + exact encoding_memo_hash_records.
  exact encoding_memo_derive_records.
qed.
