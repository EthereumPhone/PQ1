(* Retain accepted encoding collisions while refining the original memoized oracle. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid RawWots.
require import EncodingMemoOracle FullDigestPrefixSampling AcceptedEncodingPool AcceptedWotsCollision.

op accepted_table_records (h : (raw_input,digest) fmap) (words : int list list) =
  (forall x d, h.[x]=Some d => count_accepts d => mem words (raw_digits d)) /\
  (uniq words => !accepted_wots_encoding_collision h).

lemma accepted_table_empty : accepted_table_records empty [].
proof. rewrite /accepted_table_records /accepted_wots_encoding_collision; smt(emptyE). qed.

lemma accepted_table_insert h words x d :
  accepted_table_records h words => x\notin h =>
  accepted_table_records h.[x<-d]
    (if count_accepts d then rcons words (raw_digits d) else words).
proof.
  rewrite /accepted_table_records /accepted_wots_encoding_collision.
  case (count_accepts d)=> hd; smt(get_setE domE mem_rcons rcons_uniq).
qed.

lemma accepted_encoding_words_rcons nodes d :
  accepted_encoding_words (rcons nodes d)=
    (if count_accepts d then rcons (accepted_encoding_words nodes) (raw_digits d)
     else accepted_encoding_words nodes).
proof. rewrite /accepted_encoding_words filter_rcons; case (count_accepts d); by rewrite ?map_rcons. qed.

lemma accepted_memo_hash_refinement :
  equiv [Independent.hash ~ EncodingMemo(FullDigestSamples).hash :
    ={x} /\ Independent.rawhistory{1}=EncodingMemo.rawhistory{2} /\
    Independent.secrethistory{1}=EncodingMemo.secrethistory{2} /\
    Independent.queries{1}=EncodingMemo.queries{2} ==>
    ={res} /\ Independent.rawhistory{1}=EncodingMemo.rawhistory{2} /\
    Independent.secrethistory{1}=EncodingMemo.secrethistory{2} /\
    Independent.queries{1}=EncodingMemo.queries{2}].
proof. proc; inline FullDigestSamples.sample; sp 1 1; if; auto. qed.
lemma accepted_memo_derive_refinement :
  equiv [Independent.derive ~ EncodingMemo(FullDigestSamples).derive :
    ={tail} /\ Independent.rawhistory{1}=EncodingMemo.rawhistory{2} /\
    Independent.secrethistory{1}=EncodingMemo.secrethistory{2} /\
    Independent.queries{1}=EncodingMemo.queries{2} ==>
    ={res} /\ Independent.rawhistory{1}=EncodingMemo.rawhistory{2} /\
    Independent.secrethistory{1}=EncodingMemo.secrethistory{2} /\
    Independent.queries{1}=EncodingMemo.queries{2}].
proof. proc; if; auto. qed.

lemma accepted_memo_context_refinement
  (A <: PrefixContext {-Independent,-EncodingMemo,-FullDigestSamples}) :
  equiv [A(Independent).run ~ A(EncodingMemo(FullDigestSamples)).run :
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
  + exact accepted_memo_hash_refinement.
  exact accepted_memo_derive_refinement.
qed.

op accepted_memo_nodes_valid public nodes (queries : raw_input list) =
  accepted_table_records public (accepted_encoding_words nodes) /\ size nodes<=size queries.

lemma accepted_memo_hash_records :
  hoare [EncodingMemo(FullDigestSamples).hash :
    accepted_memo_nodes_valid EncodingMemo.rawhistory FullDigestSamples.nodes EncodingMemo.queries ==>
    accepted_memo_nodes_valid EncodingMemo.rawhistory FullDigestSamples.nodes EncodingMemo.queries].
proof.
  proc; inline FullDigestSamples.sample; sp 1; if; auto;
    rewrite /accepted_memo_nodes_valid /=;
    smt(size_rcons accepted_table_insert accepted_encoding_words_rcons).
qed.
lemma accepted_memo_derive_records :
  hoare [EncodingMemo(FullDigestSamples).derive :
    accepted_memo_nodes_valid EncodingMemo.rawhistory FullDigestSamples.nodes EncodingMemo.queries ==>
    accepted_memo_nodes_valid EncodingMemo.rawhistory FullDigestSamples.nodes EncodingMemo.queries].
proof. proc; if; auto. qed.
lemma accepted_memo_context_records
  (A <: PrefixContext {-EncodingMemo,-FullDigestSamples}) :
  hoare [A(EncodingMemo(FullDigestSamples)).run :
    accepted_memo_nodes_valid EncodingMemo.rawhistory FullDigestSamples.nodes EncodingMemo.queries ==>
    accepted_memo_nodes_valid EncodingMemo.rawhistory FullDigestSamples.nodes EncodingMemo.queries].
proof.
  proc (accepted_memo_nodes_valid EncodingMemo.rawhistory FullDigestSamples.nodes EncodingMemo.queries) => //.
  + exact accepted_memo_hash_records.
  exact accepted_memo_derive_records.
qed.
