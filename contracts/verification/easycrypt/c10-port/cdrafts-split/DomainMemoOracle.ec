(* Only fresh node-domain queries enter the proof sampler; every reply remains memoized. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid RawKeygen.
require import ProjectedBirthday NodeQueryDomain DomainQueryCount DomainNodeTable.

module DomainMemo (S : ProjectedSampler) = {
  var rawhistory : (raw_input,digest) fmap
  var secrethistory : (raw_input,digest) fmap
  var queries : raw_input list
  proc init() : unit = { rawhistory <- empty; secrethistory <- empty; queries <- []; }
  proc hash(x : raw_input) : digest = {
    var d;
    queries <- rcons queries x;
    if (x\notin rawhistory) {
      if (node_query x) { d <@ S.sample(); } else { d <$ full_digest; }
      rawhistory.[x] <- d;
    }
    return oget rawhistory.[x];
  }
  proc derive(tail : raw_input) : digest = {
    var d;
    if (tail\notin secrethistory) { d <$ full_digest; secrethistory.[tail] <- d; }
    return oget secrethistory.[tail];
  }
}.

lemma domain_memo_hash_lossless (S <: ProjectedSampler) :
  islossless S.sample => islossless DomainMemo(S).hash.
proof. move=> hs; proc; sp 1; if; last by auto.
  wp; if; first by call hs; auto.
  auto; smt(full_digest_ll). qed.
lemma domain_memo_derive_lossless (S <: ProjectedSampler) : islossless DomainMemo(S).derive.
proof. proc; if; auto; smt(full_digest_ll). qed.

lemma domain_memo_hash_refinement :
  equiv [Independent.hash ~ DomainMemo(ProjectedSamples).hash :
    ={x} /\ Independent.rawhistory{1}=DomainMemo.rawhistory{2} /\
    Independent.secrethistory{1}=DomainMemo.secrethistory{2} /\
    Independent.queries{1}=DomainMemo.queries{2} ==>
    ={res} /\ Independent.rawhistory{1}=DomainMemo.rawhistory{2} /\
    Independent.secrethistory{1}=DomainMemo.secrethistory{2} /\
    Independent.queries{1}=DomainMemo.queries{2}].
proof.
  proc; inline ProjectedSamples.sample; sp 1 1.
  if; first by auto.
  + if{2}; auto.
  auto.
qed.
lemma domain_memo_derive_refinement :
  equiv [Independent.derive ~ DomainMemo(ProjectedSamples).derive :
    ={tail} /\ Independent.rawhistory{1}=DomainMemo.rawhistory{2} /\
    Independent.secrethistory{1}=DomainMemo.secrethistory{2} /\
    Independent.queries{1}=DomainMemo.queries{2} ==>
    ={res} /\ Independent.rawhistory{1}=DomainMemo.rawhistory{2} /\
    Independent.secrethistory{1}=DomainMemo.secrethistory{2} /\
    Independent.queries{1}=DomainMemo.queries{2}].
proof. proc; if; auto. qed.

lemma domain_memo_context_refinement
  (A <: PrefixContext {-Independent,-DomainMemo,-ProjectedSamples}) :
  equiv [A(Independent).run ~ A(DomainMemo(ProjectedSamples)).run :
    ={glob A} /\ Independent.rawhistory{1}=DomainMemo.rawhistory{2} /\
    Independent.secrethistory{1}=DomainMemo.secrethistory{2} /\
    Independent.queries{1}=DomainMemo.queries{2} ==>
    ={res,glob A} /\ Independent.rawhistory{1}=DomainMemo.rawhistory{2} /\
    Independent.secrethistory{1}=DomainMemo.secrethistory{2} /\
    Independent.queries{1}=DomainMemo.queries{2}].
proof.
  proc (Independent.rawhistory{1}=DomainMemo.rawhistory{2} /\
    Independent.secrethistory{1}=DomainMemo.secrethistory{2} /\
    Independent.queries{1}=DomainMemo.queries{2}) => //.
  + exact domain_memo_hash_refinement.
  exact domain_memo_derive_refinement.
qed.

op domain_memo_nodes_valid public nodes (queries : raw_input list) =
  domain_table_recorded public nodes /\ size nodes<=node_query_count queries.

lemma domain_memo_hash_records :
  hoare [DomainMemo(ProjectedSamples).hash :
    domain_memo_nodes_valid DomainMemo.rawhistory ProjectedSamples.nodes DomainMemo.queries ==>
    domain_memo_nodes_valid DomainMemo.rawhistory ProjectedSamples.nodes DomainMemo.queries].
proof.
  proc; inline ProjectedSamples.sample; sp 1; if.
  + if; auto; rewrite /domain_memo_nodes_valid /=;
      smt(domain_table_insert_node domain_table_insert_other node_query_count_rcons b2i0 b2i1).
  auto; rewrite /domain_memo_nodes_valid; smt(node_query_count_rcons b2i_ge0).
qed.
lemma domain_memo_derive_records :
  hoare [DomainMemo(ProjectedSamples).derive :
    domain_memo_nodes_valid DomainMemo.rawhistory ProjectedSamples.nodes DomainMemo.queries ==>
    domain_memo_nodes_valid DomainMemo.rawhistory ProjectedSamples.nodes DomainMemo.queries].
proof. proc; if; auto. qed.
lemma domain_memo_context_records
  (A <: PrefixContext {-DomainMemo,-ProjectedSamples}) :
  hoare [A(DomainMemo(ProjectedSamples)).run :
    domain_memo_nodes_valid DomainMemo.rawhistory ProjectedSamples.nodes DomainMemo.queries ==>
    domain_memo_nodes_valid DomainMemo.rawhistory ProjectedSamples.nodes DomainMemo.queries].
proof.
  proc (domain_memo_nodes_valid DomainMemo.rawhistory ProjectedSamples.nodes DomainMemo.queries) => //.
  + exact domain_memo_hash_records.
  exact domain_memo_derive_records.
qed.
