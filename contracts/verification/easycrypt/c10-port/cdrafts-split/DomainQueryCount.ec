(* Count calls in the conservative node domain, including cached repeats. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen.
require import NodeQueryDomain IndependentWidths.

op node_query_count (queries : raw_input list) = size (filter node_query queries).

lemma node_query_count_ge0 queries : 0<=node_query_count queries.
proof. rewrite /node_query_count; exact (size_ge0 _). qed.
lemma node_query_count_le_size queries : node_query_count queries<=size queries.
proof.
  rewrite /node_query_count; elim: queries => [|x xs ih] //=.
  case (node_query x); smt().
qed.
lemma node_query_count_rcons queries x :
  node_query_count (rcons queries x)=node_query_count queries+b2i (node_query x).
proof.
  rewrite /node_query_count filter_rcons; case (node_query x); rewrite /= /b2i; smt(size_rcons).
qed.

lemma domain_hash_bound q :
  hoare[Independent.hash : node_query_count Independent.queries<=q ==>
    node_query_count Independent.queries<=q+1].
proof. proc; sp 1; if; auto; smt(node_query_count_rcons b2i_le1). qed.
lemma domain_hash_nonnode q :
  hoare[Independent.hash : !node_query x /\ node_query_count Independent.queries<=q ==>
    node_query_count Independent.queries<=q].
proof. proc; sp 1; if; auto; smt(node_query_count_rcons b2i0). qed.
lemma domain_derive_bound q :
  hoare[Independent.derive : node_query_count Independent.queries<=q ==>
    node_query_count Independent.queries<=q].
proof. proc; if; auto. qed.
lemma domain_wots_bound q :
  hoare[PreparationView(Independent).wots : node_query_count Independent.queries<=q ==>
    node_query_count Independent.queries<=q].
proof. proc; call (domain_derive_bound q); auto. qed.
lemma domain_fors_bound q :
  hoare[PreparationView(Independent).fors : node_query_count Independent.queries<=q ==>
    node_query_count Independent.queries<=q].
proof. proc; call (domain_derive_bound q); auto. qed.
