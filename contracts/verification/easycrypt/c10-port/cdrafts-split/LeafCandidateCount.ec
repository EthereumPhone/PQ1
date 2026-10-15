(* Count variable suffix guesses; the two fixed values are charged separately.
   This measure never removes a query from the oracle or its history. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid RawKeygen LeafCommitmentHybrid.

op leaf_variable_query (x : raw_input) =
  leaf_suffix_candidate x <> nseq 16 0 /\
  leaf_suffix_candidate x <> nseq 16 255.
op leaf_variable_count (queries : raw_input list) = size (filter leaf_variable_query queries).

lemma leaf_variable_count_ge0 queries : 0 <= leaf_variable_count queries.
proof. rewrite /leaf_variable_count; exact (size_ge0 _). qed.
lemma leaf_variable_count_le_size queries : leaf_variable_count queries <= size queries.
proof.
  rewrite /leaf_variable_count; elim: queries => [|x xs ih] //=.
  case (leaf_variable_query x); smt().
qed.
lemma leaf_variable_count_rcons queries x :
  leaf_variable_count (rcons queries x) = leaf_variable_count queries + b2i (leaf_variable_query x).
proof.
  rewrite /leaf_variable_count filter_rcons; case (leaf_variable_query x); rewrite /= /b2i; smt(size_rcons).
qed.
lemma leaf_suffix_last_block prefix suffix : size suffix=32 =>
  leaf_suffix_candidate (prefix ++ suffix) = take 16 suffix.
proof.
  move=> hs; rewrite /leaf_suffix_candidate size_cat hs.
  have h : size prefix+32-32=size prefix by smt().
  rewrite h drop_cat_le; first smt(size_ge0).
qed.
lemma leaf_suffix_zero_counter prefix counter : size counter=4 =>
  leaf_suffix_candidate (prefix ++ (nseq 28 0 ++ counter)) = nseq 16 0.
proof.
  move=> hc; rewrite leaf_suffix_last_block; first by rewrite size_cat size_nseq hc.
  rewrite take_cat size_nseq /=.
  by rewrite -(cat_nseq 16 12 0) // take_cat size_nseq /= take0 cats0.
qed.
lemma leaf_suffix_ff_block prefix :
  leaf_suffix_candidate (prefix ++ nseq 32 255) = nseq 16 255.
proof.
  rewrite leaf_suffix_last_block; first by rewrite size_nseq.
  by rewrite -(cat_nseq 16 16 255) // take_cat size_nseq /= take0 cats0.
qed.
lemma leaf_variable_zero_counter prefix counter : size counter=4 =>
  !leaf_variable_query (prefix ++ (nseq 28 0 ++ counter)).
proof. move=> hc; rewrite /leaf_variable_query (leaf_suffix_zero_counter prefix counter hc); smt(). qed.
lemma leaf_variable_ff_block prefix : !leaf_variable_query (prefix ++ nseq 32 255).
proof. rewrite /leaf_variable_query leaf_suffix_ff_block; smt(). qed.

lemma leaf_variable_hash_bound q :
  hoare[Independent.hash : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<=q+1].
proof. proc; sp 1; if; auto; smt(leaf_variable_count_rcons b2i_le1). qed.
lemma leaf_variable_hash_fixed q :
  hoare[Independent.hash : !leaf_variable_query x /\ leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<=q].
proof. proc; sp 1; if; auto; smt(leaf_variable_count_rcons b2i0). qed.
lemma leaf_variable_derive_bound q :
  hoare[Independent.derive : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<=q].
proof. proc; if; auto. qed.
