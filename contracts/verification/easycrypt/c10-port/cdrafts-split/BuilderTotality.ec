(* The actual independent-oracle builders and recoveries terminate. *)
require import AllCore List.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawMerkle RawFors.

lemma preparation_wots_ll : islossless PreparationView(Independent).wots.
proof. proc; call independent_derive_ll; auto. qed.

lemma preparation_fors_ll : islossless PreparationView(Independent).fors.
proof. proc; call independent_derive_ll; auto. qed.

lemma merkle_independent_build_ll :
  islossless RawMerkle(PreparationView(Independent)).build.
proof. exact (merkle_build_lossless (PreparationView(Independent))
  independent_hash_ll preparation_wots_ll). qed.

lemma fors_independent_tree_ll :
  islossless RawFors(PreparationView(Independent)).tree.
proof. exact (fors_tree_lossless (PreparationView(Independent))
  independent_hash_ll preparation_fors_ll). qed.

lemma merkle_independent_recover_ll :
  islossless RawMerkle(PreparationView(Independent)).recover.
proof. exact (merkle_recover_lossless (PreparationView(Independent))
  independent_hash_ll). qed.

lemma fors_independent_recover_ll :
  islossless RawFors(PreparationView(Independent)).recover.
proof. exact (fors_recover_lossless (PreparationView(Independent))
  independent_hash_ll). qed.
