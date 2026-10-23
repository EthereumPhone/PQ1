(* Shared forest values in the positional form used by the actual loop. *)
require import AllCore List.
require import C10Bytes C10RawOracle RawKeygen RawForest C10Representation C10FixedBackend.
require import C10FixedCallerBridge.
require import C10FunctionalWotsValue C10FunctionalForsRecovery C10FunctionalForestRecover C10FunctionalForestOne.
require import C10FunctionalForestFill.

op functional_forest_final_root f key seed ht =
  fors_root_value (interpreted_backend f) seed key ht 12.

lemma functional_forest_secrets_value f key seed ht d :
  forest_sign_secrets (interpreted_backend f) seed key ht (functional_forest_indices d) =
    mkseq (fun t => functional_forest_one_secret f key ht t (forest_index d t)) 12 ++
      [functional_forest_final_root f key seed ht].
proof.
  rewrite /forest_sign_secrets /functional_forest_indices /functional_forest_final_root
    /functional_forest_one_secret.
  congr; apply eq_in_mkseq => t hb; smt(nth_mkseq).
qed.

lemma functional_forest_secrets_finish f key seed ht d secrets order :
  perm_eq order (range 0 12) =>
  forest_covered (nseq 16 0) 13 secrets
    (fun t => functional_forest_one_secret f key ht t (forest_index d t)) order 12 =>
  put secrets 12 (functional_forest_final_root f key seed ht) =
    forest_sign_secrets (interpreted_backend f) seed key ht (functional_forest_indices d).
proof.
  move=> hp hc; rewrite functional_forest_secrets_value.
  exact (forest_covered_last (nseq 16 0) secrets _ order _ hp hc).
qed.

lemma functional_forest_paths_value f key seed ht d :
  forest_sign_paths (interpreted_backend f) seed key ht (functional_forest_indices d) =
    mkseq (fun t => functional_forest_one_path f key seed ht t (forest_index d t)) 12.
proof.
  rewrite /forest_sign_paths /functional_forest_indices /functional_forest_one_path.
  apply eq_in_mkseq => t hb; smt(nth_mkseq).
qed.

lemma functional_forest_secret_nth f key seed ht d t : 0 <= t < 12 =>
  nth (nseq 16 0) (forest_sign_secrets (interpreted_backend f) seed key ht (functional_forest_indices d)) t =
    functional_forest_one_secret f key ht t (forest_index d t).
proof. move=> hb; rewrite functional_forest_secrets_value nth_cat size_mkseq /=; smt(nth_mkseq). qed.

lemma functional_forest_final_nth f key seed ht d :
  nth (nseq 16 0) (forest_sign_secrets (interpreted_backend f) seed key ht (functional_forest_indices d)) 12 =
    functional_forest_final_root f key seed ht.
proof. by rewrite functional_forest_secrets_value nth_cat size_mkseq /=. qed.

lemma functional_forest_path_nth f key seed ht d t : 0 <= t < 12 =>
  nth [] (forest_sign_paths (interpreted_backend f) seed key ht (functional_forest_indices d)) t =
    functional_forest_one_path f key seed ht t (forest_index d t).
proof. move=> hb; by rewrite functional_forest_paths_value nth_mkseq 1:hb. qed.

lemma functional_forest_signed_roots f key seed ht d : backend_width f =>
  forest_recover_roots (interpreted_backend f) seed ht (functional_forest_indices d)
    (forest_sign_secrets (interpreted_backend f) seed key ht (functional_forest_indices d))
    (forest_sign_paths (interpreted_backend f) seed key ht (functional_forest_indices d)) =
    mkseq (fun t => functional_forest_one_root f key seed ht t (forest_index d t)) 12 ++
      [node (f (functional_fors_leaf_query seed ht 12 0 (functional_forest_final_root f key seed ht)))].
proof.
  move=> hf; rewrite functional_forest_roots_value 1:hf /functional_forest_normal_roots
    /functional_forest_last_query functional_forest_final_nth -cats1.
  congr; apply eq_in_mkseq => t hb.
  rewrite /functional_forest_one_root; smt(functional_forest_secret_nth functional_forest_path_nth).
qed.

lemma functional_forest_roots_finish f key seed ht d roots order : backend_width f =>
  perm_eq order (range 0 12) =>
  forest_covered (nseq 16 0) 13 roots
    (fun t => functional_forest_one_root f key seed ht t (forest_index d t)) order 12 =>
  put roots 12 (node (f (functional_fors_leaf_query seed ht 12 0 (functional_forest_final_root f key seed ht)))) =
    forest_recover_roots (interpreted_backend f) seed ht (functional_forest_indices d)
      (forest_sign_secrets (interpreted_backend f) seed key ht (functional_forest_indices d))
      (forest_sign_paths (interpreted_backend f) seed key ht (functional_forest_indices d)).
proof.
  move=> hf hp hc; rewrite functional_forest_signed_roots 1:hf.
  exact (forest_covered_last (nseq 16 0) roots _ order _ hp hc).
qed.

lemma functional_forest_result_value f key seed ht d : backend_width f =>
  let secrets = forest_sign_secrets (interpreted_backend f) seed key ht (functional_forest_indices d) in
  let paths = forest_sign_paths (interpreted_backend f) seed key ht (functional_forest_indices d) in
  let roots = forest_recover_roots (interpreted_backend f) seed ht (functional_forest_indices d) secrets paths in
  (secrets,paths,node (f (multi_preimage seed (address_words 0 ht 4 0 0 0 0) roots))) =
    forest_sign_value (interpreted_backend f) seed key ht (functional_forest_indices d).
proof.
  move=> hf; rewrite /forest_sign_value /forest_recover_value /forest_compress_value /=.
  by rewrite interpreted_node 1:hf.
qed.
