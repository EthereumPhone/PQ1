#!/usr/bin/env python3
"""FORWARD TAINT CLOSURE over the certified cone.

WHAT THIS IS.  Starting from the cone's `admit`ed lemmas, compute every lemma whose
proof BODY names a tainted lemma, to a fixpoint.  A theorem outside that closure does
not reach the admit by any NAMED application.

WHAT THIS IS NOT -- read before trusting it.  This is a NAME-LEVEL approximation of
"uses", and the direction is NOT uniformly safe.  An EXCLUSION claim needs an
OVER-approximation, but every hole below SHRINKS the closure, i.e. UNDER-approximates.
An earlier version of this header called the whole thing an "over-approximation", which
implied a safety margin it does not have (Kimi K3 adversarial review, 2026-08-27).  It does NOT see:
  * a bare `smt()` that picks a lemma out of the ambient context without naming it;
  * reachability through a clone instantiation or a module argument rather than a
    named application.
Neither hole is believed live here, but a check that reads stronger than it is becomes
the next fail-open.

NAME COLLISIONS BETWEEN AN `op` AND A `lemma` ARE REAL IN THIS TREE.  FORS_C_TreePort.ec
declares BOTH `op extract_op` (:1148) and `lemma extract_op` (:1485).  A pure name match
therefore CANNOT tell "applies the admitted lemma" from "uses the operator".  Two
mitigations, both implemented below:
  * POSITIONAL RULE (sound): EasyCrypt processes a file top-to-bottom and has no forward
    lemma references, so a mention at line X inside the SAME file as a lemma declared at
    line Y > X cannot be a use of that lemma.  This is what excludes `op_extract_wins`
    (:1173), which uses the OP at :1148, not the lemma at :1485.
  * AMBIGUOUS EDGES ARE KEPT, NOT DROPPED.  Where the positional rule cannot decide
    (both the op and the lemma precede the mention) the edge is retained and LABELLED
    `ambig`.  Retaining is the conservative direction for an EXCLUSION claim: it can only
    make the closure larger, never let a real taint escape.  So the honest statement is: this phase catches NAMED-APPLICATION DRIFT.  It is NOT a
soundness proof of exclusion.  A name absent from the closure is absent from the true
closure ONLY modulo the two holes above -- and both are unsafe-direction.

[UPDATE 2026-09-15: for the ONE admit left (FORS_C_TreePort.ec::extract_op) neither hole
applies, for a reason this tool does NOT compute: that theory is OUTSIDE every headline
environment.  EasyCrypt reports its symbols unknown after `require GprocTCollNamed.` (whose
cone holds the other five headline files), checked two-sided on every gate run by PHASE 3
controls scratch/_scope_*.ec.  The holes stay stated because they bite for any future admit
in a theory a headline file DOES require.]

[UPDATE 2026-09-15 (later): --check also enforces SCOPE-PROBE LINKAGE.  The files that declare
HEADLINE results must be in EXACT BIJECTION with the scratch/_scope_neg_op_<H>.ec rows of
cert-controls-split.tsv; each row MUST-FAIL, its declared reason naming every admit theory, and
its probe requiring its own headline theory.  A new headline file with no probe, or a probe left
for a file that no longer declares one, is RED here.  Controls T11..T14 in taint_controls.sh.]

Usage:  taint_closure.py            -> print the closure
        taint_closure.py --check    -> compare against cert-taint-closure.tsv, exit 1 on drift
"""
import re, sys, os

CONE_MANIFEST = 'cert-cone-files-split.tsv'
# Read by scope_linkage() only (added 2026-09-15).
CONTROLS_MANIFEST = 'cert-controls-split.tsv'
SCOPE_PROBE = re.compile(r'^scratch/_scope_neg_op_([A-Za-z0-9_]+)\.ec$')
MANIFEST      = 'cert-taint-closure.tsv'

# COMMITTED CONSTANTS -- these live in the TOOL, not only in the manifest.  A guard that
# reads its expectation out of the file it is checking cannot detect that file being gutted.
EXPECT_SEEDS       = 1      # the cone's ONE admit.  WAS 2 UNTIL 2026-08-30: the WOTS
                            # admit (nhchwcoll_hchwpre_msg) was REMOVED, not contained --
                            # its conclusion is now the BadEnc disjunction and the charge
                            # is an explicit named probability.  `extract_op` remains.
                            # This constant is deliberately EXACT, not a floor: the guard
                            # fired on the change and forced this edit to be reviewed.
EXPECT_CLOSURE     = None   # filled from the manifest, but cross-checked against EXPECT_MIN
# Declarations the parser is allowed not to register (duplicate (file,name) pairs collapse).
# Committed, not recomputed: a budget derived from the thing it checks cannot detect drift.
MIN_CLONE_STMTS  = 60  # MEASURED 80; a floor, so a broken clone scanner cannot pass vacuously.
MAX_UNREGISTERED = 2   # MEASURED: 951 declarations, 949 registered; the 2 are
                       # duplicate (file,name) pairs collapsing.  A LOOSE budget hides
                       # exactly the bugs this guard exists to catch -- keep it exact.
EXPECT_MIN_CLOSURE = 2      # was 3; one seed left, and its chain has one consumer.
                            # the closure can never be smaller than seeds+1 while a consumer exists
# Theorems that MUST NOT be in the closure.  This is the property the README asserts.
HEADLINE = [
    'functional_digest_width',
    'interpreted_backend_width',
    'node_bytes_common',
    'functional_digit_bits',
    'interpreted_node',
    'functional_chain_fold',
    'functional_chain_zero',
    'functional_chain_next',
    'functional_chain_address',
    'functional_chain_step',
    'fixed_functional_chain',
    'fixed_functional_chain_lossless',
    'raw_functional_chain_lossless',
    'raw_functional_chain',
    'functional_private_prefix',
    'functional_private_node',
    'functional_keygen_nodes',
    'functional_keygen_value',
    'functional_keygen_history_zero',
    'functional_keygen_history_next',
    'fixed_functional_keygen',
    'fixed_functional_keygen_lossless',
    'raw_functional_keygen',
    'raw_functional_keygen_lossless',
    'functional_recover_nodes',
    'functional_recover_value',
    'functional_recover_history_zero',
    'functional_recover_history_next',
    'functional_recover_cost_zero',
    'functional_recover_cost_next',
    'fixed_functional_recover',
    'fixed_functional_recover_lossless',
    'raw_functional_recover',
    'raw_functional_recover_lossless',
    'functional_shuffle_stream_zero',
    'functional_shuffle_stream_next',
    'functional_shuffle_stream_valid',
    'functional_shuffle_fold_perm',
    'functional_shuffle_order_perm',
    'fixed_functional_shuffle',
    'fixed_functional_shuffle_lossless',
    'functional_sign_nodes',
    'functional_fill_covered_zero',
    'functional_fill_covered_next',
    'functional_fill_covered_complete',
    'functional_fill_history_zero',
    'functional_fill_history_next',
    'functional_fill_cost_zero',
    'functional_fill_cost_next',
    'fixed_functional_fill',
    'fixed_functional_fill_lossless',
    'common_functional_count_prefix',
    'common_functional_count',
    'common_functional_count_lossless',
    'fixed_functional_sign',
    'fixed_functional_sign_lossless',
    'raw_functional_sign',
    'raw_functional_sign_lossless',
    'factored_functional_sign',
    'first_slot_nil',
    'first_slot_cons',
    'first_slot_bounds',
    'first_slot_zero',
    'first_slot_hit',
    'first_slot_rcons',
    'first_slot_mkseq_zero',
    'first_slot_cat',
    'first_slot_mkseq_hit',
    'signed_difference_zero',
    'wots_first_slot_common',
    'fors_first_slot_common',
    'backend_history_nil',
    'backend_history_rcons',
    'remember_consistent',
    'remember_preserves',
    'backend_empty_consistent',
    'backend_history_preserves',
    'fixed_init',
    'fixed_hash',
    'fixed_hash_ll',
    'fixed_derive',
    'fixed_derive_ll',
    'backend_width_witness',
    'fixed_hash_width',
    'fixed_hash_paired',
    'fixed_derive_paired',
    'fixed_wots_paired',
    'fixed_nonce_paired',
    'raw_fixed_wots_paired',
    'role_fixed_nonce_paired',
    'backend_history_mkseqS',
    'functional_wots_prefix',
    'fixed_wots_lossless',
    'wots_prefix_finish',
    'fixed_wots_selector',
    'functional_fors_history_zero',
    'functional_fors_history_step',
    'fixed_fors_prefix',
    'fixed_fors_lossless',
    'fors_prefix_finish',
    'fixed_fors_selector',
    'raw_wots_fixed_lossless',
    'role_nonce_fixed_lossless',
    'raw_wots_functional_selector',
    'role_nonce_functional_selector',
    'memo_reject_mass_bounds',
    'memo_reject_weight_bounds',
    'memo_reject_completion_bounds',
    'memo_reject_completion_empty',
    'memo_reject_weight_other',
    'memo_reject_completion_unqueried',
    'memo_reject_completion_complete',
    'memo_reject_completion_dominates',
    'memo_reject_scaled',
    'memo_reject_completion_step',
    'memo_reject_hash_potential',
    'memo_reject_client_potential',
    'memo_reject_client_complete',
    'memo_reject_prefilled_bound',
    'memo_reject_initialized_complete',
    'memo_reject_initialized_bound',
    'wots_context_bytes_width',
    'wots_context_bytes_valid',
    'wots_context_stem_actual',
    'wots_bytes_rank_width',
    'wots_bytes_rank_roundtrip',
    'wots_context_covered',
    'wots_context_cardinality',
    'wots_count_schedule_size',
    'wots_count_schedule_unique',
    'wots_count_schedule_actual',
    'wots_rejection_mass_exact',
    'wots_fixed_schedule_bound',
    'wots_context_union_bound',
    'wots_domain_initialized_bound',
    'memo_complete_rejection_extends',
    'wots_domain_exhausted_extends',
    'physical_hash_history',
    'physical_count_rejected',
    'physical_count_complete',
    'physical_count_exhaustion',
    'physical_count_failure',
    'physical_wots_failure',
    'physical_layer_failure',
    'physical_layer_node',
    'physical_forest_node',
    'physical_layer_outcome',
    'physical_finish_failure',
    'physical_observed_sign_failure',
    'physical_hash_extends',
    'full_availability_hash',
    'full_availability_sign',
    'full_availability_client',
    'full_availability_driver',
    'full_availability_context',
    'full_availability_initialized',
    'physical_reject_client_potential',
    'physical_reject_client_complete',
    'physical_reject_initialized_complete',
    'physical_reject_initialized_bound',
    'physical_wots_fixed_schedule',
    'physical_wots_context_union',
    'physical_wots_domain_bound',
    'signing_budget_fits_wots_schedule',
    'full_r_observer_probability',
    'byte_failed_probability_erases',
    'byte_total_initialized_availability',
    'rejection_linear_bound',
    'rejection_block_half',
    'wots_acceptance_lower',
    'wots_signing_tail',
    'wots_signing_domain_charge',
    'r_acceptance_fraction',
    'r_signing_tail',
    'r_availability_numerical',
    'total_availability_numerical',
    'total_deployed_schedule_distinct',
    'total_zero_trial_event',
    'total_duplicate_schedule_excluded',
    'total_accepted_prefill',
    'total_rejected_prefill',
    'wots_test_digest_rejected',
    'total_rejected_prefill_nonvacuous',
    'wots_test_count_exhausts',
    'wots_test_count_lossless',
    'wots_test_signer_exhausts',
    'wots_test_signer_lossless',
    'total_refusal_preserves_failed',
    'total_no_request_client_lossless',
    'total_no_request_failure_zero',
    'byte_total_deployed_availability',
    'classified_grind_exhaustion',
    'r_observed_sign_erases',
    'r_observed_sign_lossless',
    'r_observed_sign_failure',
    'full_r_init_erases',
    'full_r_hash_erases',
    'full_r_sign_erases',
    'full_r_sign_lossless',
    'full_r_sign_failure',
    'full_r_hash_failure',
    'r_observed_failure_exact',
    'r_only_classified_exhaustion',
    'r_observed_classified_exhaustion',
    'r_observed_sign_classified',
    'r_observed_sign_recorded',
    'r_observed_sign_public_cost',
    'full_r_sign_classified',
    'full_r_sign_recorded',
    'full_r_sign_live_recorded',
    'full_r_sign_history',
    'full_r_hash_history',
    'full_r_bad_step',
    'full_r_sign_progress',
    'full_r_hash_stable',
    'full_r_adaptive_exhaustion',
    'full_r_failure_context_event',
    'full_r_client_erases',
    'full_r_driver_erases',
    'full_r_context_erases',
    'full_r_final_verification_preserves_event',
    'full_r_driver_lossless',
    'full_r_context_lossless',
    'full_r_failure_context_lossless',
    'full_r_driver_exhaustion',
    'full_r_initialized_independent',
    'full_r_context_public_cost',
    'full_r_failure_context_public_cost',
    'full_r_initialized_physical',
    'byte_r_context_erases',
    'byte_r_initialized_erases',
    'byte_r_forgery_probability_unchanged',
    'byte_r_initialized_exhaustion',
    'r_empty_history_classified',
    'r_request_nonvacuous',
    'r_observer_initialization',
    'r_malformed_refusal',
    'r_cap_refusal',
    'r_failed_session_refusal',
    'r_test_digest_rejected',
    'r_test_grind_exhausts',
    'r_test_signer_observes_exhaustion',
    'r_test_signer_lossless',
    'r_test_admitted_failure',
    'paired_keygen_domain',
    'paired_keygen_preparation',
    'paired_keygen_preparation_history',
    'paired_keygen_byte_context',
    'paired_keygen_byte_initialized',
    'paired_keygen_byte_success_probability',
    'paired_keygen_byte_wots_candidate_euf_bound',
    'paired_preparation_wots',
    'paired_preparation_fors',
    'paired_preparation',
    'paired_byte_context',
    'paired_byte_initialized',
    'paired_byte_success_probability',
    'paired_session_hash',
    'paired_session_sign',
    'paired_byte_view_sign',
    'paired_byte_client',
    'paired_byte_driver',
    'paired_byte_wots_candidate_euf_bound',
    'programmed_unopened_chain_candidate_bound',
    'chain_candidate_cover_mem',
    'chain_candidate_cover_size',
    'chain_variable_nodes_le_size',
    'chain_variable_nodes_cat',
    'chain_variable_nodes_queries',
    'chain_variable_nodes_query_outputs',
    'chain_candidate_vector_cover',
    'chain_candidate_vector_mass',
    'independent_vector_candidate_bound',
    'chain_variable_derive_count',
    'chain_variable_role_grind_public_cost',
    'chain_variable_shuffle_derive_public_cost',
    'chain_variable_shuffle_permutation_public_cost',
    'chain_variable_count_public_cost',
    'chain_variable_chain_public_cost',
    'chain_variable_wots_recover_public_cost',
    'chain_variable_raw_chain_public_cost',
    'chain_variable_concrete_value_cost',
    'chain_variable_cached_value_cost',
    'chain_variable_forest_one_public_cost',
    'chain_variable_forest_sign_public_cost',
    'chain_variable_forest_recover_public_cost',
    'chain_variable_fors_public_count',
    'chain_variable_fors_tree_public_cost',
    'chain_variable_fors_sign_public_cost',
    'chain_variable_fors_root_public_cost',
    'chain_variable_fors_recover_public_cost',
    'chain_variable_leaf_public_cost',
    'chain_variable_root_public_cost',
    'chain_variable_layer_recover_public_cost',
    'chain_variable_layer_sign_public_cost',
    'chain_variable_raw_layer_recover_public_cost',
    'chain_variable_merkle_build_public_cost',
    'chain_variable_merkle_recover_public_cost',
    'chain_candidate_budget_ge0',
    'chain_variable_preparation_cost',
    'chain_variable_session_hash_cost',
    'chain_variable_session_sign_cost',
    'chain_variable_client_cost',
    'chain_variable_driver_cost',
    'chain_variable_context_cost',
    'chain_variable_signer_finish_public_cost',
    'chain_variable_signer_sign_public_cost',
    'chain_variable_signer_verify_public_cost',
    'chain_variable_wots_sign_public_cost',
    'fresh_byte_unopened_candidate_bound',
    'programmed_byte_unopened_candidate_bound',
    'selected_wots_candidate_bound',
    'chain_variable_byte_candidates_cost',
    'visible_chain_candidate_budget',
    'selected_wots_candidate_phoare',
    'configured_selected_wots_candidate_bound',
    'original_wots_candidate_coordinate_bound',
    'original_byte_wots_candidate_cut_bound',
    'original_byte_wots_candidate_euf_bound',
    'physical_byte_wots_candidate_euf_bound',
    'wots_candidate_independent_charge_tighter',
    'wots_candidate_physical_charge_tighter',
    'original_wots_candidate_union_bound',
    'original_wots_candidate_universe_bound',
    'original_byte_fors_candidate_euf_bound',
    'physical_byte_fors_candidate_euf_bound',
    'fors_candidate_independent_charge_tighter',
    'fors_candidate_physical_charge_tighter',
    'leaf_budget_leaf_cost',
    'leaf_budget_root_cost',
    'leaf_budget_layer_recover_cost',
    'leaf_budget_layer_sign_cost',
    'leaf_budget_merkle_build_cost',
    'leaf_budget_merkle_recover_cost',
    'leaf_budget_shuffle_derive_cost',
    'leaf_budget_shuffle_permutation_cost',
    'leaf_budget_count_cost',
    'leaf_budget_chain_cost',
    'leaf_budget_wots_recover_cost',
    'leaf_budget_wots_sign_cost',
    'original_byte_leaf_candidate_bound',
    'selected_byte_leaf_candidate_bound',
    'independent_leaf_candidate_at_state',
    'adaptive_hidden_leaf_candidate_at_state',
    'adaptive_unopened_leaf_candidate_at_state',
    'adaptive_selective_leaf_candidate_at_state',
    'original_leaf_candidate_coordinate_bound',
    'leaf_variable_count_ge0',
    'leaf_variable_count_le_size',
    'leaf_variable_count_rcons',
    'leaf_suffix_last_block',
    'leaf_suffix_zero_counter',
    'leaf_suffix_ff_block',
    'leaf_variable_zero_counter',
    'leaf_variable_ff_block',
    'leaf_variable_hash_bound',
    'leaf_variable_hash_fixed',
    'leaf_variable_derive_bound',
    'leaf_reduced_candidates_cover',
    'leaf_reduced_candidates_size',
    'leaf_reduced_candidate_mass',
    'original_leaf_candidate_union_bound',
    'original_byte_fors_candidate_bound',
    'leaf_counter_candidate_fixed',
    'leaf_wots_trial_fixed',
    'leaf_hmsg_candidate_fixed',
    'leaf_target_leaf_cost',
    'leaf_target_secret_cost',
    'leaf_target_fors_tree_candidate_cost',
    'leaf_target_fors_sign_candidate_cost',
    'leaf_target_fors_root_candidate_cost',
    'leaf_target_derive_bound',
    'leaf_target_wots_bound',
    'leaf_candidate_budget_ge0',
    'leaf_target_session_candidate_cost',
    'leaf_target_exposure_candidate_cost',
    'leaf_target_client_hash_candidate_cost',
    'leaf_target_client_candidate_cost',
    'leaf_target_driver_candidate_cost',
    'leaf_target_keygen_candidate_cost',
    'leaf_target_context_candidate_cost',
    'leaf_target_byte_candidate_cost',
    'leaf_target_fors_recover_candidate_cost',
    'leaf_target_forest_one_candidate_cost',
    'leaf_target_forest_sign_candidate_cost',
    'leaf_target_forest_recover_candidate_cost',
    'leaf_target_role_grind_candidate_cost',
    'leaf_target_signer_finish_candidate_cost',
    'leaf_target_signer_sign_candidate_cost',
    'leaf_target_signer_verify_candidate_cost',
    'original_observed_leaf_candidate_bound',
    'byte_domain_node_collision',
    'query_byte_domain_collision',
    'domain_verifier_extracts_forest',
    'domain_query_driver_actual_forest',
    'domain_query_context_actual_forest',
    'domain_query_byte_actual_forest',
    'domain_actual_forest_partition',
    'domain_query_byte_actual_partition',
    'domain_collision_budget_at_state',
    'domain_node_birthday_at_state',
    'independent_domain_collision_observation',
    'domain_collision_refinement',
    'domain_public_draws_recorded',
    'domain_private_covered_value',
    'domain_coverage_returns_special',
    'domain_private_opening_coverage_partition',
    'domain_forest_cases_exposure_partition',
    'domain_logged_digest_private',
    'domain_logged_fors_private_value',
    'domain_logged_special_private_root',
    'domain_recorded_verifier_forest_cases',
    'domain_verified_records_to_forest',
    'domain_forest_one_cost',
    'domain_forest_sign_cost',
    'domain_forest_recover_cost',
    'domain_forest_compress',
    'domain_forest_special',
    'domain_recorded_forest_extracts',
    'domain_fors_tree_cost',
    'domain_fors_sign_cost',
    'domain_fors_root_cost',
    'domain_fors_recover_cost',
    'domain_recorded_fors_extracts',
    'domain_leaf_cost',
    'domain_root_cost',
    'domain_layer_recover_cost',
    'domain_layer_sign_cost',
    'domain_recorded_layer_extracts',
    'domain_linear_start_unique',
    'domain_raw_chain_start_unique',
    'domain_memo_hash_lossless',
    'domain_memo_derive_lossless',
    'domain_memo_hash_refinement',
    'domain_memo_derive_refinement',
    'domain_memo_context_refinement',
    'domain_memo_hash_records',
    'domain_memo_derive_records',
    'domain_memo_context_records',
    'domain_merkle_build_cost',
    'domain_merkle_recover_cost',
    'query_byte_domain_node_cases',
    'domain_collision_is_public',
    'domain_recorded_equal_input',
    'path_input_collision_in_domain',
    'domain_table_empty',
    'domain_table_insert_node',
    'domain_table_insert_other',
    'domain_collision_implies_repeat',
    'original_byte_domain_node_euf_bound',
    'physical_byte_domain_node_euf_bound',
    'domain_node_birthday_tighter',
    'domain_node_independent_charge_tighter',
    'domain_node_physical_charge_tighter',
    'domain_merkle_pair',
    'domain_fors_pair',
    'domain_fors_leaf',
    'domain_fors_leaf_collision',
    'node_query_count_ge0',
    'node_query_count_le_size',
    'node_query_count_rcons',
    'domain_hash_bound',
    'domain_hash_nonnode',
    'domain_derive_bound',
    'domain_wots_bound',
    'domain_fors_bound',
    'node_public_budget_nonnegative',
    'node_public_budget_le_full',
    'domain_hash_valid_bound',
    'domain_signer_valid_cost',
    'domain_full_client_cost',
    'domain_full_driver_cost',
    'domain_keygen_preparation_cost',
    'domain_full_context_cost',
    'domain_byte_context_cost',
    'domain_byte_game_cost',
    'domain_shuffle_derive_cost',
    'domain_shuffle_permutation_cost',
    'domain_derive_width',
    'domain_nonnode_width',
    'domain_role_grind_cost',
    'domain_signer_finish_cost',
    'domain_signer_sign_cost',
    'domain_signer_verify_cost',
    'domain_count_cost',
    'domain_chain_cost',
    'domain_wots_recover_cost',
    'domain_wots_sign_cost',
    'domain_wots_leaf',
    'domain_recovery_leaf',
    'domain_recovery_chain_unique',
    'domain_matching_wots_endpoints',
    'domain_recovery_trace_opens_reference',
    'node_query_other_width',
    'node_query_no_hmsg',
    'node_input_kind',
    'node_query_no_count',
    'node_query_chain',
    'node_query_pair',
    'node_query_compress',
    'node_query_wide_compress',
    'node_query_merkle_kind',
    'node_query_fors_kind',
    'digit_distribution_support',
    'digit_distribution_mass',
    'digits_distribution',
    'raw_digits_encoding',
    'raw_digits_uniform',
    'digit_word_mass',
    'digit_sum_mass',
    'raw_wots_acceptance_mass',
    'wots_acceptance_mass_value',
    'wots_acceptance_mass_bounds',
    'wots_acceptance_mass_positive',
    'raw_digits_atom',
    'accepted_encoding_match_mass',
    'accepted_encoding_pair_mass',
    'full_digest_completion_step',
    'full_digest_completion_dominates',
    'full_digest_client_completion',
    'full_digest_adaptive_completion',
    'full_digest_adaptive_prefix',
    'accepted_encoding_words_cat',
    'accepted_encoding_pool_extension',
    'accepted_encoding_member',
    'accepted_encoding_pool_cons',
    'iid_has_bound',
    'accepted_head_collision_bound',
    'accepted_encoding_charge_step',
    'iid_accepted_encoding_bound',
    'adaptive_accepted_encoding_bound',
    'accepted_encoding_charge_tighter',
    'accepted_collision_is_encoding_collision',
    'accepted_different_messages_same_encoding',
    'accepted_new_message_reverse_or_encoding',
    'accepted_new_wots_opening_requires_reverse',
    'accepted_new_bottom_opening_cut',
    'accepted_new_top_opening_cut',
    'accepted_actual_new_top_cut',
    'accepted_actual_new_bottom_cut',
    'accepted_actual_partition_cut_cases',
    'query_byte_accepted_encoding_cases',
    'accepted_table_empty',
    'accepted_table_insert',
    'accepted_encoding_words_rcons',
    'accepted_memo_hash_refinement',
    'accepted_memo_derive_refinement',
    'accepted_memo_context_refinement',
    'accepted_memo_hash_records',
    'accepted_memo_derive_records',
    'accepted_memo_context_records',
    'accepted_public_collision_refinement',
    'accepted_independent_collision_budget',
    'accepted_public_draws_recorded',
    'accepted_collision_budget_at_state',
    'accepted_encoding_birthday_at_state',
    'accepted_independent_collision_observation',
    'byte_accepted_encoding_collision',
    'query_byte_accepted_encoding_collision',
    'original_byte_accepted_encoding_euf_bound',
    'physical_byte_accepted_encoding_euf_bound',
    'accepted_encoding_independent_charge_tighter',
    'accepted_encoding_physical_charge_tighter',
    'growth_word_nil',
    'growth_width_nil',
    'growth_word_cons',
    'growth_width_cons',
    'growth_width_nonnegative',
    'growth_width_bound',
    'growth_labels_bound',
    'growth_words_zero',
    'growth_words_step',
    'stirling_row_zero',
    'stirling_row_step',
    'growth_extend_member',
    'growth_words_membership',
    'stirling_row_size',
    'stirling_zero',
    'stirling_outside',
    'stirling_recurrence',
    'growth_labels_complete',
    'growth_distinct_labels',
    'growth_extend_uniq',
    'growth_next_uniq',
    'growth_words_uniq',
    'growth_extend_count',
    'growth_next_count',
    'growth_count_zero',
    'growth_count_recurrence',
    'growth_count_stirling',
    'reverse_labels_size',
    'reverse_labels_old',
    'reverse_labels_new',
    'reverse_labels_growth',
    'reverse_labels_reconstruct',
    'exact_growth_words_member',
    'exact_growth_words_size',
    'exact_growth_words_uniq',
    'reverse_labels_enumerated',
    'growth_position_bound',
    'growth_is_canonical',
    'stirling_canonical_upper',
    'distinct_words_zero',
    'distinct_words_step',
    'falling_zero',
    'falling_step',
    'falling_nonnegative',
    'distinct_step_member',
    'distinct_rem_member',
    'distinct_words_member',
    'distinct_words_size',
    'witness_alphabet_uniq',
    'witness_alphabet_member',
    'witness_alphabet_size',
    'distinct_witness_words_size',
    'distinct_witness_words_member',
    'distinct_words_uniq',
    'falling_upper',
    'falling_insufficient',
    'falling_nonpositive',
    'distinct_witness_words_insufficient',
    'coordinate_witness_stirling_pool',
    'exact_growth_assignment',
    'pool_coverage_stirling',
    'stirling_pool_enumeration',
    'stirling_pool_extension',
    'stirling_witness_union',
    'stirling_target_union',
    'stirling_j_union',
    'iid_stirling_coverage_bound',
    'adaptive_stirling_coverage_bound',
    'stirling_coverage_charge_tighter',
    'hmsg_game_stirling_pool_bound',
    'hmsg_byte_stirling_coverage_bound',
    'original_byte_stirling_coverage_bound',
    'original_byte_stirling_euf_bound',
    'physical_byte_stirling_euf_bound',
    'stirling_physical_charge_tighter',
    'stirling_independent_charge_tighter',
    'digest_wots_field',
    'digest_fors_field',
    'digest_ht_field',
    'digest_shuffle_coupled',
    'digest_count_width',
    'digest_nonce_width',
    'digest_count_coupled',
    'digest_nonce_coupled',
    'digest_wots_fill',
    'digest_wots_sign',
    'digest_wots_recover',
    'digest_fors_root_coupled',
    'digest_fors_recover_coupled',
    'digest_forest_one_coupled',
    'digest_forest_sign',
    'digest_forest_recover',
    'digest_layer_recover',
    'digest_layer_sign',
    'digest_signer_finish',
    'digest_signer_sign',
    'digest_signer_verify',
    'raw_signer_finish_digest',
    'raw_signer_sign_digest',
    'raw_signer_verify_digest',
    'raw_signer_verify_decoded_digest',
    'paired_hash_history',
    'paired_derive_history',
    'paired_shuffle_derive_history',
    'paired_shuffle_permutation_history',
    'paired_private_leaf_history',
    'paired_private_fill_history',
    'paired_fors_tree_history',
    'paired_fors_root_history',
    'paired_fors_sign_history',
    'paired_fors_recover_history',
    'paired_merkle_build_history',
    'paired_merkle_recover_history',
    'paired_forest_one_history',
    'paired_forest_sign_history',
    'paired_forest_recover_history',
    'paired_shuffle_derive_coupled',
    'paired_private_fill_coupled',
    'paired_merkle_build_coupled',
    'paired_merkle_recover_coupled',
    'paired_forest_sign_coupled',
    'paired_forest_recover_coupled',
    'paired_wots_sign',
    'paired_layer_recover',
    'paired_layer_sign',
    'paired_signer_finish',
    'paired_signer_sign',
    'paired_signer_verify',
    'raw_signer_finish_paired',
    'raw_signer_sign_paired',
    'raw_signer_verify_paired',
    'raw_signer_verify_decoded_paired',
    'shared_init_valid',
    'wots_accept_bits',
    'fors_accept_bits',
    'shared_hash_paired',
    'physical_hash_paired',
    'physical_derive_paired',
    'paired_wots_count',
    'caller_chain_history',
    'caller_chain_paired',
    'paired_wots_recover',
    'paired_nonce_grind',
    'raw_wots_count_paired',
    'raw_wots_recover_paired',
    'role_nonce_grind_paired',
    'stateful_nonce_grind_paired',
    'wots_sum_common',
    'wots_accept_common',
    'fors_accept_common',
    'wrapper_physical_budget_shape',
    'wrapper_public_budget_shape',
    'wrapper_physical_cost',
    'wrapper_public_cost',
    'wrapper_sign_full',
    'wrapper_raw_full',
    'wrapper_ready_refusal_charge',
    'wrapper_attempt_charge',
    'wrapper_sign_cap',
    'wrapper_raw_cap',
    'wrapper_client_physical_cost',
    'wrapper_driver_physical_cost',
    'wrapper_context_physical_cost',
    'wrapper_client_public_cost',
    'wrapper_driver_public_cost',
    'wrapper_context_public_cost',
    "shuffle_seed_common", "shuffle_block_common",
    "shuffle_derive_common", "shuffle_permutation_common",
    "caller_forest_one", "caller_forest_sign", "caller_forest_recover",
    "caller_layer_recover", "caller_layer_sign", "caller_signer_finish",
    "caller_signer_sign", "caller_signer_verify", "caller_signer_verify_decoded",
    "caller_fors_tree", "caller_fors_root", "caller_fors_sign", "caller_fors_recover",
    "caller_keygen_root", "caller_merkle_build", "caller_merkle_recover",
    "caller_keygen_leaf", "caller_wots_sign",
    "caller_wots_count", "caller_wots_chain", "caller_wots_recover", "caller_nonce_grind",
    "counter_common", "full_counter_word", "pad_common", "hmsg_input_common",
    "th_input_common", "pair_input_common", "multi_input_common", "wots_input_common",
    "wots_payload_common", "randomizer_input_common", "raw_wots_input_common", "role_randomizer_input_common",
    'address_common',
    'chain_index_common',
    'chain_position_common',
    'wots_private_common',
    'fors_private_common',
    "hypertree_common", "forest_common", "wots_common", "decode_word",
    'physical_byte_canonical_euf_bound',
    'original_byte_canonical_euf_bound',
    'adaptive_canonical_coverage_bound',
    'pool_coverage_canonical',
    'canonical_count_upper',
    'canonical_coverage_charge_tighter',
    'canonical_physical_charge_tighter',
    'canonical_pool_extension',
    'coordinate_witness_canonical_pool',
    'reverse_undup_index',
    'original_byte_canonical_coverage_bound',

    'accepted_joint_coordinate_mass',
    'full_digest_acceptance_split',
    'accepted_adaptive_prefix',
    'independent_assignment_mass',
    'coordinate_witness_pool',
    'actual_coverage_pool',
    'hmsg_byte_history',
    'hmsg_forest_recover_count',
    'hmsg_keygen_root_count',
    'hmsg_layer_sign_count',
    'hmsg_derive_width_count',
    'hmsg_memo_context_refinement',
    'hmsg_game_pool_bound',
    'hmsg_context_records',
    'hmsg_query_context_count',
    'hmsg_query_context_metadata',
    'hmsg_shuffle_permutation',
    'hmsg_verify_count',
    'hmsg_merkle_recover_count',
    'hmsg_wots_recover_count',
    'iid_distinct_selection',
    'physical_byte_euf_bound',
    'query_byte_numerical_cases',
    'original_byte_coverage_bound',
    'adaptive_pool_coverage_bound',
    'pool_coverage_extension',
    'query_byte_public_zero',
    'selected_assignment_mass',

    'query_byte_actual_partition',
    'query_byte_actual_forest',
    'actual_bottom_coordinate',
    'actual_partition_cut_cases',
    'query_byte_wots_encoding_collision',
    'cache_concrete_coupling',
    'cache_derive_coupling',
    'cache_value_coupling',
    'cached_chain_value_lossless',
    'repeated_top_signature',
    'chain_byte_candidate_count',
    'chain_byte_candidates_lossless',
    'complete_chain_constructs',
    'chain_cache_derive_preserved',
    'chain_context_cache_coupling',
    'cached_chain_hybrid_coupling',
    'chain_value_instrumentation',
    'adaptive_chain_hybrid',
    'chain_steps_insert',
    'chain_context_instrumentation',
    'chain_keygen_root_lossless',
    'chain_layer_sign_lossless',
    'chain_merkle_build_lossless',
    'observed_value_projection',
    'redacted_value_opened_sure',
    'prefix_cache_next_value',
    'chain_private_query_redaction',
    'chain_input_hidden_node',
    'stored_wots_next',
    'complete_chain_existing',
    'concrete_chain_replay_total',
    'chain_sampling_early_late',
    'complete_chain_existing_sure',
    'original_candidates_seed',
    'byte_chain_query_game_projection',
    'chain_signer_sign_lossless',
    'sampling_oracle_context_projection',
    'chain_start_sample_context',
    'selected_vector_visible',
    'chain_unopened_event_redaction',
    'chain_wots_sign_lossless',
    'list_chain_vector_projection',
    'programmed_chain_vector',
    'visible_chain_vector_guess_projection',
    'indexed_random_chain_cut',
    'eight_digests_list',
    'called_dual_chain_vector_projection',
    'dual_digest_projection',
    'early_plain_observed',
    'early_observed_cache_charge',
    'encoding_projected_birthday',
    'encoding_public_draws_recorded',
    'encoding_independent_collision_observation',
    'encoding_history_mass',
    'encoding_memo_context_records',
    'exposure_cut_conflicts_unreturned',
    'forest_root_unique',
    'fresh_byte_unopened_bound',
    'fresh_redacted_programmed',
    'full_sign_minimum_entry',
    'initialized_chain_sampling_early_late',
    'selected_wots_late_preserved',
    'layer_sign_root_count',
    'encoding_recorded_collision_implies_repeat',
    'minimum_byte_exposure_count',
    'minimum_verifier_exposures_preserved',
    'logged_minimal_component_openings',
    'minimum_exposure_driver_history',
    'full_sign_minimum_history',
    'node_vector_has_coordinate',
    'observed_wots_candidates_supported',
    'cached_value_cache_preserved',
    'observed_sign_projection',
    'top_cut_second',
    'observed_finish_opening',
    'observed_candidates_cut_accounted',
    'observed_count_first',
    'observed_merkle_unopened',
    'observed_layer_history_opening',
    'observed_grind_unopened',
    'observed_layer_recover_history',
    'observed_client_cut_accounted',
    'observed_signer_history_opening',
    'observed_actual_cut_unopened',
    'observed_value_opening',
    'observed_wots_opening',
    'original_byte_new_wots_bound',
    'original_wots_coordinate_bound',
    'original_byte_wots_cut_bound',
    'original_wots_universe_bound',
    'prepared_actual_cut_coupling',
    'private_value_sample_context',
    'private_value_sample_get',
    'programmed_byte_unopened_bound',
    'programmed_chain_complete',
    'programmed_unopened_chain_bound',
    'public_target_sample_context',
    'public_target_sample_get',
    'query_byte_canonical_history',
    'concrete_chain_tables_replay',
    'concrete_chain_replay_sure',
    'redacted_cached_value_cost',
    'redact_chain_context',
    'redacted_cached_value_coupling',
    'redacted_chain_derive_coupling',
    'redacted_forest_recover_public_cost',
    'redacted_fors_recover_public_cost',
    'redacted_root_public_cost',
    'redacted_raw_layer_recover_public_cost',
    'redacted_merkle_recover_public_cost',
    'redacted_context_cost',
    'redacted_signer_verify_public_cost',
    'redacted_wots_sign_public_cost',
    'selected_chain_early_late',
    'selected_wots_original_bound',
    'separated_chain_vector_projection',
    'finish_minimum_counts',
    'independent_vector_guess_bound',
    'visible_byte_candidate_budget',
    'visible_chain_installation',
    'canonical_layer_return',
    'top_output_coordinate',
    'wots_coordinates_valid',
    'repeated_wots_counts',
    'logged_component_disclosures',
    'accepted_digits_reverse_or_equal',
    'new_wots_opening_requires_reverse',
    'raw_count_first',
    'wots_r_input_disjoint',
    'wots_same_digest_signature',
    'new_top_opening_cut',

    'actual_unreturned_candidates',
    'ordinary_fors_output_coordinate',
    'selected_byte_target_bound',
    'original_unreturned_coordinate_bound',
    'original_unreturned_union_bound',
    'original_byte_fors_opening_bound',
    'original_observed_private_guess_bound',
    'selected_unreturned_implies_unopened',
    'target_layer_sign_public_cost',
    'observed_driver_openings',
    'observed_byte_candidates_unopened',
    'observed_exposure_hash',
    'forest_sign_opening',
    'target_fors_root_public_cost',
    'observed_verifier_preserves_opening',
    'returned_input_rcons',
    'target_byte_public_cost',
    'observed_session_failure_monotone',
    'target_signer_verify_public_cost',
    'target_signer_opening',
    'observed_signer_projection',
    'early_private_guess_projection',
    'target_opening_observer_projection',

    'client_query_output_binding',
    'repeated_query_recorded_twice',
    'leaf_forest_sign_projection',
    'leaf_signer_sign_projection',
    'byte_leaf_query_game_projection',
    'leaf_signer_sign_lossless',
    'adaptive_leaf_commitment',
    'adaptive_hidden_leaf_guess_bound',
    'adaptive_unopened_leaf_guess_bound',
    'initialized_private_target_sampling',
    'target_oracle_opening_coupling',
    'adaptive_selective_private_guess_bound',
    'target_byte_candidates_projection',
    'target_byte_candidates_lossless',
    'byte_selective_private_guess_bound',
    'adaptive_selective_private_guess_at_state',
    'opened_candidate_is_rejected',
    'consume_byte_selective_private_bound',

    'fors_digest_coordinate_injective',
    'unreturned_value_not_logged',
    'client_query_client_accounting',
    'byte_query_exposure_game_projection',
    'client_game_candidate_bound',
    'leaf_fors_sign_projection',
    'blocked_client_query_not_recorded',
    'consume_byte_query_budget',

    'private_value_known_elsewhere',
    'joint_memo_context_records',
    'private_alias_at_state',
    'full_context_joint_cost',
    'byte_private_node_alias',
    'message_partition_without_alias',
    'byte_private_alias_hop',
    'unaliased_opening_is_possible',
    'consume_byte_private_alias_hop',

    'byte_exposure_width',
    'fors_root_witness_unique',
    'logged_fors_private_value',
    'private_opening_coverage_partition',
    'logged_component_messages',
    'new_message_forest_partition',
    'byte_exposure_partition',
    'byte_exposure_partition_hop',

    'exposure_sign_records',
    'byte_exposure_probability',
    'full_sign_exposure_history',
    'exposure_client_supported',
    'exposure_client_accounting',
    'exposure_driver_history',
    'logged_digest_references',
    'byte_exposure_count',
    'byte_exposure_forgery_accounted',

    'raw_forest_recovery_recorded',
    'fors_root_reference_at',
    'recorded_fors_extracts',
    'recorded_forest_extracts',
    'raw_forest_sign_root',
    'verifier_records_forest',
    'full_sign_forest_entry',
    'full_client_forest_preserved',
    'recorded_verifier_forest_cases',
    'byte_game_forest_extraction',
    'byte_forest_opening_hop',

    'recorded_layer_extracts',
    'verifier_records_layers',
    'full_sign_subtree_entry',
    'recorded_verifier_subtree_cases',
    'byte_game_subtree_extraction',
    'byte_subtree_opening_hop',

    'root_reference_at',
    'full_client_root_preserved',
    'verifier_extracts_top_opening',
    'byte_game_top_extraction',
    'byte_top_opening_hop',

    'raw_chain_start_unique',
    'matching_wots_endpoints',
    'raw_recovery_recorded',
    'raw_wots_extracts_opening',
    'total_actual_wots_key_extraction',
    'raw_layer_extracts_wots_opening',
    'total_actual_layer_builder_extraction',
    'raw_wots_recovers_verifier_opening',

    'independent_honest_byte_error_zero',
    'honest_byte_public_cost',
    'physical_honest_byte_error_concrete',
    'node_draw_distribution',
    'projected_birthday',
    'public_node_birthday',
    'path_pair_collision_is_public',
    'fors_leaf_collision_is_public',
    'public_node_birthday_at_state',
    'byte_public_collision_hop',
    'public_node_zero_at_state',
    'byte_public_node_bad_hop',
    'invalid_sum_matches_only_zero',

    'total_actual_wots_correct',
    'total_raw_leaf_recorded',
    'raw_shuffle_permutation',
    'raw_wots_recovers_reference',
    'raw_wots_invalid_sum_sentinel',
    'total_actual_forest_correct',
    'forest_sign_recorded',
    'forest_recover_witness',
    'total_actual_layer_correct',
    'total_keygen_root_recorded',
    'total_merkle_build_wots_path',
    'total_layer_sign_matches_builder',
    'total_actual_signer_correct',
    'raw_signer_complete_opening',
    'raw_verify_opening',
    'raw_finish_recorded',
    'total_actual_byte_signer_correct',
    'signature_encoding_roundtrip',
    'actual_signed_encoding',
    'raw_signer_bytes',

    'merkle_build_root_projection',
    'total_merkle_build_reference',
    'total_fors_tree_reference',
    'total_fors_tree_secret_path',
    'total_actual_fors_builder_comparison',
    'total_actual_merkle_builder_comparison',
    'total_fors_tree_private_path',
    'fors_sign_recover_projection',
    'total_fors_observed_sign_correct',
    'total_fors_sign_recorded',

    'merkle_recover_leaf_or_collision',
    'fors_recover_secret_or_collision',
    'merkle_recover_recorded',
    'fors_recover_recorded',

    'session_novel_digest_bound',
    'byte_game_classified',
    'byte_game_history',
    'signer_repeated_digest',

    'byte_coordinate_replay_hop',
    'role_grind_joint_coverage',
    'signature_digest_bound',
    'role_grind_ht_bound',

    'full_win_has_no_failure',
    'raw_session_exhaustion_explicit',
    'raw_session_total_cost',
    'byte_physical_to_independent',
    'physical_signature_bytes',
    'full_physical_game_cost',
    'full_physical_to_independent',
    'signature_bytes_roundtrip',

    'bounded_hypertree_accepted',
    'EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED',
    'EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED_TIGHT',
    'EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED_TIGHT_AT_DEPLOYED_PARAMS',
    # Added 2026-08-27 with the variant itself.  A headline result that is NOT in this
    # list is NOT checked for taint -- adding a capstone without adding it here is a
    # silent coverage hole, so the two edits belong in the same commit.
    'EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED_TIGHT_AT_PINNED_ENCODER',
    'EUFCMA_SPHINCS_PLUS_C10_GROUNDED',
    'EUFCMA_SPHINCS_PLUS_C10_QWIRED',
    'gproc_Q_bound',
    # Added 2026-09-14.  WOTSNAMED (GprocWotsNamed.ec, 2026-09-01) was landed WITHOUT this
    # edit -- exactly the silent coverage hole the note above warns about; it went 13 days
    # unchecked for taint.  TCOLLNAMED (GprocTCollNamed.ec) is added with the variant itself.
    'EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED_TIGHT_AT_DEPLOYED_PARAMS_WOTSNAMED',
    'EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED_TIGHT_AT_DEPLOYED_PARAMS_TCOLLNAMED',
]

def strip_comments(s):
    out=[]; d=0; i=0; n=len(s)
    while i < n:
        if s.startswith('(*', i): d+=1; i+=2; continue
        if s.startswith('*)', i) and d>0: d-=1; i+=2; continue
        if d==0: out.append(s[i])
        elif s[i]=='\n': out.append('\n')
        i+=1
    return ''.join(out)

DECL = re.compile(r'^\s*(?:local\s+)?(?:lemma|theorem|equiv|hoare|ehoare|phoare)\s+([A-Za-z0-9_\']+)', re.M)
OPDECL = re.compile(r'^\s*(?:local\s+)?(?:op|abbrev|pred)\s+([A-Za-z0-9_\']+)', re.M)

def cone_files():
    fs=[l.strip() for l in open(CONE_MANIFEST) if l.strip() and not l.startswith('#')]
    if not fs: sys.exit('FAIL cone manifest empty -- would be vacuous')
    return fs

def parse():
    """-> {(file,name): (file, decl_line, body)} and the set of admitted (file,name) keys.

    KEYED BY (FILE, NAME), not by bare name (fixed 2026-08-27, GPT-5.6 adversarial review).
    54 lemma basenames are declared in MORE THAN ONE cone file; a bare-name dict silently
    kept only the LAST, so a taint edge into a shadowed lemma could be lost entirely."""
    lemmas={}; admitted=set(); opdecls={}
    for f in cone_files():
        if not os.path.exists(f): sys.exit(f'FAIL cone file missing: {f}')
        src=strip_comments(open(f).read())
        lines=src.split('\n')
        cur=None; start=None; buf=[]
        for i,l in enumerate(lines,1):
            om=OPDECL.match(l)
            if om: opdecls.setdefault((f, om.group(1)), i)
            m=DECL.match(l)
            if m:
                cur=m.group(1); start=i; buf=[]
                # SAME-LINE `qed.` (fixed 2026-08-27, found by GPT-5.6 adversarial review).
                # This used to `continue` unconditionally, so a one-line
                # `lemma f : X. proof. .... qed.` was NEVER REGISTERED -- and worse, `cur`
                # stayed set and swallowed the following text into that lemma's body until
                # some LATER qed.  12 such declarations exist in the cone.  A one-line lemma
                # applying an admitted result would have been INVISIBLE to the closure.
                if re.search(r'(?:^|[^A-Za-z0-9_\'])qed\.', l):
                    body=l
                    lemmas[(f,cur)]=(f, start, body)
                    if re.search(r'(?:^|[^A-Za-z0-9_\'])admit(?:ted)?\s*\.', body): admitted.add((f,cur))
                    cur=None; buf=[]
                continue
            if cur is not None:
                buf.append(l)
                # TERMINATOR MATCHED ANYWHERE ON THE LINE (fixed 2026-08-27, found by
                # Kimi K3 adversarial review).  This used to be `re.match(r'\s*qed\.')`,
                # i.e. LINE-INITIAL ONLY -- so a proof closed as `proof. by .... qed.`
                # never terminated, and the lemma's body silently swallowed everything up
                # to the next line-initial `qed.`.  314 of the cone's `qed.` lines are of
                # that shape (33% of 951 declarations), so bodies were routinely
                # mis-attributed and edges could be both invented and lost.
                if re.search(r'(?:^|[^A-Za-z0-9_\'])(?:qed|abort)\.', l):
                    body='\n'.join(buf)
                    lemmas[(f,cur)]=(f, start, body)
                    if re.search(r'(?:^|[^A-Za-z0-9_])admit(?:ted)?\s*\.', body): admitted.add((f,cur))
                    cur=None; buf=[]
    # PARSER-COVERAGE GUARD (added 2026-08-27, Kimi K3's recommendation).
    # Three separate parser bugs in this tool were each INVISIBLE because nothing compared
    # what the parser REGISTERED against what is actually declared: one-line proofs (12),
    # bare-basename overwrites (54 duplicated names), and a line-initial-only terminator
    # (314 of 951 `qed.` lines).  Every one silently SHRANK the closure, which is the
    # unsafe direction for an exclusion claim.  So: count declarations independently and
    # require the parser to have registered essentially all of them.
    raw = 0
    for f in cone_files():
        for l in strip_comments(open(f).read()).split('\n'):
            if DECL.match(l): raw += 1
    if raw == 0:
        sys.exit('FAIL anti-vacuity: zero declarations scanned -- the parser is broken')
    missed = raw - len(lemmas)
    if missed > MAX_UNREGISTERED:
        sys.exit(f'FAIL parser coverage: {raw} declarations scanned but only {len(lemmas)} '
                 f'registered ({missed} unregistered, budget {MAX_UNREGISTERED}). '
                 f'An unregistered lemma is INVISIBLE to the closure, which is the unsafe '
                 f'direction for an exclusion claim.')
    # CLONE-ROUTE GUARD (added 2026-08-28).  PHASE 5's SECOND named hole is "reachability
    # through a clone instantiation rather than a named application".  MEASURED: it is NOT
    # LIVE in this tree -- of 80 clone statements across the 45 cone files, ZERO name an
    # admit-containing theory, and both admits sit at FILE TOP LEVEL (not inside any
    # cloneable sub-theory), so cloning the whole file is the only route and nobody does it.
    # This guard keeps it that way.  It derives the forbidden names from the COMPUTED
    # admits, so it tracks the tree rather than a hardcoded list.
    admit_theories = {os.path.splitext(os.path.basename(f))[0] for (f, _n) in admitted}
    clone_stmts = 0
    offenders = []
    CLONE = re.compile(r'\bclone\b[^.]{0,400}?\.', re.S)
    for f in cone_files():
        src = strip_comments(open(f).read())
        for m in CLONE.finditer(src):
            clone_stmts += 1
            blob = m.group(0)
            for t in admit_theories:
                if re.search(r'(?:^|[^A-Za-z0-9_])' + re.escape(t) + r'(?![A-Za-z0-9_])', blob):
                    offenders.append(f'{f}:{src[:m.start()].count(chr(10))+1} clones {t}')
    # ANTI-VACUITY: a scanner that finds no clones at all would pass this guard trivially.
    if clone_stmts < MIN_CLONE_STMTS:
        sys.exit(f'FAIL clone-route guard is vacuous: only {clone_stmts} clone statements '
                 f'scanned (expected >= {MIN_CLONE_STMTS}) -- the scanner is broken')
    if offenders:
        sys.exit('FAIL clone route into an admit-containing theory is now LIVE:\n  ' +
                 '\n  '.join(offenders) +
                 '\n  PHASE 5 is a NAME-level check and cannot follow taint through a clone.')
    return lemmas, admitted, opdecls

def mentions(body, name):
    return re.search(r'(?:^|[^A-Za-z0-9_\'])'+re.escape(name)+r'(?![A-Za-z0-9_\'])', body) is not None

def closure():
    lemmas, admitted, opdecls = parse()
    if len(admitted) != EXPECT_SEEDS:
        sys.exit(f'FAIL anti-vacuity: found {len(admitted)} admitted lemmas, expected {EXPECT_SEEDS} '
                 f'-- the parser or the tree changed: {sorted(admitted)}')
    # HEADLINE is matched on the NAME half of the key; a headline name that is itself
    # duplicated across cone files is refused rather than silently resolved.
    hkeys={}
    for h in HEADLINE:
        ks=[k for k in lemmas if k[1]==h]
        if not ks:
            sys.exit(f'FAIL anti-vacuity: headline name {h} not found as a declaration -- '
                     f'the exclusion check would be vacuous')
        if len(ks)>1:
            sys.exit(f'FAIL headline name {h} is declared in {len(ks)} cone files {sorted(x[0] for x in ks)} '
                     f'-- ambiguous, refusing to guess which one the exclusion is about')
        hkeys[h]=ks[0]
    def edge(user, t):
        """Does `user` plausibly APPLY tainted lemma `t`?  -> None | 'sure' | 'ambig'"""
        uf, uln, ubody = lemmas[user]
        tf, tln, _tb  = lemmas[t]
        tname = t[1]
        if not mentions(ubody, tname): return None
        # POSITIONAL RULE (sound): no forward lemma references within a file.
        if uf == tf and uln < tln: return None
        # An `op` of the same name also in scope makes the edge undecidable by name.
        if (tf, tname) in opdecls and opdecls[(tf, tname)] < uln: return 'ambig'
        return 'sure'

    tainted = {a: 'ADMIT' for a in admitted}
    changed = True
    while changed:
        changed = False
        for nm in lemmas:
            if nm in tainted: continue
            for t in list(tainted):
                e = edge(nm, t)
                if e:
                    tainted[nm] = e; changed = True; break
    return lemmas, admitted, tainted

def scope_linkage(lemmas, admitted):
    """SCOPE-PROBE LINKAGE (added 2026-09-15).  The PHASE 3 scope controls prove, per headline file,
    that the admit's theory is UNKNOWN in that file's environment.  Nothing tied those rows to
    HEADLINE, so a new headline file got no probe and PHASE 5 said nothing.  That is the same class
    as WOTSNAMED going 13 days unregistered for taint.  Enforced here as an EXACT BIJECTION, not a
    subset: a probe left for a file that no longer declares a headline is refused too.
    Deliberately NOT checked, because PHASE 3 already makes it RED: a probe that references another
    symbol, or requires the admit theory itself, COMPILES -- and a MUST-FAIL that compiles fails."""
    probs = []
    hbases = {os.path.splitext(os.path.basename(k[0]))[0] for k in lemmas if k[1] in HEADLINE}
    theories = sorted({os.path.splitext(os.path.basename(f))[0] for (f, _n) in admitted})
    if not os.path.exists(CONTROLS_MANIFEST):
        return [f'{CONTROLS_MANIFEST} missing -- scope-probe linkage cannot be checked'], len(hbases), 0
    rows, scanned = {}, 0
    for l in open(CONTROLS_MANIFEST):
        l = l.rstrip('\n')
        if not l.strip() or l.startswith('#'): continue
        scanned += 1
        parts = l.split('\t')
        m = SCOPE_PROBE.match(parts[0])
        if m:
            if m.group(1) in rows: probs.append(f'scope probe for {m.group(1)} registered twice')
            rows[m.group(1)] = (parts[0], parts[1] if len(parts) > 1 else '', parts[2] if len(parts) > 2 else '')
    if scanned == 0:
        return [f'{CONTROLS_MANIFEST} has no rows -- scope-probe linkage would be vacuous'], len(hbases), 0
    if not rows:
        return ['scope-probe linkage is vacuous: no scratch/_scope_neg_op_<H>.ec rows matched in '
                f'{CONTROLS_MANIFEST} -- the row matcher is broken or the probes were removed'], len(hbases), 0
    for b in sorted(hbases - set(rows)):
        probs.append(f'headline file {b} has no scope probe '
                     f'(expected scratch/_scope_neg_op_{b}.ec as MUST-FAIL in {CONTROLS_MANIFEST})')
    for b in sorted(set(rows) - hbases):
        probs.append(f'scope probe {rows[b][0]} is registered for {b}, which declares no HEADLINE result')
    for b in sorted(set(rows) & hbases):
        path, kind, reason = rows[b]
        if kind != 'MUST-FAIL':
            probs.append(f'scope probe {path} is {kind!r}, not MUST-FAIL')
        for t in theories:
            if f'{t}.' not in reason:
                probs.append(f'scope probe {path}: declared reason does not name admit theory {t}')
        if not os.path.exists(path):
            probs.append(f'scope probe file missing: {path}'); continue
        src = strip_comments(open(path).read())
        reqs = set()
        for rm in re.finditer(r"(?<![A-Za-z0-9_'])require\s+([^.]*)\.", src, re.S):
            body = rm.group(1).replace('import', ' ').replace('export', ' ')
            reqs.update(re.findall(r"[A-Za-z][A-Za-z0-9_']*", body))
        if b not in reqs:
            probs.append(f'scope probe {path} does not require its headline theory {b}')
    return probs, len(hbases), len(rows)

def main():
    lemmas, admitted, tainted = closure()
    rows=sorted((lemmas[k][0], lemmas[k][1], k[1], tainted[k]) for k in tainted)
    if '--check' not in sys.argv:
        for f,ln,n,tag in rows:
            print(f'{f}\t{ln}\t{n}\t{tag}')
        print(f'# closure size = {len(rows)}', file=sys.stderr)
        return 0
    # ---- check mode ----
    problems=[]
    if len(rows) < EXPECT_MIN_CLOSURE:
        problems.append(f'closure size {len(rows)} < EXPECT_MIN_CLOSURE {EXPECT_MIN_CLOSURE} -- suspiciously small')
    for k in tainted:
        if k[1] in HEADLINE:
            problems.append(f'HEADLINE IS TAINTED: {k[1]} ({k[0]}) transitively applies an admitted lemma')
    link_probs, n_hfiles, n_probes = scope_linkage(lemmas, admitted)
    problems += link_probs
    if not os.path.exists(MANIFEST):
        problems.append(f'{MANIFEST} missing -- the closure is unpinned')
    else:
        want=set(); wrows=0
        for l in open(MANIFEST):
            l=l.rstrip('\n')
            if not l.strip() or l.startswith('#'): continue
            wrows+=1
            parts=l.split('\t')
            if len(parts) < 3: problems.append(f'malformed manifest row: {l}'); continue
            want.add((parts[0], int(parts[1]), parts[2], parts[3] if len(parts)>3 else 'taint'))
        if wrows == 0:
            problems.append('manifest has no rows -- would be vacuous')
        got=set(rows)
        # EVERY manifest site must RESOLVE: file exists, line in range, symbol on that line.
        for f,ln,n,_t in sorted(want):
            if not os.path.exists(f): problems.append(f'manifest site file missing: {f}'); continue
            src=strip_comments(open(f).read()).split('\n')
            if not (1 <= ln <= len(src)): problems.append(f'manifest site out of range: {f}:{ln}'); continue
            if not mentions(src[ln-1], n):
                problems.append(f'manifest site does not resolve: {f}:{ln} does not name {n}')
        got4 = set((f,ln,n,t) for f,ln,n,t in rows)
        want4 = want
        for extra in sorted(got4-want4): problems.append(f'TAINT CLOSURE GREW: {extra[0]}:{extra[1]} {extra[2]} [{extra[3]}]')
        for gone in sorted(want4-got4): problems.append(f'taint closure SHRANK: {gone[0]}:{gone[1]} {gone[2]} [{gone[3]}]')
    if problems:
        for p in problems: print(f'FAIL taint: {p}')
        return 1
    print(f'OK   taint containment: closure = {len(rows)} lemmas, none of the {len(HEADLINE)} '
          f'headline results is in it (name-level, NOT a soundness proof -- see the tool header)')
    print(f'OK   scope-probe linkage: {n_hfiles} headline files <-> {n_probes} registered scope probes '
          f'(exact bijection)')
    return 0

if __name__ == '__main__':
    sys.exit(main())
