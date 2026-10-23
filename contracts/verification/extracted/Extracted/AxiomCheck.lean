import Extracted.C10FunctionalForest
import Extracted.C10FunctionalForestRecover
import Extracted.C10FunctionalLayer
import Extracted.C10FunctionalBuilders
import Extracted.C10FunctionalTrees
import Extracted.C10FunctionalWotsRecover
import Extracted.C10FunctionalSearch
import Extracted.C10ShuffleBridge
import Extracted.C10AddressInputBridge
import Extracted.C10HashInputBridge
import Extracted.C10RepresentationBridge
import Extracted.SecureWrapperBridge
import Extracted.SecureWrapperCleanup
import Extracted.SecureWrapperRefusal
import Extracted.SecureWrapperCost
import Extracted.SignReleaseBridge
import Extracted.SignWholeSpec
import Extracted.SignHeaderDiffVectors
import Extracted.SignHypertreeCaller
import Extracted.SignHypertreeDiffVectors
import Extracted.SignForestSerializeCaller
import Extracted.SignLayerSerializeCaller
import Extracted.SignSerializationDiffVectors
import Extracted.SignForestPrefix
import Extracted.WotsSignBridge
import Extracted.XmssRootBridge
import Extracted.XmssAuthRecovery
import Extracted.ForsRoundtripSpec
import Extracted.ForsAuthBridge
import Extracted.ForsRootBridge
import Extracted.ForsSecretBridge
import Extracted.WotsKeygenBridge
import Extracted.WholeVerifierSpec
import Extracted.HypertreeStrictSpec
import Extracted.ForsVerifierPrefix
import Extracted.ForsRejectSpec
/- Axiom-discipline check (extends the SphincsCVerify no-sorry/axiom-lint
   culture to the extracted-code project; CI wiring tracked in §33 P1).

   Both P0 theorems close over EXACTLY the Lean kernel built-ins
   [propext, Classical.choice, Quot.sound] — verified 2026-06-10.
   In particular NO `sorryAx`: the sorries inside the Aeneas support
   library (Aeneas/Std/Slice.lean etc.) are not on our proof paths. -/
import Extracted.HMsgSpecBridge
import Extracted.WotsSpecBridge
import Extracted.WotsRecoveryBridge
import Extracted.MerkleRecoveryBridge
import Extracted.ForsRecoveryBridge
import Extracted.FindCountSpec
import Extracted.GrindRSpec
import Extracted.AdrsEquiv
import Extracted.Bits
import Extracted.ForsExtract
import Extracted.ForsSpecBridge
import Extracted.Eip1271Equiv
import Extracted.WotsDigits
import Extracted.FwManifestSpec
import Extracted.Bip39RoundtripSpec
import Extracted.RlpIntSpec
import Extracted.U256MulSpec
import Extracted.MerkleVerifySpec
import Extracted.TxMerkleSpec
import Extracted.DecodeItemSpec
import Extracted.PkFromSigSpec
import Extracted.Sha256Pure
import Extracted.HashSpecs
import Extracted.UserOpEquiv
import Extracted.UserOpEquivByteLayout
import Extracted.SpecBridge
import Extracted.ForsLoop
import Extracted.PinState.PinStateSpec
import Extracted.SlotKdf.SlotKdfSpec
import Extracted.FormatDecimal.Div10Spec
import Extracted.FormatDecimal.ExtractDigitsSpec
import Extracted.FormatDecimal.RoundCarrySpec
import Extracted.FormatDecimal.TrimFracSpec
-- FormatDecimalSpec CARVED OUT (its M7 #print-axioms moved to
-- Extracted/AxiomCheckFormatDecimal.lean) — see the M7 note below.
import Extracted.FormatDecimal.EmitSpec
-- Rust-generated differential vectors (data only, no theorems; enrolled so the
-- axiom gate elaborates them — the replay lives in Extracted/ExtractDiffCheck.lean)
import Extracted.ExtractDiffVectors
import Extracted.FormatDecimalDiffVectors

-- XMSS authentication-path construction and actual-helper membership composition.
#print axioms Extracted.Equiv.xmss_auth_leaf_schedule
#print axioms Extracted.Equiv.xmss_build_auth_spec
#print axioms Extracted.Equiv.xmss_auth_path_matches_vendored
#print axioms Extracted.Equiv.firmware_xmss_auth_matches_vendored
#print axioms Extracted.Equiv.xmss_auth_recovery_root
#print axioms Extracted.Equiv.firmware_xmss_build_recover_root
#print axioms Extracted.Equiv.firmware_xmss_build_recover_matches_vendored

-- FV-#2 sequel: slot_entropy byte-layout (invariant #8). Closure = kernel triple
-- + the disclosed `sha256_pure_bytes` hash axiom (the FV-#2 single-shot SHA-256
-- boundary), same category as `sha256_pure` / `keccak256_pure`.
#print axioms Extracted.Equiv.slot_entropy_hashes_canonical_preimage
#print axioms Extracted.Equiv.derive_c10_slot_seeds_byte_layout
#print axioms Extracted.Equiv.slot_master_byte_layout
#print axioms Extracted.Equiv.derive_c10_master_byte_layout
-- §1 deepening: derivation injectivity (PURE — kernel-only closure) + the
-- key-collision ⇒ hash-collision reduction (adds only sha256_pure_bytes).
#print axioms Extracted.Equiv.slotEntropyPreimage_chain_inj
#print axioms Extracted.Equiv.slotEntropyPreimage_slot_inj
#print axioms Extracted.Equiv.slot_entropy_crosschain_reduction
-- format_decimal Track-1 milestone 0: div10 floor-division ∀ 2^256 values
-- (the symbolic-VALUE the CBMC bit-blaster could not converge on). PURE —
-- kernel-only closure [propext, Classical.choice, Quot.sound], no hash axiom.
#print axioms Div10Spec.div10_inplace_spec
-- format_decimal Track-1 milestone M4: fmt_extract_digits full functional
-- spec ∀ 2^256 values × ∀ digit buffers (value/count/digit-range/
-- normalization/frame — see the ExtractDigitsSpec.lean header). PURE —
-- kernel-only closure, no hash axiom, no bv_decide native axiom.
#print axioms ExtractDigitsSpec.extract_digits_spec
#print axioms ExtractDigitsSpec.extract_digits_loop_spec
#print axioms ExtractDigitsSpec.is_zero_spec
-- format_decimal Track-1 milestone M5: fmt_round_half_up full functional
-- spec (value-exact +1 ulp carry propagation, prefix frame, digit-range,
-- count growth, no-round identity — see the RoundCarrySpec.lean header).
-- PURE — kernel-only closure, no hash axiom, no bv_decide native axiom.
#print axioms RoundCarrySpec.round_carry_spec
#print axioms RoundCarrySpec.round_carry_loop_spec
#print axioms RoundCarrySpec.decValue_set
-- format_decimal Track-1 milestone M6: fmt_trim_frac — returns the largest
-- fractional position ≤ frac whose DISPLAYED digit is nonzero (0 if none);
-- every trimmed position displays a structural zero (see the
-- TrimFracSpec.lean header). PURE — kernel-only closure.
#print axioms TrimFracSpec.trim_frac_spec
#print axioms TrimFracSpec.trim_frac_loop_spec
-- format_decimal Track-1 M7 — THE END-TO-END WYSIWYS COMPOSITION — is
-- axiom-gated in Extracted/AxiomCheckFormatDecimal.lean instead, because
-- kernel-typechecking `format_decimal_spec` peaks at ~42 GB RSS (single-decl
-- WP-monad composition; measured 2026-07-07) and is carved out of this default
-- 16 GB-runner gate. Run `make verify-extracted-heavy` to check its closure.
-- format_decimal Track-1 milestone M6b: fmt_emit — renders exactly
-- emitBytes (int part ++ optional '.' ++ guarded frac digits) touching ONLY
-- out[0, need); the None path returns with out LITERALLY unchanged (see the
-- EmitSpec.lean header). Plus the M7-facing emitBytes well-formedness
-- corollaries (length/ASCII alphabet/single-dot/leading-zero). PURE —
-- kernel-only closure, no hash axiom, no bv_decide native axiom.
#print axioms EmitSpec.emit_spec
#print axioms EmitSpec.emit_int_loop_spec
#print axioms EmitSpec.emit_frac_loop_spec
#print axioms EmitSpec.fmt_emit_loop0_eq_loop2
#print axioms EmitSpec.emitBytes_length
#print axioms EmitSpec.emitBytes_ascii
#print axioms EmitSpec.emitBytes_dot_iff
#print axioms EmitSpec.emitBytes_head_digit
#print axioms EmitSpec.emitBytes_no_leading_zero
#print axioms Extracted.Equiv.deserialize_pin_state_rejects_bad_len
#print axioms Extracted.Equiv.make_adrs_spec
#print axioms Extracted.Equiv.set_chain_index_spec
#print axioms Extracted.Equiv.compute_user_op_hash_terminates
#print axioms Extracted.Equiv.compute_user_op_hash_spec
#print axioms Extracted.Equiv.firmware_make_adrs_matches_vendored
#print axioms Extracted.Equiv.next_usize_spec
#print axioms Extracted.Equiv.read_bits_le_loop_terminates
#print axioms Extracted.Equiv.extract_ht_index_terminates
#print axioms Extracted.Equiv.extract_fors_indices_terminates
#print axioms Extracted.Equiv.extract_ht_index_in_range
#print axioms Extracted.Equiv.extract_fors_indices_in_range
#print axioms Extracted.Equiv.lor_eq_add_disjoint
#print axioms Extracted.Equiv.read_bits_le_spec
#print axioms Extracted.Equiv.extract_ht_index_spec
#print axioms Extracted.Equiv.extract_fors_indices_spec
#print axioms Extracted.Equiv.domain_separator_spec
#print axioms Extracted.Equiv.replay_safe_hash_spec
#print axioms Extracted.Equiv.extract_digits_spec
#print axioms Extracted.Equiv.extract_digits_lt
#print axioms Extracted.Equiv.signed_preimage_spec
-- FW-update supply-chain integrity (domain-tag cross-protocol separation +
-- authorizes-exactly-one-firmware) over the frozen 75-B PQFW_V1 preimage.
#print axioms Extracted.Equiv.preimage_layout_injective
#print axioms Extracted.Equiv.layout_domain_tag_prefix
#print axioms Extracted.Equiv.signed_preimage_authorizes_one_firmware
#print axioms Extracted.Equiv.roundtrip_11_id
#print axioms Extracted.Equiv.beValue_lt
#print axioms Extracted.Equiv.bytes_to_u64_spec
#print axioms Extracted.Equiv.bytes_to_u256_spec
#print axioms Extracted.Equiv.saturating_mul_u64_spec
#print axioms Extracted.Equiv.verify_auth_path_spec
#print axioms Extracted.Equiv.verify_proof_spec
#print axioms Extracted.Equiv.decode_length_be_spec
#print axioms Extracted.Equiv.decode_item_spec
#print axioms Extracted.Equiv.pk_from_sig_spec
#print axioms sha256_pure
#print axioms sphincs_c10.hash.truncate_spec
#print axioms sphincs_c10.hash.th_spec
#print axioms sphincs_c10.hash.th_pair_spec
#print axioms sphincs_c10.hash.wots_digest_spec
#print axioms sphincs_c10.hash.th_multi_spec
#print axioms sphincs_c10.hash.chain_hash_spec

-- Digest-field version bridge: kernel-only, no hash or translation axioms.
#print axioms Extracted.Equiv.toSpecDigest_get
#print axioms Extracted.Equiv.vendored_readBitsLe_eq_digestWord
#print axioms Extracted.Equiv.firmware_extract_ht_index_matches_vendored
#print axioms Extracted.Equiv.firmware_extract_fors_indices_matches_vendored

#print axioms sphincs_c10.hash.h_msg_spec
#print axioms Extracted.Equiv.firmware_h_msg_matches_vendored

#print axioms Extracted.Equiv.firmware_wots_digest_matches_vendored
#print axioms Extracted.Equiv.firmware_extract_digits_matches_vendored
#print axioms Extracted.Equiv.firmware_wots_digit_array_matches_vendored
#print axioms Extracted.Equiv.firmware_wots_digit_sum_matches_vendored

#print axioms Extracted.Equiv.find_count_first_success
#print axioms Extracted.Equiv.find_count_exhausted
#print axioms Extracted.Equiv.find_count_total

#print axioms Extracted.Equiv.grind_r_first_success
#print axioms Extracted.Equiv.grind_r_exhausted
#print axioms Extracted.Equiv.grind_r_total

-- Complete WOTS recovery value and outcome bridge.
#print axioms Extracted.Equiv.firmware_chain_hash_matches_vendored
#print axioms Extracted.Equiv.firmware_th_multi_matches_vendored
#print axioms Extracted.Equiv.firmware_pk_from_sig_matches_vendored
#print axioms Extracted.Equiv.vendored_wots_recovery_outcome

-- XMSS pair hash and complete nine-level recovery.
#print axioms Extracted.Equiv.firmware_th_pair_matches_vendored
#print axioms Extracted.Equiv.firmware_verify_auth_path_matches_vendored

-- FORS secret leaf and complete eleven-level recovery.
#print axioms Extracted.Equiv.fors_recovery_spec
#print axioms Extracted.Equiv.firmware_fors_recovery_matches_vendored

-- Forest-stage correspondences and whole-verifier forced-zero refusal.
#print axioms Extracted.Equiv.fors_pk_spec
#print axioms Extracted.Equiv.firmware_fors_pk_matches_vendored
#print axioms Extracted.Equiv.firmware_fors_normal_roots
#print axioms Extracted.Equiv.firmware_verify_rejects_nonzero_fors

-- Complete FORS prefix through the unchanged WOTS/XMSS continuation.
#print axioms Extracted.Equiv.firmware_parse_fors_secrets_value
#print axioms Extracted.Equiv.firmware_parse_fors_auth_value
#print axioms Extracted.Equiv.forsForestPhase_matches_vendored
#print axioms Extracted.Equiv.firmware_verify_fors_prefix

-- Exact layer parsing and two-layer continuation, with a conditional strict bridge.
#print axioms Extracted.Equiv.firmware_parse_layer_wots_value
#print axioms Extracted.Equiv.firmware_parse_layer_xmss_value
#print axioms Extracted.Equiv.parsedLayerCount_val
#print axioms Extracted.Equiv.firmware_verify_layer_body
#print axioms Extracted.Equiv.firmware_verify_hypertree_loop
#print axioms Extracted.Equiv.firmware_verifier_hypertree_continuation
#print axioms Extracted.Equiv.strict_hypertree_success_eq_raw
#print axioms Extracted.Equiv.firmware_continuation_matches_strict_success

-- Complete signature bytes and whole verifier; strict acceptance is one-way.
#print axioms Extracted.Equiv.loadValue16_signatureNode
#print axioms Extracted.Equiv.loadU32BE_parsed_count
#print axioms Extracted.Equiv.deserialise_matches_parsedSignature
#print axioms Extracted.Equiv.firmware_verify_raw_result
#print axioms Extracted.Equiv.byteVerifier_eq_strictResult
#print axioms Extracted.Equiv.firmware_verify_accepts_strict_signature
#print axioms Extracted.Equiv.firmware_verify_matches_strict_success
#print axioms Extracted.Equiv.firmware_verify_strict_forced_refusal

-- Actual WOTS secret and complete public-key generation.
#print axioms Extracted.Equiv.wotsSecretPreimage_length
#print axioms Extracted.Equiv.wots_secret_spec
#print axioms Extracted.Equiv.firmware_wots_secret_matches_vendored
#print axioms Extracted.Equiv.wots_keygen_loop_spec
#print axioms Extracted.Equiv.wots_keygen_pk_spec
#print axioms Extracted.Equiv.firmware_wots_keygen_matches_vendored

-- FORS secret generation, including hypertree-position binding.
#print axioms Extracted.Equiv.forsSecretPreimage_length
#print axioms Extracted.Equiv.fors_secret_spec
#print axioms Extracted.Equiv.firmware_fors_secret_matches_vendored

-- FORS tree construction and final signature slot.
#print axioms Extracted.Equiv.fors_root_schedule
#print axioms Extracted.Equiv.fors_compute_root_spec
#print axioms Extracted.Equiv.fors_root_node_matches_vendored
#print axioms Extracted.Equiv.firmware_fors_root_matches_vendored
#print axioms Extracted.Equiv.firmware_fors_final_slot_matches_vendored

#print axioms Extracted.Equiv.fors_auth_leaf_schedule
#print axioms Extracted.Equiv.fors_auth_carry_schedule
#print axioms Extracted.Equiv.fors_sign_tree_spec
#print axioms Extracted.Equiv.fors_auth_path_matches_vendored
#print axioms Extracted.Equiv.firmware_fors_auth_matches_vendored

-- Actual FORS signing/recovery composition
#print axioms Extracted.Equiv.fors_auth_recovery_root
#print axioms Extracted.Equiv.firmware_fors_sign_recover_root
#print axioms Extracted.Equiv.firmware_fors_sign_recover_matches_vendored

-- Actual XMSS key-generation trees and top-level public root.
#print axioms Extracted.Equiv.xmss_root_schedule
#print axioms Extracted.Equiv.xmss_compute_root_spec
#print axioms Extracted.Equiv.xmss_compute_pk_root_spec
#print axioms Extracted.Equiv.xmss_root_node_matches_vendored
#print axioms Extracted.Equiv.firmware_xmss_root_matches_vendored
#print axioms Extracted.Equiv.firmware_pk_root_matches_vendored

-- Actual shuffled WOTS construction and recovery: kernel-only, no backend/freshness claim.
#print axioms Extracted.Equiv.shuffle_permutation_spec
#print axioms Extracted.Equiv.wots_sign_first_success
#print axioms Extracted.Equiv.wots_sign_exhausted
#print axioms Extracted.Equiv.wots_sign_total
#print axioms Extracted.Equiv.wots_sign_shuffle_independent
#print axioms Extracted.Equiv.firmware_wots_sign_recovers_keygen
#print axioms Extracted.Equiv.firmware_wots_sign_matches_vendored

-- Actual shuffled FORS signing forest and unconditional caller prefix.
#print axioms Extracted.Equiv.firmware_sign_fors_normal_loop
#print axioms Extracted.Equiv.signer_fors_phase_spec
#print axioms Extracted.Equiv.firmware_sign_fors_recovers_pk
#print axioms Extracted.Equiv.firmware_sign_fors_shuffle_independent
#print axioms Extracted.Equiv.firmware_sign_fors_matches_vendored
#print axioms Extracted.Equiv.firmware_sign_fors_prefix

-- Actual signer serialization, complete byte frame and decoded fields.
#print axioms Extracted.Equiv.firmware_write16
#print axioms Extracted.Equiv.firmware_write_fors_secrets
#print axioms Extracted.Equiv.firmware_write_fors_auth
#print axioms Extracted.Equiv.firmware_write_wots_chains
#print axioms Extracted.Equiv.firmware_write_xmss_path
#print axioms Extracted.Equiv.firmware_write_count
#print axioms Extracted.Equiv.firmware_serialize_forest
#print axioms Extracted.Equiv.serializedForest_fields
#print axioms Extracted.Equiv.firmware_signer_forest_serialization
#print axioms Extracted.Equiv.firmware_serialize_layer
#print axioms Extracted.Equiv.serializedLayer_fields
#print axioms Extracted.Equiv.signer_layer_serialization_factor
#print axioms Extracted.Equiv.firmware_serialize_layer_at_params

-- Actual two-layer signer and post-FORS caller, preserving bounded failure.
#print axioms Extracted.Equiv.firmware_wots_sign_pure
#print axioms Extracted.Equiv.firmware_xmss_signing_path
#print axioms Extracted.Equiv.firmware_sign_layer_body
#print axioms Extracted.Equiv.firmware_sign_hypertree_loop
#print axioms Extracted.Equiv.firmware_sign_hypertree_success
#print axioms Extracted.Equiv.firmware_sign_hypertree_top_root
#print axioms Extracted.Equiv.firmware_signer_hypertree_suffix
#print axioms Extracted.Equiv.firmware_signer_after_forest_pure
#print axioms Extracted.Equiv.signer_root_check_match

-- Actual nonce/header and complete functional signer composition.
#print axioms Extracted.Equiv.firmware_grind_r_pure
#print axioms Extracted.Equiv.pure_grind_r_success
#print axioms Extracted.Equiv.firmware_sign_header_pure
#print axioms Extracted.Equiv.firmware_sign_header_tail
#print axioms Extracted.Equiv.header_indices_bound
#print axioms Extracted.Equiv.grind_header_forced_zero
#print axioms Extracted.Equiv.serialized_nonce_decodes
#print axioms Extracted.Equiv.firmware_sign_whole_pure
#print axioms Extracted.Equiv.firmware_sign_whole_shuffle_independent
#print axioms Extracted.Equiv.firmware_sign_nonce_exhausted
#print axioms Extracted.Equiv.signer_root_check_success
#print axioms Extracted.Equiv.firmware_sign_whole_success

-- Release-assertion caller: shared backend/helper models remain explicit.
#print axioms Extracted.Equiv.release_layer_body_projection
#print axioms Extracted.Equiv.firmware_release_sign_loop_step
#print axioms Extracted.Equiv.firmware_release_sign_loop_done
#print axioms Extracted.Equiv.firmware_release_sign_hypertree_loop
#print axioms Extracted.Equiv.release_caller_factor
#print axioms Extracted.Equiv.release_after_forest_pure
#print axioms Extracted.Equiv.firmware_sign_release_pure
#print axioms Extracted.Equiv.whole_sign_nodes_root
#print axioms Extracted.Equiv.checked_whole_nodes_factor
#print axioms Extracted.Equiv.firmware_sign_checked_release_relation
#print axioms Extracted.Equiv.firmware_sign_release_valid_key
#print axioms Extracted.Equiv.firmware_keygen_sign_release
#print axioms Extracted.Equiv.firmware_sign_release_shuffle_independent
#print axioms Extracted.Equiv.firmware_sign_release_nonce_exhausted

-- Sequential source-lifted wrapper; environmental and translation boundaries remain explicit.
#print axioms secure_wrapper_model.wrapper_success_certificate
#print axioms secure_wrapper_model.wrapper_entry_success_certificate
#print axioms secure_wrapper_model.wrapper_entry_success_verified
#print axioms secure_wrapper_model.wrapper_rate_refusal
#print axioms secure_wrapper_model.wrapper_rate_readback_refusal
#print axioms secure_wrapper_model.wrapper_rate_sentinel_refusal
#print axioms secure_wrapper_model.wrapper_inner_cleanup
#print axioms secure_wrapper_model.wrapper_inner_refusal
#print axioms secure_wrapper_model.wrapper_firmware_release
#print axioms secure_wrapper_model.wrapper_success_requires_rate

-- Source-linked paired representation endpoints; kernel-only.
#print axioms Extracted.C10RepresentationBridge.digest_byte_word
#print axioms Extracted.C10RepresentationBridge.digest_word_window
#print axioms Extracted.C10RepresentationBridge.extracted_ht_word
#print axioms Extracted.C10RepresentationBridge.extracted_fors_words
#print axioms Extracted.C10RepresentationBridge.extracted_wots_words
#print axioms Extracted.C10RepresentationBridge.counter_word
#print axioms Extracted.C10RepresentationBridge.signature_words
#print axioms Extracted.C10RepresentationBridge.signature_byte_domain
#print axioms Extracted.C10RepresentationBridge.digest_byte_domain

-- Paired hash-preimage endpoints, independent of hash output equality.
#print axioms Extracted.C10HashInputBridge.u32_bytes_value
#print axioms Extracted.C10HashInputBridge.pad_node_value
#print axioms Extracted.C10HashInputBridge.hmsg_input_value
#print axioms Extracted.C10HashInputBridge.th_input_value
#print axioms Extracted.C10HashInputBridge.pair_input_value
#print axioms Extracted.C10HashInputBridge.multi_input_value
#print axioms Extracted.C10HashInputBridge.wots_input_value
#print axioms Extracted.C10HashInputBridge.r_input_value
#print axioms Extracted.C10HashInputBridge.extracted_hmsg_input
#print axioms Extracted.C10HashInputBridge.extracted_th_input
#print axioms Extracted.C10HashInputBridge.extracted_pair_input
#print axioms Extracted.C10HashInputBridge.extracted_multi_input
#print axioms Extracted.C10HashInputBridge.extracted_wots_input
#print axioms Extracted.C10HashInputBridge.randomizer_input
#print axioms Extracted.C10HashInputBridge.extracted_grind_input
#print axioms Extracted.C10AddressInputBridge.u64_nat_value
#print axioms Extracted.C10AddressInputBridge.u64_bytes_value
#print axioms Extracted.C10AddressInputBridge.address_value
#print axioms Extracted.C10AddressInputBridge.extracted_address_input
#print axioms Extracted.C10AddressInputBridge.chain_index_value
#print axioms Extracted.C10AddressInputBridge.extracted_chain_index_input
#print axioms Extracted.C10AddressInputBridge.chain_position_value
#print axioms Extracted.C10AddressInputBridge.wots_tree_value
#print axioms Extracted.C10AddressInputBridge.wots_private_input_value
#print axioms Extracted.C10AddressInputBridge.fors_private_input_value
#print axioms Extracted.C10AddressInputBridge.extracted_wots_private_input
#print axioms Extracted.C10AddressInputBridge.extracted_fors_private_input

-- Paired shuffle exact order and actual extracted loops.
#print axioms Extracted.C10ShuffleBridge.shuffle_seed_input
#print axioms Extracted.C10ShuffleBridge.shuffle_block_input
#print axioms Extracted.C10ShuffleBridge.modeled_shuffle_derive
#print axioms Extracted.C10ShuffleBridge.modeled_shuffle_block
#print axioms Extracted.C10ShuffleBridge.u8_or_zero
#print axioms Extracted.C10ShuffleBridge.shuffle_nonzero_exact
#print axioms Extracted.C10ShuffleBridge.shuffle_copy_exact
#print axioms Extracted.C10ShuffleBridge.shuffle_stream_exact
#print axioms Extracted.C10ShuffleBridge.finishOrder_zero
#print axioms Extracted.C10ShuffleBridge.finishOrder_succ
#print axioms Extracted.C10ShuffleBridge.finishOrder_initial
#print axioms Extracted.C10ShuffleBridge.shuffle_swap_prefix
#print axioms Extracted.C10ShuffleBridge.little_endian_or
#print axioms Extracted.C10ShuffleBridge.shuffle_swap_loop_exact
#print axioms Extracted.C10ShuffleBridge.initialized_prefix
#print axioms Extracted.C10ShuffleBridge.seed_zero_iff
#print axioms Extracted.C10ShuffleBridge.stream_counts_exact
#print axioms Extracted.C10ShuffleBridge.shuffle_prefix_exact
#print axioms Extracted.C10ShuffleBridge.shuffle_exact

-- Actual seed derivation and caller label construction.
#print axioms Extracted.Equiv.shuffle_seed_compare
#print axioms Extracted.Equiv.shuffle_derive_exact
#print axioms Extracted.Equiv.shuffle_derive_total
#print axioms Extracted.Equiv.actual_forest_label
#print axioms Extracted.Equiv.actual_layer_label

-- Secure-wrapper call accounting, including refusal and arbitrary prior trace.
#print axioms secure_wrapper_model.wrapper_inner_call_cost
#print axioms secure_wrapper_model.wrapper_entry_call_cost
#print axioms secure_wrapper_model.wrapper_entry_call_bounds
#print axioms secure_wrapper_model.wrapper_entry_success_call_counts

-- Exact search-acceptance component; kernel-only closures.
#print axioms Extracted.C10AcceptanceBridge.wots_sum_value
#print axioms Extracted.C10AcceptanceBridge.wots_accept_common
#print axioms Extracted.C10AcceptanceBridge.fors_accept_common
#print axioms Extracted.C10AcceptanceBridge.extracted_wots_trial
#print axioms Extracted.C10AcceptanceBridge.extracted_fors_trial
#print axioms Extracted.C10AcceptanceBridge.extracted_wots_search
#print axioms Extracted.C10AcceptanceBridge.extracted_fors_search
#print axioms Extracted.C10FirstHit.firstSlot_nil
#print axioms Extracted.C10FirstHit.firstSlot_cons
#print axioms Extracted.C10FirstHit.all_rejected
#print axioms Extracted.C10FirstHit.first_hit
#print axioms Extracted.C10FirstHit.firstSlot_le_length
#print axioms Extracted.C10FirstHit.firstSlot_zero_iff
#print axioms Extracted.C10FirstHit.firstSlot_at
#print axioms Extracted.C10FirstHit.firstSlot_range_hit
#print axioms Extracted.C10FirstHit.firstSlot_range_exhausted
#print axioms Extracted.C10FirstHit.wots_first_slot_common
#print axioms Extracted.C10FirstHit.fors_first_slot_common
#print axioms Extracted.C10FunctionalSearch.searchCounter_val
#print axioms Extracted.C10FunctionalSearch.searchCounter_of_val
#print axioms Extracted.C10FunctionalSearch.wots_schedule_hit
#print axioms Extracted.C10FunctionalSearch.wots_schedule_exhausted
#print axioms Extracted.C10FunctionalSearch.fors_schedule_hit
#print axioms Extracted.C10FunctionalSearch.fors_schedule_exhausted
#print axioms Extracted.C10FunctionalSearch.extracted_wots_first_slot
#print axioms Extracted.C10FunctionalSearch.extracted_fors_first_slot
#print axioms Extracted.C10FunctionalSearch.extracted_wots_exhaustion_iff
#print axioms Extracted.C10FunctionalSearch.extracted_fors_exhaustion_iff

-- Functional WOTS endpoints under the supplied pure backend.
#print axioms Extracted.C10FunctionalWots.supplied_backend_width
#print axioms Extracted.C10FunctionalWots.chain_zero
#print axioms Extracted.C10FunctionalWots.chain_succ
#print axioms Extracted.C10FunctionalWots.hash_step_value
#print axioms Extracted.C10FunctionalWots.chain_pure_value
#print axioms Extracted.C10FunctionalWots.extracted_chain_value
#print axioms Extracted.C10FunctionalWots.secret_pure_value
#print axioms Extracted.C10FunctionalWots.extracted_secret_value
#print axioms Extracted.C10FunctionalWots.multi_pure_value
#print axioms Extracted.C10FunctionalWots.extracted_multi_value
#print axioms Extracted.C10FunctionalWots.pure_address_value
#print axioms Extracted.C10FunctionalWots.keygen_nodes_value
#print axioms Extracted.C10FunctionalWots.keygen_pure_value
#print axioms Extracted.C10FunctionalWots.extracted_keygen_value
#print axioms Extracted.C10FunctionalWotsSign.digest_pure_value
#print axioms Extracted.C10FunctionalWotsSign.functional_schedule_value
#print axioms Extracted.C10FunctionalWotsSign.digit_value
#print axioms Extracted.C10FunctionalWotsSign.sign_nodes_value
#print axioms Extracted.C10FunctionalWotsSign.extracted_sign_value
#print axioms Extracted.C10FunctionalWotsRecover.recover_nodes_value
#print axioms Extracted.C10FunctionalWotsRecover.extracted_recover_value

-- Functional FORS and Merkle recovery: supplied backend, kernel-only.
#print axioms Extracted.C10FunctionalTrees.pad16p_eq
#print axioms Extracted.C10FunctionalTrees.fors_secret_pure_value
#print axioms Extracted.C10FunctionalTrees.extracted_fors_secret_value
#print axioms Extracted.C10FunctionalTrees.pair_pure_value
#print axioms Extracted.C10FunctionalTrees.path_address_value
#print axioms Extracted.C10FunctionalTrees.fors_leaf_pure_value
#print axioms Extracted.C10FunctionalTrees.path_zero
#print axioms Extracted.C10FunctionalTrees.path_succ
#print axioms Extracted.C10FunctionalTrees.path_step_value
#print axioms Extracted.C10FunctionalTrees.path_fold_value
#print axioms Extracted.C10FunctionalTrees.path_value
#print axioms Extracted.C10FunctionalTrees.fors_fold_eq
#print axioms Extracted.C10FunctionalTrees.merkle_fold_eq
#print axioms Extracted.C10FunctionalTrees.extracted_fors_recover_value
#print axioms Extracted.C10FunctionalTrees.extracted_merkle_recover_value
#print axioms Extracted.C10FunctionalBuildValues.nodes_zero
#print axioms Extracted.C10FunctionalBuildValues.nodes_succ
#print axioms Extracted.C10FunctionalBuildValues.level_length
#print axioms Extracted.C10FunctionalBuildValues.nodes_length
#print axioms Extracted.C10FunctionalBuildValues.auth_length
#print axioms Extracted.C10FunctionalBuildValues.root_value
#print axioms Extracted.C10FunctionalBuildValues.level_get
#print axioms Extracted.C10FunctionalBuildValues.nodes_get_eq
#print axioms Extracted.C10FunctionalBuildValues.root_eq_node
#print axioms Extracted.C10FunctionalBuildValues.auth_get
#print axioms Extracted.C10FunctionalBuildValues.sibling_outside
#print axioms Extracted.C10FunctionalBuildValues.sibling_inside
#print axioms Extracted.C10FunctionalBuildValues.pow_two_even
#print axioms Extracted.C10FunctionalBuildValues.auth_outside_get
#print axioms Extracted.C10FunctionalBuildValues.auth_outside
#print axioms Extracted.C10FunctionalBuildValues.sibling_xor
#print axioms Extracted.C10FunctionalBuildValues.sibling_int_nat_index
#print axioms Extracted.C10FunctionalBuildValues.sibling_int_nat
#print axioms Extracted.C10FunctionalBuildValues.sibling_nat_inside
#print axioms Extracted.C10FunctionalBuildValues.sibling_nat_outside
#print axioms Extracted.C10FunctionalBuildValues.sibling_nat_range
#print axioms Extracted.C10FunctionalBuildValues.auth_nat_node
#print axioms Extracted.C10FunctionalBuildValues.sibling_shift_outside
#print axioms Extracted.Equiv.fors_auth_capture_outside
#print axioms Extracted.Equiv.fors_auth_carry_outside_spec
#print axioms Extracted.Equiv.fors_auth_loop_outside_spec
#print axioms Extracted.Equiv.xmss_auth_capture_outside
#print axioms Extracted.Equiv.xmss_auth_carry_outside_spec
#print axioms Extracted.Equiv.xmss_auth_loop_outside_spec
#print axioms Extracted.C10FunctionalBuilders.fors_node_value
#print axioms Extracted.C10FunctionalBuilders.merkle_node_value
#print axioms Extracted.C10FunctionalBuilders.extracted_fors_root_value
#print axioms Extracted.C10FunctionalBuilders.extracted_merkle_root_value
#print axioms Extracted.C10FunctionalBuilders.fors_path_value
#print axioms Extracted.C10FunctionalBuilders.merkle_path_value
#print axioms Extracted.C10FunctionalBuilders.extracted_fors_sign_valid_values
#print axioms Extracted.C10FunctionalBuilders.extracted_merkle_build_valid_value
#print axioms Extracted.C10FunctionalBuilders.extracted_fors_sign_values
#print axioms Extracted.C10FunctionalBuilders.extracted_merkle_build_value
#print axioms Extracted.Equiv.fors_sign_tree_outside_spec
#print axioms Extracted.Equiv.xmss_build_auth_outside_spec

-- Complete functional forest and layer caller endpoints.
#print axioms Extracted.C10FunctionalForest.index_words_get
#print axioms Extracted.C10FunctionalForest.forest_root_value
#print axioms Extracted.C10FunctionalForest.signing_path_value
#print axioms Extracted.C10FunctionalForest.signer_secrets_value
#print axioms Extracted.C10FunctionalForest.signer_paths_value
#print axioms Extracted.C10FunctionalForest.signing_recovery_value
#print axioms Extracted.C10FunctionalForest.signer_roots_value
#print axioms Extracted.C10FunctionalForest.forest_compression_value
#print axioms Extracted.C10FunctionalForest.extracted_forest_sign_value
#print axioms Extracted.C10FunctionalForestRecover.node_words_get
#print axioms Extracted.C10FunctionalForestRecover.path_words_get
#print axioms Extracted.C10FunctionalForestRecover.normal_root_value
#print axioms Extracted.C10FunctionalForestRecover.extracted_forest_recover_value
#print axioms Extracted.C10FunctionalLayer.layer_path_value
#print axioms Extracted.C10FunctionalLayer.layer_recovery_value
#print axioms Extracted.C10FunctionalLayer.signed_layer_recovery_value
#print axioms Extracted.C10FunctionalLayer.pure_layer_sign_values
#print axioms Extracted.C10FunctionalLayer.extracted_layer_body_values
