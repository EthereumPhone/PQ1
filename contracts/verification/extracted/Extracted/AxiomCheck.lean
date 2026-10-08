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
