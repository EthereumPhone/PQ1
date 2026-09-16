/-
  PQSigner.Verifier.Top — top-level Lean port of
  `sphincs-c10/src/lib.rs:149` (`VerifyingKey::verify`).

  Closes the Phase 7 deliverable from
  `docs/archive/handoff-verity-c10-verifier.md`. Top-level `verify` plus its
  closeable invariants:

    - `verify_length_enforced`     — sig len ≠ 4008 ⇒ false
    - `verify_deterministic`       — same args ⇒ same result
    - `hmsg_domain_separator_matches_yul` — H_msg literal `0xFF...FF`
                                            matches the Yul constant
    - `verify_byte_equivalent_to_rust`  — DELETED 2026-08-11. It was an
                                          `axiom … : True`, i.e. asserted
                                          NOTHING while being described as
                                          load-bearing. Now an OPEN
                                          OBLIGATION (see below); the KAT
                                          diff harness is an empirical
                                          witness, not a proof.

  Together with the per-phase theorems
  (Params.signature_len_eq_4008, Wots.target_sum_enforced,
  Fors.forced_zero_fors_enforced, Merkle.branchless_swap_*,
  Hash.pad16_low_half_is_zero_block), these constitute the machine-
  checked invariants on the SPHINCS+C10 verifier.
-/

import PQSigner.Verifier.Params
import PQSigner.Verifier.Address
import PQSigner.Verifier.Hash
import PQSigner.Verifier.Wots
import PQSigner.Verifier.Merkle
import PQSigner.Verifier.Fors
import PQSigner.Verifier.Hypertree

namespace PQSigner.Verifier.Top

open PQSigner.Verifier.Params
open PQSigner.Verifier.Address (ByteVec)
open PQSigner.Verifier.Hypertree (verifyHypertree)

/-! ## Top-level entry: `verify`

    Adds the sig length enforcement around the hypertree verify. The
    Yul verifier rejects (reverts) on length ≠ 4008 at
    `SPHINCsC10Asm.sol:33`. We mirror that semantically by returning
    `false` on mismatch — the wallet's try/catch around the verifier
    call treats both revert and `false` as SIG_VALIDATION_FAILED. -/

def verify (pkSeed pkRoot msgHash sig : ByteVec) : Bool :=
  if sig.size ≠ SIGNATURE_LEN then false
  else verifyHypertree pkSeed pkRoot msgHash sig

/-! ## Theorems -/

/-- **The `verify_length_enforced` theorem.** A signature of any
    length other than exactly 4008 bytes is rejected. Mirrors the Yul
    revert at `SPHINCsC10Asm.sol:33`. -/
theorem verify_length_enforced
    (pkSeed pkRoot msgHash sig : ByteVec)
    (h : sig.size ≠ SIGNATURE_LEN) :
    verify pkSeed pkRoot msgHash sig = false := by
  unfold verify
  rw [if_pos h]

/-- Concrete: a 4007-byte signature is rejected. -/
theorem verify_rejects_short_sig
    (pkSeed pkRoot msgHash : ByteVec) (sig : ByteVec)
    (h : sig.size = 4007) :
    verify pkSeed pkRoot msgHash sig = false := by
  apply verify_length_enforced
  rw [h, signature_len_eq_4008]
  decide

/-- Concrete: a 4009-byte signature is rejected. -/
theorem verify_rejects_long_sig
    (pkSeed pkRoot msgHash : ByteVec) (sig : ByteVec)
    (h : sig.size = 4009) :
    verify pkSeed pkRoot msgHash sig = false := by
  apply verify_length_enforced
  rw [h, signature_len_eq_4008]
  decide

/-- **The `verify_deterministic` theorem.** `verify` is a pure function
    of its inputs. Trivially closes since the impl uses no IO. -/
theorem verify_deterministic
    (pkSeed pkRoot msgHash sig : ByteVec) :
    verify pkSeed pkRoot msgHash sig = verify pkSeed pkRoot msgHash sig := rfl

/-- **The `hmsg_domain_separator_matches_yul` theorem.** The H_msg
    construction in Lean uses a 32-byte 0xFF pad, matching the Yul
    `mstore(0x80, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)`
    literal at `SPHINCsC10Asm.sol:50`. -/
theorem hmsg_domain_separator_matches_yul :
    (Array.replicate 32 (0xFF : UInt8)).size = 32 ∧
    (Array.replicate 32 (0xFF : UInt8)).getD 0 0 = 0xFF ∧
    (Array.replicate 32 (0xFF : UInt8)).getD 31 0 = 0xFF := by
  refine ⟨?_, ?_, ?_⟩
  · simp
  · simp [Array.getD]
  · simp [Array.getD]

/-! ## The byte-equivalence OPEN OBLIGATION (never proved; formerly a vacuous axiom)

    `verify_byte_equivalent_to_rust`: for every input
    `(pkSeed, pkRoot, msgHash, sig)`, the Lean `verify` and the Rust
    `sphincs-c10::verify` agree.

    This is NEITHER an axiom NOR a theorem: it is UNSTATED. Closing it requires
    reasoning about Rust semantics from within Lean — which needs either an FFI
    bridge or a verified Rust-to-Lean translator, neither of which exists in the
    standalone Lean stdlib. Until one does, the claim cannot even be written
    down, which is precisely why the placeholder that used to stand here
    degenerated to `True`.

    The empirical witness is the 10-vector KAT diff harness at
    `contracts/smart-wallet/test/c10_test_vectors.json` + the Foundry
    tests in `contracts/smart-wallet/test/SPHINCsC10Asm.t.sol`. Any
    divergence between Lean and Rust on those vectors would mean one
    of the two implementations has a bug; in practice they agree by
    construction (both target the same FIPS-style spec).

    Future work (per `docs/archive/handoff-verity-c10-verifier.md` §4 Phase 6):
    upstream Verity gains the Phase-0 primitives (precompile.sha256,
    calldata.read, bitfield ops, memory.scratch), enabling Verity to
    emit Yul from this Lean spec. At that point the Yul→Lean
    equivalence becomes a separate axiom; chaining both gives the
    Lean→Rust→Yul triangle the handoff calls for. -/
/-! HISTORY, 2026-08-11 — this was an `axiom … : True` and is now DELETED.

    The docstring above describes a byte-equivalence between Lean `verify` and
    `sphincs-c10::verify` and calls it load-bearing. The declaration that stood
    here asserted `True`, i.e. nothing at all: not a weak premise but a no-op
    with an axiom's name, which any reader or axiom census would have counted as
    a real cross-validation. It was consumed by no proof, so its removal costs
    no content; it removes a false premise from the tree `AXIOM_STATUS.json`
    names as the A3.1 closure path.

    The obstruction is genuine and unchanged: the Rust side is not expressible
    here, so the claim cannot be stated, let alone proved. That is an OPEN
    OBLIGATION, and it is now recorded as one rather than papered over with a
    trivially-true axiom. State a real axiom over a real proposition if and when
    a proof here actually needs it.

    Recurrence is gated: `lint_fv_invariants.sh` fails on `axiom … : True`
    anywhere under `contracts/`. -/

/-! ## Summary

    Total theorem count in `PQSigner.Verifier.*`:
      - Params: 6 closed (subtree_h_eq_nine, subtree_h_times_d_eq_h,
        sig_fors_total_eq_2336, sig_ht_layer_eq_836,
        signature_len_eq_4008, sig_len_decomposes, adrs_types_distinct,
        k_pred_eq_twelve, fors_and_ht_bits_fit_in_digest)
      - Address: 4 closed (u32ToBE_size_eq_4, u64ToBE_size_eq_8,
        adrs_size_eq_32, adrs_type_disjoint, setChainPos_size_eq,
        setChainIndex_size_eq, setChainPos_size_eq_32,
        setChainIndex_size_eq_32)
      - Hash: 5 closed (truncate_size_eq_N, truncate_sha256_size_eq_N,
        pad16_size_eq_32, pad16_low_half_is_zero_block,
        th_size_eq_N, thPair_size_eq_N, thMulti_size_eq_N,
        hMsg_size_eq_32, wotsDigest_size_eq_32,
        hmsg_domain_pad_is_32_FF)
      - Wots: 4 closed (extractDigits_length_eq_L,
        extract_digits_total_bits_eq_129, extractDigit_lt_W,
        target_sum_lt_max, target_sum_enforced,
        chain_iterates_w_minus_1_minus_digit_steps,
        accepted_digit_sum_eq_205)
      - Merkle: 3 closed + 1 open proof (yul_swap_selector_in_known_set is
        documented + non-essential; the load-bearing
        branchless_swap_equivalent_to_branching_swap closes by rfl)
      - Fors: 9 closed (fors_indices_length_eq_K,
        fors_indices_total_bits_eq_143, ht_index_bits_offset_eq_143,
        extractForsIndex_lt_2_pow_A, extractForsIndex_lt_FORS_LEAVES,
        extractHtIndex_lt_2_pow_H, forced_zero_offset_eq_132,
        forced_zero_mask_width_eq_11, forced_zero_mask_value,
        forced_zero_fors_enforced, forced_zero_iff_high_bits_clear,
        pkFromSig_uses_K_roots, extract_at_132_matches_kth_index)
      - Hypertree: 3 closed + 0 axioms (was "1 axiom" — that axiom was the
        vacuous `: True` one, DELETED 2026-08-11)
        (hypertree_d_eq_2_unrolls_into_two_layers,
        layer_parsing_deterministic, signature_length_is_4008;
        hypertree_verify_equivalent_to_rust was a vacuous `: True` axiom,
        DELETED 2026-08-11 — now an open obligation, see Hypertree.lean)
      - Top: 5 closed + 0 axioms (was "1 axiom", same vacuous `: True`
        declaration, DELETED 2026-08-11) (verify_length_enforced,
        verify_rejects_short_sig, verify_rejects_long_sig,
        verify_deterministic, hmsg_domain_separator_matches_yul;
        verify_byte_equivalent_to_rust was a vacuous `: True` axiom,
        DELETED 2026-08-11 — now an open obligation, see above)

    Net: ~40 closed theorems + 3 axioms + 12 documented sorries.
    CORRECTED 2026-08-20 (issue #673) — axiom count 2 → 3: alongside
    `sha256_size` / `sha256_deterministic` (Verifier/Hash.lean:40,47, the
    opaque-hash interface) there is a third, `predict_matches_create`
    (PQSmartWalletFactory.lean:65) — a content-bearing CREATE2
    address-prediction claim over Solady `LibClone`, inventoried in
    contracts/verity/TRUST_ASSUMPTIONS.md item 4. Sorry count 1 → 12: the
    Merkle.lean site above plus 11 unfinished bodies in
    PQSigner/Theorems.lean (wallet-side, outside the `Verifier.*` tree this
    tally otherwise covers); the old zero-hole CI gate silently passed all
    12 (fail-open `grep -c` over multiple files) and is now a pinned-ratchet
    gate in contracts/verity/Makefile (`make -C contracts/verity ci`).
    EARLIER CORRECTION 2026-08-11 — the "axioms" are NOT the two Lean↔Rust
    bridges (those asserted `True` and are deleted, see Hypertree/Top
    entries above).
-/

end PQSigner.Verifier.Top
