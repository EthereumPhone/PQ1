//! Negative tests for byte-exact constants that are baked into deployed
//! on-chain contracts, into the v0.6 EntryPoint userOpHash preimage, or
//! into the CREATE2 address-stability invariant (CLAUDE.md, invariant #6).
//!
//! **What's being attacked.** A future contributor renames a domain
//! tag, "fixes" a magic value, or refactors the factory address into a
//! "cleaner" representation that happens to change the bytes. Every
//! constant in this file is one a deployed wallet, an existing on-chain
//! verifier, or an external EIP-aware verifier (Solady, Ambire, viem)
//! depends on. A silent change is an interop break that **cannot** be
//! recovered without redeploying every wallet — which CLAUDE.md
//! invariant #6 forbids ("same 24 words → same address on every chain").
//!
//! These tests pass when the bytes are still exactly what they were
//! when the corresponding on-chain artifacts were deployed.

use pqsigner_proto::*;

// ───────────────────────────────────────────────────────────────────────
// EIP-6492 magic suffix
//
// Spec value (https://eips.ethereum.org/EIPS/eip-6492):
//   "Magic bytes: 0x6492649264926492649264926492649264926492649264926492649264926492"
// Any 6492-aware verifier checks the LAST 32 bytes of the sig against
// this. Mutating a byte makes every counterfactual EIP-1271 sig the
// firmware emits unrecognisable to Solady / Ambire / viem.
// ───────────────────────────────────────────────────────────────────────

#[test]
fn negative_eip6492_magic_must_match_spec_byte_for_byte() {
    let spec: [u8; 32] = [
        0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92,
        0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92,
        0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92,
        0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92,
    ];
    assert_eq!(
        EIP6492_MAGIC, spec,
        "EIP6492_MAGIC drifted from the spec value 0x6492…6492 — counterfactual EIP-1271 sigs would no longer be recognised by Solady/Ambire/viem"
    );
}

// ───────────────────────────────────────────────────────────────────────
// Factory address — Arachnid-deterministic, mainnet-stable
//
// CLAUDE.md: "byte-identical on every chain that has the Arachnid
// deployer and EntryPoint v0.6 live". The CREATE2 wallet address
// formula bakes this in via `addr = keccak256(0xff || factory || salt
// || PROXY_INIT_CODE_HASH)[12..]`.
// ───────────────────────────────────────────────────────────────────────

#[test]
fn negative_pq_smart_wallet_factory_address_frozen() {
    let expected: [u8; 20] = [
        0xe8, 0xCE, 0x78, 0xCD, 0x97, 0x64, 0x97, 0x44, 0x7F, 0xF8,
        0xB7, 0x6c, 0x71, 0xb5, 0x9a, 0xE4, 0x2A, 0xf0, 0xd4, 0x52,
    ];
    assert_eq!(
        PQ_SMART_WALLET_FACTORY, expected,
        "PQ_SMART_WALLET_FACTORY changed — invariant #6 (cross-chain address stability) would break for every existing wallet"
    );
}

#[test]
fn negative_proxy_init_code_hash_frozen() {
    let expected: [u8; 32] = [
        0xac, 0x0c, 0x44, 0xb6, 0xd0, 0x6f, 0x67, 0x8e,
        0xb3, 0x50, 0x42, 0x6f, 0x4d, 0x0d, 0x7a, 0x89,
        0xcc, 0x72, 0x9d, 0xcb, 0x15, 0x6d, 0xe3, 0x03,
        0xfa, 0x77, 0xa7, 0x75, 0x2c, 0xcc, 0x22, 0xb6,
    ];
    assert_eq!(
        PROXY_INIT_CODE_HASH, expected,
        "PROXY_INIT_CODE_HASH drifted — the CREATE2 wallet address formula would land at a different address than every previously-derived seed"
    );
}

// ───────────────────────────────────────────────────────────────────────
// Function selectors — keccak256 of canonical signatures.
// See `negative_selector_keccak.rs` for the keccak cross-check; the
// tests below freeze the **declared bytes** so that a future change has
// to fail *two* tests, not one.
// ───────────────────────────────────────────────────────────────────────

#[test]
fn negative_execute_selector_bytes_frozen() {
    assert_eq!(
        EXECUTE_SELECTOR,
        [0x14, 0x44, 0x3c, 0x57],
        "EXECUTE_SELECTOR drifted — every Type 2 UserOp's callData prefix would no longer match the PQSmartWallet's executeWithOffchainCount entry"
    );
}

#[test]
fn negative_execute_batch_selector_bytes_frozen() {
    assert_eq!(
        EXECUTE_BATCH_SELECTOR,
        [0x7a, 0x38, 0x99, 0x33],
        "EXECUTE_BATCH_SELECTOR drifted — batch UserOps would land on the wrong dispatcher"
    );
}

#[test]
fn negative_create_account_selector_bytes_frozen() {
    assert_eq!(
        PQ_CREATE_ACCOUNT_SELECTOR,
        [0xf6, 0x18, 0x2a, 0x73],
        "PQ_CREATE_ACCOUNT_SELECTOR drifted — factory deploy calls would revert"
    );
}

#[test]
fn negative_add_owner_bytes_selector_bytes_frozen() {
    assert_eq!(
        PQ_ADD_OWNER_BYTES_SELECTOR,
        [0x10, 0x14, 0x90, 0xcb],
        "PQ_ADD_OWNER_BYTES_SELECTOR drifted — Type 1 slot-registration UserOps would no-op"
    );
}

#[test]
fn negative_set_pre_signature_selector_bytes_frozen() {
    assert_eq!(
        SET_PRE_SIGNATURE_SELECTOR,
        [0xec, 0x6c, 0xb1, 0x3f],
        "SET_PRE_SIGNATURE_SELECTOR drifted — CoW v3 mandatory-trailer gate would stop recognising CoW UserOps"
    );
}

#[test]
fn negative_approve_hash_selector_bytes_frozen() {
    assert_eq!(
        APPROVE_HASH_SELECTOR,
        [0xd4, 0xd9, 0xbd, 0xcd],
        "APPROVE_HASH_SELECTOR drifted — Safe approveHash clear-sign path would stop recognising Safe UserOps"
    );
}

// ───────────────────────────────────────────────────────────────────────
// Domain-separation tags — KDF / hash inputs whose bytes are part of
// the on-chain signed message preimage.
// ───────────────────────────────────────────────────────────────────────

#[test]
fn negative_factory_add_slot_domain_byte_for_byte() {
    // Mirrored on-chain as `FACTORY_ADD_SLOT_DOMAIN` in PQSmartWalletFactory.
    // Changing this domain tag means every existing bootstrap key's
    // factory authorisation sig becomes invalid.
    assert_eq!(
        FACTORY_ADD_SLOT_DOMAIN, b"pqwallet-factory-add-slot",
        "FACTORY_ADD_SLOT_DOMAIN drifted — pre-computed bootstrap-signed slot-add digests stop verifying on-chain"
    );
}

// ───────────────────────────────────────────────────────────────────────
// CoW Protocol — real settlement address and sentinel must differ
// **only** in the last byte. The sentinel is used as a DB lookup key,
// the settlement address is the EIP-712 verifyingContract; collapsing
// the two would make every CoW UserOp the wallet handles point at the
// wrong VK or the wrong verifyingContract.
// ───────────────────────────────────────────────────────────────────────

#[test]
fn negative_gpv2_settlement_address_frozen() {
    let expected: [u8; 20] = [
        0x90, 0x08, 0xd1, 0x9f, 0x58, 0xaa, 0xbd, 0x9e, 0xd0, 0xd6,
        0x09, 0x71, 0x56, 0x5a, 0xa8, 0x51, 0x05, 0x60, 0xab, 0x41,
    ];
    assert_eq!(
        GPV2_SETTLEMENT_ADDRESS, expected,
        "GPV2_SETTLEMENT_ADDRESS drifted — the EIP-712 domain separator the wallet recomputes would no longer match what CoW signs"
    );
}

#[test]
fn negative_gpv2_vault_relayer_address_frozen() {
    let expected: [u8; 20] = [
        0xc9, 0x2e, 0x8b, 0xdf, 0x79, 0xf0, 0x50, 0x7f, 0x65, 0xa3,
        0x92, 0xb0, 0xab, 0x46, 0x67, 0x71, 0x6b, 0xfe, 0x01, 0x10,
    ];
    assert_eq!(
        GPV2_VAULT_RELAYER_ADDRESS, expected,
        "GPV2_VAULT_RELAYER_ADDRESS drifted — the trusted UI would mislabel (or stop labelling) the spender of a CoW approve record"
    );
}

// ───────────────────────────────────────────────────────────────────────
// Safe MultiSendCallOnly allowlist — the ONLY contracts a SafeTx may
// DELEGATECALL into. Source: safe-global/safe-deployments
// (multi_send_call_only.json for v1.3.0 + v1.4.1). A drifted byte here
// either bricks the multiSend clear-sign flow (refusal) or — far worse —
// allowlists an attacker contract whose delegatecalled code ignores the
// rendered records entirely.
// ───────────────────────────────────────────────────────────────────────

#[test]
fn negative_multisend_call_only_allowlist_frozen() {
    let expected: [[u8; 20]; 4] = [
        // v1.3.0 canonical 0x40A2aCCbd92BCA938b02010E17A5b8929b49130D
        [
            0x40, 0xa2, 0xac, 0xcb, 0xd9, 0x2b, 0xca, 0x93, 0x8b, 0x02,
            0x01, 0x0e, 0x17, 0xa5, 0xb8, 0x92, 0x9b, 0x49, 0x13, 0x0d,
        ],
        // v1.3.0 eip155 0xA1dabEF33b3B82c7814B6D82A79e50F4AC44102B
        [
            0xa1, 0xda, 0xbe, 0xf3, 0x3b, 0x3b, 0x82, 0xc7, 0x81, 0x4b,
            0x6d, 0x82, 0xa7, 0x9e, 0x50, 0xf4, 0xac, 0x44, 0x10, 0x2b,
        ],
        // v1.4.1 canonical 0x9641d764fc13c8B624c04430C7356C1C7C8102e2
        [
            0x96, 0x41, 0xd7, 0x64, 0xfc, 0x13, 0xc8, 0xb6, 0x24, 0xc0,
            0x44, 0x30, 0xc7, 0x35, 0x6c, 0x1c, 0x7c, 0x81, 0x02, 0xe2,
        ],
        // v1.5.0 canonical 0xA83c336B20401Af773B6219BA5027174338D1836
        [
            0xa8, 0x3c, 0x33, 0x6b, 0x20, 0x40, 0x1a, 0xf7, 0x73, 0xb6,
            0x21, 0x9b, 0xa5, 0x02, 0x71, 0x74, 0x33, 0x8d, 0x18, 0x36,
        ],
    ];
    assert_eq!(
        MULTISEND_CALL_ONLY_ADDRESSES, expected,
        "MULTISEND_CALL_ONLY_ADDRESSES drifted from the canonical safe-deployments addresses"
    );
    // The allowlist must never contain the plain (delegatecall-capable)
    // MultiSend deployments.
    let plain_multisend_v130: [u8; 20] = [
        0xa2, 0x38, 0xcb, 0xeb, 0x14, 0x2c, 0x10, 0xef, 0x7a, 0xd8,
        0x44, 0x2c, 0x6d, 0x1f, 0x9e, 0x89, 0xe0, 0x7e, 0x77, 0x61,
    ];
    let plain_multisend_v141: [u8; 20] = [
        0x38, 0x86, 0x9b, 0xf6, 0x6a, 0x61, 0xcf, 0x6b, 0xdb, 0x99,
        0x6a, 0x6a, 0xe4, 0x0d, 0x58, 0x53, 0xfd, 0x43, 0xb5, 0x26,
    ];
    // 0x218543288004CD07832472D464648173c77D7eB7
    let plain_multisend_v150: [u8; 20] = [
        0x21, 0x85, 0x43, 0x28, 0x80, 0x04, 0xcd, 0x07, 0x83, 0x24,
        0x72, 0xd4, 0x64, 0x64, 0x81, 0x73, 0xc7, 0x7d, 0x7e, 0xb7,
    ];
    for a in &MULTISEND_CALL_ONLY_ADDRESSES {
        assert_ne!(a, &plain_multisend_v130, "plain MultiSend v1.3.0 must not be allowlisted");
        assert_ne!(a, &plain_multisend_v141, "plain MultiSend v1.4.1 must not be allowlisted");
        assert_ne!(a, &plain_multisend_v150, "plain MultiSend v1.5.0 must not be allowlisted");
    }
}

// ───────────────────────────────────────────────────────────────────────
// Safe EIP-712 typehashes — keccak256 of the canonical struct
// signature. Cross-checked against the literal expected value (the
// `negative_selector_keccak.rs` file does the keccak path).
// ───────────────────────────────────────────────────────────────────────

#[test]
fn negative_safe_domain_typehash_frozen() {
    let expected: [u8; 32] = [
        0x47, 0xe7, 0x95, 0x34, 0xa2, 0x45, 0x95, 0x2e, 0x8b, 0x16, 0x89, 0x3a, 0x33, 0x6b, 0x85,
        0xa3, 0xd9, 0xea, 0x9f, 0xa8, 0xc5, 0x73, 0xf3, 0xd8, 0x03, 0xaf, 0xb9, 0x2a, 0x79, 0x46,
        0x92, 0x18,
    ];
    assert_eq!(
        SAFE_DOMAIN_TYPEHASH, expected,
        "SAFE_DOMAIN_TYPEHASH drifted — Safe v1.3.0+ approveHash sigs would compute a different domain separator and fail the on-chain cross-check"
    );
}

#[test]
fn negative_safe_tx_typehash_frozen() {
    let expected: [u8; 32] = [
        0xbb, 0x83, 0x10, 0xd4, 0x86, 0x36, 0x8d, 0xb6, 0xbd, 0x6f, 0x84, 0x94, 0x02, 0xfd, 0xd7,
        0x3a, 0xd5, 0x3d, 0x31, 0x6b, 0x5a, 0x4b, 0x26, 0x44, 0xad, 0x6e, 0xfe, 0x0f, 0x94, 0x12,
        0x86, 0xd8,
    ];
    assert_eq!(
        SAFE_TX_TYPEHASH, expected,
        "SAFE_TX_TYPEHASH drifted — every approveHash clear-sign would compute a safeTxHash that doesn't match the on-chain Safe"
    );
}

// ───────────────────────────────────────────────────────────────────────
// Wire-format size freeze — these constants are byte-counted by the
// companion app and by on-chain verifiers. Listed once more here as a
// dedicated "any silent change is a breaking on-chain change" gate.
// ───────────────────────────────────────────────────────────────────────

#[test]
fn negative_wire_format_lengths_frozen() {
    // C10 sig — verifier slice size is hardcoded on-chain.
    assert_eq!(C10_SIG_LEN, 4_008);
    // SignatureWrapper ABI encoding — wallet decodes exactly this many bytes.
    assert_eq!(SIG_WRAPPER_LEN, 4_128);
    // initCode — companion populates UserOperation06.initCode with exactly this length.
    assert_eq!(PQ_INIT_CODE_LEN, 4_280);
    // EIP-6492 wrapper output — Solady / Ambire / viem parse this length.
    assert_eq!(SIGN_OFFCHAIN_OUTPUT_LEN_6492, 8_616);
    // Deployed-path EIP-1271 sig output.
    assert_eq!(SIGN_OFFCHAIN_OUTPUT_LEN, 4_016);
    // owner_bytes record stored on-chain.
    assert_eq!(OWNER_BYTES_LEN, 64);
    // Unified sign input header (offset of data_len).
    assert_eq!(SIGN_USEROP_HEADER_LEN, 330);
    // CMD_SIGN_OFFCHAIN input header (offset of payload).
    assert_eq!(SIGN_OFFCHAIN_HEADER_LEN, 17);
    // Per-chain caps (mirrored on-chain).
    assert_eq!(MAX_BOOTSTRAP_USES, 65_536);
    assert_eq!(MAX_SLOT_USES, 65_536);
    // Personal-sign payload cap on the trusted-display path.
    assert_eq!(MAX_OFFCHAIN_PERSONAL_SIGN_LEN, 700);
}
