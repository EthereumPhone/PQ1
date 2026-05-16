//! Adversarial tests that challenge the assumptions the `pqsigner-aa`
//! slice holds. Each test passes when the code **rejects** the bad input
//! or refuses to violate an invariant; failure here means an attacker
//! found a silent door.
//!
//! Threat surface targeted (from CLAUDE.md):
//!   * Invariant #6 — bootstrap C10 keys + factory + EntryPoint v0.6
//!     baked into CREATE2 init-code hash; same 24 words → same address
//!     on every chain. Any field that the verifier rehashes (sender,
//!     nonce, gas, callData, etc.) must produce a different
//!     `userOpHash` / `sphincsDigest` when it changes.
//!   * "Frozen wire formats" — on-chain verifier depends on exact byte
//!     layouts. Any silent drift in `USEROP_HEADER_LEN`, ABI offsets,
//!     padding, EIP-712 typehashes, or ERC-6492 magic suffix would
//!     break sigs.
//!   * "No casual KDF tag changes" / "Solady-nested EIP-712 chains the
//!     wallet address into the hash" — the domain constants and proxy
//!     derivation must be deterministic and sensitive to every input
//!     bit.

use pqsigner_aa::eip1271::{
    domain_separator, personal_sign_replay_safe_hash, proxy_address,
};
use pqsigner_aa::eip6492::{has_magic_suffix, wrap_signature};
use pqsigner_aa::userop::{
    compute_sphincs_digest_v06, compute_user_op_hash, parse_header,
    reconstruct_execute_batch_calldata, reconstruct_execute_calldata, AaError, AaUserOpParams,
    AaUserOpParamsV06Sha256, BatchAaError, BatchInnerTx, WireParseError, ENTRY_POINT_V06,
    EXECUTE_BATCH_SELECTOR, EXECUTE_SELECTOR, KECCAK_EMPTY, MAX_EXECUTE_CALLDATA_LEN,
    SHA256_EMPTY,
};
use pqsigner_proto::{
    EIP6492_BLOB_LEN, EIP6492_FACTORY_CALLDATA_LEN, EIP6492_FACTORY_CALLDATA_PADDED,
    EIP6492_INNER_WRAPPER_LEN, EIP6492_MAGIC, MAX_BATCH_TXS, MAX_TX_LEN, USEROP_HEADER_LEN,
};
use pqsigner_tx_core::eip1559::{Eip1559Tx, U256};

// ---------- shared fixtures --------------------------------------------------

fn u256_from_u64(v: u64) -> U256 {
    let mut buf = [0u8; 32];
    buf[24..].copy_from_slice(&v.to_be_bytes());
    U256(buf)
}

fn baseline_params() -> AaUserOpParams {
    AaUserOpParams {
        sender: [0x42; 20],
        entry_point: ENTRY_POINT_V06,
        chain_id: 1,
        nonce: u256_from_u64(1),
        call_gas_limit: u256_from_u64(100_000),
        verification_gas_limit: u256_from_u64(200_000),
        pre_verification_gas: u256_from_u64(21_000),
        max_fee_per_gas: u256_from_u64(50_000_000_000),
        max_priority_fee_per_gas: u256_from_u64(2_000_000_000),
        init_code_hash: KECCAK_EMPTY,
        paymaster_and_data_hash: KECCAK_EMPTY,
    }
}

fn baseline_v06_params() -> AaUserOpParamsV06Sha256 {
    AaUserOpParamsV06Sha256 {
        sender: [0x42; 20],
        entry_point: ENTRY_POINT_V06,
        chain_id: 1,
        nonce: u256_from_u64(1),
        init_code_digest: SHA256_EMPTY,
        call_gas_limit: u256_from_u64(100_000),
        verification_gas_limit: u256_from_u64(200_000),
        pre_verification_gas: u256_from_u64(21_000),
        max_fee_per_gas: u256_from_u64(50_000_000_000),
        max_priority_fee_per_gas: u256_from_u64(2_000_000_000),
        paymaster_and_data_digest: SHA256_EMPTY,
    }
}

fn baseline_tx() -> Eip1559Tx {
    Eip1559Tx {
        chain_id: 1,
        nonce: 0,
        max_priority_fee_per_gas: u256_from_u64(2_000_000_000),
        max_fee_per_gas: u256_from_u64(50_000_000_000),
        gas_limit: 21_000,
        to: Some([0xAB; 20]),
        value: U256::zero(),
        data_len: 0,
        access_list_count: 0,
        signing_hash: [0u8; 32],
    }
}

// =============================================================================
// reconstruct_execute_calldata — parser / state / invariant attacks
// =============================================================================

#[test]
fn negative_reconstruct_rejects_contract_creation() {
    // Inner tx with `to == None` is a CREATE — wrapping it as
    // `executeWithOffchainCount(target, value, data)` would silently
    // drop the codeword and let an attacker push deploy bytes through
    // the value-transfer UI. Refusal is invariant.
    let mut tx = baseline_tx();
    tx.to = None;
    let err = reconstruct_execute_calldata(1, 0, &tx, &[]).err();
    assert_eq!(
        err,
        Some(AaError::ContractCreation),
        "contract-creation inner tx must be rejected — no silent CREATE through executeWithOffchainCount",
    );
}

#[test]
fn negative_reconstruct_rejects_oversized_data() {
    // Anything past MAX_EXECUTE_CALLDATA_LEN must error rather than
    // truncating into the fixed-size stack buffer.
    let tx = baseline_tx();
    let huge = std::vec![0u8; MAX_EXECUTE_CALLDATA_LEN];
    let err = reconstruct_execute_calldata(1, 0, &tx, &huge).err();
    assert_eq!(
        err,
        Some(AaError::CallDataTooLong),
        "oversized data must be rejected, never silently truncated into the stack buffer",
    );
}

#[test]
fn negative_reconstruct_owner_index_baked_into_calldata() {
    // The signed callData carries ownerIndex; if NS could choose one
    // value at sign-time and another at submission, the wallet could
    // be tricked into spending from the wrong slot. Verify that the
    // produced calldata changes when ownerIndex changes.
    let tx = baseline_tx();
    let a = reconstruct_execute_calldata(1, 0, &tx, b"").unwrap();
    let b = reconstruct_execute_calldata(2, 0, &tx, b"").unwrap();
    assert_ne!(
        a.as_slice(),
        b.as_slice(),
        "ownerIndex must be cryptographically bound into the executeWithOffchainCount calldata",
    );
}

#[test]
fn negative_reconstruct_offchain_count_baked_into_calldata() {
    // Same property for newOffchainCount: it's part of the signed
    // callData, so the on-chain monotonic counter update reflects
    // what the firmware claimed. Hostile NS that supplies a stale
    // count is detectable via this binding.
    let tx = baseline_tx();
    let a = reconstruct_execute_calldata(1, 7, &tx, b"").unwrap();
    let b = reconstruct_execute_calldata(1, 8, &tx, b"").unwrap();
    assert_ne!(a.as_slice(), b.as_slice());
}

#[test]
fn negative_reconstruct_selector_is_executewithoffchaincount() {
    // The selector pins the on-chain entry point to
    // `executeWithOffchainCount`. A future refactor that swapped it
    // for a non-counter-bumping `execute(...)` would break invariant
    // #9 (combined cap monotonicity).
    let tx = baseline_tx();
    let out = reconstruct_execute_calldata(1, 0, &tx, b"").unwrap();
    assert_eq!(
        &out.as_slice()[..4],
        &EXECUTE_SELECTOR,
        "selector must remain `executeWithOffchainCount(...)` so the on-chain offchainSigCount[] is bumped",
    );
}

#[test]
fn negative_reconstruct_padding_bytes_zero_no_leakage() {
    // ABI requires zero-padding past the last data byte. Padding that
    // happened to be uninitialised stack memory would leak across the
    // signature boundary into on-chain calldata.
    let tx = baseline_tx();
    let data = [0xFFu8; 1]; // padded out to 32 bytes
    let out = reconstruct_execute_calldata(1, 0, &tx, &data).unwrap();
    let slice = out.as_slice();
    // length word starts at offset 164; data starts at 196; padding
    // bytes are [197..228) since data_len=1.
    assert_eq!(slice.len(), 196 + 32);
    for (i, b) in slice[197..228].iter().enumerate() {
        assert_eq!(
            *b, 0,
            "padding byte {} after data must be zero (no leakage), got 0x{:02x}",
            197 + i, b
        );
    }
}

// =============================================================================
// reconstruct_execute_batch_calldata
// =============================================================================

#[test]
fn negative_batch_empty_refused() {
    // Empty batch is a UX antipattern *and* a footgun: the on-chain
    // contract would bump the off-chain counter for "no work".
    let err = reconstruct_execute_batch_calldata(1, 0, &[]).err();
    assert_eq!(err, Some(BatchAaError::EmptyBatch));
}

#[test]
fn negative_batch_exceeds_max_count_refused() {
    let empty: [u8; 0] = [];
    let tx = BatchInnerTx { to: [0u8; 20], value: [0u8; 32], data: &empty };
    let v: std::vec::Vec<_> = std::iter::repeat(tx).take(MAX_BATCH_TXS + 1).collect();
    let err = reconstruct_execute_batch_calldata(1, 0, &v).err();
    assert_eq!(
        err,
        Some(BatchAaError::CallDataTooLong),
        "batch with > MAX_BATCH_TXS entries must be rejected",
    );
}

#[test]
fn negative_batch_one_entry_too_long_refuses_whole_batch() {
    // A hostile NS hides an oversized payload inside one inner tx of a
    // mixed batch. Refusing the whole batch (rather than truncating
    // the bad one) is the safe choice.
    let small = [0xAAu8; 4];
    let huge = std::vec![0xBBu8; MAX_TX_LEN + 1];
    let txs = [
        BatchInnerTx { to: [0x11; 20], value: [0u8; 32], data: &small },
        BatchInnerTx { to: [0x22; 20], value: [0u8; 32], data: &huge },
    ];
    let err = reconstruct_execute_batch_calldata(1, 0, &txs).err();
    assert_eq!(
        err,
        Some(BatchAaError::CallDataTooLong),
        "a single oversized inner-tx must abort the whole batch reconstruction",
    );
}

#[test]
fn negative_batch_selector_is_executebatchwithoffchaincount() {
    let empty: [u8; 0] = [];
    let txs = [BatchInnerTx { to: [0x11; 20], value: [0u8; 32], data: &empty }];
    let out = reconstruct_execute_batch_calldata(1, 0, &txs).unwrap();
    assert_eq!(&out.as_slice()[..4], &EXECUTE_BATCH_SELECTOR);
}

#[test]
fn negative_batch_owner_index_and_count_bound() {
    let empty: [u8; 0] = [];
    let txs = [BatchInnerTx { to: [0x11; 20], value: [0u8; 32], data: &empty }];
    let a = reconstruct_execute_batch_calldata(1, 0, &txs).unwrap();
    let b = reconstruct_execute_batch_calldata(2, 0, &txs).unwrap();
    let c = reconstruct_execute_batch_calldata(1, 1, &txs).unwrap();
    assert_ne!(a.as_slice(), b.as_slice(), "batch ownerIndex must be bound into calldata");
    assert_ne!(a.as_slice(), c.as_slice(), "batch newOffchainCount must be bound into calldata");
}

#[test]
fn negative_batch_inner_tx_swap_changes_calldata() {
    // Swapping two inner txs (different addresses + values) must
    // produce a strictly different signed calldata, even though the
    // {to,value} *set* is identical. Otherwise an MEV-style reorder
    // attack could swap victim/recipient after the user confirmed.
    let empty: [u8; 0] = [];
    let txs_ab = [
        BatchInnerTx { to: [0x11; 20], value: u256_be(1), data: &empty },
        BatchInnerTx { to: [0x22; 20], value: u256_be(2), data: &empty },
    ];
    let txs_ba = [
        BatchInnerTx { to: [0x22; 20], value: u256_be(2), data: &empty },
        BatchInnerTx { to: [0x11; 20], value: u256_be(1), data: &empty },
    ];
    let a = reconstruct_execute_batch_calldata(1, 0, &txs_ab).unwrap();
    let b = reconstruct_execute_batch_calldata(1, 0, &txs_ba).unwrap();
    assert_ne!(
        a.as_slice(),
        b.as_slice(),
        "swapping the order of inner txs must change the signed calldata",
    );
}

fn u256_be(v: u64) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[24..].copy_from_slice(&v.to_be_bytes());
    b
}

// =============================================================================
// parse_header
// =============================================================================

#[test]
fn negative_parse_header_truncated_rejected() {
    // 1 byte short of the required header → Truncated, *not* a panic
    // or silent default-fill.
    let wire = std::vec![0u8; USEROP_HEADER_LEN - 1];
    assert!(matches!(parse_header(&wire), Err(WireParseError::Truncated)));
}

#[test]
fn negative_parse_header_empty_rejected() {
    assert!(matches!(parse_header(&[]), Err(WireParseError::Truncated)));
}

#[test]
fn negative_parse_header_one_byte_short_of_each_field_rejected() {
    // Range-walk every length from 0..USEROP_HEADER_LEN. None of them
    // must parse — only the exact length (or more) is allowed.
    for len in 0..USEROP_HEADER_LEN {
        let wire = std::vec![0u8; len];
        assert!(
            matches!(parse_header(&wire), Err(WireParseError::Truncated)),
            "header parser accepted a buffer of length {len}, which is below USEROP_HEADER_LEN ({USEROP_HEADER_LEN})",
        );
    }
}

#[test]
fn negative_parse_header_chain_id_is_big_endian_not_little() {
    // If a refactor swapped to LE the wire would silently re-interpret
    // chain_ids — a cross-chain replay vector. Force BE by checking a
    // value that's distinguishable in either order.
    let mut wire = std::vec![0u8; USEROP_HEADER_LEN];
    // chain_id offset = 1 (has_bundle) + 20 (sender) + 20 (entry_point) = 41
    wire[41..49].copy_from_slice(&0x0001_0203_0405_0607u64.to_be_bytes());
    let parsed = parse_header(&wire).unwrap();
    assert_eq!(
        parsed.chain_id, 0x0001_0203_0405_0607,
        "chain_id must be parsed big-endian — any LE drift opens cross-chain replay",
    );
}

// =============================================================================
// compute_user_op_hash & compute_sphincs_digest_v06 — replay separation
// =============================================================================
//
// For each field that the EntryPoint v0.6 spec covers, flip it and
// confirm the hash differs. The on-chain `validateUserOp` ignores the
// keccak hash (the firmware signs `sphincsDigest`), but this hash is
// what RPCs / bundlers see — drift here breaks tooling. The sphincs
// digest variant is the *security-critical* one — any unbound field
// means a sig can be replayed with a different value of it.

#[test]
fn negative_userop_hash_binds_chain_id() {
    let p1 = baseline_params();
    let mut p2 = baseline_params();
    p2.chain_id = 8453;
    let cdh = [0xAA; 32];
    assert_ne!(compute_user_op_hash(&p1, &cdh), compute_user_op_hash(&p2, &cdh));
}

#[test]
fn negative_userop_hash_binds_entry_point() {
    let p1 = baseline_params();
    let mut p2 = baseline_params();
    p2.entry_point = [0xCC; 20];
    let cdh = [0xAA; 32];
    assert_ne!(compute_user_op_hash(&p1, &cdh), compute_user_op_hash(&p2, &cdh));
}

#[test]
fn negative_userop_hash_binds_call_data_hash() {
    let p = baseline_params();
    let a = [0xAA; 32];
    let b = [0xBB; 32];
    assert_ne!(compute_user_op_hash(&p, &a), compute_user_op_hash(&p, &b));
}

#[test]
fn negative_sphincs_digest_binds_every_field() {
    // Exhaustive: each AaUserOpParamsV06Sha256 field is individually
    // mutated and the resulting digest must differ. This is the
    // strongest replay-protection assertion in the suite.
    let base = baseline_v06_params();
    let cd = [0xAB; 32];
    let h0 = compute_sphincs_digest_v06(&base, &cd);

    let mut m = base.clone();
    m.sender[0] ^= 0xFF;
    assert_ne!(compute_sphincs_digest_v06(&m, &cd), h0, "sender unbound");

    let mut m = base.clone();
    m.entry_point[0] ^= 0xFF;
    assert_ne!(compute_sphincs_digest_v06(&m, &cd), h0, "entry_point unbound");

    let mut m = base.clone();
    m.chain_id = m.chain_id.wrapping_add(1);
    assert_ne!(compute_sphincs_digest_v06(&m, &cd), h0, "chain_id unbound");

    let mut m = base.clone();
    m.nonce.0[31] ^= 0x01;
    assert_ne!(compute_sphincs_digest_v06(&m, &cd), h0, "nonce unbound");

    let mut m = base.clone();
    m.init_code_digest[0] ^= 0xFF;
    assert_ne!(compute_sphincs_digest_v06(&m, &cd), h0, "init_code_digest unbound");

    let mut m = base.clone();
    m.call_gas_limit.0[31] ^= 0x01;
    assert_ne!(compute_sphincs_digest_v06(&m, &cd), h0, "call_gas_limit unbound");

    let mut m = base.clone();
    m.verification_gas_limit.0[31] ^= 0x01;
    assert_ne!(
        compute_sphincs_digest_v06(&m, &cd),
        h0,
        "verification_gas_limit unbound",
    );

    let mut m = base.clone();
    m.pre_verification_gas.0[31] ^= 0x01;
    assert_ne!(compute_sphincs_digest_v06(&m, &cd), h0, "pre_verification_gas unbound");

    let mut m = base.clone();
    m.max_fee_per_gas.0[31] ^= 0x01;
    assert_ne!(compute_sphincs_digest_v06(&m, &cd), h0, "max_fee_per_gas unbound");

    let mut m = base.clone();
    m.max_priority_fee_per_gas.0[31] ^= 0x01;
    assert_ne!(
        compute_sphincs_digest_v06(&m, &cd),
        h0,
        "max_priority_fee_per_gas unbound",
    );

    let mut m = base.clone();
    m.paymaster_and_data_digest[0] ^= 0xFF;
    assert_ne!(
        compute_sphincs_digest_v06(&m, &cd),
        h0,
        "paymaster_and_data_digest unbound",
    );

    // callData digest separately.
    let mut cd2 = cd;
    cd2[0] ^= 0xFF;
    assert_ne!(compute_sphincs_digest_v06(&base, &cd2), h0, "call_data_digest unbound");
}

#[test]
fn negative_sphincs_digest_field_order_matters() {
    // Two params with mirrored gas fields (e.g. callGasLimit and
    // verificationGasLimit swapped) must yield distinct digests. If
    // they collide, an attacker who controls one field can replay the
    // other.
    let mut a = baseline_v06_params();
    let mut b = baseline_v06_params();
    a.call_gas_limit = u256_from_u64(100_000);
    a.verification_gas_limit = u256_from_u64(200_000);
    b.call_gas_limit = u256_from_u64(200_000);
    b.verification_gas_limit = u256_from_u64(100_000);
    let cd = [0xAB; 32];
    assert_ne!(compute_sphincs_digest_v06(&a, &cd), compute_sphincs_digest_v06(&b, &cd));
}

// =============================================================================
// EIP-1271 typehashes & domain — these are the wallet's verifier ABI.
// Drifting them would invalidate every off-chain signature.
// =============================================================================

#[test]
fn negative_domain_separator_chain_id_is_uint256_not_address_slot() {
    // chainId lives at slot[3] right-padded into the low 8 bytes of a
    // uint256 slot. If a refactor accidentally wrote it into the
    // verifyingContract slot the separator would shift silently.
    let v = [0x01u8; 20];
    let d_chain1 = domain_separator(1, &v);
    // A chain_id whose BE bytes happen to overlap the verifyingContract
    // slot would collide only if the field was misplaced. Make sure
    // the value 1 in chain_id doesn't equal the value [0x01;20]+0 in
    // verifyingContract slot.
    let d_alt = domain_separator(0, &[0x01u8; 20]);
    assert_ne!(d_chain1, d_alt);
}

#[test]
fn negative_replay_safe_hash_changes_with_chain() {
    // Cross-chain replay protection for EIP-1271 signatures.
    let v = [0xAA; 20];
    assert_ne!(
        personal_sign_replay_safe_hash(1, &v, b"hello"),
        personal_sign_replay_safe_hash(2, &v, b"hello"),
    );
}

#[test]
fn negative_replay_safe_hash_changes_with_verifying_contract() {
    // Two wallets cannot share an EIP-1271 signature, even on the
    // same chain — Solady-nested EIP-712 binds `address(this)`.
    assert_ne!(
        personal_sign_replay_safe_hash(1, &[0xAA; 20], b"hello"),
        personal_sign_replay_safe_hash(1, &[0xBB; 20], b"hello"),
    );
}

#[test]
fn negative_proxy_address_zero_keys_not_special_cased() {
    // All-zero pk_seed + pk_root must still produce a valid address
    // (no special-case bypass that returns zero). If a refactor
    // short-circuits on a sentinel input, a wallet derived from that
    // sentinel collides with the bypass output.
    let zero = [0u8; 32];
    let addr = proxy_address(&zero, &zero);
    assert_ne!(addr, [0u8; 20], "proxy_address(0,0) must not return 0x00..00");
}

// =============================================================================
// ERC-6492 wrap_signature
// =============================================================================

#[test]
fn negative_eip6492_magic_suffix_exact() {
    // The magic suffix is what universal verifiers detect on. Drift =
    // every counterfactual signature stops validating.
    let fc = [0u8; EIP6492_FACTORY_CALLDATA_LEN];
    let inner = [0u8; EIP6492_INNER_WRAPPER_LEN];
    let mut blob = [0u8; EIP6492_BLOB_LEN];
    wrap_signature(&mut blob, &[0u8; 20], &fc, &inner);
    assert_eq!(
        &blob[blob.len() - 32..],
        &EIP6492_MAGIC,
        "ERC-6492 magic must be the 32-byte 0x6492…6492 suffix",
    );
    // Bytes are literally the repeating 0x6492 pattern.
    for chunk in EIP6492_MAGIC.chunks(2) {
        assert_eq!(chunk, [0x64, 0x92]);
    }
}

#[test]
fn negative_eip6492_has_magic_suffix_rejects_truncated() {
    assert!(!has_magic_suffix(&[]));
    assert!(!has_magic_suffix(&[0u8; 31]));
    // 32 bytes of zeros: same length as magic, but bytes wrong.
    assert!(!has_magic_suffix(&[0u8; 32]));
    // Magic but offset by one byte at the front: should still detect.
    let mut buf = [0u8; 33];
    buf[1..].copy_from_slice(&EIP6492_MAGIC);
    assert!(has_magic_suffix(&buf));
    // Magic in the middle, junk at the end: must not detect.
    let mut buf = [0u8; 64];
    buf[0..32].copy_from_slice(&EIP6492_MAGIC);
    assert!(!has_magic_suffix(&buf));
}

#[test]
fn negative_eip6492_wrap_panics_on_wrong_factory_calldata_len() {
    // Anything other than exactly EIP6492_FACTORY_CALLDATA_LEN bytes
    // would corrupt offsets and feed garbage to the universal
    // verifier. Refusal here is a `panic` (the assert in the helper);
    // that's the right behaviour for a programmer error.
    let result = std::panic::catch_unwind(|| {
        let fc = [0u8; EIP6492_FACTORY_CALLDATA_LEN - 1];
        let inner = [0u8; EIP6492_INNER_WRAPPER_LEN];
        let mut blob = [0u8; EIP6492_BLOB_LEN];
        wrap_signature(&mut blob, &[0u8; 20], &fc, &inner);
    });
    assert!(
        result.is_err(),
        "wrap_signature must panic on wrong factory_calldata length",
    );
}

#[test]
fn negative_eip6492_blob_address_padding_is_zero() {
    // ABI address slot is right-aligned; the top 12 bytes must be
    // zero. Anything else would let an attacker smuggle bytes through
    // the slot.
    let fc = [0xAAu8; EIP6492_FACTORY_CALLDATA_LEN];
    let inner = [0xBBu8; EIP6492_INNER_WRAPPER_LEN];
    let mut blob = [0u8; EIP6492_BLOB_LEN];
    wrap_signature(&mut blob, &[0x42; 20], &fc, &inner);
    assert!(blob[..12].iter().all(|&b| b == 0));
}

#[test]
fn negative_eip6492_factory_calldata_padding_is_zero() {
    // The 28-byte pad between fc end and innerSig length must be
    // zero so universal verifiers re-ABI-decode the tuple cleanly. A
    // non-zero pad would not break parsing (ABI ignores it), but
    // would leak whatever was on the stack before. Test the seal.
    let fc = [0xAAu8; EIP6492_FACTORY_CALLDATA_LEN];
    let inner = [0xBBu8; EIP6492_INNER_WRAPPER_LEN];
    let mut blob = [0xFFu8; EIP6492_BLOB_LEN]; // start with poison
    wrap_signature(&mut blob, &[0u8; 20], &fc, &inner);
    let pad_start = 128 + EIP6492_FACTORY_CALLDATA_LEN;
    let pad_end = 128 + EIP6492_FACTORY_CALLDATA_PADDED;
    assert!(
        blob[pad_start..pad_end].iter().all(|&b| b == 0),
        "factory_calldata pad must zero out poisoned stack bytes — no leakage into on-chain blob",
    );
}

#[test]
fn negative_eip6492_inner_sig_length_field_matches_constant() {
    // The on-wire length tag for innerSig must always equal
    // EIP6492_INNER_WRAPPER_LEN — if it drifted, universal verifiers
    // would slice the wrong byte range.
    let fc = [0u8; EIP6492_FACTORY_CALLDATA_LEN];
    let inner = [0u8; EIP6492_INNER_WRAPPER_LEN];
    let mut blob = [0u8; EIP6492_BLOB_LEN];
    wrap_signature(&mut blob, &[0u8; 20], &fc, &inner);
    let sig_len_off = 128 + EIP6492_FACTORY_CALLDATA_PADDED;
    let mut expected = [0u8; 32];
    let be = (EIP6492_INNER_WRAPPER_LEN as u64).to_be_bytes();
    expected[24..32].copy_from_slice(&be);
    assert_eq!(&blob[sig_len_off..sig_len_off + 32], &expected);
}
