//! Generate Rust-side C10 test vectors for the Solidity `SPHINCsC10Asm`
//! verifier. Produces a battery of signed messages + edge-case
//! mutations from a deterministic keypair. Writes
//! `../contracts/smart-wallet/test/c10_test_vectors.json` for the
//! forge test harness.
//!
//! Run with:
//!   cargo test -p sphincs-c10 --test gen_test_vectors --release -- --nocapture
//!
//! Release mode is strongly recommended — the hypertree keygen runs in
//! software sha2 and takes O(seconds) on a laptop, O(30+ s) in debug.
//!
//! Schema (extended 2026-05-11):
//!   {
//!     "pkSeed", "pkRoot", "message", "signature", "sigLen":
//!         — legacy single-vector fields (still consumed by existing
//!           SPHINCsC10Asm.t.sol and PQSmartWalletRealSig.t.sol).
//!     "userOpBench": { ... } — kept verbatim; consumed by
//!         PQSmartWalletRealSig.t.sol.
//!     "vectors": [ {label, pkSeed, pkRoot, message, signature, expectValid}, ... ]
//!         — NEW: 10 edge-case vectors for the multi-vector Foundry
//!         loop in SPHINCsC10AsmTest.testAllKatVectors.
//!   }

use sha2::{Digest, Sha256};
use sphincs_c10::params::{N, SIGNATURE_LEN};
use sphincs_c10::{verify, SigningKey};
use std::fs;

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::from("0x");
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn pad_to_b32_hex(val: &[u8; N]) -> String {
    let mut out = [0u8; 32];
    out[..N].copy_from_slice(val);
    to_hex(&out)
}

fn sha256_of(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

#[allow(clippy::too_many_arguments)]
fn sphincs_digest(
    sender: &[u8; 20],
    nonce: &[u8; 32],
    init_code: &[u8],
    call_data: &[u8],
    call_gas_limit: &[u8; 32],
    verification_gas_limit: &[u8; 32],
    pre_verification_gas: &[u8; 32],
    max_fee_per_gas: &[u8; 32],
    max_priority_fee_per_gas: &[u8; 32],
    paymaster_and_data: &[u8],
    entry_point: &[u8; 20],
    chain_id: &[u8; 32],
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(360);
    buf.extend_from_slice(sender);
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(&sha256_of(init_code));
    buf.extend_from_slice(&sha256_of(call_data));
    buf.extend_from_slice(call_gas_limit);
    buf.extend_from_slice(verification_gas_limit);
    buf.extend_from_slice(pre_verification_gas);
    buf.extend_from_slice(max_fee_per_gas);
    buf.extend_from_slice(max_priority_fee_per_gas);
    buf.extend_from_slice(&sha256_of(paymaster_and_data));
    buf.extend_from_slice(entry_point);
    buf.extend_from_slice(chain_id);
    sha256_of(&buf)
}

fn build_execute_calldata(
    owner_index: u64,
    new_offchain_count: u64,
    target: [u8; 20],
    value: [u8; 32],
) -> Vec<u8> {
    let mut cd = Vec::with_capacity(196);
    cd.extend_from_slice(&[0x14, 0x44, 0x3c, 0x57]);
    let mut oi = [0u8; 32];
    oi[24..].copy_from_slice(&owner_index.to_be_bytes());
    cd.extend_from_slice(&oi);
    let mut oc = [0u8; 32];
    oc[24..].copy_from_slice(&new_offchain_count.to_be_bytes());
    cd.extend_from_slice(&oc);
    let mut a = [0u8; 32];
    a[12..].copy_from_slice(&target);
    cd.extend_from_slice(&a);
    cd.extend_from_slice(&value);
    let mut off = [0u8; 32];
    off[31] = 0xa0;
    cd.extend_from_slice(&off);
    cd.extend_from_slice(&[0u8; 32]);
    cd
}

/// One self-describing vector entry. `expectValid` is the result the
/// Yul verifier (and our Lean spec) MUST produce on this `(pkSeed,
/// pkRoot, message, signature)` triple. A `false` here can be either a
/// clean `false` return or a revert — the Foundry harness's
/// `_verifyRejected` helper treats both equally.
#[derive(Debug)]
struct Vector {
    label: String,
    pk_seed_b32: String,
    pk_root_b32: String,
    message_b32: String,
    signature: Vec<u8>,
    expect_valid: bool,
}

fn to_vector_json(v: &Vector) -> String {
    format!(
        r#"    {{"label": "{}", "pkSeed": "{}", "pkRoot": "{}", "message": "{}", "signature": "{}", "expectValid": {}}}"#,
        v.label,
        v.pk_seed_b32,
        v.pk_root_b32,
        v.message_b32,
        to_hex(&v.signature),
        v.expect_valid
    )
}

#[test]
fn generate_c10_test_vectors() {
    // ── Deterministic keypair ──
    let sk_seed: [u8; 32] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01,
    ];
    let pk_seed: [u8; N] = [
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    ];

    println!("Running C10 hypertree keygen…");
    let sk = SigningKey::keygen(sk_seed, pk_seed);

    let pk_seed_b32 = pad_to_b32_hex(sk.pk_seed());
    let pk_root_b32 = pad_to_b32_hex(sk.pk_root());

    // ── Legacy single-vector message (kept verbatim for backward-
    //    compat with existing tests) ──
    let msg: [u8; 32] = *b"PQSigner OS C10 Foundry test vec";
    let legacy_sig = sk.sign(&msg, None);
    assert!(verify(sk.pk_seed(), sk.pk_root(), &msg, &legacy_sig));
    assert_eq!(legacy_sig.len(), SIGNATURE_LEN);

    // ── Multi-vector battery ──
    let mut vectors: Vec<Vector> = Vec::new();

    // 1-4: Four valid signatures over distinct messages.
    // Each message is exactly 32 bytes (no NUL terminator).
    let valid_messages: [[u8; 32]; 4] = [
        *b"PQSigner OS C10 Foundry test vec",
        *b"PQSigner C10 multi-vec test #002",
        *b"PQSigner C10 multi-vec test #003",
        *b"PQSigner C10 multi-vec test #004",
    ];
    for (idx, msg) in valid_messages.iter().enumerate() {
        let sig = sk.sign(msg, None);
        assert!(verify(sk.pk_seed(), sk.pk_root(), msg, &sig));
        vectors.push(Vector {
            label: format!("valid-{}", idx + 1),
            pk_seed_b32: pk_seed_b32.clone(),
            pk_root_b32: pk_root_b32.clone(),
            message_b32: to_hex(msg),
            signature: sig.to_vec(),
            expect_valid: true,
        });
    }

    // Take vector 1 as the "base" for mutations.
    let base_msg: [u8; 32] = valid_messages[0];
    let base_sig: Vec<u8> = vectors[0].signature.clone();

    // 5: Wrong message. Same sig, different message — digest differs,
    //    indices differ, almost-certainly fails.
    let wrong_msg: [u8; 32] = *b"This is definitely not the msg!!";
    assert!(!verify(sk.pk_seed(), sk.pk_root(), &wrong_msg, &base_sig.clone().try_into().unwrap()));
    vectors.push(Vector {
        label: "wrong-message".to_string(),
        pk_seed_b32: pk_seed_b32.clone(),
        pk_root_b32: pk_root_b32.clone(),
        message_b32: to_hex(&wrong_msg),
        signature: base_sig.clone(),
        expect_valid: false,
    });

    // 6: Wrong root. Same sig + message, different pkRoot.
    let mut wrong_root_bytes = [0u8; 32];
    wrong_root_bytes[0] = 0x01;
    vectors.push(Vector {
        label: "wrong-root".to_string(),
        pk_seed_b32: pk_seed_b32.clone(),
        pk_root_b32: to_hex(&wrong_root_bytes),
        message_b32: to_hex(&base_msg),
        signature: base_sig.clone(),
        expect_valid: false,
    });

    // 7: Mutated R (first 16 bytes). Changes the H_msg digest →
    //    forced-zero check almost certainly fails.
    let mut mutated_r = base_sig.clone();
    for byte in mutated_r.iter_mut().take(N) {
        *byte ^= 0xFF;
    }
    vectors.push(Vector {
        label: "mutated-R".to_string(),
        pk_seed_b32: pk_seed_b32.clone(),
        pk_root_b32: pk_root_b32.clone(),
        message_b32: to_hex(&base_msg),
        signature: mutated_r,
        expect_valid: false,
    });

    // 8: Mutated FORS auth path (deep in the FORS section, around
    //    offset 2300). Changes a Merkle node inside FORS → reconstructed
    //    fors_pk differs → fors_pk ↛ slot pk → hypertree verify fails.
    let mut mutated_fors = base_sig.clone();
    mutated_fors[2300] ^= 0xFF;
    vectors.push(Vector {
        label: "mutated-FORS-auth".to_string(),
        pk_seed_b32: pk_seed_b32.clone(),
        pk_root_b32: pk_root_b32.clone(),
        message_b32: to_hex(&base_msg),
        signature: mutated_fors,
        expect_valid: false,
    });

    // 9: Mutated WOTS sigma (layer 0, around offset 2500). Changes
    //    one of the 43 WOTS chain values → wots_pk differs → Merkle
    //    walk yields wrong subtree root.
    let mut mutated_wots = base_sig.clone();
    mutated_wots[2500] ^= 0xFF;
    vectors.push(Vector {
        label: "mutated-WOTS-sigma".to_string(),
        pk_seed_b32: pk_seed_b32.clone(),
        pk_root_b32: pk_root_b32.clone(),
        message_b32: to_hex(&base_msg),
        signature: mutated_wots,
        expect_valid: false,
    });

    // 10: Mutated WOTS count (layer 0, offset = 2336 + 43*16 = 3024).
    //     The count is the C10 grinder's success witness; mutating it
    //     makes the digit-sum fail the TARGET_SUM=205 check → Yul
    //     reverts via `eq(digitSum, 205)` at SPHINCsC10Asm.sol:139.
    let mut mutated_count = base_sig.clone();
    let count_offset = 2336 + 43 * 16; // 3024
    mutated_count[count_offset] ^= 0xFF;
    mutated_count[count_offset + 1] ^= 0xFF;
    mutated_count[count_offset + 2] ^= 0xFF;
    mutated_count[count_offset + 3] ^= 0xFF;
    vectors.push(Vector {
        label: "mutated-WOTS-count-target-sum-fail".to_string(),
        pk_seed_b32: pk_seed_b32.clone(),
        pk_root_b32: pk_root_b32.clone(),
        message_b32: to_hex(&base_msg),
        signature: mutated_count,
        expect_valid: false,
    });

    // Sanity-check: every "expectValid: false" vector must actually
    // be rejected by the Rust verifier — otherwise we'd be shipping a
    // false-negative test case.
    for v in &vectors {
        if v.expect_valid {
            continue;
        }
        let sig_arr: &[u8; SIGNATURE_LEN] = v
            .signature
            .as_slice()
            .try_into()
            .expect("sig must be 4008 bytes");
        let msg_bytes: [u8; 32] = hex_decode_32(&v.message_b32);
        let pk_seed_inner = pad32_to_n16(&v.pk_seed_b32);
        let pk_root_inner = pad32_to_n16(&v.pk_root_b32);
        let result = verify(&pk_seed_inner, &pk_root_inner, &msg_bytes, sig_arr);
        assert!(
            !result,
            "Vector '{}' was declared invalid but Rust verifier accepts it",
            v.label
        );
    }

    println!("All {} test vectors validated.", vectors.len());

    // ── userOpBench (legacy, kept verbatim) ──
    let mut sender = [0u8; 20];
    sender[18] = 0xbe;
    sender[19] = 0xef;
    let nonce = [0u8; 32];
    let init_code: Vec<u8> = Vec::new();
    let mut target = [0u8; 20];
    target[18] = 0xca;
    target[19] = 0xfe;
    let call_data = build_execute_calldata(1, 0, target, [0u8; 32]);
    let call_gas_limit = [0u8; 32];
    let verification_gas_limit = [0u8; 32];
    let pre_verification_gas = [0u8; 32];
    let max_fee_per_gas = [0u8; 32];
    let max_priority_fee_per_gas = [0u8; 32];
    let paymaster_and_data: Vec<u8> = Vec::new();
    let mut entry_point = [0u8; 20];
    entry_point[18] = 0x43;
    entry_point[19] = 0x37;
    let mut chain_id = [0u8; 32];
    chain_id[28..].copy_from_slice(&31337u32.to_be_bytes());

    let user_op_digest = sphincs_digest(
        &sender,
        &nonce,
        &init_code,
        &call_data,
        &call_gas_limit,
        &verification_gas_limit,
        &pre_verification_gas,
        &max_fee_per_gas,
        &max_priority_fee_per_gas,
        &paymaster_and_data,
        &entry_point,
        &chain_id,
    );

    let user_op_sig = sk.sign(&user_op_digest, None);

    let vectors_json: String = vectors
        .iter()
        .map(to_vector_json)
        .collect::<Vec<_>>()
        .join(",\n");

    let json = format!(
        r#"{{
  "pkSeed": "{}",
  "pkRoot": "{}",
  "message": "{}",
  "signature": "{}",
  "sigLen": {},
  "userOpBench": {{
    "sender": "{}",
    "nonce": "{}",
    "callData": "{}",
    "callGasLimit": "{}",
    "verificationGasLimit": "{}",
    "preVerificationGas": "{}",
    "maxFeePerGas": "{}",
    "maxPriorityFeePerGas": "{}",
    "entryPoint": "{}",
    "chainId": 31337,
    "digest": "{}",
    "signature": "{}"
  }},
  "vectors": [
{}
  ]
}}"#,
        pk_seed_b32,
        pk_root_b32,
        to_hex(&base_msg),
        to_hex(&base_sig),
        base_sig.len(),
        to_hex(&sender),
        to_hex(&nonce),
        to_hex(&call_data),
        to_hex(&call_gas_limit),
        to_hex(&verification_gas_limit),
        to_hex(&pre_verification_gas),
        to_hex(&max_fee_per_gas),
        to_hex(&max_priority_fee_per_gas),
        to_hex(&entry_point),
        to_hex(&user_op_digest),
        to_hex(&user_op_sig),
        vectors_json,
    );

    let out_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../contracts/smart-wallet/test/c10_test_vectors.json"
    );
    fs::write(out_path, &json).expect("write c10 test vectors");
    println!("Wrote {} vectors to {}", vectors.len(), out_path);
}

/// Helper: decode a `0x`-prefixed 64-hex-char string to a 32-byte array.
fn hex_decode_32(s: &str) -> [u8; 32] {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(hex).expect("valid hex");
    assert_eq!(bytes.len(), 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

/// Helper: read top N bytes from a `0x`-prefixed 32-byte hex string.
fn pad32_to_n16(s: &str) -> [u8; N] {
    let full = hex_decode_32(s);
    let mut out = [0u8; N];
    out.copy_from_slice(&full[..N]);
    out
}
