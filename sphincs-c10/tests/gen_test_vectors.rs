//! Generate Rust-side C10 test vectors for the Solidity `SPHINCsC10Asm`
//! verifier. Produces a signature from a deterministic keypair + message,
//! runs the Rust verifier locally as a sanity check, and writes the
//! result to `../contracts/smart-wallet/test/c10_test_vectors.json` so
//! the forge test harness can load it with `vm.readFile`.
//!
//! Run with:
//!   cargo test -p sphincs-c10 --test gen_test_vectors --release -- --nocapture
//!
//! Release mode is strongly recommended — the hypertree keygen runs in
//! software sha2 and takes O(seconds) on a laptop, O(30+ s) in debug.

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
    // Bytes32-shaped hex: top N bytes populated, bottom 32-N bytes zero.
    let mut out = [0u8; 32];
    out[..N].copy_from_slice(val);
    to_hex(&out)
}

fn sha256_of(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Mirror of `PQSmartWallet.sphincsDigest(userOp)` under EntryPoint v0.6:
///   sha256(
///     sender || nonce || sha256(initCode) || sha256(callData) ||
///     callGasLimit || verificationGasLimit || preVerificationGas ||
///     maxFeePerGas || maxPriorityFeePerGas ||
///     sha256(paymasterAndData) || entryPoint || chainid
///   )
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

/// Build the calldata for `PQSmartWallet.execute(target, value, data)` with
/// `data == ""`. Selector `0xb61d27f6` matches `execute(address,uint256,bytes)`
/// — verified at runtime by the Foundry side via `abi.encodeCall`.
fn build_execute_calldata(target: [u8; 20], value: [u8; 32]) -> Vec<u8> {
    let mut cd = Vec::with_capacity(132);
    cd.extend_from_slice(&[0xb6, 0x1d, 0x27, 0xf6]);
    let mut a = [0u8; 32];
    a[12..].copy_from_slice(&target);
    cd.extend_from_slice(&a);
    cd.extend_from_slice(&value);
    let mut off = [0u8; 32];
    off[31] = 0x60;
    cd.extend_from_slice(&off);
    cd.extend_from_slice(&[0u8; 32]);
    cd
}

#[test]
fn generate_c10_test_vectors() {
    // Deterministic keypair so re-runs are bit-identical.
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

    println!("Running C10 hypertree keygen (this takes a few seconds)…");
    let sk = SigningKey::keygen(sk_seed, pk_seed);

    let msg: [u8; 32] = *b"PQSigner OS C10 Foundry test vec";
    assert_eq!(msg.len(), 32);

    println!("Signing…");
    let sig = sk.sign(&msg, None);
    assert_eq!(sig.len(), SIGNATURE_LEN, "sig must be 4008 bytes");

    // Self-verify sanity check.
    assert!(
        verify(sk.pk_seed(), sk.pk_root(), &msg, &sig),
        "Rust verify must accept freshly-generated sig"
    );

    // ── userOp-shaped vector for the wallet validateUserOp gas bench ──
    //
    // Fixed userOp shape (matches `PQSmartWallet.t.sol` bench):
    //   sender             = 0x000000000000000000000000000000000000beef
    //   nonce              = 0
    //   initCode           = ""
    //   callData           = execute(target=0xcafe, value=0, data="")
    //   callGasLimit       = 0
    //   verificationGasLimit = 0
    //   preVerificationGas = 0
    //   maxFeePerGas       = 0
    //   maxPriorityFeePerGas = 0
    //   paymasterAndData   = ""
    //   entryPoint         = 0x0000000000000000000000000000000000004337
    //   chainId            = 31337 (forge default)
    //
    // The slot pubkey installed at ownerIndex==1 is the same C10 keypair
    // as above, so we re-use `sk` for signing.
    let mut sender = [0u8; 20];
    sender[18] = 0xbe;
    sender[19] = 0xef;
    let nonce = [0u8; 32];
    let init_code: Vec<u8> = Vec::new();
    let mut target = [0u8; 20];
    target[18] = 0xca;
    target[19] = 0xfe;
    let call_data = build_execute_calldata(target, [0u8; 32]);
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

    println!("Signing userOp digest…");
    let user_op_sig = sk.sign(&user_op_digest, None);
    assert_eq!(user_op_sig.len(), SIGNATURE_LEN);
    assert!(
        verify(sk.pk_seed(), sk.pk_root(), &user_op_digest, &user_op_sig),
        "Rust verify must accept freshly-generated userOp sig"
    );

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
  }}
}}"#,
        pad_to_b32_hex(sk.pk_seed()),
        pad_to_b32_hex(sk.pk_root()),
        to_hex(&msg),
        to_hex(&sig),
        sig.len(),
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
    );

    let out_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../contracts/smart-wallet/test/c10_test_vectors.json"
    );
    fs::write(out_path, &json).expect("write c10 test vectors");
    println!("Wrote C10 vectors to {}", out_path);
}
