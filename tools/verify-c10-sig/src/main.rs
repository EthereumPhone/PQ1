//! Offline cryptographic verification of the C10 Type-2 signature that the
//! pq1 board produced over USB HID.
//!
//! The on-device test proved the response was WELL-FORMED (4148 B, wrapper
//! ownerIndex=1, offset 0x40, length 4008, non-degenerate body). That is not
//! the same as VALID. This binary closes that gap by rebuilding the exact
//! signed preimage with the firmware's own host-linkable code and checking
//! the signature against the public key derived from the `e2e-test` fixed
//! mnemonic.
//!
//! WHY THE FIRMWARE'S OWN FUNCTIONS: `compute_sphincs_digest_v06`,
//! `reconstruct_execute_calldata` and `derive_c10_slot_keypair` are the exact
//! functions `cmd_sign_userop.rs` calls (see its :2007, :2344, :2377-2389).
//! Re-deriving the preimage by hand from the spec would test my reading of
//! the docs, not the device.
//!
//! NEGATIVE CONTROLS ARE MANDATORY HERE. A harness that can only print PASS
//! proves nothing about its own discriminating power, and this whole session
//! has repeatedly produced "evidence" from checks that could not have failed.
//! So every signature is ALSO checked against a corrupted digest and against
//! the other capture's key material; those MUST fail. If a tampered input
//! verifies, the harness is broken and the PASS is void.

use pqsigner_aa::userop::{
    compute_sphincs_digest_v06, reconstruct_execute_calldata, sha256_bytes,
    AaUserOpParamsV06Sha256, ENTRY_POINT_V06, SHA256_EMPTY,
};
use pqsigner_domain::{derive_c10_slot_keypair, slot_master_entropy_from_bip39};
use pqsigner_tx_core::eip1559::{Eip1559Tx, U256};
use sphincs_c10::params::SIGNATURE_LEN;
use sphincs_tz_bip39::Mnemonic;

// ── exactly what hid_sign.py sent ───────────────────────────────────────
const CHAIN_ID: u64 = 84_532;
const SLOT_INDEX: u32 = 0;
const ACCOUNT_INDEX: u32 = 0;
const OWNER_INDEX: u64 = SLOT_INDEX as u64 + 1; // cmd_sign_userop.rs:1889
const NEW_OFFCHAIN_COUNT: u64 = 0; // device echoed 0
const NONCE: u64 = 0;
const CALL_GAS: u64 = 50_000;
const VER_GAS: u64 = 800_000;
const PRE_VER_GAS: u64 = 150_000;
const MAX_FEE: u64 = 1_000_000_000;
const MAX_PRIORITY_FEE: u64 = 100_000_000;
const VALUE_WEI: u64 = 1_000_000_000_000_000;
const TO_ADDRESS: [u8; 20] = [0x11; 20];
/// Device-reported CREATE2 prediction for account 0 (GET_WALLET_ADDRESS).
const SENDER_HEX: &str = "bee6a6e73e418d42ef382ecf8e8025740e97c2fe";

/// `e2e-test` auto-provisioning mnemonic (secure/src/main.rs:3607-3610) —
/// the standard all-zeros BIP-39 vector. A published test vector, not a key.
const E2E_WORDS: [&str; 24] = [
    "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
    "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
    "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "art",
];

fn u256_from_u64(v: u64) -> U256 {
    let mut w = [0u8; 32];
    w[24..32].copy_from_slice(&v.to_be_bytes());
    U256(w)
}

/// Rebuild the 32-byte digest the firmware signed, via its own code path.
fn signed_digest(sender: [u8; 20]) -> [u8; 32] {
    // reconstruct_execute_calldata reads ONLY tx.to and tx.value (verified at
    // aa/src/userop.rs:175-192); every other field is inert for the calldata,
    // so zeros here cannot perturb the digest.
    let tx = Eip1559Tx {
        chain_id: CHAIN_ID,
        nonce: NONCE,
        max_priority_fee_per_gas: u256_from_u64(MAX_PRIORITY_FEE),
        max_fee_per_gas: u256_from_u64(MAX_FEE),
        gas_limit: CALL_GAS,
        to: Some(TO_ADDRESS),
        value: u256_from_u64(VALUE_WEI),
        data_len: 0,
        access_list_count: 0,
        signing_hash: [0u8; 32],
        userop_fields: None,
    };

    let exec = reconstruct_execute_calldata(OWNER_INDEX, NEW_OFFCHAIN_COUNT, &tx, &[])
        .expect("execute calldata reconstruction failed");
    let call_digest = sha256_bytes(exec.as_slice());

    let params = AaUserOpParamsV06Sha256 {
        sender,
        entry_point: ENTRY_POINT_V06,
        chain_id: CHAIN_ID,
        nonce: u256_from_u64(NONCE),
        // include_init_code = false -> SHA256_EMPTY (cmd_sign_userop.rs:2345)
        init_code_digest: SHA256_EMPTY,
        call_gas_limit: u256_from_u64(CALL_GAS),
        verification_gas_limit: u256_from_u64(VER_GAS),
        pre_verification_gas: u256_from_u64(PRE_VER_GAS),
        max_fee_per_gas: u256_from_u64(MAX_FEE),
        max_priority_fee_per_gas: u256_from_u64(MAX_PRIORITY_FEE),
        // hid_sign.py sent sha256("") as paymaster_and_data_hash
        paymaster_and_data_digest: SHA256_EMPTY,
    };
    compute_sphincs_digest_v06(&params, &call_digest)
}

/// Pull the 4008-byte C10 signature out of a 4148-byte device response.
fn extract_sig(resp: &[u8]) -> [u8; SIGNATURE_LEN] {
    assert_eq!(resp.len(), 4148, "unexpected response length");
    let init_len = u32::from_be_bytes(resp[8..12].try_into().unwrap()) as usize;
    assert_eq!(init_len, 0, "expected no initCode");
    let mut off = 12 + init_len;
    let t1_len = u32::from_be_bytes(resp[off..off + 4].try_into().unwrap()) as usize;
    assert_eq!(t1_len, 0, "expected no Type-1");
    off += 4 + t1_len;
    let t2_len = u32::from_be_bytes(resp[off..off + 4].try_into().unwrap()) as usize;
    assert_eq!(t2_len, 4128, "expected a 4128-byte Type-2 wrapper");
    off += 4;
    let wrapper = &resp[off..off + t2_len];
    // abi.encode(uint256 ownerIndex, bytes c10Sig): ownerIndex | 0x40 | len | sig
    let sig_len = u32::from_be_bytes(wrapper[92..96].try_into().unwrap()) as usize;
    assert_eq!(sig_len, SIGNATURE_LEN, "wrapper declares wrong sig length");
    let mut sig = [0u8; SIGNATURE_LEN];
    sig.copy_from_slice(&wrapper[96..96 + SIGNATURE_LEN]);
    sig
}

fn main() {
    let mut sender = [0u8; 20];
    hex::decode_to_slice(SENDER_HEX, &mut sender).expect("bad sender hex");

    // ── derive the expected slot public key from the fixed mnemonic ──
    let mnemonic = Mnemonic::from_words(&E2E_WORDS).expect("e2e mnemonic rejected");
    let bip39_seed = mnemonic.to_seed("");
    let slot_master = slot_master_entropy_from_bip39(&bip39_seed, ACCOUNT_INDEX);
    println!("==> deriving slot keypair (chain {CHAIN_ID}, slot {SLOT_INDEX}) ...");
    let (sk, _pk_seed_32, _pk_root_32) = derive_c10_slot_keypair(&slot_master, CHAIN_ID, SLOT_INDEX);
    let vk = sk.verifying_key();
    println!("    pk_seed = {}", hex::encode(vk.pk_seed));
    println!("    pk_root = {}", hex::encode(vk.pk_root));

    // Wrong-key control: a genuinely valid keypair for a DIFFERENT slot.
    // Stronger than bit-flipping pk_root, which could fail for the wrong
    // reason (malformed key rather than wrong key).
    let (sk_other, _, _) = derive_c10_slot_keypair(&slot_master, CHAIN_ID, SLOT_INDEX + 1);
    let vk_other = sk_other.verifying_key();

    let digest = signed_digest(sender);
    println!("    signed digest = {}", hex::encode(digest));

    // A wrong digest, for the negative control.
    let mut bad_digest = digest;
    bad_digest[0] ^= 0x01;

    let mut failures: Vec<String> = Vec::new();
    let mut verified = 0usize;

    // Response files come from `tools/hid_sign.py --out FILE`. Take them as
    // arguments so the tool works from any directory; the defaults are only
    // a convenience for the common "ran it next to the repo" case.
    let args: Vec<String> = std::env::args().skip(1).collect();
    let paths: Vec<String> = if args.is_empty() {
        vec!["sign_response_1.bin".into(), "sign_response_2.bin".into()]
    } else {
        args
    };
    println!("\n==> checking {} response file(s)", paths.len());

    for path in &paths {
        let name = path.rsplit('/').next().unwrap_or(path);
        let Ok(resp) = std::fs::read(path) else {
            println!("\n-- {path}: NOT FOUND, skipping");
            continue;
        };
        let sig = extract_sig(&resp);
        println!("\n-- {name}");
        println!("   sig[0..16] = {}", hex::encode(&sig[..16]));

        // POSITIVE: the real digest must verify.
        let ok = vk.verify(&digest, &sig);
        println!("   {}  verify(correct digest)      = {ok}", if ok { "OK  " } else { "FAIL" });
        if ok {
            verified += 1;
        } else {
            failures.push(format!("{name}: signature did NOT verify"));
        }

        // NEGATIVE 1: one flipped bit in the message must break it.
        let bad = vk.verify(&bad_digest, &sig);
        println!("   {}  verify(1-bit-wrong digest)  = {bad}  (must be false)",
                 if bad { "FAIL" } else { "OK  " });
        if bad {
            failures.push(format!("{name}: CONTROL BROKEN — wrong digest still verified"));
        }

        // NEGATIVE 2: a corrupted signature must break it.
        let mut tampered = sig;
        tampered[100] ^= 0xFF;
        let t = vk.verify(&digest, &tampered);
        println!("   {}  verify(tampered signature)  = {t}  (must be false)",
                 if t { "FAIL" } else { "OK  " });
        if t {
            failures.push(format!("{name}: CONTROL BROKEN — tampered sig still verified"));
        }

        // NEGATIVE 3: a wrong public key must break it.
        let k = vk_other.verify(&digest, &sig);
        println!("   {}  verify(valid key, wrong slot)= {k}  (must be false)",
                 if k { "FAIL" } else { "OK  " });
        if k {
            failures.push(format!("{name}: CONTROL BROKEN — another slot's key verified it"));
        }
    }

    println!();
    if verified == 0 {
        println!("=== FAIL === no signature verified");
    }
    if failures.is_empty() && verified > 0 {
        println!("=== PASS === {verified} device signature(s) cryptographically VALID");
        println!("    against the key derived from the e2e-test mnemonic,");
        println!("    with all negative controls correctly failing.");
        std::process::exit(0);
    }
    println!("=== PROBLEMS ===");
    for f in &failures {
        println!("  - {f}");
    }
    std::process::exit(1);
}
