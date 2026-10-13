//! `verify-c10-sig rotation` — what a seedless companion must do with a
//! protocol-0x0203 slot-rotation response (#353), checked against the
//! firmware's own host-linkable code.
//!
//! The response's Type-1 section is `new_owner_bytes(64) || wrapper(4128)`.
//! This mode:
//!
//! 1. rebuilds the Type-1 UserOp from the returned owner bytes
//!    (`callData = addOwnerBytes(owner)`, nonce = base, no initCode, no
//!    paymaster, the request's gas words) and verifies the bootstrap
//!    signature against the wallet's bootstrap public key;
//! 2. verifies the Type-2 signature (nonce = base + 1, ownerIndex =
//!    slot + 1, `executeWithOffchainCount` of a plain value transfer)
//!    against the public key carried in the owner bytes;
//! 3. runs MANDATORY negative controls: a flipped owner byte, a wrong
//!    nonce and a wrong key must each fail.
//!
//! The bootstrap public key comes either from the fixed `e2e-test`
//! mnemonic (`e2e`, which additionally checks the owner bytes equal the
//! independently derived slot key) or from a `GET_INIT_CODE` response
//! (`initcode=FILE`, bytes `[24..56)` / `[56..88)` = masterPkSeed /
//! masterPkRoot), which needs no seed and works against a real wallet.
//!
//! Usage:
//!   verify-c10-sig rotation RESP.bin chain=N slot=N sender=HEX nonce=N
//!       to=HEX value=WEI gas=CGL,VGL,PVG,MAXFEE,MAXPRIO
//!       [account=N] [paymaster=HEX32] (e2e | initcode=FILE)

use pqsigner_aa::userop::{
    add_owner_bytes_calldata, compute_sphincs_digest_v06, reconstruct_execute_calldata,
    sha256_bytes, AaUserOpParamsV06Sha256, ENTRY_POINT_V06, SHA256_EMPTY,
};
use pqsigner_domain::{
    derive_c10_master_keypair_from_entropy, derive_c10_slot_keypair,
    slot_master_entropy_from_bip39,
};
use pqsigner_tx_core::eip1559::{Eip1559Tx, U256};
use sphincs_c10::params::SIGNATURE_LEN;
use sphincs_c10::VerifyingKey;
use sphincs_tz_bip39::Mnemonic;

const OWNER_LEN: usize = 64;
const WRAPPER_LEN: usize = 4128;
const T1_SECTION_LEN: usize = OWNER_LEN + WRAPPER_LEN;

struct Args {
    resp: Vec<u8>,
    chain: u64,
    account: u32,
    slot: u32,
    sender: [u8; 20],
    nonce: u64,
    to: [u8; 20],
    value: u128,
    gas: [u64; 5],
    paymaster: [u8; 32],
    e2e: bool,
    initcode: Option<Vec<u8>>,
}

fn word_u64(v: u64) -> U256 {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    U256(w)
}

fn word_u128(v: u128) -> U256 {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    U256(w)
}

fn hex_fixed<const L: usize>(s: &str) -> [u8; L] {
    let mut out = [0u8; L];
    hex::decode_to_slice(s.trim_start_matches("0x"), &mut out)
        .unwrap_or_else(|_| panic!("expected {L}-byte hex, got {s}"));
    out
}

fn parse(argv: &[String]) -> Args {
    let mut it = argv.iter();
    let resp_path = it.next().expect("missing RESP.bin");
    let resp = std::fs::read(resp_path).unwrap_or_else(|e| panic!("{resp_path}: {e}"));
    let mut a = Args {
        resp,
        chain: 0,
        account: 0,
        slot: 0,
        sender: [0; 20],
        nonce: 0,
        to: [0; 20],
        value: 0,
        gas: [0; 5],
        paymaster: SHA256_EMPTY,
        e2e: false,
        initcode: None,
    };
    let mut seen = 0u32;
    for kv in it {
        if kv == "e2e" {
            a.e2e = true;
            continue;
        }
        let (k, v) = kv.split_once('=').unwrap_or_else(|| panic!("bad argument {kv}"));
        match k {
            "chain" => { a.chain = v.parse().expect("chain"); seen |= 1; }
            "slot" => { a.slot = v.parse().expect("slot"); seen |= 2; }
            "sender" => { a.sender = hex_fixed(v); seen |= 4; }
            "nonce" => { a.nonce = v.parse().expect("nonce"); seen |= 8; }
            "to" => { a.to = hex_fixed(v); seen |= 16; }
            "value" => { a.value = v.parse().expect("value"); seen |= 32; }
            "gas" => {
                let parts: Vec<u64> = v.split(',').map(|p| p.parse().expect("gas word")).collect();
                assert_eq!(parts.len(), 5, "gas=CGL,VGL,PVG,MAXFEE,MAXPRIO");
                a.gas.copy_from_slice(&parts);
                seen |= 64;
            }
            "account" => a.account = v.parse().expect("account"),
            "paymaster" => a.paymaster = hex_fixed(v),
            "initcode" => a.initcode = Some(std::fs::read(v).unwrap_or_else(|e| panic!("{v}: {e}"))),
            _ => panic!("unknown argument {k}"),
        }
    }
    assert_eq!(seen, 127, "chain, slot, sender, nonce, to, value and gas are all required");
    assert!(a.e2e ^ a.initcode.is_some(), "pass exactly one of `e2e` or `initcode=FILE`");
    assert!(a.slot >= 1, "rotation targets slot >= 1");
    a
}

fn be32(b: &[u8], off: usize) -> usize {
    u32::from_be_bytes(b[off..off + 4].try_into().unwrap()) as usize
}

fn wrapper_sig(wrapper: &[u8], want_owner_index: u64) -> [u8; SIGNATURE_LEN] {
    assert_eq!(wrapper.len(), WRAPPER_LEN);
    assert!(wrapper[..24].iter().all(|&b| b == 0));
    let idx = u64::from_be_bytes(wrapper[24..32].try_into().unwrap());
    assert_eq!(idx, want_owner_index, "wrapper ownerIndex");
    assert_eq!(be32(wrapper, 92), SIGNATURE_LEN, "wrapper sig length");
    let mut sig = [0u8; SIGNATURE_LEN];
    sig.copy_from_slice(&wrapper[96..96 + SIGNATURE_LEN]);
    sig
}

fn vk_from_words(seed32: &[u8], root32: &[u8]) -> VerifyingKey {
    let mut b = [0u8; 32];
    b[..16].copy_from_slice(&seed32[..16]);
    b[16..].copy_from_slice(&root32[..16]);
    VerifyingKey::from_bytes(&b)
}

#[allow(clippy::too_many_arguments)]
fn userop_digest(
    a: &Args,
    nonce: u64,
    call: &[u8],
    paymaster: [u8; 32],
) -> [u8; 32] {
    let params = AaUserOpParamsV06Sha256 {
        sender: a.sender,
        entry_point: ENTRY_POINT_V06,
        chain_id: a.chain,
        nonce: word_u64(nonce),
        init_code_digest: SHA256_EMPTY,
        call_gas_limit: word_u64(a.gas[0]),
        verification_gas_limit: word_u64(a.gas[1]),
        pre_verification_gas: word_u64(a.gas[2]),
        max_fee_per_gas: word_u64(a.gas[3]),
        max_priority_fee_per_gas: word_u64(a.gas[4]),
        paymaster_and_data_digest: paymaster,
    };
    compute_sphincs_digest_v06(&params, &sha256_bytes(call))
}

pub fn run(argv: &[String]) -> ! {
    let a = parse(argv);
    let r = &a.resp;
    let mut failures: Vec<String> = Vec::new();
    let mut check = |ok: bool, what: &str, must: bool| {
        let pass = ok == must;
        println!("   {}  {what} = {ok}{}", if pass { "OK  " } else { "FAIL" },
                 if must { "" } else { "  (must be false)" });
        if !pass {
            failures.push(what.to_string());
        }
    };

    // ── response shape (0x0203) ──
    let count = u64::from_be_bytes(r[0..8].try_into().unwrap());
    assert_eq!(be32(r, 8), 0, "rotation never carries initCode");
    let t1_len = be32(r, 12);
    assert_eq!(t1_len, T1_SECTION_LEN, "0x0203 Type-1 section must be 4192 bytes");
    let owner: [u8; OWNER_LEN] = r[16..16 + OWNER_LEN].try_into().unwrap();
    let t1_sig = wrapper_sig(&r[16 + OWNER_LEN..16 + T1_SECTION_LEN], 0);
    let t2_off = 16 + T1_SECTION_LEN;
    assert_eq!(be32(r, t2_off), WRAPPER_LEN);
    assert_eq!(r.len(), t2_off + 4 + WRAPPER_LEN, "trailing bytes after Type-2");
    let t2_sig = wrapper_sig(&r[t2_off + 4..], u64::from(a.slot) + 1);
    println!("==> rotation response: {} bytes, off-chain count {count}", r.len());
    println!("    new owner pkSeed = {}", hex::encode(&owner[..32]));
    println!("    new owner pkRoot = {}", hex::encode(&owner[32..]));
    assert!(owner[16..32].iter().all(|&b| b == 0), "pkSeed must be N-masked");

    // ── bootstrap key ──
    let boot_vk = if let Some(ic) = &a.initcode {
        assert_eq!(ic.len(), 4280, "GET_INIT_CODE response must be 4280 bytes");
        println!("==> bootstrap key from GET_INIT_CODE (no seed)");
        vk_from_words(&ic[24..56], &ic[56..88])
    } else {
        println!("==> bootstrap key from the e2e-test mnemonic");
        let m = Mnemonic::from_words(&crate::E2E_WORDS).expect("e2e mnemonic");
        let entropy = m.to_entropy().expect("e2e entropy");
        let (sk, seed32, root32) = derive_c10_master_keypair_from_entropy(&entropy, a.account);
        let vk = sk.verifying_key();
        assert_eq!(vk.pk_seed[..], seed32[..16]);
        assert_eq!(vk.pk_root[..], root32[..16]);
        // e2e only: the returned owner bytes must equal the independently
        // derived slot key — the companion receives the right key.
        let slot_master = slot_master_entropy_from_bip39(&m.to_seed(""), a.account);
        let (_slot_sk, s_seed32, s_root32) = derive_c10_slot_keypair(&slot_master, a.chain, a.slot);
        let mut expect = [0u8; OWNER_LEN];
        expect[..32].copy_from_slice(&s_seed32);
        expect[32..].copy_from_slice(&s_root32);
        check(expect == owner, "owner bytes == derived slot key", true);
        vk
    };

    // ── Type-1: rebuilt from the returned owner bytes ──
    println!("\n-- Type-1 (bootstrap) over addOwnerBytes(owner), nonce {}", a.nonce);
    let t1_call = add_owner_bytes_calldata(&owner);
    let t1_digest = userop_digest(&a, a.nonce, &t1_call, SHA256_EMPTY);
    check(boot_vk.verify(&t1_digest, &t1_sig), "verify(bootstrap, rebuilt Type-1)", true);
    let mut flipped = owner;
    flipped[5] ^= 1;
    let bad_call = add_owner_bytes_calldata(&flipped);
    check(boot_vk.verify(&userop_digest(&a, a.nonce, &bad_call, SHA256_EMPTY), &t1_sig),
          "verify(bootstrap, owner byte flipped)", false);
    check(boot_vk.verify(&userop_digest(&a, a.nonce + 1, &t1_call, SHA256_EMPTY), &t1_sig),
          "verify(bootstrap, nonce base+1)", false);

    // ── Type-2: signed by the key the owner bytes carry ──
    println!("\n-- Type-2 (new slot {}) at nonce {}", a.slot, a.nonce + 1);
    let new_vk = vk_from_words(&owner[..32], &owner[32..]);
    let tx = Eip1559Tx {
        chain_id: a.chain,
        nonce: 0,
        max_priority_fee_per_gas: word_u64(0),
        max_fee_per_gas: word_u64(0),
        gas_limit: 0,
        to: Some(a.to),
        value: word_u128(a.value),
        data_len: 0,
        access_list_count: 0,
        signing_hash: [0u8; 32],
        userop_fields: None,
    };
    let exec = reconstruct_execute_calldata(u64::from(a.slot) + 1, count, &tx, &[])
        .expect("execute calldata");
    let t2_digest = userop_digest(&a, a.nonce + 1, exec.as_slice(), a.paymaster);
    check(new_vk.verify(&t2_digest, &t2_sig), "verify(new slot key, Type-2)", true);
    let mut other = owner;
    other[33] ^= 1;
    check(vk_from_words(&other[..32], &other[32..]).verify(&t2_digest, &t2_sig),
          "verify(wrong key, Type-2)", false);
    check(boot_vk.verify(&t2_digest, &t2_sig), "verify(bootstrap key, Type-2)", false);
    check(new_vk.verify(&t1_digest, &t1_sig), "verify(new slot key, Type-1)", false);

    println!();
    if failures.is_empty() {
        println!("=== PASS === rotation response is executable by a seedless companion:");
        println!("    the Type-1 rebuilt from the returned owner bytes verifies under the");
        println!("    bootstrap key, the Type-2 verifies under the returned key, and every");
        println!("    negative control fails.");
        std::process::exit(0);
    }
    println!("=== FAIL ===");
    for f in &failures {
        println!("  - {f}");
    }
    std::process::exit(1);
}
