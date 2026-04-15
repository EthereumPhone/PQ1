//! Generate test vectors for cross-language verification (Rust <-> Solidity).
//!
//! Run with: `cargo test -p jardin-fosc --test gen_test_vectors -- --nocapture`
//! Writes JSON to `../contracts/smart-wallet/test/jardin_test_vectors.json`.

use jardin_fosc::{params::*, JardinSlot};
use std::fs;

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::from("0x");
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[test]
fn generate_test_vectors() {
    let entropy = [0x42u8; 32];
    let mut slot = JardinSlot::keygen(entropy);

    let pk_seed_hex = to_hex(&slot.pk_seed);
    let pk_root_hex = to_hex(&slot.pk_root);

    // Generate signatures for q=1, q=2, q=50
    let test_qs = [1u32, 2, 50];
    let mut sigs = Vec::new();

    for &target_q in &test_qs {
        // Advance slot to the right q
        while slot.next_q < target_q {
            let dummy_msg = {
                let mut m = [0u8; 32];
                m[0..4].copy_from_slice(&slot.next_q.to_be_bytes());
                m
            };
            let _ = slot.sign(&dummy_msg).unwrap();
        }

        let msg = {
            let mut m = [0u8; 32];
            m[0] = 0xAA;
            m[1..5].copy_from_slice(&target_q.to_be_bytes());
            m
        };
        let sig = slot.sign(&msg).unwrap();

        // Verify locally first
        assert!(
            jardin_fosc::verify(&slot.pk_seed, &slot.pk_root, &msg, &sig.data[..sig.len]),
            "local verify failed for q={}",
            target_q
        );

        sigs.push(format!(
            r#"    {{
      "q": {},
      "message": "{}",
      "signature": "{}",
      "sigLen": {}
    }}"#,
            target_q,
            to_hex(&msg),
            to_hex(&sig.data[..sig.len]),
            sig.len
        ));
    }

    // Compute slot key and sub VK hash
    let master_entropy = [0x42u8; 32];
    let slot_r = jardin_fosc::hash::jardin_slot_r(&master_entropy, 0);
    let slot_key = jardin_fosc::hash::keccak256(&slot_r);

    // Re-create the slot to get sub_vk_hash
    let slot2 = JardinSlot::keygen(entropy);
    let sub_vk_hash = slot2.sub_vk_hash();

    let json = format!(
        r#"{{
  "pkSeed": "{}",
  "pkRoot": "{}",
  "slotKey": "{}",
  "subVkHash": "{}",
  "signatures": [
{}
  ]
}}"#,
        pk_seed_hex,
        pk_root_hex,
        to_hex(&slot_key),
        to_hex(&sub_vk_hash),
        sigs.join(",\n")
    );

    let out_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../contracts/smart-wallet/test/jardin_test_vectors.json"
    );
    fs::write(out_path, &json).expect("write test vectors");
    println!("Wrote test vectors to {}", out_path);
    println!("{}", json);
}
