//! Machine-readable fixed vectors for `tools/cross_parity_erc8213.py`.
//!
//! This example is deliberately built through the root lockfile so the parity
//! lane executes the same `pqsigner-tx-core` dependency closure as firmware
//! host tests.  Its TSV protocol is strict and versioned by the coordinator.

use pqsigner_tx_core::erc8213::{calldata_digest, eip712_final_hash};

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn emit_calldata(name: &str, data: &[u8]) {
    println!(
        "calldata\t{name}\t{}\t{}",
        hex(data),
        hex(&calldata_digest(data))
    );
}

fn emit_eip712(name: &str, domain_separator: &[u8; 32], struct_hash: &[u8; 32]) {
    println!(
        "eip712\t{name}\t{}\t{}\t{}",
        hex(domain_separator),
        hex(struct_hash),
        hex(&eip712_final_hash(domain_separator, struct_hash))
    );
}

fn main() {
    println!("pq1-erc8213-parity-v1");

    emit_calldata("empty", &[]);
    emit_calldata("single-zero", &[0]);
    emit_calldata("three-bytes", &[0xab, 0xcd, 0xef]);

    let mut transfer = [0u8; 68];
    transfer[..4].copy_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
    transfer[16..36].copy_from_slice(&[
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff, 0x00, 0x11, 0x22, 0x33,
    ]);
    transfer[67] = 0x2a;
    emit_calldata("erc20-transfer", &transfer);

    let mut max_pattern = [0u8; 4096];
    for (index, byte) in max_pattern.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(29).wrapping_add(7);
    }
    emit_calldata("max-4kib-pattern", &max_pattern);

    // The per-call cap since 2026-10-22 (MAX_TX_LEN = 8192): the largest
    // calldata whose fingerprint the device now shows and binds.
    let mut max_8k_pattern = [0u8; 8192];
    for (index, byte) in max_8k_pattern.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(29).wrapping_add(7);
    }
    emit_calldata("max-8kib-pattern", &max_8k_pattern);

    emit_eip712("all-zero", &[0; 32], &[0; 32]);
    emit_eip712("uniform", &[0x11; 32], &[0x22; 32]);
    let mut domain_separator = [0u8; 32];
    let mut struct_hash = [0u8; 32];
    for index in 0..32 {
        domain_separator[index] = (index as u8).wrapping_mul(3).wrapping_add(1);
        struct_hash[index] = 255u8.wrapping_sub((index as u8).wrapping_mul(5));
    }
    emit_eip712("asymmetric-pattern", &domain_separator, &struct_hash);
}
