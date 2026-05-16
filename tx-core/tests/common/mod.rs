//! Shared fixtures for the `pqsigner-tx-core` integration tests.
//!
//! These helpers materialise canonical RLP / EIP-1559 envelope bytes
//! from typed inputs so a test reads as "an envelope with chain_id=1,
//! gas=21_000, to=0x11..11" rather than as a wall of magic hex. Every
//! helper is deliberately permissive: a test can ask for a malformed
//! envelope by post-hoc surgery on the returned `Vec`.

#![allow(dead_code)]

/// Minimal RLP-encode a byte string. Mirrors the canonical encoder the
/// in-crate unit tests use, kept here so integration tests don't have
/// to reach into private modules.
pub fn rlp_encode_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if bytes.len() == 1 && bytes[0] <= 0x7f {
        out.push(bytes[0]);
    } else if bytes.len() <= 55 {
        out.push(0x80 + bytes.len() as u8);
        out.extend_from_slice(bytes);
    } else {
        let len_bytes = (bytes.len() as u64).to_be_bytes();
        let first_nonzero = len_bytes.iter().position(|&b| b != 0).unwrap();
        let len_enc = &len_bytes[first_nonzero..];
        out.push(0xb7 + len_enc.len() as u8);
        out.extend_from_slice(len_enc);
        out.extend_from_slice(bytes);
    }
    out
}

/// RLP-encode a list whose items are already individually RLP-encoded.
pub fn rlp_encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    for it in items {
        body.extend_from_slice(it);
    }
    let mut out = Vec::new();
    if body.len() <= 55 {
        out.push(0xc0 + body.len() as u8);
    } else {
        let len_bytes = (body.len() as u64).to_be_bytes();
        let first_nonzero = len_bytes.iter().position(|&b| b != 0).unwrap();
        let len_enc = &len_bytes[first_nonzero..];
        out.push(0xf7 + len_enc.len() as u8);
        out.extend_from_slice(len_enc);
    }
    out.extend_from_slice(&body);
    out
}

/// Strip leading zero bytes (RLP canonical form for non-zero ints).
pub fn be_trim(bytes: &[u8]) -> Vec<u8> {
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    bytes[first..].to_vec()
}

/// Build a complete unsigned EIP-1559 envelope (`0x02 ‖ rlp(list9)`)
/// with an empty access list.
pub fn build_envelope(
    chain_id: u64,
    nonce: u64,
    max_prio: u64,
    max_fee: u64,
    gas_limit: u64,
    to: Option<[u8; 20]>,
    value_wei: u64,
    data: &[u8],
) -> Vec<u8> {
    let items = vec![
        rlp_encode_bytes(&be_trim(&chain_id.to_be_bytes())),
        rlp_encode_bytes(&be_trim(&nonce.to_be_bytes())),
        rlp_encode_bytes(&be_trim(&max_prio.to_be_bytes())),
        rlp_encode_bytes(&be_trim(&max_fee.to_be_bytes())),
        rlp_encode_bytes(&be_trim(&gas_limit.to_be_bytes())),
        match to {
            Some(a) => rlp_encode_bytes(&a),
            None => rlp_encode_bytes(&[]),
        },
        rlp_encode_bytes(&be_trim(&value_wei.to_be_bytes())),
        rlp_encode_bytes(data),
        rlp_encode_list(&[]),
    ];
    let list = rlp_encode_list(&items);
    let mut env = vec![0x02u8];
    env.extend_from_slice(&list);
    env
}

/// Build an envelope with a caller-supplied access list payload (the
/// already-RLP-encoded list, including its `0xc0..0xff` prefix).
pub fn build_envelope_with_access_list(
    chain_id: u64,
    nonce: u64,
    max_prio: u64,
    max_fee: u64,
    gas_limit: u64,
    to: Option<[u8; 20]>,
    value_wei: u64,
    data: &[u8],
    access_list_rlp: &[u8],
) -> Vec<u8> {
    let items = vec![
        rlp_encode_bytes(&be_trim(&chain_id.to_be_bytes())),
        rlp_encode_bytes(&be_trim(&nonce.to_be_bytes())),
        rlp_encode_bytes(&be_trim(&max_prio.to_be_bytes())),
        rlp_encode_bytes(&be_trim(&max_fee.to_be_bytes())),
        rlp_encode_bytes(&be_trim(&gas_limit.to_be_bytes())),
        match to {
            Some(a) => rlp_encode_bytes(&a),
            None => rlp_encode_bytes(&[]),
        },
        rlp_encode_bytes(&be_trim(&value_wei.to_be_bytes())),
        rlp_encode_bytes(data),
        access_list_rlp.to_vec(),
    ];
    let list = rlp_encode_list(&items);
    let mut env = vec![0x02u8];
    env.extend_from_slice(&list);
    env
}
