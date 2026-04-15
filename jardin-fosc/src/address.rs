//! ADRS (address) construction for JARDIN FORS+C.
//!
//! All tweakable hashes use a 32-byte address packed into a single uint256.
//! Layout matches the Solidity verifier exactly.
//!
//! ```text
//! bits 255-224: layer     (unused, 0)
//! bits 223-160: tree      (unused, 0)
//! bits 159-128: atype     (3, 4, or 6)
//! bits 127- 96: kp        (tree index for FORS)
//! bits  95- 64: ci        (q = leaf counter)
//! bits  63- 32: cp        (height or depth)
//! bits  31-  0: ha        (leaf/node index)
//! ```

/// Pack ADRS fields into a 32-byte big-endian value.
///
/// Only the lower 20 bytes are used (layer and tree are always 0 for JARDIN).
pub fn make_adrs(atype: u32, kp: u32, ci: u32, cp: u32, ha: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    // layer (bytes 0..4) = 0
    // tree  (bytes 4..12) = 0
    // atype (bytes 12..16)
    out[12..16].copy_from_slice(&atype.to_be_bytes());
    // kp (bytes 16..20)
    out[16..20].copy_from_slice(&kp.to_be_bytes());
    // ci (bytes 20..24)
    out[20..24].copy_from_slice(&ci.to_be_bytes());
    // cp (bytes 24..28)
    out[24..28].copy_from_slice(&cp.to_be_bytes());
    // ha (bytes 28..32)
    out[28..32].copy_from_slice(&ha.to_be_bytes());
    out
}
