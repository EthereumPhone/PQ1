//! ADRS (address) construction for domain separation.
//!
//! An ADRS is a 32-byte value packed as:
//!
//! ```text
//!   bits [255..224]  layer         (u32)
//!   bits [223..160]  tree          (u64)
//!   bits [159..128]  address_type  (u32)
//!   bits [127..96]   keypair       (u32)
//!   bits [95..64]    chain_index   (u32)
//!   bits [63..32]    chain_pos     (u32)
//!   bits [31..0]     hash_address  (u32)
//! ```
//!
//! Matches the Python signer's `make_adrs()` and the Solidity verifier's
//! inline Yul address construction.

/// Build a 32-byte ADRS from its components.
///
/// All values are truncated to their respective bit widths before packing.
#[inline]
pub fn make_adrs(
    layer: u32,
    tree: u64,
    atype: u32,
    kp: u32,
    ci: u32,
    cp: u32,
    ha: u32,
) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[0..4].copy_from_slice(&layer.to_be_bytes());
    // tree occupies bytes [4..12) as u64 BE
    buf[4..12].copy_from_slice(&tree.to_be_bytes());
    buf[12..16].copy_from_slice(&atype.to_be_bytes());
    buf[16..20].copy_from_slice(&kp.to_be_bytes());
    buf[20..24].copy_from_slice(&ci.to_be_bytes());
    buf[24..28].copy_from_slice(&cp.to_be_bytes());
    buf[28..32].copy_from_slice(&ha.to_be_bytes());
    buf
}

/// Return a copy of `adrs` with the chain_index field (bits [95..64]) set
/// to `idx`. Used by WOTS signing to iterate over chains.
#[inline]
pub fn set_chain_index(adrs: &[u8; 32], idx: u32) -> [u8; 32] {
    let mut out = *adrs;
    out[20..24].copy_from_slice(&idx.to_be_bytes());
    out
}

/// Return a copy of `adrs` with the chain_pos field (bits [63..32]) set
/// to `pos`. Used by chain hashing.
#[inline]
pub fn set_chain_pos(adrs: &[u8; 32], pos: u32) -> [u8; 32] {
    let mut out = *adrs;
    out[24..28].copy_from_slice(&pos.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adrs_layout_matches_python() {
        // Python: make_adrs(1, 0, 3, 7, 0, 0, 42)
        // = (1 << 224) | (0 << 160) | (3 << 128) | (7 << 96) | (0 << 64) | (0 << 32) | 42
        let adrs = make_adrs(1, 0, 3, 7, 0, 0, 42);
        // layer=1 at bytes [0..4)
        assert_eq!(u32::from_be_bytes([adrs[0], adrs[1], adrs[2], adrs[3]]), 1);
        // tree=0 at bytes [4..12)
        assert_eq!(
            u64::from_be_bytes([
                adrs[4], adrs[5], adrs[6], adrs[7], adrs[8], adrs[9], adrs[10], adrs[11]
            ]),
            0
        );
        // atype=3 at bytes [12..16)
        assert_eq!(
            u32::from_be_bytes([adrs[12], adrs[13], adrs[14], adrs[15]]),
            3
        );
        // kp=7 at bytes [16..20)
        assert_eq!(
            u32::from_be_bytes([adrs[16], adrs[17], adrs[18], adrs[19]]),
            7
        );
        // ha=42 at bytes [28..32)
        assert_eq!(
            u32::from_be_bytes([adrs[28], adrs[29], adrs[30], adrs[31]]),
            42
        );
    }
}
