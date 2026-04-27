//! Wire format and verifier for the function-selector → text-signature
//! bundle that the host (companion app) attaches to a `CMD_SIGN_USEROP`
//! request when its local selectors DB has a hit on `calldata[0..4]`.
//!
//! The trust model is identical to [`crate::erc20::bundle`] and
//! [`crate::names::bundle`]: only the 32-byte Merkle root rides in the
//! secure image, the host holds the full blob, and the bundle crosses
//! the gateway carrying canonical bytes + proof. The secure world
//! re-derives the leaf hash and walks the proof up to
//! [`crate::db_roots::SELECTOR_DB_ROOT`] before letting any byte near
//! the OLED.
//!
//! ## Wire layout
//!
//! ```text
//!   selector       [u8; 4]
//!   text_sig_len   u8
//!   text_sig       [u8; text_sig_len]
//!   leaf_index     u32 LE
//!   proof_depth    u32 LE
//!   proof          [u8; proof_depth * 32]
//! ```
//!
//! `text_sig_len` is capped at
//! [`sphincs_tz_shared::db_format::SELECTOR_TEXT_SIG_MAX_LEN`] and every
//! byte must lie in printable ASCII (0x20..=0x7e). The OLED only
//! renders ASCII anyway, and anything else would be a spoofing
//! foothold.
//!
//! ## Cross-checks before trusting the metadata
//!
//! Merkle verification proves the supplied `(selector, text_sig)`
//! pair exists in the curated DB the secure firmware was built
//! against. It does NOT prove the supplied `selector` matches whatever
//! calldata the secure world is about to sign. That second check
//! lives in `cmd_sign_userop.rs`, which compares
//! `bundle.selector == inner_data[0..4]` after Merkle verification
//! succeeds. Without that cross-check a hostile host could supply a
//! perfectly valid `transfer(address,uint256)` bundle while signing a
//! transaction whose calldata starts with a completely different
//! selector.

use crate::db_roots::SELECTOR_DB_ROOT;
use sphincs_tz_shared::db_format::SELECTOR_TEXT_SIG_MAX_LEN;

use super::super::erc20::merkle::verify_proof;

/// Decoded + Merkle-verified function-selector entry. Borrows from the
/// gateway buffer the bundle was copied into; the lifetime is tied to
/// that buffer's stack frame.
#[derive(Clone, Copy, Debug)]
pub struct SelectorMeta<'a> {
    pub selector: [u8; 4],
    pub text_sig: &'a [u8],
}

/// Maximum total bundle size, used to bound the secure-side stack
/// buffer that holds the copy. 4 + 1 + 63 + 4 + 4 + 32 levels of proof
/// = 1100 bytes upper bound.
pub const MAX_SELECTOR_BUNDLE_LEN: usize =
    4 + 1 + SELECTOR_TEXT_SIG_MAX_LEN + 4 + 4 + 32 * 32;

/// Verify a single selector bundle. On success returns the decoded
/// metadata; on any failure returns `None`. `bundle` must be the exact
/// bytes the host wrote — no outer length prefix. The caller parses
/// any length prefix at the gateway boundary.
pub fn verify_selector_bundle(bundle: &[u8]) -> Option<SelectorMeta<'_>> {
    let mut off = 0usize;

    // Header fixed fields.
    if bundle.len() < off + 4 + 1 {
        return None;
    }
    let selector: [u8; 4] = bundle.get(off..off + 4)?.try_into().ok()?;
    off += 4;

    // Text signature (length-prefixed).
    let text_sig_len = *bundle.get(off)? as usize;
    off += 1;
    if text_sig_len == 0 || text_sig_len > SELECTOR_TEXT_SIG_MAX_LEN {
        return None;
    }
    let text_sig = bundle.get(off..off + text_sig_len)?;
    off += text_sig_len;
    if !is_clean_ascii(text_sig) {
        return None;
    }

    // Merkle proof header.
    if bundle.len() < off + 4 + 4 {
        return None;
    }
    let leaf_index = read_u32_le(bundle, off)? as usize;
    off += 4;
    let proof_depth = read_u32_le(bundle, off)? as usize;
    off += 4;
    if proof_depth > 32 {
        return None;
    }

    let proof_size = proof_depth * 32;
    // Reject trailing bytes — the buffer must be exactly the bundle.
    if bundle.len() != off + proof_size {
        return None;
    }
    let proof = bundle.get(off..off + proof_size)?;

    // Re-derive the canonical leaf bytes from the supplied fields.
    // MUST match dbgen::selectors::canonical_selector_leaf byte-for-byte.
    let canonical_len = 4 + 1 + text_sig_len;
    let mut canonical = [0u8; 4 + 1 + SELECTOR_TEXT_SIG_MAX_LEN];
    let mut p = 0usize;
    canonical[p..p + 4].copy_from_slice(&selector);
    p += 4;
    canonical[p] = text_sig_len as u8;
    p += 1;
    canonical[p..p + text_sig_len].copy_from_slice(text_sig);
    p += text_sig_len;
    debug_assert_eq!(p, canonical_len);

    if !verify_proof(
        &canonical[..canonical_len],
        leaf_index,
        proof,
        proof_depth,
        &SELECTOR_DB_ROOT,
    ) {
        return None;
    }

    Some(SelectorMeta { selector, text_sig })
}

fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    let bytes: [u8; 4] = buf.get(off..off + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn is_clean_ascii(s: &[u8]) -> bool {
    s.iter().all(|&b| (0x20..0x7f).contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// Local Merkle helper — mirrors `dbgen/src/merkle.rs` so the test
    /// can build a tree without pulling dbgen as a dev-dependency.
    fn leaf_hash(canonical: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([0x00u8]);
        h.update(canonical);
        let out = h.finalize();
        let mut a = [0u8; 32];
        a.copy_from_slice(&out);
        a
    }
    fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([0x01u8]);
        h.update(left);
        h.update(right);
        let out = h.finalize();
        let mut a = [0u8; 32];
        a.copy_from_slice(&out);
        a
    }

    /// Build a Merkle tree over `leaves` (padding to power-of-two by
    /// duplicating the last leaf), return `(root, proofs)`.
    fn build_tree(mut leaves: Vec<[u8; 32]>) -> ([u8; 32], Vec<Vec<[u8; 32]>>) {
        let n = leaves.len();
        let target = n.next_power_of_two();
        while leaves.len() < target {
            let last = *leaves.last().unwrap();
            leaves.push(last);
        }
        let mut levels = vec![leaves];
        while levels.last().unwrap().len() > 1 {
            let cur = levels.last().unwrap();
            let mut next = Vec::with_capacity(cur.len() / 2);
            for p in cur.chunks(2) {
                next.push(node_hash(&p[0], &p[1]));
            }
            levels.push(next);
        }
        let root = levels.last().unwrap()[0];
        let depth = levels.len() - 1;

        let mut proofs = Vec::with_capacity(n);
        for i in 0..n {
            let mut idx = i;
            let mut p = Vec::with_capacity(depth);
            for level in &levels[..depth] {
                let sib = idx ^ 1;
                p.push(level[sib]);
                idx >>= 1;
            }
            proofs.push(p);
        }
        (root, proofs)
    }

    fn canonical(selector: &[u8; 4], text: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + 1 + text.len());
        v.extend_from_slice(selector);
        v.push(text.len() as u8);
        v.extend_from_slice(text);
        v
    }

    /// Build a full bundle and patch the embedded root to match.
    fn build_bundle(
        selector: [u8; 4],
        text: &[u8],
        leaf_index: usize,
        depth: usize,
        proof: &[[u8; 32]],
    ) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&selector);
        b.push(text.len() as u8);
        b.extend_from_slice(text);
        b.extend_from_slice(&(leaf_index as u32).to_le_bytes());
        b.extend_from_slice(&(depth as u32).to_le_bytes());
        for s in proof {
            b.extend_from_slice(s);
        }
        b
    }

    /// Run the verify against a fixture-supplied root by patching
    /// SELECTOR_DB_ROOT temporarily. We avoid runtime patching by
    /// constructing test data such that its computed root matches the
    /// real embedded root — but the embedded root is the production
    /// curated one, so instead we rely on the test having access to a
    /// stub. The simplest approach: bypass the real `verify_proof`
    /// by inlining the same logic with an alternative root.
    fn verify_with_root(bundle: &[u8], root: &[u8; 32]) -> Option<([u8; 4], Vec<u8>)> {
        // Mirror of verify_selector_bundle, but verifying against an
        // arbitrary root so unit tests don't depend on dbgen having
        // run.
        let mut off = 0usize;
        if bundle.len() < off + 4 + 1 {
            return None;
        }
        let selector: [u8; 4] = bundle[off..off + 4].try_into().ok()?;
        off += 4;
        let text_sig_len = *bundle.get(off)? as usize;
        off += 1;
        if text_sig_len == 0 || text_sig_len > SELECTOR_TEXT_SIG_MAX_LEN {
            return None;
        }
        let text = bundle.get(off..off + text_sig_len)?;
        off += text_sig_len;
        if !is_clean_ascii(text) {
            return None;
        }
        if bundle.len() < off + 4 + 4 {
            return None;
        }
        let leaf_index = read_u32_le(bundle, off)? as usize;
        off += 4;
        let proof_depth = read_u32_le(bundle, off)? as usize;
        off += 4;
        if proof_depth > 32 {
            return None;
        }
        let proof_size = proof_depth * 32;
        if bundle.len() != off + proof_size {
            return None;
        }
        let proof = &bundle[off..off + proof_size];
        let canonical = canonical(&selector, text);
        if !verify_proof(&canonical, leaf_index, proof, proof_depth, root) {
            return None;
        }
        Some((selector, text.to_vec()))
    }

    #[test]
    fn round_trip_happy_path() {
        // Build a 4-leaf tree of (selector, text_sig) pairs.
        let entries = vec![
            ([0xa9, 0x05, 0x9c, 0xbb], "transfer(address,uint256)"),
            ([0x09, 0x5e, 0xa7, 0xb3], "approve(address,uint256)"),
            ([0x23, 0xb8, 0x72, 0xdd], "transferFrom(address,address,uint256)"),
            ([0x70, 0xa0, 0x82, 0x31], "balanceOf(address)"),
        ];
        let leaves: Vec<[u8; 32]> = entries
            .iter()
            .map(|(s, t)| leaf_hash(&canonical(s, t.as_bytes())))
            .collect();
        let (root, proofs) = build_tree(leaves);

        for (i, (sel, text)) in entries.iter().enumerate() {
            let b = build_bundle(*sel, text.as_bytes(), i, proofs[i].len(), &proofs[i]);
            let verified = verify_with_root(&b, &root)
                .unwrap_or_else(|| panic!("bundle {} failed", i));
            assert_eq!(&verified.0, sel);
            assert_eq!(verified.1.as_slice(), text.as_bytes());
        }
    }

    #[test]
    fn corrupted_proof_rejected() {
        let entries = vec![
            ([0xa9, 0x05, 0x9c, 0xbb], "transfer(address,uint256)"),
            ([0x09, 0x5e, 0xa7, 0xb3], "approve(address,uint256)"),
        ];
        let leaves: Vec<[u8; 32]> = entries
            .iter()
            .map(|(s, t)| leaf_hash(&canonical(s, t.as_bytes())))
            .collect();
        let (root, proofs) = build_tree(leaves);

        let mut b = build_bundle(
            entries[0].0,
            entries[0].1.as_bytes(),
            0,
            proofs[0].len(),
            &proofs[0],
        );
        // Flip a byte in the proof tail.
        let last = b.len() - 1;
        b[last] ^= 0x01;
        assert!(verify_with_root(&b, &root).is_none());
    }

    #[test]
    fn wrong_leaf_index_rejected() {
        let entries = vec![
            ([0xa9, 0x05, 0x9c, 0xbb], "transfer(address,uint256)"),
            ([0x09, 0x5e, 0xa7, 0xb3], "approve(address,uint256)"),
        ];
        let leaves: Vec<[u8; 32]> = entries
            .iter()
            .map(|(s, t)| leaf_hash(&canonical(s, t.as_bytes())))
            .collect();
        let (root, proofs) = build_tree(leaves);

        // Use entry 0's data but entry 1's index.
        let b = build_bundle(
            entries[0].0,
            entries[0].1.as_bytes(),
            1,
            proofs[1].len(),
            &proofs[1],
        );
        assert!(verify_with_root(&b, &root).is_none());
    }

    #[test]
    fn non_ascii_text_sig_rejected() {
        let entries = vec![([0xde, 0xad, 0xbe, 0xef], "ok(uint256)")];
        let leaves: Vec<[u8; 32]> = entries
            .iter()
            .map(|(s, t)| leaf_hash(&canonical(s, t.as_bytes())))
            .collect();
        let (_root, _proofs) = build_tree(leaves);

        // Build a bundle whose text_sig contains a control byte. Even
        // before the Merkle check, the ASCII gate must reject it.
        let bad_text: Vec<u8> = vec![b't', 0x07, b's']; // BEL byte
        let mut b = Vec::new();
        b.extend_from_slice(&entries[0].0);
        b.push(bad_text.len() as u8);
        b.extend_from_slice(&bad_text);
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        // Use SELECTOR_DB_ROOT here (any root works; we expect rejection
        // before the Merkle step).
        assert!(verify_selector_bundle(&b).is_none());
    }

    #[test]
    fn oversized_text_sig_rejected() {
        let mut text = Vec::new();
        text.resize(SELECTOR_TEXT_SIG_MAX_LEN + 1, b'A');
        let mut b = Vec::new();
        b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        b.push(text.len() as u8);
        b.extend_from_slice(&text);
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        assert!(verify_selector_bundle(&b).is_none());
    }

    #[test]
    fn empty_text_sig_rejected() {
        let mut b = Vec::new();
        b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        b.push(0u8); // text_sig_len = 0
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        assert!(verify_selector_bundle(&b).is_none());
    }

    #[test]
    fn oversized_proof_depth_rejected() {
        let mut b = Vec::new();
        b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        b.push(1u8);
        b.push(b'x');
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&33u32.to_le_bytes()); // > 32
        // Don't bother appending proof bytes — depth check trips first.
        assert!(verify_selector_bundle(&b).is_none());
    }

    #[test]
    fn trailing_bytes_rejected() {
        // Construct a complete bundle (depth 0, single-leaf tree) and
        // append one extra byte; verifier must reject.
        let entries = vec![([0xa9, 0x05, 0x9c, 0xbb], "transfer(address,uint256)")];
        let leaves: Vec<[u8; 32]> = entries
            .iter()
            .map(|(s, t)| leaf_hash(&canonical(s, t.as_bytes())))
            .collect();
        let (root, proofs) = build_tree(leaves);

        let mut b = build_bundle(
            entries[0].0,
            entries[0].1.as_bytes(),
            0,
            proofs[0].len(),
            &proofs[0],
        );
        b.push(0xff);
        assert!(verify_with_root(&b, &root).is_none());
    }
}
