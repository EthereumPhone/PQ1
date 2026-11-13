//! TRACK-B EXPERIMENT (autoresearch, never shipped as-is): a cache of the top hypertree layer.
//!
//! Layer `D - 1` has a single tree (tree 0) that is the same for every signature of a key. A pass
//! normally rebuilds all 512 leaves of it (177,151 digests). The cache keeps the 32 nodes at height
//! `HC = 4` (512 B); a pass rebuilds only the 16-leaf subtree under the target leaf, checks its root
//! against the stored node, hashes the stored nodes up to the root and refuses unless that root is
//! `pk_root`. The cache carries a SHA-256 digest of its nodes, re-checked on every use.
//!
//! Fill and confirm (review H1): `keygen_with_top_cache` builds the top tree twice, the second time
//! with a rotated WOTS chain order, and only marks the cache valid when both builds agree on every
//! stored node and on the root.
use crate::address::make_adrs;
use crate::hash::{pad16, sha256_bytes, th_pair};
use crate::params::*;
use core::sync::atomic::{AtomicU32, Ordering};

/// Height of the stored nodes.
pub const HC: usize = 4;
/// Number of stored nodes.
pub const NC: usize = SUBTREE_LEAVES >> HC;

/// Cache uses since boot (proves a warm sign used the cache).
pub static HITS: AtomicU32 = AtomicU32::new(0);

/// The cached top-layer nodes.
pub struct TopCache {
    nodes: [[u8; N]; NC],
    digest: [u8; 32],
    valid: bool,
}

impl TopCache {
    /// An empty, invalid cache.
    #[must_use]
    pub const fn empty() -> Self {
        Self { nodes: [[0u8; N]; NC], digest: [0u8; 32], valid: false }
    }

    fn digest_of(nodes: &[[u8; N]; NC]) -> [u8; 32] {
        let mut buf = [0u8; N * NC];
        for (i, n) in nodes.iter().enumerate() {
            buf[i * N..(i + 1) * N].copy_from_slice(n);
        }
        sha256_bytes(&buf)
    }

    /// Test-only: flip one bit of stored node `i` (must-refuse control).
    #[doc(hidden)]
    pub fn corrupt_node_for_test(&mut self, i: usize) {
        self.nodes[i % NC][0] ^= 1;
    }

    /// Wipe: invalidate first, then zero the nodes.
    pub fn wipe(&mut self) {
        // SAFETY: plain volatile stores to fields of `self`.
        unsafe {
            core::ptr::write_volatile(&mut self.valid, false);
            for n in self.nodes.iter_mut() {
                core::ptr::write_volatile(n, [0u8; N]);
            }
            core::ptr::write_volatile(&mut self.digest, [0u8; 32]);
        }
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
    }

    /// Build the top tree over all leaves, storing the height-`HC` nodes; `rot` rotates the WOTS
    /// chain order of every leaf (0 = identity). Returns the root.
    fn build(&mut self, seed: &[u8; 32], sk_seed: &[u8; 32], rot: u8) -> [u8; N] {
        let layer = (D - 1) as u32;
        let tree = 0u64;
        let mut stack = [[0u8; N]; SUBTREE_H + 1];
        let mut heights = [0u32; SUBTREE_H + 1];
        let mut sp = 0usize;
        for kp in 0..SUBTREE_LEAVES {
            let mut node = leaf(seed, sk_seed, layer, tree, kp as u32, rot);
            let mut h = 0u32;
            loop {
                if h as usize == HC {
                    self.nodes[kp >> HC] = node;
                }
                if !(sp > 0 && heights[sp - 1] == h) {
                    break;
                }
                sp -= 1;
                let sib = stack[sp];
                let adrs = make_adrs(layer, tree, ADRS_TREE, 0, 0, h + 1, (kp >> (h + 1)) as u32);
                node = th_pair(seed, &adrs, &pad16(&sib), &pad16(&node));
                h += 1;
            }
            stack[sp] = node;
            heights[sp] = h;
            sp += 1;
        }
        stack[0]
    }

    /// The auth path and root of the top tree for `idx_leaf`, from the cache plus a rebuild of the
    /// 16-leaf subtree under it. Panics (refuses to sign) on any integrity failure.
    pub(crate) fn auth_path(
        &self,
        seed: &[u8; 32],
        sk_seed: &[u8; 32],
        idx_leaf: u32,
        pk_root: &[u8; N],
    ) -> ([[u8; N]; SUBTREE_H], [u8; N]) {
        assert!(self.valid, "top cache not valid");
        assert!(Self::digest_of(&self.nodes) == self.digest, "top cache digest mismatch");
        let layer = (D - 1) as u32;
        let tree = 0u64;
        let mut auth = [[0u8; N]; SUBTREE_H];
        // 1. Rebuild the 2^HC-leaf subtree containing idx_leaf, collecting heights 0..HC.
        let lo = idx_leaf as usize & !((1 << HC) - 1);
        let mut stack = [[0u8; N]; HC + 1];
        let mut heights = [0u32; HC + 1];
        let mut sp = 0usize;
        for kp in lo..lo + (1 << HC) {
            let mut node = leaf(seed, sk_seed, layer, tree, kp as u32, 0);
            let mut h = 0u32;
            while sp > 0 && heights[sp - 1] == h {
                sp -= 1;
                let left = stack[sp];
                // The target's sibling at height h is the left node or this one.
                let sib = (idx_leaf >> h) ^ 1;
                let left_idx = (kp >> h) as u32 - 1;
                if left_idx == sib {
                    auth[h as usize] = left;
                } else if left_idx + 1 == sib {
                    auth[h as usize] = node;
                }
                let adrs = make_adrs(layer, tree, ADRS_TREE, 0, 0, h + 1, (kp >> (h + 1)) as u32);
                node = th_pair(seed, &adrs, &pad16(&left), &pad16(&node));
                h += 1;
            }
            stack[sp] = node;
            heights[sp] = h;
            sp += 1;
        }
        assert!(stack[0] == self.nodes[idx_leaf as usize >> HC], "top cache: rebuilt subtree differs");
        // 2. Hash the stored nodes up to the root, taking the target's siblings on the way.
        let mut level = self.nodes;
        let mut width = NC;
        for h in HC..SUBTREE_H {
            auth[h] = level[((idx_leaf >> h) ^ 1) as usize];
            for p in 0..width / 2 {
                let adrs = make_adrs(layer, tree, ADRS_TREE, 0, 0, h as u32 + 1, p as u32);
                level[p] = th_pair(seed, &adrs, &pad16(&level[2 * p]), &pad16(&level[2 * p + 1]));
            }
            width /= 2;
        }
        assert!(&level[0] == pk_root, "top cache: root is not pk_root");
        HITS.fetch_add(1, Ordering::Relaxed);
        (auth, level[0])
    }
}

/// One top-layer leaf (the WOTS public key of key pair `kp`), with chain order rotated by `rot`.
fn leaf(seed: &[u8; 32], sk_seed: &[u8; 32], layer: u32, tree: u64, kp: u32, rot: u8) -> [u8; N] {
    if rot == 0 {
        return crate::wots::keygen_pk(seed, sk_seed, layer, tree, kp);
    }
    #[cfg(feature = "hw-sha256-prfchain")]
    {
        let base_adrs = make_adrs(layer, tree, ADRS_WOTS, kp, 0, 0, 0);
        let mut order = [0u8; L];
        for (i, o) in order.iter_mut().enumerate() {
            *o = ((i + rot as usize) % L) as u8;
        }
        let mut pk_elements = [[0u8; N]; L];
        crate::hash::wots_chains(seed, sk_seed, &base_adrs, layer, tree, kp, Some(&order), None, &mut pk_elements);
        let pk_adrs = make_adrs(layer, tree, ADRS_WOTS_PK, kp, 0, 0, 0);
        crate::hash::th_multi(seed, &pk_adrs, &pk_elements)
    }
    // Generic and v2 paths: the same chains in rotated order, so the confirm
    // build is a different computation, not a replay of the first.
    #[cfg(not(feature = "hw-sha256-prfchain"))]
    {
        let base_adrs = make_adrs(layer, tree, ADRS_WOTS, kp, 0, 0, 0);
        let mut pk_elements = [[0u8; N]; L];
        for step in 0..L {
            let i = (step + rot as usize) % L;
            pk_elements[i] = crate::hash::wots_secret_chain(seed, sk_seed, &base_adrs, layer, tree, kp, i as u32, (W - 1) as u32);
        }
        let pk_adrs = make_adrs(layer, tree, ADRS_WOTS_PK, kp, 0, 0, 0);
        crate::hash::th_multi(seed, &pk_adrs, &pk_elements)
    }
}

/// Keygen that also fills and confirms a top-layer cache: two independent builds of the top tree
/// (identity and rotated chain order) must agree on every stored node and on the root.
pub fn keygen_with_top_cache(sk_seed: [u8; 32], pk_seed: [u8; N], cache: &mut TopCache) -> crate::SigningKey {
    let seed = pad16(&pk_seed);
    cache.wipe();
    let root = cache.build(&seed, &sk_seed, 0);
    let mut confirm = TopCache::empty();
    let root2 = confirm.build(&seed, &sk_seed, 17);
    assert!(root == root2 && confirm.nodes == cache.nodes, "top cache: confirm build differs");
    confirm.wipe();
    cache.digest = TopCache::digest_of(&cache.nodes);
    cache.valid = true;
    crate::SigningKey::from_parts(sk_seed, pk_seed, root)
}

/// Test-only sweep: for every top-layer leaf, the cached auth path and root equal a full rebuild's.
/// Returns the number of leaves checked (panics on the first difference).
#[doc(hidden)]
pub fn sweep_against_full_build(cache: &TopCache, pk_seed: &[u8; N], sk_seed: &[u8; 32], pk_root: &[u8; N]) -> u32 {
    let seed = pad16(pk_seed);
    let mut n = 0;
    for leaf in 0..SUBTREE_LEAVES as u32 {
        let (a, r) = cache.auth_path(&seed, sk_seed, leaf, pk_root);
        let (b, s) = crate::merkle::build_subtree_with_auth(
            &seed, sk_seed, (D - 1) as u32, 0, leaf, &crate::hypertree::progress_none(), 0, 0,
        );
        assert!(a == b && r == s, "sweep: leaf {leaf} differs");
        n += 1;
    }
    n
}
