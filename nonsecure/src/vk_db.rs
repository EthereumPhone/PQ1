//! Non-secure-side ZK clear-signing VK DB lookup.
//!
//! Mirrors `erc20_db.rs`: the full pool of (chain_id, contract, vk)
//! triples lives in NS rodata; this module walks the sorted index,
//! finds the matching VK, and emits a bundle the secure world can
//! Merkle-verify against its embedded root.

use sphincs_tz_shared::db_format::{
    read_u32_le, read_u64_le, VK_BLOB_LEN, VK_DB_ENTRY_LEN, VK_DB_HEADER_LEN, VK_DB_MAGIC,
    VK_DB_VERSION, VK_ENTRY_OFF_CHAIN_ID, VK_ENTRY_OFF_CONTRACT, VK_ENTRY_OFF_VK_ID,
    VK_HDR_OFF_ENTRY_CNT, VK_HDR_OFF_PROOFS_OFF, VK_HDR_OFF_PROOF_DEPTH, VK_HDR_OFF_VERSION,
    VK_HDR_OFF_VK_POOL_OFF,
};

static VK_DB: &[u8] = include_bytes!("vk_db.bin");

/// Build a VK bundle for `(chain_id, contract)`. Writes into `out`
/// and returns the number of bytes written, or `None` if not found
/// or if `out` is too small.
///
/// Wire layout (must match `secure/src/zk/vk_bundle.rs`):
///
/// ```text
///   chain_id      u64 LE       ( 8 B)
///   contract      [u8; 20]     (20 B)
///   vk            [u8; 960]    (960 B)
///   leaf_index    u32 LE       ( 4 B)
///   proof_depth   u32 LE       ( 4 B)
///   proof         [u8; proof_depth * 32]
/// ```
pub fn build_bundle(chain_id: u64, contract: &[u8; 20], out: &mut [u8]) -> Option<usize> {
    let view = open(VK_DB)?;
    let idx = view.find_index(chain_id, contract)?;
    let entry_off = VK_DB_HEADER_LEN + idx * VK_DB_ENTRY_LEN;
    let vk_id = view.blob[entry_off + VK_ENTRY_OFF_VK_ID] as usize;
    let vk_pool_start = view.vk_pool_off + vk_id * VK_BLOB_LEN;

    let needed = 8 + 20 + VK_BLOB_LEN + 4 + 4 + view.proof_depth * 32;
    if out.len() < needed {
        return None;
    }

    let mut p = 0usize;
    out[p..p + 8].copy_from_slice(&chain_id.to_le_bytes());
    p += 8;
    out[p..p + 20].copy_from_slice(contract);
    p += 20;
    out[p..p + VK_BLOB_LEN].copy_from_slice(&view.blob[vk_pool_start..vk_pool_start + VK_BLOB_LEN]);
    p += VK_BLOB_LEN;
    out[p..p + 4].copy_from_slice(&(idx as u32).to_le_bytes());
    p += 4;
    out[p..p + 4].copy_from_slice(&(view.proof_depth as u32).to_le_bytes());
    p += 4;

    let proof_base = view.proofs_off + idx * view.proof_depth * 32;
    let proof_size = view.proof_depth * 32;
    out[p..p + proof_size].copy_from_slice(&view.blob[proof_base..proof_base + proof_size]);
    p += proof_size;

    Some(p)
}

struct VkDbView {
    blob: &'static [u8],
    entry_cnt: usize,
    vk_pool_off: usize,
    proof_depth: usize,
    proofs_off: usize,
}

fn open(blob: &'static [u8]) -> Option<VkDbView> {
    if blob.len() < VK_DB_HEADER_LEN {
        return None;
    }
    if blob[..4] != VK_DB_MAGIC {
        return None;
    }
    if read_u32_le(blob, VK_HDR_OFF_VERSION) != VK_DB_VERSION {
        return None;
    }
    let entry_cnt = read_u32_le(blob, VK_HDR_OFF_ENTRY_CNT) as usize;
    let vk_pool_off = read_u32_le(blob, VK_HDR_OFF_VK_POOL_OFF) as usize;
    let proof_depth = read_u32_le(blob, VK_HDR_OFF_PROOF_DEPTH) as usize;
    let proofs_off = read_u32_le(blob, VK_HDR_OFF_PROOFS_OFF) as usize;
    Some(VkDbView {
        blob,
        entry_cnt,
        vk_pool_off,
        proof_depth,
        proofs_off,
    })
}

impl VkDbView {
    fn find_index(&self, chain_id: u64, contract: &[u8; 20]) -> Option<usize> {
        let mut lo = 0usize;
        let mut hi = self.entry_cnt;
        while lo < hi {
            let mid = (lo + hi) / 2;
            let off = VK_DB_HEADER_LEN + mid * VK_DB_ENTRY_LEN;
            let mid_chain = read_u64_le(self.blob, off + VK_ENTRY_OFF_CHAIN_ID);
            let mid_contract: &[u8] =
                &self.blob[off + VK_ENTRY_OFF_CONTRACT..off + VK_ENTRY_OFF_CONTRACT + 20];
            let cmp = match mid_chain.cmp(&chain_id) {
                core::cmp::Ordering::Equal => mid_contract.cmp(&contract[..]),
                other => other,
            };
            match cmp {
                core::cmp::Ordering::Less => lo = mid + 1,
                core::cmp::Ordering::Greater => hi = mid,
                core::cmp::Ordering::Equal => return Some(mid),
            }
        }
        None
    }
}
