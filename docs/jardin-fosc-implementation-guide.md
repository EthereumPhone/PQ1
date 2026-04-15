# JARDÍN FORS+C Implementation Guide

Implementing a FORS+C compact signature system: on-chain Solidity verifier, constrained Rust signer, and key rotation lifecycle.

**Parameters (Variant 2):** k=26 trees, a=5 height (32 leaves/tree), n=16 bytes (128-bit), Q_MAX=95 signatures per slot.

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Solidity Verifier](#2-solidity-verifier)
3. [Rust Signer for Constrained Devices](#3-rust-signer-for-constrained-devices)
4. [Key Rotation Logic](#4-key-rotation-logic)
5. [Signature Encoding](#5-signature-encoding)
6. [Security Properties](#6-security-properties)

---

## 1. System Overview

JARDÍN FORS+C uses a two-tier architecture:

```
┌─────────────────────────────────────────────────────┐
│                    On-chain                          │
│                                                     │
│  Account Contract                                   │
│  ├── slots: mapping(H(r) → H(subPkSeed,subPkRoot)) │
│  ├── masterPkSeed, masterPkRoot (C11 identity)      │
│  │                                                  │
│  │  Type 1 (register): C11 verify + slot write      │
│  │  Type 2 (compact):  slot lookup + FORS+C verify  │
│  │                                                  │
│  └──► JardinForsCVerifier (stateless, shared)       │
│        verifyForsCUnbalanced(seed, root, msg, sig)  │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│                  Off-chain (signer)                  │
│                                                     │
│  1. Keygen: build 95 FORS trees + unbalanced tree   │
│     → subPkSeed, subPkRoot (stored in slot)         │
│     → precomputed secrets + auth paths (in memory)  │
│                                                     │
│  2. Sign: grind counter (~32 iterations) +           │
│     assemble FORS opening + unbalanced auth path    │
│                                                     │
│  3. Rotate: after q=95, generate new slot keygen    │
└─────────────────────────────────────────────────────┘
```

The on-chain cost per compact transaction is ~173K gas (ERC-4337) or ~117K gas (frame tx). Slot registration costs ~289–323K gas and happens once per 95 transactions.

---

## 2. Solidity Verifier

### 2.1. Deploying the Verifier

`JardinForsCVerifier` is a stateless pure contract. Deploy it once and share across all accounts:

```solidity
JardinForsCVerifier verifier = new JardinForsCVerifier();
```

The verifier has a single entry point:

```solidity
function verifyForsCUnbalanced(
    bytes32 pkSeed,
    bytes32 pkRoot,
    bytes32 message,
    bytes calldata sig
) external pure returns (bool valid)
```

### 2.2. Verification Algorithm

The verifier performs these steps in Yul assembly (~66K gas base + ~500 gas per unbalanced auth node):

**Step 1 — Parse signature and derive q:**

```
authBytes = sig.length - 2452
q = authBytes / 16          // leaf index derived from sig length, no on-chain counter
```

Minimum sig length is 2468 bytes (q=1). Auth bytes must be a positive multiple of 16.

**Step 2 — H_msg (192-byte domain-separated hash):**

```
H_msg = keccak256(pkSeed || pkRoot || R || message || counter || 0xFF..FF)
                   32B      32B      32B    32B        32B       32B = 192 bytes
```

The domain mask `0xFF..FF` (32 bytes of all-ones) separates H_msg from all other tweakable hashes, which are 96 or 128 bytes.

**Step 3 — Forced-zero check:**

```
last_index = (H_msg >> 125) & 0x1F    // bits 125-129
require(last_index == 0)               // tree 25 index must be zero
```

This eliminates one full FORS tree opening from the signature (saves ~96 bytes and ~6 hash ops). The signer grinds the counter to satisfy this; the verifier just checks it.

**Step 4 — Verify 25 FORS tree openings:**

For each tree `t` in `0..24`:

```
index_t = (H_msg >> (t * 5)) & 0x1F

// Hash the revealed secret into a leaf
leaf_adrs = {atype=3, kp=t, ci=q, ha=index_t}
node = keccak256(pkSeed || leaf_adrs || secret_t) & N_MASK

// Walk 5-level auth path to tree root
for h in 0..5:
    sibling = auth[t][h]
    parent_adrs = {atype=3, kp=t, ci=q, cp=h+1, ha=parent_idx}
    // Branchless Merkle swap (Solady pattern):
    s = (pathIdx & 1) << 5
    mstore(xor(0x40, s), node)
    mstore(xor(0x60, s), sibling)
    node = keccak256(pkSeed || parent_adrs || left || right) & N_MASK
```

**Step 5 — Last tree (tree 25, forced-zero):**

The signer provides the last tree's root directly (index is forced to 0, so the root itself suffices). The verifier hashes it as a leaf:

```
lastRoot_adrs = {atype=3, kp=25, ci=q, ha=0}
tree_root_25 = keccak256(pkSeed || lastRoot_adrs || lastRoot) & N_MASK
```

**Step 6 — Compress 26 FORS roots into forsPk:**

```
roots_adrs = {atype=4, ci=q}
forsPk = keccak256(pkSeed || roots_adrs || root_0 || root_1 || ... || root_25) & N_MASK
                    32B      32B          26 * 32B = 896 bytes total
```

**Step 7 — Walk unbalanced tree auth path:**

The unbalanced tree connects Q_MAX FORS public keys in a left-spine structure:

```
// Step 0: auth[0] is LEFT, forsPk is RIGHT
unb_adrs = {atype=6, cp=q-1}
node = keccak256(pkSeed || unb_adrs || auth[0] || forsPk) & N_MASK

// Steps 1..q-1: node is LEFT, auth[j] is RIGHT
for j in 1..q:
    unb_adrs = {atype=6, cp=q-1-j}
    node = keccak256(pkSeed || unb_adrs || node || auth[j]) & N_MASK
```

**Step 8 — Compare:**

```
valid = (node == pkRoot)
```

### 2.3. Account Contract Integration

The account contract stores slot registrations and delegates verification to the shared verifier. Here is the minimal integration pattern:

```solidity
// Storage
mapping(bytes32 => bytes32) public slots; // H(r) → H(subPkSeed || subPkRoot)
address public immutable forscVerifier;

// Type 2 validation (compact FORS+C path)
function validateType2(bytes32 msgHash, bytes calldata pq) internal view returns (bool) {
    bytes32 key     = bytes32(pq[0:32]);      // H(r), identifies the slot
    bytes16 subSeed = bytes16(pq[32:48]);      // sub-key pkSeed (16 bytes, n=128-bit)
    bytes16 subRoot = bytes16(pq[48:64]);      // sub-key pkRoot (16 bytes)

    // Verify the sub-key belongs to a registered slot
    require(keccak256(abi.encodePacked(subSeed, subRoot)) == slots[key]);

    // Delegate FORS+C verification to shared verifier
    (bool ok, bytes memory res) = forscVerifier.staticcall(
        abi.encodeWithSignature(
            "verifyForsCUnbalanced(bytes32,bytes32,bytes32,bytes)",
            bytes32(subSeed),     // pad to 32 bytes for the verifier
            bytes32(subRoot),
            msgHash,
            pq[64:]               // raw FORS+C signature
        )
    );
    return ok && res.length >= 32 && abi.decode(res, (bool));
}
```

Slot registration (Type 1 path, requires C11 full SPHINCS- proof):

```solidity
function registerSlot(bytes32 r, bytes16 subSeed, bytes16 subRoot) internal {
    bytes32 key = keccak256(abi.encodePacked(r));
    require(slots[key] == bytes32(0), "slot exists");
    slots[key] = keccak256(abi.encodePacked(subSeed, subRoot));
}
```

### 2.4. Address Field Layout (ADRS)

All tweakable hashes pack a 32-byte address into a single `uint256`. The verifier uses these address types:

| atype | Name | Fields used | Purpose |
|---|---|---|---|
| 3 | FORS_TREE | kp=tree, ci=q, cp=height, ha=index | FORS leaf hash and internal nodes |
| 4 | FORS_ROOTS | ci=q | Compress 26 FORS roots into forsPk |
| 6 | UNBALANCED | cp=depth | Walk unbalanced tree auth path |

Layout in a `uint256` (big-endian):

```
bits 255-224: layer     (unused, 0)
bits 223-160: tree      (unused, 0)
bits 159-128: atype     (3, 4, or 6)
bits 127- 96: kp        (tree index for FORS)
bits  95- 64: ci        (q = leaf counter)
bits  63- 32: cp        (height or depth)
bits  31-  0: ha        (leaf/node index)
```

---

## 3. Rust Signer for Constrained Devices

### 3.1. Dependencies

Minimal `no_std`-compatible dependency set for an embedded signer:

```toml
[dependencies]
tiny-keccak = { version = "2", features = ["keccak"], default-features = false }

# Optional: for BIP-39 key derivation on richer devices
# bip39 = { version = "2", default-features = false }
# hmac = "0.12"
# sha2 = "0.10"
```

`tiny-keccak` is the only hard requirement. It provides `no_std` Keccak-256 with no allocator needed for the hash primitive itself. The signer needs ~16 KB stack for tree construction and ~150 KB heap for precomputed state (or can recompute per-sign on very constrained devices).

### 3.2. Core Types and Constants

```rust
#![no_std]

// 256-bit value in big-endian word order: [0] = most significant
pub type U256 = [u64; 4];
pub const ZERO: U256 = [0; 4];

// JARDÍN FORS+C Variant 2 parameters
pub const N: usize = 16;         // hash output bytes (128-bit security)
pub const K: usize = 26;         // number of FORS trees
pub const A: usize = 5;          // FORS tree height (2^5 = 32 leaves/tree)
pub const A_MASK: u64 = 0x1F;    // (1 << A) - 1
pub const Q_MAX: usize = 95;     // max signatures per slot

// N_MASK: keep top 128 bits of keccak output
pub const N_MASK: U256 = [u64::MAX, u64::MAX, 0, 0];

// Address type constants
pub const ADRS_FORS_TREE: u32 = 3;
pub const ADRS_FORS_ROOTS: u32 = 4;
pub const ADRS_UNBALANCED: u32 = 6;

// Domain separator for H_msg (all 0xFF)
pub const HMSG_DOMAIN: U256 = [u64::MAX; 4];

// Signature layout
pub const FORSC_BODY: usize = 32 + 4 + (K - 1) * (N + A * N) + N; // 2452
```

### 3.3. Hash Primitives

These match the Solidity verifier exactly. Every hash output is masked to 128 bits.

```rust
use tiny_keccak::{Hasher, Keccak};

fn keccak256(data: &[u8]) -> U256 {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    u256_from_be(&out)
}

fn mask_n(val: U256) -> U256 {
    [val[0] & N_MASK[0], val[1] & N_MASK[1], 0, 0]
}

/// Tweakable hash: th(seed, adrs, input) → 128-bit
fn th(seed: U256, adrs: U256, input: U256) -> U256 {
    let mut buf = [0u8; 96];
    buf[0..32].copy_from_slice(&u256_to_be(&seed));
    buf[32..64].copy_from_slice(&u256_to_be(&adrs));
    buf[64..96].copy_from_slice(&u256_to_be(&input));
    mask_n(keccak256(&buf))
}

/// Tweakable hash pair: th_pair(seed, adrs, left, right) → 128-bit
fn th_pair(seed: U256, adrs: U256, left: U256, right: U256) -> U256 {
    let mut buf = [0u8; 128];
    buf[0..32].copy_from_slice(&u256_to_be(&seed));
    buf[32..64].copy_from_slice(&u256_to_be(&adrs));
    buf[64..96].copy_from_slice(&u256_to_be(&left));
    buf[96..128].copy_from_slice(&u256_to_be(&right));
    mask_n(keccak256(&buf))
}

/// Compress multiple values: th_multi(seed, adrs, vals[]) → 128-bit
fn th_multi(seed: U256, adrs: U256, vals: &[U256]) -> U256 {
    // 32 + 32 + K*32 = 896 bytes for K=26
    let mut buf = [0u8; 896];
    buf[0..32].copy_from_slice(&u256_to_be(&seed));
    buf[32..64].copy_from_slice(&u256_to_be(&adrs));
    for (i, v) in vals.iter().enumerate() {
        let off = 64 + i * 32;
        buf[off..off + 32].copy_from_slice(&u256_to_be(v));
    }
    let len = 64 + vals.len() * 32;
    mask_n(keccak256(&buf[..len]))
}

/// JARDÍN H_msg: 192-byte domain-separated hash → full 256-bit digest
fn jardin_h_msg(seed: U256, root: U256, r: U256, message: U256, counter: u32) -> U256 {
    let mut buf = [0u8; 192];
    buf[0..32].copy_from_slice(&u256_to_be(&seed));
    buf[32..64].copy_from_slice(&u256_to_be(&root));
    buf[64..96].copy_from_slice(&u256_to_be(&r));
    buf[96..128].copy_from_slice(&u256_to_be(&message));
    // counter as u256 (big-endian, value in last 4 bytes)
    buf[156..160].copy_from_slice(&counter.to_be_bytes());
    buf[160..192].copy_from_slice(&u256_to_be(&HMSG_DOMAIN));
    keccak256(&buf)
}

/// ADRS packing (matches Solidity layout)
fn make_adrs(atype: u32, kp: u32, ci: u32, cp: u32, ha: u32) -> U256 {
    // layer=0, tree=0 for JARDÍN (single-layer FORS)
    let w1 = atype as u64;         // bits 159-128
    let w2 = ((kp as u64) << 32) | (ci as u64);
    let w3 = ((cp as u64) << 32) | (ha as u64);
    [0, w1, w2, w3]
}
```

### 3.4. Key Derivation

```rust
/// Derive JARDÍN sub-key pair from entropy
fn jardin_derive_keys(entropy: U256) -> (U256, U256) {
    let sub = keccak256(&[b"jardin_sub_v1".as_slice(), &u256_to_be(&entropy)].concat());
    let pk_seed = mask_n(keccak256(&[b"jardin_pk_seed", &u256_to_be(&sub)].concat()));
    let sk_seed = keccak256(&[b"jardin_sk_seed", &u256_to_be(&sub)].concat());
    (pk_seed, sk_seed)
}

/// Derive FORS secret for a specific (q, tree, leaf)
fn fors_secret(sk_seed: U256, q: u32, tree_idx: u32, leaf_idx: u32) -> U256 {
    let mut data = [0u8; 44]; // 32 + 5 + 4 + 4 - 1 (packed)
    let mut buf = Vec::new(); // or use fixed buffer on no_alloc
    buf.extend_from_slice(&u256_to_be(&sk_seed));
    buf.extend_from_slice(b"jfors");
    buf.extend_from_slice(&q.to_be_bytes());
    buf.extend_from_slice(&tree_idx.to_be_bytes());
    buf.extend_from_slice(&leaf_idx.to_be_bytes());
    mask_n(keccak256(&buf))
}

/// Sentinel value (used as left child of deepest unbalanced spine node)
fn jardin_sentinel(seed: U256, sk_seed: U256) -> U256 {
    let mut buf = Vec::new();
    buf.extend_from_slice(&u256_to_be(&seed));
    buf.extend_from_slice(&u256_to_be(&sk_seed));
    buf.extend_from_slice(b"jardin_sentinel");
    mask_n(keccak256(&buf))
}
```

### 3.5. Keygen (Run Once Per Slot)

This is the expensive part (~235K hashes). On a constrained device, run this during idle time or when the previous slot is nearing exhaustion.

```rust
/// Precomputed slot state — store this in device memory
pub struct JardinSlot {
    pub pk_seed: U256,
    pub sk_seed: U256,
    pub pk_root: U256,            // unbalanced tree root = sub-key public key
    pub fors_pks: [U256; Q_MAX],  // FORS public keys for q=1..Q_MAX
    pub spine: [U256; Q_MAX - 1], // unbalanced tree spine nodes
    pub sentinel: U256,
    pub next_q: u32,              // next leaf to use (starts at 1)
}

/// Build a single FORS tree and return its root
fn build_fors_tree(seed: U256, sk_seed: U256, q: u32, tree_idx: u32) -> U256 {
    let n_leaves: usize = 1 << A; // 32
    let mut nodes = [[ZERO; 32]; 6]; // levels 0..5, max 32 nodes/level

    // Leaf level
    for j in 0..n_leaves {
        let secret = fors_secret(sk_seed, q, tree_idx, j as u32);
        let adrs = make_adrs(ADRS_FORS_TREE, tree_idx, q, 0, j as u32);
        nodes[0][j] = th(seed, adrs, secret);
    }

    // Internal levels
    for h in 0..A {
        let width = n_leaves >> (h + 1);
        for idx in 0..width {
            let adrs = make_adrs(ADRS_FORS_TREE, tree_idx, q, (h + 1) as u32, idx as u32);
            nodes[h + 1][idx] = th_pair(seed, adrs, nodes[h][idx * 2], nodes[h][idx * 2 + 1]);
        }
    }
    nodes[A][0] // root
}

/// Compute FORS+C public key for a given q
fn compute_forsc_pk(seed: U256, sk_seed: U256, q: u32) -> U256 {
    let mut roots = [ZERO; K];
    for t in 0..K {
        roots[t] = build_fors_tree(seed, sk_seed, q, t as u32);
    }

    // Last tree: hash root as leaf (forced-zero optimization)
    let last_adrs = make_adrs(ADRS_FORS_TREE, (K - 1) as u32, q, 0, 0);
    roots[K - 1] = th(seed, last_adrs, roots[K - 1]);

    let roots_adrs = make_adrs(ADRS_FORS_ROOTS, 0, q, 0, 0);
    th_multi(seed, roots_adrs, &roots)
}

/// Full keygen: build unbalanced tree over Q_MAX FORS public keys
pub fn keygen(entropy: U256) -> JardinSlot {
    let (pk_seed, sk_seed) = jardin_derive_keys(entropy);
    let sentinel = jardin_sentinel(pk_seed, sk_seed);

    // Compute all Q_MAX FORS public keys
    let mut fors_pks = [ZERO; Q_MAX];
    for i in 0..Q_MAX {
        fors_pks[i] = compute_forsc_pk(pk_seed, sk_seed, (i + 1) as u32);
    }

    // Build unbalanced tree (left-spine)
    //
    // Structure:           root
    //                     /    \
    //                  spine[0]  fors_pks[0]    (q=1, rightmost)
    //                  /    \
    //              spine[1]  fors_pks[1]         (q=2)
    //              /    \
    //            ...     ...
    //          /    \
    //      sentinel  fors_pks[Q_MAX-1]           (q=Q_MAX, deepest)
    //
    let mut spine = [ZERO; Q_MAX - 1];

    // Bottom: sentinel || fors_pks[Q_MAX-1]
    let d = Q_MAX;
    spine[d - 2] = th_pair(
        pk_seed,
        make_adrs(ADRS_UNBALANCED, 0, 0, (d - 1) as u32, 0),
        sentinel,
        fors_pks[d - 1],
    );

    // Build spine upward
    for i in (0..d - 2).rev() {
        spine[i] = th_pair(
            pk_seed,
            make_adrs(ADRS_UNBALANCED, 0, 0, (i + 1) as u32, 0),
            spine[i + 1],
            fors_pks[i + 1],
        );
    }

    // Root: spine[0] || fors_pks[0]
    let pk_root = th_pair(
        pk_seed,
        make_adrs(ADRS_UNBALANCED, 0, 0, 0, 0),
        spine[0],
        fors_pks[0],
    );

    JardinSlot {
        pk_seed,
        sk_seed,
        pk_root,
        fors_pks,
        spine,
        sentinel,
        next_q: 1,
    }
}
```

**Memory budget:** `JardinSlot` is approximately:
- `fors_pks`: 95 * 32 = 3,040 bytes
- `spine`: 94 * 32 = 3,008 bytes
- Keys + sentinel: 5 * 32 = 160 bytes
- **Total: ~6.2 KB** persistent state per slot

### 3.6. Signing (Per Transaction)

This is the fast path — ~32 keccak256 calls on average.

```rust
/// Signature output
pub struct JardinSignature {
    pub data: [u8; FORSC_BODY + Q_MAX * N], // max possible size
    pub len: usize,
}

/// Sign a message using the next available leaf
pub fn sign(slot: &mut JardinSlot, message: U256) -> Result<JardinSignature, &'static str> {
    let q = slot.next_q;
    if q as usize > Q_MAX {
        return Err("slot exhausted — rotate keys");
    }

    let seed = slot.pk_seed;
    let sk_seed = slot.sk_seed;
    let root = slot.pk_root;

    // ── Step 1: Compute deterministic R ──
    let mut r_buf = [0u8; 69]; // 32 + 8("jardin_R") + 32 + 4
    r_buf[0..32].copy_from_slice(&u256_to_be(&sk_seed));
    r_buf[32..40].copy_from_slice(b"jardin_R");
    r_buf[40..72].copy_from_slice(&u256_to_be(&message));
    r_buf[72..76].copy_from_slice(&q.to_be_bytes());
    // Note: actual buffer is sk_seed(32) + "jardin_R"(8) + message(32) + q(4) = 76 bytes
    let r = keccak256(&r_buf[..76]);

    // ── Step 2: Grind counter until forced-zero ──
    // Expected iterations: 2^5 = 32 (one keccak256 each)
    let last_shift = (K - 1) * A; // 125
    let mut counter: u32 = 0;
    let digest = loop {
        let d = jardin_h_msg(seed, root, r, message, counter);
        if (u256_shr(&d, last_shift) & A_MASK) == 0 {
            break d;
        }
        counter += 1;
        if counter > 10_000_000 {
            return Err("grinding failed");
        }
    };

    // ── Step 3: Extract FORS indices ──
    let mut indices = [0u32; K];
    for t in 0..K {
        indices[t] = (u256_shr(&digest, t * A) & A_MASK) as u32;
    }
    // indices[K-1] == 0 is guaranteed by the grind

    // ── Step 4: Build FORS openings for trees 0..24 ──
    let mut sig = JardinSignature {
        data: [0u8; FORSC_BODY + Q_MAX * N],
        len: 0,
    };

    // R (32 bytes)
    sig.data[0..32].copy_from_slice(&u256_to_be(&r));
    // counter (4 bytes, big-endian)
    sig.data[32..36].copy_from_slice(&counter.to_be_bytes());
    let mut off = 36;

    for t in 0..(K - 1) {
        // Rebuild FORS tree t for this q (26 trees * 63 nodes = ~1,638 hashes)
        // This is the per-sign cost beyond grinding.
        // On very constrained devices, precompute and cache these at keygen time.
        let n_leaves: usize = 1 << A;
        let mut tree_nodes = [[ZERO; 32]; 6];

        for j in 0..n_leaves {
            let secret = fors_secret(sk_seed, q, t as u32, j as u32);
            let adrs = make_adrs(ADRS_FORS_TREE, t as u32, q, 0, j as u32);
            tree_nodes[0][j] = th(seed, adrs, secret);
        }
        for h in 0..A {
            let width = n_leaves >> (h + 1);
            for idx in 0..width {
                let adrs = make_adrs(ADRS_FORS_TREE, t as u32, q, (h + 1) as u32, idx as u32);
                tree_nodes[h + 1][idx] = th_pair(
                    seed, adrs, tree_nodes[h][idx * 2], tree_nodes[h][idx * 2 + 1]
                );
            }
        }

        // Secret (16 bytes, top half of U256)
        let secret = fors_secret(sk_seed, q, t as u32, indices[t]);
        sig.data[off..off + N].copy_from_slice(&u256_to_be(&secret)[..N]);
        off += N;

        // Auth path: 5 siblings (5 * 16 = 80 bytes)
        let mut path_idx = indices[t] as usize;
        for h in 0..A {
            let sibling = tree_nodes[h][path_idx ^ 1];
            sig.data[off..off + N].copy_from_slice(&u256_to_be(&sibling)[..N]);
            off += N;
            path_idx >>= 1;
        }
    }

    // ── Step 5: Last tree root (tree 25, 16 bytes) ──
    let last_root = build_fors_tree(seed, sk_seed, q, (K - 1) as u32);
    sig.data[off..off + N].copy_from_slice(&u256_to_be(&last_root)[..N]);
    off += N;

    assert!(off == FORSC_BODY); // 2452

    // ── Step 6: Unbalanced tree auth path (q * 16 bytes) ──
    let auth = get_unbalanced_auth_path(slot, q as usize);
    for node in &auth {
        sig.data[off..off + N].copy_from_slice(&u256_to_be(node)[..N]);
        off += N;
    }

    sig.len = off; // 2452 + q * 16

    // Advance counter
    slot.next_q = q + 1;

    Ok(sig)
}

/// Get unbalanced tree auth path for leaf q (1-indexed)
fn get_unbalanced_auth_path(slot: &JardinSlot, q: usize) -> Vec<U256> {
    let d = Q_MAX;
    let i = q - 1; // 0-indexed

    let mut auth = Vec::with_capacity(q);

    // First auth node: spine sibling or sentinel
    if i == 0 {
        auth.push(slot.spine[0]);
    } else if i >= d - 1 {
        auth.push(slot.sentinel);
    } else {
        auth.push(slot.spine[i]);
    }

    // Remaining: previous FORS public keys (walking up the spine)
    for j in (0..i).rev() {
        auth.push(slot.fors_pks[j]);
    }

    auth
}
```

**Signing cost breakdown:**

| Phase | Hashes | Notes |
|---|---|---|
| Grinding | ~32 | 1 keccak256 per counter attempt |
| FORS tree rebuilds | 25 * 63 = 1,575 | Rebuild 25 trees to extract auth paths |
| Last tree root | 63 | One tree to get root |
| **Total per sign** | **~1,670** | ~50ms on ARM Cortex-M4 @ 100 MHz |

To avoid the 1,575 FORS rebuild hashes, precompute and cache all tree nodes at keygen time. This costs ~150 KB RAM but reduces per-sign cost to just ~32 hashes (grinding only):

```rust
/// Extended slot with precomputed FORS trees (uses ~150 KB)
pub struct JardinSlotCached {
    pub slot: JardinSlot,
    /// tree_nodes[q][tree][level][node] — all FORS trees precomputed
    /// Only stores the current q's trees; rebuild when q advances.
    pub current_trees: [[[U256; 32]; 6]; K - 1], // 25 trees * 6 levels * 32 nodes * 32B
}
```

### 3.7. Constrained Device Optimization Strategies

**Strategy A — Minimal RAM (~6 KB), slow sign (~1,670 hashes):**
Store only `JardinSlot`. Rebuild FORS trees on each sign. Best for devices with limited RAM but no latency requirements.

**Strategy B — Moderate RAM (~150 KB), fast sign (~32 hashes):**
Precompute all FORS trees for the current q at keygen time. Cache in `JardinSlotCached`. After signing, advance q and rebuild trees for the next q during idle time.

**Strategy C — Pipelined keygen:**
While using q=N, precompute trees for q=N+1 in background. When the slot nears exhaustion (q > 80), begin keygen for the next slot in background. The registration Type 1 transaction can be sent as soon as the new slot's `pk_root` is ready.

### 3.8. U256 Helpers

```rust
fn u256_to_be(val: &U256) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&val[0].to_be_bytes());
    out[8..16].copy_from_slice(&val[1].to_be_bytes());
    out[16..24].copy_from_slice(&val[2].to_be_bytes());
    out[24..32].copy_from_slice(&val[3].to_be_bytes());
    out
}

fn u256_from_be(bytes: &[u8; 32]) -> U256 {
    [
        u64::from_be_bytes(bytes[0..8].try_into().unwrap()),
        u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
        u64::from_be_bytes(bytes[16..24].try_into().unwrap()),
        u64::from_be_bytes(bytes[24..32].try_into().unwrap()),
    ]
}

/// Extract bits from U256 (big-endian) at a given bit position
fn u256_shr(val: &U256, bits: usize) -> u64 {
    if bits >= 256 { return 0; }
    let word_idx = bits / 64;
    let bit_idx = bits % 64;
    let be_word_idx = 3 - word_idx;
    if bit_idx == 0 {
        val[be_word_idx]
    } else if be_word_idx == 0 {
        val[0] >> bit_idx
    } else {
        (val[be_word_idx] >> bit_idx) | (val[be_word_idx - 1] << (64 - bit_idx))
    }
}
```

---

## 4. Key Rotation Logic

### 4.1. Lifecycle

```
         ┌─────────────────────────────────────────────────────────┐
         │                    Lifecycle                            │
         │                                                        │
DEPLOY ──┤  masterPkSeed, masterPkRoot set (C11 identity)         │
         │                                                        │
         │  ┌──── Slot N ────────────────────────────────┐        │
         │  │                                            │        │
    ───────►│ Type 1: register(r, subSeed, subRoot)      │        │
         │  │   requires: C11 proof over masterPk        │        │
         │  │   writes: slots[H(r)] = H(subSeed||subRoot)│        │
         │  │   gas: ~289-323K                           │        │
         │  │                                            │        │
         │  │ Type 2: sign(q=1)   → 2,468 B, 173K gas   │        │
         │  │ Type 2: sign(q=2)   → 2,484 B, 174K gas   │        │
         │  │ ...                                        │        │
         │  │ Type 2: sign(q=95)  → 3,972 B, 219K gas   │        │
         │  │                                            │        │
         │  └──── Slot exhausted ────────────────────────┘        │
         │                     │                                  │
         │                     ▼                                  │
         │  ┌──── Slot N+1 ──────────────────────────────┐        │
         │  │ Type 1: register(r', subSeed', subRoot')   │        │
         │  │ ...                                        │        │
         │  └────────────────────────────────────────────┘        │
         └────────────────────────────────────────────────────────┘
```

### 4.2. When to Rotate

| Trigger | Action |
|---|---|
| `next_q > Q_MAX` (95) | **Must rotate.** Generate new slot, send Type 1 registration. |
| Device backup restored | **Must rotate.** Old q values may be reused. Generate fresh slot. |
| Proactive (q > 80) | **Should rotate.** Begin keygen for next slot in background. |
| Key compromise suspected | Rotate master keys via `rotateMasterKeys()` (self-call through account). |

### 4.3. Signer-Side Rotation

```rust
/// State machine for the signer
pub struct JardinSigner {
    pub master_entropy: U256,        // derives masterPkSeed, masterPkRoot (C11)
    pub current_slot: JardinSlot,
    pub next_slot: Option<JardinSlot>, // precomputed next slot
    pub slot_count: u32,             // for entropy derivation
}

impl JardinSigner {
    /// Check if rotation is needed
    pub fn needs_rotation(&self) -> bool {
        self.current_slot.next_q as usize > Q_MAX
    }

    /// Check if precomputation should start
    pub fn should_precompute(&self) -> bool {
        self.current_slot.next_q > 80 && self.next_slot.is_none()
    }

    /// Begin precomputing the next slot (call during idle time)
    pub fn precompute_next_slot(&mut self) {
        self.slot_count += 1;
        // Derive fresh entropy for the new slot
        let slot_entropy = keccak256(
            &[
                &u256_to_be(&self.master_entropy)[..],
                b"jardin_slot",
                &self.slot_count.to_be_bytes(),
            ].concat()
        );
        self.next_slot = Some(keygen(slot_entropy));
    }

    /// Rotate to the precomputed slot
    /// Returns (r, subPkSeed, subPkRoot) for the Type 1 registration tx
    pub fn rotate(&mut self) -> Result<(U256, U256, U256), &'static str> {
        let new_slot = self.next_slot.take().ok_or("next slot not precomputed")?;
        let r = keccak256(
            &[
                &u256_to_be(&self.master_entropy)[..],
                b"jardin_r",
                &self.slot_count.to_be_bytes(),
            ].concat()
        );
        let sub_seed = new_slot.pk_seed;
        let sub_root = new_slot.pk_root;
        self.current_slot = new_slot;
        Ok((r, sub_seed, sub_root))
    }

    /// Sign a message (Type 2 compact)
    pub fn sign_compact(&mut self, message: U256) -> Result<JardinSignature, &'static str> {
        if self.needs_rotation() {
            return Err("slot exhausted — call rotate() first");
        }
        sign(&mut self.current_slot, message)
    }
}
```

### 4.4. On-Chain Rotation Flow

**Registration transaction (Type 1):**

The signer constructs:

```
signature = [0x01]                    // type byte
          + [ecdsa_sig (65B)]         // ECDSA over userOpHash (hybrid only)
          + [r (32B)]                 // slot randomness
          + [subPkSeed (16B)]         // new sub-key seed
          + [subPkRoot (16B)]         // new sub-key root
          + [c11_sig (~3976B)]        // full C11 SPHINCS- proof over masterPk
```

The account contract:
1. Verifies ECDSA signature (hybrid mode only)
2. Verifies C11 signature against `masterPkSeed`, `masterPkRoot`
3. Writes `slots[keccak256(r)] = keccak256(subPkSeed || subPkRoot)`

**Compact transaction (Type 2):**

```
signature = [0x02]                    // type byte
          + [ecdsa_sig (65B)]         // ECDSA over userOpHash (hybrid only)
          + [H(r) (32B)]             // slot key (hash of r)
          + [subPkSeed (16B)]         // identifies the slot
          + [subPkRoot (16B)]
          + [fors_sig (2452 + q*16B)] // FORS+C signature
```

### 4.5. Emergency Fallback

If the signer state is lost entirely, a stateless C11 signature can always be used without any registered slot. Send a Type 1 with `r = 0x00` (no slot registration) to execute directly:

```solidity
// In the account contract, Type 1 with r == 0:
if (r != bytes32(0)) {
    // register slot
    slots[keccak256(r)] = keccak256(subSeed, subRoot);
}
// C11 verification happens regardless — tx executes either way
```

This costs ~308K gas but requires no prior state. It serves as the recovery path.

---

## 5. Signature Encoding

### 5.1. FORS+C Signature Layout (passed to verifier)

```
Offset   Size    Field
──────   ────    ─────
0        32      R (randomness from deterministic derivation)
32       4       counter (grinding result, big-endian u32)
36       96×25   25 FORS tree openings:
                   each = secret(16B) + auth_path(5 × 16B = 80B) = 96B
2436     16      lastRoot (tree 25's root, forced-zero optimization)
2452     16×q    unbalanced tree auth path (q nodes × 16B)
──────
Total:   2452 + q × 16 bytes
```

### 5.2. Signature Sizes

| q | Total bytes | Calldata gas (@ 16/byte) |
|---|---|---|
| 1 | 2,468 | ~39K |
| 32 | 2,964 | ~47K |
| 95 | 3,972 | ~64K |

For comparison, a full C11 SPHINCS- signature is 3,976 bytes — nearly identical to q=95. This is the natural crossover point that motivates Q_MAX=95.

---

## 6. Security Properties

### 6.1. Normal Operation (each q used once)

- **Security: 128 bits** (k × a = 26 × 5 = 130 bits conservative)
- Each FORS+C signature reveals 25 secrets from 25 independent trees. An attacker must guess a valid set of secrets for a different message — brute force of 2^130.

### 6.2. Accidental Double-Sign (r=2, same q signed twice)

- **Security: ~105 bits** (graceful degradation)
- Two signatures on the same q reveal at most 2 secrets per tree (out of 32 leaves). Forging requires guessing the remaining secrets — still 2^105 work.
- This can happen if signer state is restored from backup. The protocol handles it cryptographically rather than with fragile on-chain counters.

### 6.3. Forced-Zero Optimization

The last FORS tree (tree 25) has its index forced to 0 by grinding. This means:
- The signer never reveals a secret from tree 25 — only the root
- Saves 80 bytes (5-level auth path) per signature
- Cost: ~32 extra keccak256 calls during signing (grinding)

### 6.4. Replay Protection

FORS+C itself does not provide replay protection. Replay is prevented by:
- **ERC-4337:** EntryPoint nonce
- **EIP-8141 Frame:** protocol-level nonce
- The message hash includes the nonce, so replaying a signature on a different nonce produces a different H_msg digest.

### 6.5. Quantum Safety

| Component | Quantum safe? | Notes |
|---|---|---|
| FORS+C verification | Yes | Hash-based, no lattice/number theory |
| Keccak-256 | Yes | Grover's reduces to 128-bit (from 256-bit) |
| ECDSA co-signature | No | Hybrid mode only; defense-in-depth |
| Key derivation | Yes | HMAC-SHA512 + Keccak (symmetric) |
| Unbalanced tree | Yes | Standard Merkle construction |
