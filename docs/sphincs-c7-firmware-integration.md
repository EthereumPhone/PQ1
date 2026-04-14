# SPHINCS+C7 Firmware Integration Guide

Context: the `sphincs-c7` Rust crate is implemented and verified against the Python reference signer and Solidity verifier. This document covers everything needed to wire it into the firmware, replacing the `slh-dsa` crate (SLH-DSA-SHA2-128f, 17,088-byte signatures) with `sphincs-c7` (keccak256-based, 3,704-byte signatures).

## What changes and what doesn't

**Changes:**
- Signature size: 17,088 → 3,704 bytes
- Hash function: SHA-256 → Keccak-256
- Key derivation domain tags (new recovery contract)
- `slh-dsa` crate removed, `sphincs-c7` added
- Seed split: sk_seed(16)+sk_prf(16)+pk_seed(16) → sk_seed(32)+pk_seed(16)

**Stays the same:**
- Verifying key: 32 bytes (pk_seed[16] || pk_root[16])
- Wrapper header: 73 bytes (signer_type + key_index + ots_index + pk_seed_b32 + pk_root_b32)
- BIP-39 entropy: 32 bytes, dual-SE XOR split unchanged
- PBKDF2-HMAC-SHA512 from entropy to 64-byte BIP-39 seed
- All SE drivers, PIN handling, TrustZone, NSC gateway dispatch

## File-by-file changes

### 1. `Cargo.toml` (workspace root)

```diff
 members = [
     ...
     "sphincs-c7",
 ]

+[workspace.dependencies]
+sphincs-c7 = { path = "sphincs-c7" }

-[profile.dev.package.slh-dsa]
-opt-level = 3
+[profile.dev.package.sphincs-c7]
+opt-level = 3

-[profile.release.package.slh-dsa]
-opt-level = 3
+[profile.release.package.sphincs-c7]
+opt-level = 3
```

### 2. `secure/Cargo.toml`

```diff
-slh-dsa = { version = "0.2.0-rc.4", default-features = false }
-signature = { version = "3.0.0-rc.10", default-features = false }
+sphincs-c7 = { workspace = true }
```

The `signature` crate is no longer needed — `sphincs-c7` has its own `SigningKey::sign()` API.

### 3. `shared/src/lib.rs`

All size constants that cascade through the entire codebase:

```rust
// BEFORE → AFTER
pub const SIGNING_KEY_LEN: usize = 64;      // → 48  (sk_seed=32 + pk_seed=16)
pub const VERIFYING_KEY_LEN: usize = 32;    // → 32  (unchanged)
pub const SIGNATURE_LEN: usize = 17_088;    // → 3_704

// Derived (auto-update via the formulas already in code):
// WRAPPER_TOTAL_LEN = 73 + 3_704 = 3_777
// INIT_CODE_LEN: needs recalculation (see §6)
// MAX_USEROP_RESPONSE_LEN: recalculate from new INIT_CODE_LEN + WRAPPER_TOTAL_LEN
```

The `signature_is_32byte_aligned` test assertion must change: 3,704 % 32 = 8, so the raw signature is NOT 32-byte aligned. The ABI encoding adds 24 bytes of zero padding. Either remove the assertion or change it to test the padded length.

### 4. `secure/src/crypto.rs` — Key derivation

This is the recovery contract. All domain tags change.

**Import change:**
```diff
-use slh_dsa::{Sha2_128f, SigningKey};
+use sphincs_c7::SigningKey;
```

**New KDF helper** (keccak256-based, matching C7's hash domain):
```rust
fn kdf_keccak(domain: &[u8], input: &[u8], index: u8) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    let mut h = Keccak256::new();
    h.update(domain);
    h.update(input);
    h.update([index]);
    h.finalize().into()
}
```

**Seed derivation — `SEED_LEN` stays 48 but the split changes:**

```rust
pub const SEED_LEN: usize = 48; // sk_seed(32) + pk_seed(16)

// BEFORE: 3 x SHA-256 chunks → sk_seed(16), sk_prf(16), pk_seed(16)
// AFTER:  2 x Keccak-256 chunks → sk_seed(32), pk_seed(16)

pub fn c7_seed_from_bip39(bip39_seed: &[u8; 64]) -> [u8; SEED_LEN] {
    let mut out = [0u8; SEED_LEN];
    let sk_hash = kdf_keccak(b"sphincsc7-sk-seed", bip39_seed, 0);
    out[0..32].copy_from_slice(&sk_hash);              // sk_seed: 32 bytes
    let pk_hash = kdf_keccak(b"sphincsc7-pk-seed", bip39_seed, 0);
    out[32..48].copy_from_slice(&pk_hash[..16]);       // pk_seed: 16 bytes
    out
}
```

**Bootstrap derivation:**
```rust
pub fn bootstrap_seed_from_bip39(bip39_seed: &[u8; 64]) -> [u8; SEED_LEN] {
    let mut out = [0u8; SEED_LEN];
    let sk = kdf_keccak(b"pqwallet-c7-bootstrap-sk-seed", bip39_seed, 0);
    out[0..32].copy_from_slice(&sk);
    let pk = kdf_keccak(b"pqwallet-c7-bootstrap-pk-seed", bip39_seed, 0);
    out[32..48].copy_from_slice(&pk[..16]);
    out
}
```

**Per-chain main signer derivation:**
```rust
pub fn main_signer_seed_from_bip39(
    bip39_seed: &[u8; 64], chain_id: u64, key_index: u32,
) -> [u8; SEED_LEN] {
    let mut input = [0u8; 64 + 8 + 4];
    input[..64].copy_from_slice(bip39_seed);
    input[64..72].copy_from_slice(&chain_id.to_be_bytes());
    input[72..76].copy_from_slice(&key_index.to_be_bytes());

    let mut out = [0u8; SEED_LEN];
    let sk = kdf_keccak(b"pqwallet-c7-main-sk-seed", &input, 0);
    out[0..32].copy_from_slice(&sk);
    let pk = kdf_keccak(b"pqwallet-c7-main-pk-seed", &input, 0);
    out[32..48].copy_from_slice(&pk[..16]);
    out
}
```

**`derive_signing_key` — construct the C7 `SigningKey`:**
```rust
pub fn derive_signing_key(seed: &[u8; SEED_LEN]) -> SigningKey {
    let mut sk_seed = [0u8; 32];
    let mut pk_seed = [0u8; 16];
    sk_seed.copy_from_slice(&seed[0..32]);
    pk_seed.copy_from_slice(&seed[32..48]);
    // keygen computes pk_root by building the full hypertree — expensive!
    // Only call at provisioning time. For signing, use from_parts with
    // a cached pk_root.
    SigningKey::keygen(sk_seed, pk_seed)
}
```

**Important: keygen is expensive (~10s on Cortex-M33).** At provisioning, compute it once and cache the VK (pk_seed || pk_root) in r-mem. At signing time, reconstruct using `SigningKey::from_parts(sk_seed, pk_seed, pk_root)` with the cached pk_root — no hypertree rebuild needed.

**All `derive_*_key_from_entropy` functions** follow the same pattern — change the return type from `SigningKey<Sha2_128f>` to `sphincs_c7::SigningKey`, call the new seed derivation functions, and construct via `from_parts` (with cached pk_root) or `keygen` (at provisioning).

**`derive_keypair_from_entropy` return type:**
```diff
-pub fn derive_keypair_from_entropy(entropy: &[u8; ENTROPY_LEN]) -> (SigningKey<Sha2_128f>, [u8; 32])
+pub fn derive_keypair_from_entropy(entropy: &[u8; ENTROPY_LEN]) -> (sphincs_c7::SigningKey, [u8; 32])
```

The 32-byte VK is `signing_key.verifying_key().to_bytes()` — same format (pk_seed[16] || pk_root[16]).

### 5. `secure/src/nsc/sign_and_emit.rs` — Signing hot path

**`decrypt_and_sign()` — raw signature (legacy path):**

```diff
-    use slh_dsa::Sha2_128f;
-    use slh_dsa::SigningKey as Sk;
-    let sig = match <Sk<Sha2_128f>>::try_sign_with_context(
-        &signing_key, msg_hash, &[], Some(&rand_buf),
-    ) {
+    let sig = signing_key.sign(msg_hash, Some(&rand_buf));

     // Write signature to NS memory (3,704 bytes instead of 17,088)
     let sig_bytes = sig;  // [u8; 3704] — no .to_bytes() needed
     for i in 0..SIGNATURE_LEN {
         core::ptr::write_volatile(sig_ptr.add(i), sig_bytes[i]);
     }
```

**`decrypt_and_sign_wrapped()` — PQSignatureWrapper (v2 path):**

The 73-byte wrapper header is unchanged. Only the raw signature changes:

```diff
     // 4. Write pk_seed/pk_root to wrapper header
     {
-        use signature::Keypair;
-        let vk_bytes = signing_key.verifying_key().to_bytes();
+        let vk = signing_key.verifying_key();
+        let vk_bytes = vk.to_bytes();
         // VK = pk_seed[16] || pk_root[16]
         // (padding logic stays the same)
     }

     // 5. Sign
-    use slh_dsa::Sha2_128f;
-    use slh_dsa::SigningKey as Sk;
-    let sig = match <Sk<Sha2_128f>>::try_sign_with_context(
-        &signing_key, msg_hash, &[], Some(&rand_buf),
-    ) { ... };
-    let sig_bytes = sig.to_bytes();
+    let sig_bytes = signing_key.sign(msg_hash, Some(&rand_buf));

     // 6. Write 3,704-byte signature after header
     let sig_offset = WRAPPER_HEADER_LEN;
     for i in 0..SIGNATURE_LEN {
         core::ptr::write_volatile(sig_ptr.add(sig_offset + i), sig_bytes[i]);
     }
```

**`derive_sign_randomizer()` — switch to keccak256 for consistency:**

```diff
 fn derive_sign_randomizer(master: &[u8; 32], msg_hash: &[u8; 32], out: &mut [u8; 16]) {
-    use sha2::{Digest, Sha256};
-    let mut h = Sha256::new();
-    h.update(b"sphincs-sign-rand");
+    use sha3::{Digest, Keccak256};
+    let mut h = Keccak256::new();
+    h.update(b"sphincsc7-sign-rand");
     h.update(master);
     h.update(msg_hash);
     let r = h.finalize();
     out.copy_from_slice(&r[..16]);
 }
```

### 6. `secure/src/aa/init_code.rs` — initCode construction

`INIT_CODE_LEN` changes because the bootstrap signature is now 3,704 bytes (not 32-byte aligned).

**ABI padding:** `3704 % 32 = 8`, so 24 bytes of zero-padding are needed:

```rust
// New INIT_CODE_LEN calculation:
// factory(20) + selector(4) + 4×bytes32(128) + offset(32) + length(32) + sig_padded
// sig_padded = ceil(3704 / 32) * 32 = 116 * 32 = 3712
// Total = 20 + 4 + 128 + 32 + 32 + 3712 = 3928

pub const INIT_CODE_LEN: usize = 20 + 4 + 4 * 32 + 32 + 32 + ((SIGNATURE_LEN + 31) / 32) * 32;
```

In `write_init_code_to_ns()`, add zero-padding after the signature:

```rust
// Write bootstrap signature data
for i in 0..SIGNATURE_LEN {
    core::ptr::write_volatile(out_ptr.add(pos), bootstrap_sig[i]);
    pos += 1;
}

// ABI zero-padding to 32-byte boundary
let padding = ((SIGNATURE_LEN + 31) / 32) * 32 - SIGNATURE_LEN; // = 8
for _ in 0..padding {
    core::ptr::write_volatile(out_ptr.add(pos), 0u8);
    pos += 1;
}
```

Same padding logic in `compute_init_code_hash()`:
```rust
h.update(bootstrap_sig);
let zeros = [0u8; 32];
let padding = ((SIGNATURE_LEN + 31) / 32) * 32 - SIGNATURE_LEN;
h.update(&zeros[..padding]);
```

### 7. `secure/src/nsc/cmd_sign_bootstrap.rs`

Replace `slh_dsa` imports and signing call with `sphincs_c7` equivalent. Same pattern as `sign_and_emit.rs`.

### 8. `nonsecure/` — buffer sizes auto-update

The nonsecure world uses `SIGNATURE_LEN`, `WRAPPER_TOTAL_LEN`, and `MAX_USEROP_RESPONSE_LEN` from `shared/src/lib.rs` for static buffer sizing. These auto-update when the shared constants change. No code logic changes needed in nonsecure — only buffer sizes shrink.

Files that allocate signature-sized buffers:
- `nonsecure/src/main.rs:39` — `static mut SIG_BUF: [u8; SIGNATURE_LEN]`
- `nonsecure/src/e2e_test.rs:37` — `static mut SIG_BUF: [u8; SIGNATURE_LEN]`
- `nonsecure/src/usb/commands.rs:24` — `static mut SIG_BUF: [u8; MAX_USEROP_RESPONSE_LEN + 2]`

These all reference the shared constants, so they auto-shrink. No manual edits needed.

### 9. `desktop/Cargo.toml` + `desktop/src/main.rs`

```diff
 # desktop/Cargo.toml
-slh-dsa = "0.2.0-rc.4"
-signature = "3.0.0-rc.10"
+sphincs-c7 = { path = "../sphincs-c7" }
+sha3 = "0.10"
```

In `main.rs`: replace `slh_dsa::{Sha2_128f, SigningKey, VerifyingKey}` with `sphincs_c7::{SigningKey, VerifyingKey}`. The desktop crate uses `SigningKey::new(&mut rng)` for keygen — replace with `SigningKey::keygen(sk_seed, pk_seed)` where the seeds are derived from entropy.

## Keygen performance on Cortex-M33

`SigningKey::keygen()` builds one 4096-leaf XMSS subtree at the top HT layer. Each leaf requires 43 WOTS chain computations of 7 keccak256 steps = 301 keccak256 calls. Total: 4096 × 301 ≈ 1.2M keccak256 calls + Merkle tree hashing.

At ~1500 cycles per keccak256, 160 MHz clock: **~11 seconds**.

This runs once at provisioning. At signing time, use `SigningKey::from_parts(sk_seed, pk_seed, cached_pk_root)` to skip the keygen.

## Signing performance on Cortex-M33

Each sign operation:
1. R-grinding: ~2^16 / 2^16 ≈ 1 average keccak256 for forced-zero (probability 1/65536 per attempt, but with K×A=128 bit range, so ~(2^16) trials needed... actually `P(last_index=0) ≈ 1/65536` so ~65K trials average). Each trial: 1 keccak256. At 1500 cycles: 65K × 1500 / 160M ≈ 0.6s.
2. FORS: 7 tree traversals of 65536 leaves each. Memory-efficient Treehash, but each tree is ~65K keccak256 calls. Total: 7 × 65K ≈ 455K keccak256 ≈ 4.3s.
3. HT: 2 subtree traversals of 4096 leaves + WOTS signing. ~2.5M keccak256 ≈ 23s.

**Total estimated signing time: ~28 seconds on Cortex-M33.** This is slower than SLH-DSA-SHA2-128f (~3-5s) because C7 has much larger trees (h=24 vs h'=3 per XMSS subtree). Consider precomputing the FORS trees and HT subtrees during the idle window to reduce interactive latency.

## Domain tag summary

| Purpose | Old tag | New tag |
|---------|---------|---------|
| Legacy signer seed | `"sphincs-slh-seed"` | `"sphincsc7-sk-seed"`, `"sphincsc7-pk-seed"` |
| Bootstrap sk_seed | `"pqwallet-bootstrap-sk-seed"` | `"pqwallet-c7-bootstrap-sk-seed"` |
| Bootstrap sk_prf | `"pqwallet-bootstrap-sk-prf"` | _(removed — C7 has no sk_prf)_ |
| Bootstrap pk_seed | `"pqwallet-bootstrap-pk-seed"` | `"pqwallet-c7-bootstrap-pk-seed"` |
| Main sk_seed | `"pqwallet-main-sk-seed"` | `"pqwallet-c7-main-sk-seed"` |
| Main sk_prf | `"pqwallet-main-sk-prf"` | _(removed)_ |
| Main pk_seed | `"pqwallet-main-pk-seed"` | `"pqwallet-c7-main-pk-seed"` |
| Sign randomizer | `"sphincs-sign-rand"` | `"sphincsc7-sign-rand"` |
| Wrap key | `"sphincs-wrap-key"` | _(unchanged — not hash-domain dependent)_ |
| Entropy nonce | `"sphincs-entropy-nonce"` | _(unchanged)_ |

## sphincs-c7 crate API reference

```rust
use sphincs_c7::{SigningKey, VerifyingKey, verify};
use sphincs_c7::params::{N, SIGNATURE_LEN, VERIFYING_KEY_LEN};

// Keygen (expensive — provisioning only)
let sk = SigningKey::keygen(sk_seed, pk_seed);  // builds hypertree

// Reconstruct from cached parts (fast — for signing)
let sk = SigningKey::from_parts(sk_seed, pk_seed, pk_root);

// Get verifying key
let vk: VerifyingKey = sk.verifying_key();
let vk_bytes: [u8; 32] = vk.to_bytes();  // pk_seed[16] || pk_root[16]

// Sign (returns [u8; 3704])
let sig: [u8; 3704] = sk.sign(msg_hash, Some(&randomizer));
let sig: [u8; 3704] = sk.sign(msg_hash, None);  // deterministic

// Verify
let valid: bool = vk.verify(msg_hash, &sig);
let valid: bool = verify(&pk_seed, &pk_root, msg_hash, &sig);

// Access key material
let sk_seed: &[u8; 32] = sk.sk_seed();
let pk_seed: &[u8; 16] = sk.pk_seed();
let pk_root: &[u8; 16] = sk.pk_root();
```

## Verification checklist

After integration, verify with:

1. `cargo check -p sphincs-tz-secure --target thumbv8m.main-none-eabi` — firmware compiles
2. `cargo test -p sphincs-c7` — crate unit tests + cross-language verification
3. `make run` — QEMU smoke test with mock SE
4. `make e2e` — automated end-to-end in QEMU
5. `forge test --mc GasBenchmarkReal -vvv` — on-chain C7 benchmarks still pass
6. `forge test --mc GasComparison -vvv` — gas comparison proves improvement
