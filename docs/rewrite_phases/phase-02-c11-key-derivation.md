# Phase 2 — C11 key derivation from BIP-39 seed

**Status:** not started.
**Depends on:** phase 1 (flash persistence) — independent actually, can be done
in parallel.
**Blocks:** phase 3 (unified sign state machine needs the C11 keypair to sign
Type 1 registrations).

## Why this phase exists

SPHINCs-'s reference signer (`/home/markus/Documents/SPHINCs-/signer-wasm/`)
derives a SPHINCS+C11 master keypair from the BIP-39 seed using a specific
domain-separated KDF chain. Our on-chain verifier will check Type 1
signatures against that exact master, so the derivation must be bit-for-bit
identical to SPHINCs-'s. If we get any domain tag or byte order wrong, the
on-chain verifier rejects every Type 1 we produce, which means slot
registration fails, which means the wallet never works.

This is **part of the recovery contract**: the same 24 words must produce the
same on-chain wallet address forever, across devices, across firmware
versions.

## Reference: SPHINCs-'s derivation

From `/home/markus/Documents/SPHINCs-/signer-wasm/src/keygen.rs`:

```rust
pub fn from_mnemonic(mnemonic: &str, passphrase: &str)
    -> Result<(U256, U256, U256, String), String>
{
    // Step 1: BIP-39 mnemonic → 512-bit seed
    let bip39_seed = Mnemonic::parse(mnemonic)?.to_seed_normalized(passphrase);

    // Step 2: SPHINCS+ master secret (quantum-safe)
    let sphincs_master = HMAC-SHA512("sphincs-c6-v1", bip39_seed);  // 64 bytes

    // Step 3: Derive pkSeed and skSeed
    let pk_seed = keccak256(["pk_seed", sphincs_master[0..32]]) & N_MASK;
    let sk_seed = keccak256(["sk_seed", sphincs_master[0..32]]);

    // Step 4: ECDSA address (WE DO NOT USE THIS — pure PQ only)

    // Step 5: Build pkRoot (full SPHINCS+ hypertree root)
    let pk_root = merkle::build_subtree_root(pk_seed, sk_seed, 1, 0);

    Ok((pk_seed, sk_seed, pk_root, ecdsa_address))
}
```

**Domain tags to copy verbatim:**
- HMAC-SHA512 key: the ASCII bytes `"sphincs-c6-v1"` (13 bytes, no nul, no
  length prefix)
- Keccak-256 inputs:
  - pkSeed: `b"pk_seed"` (7 bytes) `||` `sphincs_master[0..32]`
  - skSeed: `b"sk_seed"` (7 bytes) `||` `sphincs_master[0..32]`
- N_MASK: top 16 bytes kept, bottom 16 bytes zeroed (matches
  `jardin-fosc`'s `mask_n`)

## What this repo already has

- **`sphincs-c7` crate** (at `sphincs-c7/`) actually implements **SPHINCS+C11**
  (name is a historical holdover from when the repo used C7). Confirmed by
  reading `sphincs-c7/src/params.rs:1–3`:
  > `C11: W+C_F+C  h=16  d=2  a=11  k=13  w=8  l=43  target_sum=203  sig=3976`

  Compatible with SPHINCs-'s `SPHINCs-C11Asm.sol` verifier (also confirmed by
  the crate header comment).
- **`secure/src/crypto.rs`** already has JARDÍN master entropy derivation
  (`jardin_master_entropy_from_bip39`) using domain `"pqwallet-jardin-master"`.
  That's a **different** derivation — it feeds into
  `jardin_fosc::hash::jardin_slot_entropy` for slot-entropy. Leave it alone;
  it's already frozen recovery state.
- **HMAC-SHA512** is available via the `hmac` + `sha2` crates (check
  `secure/Cargo.toml`).

## Files to modify

- **`secure/src/crypto.rs`** — add the C11 keypair derivation function.
- **`secure/Cargo.toml`** — verify `hmac` and `sha2` deps (they should already
  be present). No additions expected.

## What to build

Add to `secure/src/crypto.rs`:

```rust
/// SPHINCs--compatible C11 master keypair derivation.
///
/// Matches `/home/markus/Documents/SPHINCs-/signer-wasm/src/keygen.rs` exactly.
/// The "sphincs-c6-v1" domain tag is a historical quirk — do not "fix" it.
///
/// Returns `(pk_seed_32, sk_seed_32)`. pk_seed has the top 16 bytes of the
/// keccak output kept and the bottom 16 bytes zeroed (N-mask). sk_seed is
/// the full 32-byte keccak output.
///
/// This is part of the recovery contract: same 24 words must produce the
/// same pk_seed/sk_seed forever. Changing any tag or byte order changes
/// the on-chain wallet address.
pub fn derive_c11_master_from_bip39_seed(bip39_seed: &[u8; 64]) -> ([u8; 32], [u8; 32]) {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    use sha3::{Digest, Keccak256};

    // Step 1: HMAC-SHA512("sphincs-c6-v1", bip39_seed) → 64-byte master
    let mut mac = Hmac::<Sha512>::new_from_slice(b"sphincs-c6-v1")
        .expect("HMAC-SHA512 accepts any key length");
    mac.update(bip39_seed);
    let sphincs_master = mac.finalize().into_bytes();

    // Step 2: pk_seed = keccak256("pk_seed" || master[0..32]) & N_MASK
    let mut pk_hasher = Keccak256::new();
    pk_hasher.update(b"pk_seed");
    pk_hasher.update(&sphincs_master[..32]);
    let pk_digest = pk_hasher.finalize();
    let mut pk_seed = [0u8; 32];
    pk_seed[..16].copy_from_slice(&pk_digest[..16]);  // top 16 bytes, rest zero

    // Step 3: sk_seed = keccak256("sk_seed" || master[0..32])
    let mut sk_hasher = Keccak256::new();
    sk_hasher.update(b"sk_seed");
    sk_hasher.update(&sphincs_master[..32]);
    let sk_digest = sk_hasher.finalize();
    let mut sk_seed = [0u8; 32];
    sk_seed.copy_from_slice(&sk_digest);

    // Zeroize the full master buffer — we only needed the first 32 bytes.
    // (sphincs_master is a GenericArray; it's dropped at function end but
    // we go out of our way to zero it first in case the compiler reuses
    // the stack slot.)
    let mut master_arr = [0u8; 64];
    master_arr.copy_from_slice(&sphincs_master);
    master_arr.zeroize();

    (pk_seed, sk_seed)
}
```

Additionally, provide a derivation that returns `(pk_seed, pk_root)` by
running the SPHINCs-C11 hypertree root computation from the `sphincs-c7`
crate. Check what the crate exposes:

```bash
grep -n "pub fn\|pub use" /home/markus/Documents/sphincs_rust/sphincs-c7/src/lib.rs
```

If the crate has `SigningKey::from_seed_pair(pk_seed, sk_seed)` or similar,
use that. Otherwise, expose the hypertree-root helper.

## Cross-codebase verification test

The critical thing is that a given mnemonic produces the same
`(pk_seed, sk_seed, pk_root)` tuple in both repos.

**Test vector procedure:**

1. Install Rust in both repos (should already be set up).
2. In `/home/markus/Documents/SPHINCs-/signer-wasm/`, add or run a test that
   invokes `keygen::from_mnemonic` with a fixed mnemonic. Record
   `pk_seed`, `sk_seed`, `pk_root` in hex. A fixed test mnemonic to use
   (not a real wallet's words):
   ```
   abandon abandon abandon abandon abandon abandon abandon abandon
   abandon abandon abandon abandon abandon abandon abandon abandon
   abandon abandon abandon abandon abandon abandon abandon art
   ```
   (This is BIP-39 test vector 1 with 24 words; search BIP-39 wikis if you
   need entropy.)
3. In this repo, write a test in `secure/src/crypto.rs` (#[cfg(test)] block)
   that calls `derive_c11_master_from_bip39_seed` on the BIP-39 seed
   derived from the same mnemonic. Assert pk_seed and sk_seed match.
4. For pk_root, if you can extract the corresponding function from
   `sphincs-c7`, also assert that matches.

The test file location: `secure/src/crypto.rs` host tests (check existing
pattern — the `aa/userop.rs` tests work; see `#[cfg(test)]` block there for
the pattern).

## Frozen invariants specific to this phase

- Domain tag `"sphincs-c6-v1"` (13 bytes ASCII, no nul, no length prefix).
- Domain tag `"pk_seed"` (7 bytes ASCII) as prefix before master[0..32].
- Domain tag `"sk_seed"` (7 bytes ASCII) as prefix before master[0..32].
- HMAC-SHA512 key is the tag bytes; message is the full 64-byte BIP-39 seed.
- Only the first 32 bytes of the 64-byte HMAC output are used for pkSeed /
  skSeed derivation. The rest are discarded.
- N_MASK on pkSeed: top 16 bytes (offsets 0..16) kept, bottom 16 bytes
  (offsets 16..32) are zero.
- skSeed is the full 32-byte keccak output, no masking.

## What NOT to do

- **Don't "modernize"** `"sphincs-c6-v1"` to `"sphincs-c11-v1"` — it's a
  historical quirk in the reference repo and changing it changes every
  wallet address.
- **Don't swap HMAC-SHA512 for HMAC-SHA256** — SPHINCs- uses 512, and even
  though we only use the first 32 bytes, the mixing is different.
- **Don't add a passphrase argument.** SPHINCs-'s keygen takes one but this
  wallet uses empty passphrase (standard BIP-39). The `to_seed_normalized`
  call in SPHINCs- passes "" by default in tests.
- **Don't zeroize pk_seed / sk_seed** — those are meant to leave the function
  as return values. Only the intermediate `sphincs_master` buffer should be
  wiped.
- **Don't add this derivation to `unlock_master()` eagerly** — derive
  on-demand inside the sign command, since some signing paths (Type 2 only)
  don't need the C11 keypair and the derivation isn't free.

## Verification

1. `cargo build --release --target thumbv8m.main-none-eabi -p sphincs-tz-secure ...` (should still compile).
2. Host unit test that derives `(pk_seed, sk_seed)` for the fixed mnemonic
   and asserts known-good hex values. You'll need to generate those hex
   values first by running the SPHINCs- signer.
3. Optionally: port the SPHINCs-'s `test_cases.rs` or equivalent test
   vectors into this repo as a regression test.

## Where to go next

Phase 3 needs `derive_c11_master_from_bip39_seed` to exist. It also needs a
way to sign arbitrary 32-byte hashes with the derived C11 keypair — look at
what `sphincs-c7::SigningKey` exposes and wire it up through a helper in
`crypto.rs` if the crate's API isn't ergonomic enough to call directly from
`cmd_sign_userop.rs`.
