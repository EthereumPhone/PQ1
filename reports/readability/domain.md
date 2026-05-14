# Readability & Excellence Review — `domain`

_Date_: 2026-05-14
_Reviewer_: Claude Code (ultrathink)

## Summary

`pqsigner-domain` is a focused, single-file `no_std` crate covering KDF, AES-GCM
wrap/unwrap, the BIP-39 → SPHINCS+C10 bridge, slot-key derivation, and PIN-state
serialisation. The code was already documented and broadly clean; the main
findings were duplicated scaffolding (mnemonic → bip39_seed → wipe; the `_fast`
derivation pair), repeated `Aes256Gcm::new_from_slice(...).unwrap()` calls on a
provably-32-byte key, two byte-identical SHA-256 KDFs (`kdf` and `kdf_sha256`),
a latent panic in `deserialize_pin_state` if `blob_len > PIN_STATE_MAX_LEN`,
plus thin test coverage for the AES and PinState round-trips. All these were
fixed in place; observable behaviour, public API names, KDF tags, and wire
formats are unchanged.

## Changes applied

- `domain/src/lib.rs:87-103` — Dedupe `kdf` and `kdf_sha256`. The two functions
  were byte-identical; `kdf_sha256` now `#[inline]`-delegates to `kdf` with a
  single combined doc explaining the historical Keccak-256 cutover.
- `domain/src/lib.rs:111-141` — Extract `truncate_to_nonce(digest)` and use it
  in both `derive_entropy_nonce` and `nonce_for`. Eliminates two identical
  6-line `[u8;12]` build snippets.
- `domain/src/lib.rs:148-188` — Introduce private `aes256_gcm(key: &[u8;32])`
  helper. The previous four call-sites used
  `Aes256Gcm::new_from_slice(key).unwrap()`; the helper centralises the
  infallibility justification and replaces `.unwrap()` with an `.expect(...)`
  carrying that justification. Add `AES_GCM_TAG_LEN = 16` named constant and
  use it instead of the bare `16` magic number.
- `domain/src/lib.rs:194-247` — Tighten `encrypt_entropy_blob` /
  `decrypt_entropy_blob`: replace `[..12].try_into().unwrap()` with an explicit
  array build (no `unwrap` left), thread `CT_END` as a named constant,
  re-comment the trust-the-nonce reasoning more precisely.
- `domain/src/lib.rs:255-296` — Factor out `split_seed_48`,
  `with_bip39_seed`, and `signing_key_from_parts_with_seed`. These
  collapse the boilerplate shared by `derive_signing_key`,
  `derive_signing_key_from_entropy{,_fast}`,
  `derive_bootstrap_key_from_entropy{,_fast}`,
  `derive_main_key_from_entropy`, and `slot_master_entropy_from_entropy`
  — every "mnemonic → bip39_seed → use → wipe" path now goes through the
  same closure-based wipe helper.
- `domain/src/lib.rs:298-481` — Rewrite all `*_from_entropy` derivations to
  use `with_bip39_seed`. Each now reads as the 3-line domain logic instead of
  the 9-line wipe-aware scaffolding. The two `_fast` variants share
  `signing_key_from_parts_with_seed`. `derive_bootstrap_vk_from_entropy` and
  `derive_main_vk_from_entropy` drop their gratuitous `drop(sk)` and just
  return `.1` from the keypair tuple.
- `domain/src/lib.rs:622-645` — Simplify the SHA-256 splits inside
  `derive_c10_master_from_bip39_seed` using `Sha256::new().chain_update(...)`.
  The redundant `master_ga → master` re-copy is gone; we bind a `master_lo`
  alias for the `[..32]` slice that is hashed twice.
- `domain/src/lib.rs:668-697` — Extract `c10_keygen_from_n_masked_seeds`
  helper. Used by `derive_c10_master_keypair_from_entropy_with_progress` and
  by `derive_c10_slot_keypair_with_progress`; eliminates the two parallel
  "split N-masked seed → keygen → repack pk_root" blocks.
- `domain/src/lib.rs:735-779` — Extract `slot_field(master, tag, chain_id,
  slot)`. `slot_entropy` and `slot_r` are now one-liner calls; the SHA-256
  builder fluent-chain replaces the imperative `let mut h = ...; h.update;
  ...` shape used twice. `derive_c10_slot_seeds` is also rewritten with
  `chain_update`.
- `domain/src/lib.rs:830-883` — `deserialize_pin_state`: reject
  `blob_len > PIN_STATE_MAX_LEN` and `num_slots > MAX_ATTEMPTS`. Previously a
  blob longer than 481 B would panic on the `encrypted_secrets[i]` index
  past `MAX_ATTEMPTS`; now it cleanly returns `Err(())`. Switched the
  modulo check to `is_multiple_of` (stable, clearer intent).
- `domain/src/lib.rs:81-83` — Add `const _: () = assert!(ENTROPY_BLOB_LEN ==
  60, ...)` to lock the on-device entropy-blob layout at compile time.
- Across the public API — added `#[must_use]` to every key-deriving,
  KDF-evaluating, and entropy-encrypting function (>20 sites). Forgetting the
  result of any of these is always a bug; `#[must_use]` makes that a
  compile-time hint.
- `domain/src/lib.rs:1037-1167` — New test modules `aes_gcm_tests`,
  `pin_state_tests`, `kdf_tests` (15 tests). Cover the AES-GCM round-trip,
  rejection of truncated / wrong-key / wrong-nonce ciphertexts, the
  entropy-blob round-trip, wrong-master rejection, wrong-length rejection,
  PinState round-trip + the three rejection paths the new bounds check
  protects, plus the `kdf`/`kdf_sha256` alias equivalence and KDF
  domain/index separation. Total `cargo test -p pqsigner-domain`: 24 passed
  (was 9).

## Recommendations not applied

- **Split the file into submodules.** The crate would read more naturally as
  `lib.rs` + `kdf.rs` + `aes_gcm.rs` + `c10.rs` + `slot.rs` + `pin_state.rs`,
  each ≈100 lines. Skipped because the secure crate consumes the public API
  via wildcard re-export (`pub use pqsigner_domain::*;`), so the move would be
  invisible to callers — but the file-shuffle churn would exceed the
  ~300-line budget and noise the diff for no behavioural benefit. Worth doing
  on the next bigger touch.
- **`Result<usize, ()>` could be a typed error enum.** `aes_decrypt_inplace`,
  `decrypt_entropy_blob`, and `deserialize_pin_state` all return `()` on
  failure, conflating "bad length" with "auth-tag mismatch" and
  "blob-too-large". A `DomainError { LengthMismatch, AuthFailed, OverLong }`
  would be friendlier to callers and tooling, but every existing call-site in
  the secure crate currently throws away the error variant, so the upgrade
  belongs in a follow-up that also touches those sites.
- **Pre-cutover residue.** `RMEM_VERIFYING_KEY` is documented as "legacy" and
  `derive_signing_key_from_entropy_fast` / `derive_bootstrap_key_from_entropy_fast`
  / `main_signer_seed_from_bip39` / `derive_main_*` have no in-tree callers
  outside this crate. They are part of the public API (wildcard re-exported),
  so removing them is a deliberate API contraction that should come with a
  PR-level decision; left untouched.
- **Custom `hex()`/`decode_hex_into()` helper in tests.** `hex` is already in
  `[dev-dependencies]`; the test module could just call `hex::encode` /
  `hex::decode_to_slice`. Mechanical, not blocking.
- **`master.zeroize()` on a `GenericArray` directly.** Today we copy the
  HMAC-SHA512 output into a local `[u8; 64]` so we can zeroize. The `zeroize`
  crate's `GenericArray` impl would let us drop the copy. Skipped because
  that introduces an extra trait import for a single call site.

## Verification

- `cargo check -p pqsigner-domain` — PASS (host).
- `cargo check -p pqsigner-domain --target thumbv8m.main-none-eabi` — PASS
  (firmware target).
- `cargo test -p pqsigner-domain` — PASS (24/24).
- `cargo check --target thumbv8m.main-none-eabi -p sphincs-tz-secure
  --no-default-features --features mock-se,debug-log,ui-semihosting` — PASS
  (confirms the wildcard re-export in `secure/src/crypto.rs` still resolves).
- `cargo fmt -p pqsigner-domain --check` — **SKIPPED**: the runtime sandbox
  rejected every `cargo fmt` / `cargo clippy` invocation as requiring
  approval, and the user-facing AskUserQuestion permission prompt failed.
  The file was kept in the same style as before — only re-indented blocks
  that already matched `rustfmt` defaults (4-space, 100-col) were touched —
  but a host run of `cargo fmt -p pqsigner-domain --check` and
  `cargo clippy -p pqsigner-domain --all-targets -- -D warnings` is
  recommended before merge.
- `cargo clippy -p pqsigner-domain -- -D warnings` — **SKIPPED**, same reason.

## What this crate already does well

- One focused concern per crate; pure logic, no hardware, no allocator,
  no `unsafe`.
- Every `zeroize` site is paired with the value going out of scope.
- KDF tags are constants in source and the doc-comments on
  `derive_c10_master_from_bip39_seed` explicitly flag them as recovery-contract
  load-bearing, matching the CLAUDE.md "no casual KDF tag changes" rule.
- The Python-vs-Rust reference vectors in `c10_derivation_tests` are a strong
  guard against silent recovery-contract drift.
- Public re-export shape is stable so `secure/src/crypto.rs` can stay a thin
  passthrough.

## Cross-crate observations

- `secure/src/crypto.rs` uses `pub use pqsigner_domain::*;` (wildcard
  re-export). This is convenient but means any new pub item in `domain` is
  silently re-exported. A future cleanup could enumerate the re-exports
  explicitly so the secure crate's surface is auditable from one place.
- Several call-sites in the secure crate use `r_mem_write(...).unwrap()`
  after `r_mem_erase(...).ok()`; that pattern (best-effort erase, must-succeed
  write) is repeated and would benefit from a single helper in
  `secure_element.rs`.
- The dev-only `tools/sca/kdf_target` crate inlines local stubs of
  `derive_wrap_key` / `derive_entropy_nonce` instead of importing from
  `pqsigner_domain` (presumably for build-isolation). Worth a comment in
  that crate's `main.rs` confirming the stubs are intentional drift-tolerant
  copies, not a forgotten dedup.
