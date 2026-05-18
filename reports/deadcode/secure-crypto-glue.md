# Dead-Code Removal — `secure-crypto-glue`

_Date_: 2026-05-16
_Reviewer_: Claude Code (ultrathink)

## Scope
Secure-side crypto wrappers (re-export shims + dual-SE entropy split + offchain-state).

Files audited:
- `secure/src/crypto.rs` (318 lines)
- `secure/src/dual_se.rs` (810 lines)
- `secure/src/offchain_state.rs` (210 lines)
- `secure/src/aa/mod.rs` (41 lines)
- `secure/src/erc20/mod.rs` (27 lines)
- `secure/src/names/mod.rs` (20 lines)
- `secure/src/selectors/mod.rs` (34 lines)
- `secure/src/db_roots.rs` (78 lines)

## Summary
Slice is essentially clean. A single trivially-dead public wrapper was
removed: `crypto::c10_sign_verified`, the no-progress variant that
delegates to `c10_sign_verified_with_progress(.., |_| {})`. A
whole-workspace grep confirmed zero callers under any feature
combination — every caller (cmd_sign_userop, cmd_sign_userop_batch,
cmd_sign_offchain, factory_calldata, the SCA target) uses the
`_with_progress` form directly. The doc comments on the module and on
the surviving function were tightened so the deleted symbol is no
longer referenced. Everything else flagged by host-build `dead_code`
warnings in this slice is bucket-2 dev/test infrastructure or
feature-gated arm-only code (see Skipped), and was left untouched.

## Deletions applied
| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|
| `secure/src/crypto.rs:33–38` | `pub fn c10_sign_verified` | 1 (truly unused) | No-progress wrapper around `c10_sign_verified_with_progress`. Zero callers anywhere in the workspace; not `#[no_mangle]`, not `#[used]`, not part of a linker/ABI surface. Every actual signing site already passes a `progress` callback. |
| `secure/src/crypto.rs:10–11, 40` | doc references to the deleted symbol | 5 (stale comment) | Module docstring bullet and the surviving function's `/// Like [`c10_sign_verified`] …` rustdoc link would have dangled. Replaced with a self-contained sentence. |

## Reverted during bisect
None — the equivalence check passed on the first try.

## Cross-slice observations
Multiple `unused_*` warnings in the host check come from outside this
slice and reflect arm/feature-gated callers (not visible to a default
`cargo check`):
- `secure/src/scp03_logic.rs` `aes128_cbc_{encrypt,decrypt}` / `kdf`
- `secure/src/iso7816.rs` `tlv_put_u32`
- `secure/src/fih.rs` `SEC_TRUE`/`SEC_FALSE`/`FihBool` (`FihBool` is
  used by `dual_se::DualSecureElement` under `dual-se`; the rest may
  be vestigial)
- `secure/src/sign_rate.rs` `MIN_SIGN_INTERVAL_MS`
- `secure/src/secure_element.rs` `SeError::SlotExpired`,
  `WalletStore` trait method shells (all called by NSC under SE
  backends), `MockSecureElement::macd_all_initialized`
- `secure/src/tx/typed_call/abi.rs` `Walked::type_id`, `read_bool`
- `secure/src/tx/mod.rs` `pub use pqsigner_tx_core::hash`
- `secure/src/tx/eip712/safe/mod.rs` `VerifiedSafeV1` re-export

Flagged for the appropriate per-slice passes (out of scope here).

In this slice's own files, the QEMU-backend `offchain_state::backend::
reset_for_test()` (gated `feature = "e2e-test"`) has no callers but
is documented as "tests that want to simulate a recovery just call
…". Left as a bucket-2/4 borderline — deleting it would change no
observable behaviour, but it is `e2e-test`-gated dev tooling, so the
safe call is to leave the helper available for a future recovery
test rather than have it re-introduced later. Recommendation only.

## Skipped
- `dual_se::run_admin_wipe_roundtrip` / `run_multi_unlock_roundtrip`
  (gated `dual-se-admin-wipe-e2e` / `dual-se-multi-unlock-e2e`) —
  bucket 2 dev e2e harnesses.
- `aa::{eip1271,eip6492}` re-exports — used by NSC under arm + SE
  feature gates (`cmd_sign_offchain.rs`); flagged unused on host
  build only.
- `erc20::{calldata,dispatch,merkle, dispatch::{dispatch_tx,TxKind},
  bundle::MAX_ERC20_BUNDLE_LEN}` re-exports — used by NSC, tx/display,
  and zk modules under arm + feature gates.
- `names::{resolver, MAX_NAME_BUNDLE_LEN, NameResolver, MAX_NAME_BUNDLES}`
  re-exports — used by NSC + tx/display under arm + feature gates.
- `selectors::{parse_self_attest_bundle, SelectorMeta,
  SelectorProvenance, MAX_SELECTOR_BUNDLE_LEN, MAX_SELF_ATTEST_BUNDLE_LEN}`
  top-level and nested `bundle::` re-exports — used by NSC +
  tx/display + fuzz_props under arm + feature gates. The nested
  `bundle::` module is documented as a "backwards-compat alias";
  no consumer of the nested path other than `verify_selector_bundle`
  exists today, but flipping it would be a refactor, not a deletion
  — out of scope.
- `db_roots::VK_DB_ROOT`, `db_roots::ERC20_POSEIDON_ROOT` — used by
  `secure/src/zk/{groth16,vk_bundle,mod}.rs`; the zk module is not
  reached by the default-feature host build that surfaces the
  "never used" lint.
- `crypto::CFI_STEP_*` constants — used inside
  `c10_sign_verified_with_progress`; the function itself is reached
  only under arm + SE features (via NSC commands).

## Equivalence check

Per CLAUDE.md the secure crate's normal build is firmware-only
(`thumbv8m.main-none-eabi`); a default `cargo check -p sphincs-tz-secure`
runs the host-side parser proptests via `#[cfg(test)]` and skips
every arm-gated module. That is the only `cargo` invocation in this
sandbox able to compile + run any code from this slice, so it is the
gate I used.

- `cargo fmt -p sphincs-tz-secure --check` — **N/A** (sandbox blocked
  the invocation; edits are limited to a removed function + two
  comment-only tweaks, no formatting drift introduced).
- `cargo check -p sphincs-tz-secure --tests` — **EQUIV**. Baseline
  EXIT=0 with 39 warnings; post-deletion EXIT=0 with 38 warnings.
  The single warning removed is exactly
  `function 'c10_sign_verified' is never used`, which is the
  function this pass deleted. No new warnings.
- `cargo test -p sphincs-tz-secure --tests` — **EQUIV**. Baseline
  121 passed / 0 failed; post-deletion 121 passed / 0 failed.
  (Captured by stashing the edit, running `cargo test`, and
  restoring.)
- `cargo clippy -p sphincs-tz-secure -- -D warnings` — **N/A**
  (cannot pass `-D warnings` while 38 pre-existing out-of-scope
  warnings remain; not informative for a scoped pass).
- Firmware-target cargo build under arm features — **N/A** in this
  sandbox (the long-form per-feature build commands in
  `.claude/settings.local.json` are not invocable here). The single
  deleted item is a non-mangled pure-Rust function with zero callers
  in any tree, including the arm-gated NSC modules — so the
  firmware codegen cannot reference it, and removing it cannot
  change the firmware binary. Binary-hash equivalence is asserted by
  construction.
