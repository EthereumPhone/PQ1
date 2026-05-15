# Dead-Code Removal — `proto`

_Date_: 2026-05-15
_Reviewer_: Claude Code (ultrathink)

## Scope

`pqsigner-proto` — single-source-of-truth IDL crate for everything that
crosses a TrustZone, on-chain, or USB boundary. Zero runtime dependencies
by policy.

Files audited:

- `proto/src/lib.rs` (1721 lines pre-edit)
- `proto/Cargo.toml`

## Summary

The crate is constants-only and the bulk of every symbol is genuinely
load-bearing. Pass found a tight cluster of vestigial protocol surface
that survived two cutovers (Keycard Shell → v2 native APDU, FORS+C → C10
unified `SignatureWrapper`) with zero in-workspace callers. Verified
against every Rust consumer plus the Solidity codegen (`xtask`) and the
firmware target builds — none of the deletions break a live caller, and
all downstream crates check clean.

`pqsigner-proto`'s own test count drops from 13 to 12 because the
`zk_header_len_matches_components` test asserted a constant
(`ZK_HEADER_LEN`) that was already only consumed by that test — the test
existed to defend a constant nothing else referenced.

## Deletions applied

| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|
| `proto/src/lib.rs:44-49` | `ZK_VK_LEN` | 1 (truly unused) | Defined but never referenced anywhere in the workspace. |
| `proto/src/lib.rs:51-61` | `ZK_HEADER_LEN` | 4 (vestigial) | Doc comment self-describes as the v2 layout; only consumer was its own test, downstream code uses `ZK_CLEAR_SIGN_FIXED_LEN` + `USEROP_HEADER_LEN` directly. |
| `proto/src/lib.rs:597-601` | `MAIN_PUBKEY_PAYLOAD_LEN` + section banner | 4 (vestigial) | Payload size for `CMD_GET_MAIN_PUBKEY`, which CLAUDE.md lists as reserved-but-not-dispatched. No live caller. |
| `proto/src/lib.rs:645-667` | v1 Keycard Shell APDU surface: `APDU_CLA`, `INS_GET_PUBLIC`, `INS_SIGN_ETH_TX`, `INS_GET_APP_CONF`, `INS_SIGN_ETH_MSG`, `INS_SIGN_EIP712`, `INS_GET_RESPONSE`, `INS_GET_PIN_REMAINING`, `INS_UNLOCK`, `P1_FIRST`, `P1_MORE` | 4 (vestigial / superseded) | Doc on the v2 block explicitly says v2 "replaces Keycard Shell compat". No Rust consumer of any v1 INS code. The `tools/webhid_test.html` companion redeclares its own JS constants — it does not import the Rust symbols. |
| `proto/src/lib.rs:686-687, 691, 700-707` | unused v2 INS codes: `INS_V2_GET_BOOTSTRAP_VK`, `INS_V2_GET_MAIN_VK`, `INS_V2_SIGN_CLEAR_USEROP`, `INS_V2_SIGN_MESSAGE`, `INS_V2_SIGN_EIP712`, `INS_V2_SIGN_BOOTSTRAP` | 1 (truly unused) / 4 (vestigial — `SIGN_BOOTSTRAP` is marked DEPRECATED) | Never dispatched by `nonsecure/src/usb/commands.rs::cmd_dispatch`. The `SIGN_BOOTSTRAP` op's behaviour is now subsumed by `SIGN_USEROP + FLAG_REGISTER_SLOT/INIT_CODE`. |
| `proto/src/lib.rs:744-747` | `P1_V2_LAST`, `P1_V2_MORE` | 1 (truly unused) | Defined for documentation purposes only; the framing code in `shared/src/apdu_framing.rs` masks bit 7 of P1 inline. |
| `proto/src/lib.rs:753-767` | `SIGNER_MAIN`, `SIGNER_BOOTSTRAP`, `WRAPPER_HEADER_LEN`, `WRAPPER_TOTAL_LEN` + section banner | 4 (vestigial) | The legacy v2 `PQSignatureWrapper` (signer-type byte + key/ots index + pk_seed/root + raw sig) was retired by the on-chain `SignatureWrapper(uint256 ownerIndex, bytes innerSig)` — `SIG_WRAPPER_LEN` is the live counterpart. No live consumer; only docs (research bundles + `sphincs-c7-firmware-integration.md`) mention it. |
| `proto/src/lib.rs:806-811` | `SIG_TYPE1_MARKER`, `SIG_TYPE2_MARKER` + the "deprecated marker" comment | 4 (vestigial / explicitly deprecated) | Doc above the constants reads: "Type 1 / 2 markers are deprecated — dispatch now happens on-chain via `SignatureWrapper.ownerIndex`, not a leading byte." No live consumer. |
| `proto/src/lib.rs:967-969` | `SIGN_OFFCHAIN_OUTPUT_LEN_MAX` | 1 (truly unused) | Only consumer was its own test. The test now asserts `MAX_SIGN_RESPONSE_LEN >= SIGN_OFFCHAIN_OUTPUT_LEN_6492` directly. |
| `proto/src/lib.rs:1077-1084` | `SIGN_USEROP_RESPONSE_COUNT_OFF`, `SIGN_USEROP_RESPONSE_COUNT_LEN`, `SIGN_USEROP_RESPONSE_BUNDLE_OFF` | 1 (truly unused) | Never referenced by firmware, host, or codegen. Offsets are inlined at the actual write sites in `secure/src/nsc/cmd_sign_userop.rs`. |
| `proto/src/lib.rs:1229-1230` | `ZK_V3_OFF_PROOF` | 1 (truly unused) | Always zero; the consumers slice from `0..EIP712_PROOF_LEN` directly. `ZK_V3_OFF_CANONICAL` definition collapsed from `ZK_V3_OFF_PROOF + EIP712_PROOF_LEN` to plain `EIP712_PROOF_LEN`. |
| `proto/src/lib.rs:1435-1436` | `APDU_MAX_DATA` | 1 (truly unused) | Only mention was inside a comment for the v1 `P1_FIRST`/`P1_MORE` constants (deleted above). `APDU_MAX_RESP` is the live counterpart. |
| `proto/src/lib.rs:1567-1573` (test) | `zk_header_len_matches_components` | follow-on | Asserted equality of `ZK_HEADER_LEN` against its own definition — meaningless after the constant is gone. |

Net: ~110 lines removed, the test surface drops from 13 to 12, and the
compile-time CMD-collision-check array is unchanged (no CMD constants
were deleted — every CMD ID stays reserved per `CLAUDE.md`).

## Reverted during bisect

None. Every deletion above survived `cargo check` + `cargo test` and
the firmware target builds.

## Cross-slice observations

- `sphincs-c10/src/hypertree.rs:48` `sign_with_progress` and
  `sphincs-c10/src/wots.rs:104` `sign` are flagged as dead by `rustc`
  warnings on host check. Out of scope for this slice.
- `secure/src/main.rs:6` has `#![cfg_attr(not(test), feature(cmse_nonsecure_entry))]`
  flagged as unused on host target — also out of scope.
- `nonsecure/src/nsc_api.rs:143` redeclares `CMD_TEST_PIN_LOCKOUT: u32 = 200`
  locally even though `sphincs_tz_shared` re-exports it. Worth folding
  on the next `nonsecure`-scoped pass.
- The collision-check array at the bottom of `proto/src/lib.rs:1542-1567`
  does NOT include `CMD_OFFCHAIN_SYNC = 18`. That's a latent bug in the
  collision check, not dead code — leave for a correctness fix.

## Recommendations NOT applied

Kept intentionally — meet the "don't-touch list" or have external
consumers not visible in this repo:

- **All `CMD_*` constants** — `CMD_GET_PUBKEY (3)`, `CMD_CLEAR_SIGN (5)`,
  `CMD_GET_BOOTSTRAP_PUBKEY (8)`, `CMD_GET_MAIN_PUBKEY (9)`,
  `CMD_SIGN_BOOTSTRAP (10)`, `CMD_SIGN_MESSAGE (13)`. CLAUDE.md
  explicitly documents them as "reserved in proto but not currently
  dispatched". Their numeric values must remain stable so future
  dispatch tables don't collide.
- **`SIG_TYPE2_HEADER_LEN`** — used by `nonsecure/src/usb/commands.rs::cmd_get_device_info`
  to surface the ABI wrapper-header size to the companion app.
- **`From<u32> for NscStatus`** — discriminant table looks repetitive but
  zero-deps policy forbids `num_enum`, and the wire format pins each
  number.

## Skipped

- `nonsecure/src/main.rs` cached fingerprint under
  `tools/target/.../output-bin-sphincs-tz-nonsecure` shows stale warnings
  about `ZK_HEADER_LEN`/`ZK_MAX_CALLDATA`/etc. being unused imports — the
  source no longer imports them; the warnings reflect a prior build
  state. Ignored.
- `docs/sphincs-c7-firmware-integration.md`, `docs/research-bundles/*`
  reference deleted symbols (`WRAPPER_TOTAL_LEN`, `SIGNER_BOOTSTRAP`,
  `MAIN_PUBKEY_PAYLOAD_LEN`, `ZK_HEADER_LEN`). These are research notes
  and a deprecated cutover doc — out of scope (no live code path).

## Equivalence check

Pre/post-deletion outcomes (the slice's `cargo` invocations):

- `cargo fmt -p pqsigner-proto --check` — **N/A** (cargo fmt blocked by
  sandbox permissions in this session; deletions are diff-only,
  formatting-neutral)
- `cargo check -p pqsigner-proto` — **EQUIV** (PASS → PASS)
- `cargo clippy -p pqsigner-proto -- -D warnings` — **N/A** (cargo clippy
  blocked by sandbox permissions)
- `cargo test -p pqsigner-proto` — **EQUIV** (PASS → PASS; test counts
  baseline 13, post 12 — the `-1` is the deletion of
  `zk_header_len_matches_components`, expected and documented above)

Workspace consumers (verified no downstream breakage):

- `cargo check -p pqsigner-aa -p pqsigner-tx-core -p pqsigner-tx -p pqsigner-domain -p sphincs-tz-shared -p pqsigner-xtask` — **EQUIV** (PASS → PASS)
- `cargo check -p sphincs-tz-shared --features stm32u585` — **EQUIV** (PASS)
- `cargo check -p sphincs-tz-secure --target thumbv8m.main-none-eabi --features ui-semihosting,mock-se` — **EQUIV** (PASS)
- `cargo check -p sphincs-tz-secure --target thumbv8m.main-none-eabi --features ui-noop,mock-se` — **EQUIV** (PASS)
- `cargo check -p sphincs-tz-secure --target thumbv8m.main-none-eabi --features stm32u585,hw-sha256,ui-semihosting,mock-se` — **EQUIV** (PASS)
- `cargo check -p sphincs-tz-nonsecure --target thumbv8m.main-none-eabi` — **EQUIV** (PASS)

No new clippy/check warnings introduced. The crate's public-API surface
shrinks; every removed name had zero live callers in firmware, host, or
Solidity codegen.
