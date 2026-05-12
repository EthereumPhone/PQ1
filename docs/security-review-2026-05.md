# Security Review — 2026-05-12

Audit scope: firmware (`secure/`, `nonsecure/`, `proto/`, `domain/`, `aa/`,
`tx-core/`, `tx/`, `hal/`, `shared/`, `fw-manifest/`, `fsbl/`, `bip39/`,
`sphincs-c10/` API surface only). The on-chain Solidity verifier, the
ZK Groth16 verifier internals, the SE050/OPTIGA driver internals, and
the trusted-UI rendering pipeline are out of scope and warrant their
own passes.

## Fixed in this change

| ID  | Sev  | Files touched | Summary |
|-----|------|---------------|---------|
| C-1 | Crit | `secure/build.rs`, `secure/Cargo.toml`, `secure/src/fw_update/{mod,vendor_pubkey}.rs` | Embed vendor SPHINCS+C10 pubkey via `FSBL_VENDOR_PUBKEY` env var (same path FSBL uses), verify manifest signature at `verify_manifest` BEFORE the destructive ops in `cmd_fw_commit` (slot erase, OTP rollback-floor bump, boot-state write). The "fingerprint-must-match-active-slot" gate that protected nothing — attacker can replicate it trivially — is gone. |
| C-2 | Crit | `secure/src/nsc/cmd_fw_chunk.rs` | Added `HandlerGuard::enter()` at handler entry. Prevents the use-after-drop on `FwUpdateCtx` when SysTick's idle-wipe races with a chunk write. |
| H-2 | High | `cmd_sign_userop.rs`, `cmd_sign_userop_batch.rs`, `cmd_sign_offchain.rs` | Open-coded inline `if ok_sentinel != OK_SENTINEL` blocks replaced with `fi::check_true(\|\| v1 && v2)`. The sentinel now lives in a `*mut u32` (Trezor pattern) so LLVM can't fold the third check into a register-only compare. |
| H-3 | High | `cmd_sign_userop.rs`, `cmd_sign_userop_batch.rs` | Added a symmetric `fi::check_true` outer verify-before-release for the Type 1 (bootstrap) `factorySig` and `addOwnerBytes` signatures. Previously only the Type 2 sig had the outer FI guard. |
| H-4 | High | `secure/src/nsc/mod.rs` | `gated_unlock` now reads `result.is_ok()` twice, separated by `wait_random()`, and routes the verdict through `fi::check_true`. A glitch that turns `Err` into the `Ok` arm (and resets the MCU page-124 attempt counter) must now defeat the sentinel-gated check too. The SE silicon counter is still the primary rate-limit. |
| L-2 | Low  | `cmd_sign_userop.rs`, `cmd_sign_userop_batch.rs`, `cmd_sign_offchain.rs` | `SNAP_BUF` now wiped on the **happy path** exit as well as entry. Error paths still leave data resident until the next sign — see "Not fixed" below. |
| L-6 | Low  | `secure/src/hw/otp.rs` | OTP rollback-floor post-bump readback now double-evaluated through `fi::check_true`. |
| M-1 | Med  | `secure/src/nsc/mod.rs` | `HANDLER_DEPTH` migrated from `static mut u32` (read-modify-write race) to `AtomicU32` (`fetch_add(1, SeqCst)` / `compare_exchange_weak` saturating decrement). Closes the tiny window where SysTick could observe `depth == 0` between a handler's read and write of the increment. |

### Build verification

- `cargo check -p sphincs-tz-secure --target thumbv8m.main-none-eabi --features "stm32u585 ui-noop dual-se"` → clean
- `cargo check -p sphincs-tz-secure --target thumbv8m.main-none-eabi --features "ui-noop mock-se"` → clean
- `cargo test -p sphincs-tz-secure --tests` → 105/105 passing
- `cargo build -p sphincs-tz-secure --target thumbv8m.main-none-eabi --features "ui-noop mock-se" --release` → clean

### One-line behavior changes

1. **All builds for `--features stm32u585` without `FSBL_VENDOR_PUBKEY` set emit a cargo:warning** and produce a binary that REJECTS every manifest (the embedded pubkey is all-zero). Production CI must set the env var; dev recipes should run `make dev-pubkey-fixture` (a recipe that needs to be added; see "Production checklist" §F-1).
2. **`cmd_fw_chunk` now blocks SysTick idle-wipe** for the (short) duration of one chunk write. Stalls in flash-page-erase still leave the inactive slot in a half-written state, but the SRAM `FwUpdateCtx` is safe.

## Not fixed (cannot be done from firmware alone)

### C-3. Pre-production TZSC/SAU regression
`secure/src/sau.rs:173-181, 232`. `TZSC_SECCFGR{1,2,3} = 0` (everything NS) and SAU region 3 maps the entire peripheral window NS. Cannot be tightened until the GTZC2_TZSC base address is confirmed against RM0456 — the first guess (`0x5203_4400`) bus-faults on touch. This is a hardware/bring-up problem, not a software fix. CI must hard-fail any release build whose `sau::init()` leaves the SECCFGRx registers cleared.

### H-1. AES-GCM nonce derived from master_secret
`domain/src/lib.rs:121-126`. Today's construction is safe because distinct entropy → distinct master → distinct nonce. The fix (random 96-bit nonce stored in the blob) requires touching the entropy-blob wire format on both SEs, which would be a flag-day data migration for every provisioned device. Defer until the next planned format-bump. The brittleness is documented in the function docstring as a regression test target.

### H-5. `CMD_GET_INIT_CODE` produces deploy signatures without user confirm
`secure/src/nsc/cmd_get_init_code.rs`. Adding a confirm is straightforward but changes companion-app flows (every cold "what's my address on chain X" lookup would prompt). Needs a product decision on UX trade-off vs. the harvesting risk (a hostile companion enumerating slot-0 deploy signatures for every chain).

### H-6. `paymaster_and_data` is signed but never displayed
The user has no way to see what paymaster the UserOp is authorizing. Fixing this requires a new optional trailer carrying the decoded paymaster address + fee fields, a new trusted-UI page, and a companion-app schema bump. Tracked separately as a UX-and-protocol change.

### M-2. 64-bit `slot_key` truncation
`offchain_state.rs:23`, `hw/flash.rs:943`. Wide enough for documented usage (≤ 256 active slots/device); tightening to 128 bits is a format change to the per-slot flash journal. Defer until the next compaction cycle of page 123 lands a wire-format bump anyway.

### M-3. `last_userop_count_set` silently tolerates regressions
`hw/flash.rs:1377-1392`. The trade-off is documented (avoid bricking the slot vs. detect bugs). I added a `secure_log!` recommendation to the review but did not change the runtime semantics — it's a deliberate product choice.

### M-4. `cmd_get_wallet_address` keygen without `HandlerGuard`
Low risk (entropy lives on stack as `Zeroizing`, BSS master_secret is only re-read at the start). Added to the production checklist below for symmetry.

### M-5. Slot-rotation confirm needs more context
Pure UI improvement; needs a product decision on what to show.

### L-2 (partial). `SNAP_BUF` not wiped on error paths
Fixed on happy path only. A scope-guard pattern that fires on every `return` would close this completely; current code has too many early `return NscStatus::*` to refactor blindly. Tracked.

### L-3. `verify_pin_with_chip` is not double-checked
The SE driver's authenticated-channel response is itself the gate; the MCU-side Rust match is the only post-SE conditional. Hardening it further requires either calling `se.unlock(pin)` twice (burns 2× SE counter) or surfacing a glitch-tolerant discriminant from the SE driver. Out of scope for this pass.

### L-7. QEMU mailbox dispatcher has no length validation on `CMD`
Match is exhaustive on `u32`; safe by construction. No change.

## Production checklist

These items MUST be resolved before any device leaves the bench.

### A. Mandatory build-time gates
- [ ] **CI hard-fails** on `stm32u585` builds where `FSBL_VENDOR_PUBKEY` is unset. The cargo:warning is not enough — turn it into a hard error in the production Makefile recipe (mirror `make fsbl-release`).
- [ ] **CI runs `make verify-pins`** (already exists) and verifies the `compile_error!` fences in `secure/src/nsc/mod.rs:98-116` still gate the dev features.
- [ ] **Add a test** that a release build's `verify_manifest` rejects a manifest signed by a different key. Easy way: re-sign the dev fixture with a different seed, point `FSBL_VENDOR_PUBKEY` at the prod fixture, exercise BEGIN, assert `WrongVendor`.

### B. TZSC/SAU lockdown (C-3)
- [ ] Confirm GTZC2_TZSC base address against RM0456 §§54 and on real silicon (bus-fault canary).
- [ ] In `sau::stm32::configure_gtzc()`: set every SECCFGRx to a default-secure baseline, allowlist only the peripherals NS actually needs (USB OTG FS, GPIO subset, the UCPD1 register reserved for boot-time only).
- [ ] Tighten SAU region 3 to cover only the NS-allowed peripheral window, not all 256 MB.
- [ ] Add a post-init self-check that reads back every SECCFGRx and halts on mismatch.

### C. FI hardening rollout
- [ ] Audit every other gateway handler for symmetry with the H-3 fix (single-tx, batch, offchain sign all now have outer FI guards on every sig release; verify no path was missed).
- [ ] Replace remaining open-coded sentinel patterns in the codebase with `fi::check_true` (grep `OK_SENTINEL`/`FAIL_SENTINEL` for unattended sites).
- [ ] Move `tamp::on_tamp_irq` from log-only to `trigger_lockout_wipe()` per the docstring at `hw/tamp.rs:13`.

### D. FW-update finishing
- [ ] **Wire up the real confirm UI** in `fw_update::confirm_commit` (currently stubbed to return `false` in non-e2e builds, which is what saved C-1 from being live).
- [ ] Add the unit test that `verify_manifest` rejects:
  - Wrong-vendor signature (BadSignature)
  - Tampered images post-streaming (SecureMismatch/NonsecureMismatch)
  - Below-floor versions (BelowRollback)
- [ ] Reconsider whether OTP bump should still live inside `cmd_fw_commit` or move to a post-boot "I survived" handler. Today the signature check protects the OTP bump from forged manifests but the user's confirm still gates a *legitimate-but-malicious-version-bump* DoS (someone tricks the user into installing a vendor-signed v(MAX-1) release, then no v50 downgrade is possible). The full fix is to require an additional cool-off / multi-version bump constraint.

### E. UX gaps
- [ ] **H-5**: gate `CMD_GET_INIT_CODE` behind a single OLED confirm or per-session quota.
- [ ] **H-6**: add `paymaster_and_data` decode + display.
- [ ] **M-5**: show `slot N-1 used X/65536` on the rotation confirm.
- [ ] Show paymaster address + fee summary in the basic sign render.

### F. Dev infrastructure
- [ ] Add `make dev-pubkey-fixture` recipe that writes `fsbl/fixtures/dev_pubkey.bin`, set `FSBL_VENDOR_PUBKEY` to it for all dev Makefile recipes, document in `docs/dev-board-setup.md`.
- [ ] Add `make ship-checklist` recipe that asserts:
  - `FSBL_VENDOR_PUBKEY` is set AND not the dev fixture
  - `TZSC_SECCFGR*` are non-zero (read back from a hardware probe)
  - The runtime self-test confirms `vendor_pubkey::VENDOR_PK_FPR` matches the fwsign-published fingerprint
  - All compile-time fences in `secure/src/nsc/mod.rs:98-116` are honored

### G. Carry-overs from this review (low-priority but tracked)
- [ ] M-2: 128-bit `slot_key`
- [ ] M-3: `secure_log!` on `last_userop_count_set` regression
- [ ] M-4: `HandlerGuard` for `cmd_get_wallet_address`
- [ ] L-1: comment/code drift on the pkSeed/pkRoot layout
- [ ] L-2 (full): scope-guard `SNAP_BUF` wipe on every return path
- [ ] L-3: FI on the unlock-result match
- [ ] L-5: surface the FI-detected "reconstructed entropy doesn't match master" via a persistent flag readable from the wizard
- [ ] L-8: bootstrap_cache eviction hygiene

## How to verify the fixes

```bash
# Build matrix
cargo check -p sphincs-tz-secure --target thumbv8m.main-none-eabi --features "stm32u585 ui-noop dual-se"
cargo check -p sphincs-tz-secure --target thumbv8m.main-none-eabi --features "ui-noop mock-se"
cargo test  -p sphincs-tz-secure --tests
cargo build -p sphincs-tz-secure --target thumbv8m.main-none-eabi --features "ui-noop mock-se" --release

# Run a sign smoke
make e2e

# (Once the vendor-pubkey fixture is wired) FW-update e2e
FSBL_VENDOR_PUBKEY=fsbl/fixtures/dev_pubkey.bin make fw-update-e2e
```

The signature-verify path is exercised in unit tests at `fw-manifest/src/lib.rs`; the integration on the secure firmware side currently has no direct test (the `confirm_commit` stub returns `false` so the COMMIT path never fires in production). Adding one is on the production checklist (D).
