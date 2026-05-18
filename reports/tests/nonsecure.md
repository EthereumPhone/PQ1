# Test Suite Added — `nonsecure`

_Date_: 2026-05-17
_Author_: Claude Code (ultrathink)

## Scope
NS entrypoint, USB HID transport, gateway caller, e2e driver.

Source files covered:
- `nonsecure/src/main.rs:323` — `#[cortex_m_rt::entry] fn main()` (USB / QEMU
  interactive demo), `build_value_transfer_payload`, `ns_debug_log`
- `nonsecure/src/nsc_api.rs:457` — transport-agnostic gateway API
  (QEMU shared-memory mailbox under `cfg(not(stm32u585))`, CMSE veneer
  `extern "C"` shim under `cfg(stm32u585)`)
- `nonsecure/src/usb/mod.rs:138` — USB stack assembly, OTG-FS clock /
  pin wiring
- `nonsecure/src/usb/hid.rs:140` — `PqSignerHid` custom HID class
  (Usage Page 0xFFA0, 64-byte interrupt EP pair)
- `nonsecure/src/usb/transport.rs:142` — APDU-over-HID `Transport`
  state machine (delegates RX framing to
  `sphincs_tz_shared::apdu_framing::HidFrameAssembler`)
- `nonsecure/src/usb/commands.rs:1135` — APDU v2 `CommandRouter` plus
  the `maybe_inject_*` companion-side metadata injectors (ERC-20 / VK /
  VK-v3 / names)
- `nonsecure/src/erc20_db.rs:145` — `(chain_id, contract) → Merkle
  bundle` lookup over the `include_bytes!("erc20_db.bin")` blob
- `nonsecure/src/names_db.rs:163` — address-name DB lookup
- `nonsecure/src/vk_db.rs:116` — VK DB lookup
- `nonsecure/src/selectors_db.rs:139` — selectors DB lookup (e2e-only)
- `nonsecure/src/e2e_test.rs:1267` — scripted runner: 14+ scenarios
  spanning value transfer, ERC-20 transfer, Safe approveHash flow, ZK
  clear-sign, EIP-1271, batch sign, rotate-slot, off-chain counter
  paths
- `nonsecure/src/bench_key_speed.rs:239` — DWT-timed sign bench
- `nonsecure/src/fwup_hw_test.rs:302` — FW_BEGIN/CHUNK/STATUS/ABORT
  logic test
- `nonsecure/src/gtzc_test.rs:169` — GTZC1 TZSC enforcement validator
- `nonsecure/src/tzic_wipe_test.rs:50` — TZIC illegal-access wipe demo
- `nonsecure/build.rs:36` — dbgen blob magic check
- `nonsecure/memory.x`, `memory-stm32u585.x` — linker scripts

## Test files added / extended

**None.** See "Verification" below.

## Positive coverage

None added in this pass — see "Coverage gaps deliberately left".

## Negative coverage (the important one)

None added in this pass — see "Coverage gaps deliberately left".

## Production-code bugs surfaced by negative tests

None — no tests were able to run.

## Coverage gaps deliberately left

### Why this pass produced no test code

`nonsecure` is a **bin-only firmware crate** with `#![no_std]
#![no_main]`, a `#[cortex_m_rt::entry] fn main()`, and hard
dependencies on Cortex-M-only crates (`cortex-m-rt`,
`cortex-m-semihosting`, `panic-semihosting`, `panic-halt`,
`synopsys-usb-otg`). Cargo unconditionally links the bin target when
building any integration test in the package, so the bin's link
failure on the host blocks every `cargo test -p sphincs-tz-nonsecure
…` invocation.

Empirically (`cargo test -p sphincs-tz-nonsecure --target
x86_64-unknown-linux-gnu --test <any> --no-run`):

```
rust-lld: error: undefined symbol: __nop
  >>> referenced by nsc_api.rs:0 (nonsecure/src/nsc_api.rs:0)
  >>>               sphincs_tz_nonsecure-…rcgu.o:(__cortex_m_rt_main)

rust-lld: error: undefined symbol: __primask_r
rust-lld: error: undefined symbol: __cpsid
rust-lld: error: undefined symbol: __cpsie
  >>> referenced by call_asm.rs:19 (cortex-m-0.7.7/src/call_asm.rs:19)
  >>>               cortex_m_semihosting-…rcgu.o:(hstdout_fmt) in
  >>>               libcortex_m_semihosting-….rlib
```

The ARMv8-M `nop` / `primask_r` / `cpsid` / `cpsie` opcodes referenced
by `cortex-m-semihosting` and `cortex-m-rt`'s entry stub have no
host-architecture replacement. `--no-default-features` does not help
because none of the cortex-m deps are gated behind a feature.

Cross-compiling the test harness to `thumbv8m.main-none-eabi` would
require an embedded test framework (`defmt-test` / `cortex-m-test`)
running under QEMU or probe-rs — the task forbids `make e2e` /
`make e2e-hw` / on-target QEMU runs from this pass, and even setting
that aside, libtest is not available under `no_std` on Arm
(`E0463: requires sized lang item`).

Under the rules of this pass (`#[cfg(test)]` blocks, integration tests
under `tests/`, and `[dev-dependencies]` Cargo.toml entries are the
only permitted edits — no production-code modifications), **no
host-runnable test could be made to compile**.

This is the same structural property the prior `fsbl` slice
(reports/tests/fsbl.md) ran into and resolved the same way — the two
bin-only firmware crates need their pure-logic helpers lifted into a
host-testable workspace crate (or `main.rs` flipped to
`cfg_attr(not(test), …)` à la `secure/src/main.rs`) before the
suite below can be written.

### Avenues considered + ruled out

1. **`#[cfg(test)] mod tests` blocks inside source files
   (`usb/commands.rs::CommandRouter`, `erc20_db.rs`, `names_db.rs`,
   `vk_db.rs`, `usb/transport.rs`).** Ruled out: cargo still
   compiles the bin (whose top-level `use panic_semihosting as _;`
   and `#[cortex_m_rt::entry]` reach into ARM-only asm) as part of
   the package build for every `cargo test -p …` invocation, before
   any `#[cfg(test)]` module is considered.

2. **Integration tests under `nonsecure/tests/*.rs` that depend on
   nothing from the `nonsecure` crate (purely re-deriving wire
   contracts against `sphincs-tz-shared`).** Ruled out by the same
   mechanic — cargo links the bin even when only an `--test foo`
   target is selected. Confirmed by adding a 3-line smoke probe; same
   `__nop` / `__primask_r` / `__cpsid` / `__cpsie` undefined-symbol
   failures. Probe was reverted before this report was written.

3. **Switch top-level attributes to test-aware
   (`#![cfg_attr(not(test), no_std)]` /
   `#![cfg_attr(not(test), no_main)]`, gate `cortex_m_rt::entry`
   with `cfg(not(test))`, gate `panic_semihosting` / `panic_halt`
   imports).** This is what `secure/src/main.rs` does. Ruled out
   here: modifying production attributes and gating production
   functions with `cfg` is the line this pass cannot cross. The
   pattern is the right long-term answer for nonsecure but belongs
   in a dedicated PR.

4. **Add an opt-in `host-tests` feature that disables the cortex-m
   imports and the `#[entry]` gate.** Same blocker as (3); the
   feature still has to be wired up through main.rs `cfg_attr` /
   `cfg(not(feature = …))` lines, which is production code.

5. **Add a `src/lib.rs` exposing pure-logic modules
   (`erc20_db`, `names_db`, `vk_db`, `selectors_db`) for tests,
   gated `cfg(test)`.** Ruled out: creating a new `src/lib.rs` is
   production-code modification and Cargo's `[lib]` target affects
   the production build surface even with an empty body.

6. **Lift `erc20_db` / `names_db` / `vk_db` / `selectors_db` into a
   new `pqsigner-ns-dblookup` workspace crate (or fold them into
   `sphincs-tz-shared`'s `db_format` module).** This is the
   "Pull pure-logic helpers out via the existing workspace crate
   split" path that CLAUDE.md and the task prompt explicitly call
   out as the right long-term move — but it requires touching
   production files (the four db modules to delete the moved code,
   plus `nonsecure/src/usb/commands.rs` to re-route the
   `maybe_inject_*` helpers through the new crate, plus a new
   workspace member in the root `Cargo.toml`). Out of scope for a
   test-only pass.

7. **Write the wire-format / injector tests inside `sphincs-tz-shared`
   instead.** Ruled out as a scope violation: the task slug is
   `nonsecure`. `shared` already has a 93-test positive+negative pass
   (reports/tests/shared.md) covering `apdu_framing` and `db_format`
   end-to-end. The negative tests below for the *NS-specific* layer
   (the four `maybe_inject_*` paths, `total_sign_response_len`'s
   bounds, the `ensure_trailer_skeleton` six-slot invariant, the
   `setup_chunked_response` chunking math, `read_be_u32`'s overflow
   semantics) belong in this crate's package because they exercise
   private NS-side state machines, not the shared parsers.

8. **Use an embedded test framework (`defmt-test`, `cortex-m-test`)
   as a dev-dependency and run on QEMU / probe-rs.** Ruled out: even
   if wired up, running it needs QEMU mps2-an505 or a real B-U585
   board — both explicitly excluded from this pass. And the dev-dep
   still needs `main.rs` / `Cargo.toml` gymnastics to compose with
   the existing `cortex_m_rt::entry`, returning us to
   production-code modification.

9. **Compile-fail (`trybuild`) tests for the feature-gate exclusions
   (`debug-log` + `mode-production`, `e2e-test` + `usb`, etc.).**
   Ruled out: the `compile_error!` fences live in the **secure**
   crate (`secure/src/nsc/mod.rs` and friends), not in `nonsecure`.
   `nonsecure` has no production feature-combination guards — the
   secure crate is what gates the firmware. Adding `compile_error!`
   here is a production-code edit. The trybuild harness would
   *still* be defeated by the `cortex-m-semihosting` link failure
   on host before any compile-fail case is evaluated.

### Tests that would be written if a host path existed

If a follow-up PR lifts the pure-logic helpers out (option 6) or
flips `main.rs` to `cfg_attr(not(test), …)` (option 3), the suite
should at minimum include the following — organised by the surface
under attack.

#### Positive coverage seeds

**APDU-router public surface (`usb::commands::CommandRouter`):**
- Every non-chained command (`GET_DEVICE_INFO`, `GET_STATUS`,
  `UNLOCK`, `LOCK`, `GET_WALLET_ADDRESS`, `GET_INIT_CODE`,
  `OFFCHAIN_STATUS`, `OFFCHAIN_SYNC`, `GET_RESPONSE`, the 4 FW_*
  variants) — happy-path with a mocked `nsc_api` returning `Ok`.
- Each chained command (`SIGN_USEROP`, `SIGN_USEROP_BATCH`,
  `SIGN_OFFCHAIN`, `FW_BEGIN`) — single-APDU short payload and the
  multi-APDU `0x10 | INS` chain-bit path.
- `GET_DEVICE_INFO` capabilities field exactly equals
  `CAP_SIGN_USEROP = 0x01` — refuse silent additions.
- `GET_DEVICE_INFO` `ep_version` field byte-equals `0x00 0x06` — the
  EntryPoint v0.6 stake-in-the-ground from CLAUDE.md invariant #6.
- `GET_DEVICE_INFO` `sig_param_set` byte equals 2 (SPHINCS+C10) —
  invariant #5.
- `GET_DEVICE_INFO` Type-2 sig-size word equals `SIG_TYPE2_LEN`
  (4128 with the 64-byte owner header overhead reported separately).
- `GET_STATUS` response is exactly 5 bytes: `[provisioned, locked,
  remaining, SW_OK_hi, SW_OK_lo]`.
- `cmd_get_wallet_address` accepts both the zero-length body
  (account 0 legacy) AND the 4-byte body, returning identical
  `addr || SW_OK`.
- `cmd_get_init_code` accepts exactly 12 bytes, returning
  `PQ_INIT_CODE_LEN` (4280) bytes via `setup_chunked_response`.
- `total_sign_response_len` correctly parses
  `count(8) | ic_len(4) | … | t2_len(4)` for the three Type 1 /
  Type 2 framing shapes (init-code present, register-slot present,
  both, neither) AND returns exactly the sum.

**HID transport (`usb::transport::Transport`):**
- `try_receive` returns `Some(&[…])` once the assembler signals
  `ApduComplete`; `None` for `NeedMore` and `Dropped`.
- `poll_tx` first-frame layout: `chan(2) | TAG_APDU | seq=0 | len(2)
  | data[57]`; second-frame layout: `chan(2) | TAG_APDU | seq=N |
  data[59]`. Byte-exact.
- `queue_response` clamps `len` to `tx_buf.len() = 256` and
  reports `tx_active = true` until the last byte is shipped.
- `PingEcho` path echoes the inbound frame byte-for-byte.

**db lookups (`erc20_db`, `names_db`, `vk_db`):**
- Round-trip: every entry in the bundled DB is findable by its
  `(chain_id, key)` and the returned bundle's `leaf_index` /
  `proof_depth` match the DB header.
- Bundle wire layout against the documented schema in each module's
  doc comment — `chain_id(8 LE) || key(20) || …`.

**Companion-driven trailer injectors:**
- `maybe_inject_erc20_bundle`: bare `[header | data]` with
  `(chain_id, tx.to)` ∈ DB → trailer is appended exactly as
  `u16 BE len || bundle`. Cursor returned equals
  `payload_end + 2 + bundle_len`.
- `maybe_inject_vk_bundle`: bare trailer of exactly
  `ZK_CLEAR_SIGN_FIXED_LEN` bytes whose `(chain_id, tx.to)` hits the
  VK DB → bundle appended after the trailer payload and the trailer's
  u16 length header rewritten to `fixed + bundle_len`.
- `maybe_inject_vk_bundle_v3`: same, keyed on
  `COWSWAP_EIP712_SENTINEL` rather than `tx.to`.
- `maybe_inject_names_bundles`: deduplicates the candidate address
  list across `tx.to`, ERC-20 `transfer` recipient, `approve`
  spender, and `transferFrom` (from, to). Returns `received_len`
  unchanged when zero bundles emit.
- `ensure_trailer_skeleton` walks exactly 6 sections (erc20, v1_zk,
  v3_zk, safe_v1, selector, self_attest) and emits a `[0, 0]` u16
  prefix for each missing one — byte-exact final cursor.

**Gateway shim (`nsc_api`):**
- Each public function's signature: input pointer + length is passed
  through to `transport::*_call` unchanged. (Mockable behind a fake
  transport once the helpers are lifted.)

#### Negative coverage seeds (the high-value ones)

These map directly onto CLAUDE.md invariants and the NS-specific
adversarial surface.

**Wire-format / parser fuzz seeds (router):**
- APDU shorter than 4 bytes → `SW_WRONG_LENGTH`. (Already covered in
  `shared::apdu_framing`, but the *dispatcher* must return that SW
  rather than panicking.)
- `Lc > apdu.len() - 5` → `SW_WRONG_LENGTH`. The router must not deref
  past the slice.
- Unsupported CLA → `SW_CLA_NOT_SUPPORTED`. Sweep all 256 CLA values;
  exactly `APDU_CLA_V2 = 0xF0` accepts, every other byte rejects.
- Unsupported INS under correct CLA → `SW_INS_NOT_SUPPORTED`. Sweep
  all 256 INS values; only the documented table is accepted.
- Chain bit (`0x10 | INS`) on a non-chainable INS (e.g. UNLOCK,
  GET_STATUS) → `SW_WRONG_LENGTH` / `SW_CONDITIONS_NOT_SATISFIED`.
- Mid-chain INS mismatch (started a `SIGN_USEROP` chain, sent a
  `SIGN_OFFCHAIN` continuation) → `ProtocolError` mapped to
  `SW_CONDITIONS_NOT_SATISFIED`. The `ChainStepOutcome` enum's
  rejection paths must surface, not silently flush the buffer.
- Chain payload total > `CHAIN_BUF_LEN` → rejected with
  `SW_WRONG_LENGTH`; the accumulation cursor never writes past
  `CHAIN_BUF`. (Attack: companion sends 8 KB+ of bogus continuations
  trying to scribble into adjacent statics.)
- `GET_RESPONSE` with no pending state → `SW_CONDITIONS_NOT_SATISFIED`.
- `SIGN_USEROP` payload shorter than `SIGN_USEROP_HEADER_LEN` (330) →
  `SW_WRONG_LENGTH` (catches the off-by-one that would let an attacker
  trigger a short read of `CHAIN_BUF[..less-than-330]` into the
  secure-world parser).
- `SIGN_USEROP_BATCH` payload shorter than `SIGN_USEROP_BATCH_HEADER_LEN
  + SIGN_USEROP_BATCH_TX_PREFIX_LEN` → `SW_WRONG_LENGTH`.
- `SIGN_OFFCHAIN` payload longer than `SIGN_OFFCHAIN_INPUT_MAX_LEN`
  → `SW_WRONG_LENGTH`. The hard cap must fire before the gateway
  call. (NS-side guard against an oversize HID body crashing
  the secure-world chunker.)
- `OFFCHAIN_STATUS` body length ≠ `OFFCHAIN_STATUS_INPUT_LEN` →
  `SW_WRONG_LENGTH`.
- `OFFCHAIN_SYNC` body length ≠ `OFFCHAIN_SYNC_INPUT_LEN` →
  `SW_WRONG_LENGTH`.
- `GET_INIT_CODE` body length ≠ 12 → `SW_WRONG_LENGTH`.
- `GET_WALLET_ADDRESS` body length ∉ {0, 4} → `SW_WRONG_LENGTH`.
- `CMD_FW_BEGIN` final chained length ≠ `MANIFEST_SIZE` (8 KB) →
  `SW_WRONG_LENGTH`. A short manifest must never reach the secure
  parser.
- `CMD_FW_CHUNK` `data.len() ∉ [FW_CHUNK_HEADER_LEN,
  FW_CHUNK_HEADER_LEN + FW_MAX_CHUNK]` → `SW_WRONG_LENGTH`.

**Frozen-format stability (on-chain breaking changes):**
- `SIGN_USEROP_HEADER_LEN == 330` byte-exact assert. Any future change
  here breaks every signed bootstrap key in the field.
- `SIG_TYPE2_LEN == 4128` byte-exact. The wallet contract's
  `validateUserOp` ABI-decodes this length.
- `SIG_TYPE1_LEN == 4128` byte-exact.
- `PQ_INIT_CODE_LEN == 4280` byte-exact. Quoted in CLAUDE.md's
  "Wire formats (frozen)" section.
- `SIGN_OFFCHAIN_OUTPUT_LEN == 4016`,
  `SIGN_OFFCHAIN_OUTPUT_LEN_6492 == 8616` byte-exact. (EIP-6492 magic
  trailer math.)
- `OFFCHAIN_STATUS_INPUT_LEN == 13`,
  `OFFCHAIN_STATUS_OUTPUT_LEN == 24` byte-exact.
- `OFFCHAIN_SYNC_INPUT_LEN == 21` byte-exact.
- `FW_STATUS_RESPONSE_LEN`, `FW_CHUNK_HEADER_LEN`, `FW_MAX_CHUNK` byte-
  exact assertions — the FW-update streaming wire format must not
  silently drift.
- `APDU_CLA_V2 == 0xF0` — the single class byte the post-cutover
  router accepts. A drift here strands every shipped companion build.
- `INS_V2_*` constants byte-exact (`0x01`/`0x02`/`0x10`/`0x11`/
  `0x30`/`0x32`/`0x60`/`0x61`/`0x62`/`0x63`/`0x64`/`0xC0` + the FW
  cluster). Same rationale.
- `SW_*` constants — every status word the router can emit pinned to
  its current value so the companion's branch decoder doesn't break.

**State-machine attacks (`CommandRouter` / `ChainState`):**
- Send only the chain-bit-set first APDU of `SIGN_USEROP` and never
  the terminator → no gateway call ever fires, `CHAIN_BUF` is not
  consumed, next dispatch starts from a clean cursor (proves the
  router doesn't leak state between requests).
- Duplicate-init: send two chain-start APDUs back-to-back for the
  same INS → second wins (cursor resets to 0), no leftover bytes
  from the first attempt land in the secure payload.
- Send a fresh `SIGN_USEROP` (non-chained, single APDU) immediately
  after dropping a chained request mid-stream → secure payload is
  the new one only.
- `GET_RESPONSE` with the chunker pointer mid-stream → returns the
  next chunk and bumps `PENDING_POS`; final chunk flips `PENDING_PTR`
  to null and emits `SW_OK`.

**Algorithm-policy invariants (CLAUDE.md invariants #5, #6):**
- Compile-time assert that no public router INS dispatches to a
  non-C10 signer. (Static-string-search test on the rendered call
  graph — fails if `c10_sign` is ever replaced by `ecdsa_sign` /
  `ed25519_sign` / `fors_c_sign`.)
- `GET_DEVICE_INFO`'s `sig_param_set` byte stays 2 forever. Adding
  3 = "ECDSA fallback" must require a deliberate edit + a fresh
  CLAUDE.md amendment.
- Router has no path to a `rotate_master_keys` / `reset_bootstrap_uses`
  / `reset_slot_uses` / `increase_max*` INS. Sweep all 256 INS
  values — none of those names appear in dispatch.

**Buffer / pointer hardening:**
- `setup_chunked_response(total_data = MAX_SIGN_RESPONSE_LEN)` does
  not overflow `SIG_BUF` (which is `MAX_SIGN_RESPONSE_LEN + 2`).
- `setup_chunked_response(0)` returns `Response { len: 2 }` carrying
  only `SW_OK`. (Edge case — empty bundle path.)
- `total_sign_response_len`: corrupt `ic_len` to `u32::MAX` →
  returns `None` → router emits `SW_INTERNAL_ERROR`. Catches an
  attacker-controlled length-field that would otherwise walk
  `SIG_BUF`. (Attack mode: a buggy secure handler writes a bad
  length; NS must refuse to ship the bytes downstream.)
- `total_sign_response_len`: `ic_len_off + 4 > SIG_BUF.len()` →
  `None`.
- `read_be_u32(buf, off)` with `off + 4 > buf.len()` → `None`. The
  `checked_add` must not silently saturate.
- `queue_response(ptr, len = 1 GiB)` → clamps to `tx_buf.len() = 256`;
  no out-of-bounds copy.

**Companion injector adversarial paths:**
- `maybe_inject_erc20_bundle` with `received_len < SIGN_USEROP_HEADER_LEN`
  → returns input length unchanged (no panic).
- `maybe_inject_erc20_bundle` where `data_len_field` overflows
  `received_len` → returns input length unchanged (defence against
  an attacker-controlled length pointing past the buffer).
- `maybe_inject_erc20_bundle` where companion already attached a
  trailer (`received_len > payload_end`) → returns
  `received_len` unchanged. Catches the "augment-twice → double-
  trailer" failure mode.
- `maybe_inject_vk_bundle` with declared length ≠
  `ZK_CLEAR_SIGN_FIXED_LEN` → returns `received_len` unchanged. The
  v1 injector must refuse to splice into a partial / already-extended
  trailer.
- `maybe_inject_vk_bundle_v3` with declared length ≠
  `ZK_V3_FIXED_LEN` → unchanged.
- `inject_vk_bundle_at` with `new_declared_len > u16::MAX` →
  unchanged. (Attack: a VK bundle so large that the rewritten u16
  trailer length silently wraps.)
- `inject_vk_bundle_at` with `new_len > CHAIN_BUF_LEN` → unchanged.
- `maybe_inject_names_bundles` with `cand_n == 0` → unchanged, NO
  count byte emitted. Attack: a lone `[count = 0]` byte read by the
  secure parser as a self_attest u16 length (the exact regression
  the commit-33cd0ed note in `ensure_trailer_skeleton` describes).
- `ensure_trailer_skeleton` with a *malformed* declared section
  length that overruns `received_len` → returns `new_len` unchanged
  without writing past `CHAIN_BUF[received_len]`. The
  `if pos > new_len { return new_len; }` guard at the bottom of the
  loop must fire.
- `ensure_trailer_skeleton` already at full skeleton (six u16
  prefixes present) → no-op, returns `received_len` exactly.
- `ensure_trailer_skeleton` count of u16 prefixes is **exactly 6**.
  This is the regression the source comment quotes:
  > "Bumped from 5 → 6 when commit 33cd0ed added the self_attest slot
  > to the secure parser; without this the NS-injected names count
  > byte got read as the self_attest u16 length and tripped 'bad
  > self-attest' on every ETH transfer to a named address."
  Pin the 6 with a constant assertion so a refactor that drops it
  back to 5 (or extends to 7 without bumping the secure parser)
  fires a test failure.
- ERC-20 calldata candidate-extraction: send a `transferFrom` call
  with `data_len` exactly `4 + 32 + 32` (instead of `+ 32 + 32 + 32`)
  → the `>= 4 + 32 + 32 + 32` guard must skip the recipient
  extraction (no out-of-bounds read of `data[4 + 32 + 12..4 + 64]`).
- `transfer(address,uint256)` selector with first 12 bytes of the
  address slot non-zero → padded zero-check refuses (NS-side defence
  against malformed selector arguments). Currently the code reads
  `data[4 + 12..4 + 32]` without validating padding; a test should
  pin the current behaviour even if just to flag it.

**Constant-time / branch-on-secret:**
- The NS side is by design secret-free (CLAUDE.md invariant #4 — NS
  never sees PIN / entropy / signing key). A negative test should
  static-search every NS source file for the strings `PIN`, `pin`,
  `secret`, `master`, `entropy`, `priv_key`, `sk_` followed by `==`
  or `!=` to assert no equality compare on a name suggesting a
  secret quantity. This is "trust but verify" against future drift.

**Feature-gate combinations:**
- `e2e-test` + `fwup-hw-test` together → compile error (two
  competing `#[cortex_m_rt::entry] fn main()` definitions). Currently
  enforced by `cfg(not(feature = "fwup-hw-test"))` on the e2e_test
  mod gate — pin it with a trybuild compile-fail.
- `gtzc-test` + `tzic-wipe-test` together → compile error (same
  reason).
- `bench-key-speed` without `stm32u585` → still compiles (the bench
  has no STM32U585-specific imports), but the DWT-timing path is a
  no-op. Pin documented behavior in case someone changes the gating.
- `usb` enabled simultaneously with the e2e-test / bench / fwup /
  gtzc / tzic-wipe entry points → compile-fail (the main() picker in
  main.rs requires exactly one entry point to win the
  `#[cortex_m_rt::entry]` slot). Pin via trybuild.

**Memory.x layout stability:**
- `memory.x` defines `FLASH` at `0x0810_0000` length `0x0008_0000`
  (NS slot A, 512 KB) and `memory-stm32u585.x` defines the
  corresponding hardware regions. Pin the byte-content with an
  `include_str!` snapshot test — a silent drift in the linker
  script causes every existing signed manifest's NS-image
  measurement to mismatch and bricks shipped devices.

**Bind to CLAUDE.md "frozen" promises:**
- The `gtzc-test` and `tzic-wipe-test` features' presence in
  `Cargo.toml` already documents an off-by-default,
  hardware-only entry point — a negative test should assert
  `Cargo.toml`'s feature list does NOT acquire a `default = ["e2e-
  test"]` or `default = ["usb"]` line. (Combined with the secure
  crate's `mode-production` fence, this is the NS-side half of the
  "no dev features in shipped firmware" contract.)
- `FW_VERSION = [0x03, 0x00, 0x00]` (in `usb/commands.rs:104`) — pin
  it. A silent rev-bump from companion changes how `GET_DEVICE_INFO`
  is parsed.
- `PROTOCOL_VERSION` (from `sphincs-tz-shared`) — pin the byte
  emitted in `GET_DEVICE_INFO`.
- `COWSWAP_EIP712_SENTINEL` (used in `maybe_inject_vk_bundle_v3`) —
  pin the 20-byte address. Changing the sentinel breaks the v3
  CoW clear-sign path silently.

#### Tests that would *not* be host-runnable even after refactor

Some surface area genuinely needs on-target / QEMU execution:

- `main()`'s USB-pre-init register dump (DHCSR check + OTG_FS
  register reads).
- `usb::init()`'s RCC clock / GPIO AF wiring sequence.
- `gtzc_test` GTZC1 TZSC NS-alias probing (relies on real TrustZone).
- `tzic_wipe_test` GTZC illegal-access wipe escalation.
- `bench_key_speed` DWT cycle counter timing.
- The full `e2e_test.rs` scenarios (require an actual secure-world
  responder behind the gateway).

These should remain `make e2e` / `make e2e-hw` / `make
gtzc-enforcement-hw` driven and are not negotiable for a host
suite.

## Verification

- `cargo fmt -p sphincs-tz-nonsecure --check` — N/A (no test code
  committed).
- `cargo check -p sphincs-tz-nonsecure --tests --target
  x86_64-unknown-linux-gnu` — **PASS** (no link step; checks
  compile cleanly).
- `cargo clippy -p sphincs-tz-nonsecure --tests -- -D warnings` —
  N/A (no test code committed).
- `cargo test -p sphincs-tz-nonsecure` — **N/A** on host (link
  failure due to ARM-only `__nop` / `__primask_r` / `__cpsid` /
  `__cpsie` symbols pulled in unconditionally by `cortex-m-rt` and
  `cortex-m-semihosting`; same structural blocker on
  `--target thumbv8m.main-none-eabi --tests`, which additionally
  fails for the missing `sized` lang_item under `no_std` libtest).
- (firmware) on-target tests deferred: **yes** — every test listed
  in the "would be written" section is host-via-extracted-lib once
  one of the production-modification avenues (option 3 or 6 above)
  is taken. The on-target subset (`make e2e`, `make e2e-hw`,
  `make gtzc-enforcement-hw`, `make tzic-wipe-hw`,
  `make test-key-speed`, `make test-update-hw`) already exists and
  is exercised by CI through the Makefile targets.

## Recommendation for the follow-up pass

Two paths unblock this slice cleanly; they are not mutually
exclusive.

1. **Lift `erc20_db`, `names_db`, `vk_db`, `selectors_db`, plus the
   `maybe_inject_*` and `ensure_trailer_skeleton` helpers from
   `usb/commands.rs`, into a new `pqsigner-ns-injectors` workspace
   crate (no_std, zero ARM deps).** Mirror the modularity-refactor
   pattern already used for `proto`, `tx-core`, `aa`, `domain`, `tx`,
   `hal`. The new crate is host-testable; the negative suite under
   "Companion injector adversarial paths" + "Wire-format / parser
   fuzz seeds (router)" lives there. Also exposes the same
   primitives to the companion app, eliminating a duplicate
   metadata-lookup implementation. Highest-value option.

2. **Mirror the `secure/src/main.rs`
   `#![cfg_attr(not(test), no_std)] #![cfg_attr(not(test), no_main)]`
   pattern in `nonsecure/src/main.rs`, gating the `cortex_m_rt`
   imports and `#[entry] fn main()` behind `cfg(not(test))`.**
   Smaller PR; host-testable via `cargo test -p sphincs-tz-nonsecure
   --target x86_64-unknown-linux-gnu`. Less ergonomic than option 1
   because the four db modules stay inside the bin crate and tests
   have to reach into them via `#[cfg(test)] pub use` re-exports
   from `main.rs`.

Option 1 is the recommended follow-up.
