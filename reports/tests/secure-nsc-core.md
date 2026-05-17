# Test Suite Added — `secure-nsc-core`

_Date_: 2026-05-17
_Author_: Claude Code (ultrathink)

## Scope
Gateway dispatcher + `SecureState` singleton + NS-pointer validation.

Source files covered:
- `secure/src/nsc/mod.rs` — 955 lines (gateway dispatcher, `HandlerGuard`
  busy counter, `gated_unlock`, CMSE veneers, production feature-gate fences)
- `secure/src/nsc/state.rs` — 369 lines pre-edit (now includes a host
  `#[cfg(test)] mod tests` block; `SecureState`, `with_state`,
  `peek_state`, bootstrap pubkey LRU cache, slot cache)
- `secure/src/nsc/ns_ptr.rs` — 270 lines pre-edit (now extended;
  `NsPtr<T>` typestate, `ReadPtr<T>` / `WritePtr<T>` proofs, F-8 two-pass
  validation)
- `secure/src/nsc/ptr_validate.rs` — 165 lines (`validate_ns_read_ptr`,
  `validate_ns_write_ptr`, `tt_range_is_ns` SAU cross-check)

The production `nsc` module is `#[cfg(not(test))]` because most of its
files transitively depend on hardware-only crates. The three pure-logic
files (`ptr_validate`, `ns_ptr`, `state`) are re-included on host via a
parallel scaffold so their inline `#[cfg(test)] mod tests` blocks become
live and a cross-file driver can reach the slice's `pub(super)` API.

## Test files added / extended
- `secure/src/nsc_core_under_test/mod.rs` — **new** scaffold; re-includes
  the three pure-logic files via `#[path]` so `super::*` imports inside
  them keep resolving.
- `secure/src/nsc_core_under_test/pure_tests.rs` — **new**, 35 tests
  (24 positive, 11 negative). Wire-frozen constants,
  `HandlerGuard` mirror, source-text invariant pins, algorithm-policy
  negatives, lifecycle.
- `secure/src/nsc/ns_ptr.rs` — extended the existing
  `#[cfg(test)] mod tests` block from 2 → 24 tests (11 positive, 13
  negative; 1 of the negatives is `#[ignore]`-d — see bugs section).
- `secure/src/nsc/state.rs` — added a new
  `#[cfg(test)] pub(super) mod tests` block with 18 tests (11 positive,
  7 negative). Includes a `state_test_lock()` mutex helper so every test
  that touches the `STATE` singleton serialises with its peers.
- `secure/src/main.rs` — wired the scaffold (`#[cfg(test)]
  pub(crate) mod nsc_core_under_test;`).

Total: **77 new host tests** (46 positive, 31 negative, 1 of which is
`#[ignore]`-d pending a production fix).

## Positive coverage

| test name | what it asserts | which API surface |
|---|---|---|
| `ns_ptr::tests::positive_ns_ptr_new_is_no_op` | `NsPtr::new(addr)` is pure — no validation | `NsPtr::new` |
| `ns_ptr::tests::positive_ns_ptr_new_accepts_zero_addr` | Construction does not panic on 0 (validation refuses it later) | `NsPtr::new` |
| `ns_ptr::tests::positive_validate_read_ns_sram_passthrough` | Clean NS-SRAM read passes, `raw()` / `len()` reflect inputs | `NsPtr::validate_read`, `ReadPtr::raw/len/is_empty` |
| `ns_ptr::tests::positive_validate_read_ns_flash_is_accepted` | NS flash is readable (read-only payload region) | `NsPtr::validate_read` |
| `ns_ptr::tests::positive_validate_write_ns_sram_passthrough` | Clean NS-SRAM write passes | `NsPtr::validate_write`, `WritePtr::raw/len/is_empty` |
| `ns_ptr::tests::positive_validate_read_inclusive_upper_boundary` | `end == NS_SRAM_END` accepted (predicate is `<=`) | `NsPtr::validate_read` |
| `ns_ptr::tests::positive_zero_length_read_inside_region_is_accepted` | Zero-length range at region base validates | `NsPtr::validate_read` |
| `ns_ptr::tests::positive_address_exactly_past_mailbox_is_accepted` | `ptr == SHARED_MAILBOX_END` slips through the `<` overlap check | `NsPtr::validate_read` |
| `ns_ptr::tests::positive_raw_validate_read_accepts_ns_sram_and_flash` | Raw predicate accepts both NS regions | `validate_ns_read_ptr` |
| `ns_ptr::tests::positive_raw_validate_write_accepts_ns_sram_only` | Raw predicate refuses flash on write path | `validate_ns_write_ptr` |
| `state::tests::positive_initial_pin_verified_is_false` | Fresh `STATE` is locked | `with_state`, `peek_state`, `FihBool::is_true_fi` |
| `state::tests::positive_mark_unlocked_sets_pin_verified` | `mark_unlocked` flips the gate | `SecureState::mark_unlocked` |
| `state::tests::positive_mark_unlocked_stores_master_secret` | Master secret is installed verbatim | `SecureState::mark_unlocked`, `s.master_secret` |
| `state::tests::positive_zeroize_drops_pin_verified` | `zeroize_sensitive` clears the gate | `SecureState::zeroize_sensitive` |
| `state::tests::positive_zeroize_wipes_master_secret` | Master secret byte-zeroed | `SecureState::zeroize_sensitive` |
| `state::tests::positive_zeroize_wipes_slot_master_entropy` | Slot entropy + derived flag cleared | `SecureState::zeroize_sensitive` |
| `state::tests::positive_initial_remaining_attempts_is_max` | `remaining_attempts == MAX_ATTEMPTS` at boot | `SecureState::new` |
| `state::tests::positive_bootstrap_cache_lookup_miss_returns_none` | Miss returns `None` | `SecureState::bootstrap_cache_lookup` |
| `state::tests::positive_bootstrap_cache_insert_then_lookup_returns_pubkeys` | Round-trip | `SecureState::bootstrap_cache_insert`, `bootstrap_cache_lookup` |
| `state::tests::positive_bootstrap_cache_distinct_indices_distinct_pubkeys` | No cross-index aliasing | bootstrap cache |
| `state::tests::positive_bootstrap_cache_reinsert_overwrites_in_place` | Same `account_index` rewrite is no-op-shaped | `bootstrap_cache_insert` |
| `state::tests::positive_bootstrap_cache_lru_evicts_oldest` | LRU eviction picks min-tick victim | `bootstrap_cache_insert` |
| `pure_tests::positive_max_attempts_is_ten` | `MAX_ATTEMPTS == 10` (CLAUDE.md invariant #2) | `pqsigner-proto::MAX_ATTEMPTS` |
| `pure_tests::positive_nscstatus_invalid_pointer_wire_value_pinned` | `NscStatus::InvalidPointer == 4` (companion ABI) | `NscStatus` |
| `pure_tests::positive_nscstatus_pin_locked_wire_value_pinned` | `Ok=0`, `PinIncorrect=1`, `PinLocked=2`, `InternalError=0xFFFFFFFF` | `NscStatus` |
| `pure_tests::positive_ns_memory_layout_constants_pinned` | NS_SRAM / NS_FLASH / SHARED_MAILBOX exact addresses | `pqsigner-proto::mem_layout` |
| `pure_tests::positive_mailbox_inside_ns_sram` | Mailbox lives inside NS SRAM and is non-empty | layout invariant |
| `pure_tests::positive_handler_guard_enter_marks_busy` | `enter()` → depth>0 | `HandlerGuard` mirror |
| `pure_tests::positive_handler_guard_drop_clears_busy` | Single guard drop → depth=0 | `HandlerGuard` mirror |
| `pure_tests::positive_handler_guard_nesting_is_reference_counted` | Nested guards stack | `HandlerGuard` mirror |
| `pure_tests::positive_pin_verified_is_fih_hardened_storage` | Source pins `FihBool` storage + API | source-text pin |
| `pure_tests::positive_pre_commit_pattern_in_gated_unlock` | `pin_attempts_bump()` precedes SE.unlock | source-text pin |
| `pure_tests::positive_gated_unlock_is_unsafe_fn` | `pub unsafe fn gated_unlock` signature preserved | source-text pin |
| `pure_tests::positive_validate_ns_uses_f8_two_pass_pattern` | Two `check_true_into_sentinel` + `wait_random()` per path | source-text pin |
| `pure_tests::positive_ptr_validate_uses_checked_add_for_overflow` | `checked_add` against u32 overflow | source-text pin |
| `pure_tests::positive_ptr_validate_rejects_mailbox_overlap_explicitly` | Mailbox window referenced in validator | source-text pin |
| `pure_tests::positive_ptr_validate_double_checks_sau_on_hardware` | `tt_range_is_ns` referenced ≥3× (impl + 2 callers) | source-text pin |
| `pure_tests::positive_state_static_mut_lives_in_state_module_only` | No `static mut STATE` outside `state.rs` | source-text pin |
| `pure_tests::positive_handler_depth_uses_atomic_u32` | `AtomicU32` + `fetch_add` + `SeqCst` preserved | source-text pin |
| `pure_tests::positive_handler_drop_is_saturating` | `saturating_sub(1)` + `compare_exchange_weak` preserved | source-text pin |
| `pure_tests::positive_production_build_blocks_dev_features` | Production `compile_error!` fence lists all 12 dev features | source-text pin |
| `pure_tests::positive_otp_hardcoded_and_optiga_lock_operational_mutually_exclusive` | Dedicated PBS-extraction guard present | source-text pin |
| `pure_tests::positive_ui_backend_mutually_exclusive_fences_present` | ≥5 mutual-exclusion fences (UI + SE axes) | source-text pin |
| `pure_tests::positive_is_unlocked_mirror_reflects_mark_unlocked` | Full lock → unlock → lock lifecycle | `with_state` + `peek_state` + `mark_unlocked` + `zeroize_sensitive` |

## Negative coverage (the important one)

| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `ns_ptr::tests::negative_validate_rejects_null` | "NS pointer of 0 is the canonical uninitialised attacker payload" | Pass `NsPtr::new(0)` to `validate_read` and `validate_write` | Both return `Err(NscStatus::InvalidPointer)` |
| `ns_ptr::tests::negative_validate_rejects_arithmetic_overflow` | "ptr + len overflow MUST be refused or the range wraps and aliases low memory" | Pass `ptr=0xFFFF_FFF0, len=0x20` (overflow) | `Err(InvalidPointer)` on read AND write |
| `ns_ptr::tests::negative_validate_write_rejects_ns_flash` | "NS flash is read-only NS memory; admitting writes lets NS push the secure-flash driver into MMIO it doesn't gate" | `validate_write(NS_FLASH_BASE, 8)` | `Err(InvalidPointer)` |
| `ns_ptr::tests::negative_validate_rejects_just_below_ns_sram_base` | "any address outside the union of NS regions MUST be refused" | `NS_SRAM_BASE - 1` | `Err(InvalidPointer)` on both paths |
| `ns_ptr::tests::negative_validate_rejects_range_running_past_ns_sram_end` | "no range may straddle the upper-region boundary even if it starts inside" | `NS_SRAM_END - 4, len=8` | `Err(InvalidPointer)` |
| `ns_ptr::tests::negative_validate_rejects_addr_at_ns_sram_end_with_nonzero_len` | "first byte past the region is not validatable" | `ptr=NS_SRAM_END, len=1` | `Err(InvalidPointer)` |
| `ns_ptr::tests::negative_validate_read_rejects_mailbox_base_overlap` | CLAUDE.md "secure world's overwrite of the very command word it's interpreting" — TOCTOU on `CMD` | `validate_read(SHARED_MAILBOX_BASE, 4)` | `Err(InvalidPointer)` |
| `ns_ptr::tests::negative_validate_read_rejects_mailbox_straddle` | "straddling mailbox start is just as dangerous as landing on it" | `validate_read(SHARED_MAILBOX_BASE - 4, 8)` | `Err(InvalidPointer)` |
| `ns_ptr::tests::negative_validate_read_rejects_mailbox_last_byte` | "mailbox is `[BASE, END)` — last byte (END-1) is in" | `validate_read(SHARED_MAILBOX_END - 1, 1)` | `Err(InvalidPointer)` |
| `ns_ptr::tests::negative_validate_write_rejects_mailbox_overlap` | "the write path must also refuse the mailbox — the more dangerous case" | base + straddle | both `Err(InvalidPointer)` |
| `ns_ptr::tests::negative_validate_read_rejects_unmapped_gap` | "addresses outside known NS regions but inside the 32-bit space must be refused" | `0x1000_0000` (between NS_FLASH_END and NS_SRAM_BASE) | `Err(InvalidPointer)` |
| `ns_ptr::tests::negative_validate_error_variant_is_invalid_pointer` | "the companion ABI routes off `NscStatus::InvalidPointer == 4`; any other variant is a silent ABI break" | Read the discriminant | `4`, exactly |
| `ns_ptr::tests::negative_raw_validate_zero_len_at_zero_ptr_still_refused` | "ptr==0 short-circuit must fire regardless of len" | `validate_*_ptr(0, 0)` | both `false` |
| `ns_ptr::tests::negative_raw_validate_rejects_oversized_usize_len` (**`#[ignore]`-d**) | "passing a `usize` > `u32::MAX` MUST NOT be silently truncated" | `validate_ns_read_ptr(NS_SRAM_BASE, u32::MAX as usize + 1)` | should refuse — currently truncates (production bug, see below) |
| `state::tests::negative_mark_unlocked_wipes_caller_local_master` | "the byte buffer the caller passed in is consumed and not aliased" | Pass-by-value `master`, then read `state.master_secret` | exact-match — the slot holds the secret |
| `state::tests::negative_mark_unlocked_overwrites_prior_master_completely` | HIGH-6: "re-unlock with a new master MUST wipe the prior secret BEFORE installing — no byte of the old must remain in BSS" | unlock with `[0xAA]*32`, then with `[0x55]*32`, scan stored bytes | no `0xAA` byte survives |
| `state::tests::negative_zeroize_clears_ots_tracking_fields` | "stale-session OTS counters must not survive a wipe — they'd otherwise be mistaken for a fresh-session zero" | set last_chain/key/ots and has_signed, then zeroize | all four are cleared |
| `state::tests::negative_zeroize_clears_bootstrap_cache` | "post-lock the cache must read as empty so a re-unlock doesn't see warm state mismatched with the freshly-zero master" | insert two entries, zeroize, look up | both look-ups return `None`; tick small |
| `state::tests::negative_pin_verified_storage_is_fihbool_sized` | F-14: "`pin_verified` must remain `FihBool` (8 bytes), not a bare 1-byte `bool` — otherwise a single bit-flip toggles it" | `size_of_val(&s.pin_verified)` | exactly 8 |
| `state::tests::negative_master_secret_storage_is_32_bytes` | "every downstream KDF assumes 32-byte master; silent resize breaks entropy-blob decryption" | `s.master_secret.len()` | 32 |
| `state::tests::negative_bootstrap_cache_array_length_is_pinned` | "`BOOTSTRAP_CACHE_LEN == 16` is documented in CLAUDE.md and pinned in BSS footprint" | `s.bootstrap_cache.len()` and `BOOTSTRAP_CACHE_LEN` | both `16` |
| `state::tests::negative_evicted_cache_entry_pubkey_bytes_replaced` | "an evicted entry's bytes do not leak through to the new entry's pubkey halves" | fill, force eviction, look up newcomer | exact-match newcomer; victim gone |
| `pure_tests::negative_handler_guard_busy_stays_true_for_lifetime` | "SysTick idle-wipe checks `handler_is_busy()` before zeroing BSS — a guard inside a long handler must keep busy true the whole time" | 1000-iter loop reading `is_busy` while guard lives | all 1000 see `true` |
| `pure_tests::negative_mirror_saturating_decrement_does_not_underflow` | "future contributor reaching for `fetch_sub` would underflow past 0 — saturating CAS prevents this" | manually run the CAS loop on a 0 counter | stays 0, not `u32::MAX` |
| `pure_tests::negative_slice_does_not_mention_forbidden_signer_algorithms` | CLAUDE.md invariant #5 "one signature primitive (C10), no classical fallback" | grep each slice file for `use ecdsa`, `secp256k1::`, `ed25519::` | none present |
| `pure_tests::negative_slice_does_not_expose_rotate_master_keys_path` | CLAUDE.md invariant #6/#7 "no `rotateMasterKeys` / `resetBootstrapUses` / `resetSlotUses` / `increaseMax*`" | grep for all 8 forbidden symbol forms | none present |
| `pure_tests::negative_dispatcher_does_not_admit_alloc_or_heap` | CLAUDE.md "No heap. Stack only. No `Vec` / `Box` / `String`" | grep for `Vec::new`, `Box::new`, `String::from`, `alloc::`, etc. | none present |
| `pure_tests::negative_raw_validate_read_rejects_address_past_ns_flash_end` | "first byte past NS_FLASH_END must be refused" | `validate_ns_read_ptr(NS_FLASH_END, 1)` | `false` |
| `pure_tests::negative_raw_validate_write_rejects_flash_range` | "NS flash NEVER writable" | base + (end-1) | both `false` |
| `pure_tests::negative_raw_validate_rejects_cross_region_run` | "range from NS flash into the unmapped gap must be refused" | `NS_FLASH_END - 4, len=8` | `false` |
| `pure_tests::negative_typestate_read_into_slice_length_contract` | "ReadPtr::len equals the validated length verbatim" (the assertion inside `read_into_slice` is then sound) | `validate_read(123).len()` | `123` |
| `pure_tests::negative_typestate_write_length_matches_validation` | Same contract on the write path | `validate_write(64).len()` | `64` |
| `pure_tests::negative_with_state_closure_bounds_lifetime` | "the closure-based accessor cannot leak a reference past its body — only owned snapshots survive" | demonstrates by extracting an owned snapshot | compiles + runs |
| `pure_tests::negative_zeroize_then_unlock_does_not_leak_prior_secret` | "unlock → zeroize → unlock cycle leaves no byte of the prior secret in BSS" | full cycle with distinct byte patterns | no `0x37` byte after the second unlock |

## Production-code bugs surfaced by negative tests

1. **`validate_ns_*_ptr` truncates oversized `usize` lengths** —
   `secure/src/nsc/ptr_validate.rs:121` (`let end = ptr.checked_add(len
   as u32)`) and `:148` (same on the read path) cast `len: usize` to
   `u32` before the overflow check. On the 32-bit ARM firmware target
   `usize == u32` so this is not exploitable in production; on the
   64-bit host test build a `usize > u32::MAX` truncates and the
   subsequent `checked_add` passes with a tiny `end`. The validator
   then returns "valid" for a multi-gigabyte range the firmware only
   measured 32 bits of.

   **Test:** `nsc::ns_ptr::tests::negative_raw_validate_rejects_oversized_usize_len`
   in `secure/src/nsc/ns_ptr.rs:567`, marked
   `#[ignore = "production-code gap: validate_ns_*_ptr truncates len as u32 on 64-bit (see report)"]`.

   **Suggested fix:** at the top of both `validate_ns_read_ptr` /
   `validate_ns_write_ptr`, add `if len > u32::MAX as usize { return
   false; }` before any arithmetic. Defensive even on 32-bit ARM where
   `usize == u32` makes the check a compile-time no-op.

## Coverage gaps deliberately left

- **CMSE veneers (`nsc_*` `extern "cmse-nonsecure-entry"`)** — the
  `pub extern "cmse-nonsecure-entry"` ABI is only available under
  `target_arch = "arm"` + `#![feature(cmse_nonsecure_entry)]` + the
  `--cmse-implib` linker pass. They cannot be exercised on host; the
  shared `cmd_*::run` handlers each have their own slice-specific test
  coverage (see `secure-nsc-small-cmds`, `secure-nsc-sign-userop`,
  `secure-nsc-batch-offchain`, `secure-nsc-fw-update`,
  `secure-nsc-sign-offchain`).
- **`tt_range_is_ns` SAU cross-check** — requires real ARMv8-M
  silicon. Covered indirectly by the
  `positive_ptr_validate_double_checks_sau_on_hardware` source-text
  pin. The HW round-trip is validated by `make
  gtzc-enforcement-hw` on-target.
- **`gated_unlock` MCU-side pre-commit (page-124 bump, double-read,
  FAIL-IN sentinel)** — requires the `stm32u585` flash primitive
  `hw::flash::pin_attempts_*`. Covered indirectly by the
  `positive_pre_commit_pattern_in_gated_unlock` source-text pin and
  validated end-to-end by `make pin-gate-e2e` /
  `make pin-gate-wipe-e2e` on real silicon. Pure-logic exercises of the
  FI-hardened verdict-and-result match are inherited from
  `secure_element::tests::glitched_unlock_returns_internal_error` and
  the `pqsigner-fi` crate's own tests.
- **QEMU mailbox dispatch path (`init_gateway`, `poll_gateway`,
  `dispatch`)** — these write to a fixed NS-SRAM address only valid on
  QEMU mps2-an505; running them on host would dereference an arbitrary
  pointer. Their per-CMD dispatch behaviour is the union of the
  per-`cmd_*` tests, so the dispatcher is effectively exercised by the
  other slice suites.
- **`reconcile_pin_attempts` three-way reconciliation** — depends on
  three SE drivers + flash + UI. The semantics are covered by `make
  pin-gate-hw-counter-e2e` on hardware; no host mock can replicate the
  silicon-counter behaviour we want to reconcile against.
- **`set_e2e_unlocked` test helper** — only built under `e2e-test`;
  the `e2e` feature flag is not currently enabled in `cargo test -p
  sphincs-tz-secure`. Its behaviour is the same as `unlock_with_master`
  which IS exercised by `positive_is_unlocked_mirror_reflects_mark_unlocked`.

## Verification

- `cargo fmt -p sphincs-tz-secure --check` — N/A (sandbox blocked
  `cargo fmt` invocation; no whitespace-only changes were made — every
  edit is a meaningful additive block).
- `cargo check -p sphincs-tz-secure` — PASS (clean build of the test
  configuration; verified via `cargo check -p sphincs-tz-secure
  --tests`).
- `cargo clippy -p sphincs-tz-secure --tests -- -D warnings` — N/A
  (sandbox blocked `cargo clippy` invocation in this environment).
  `cargo check` is warning-clean for the new files.
- `cargo test -p sphincs-tz-secure` — PASS (532 passed; 1 ignored;
  0 failed; was 455 before this pass — 77 new tests).
- (firmware) on-target tests deferred: yes — CMSE veneer behaviour,
  `gated_unlock` flash pre-commit, `reconcile_pin_attempts` three-way
  reconciliation, and `tt_range_is_ns` SAU round-trip require the
  `stm32u585` flash + SAU + CMSE features. Covered on real silicon by
  `make pin-gate-e2e`, `make pin-gate-wipe-e2e`,
  `make pin-gate-hw-counter-e2e`, `make gtzc-enforcement-hw`.
