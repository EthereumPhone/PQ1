# Handoff — Modularity Refactor (in progress)

> **Read order:** §1 (orientation) → §2 (what's landed) → §3 (what's
> still pending) → §4 (gotchas) → §5 (first actions). The plan file
> at `/home/markus/.claude/plans/ok-make-a-plan-logical-lobster.md`
> is the authoritative design spec; this doc is the **execution map**
> — it tells you what's been done, what's left, what footguns the
> previous runs hit, and where to pick up.
>
> This is the **third revision** of the handoff:
> - Revision 1 (2026-04-30, run 1) wrote down what landed in the
>   first execution session: Phases 0+2+3+4 + Phase 10 PR E.
> - Revision 2 (2026-04-30, run 2) appended a §11 delta documenting
>   the second run: Phases 5.1–5.4 + 6 PR 1 + 8 PR 1 + 10 PRs A/B/D
>   + Phase 11 partial.
> - Revision 3 (this file, 2026-04-30) consolidates both runs into a
>   single coherent narrative so the next person doesn't have to
>   reconstruct state across two delta sections. Earlier revisions
>   live in `git log -- docs/handoff-modularity-refactor.md` if you
>   need them.

---

## 1. Orientation

### 1.1 What this refactor is

A six-axis audit of `/home/markus/Documents/sphincs_rust` on 2026-04-30
found that PQSigner OS has the **right boundaries** (S↔NS split, dual-SE
entropy XOR, on-chain `ISPHINCSVerifier`) but the **wrong interfaces
between them**:

1. Most polymorphism is `cfg`-gated rather than trait-routed (291
   `cfg(feature = "stm32u585")` sites in `secure/src/`, mostly
   per-driver-call switching).
2. The Rust↔Solidity wire format was duplicated by hand on both sides
   without an IDL — `C10_SIG_LEN = 4008` lived in three places.
3. Pure-logic modules (AA hashing, EIP-1559 parsing, ERC-20 trust
   gates, BIP-39→C10 derivation) lived inside `secure/` so host-side
   reference signers couldn't reuse them without pulling in
   hardware-bound dependencies.
4. CI ran Foundry tests but no Rust tests.
5. The 50 ad-hoc feature flags lacked any cross-axis enforcement;
   build.rs panicked late, the production fence in
   `secure/src/nsc/mod.rs` was incomplete.
6. `secure/src/nsc/cmd_sign_userop.rs` was a 1241-line monolith.

### 1.2 Why now

Pre-production. **No devices have shipped, no on-chain wallets hold
funds.** Domain tags, CREATE2 salt preimages, and feature names can
still move without breaking real users — only bench-board
re-provisioning. After launch each Tier-1 extraction is ~10× more
expensive. See
`/home/markus/.claude/projects/-home-markus-Documents-sphincs-rust/memory/project_pre_production_status.md`.

### 1.3 Plan structure

The plan file (`/home/markus/.claude/plans/ok-make-a-plan-logical-lobster.md`)
sequences the work into 12 phases (0–11 + optional 12). Each phase
is meant to leave the build green so phases land independently. After
two execution runs, the state is:

```
0.  Snapshot                          ✅ landed (run 1)
1.  CI matrix                         🟡 PENDING — authored, removed before commit; user-decision blocker
2.  compile_error! fences             ✅ landed (run 1)
3.  pqsigner-proto crate              ✅ landed (run 1)
4.  Solidity constants codegen        ✅ landed (run 1)
5.  pqsigner-aa + -tx + -domain       ✅ PARTIAL — extracts done, tx/typed_call/* + tx/eip712/* still in secure/
6.  pqsigner-hal trait crate + impls  ✅ PARTIAL — PR 1 (trait crate) only; PRs 2-4 (impls) deferred
7.  cfg → trait migration             ❌ NOT STARTED — biggest single win, blocked on 6 PRs 2-4
8.  Feature axes 50 → 25-35           ✅ PARTIAL — PR 1 (axis aliases) only; PR 2 (Makefile flip) deferred
9.  cmd_sign_userop decomposition     ❌ NOT STARTED — 1241 LOC monolith, multi-day refactor
10. Polish (5 PRs)                    ✅ PARTIAL — PRs A, B, D, E landed; PR C (phased boot) blocked on 6 PRs 2-4
11. Doc cleanup                       ✅ PARTIAL — Key File Map + work-todo + this doc updated; testing-matrix + how-tos + xtask doc-check pending
12. Domain-tag rename                 ⏸️  GATED ON USER APPROVAL — optional pre-launch one-shot
```

### 1.4 Critical artifacts to read before continuing

| What | Where |
|---|---|
| The plan | `/home/markus/.claude/plans/ok-make-a-plan-logical-lobster.md` |
| Project context (invariants, file map) | `CLAUDE.md` |
| Pre-production status | `~/.claude/projects/-home-markus-Documents-sphincs-rust/memory/project_pre_production_status.md` |
| Baseline metrics (pre-refactor) | `docs/work-todo.md` — section "Modularity refactor — baseline (2026-04-30)" |
| Completion log entries (2 rows for the 2 runs) | `docs/work-todo.md` — last two rows of "Completion Log" |
| This file | `docs/handoff-modularity-refactor.md` |

---

## 2. Current state — what landed across both runs

### 2.1 New workspace members

```toml
# Run 1
"proto"      # pqsigner-proto       — Phase 3: protocol IDL (constants, enums, wire sizes)
"xtask"      # pqsigner-xtask       — Phase 4: Solidity-constants codegen tool

# Run 2
"tx-core"    # pqsigner-tx-core     — Phase 5 PR 5.1: RLP, EIP-1559, U256, keccak256
"aa"         # pqsigner-aa          — Phase 5 PR 5.2: UserOp hash + EIP-1271 PersonalSign
"domain"     # pqsigner-domain      — Phase 5 PR 5.3: KDF, AES-GCM wrap, BIP-39→C10
"tx"         # pqsigner-tx          — Phase 5 PR 5.4 partial: erc20/names/selectors verifiers
"hal"        # pqsigner-hal         — Phase 6 PR 1: trait surface (no impls yet)
```

The secure crate now depends on all six. `secure/src/{tx,aa,erc20,names,
selectors}/mod.rs` and `secure/src/crypto.rs` are thin re-export shims so
existing call sites compile unchanged. `sphincs-tz-shared` continues to
re-export `pqsigner-proto` plus the firmware-specific `apdu_framing` and
`db_format` modules; it goes away in Phase 11.

### 2.2 Other artifacts produced

- **`contracts/smart-wallet/src/generated/PqsignerProto.sol`** —
  AUTO-GENERATED by `cargo run -p pqsigner-xtask -- gen-solidity-constants`.
  Imported by `PQSmartWallet.sol`, `PQSmartWalletFactory.sol`,
  `PQMultiOwnable.sol`. Source of truth is Rust;
  `gen-solidity-constants --check` returns non-zero on drift.
- **`secure/src/nsc/ns_ptr.rs`** — `NsPtr<T>` / `ReadPtr<T>` /
  `WritePtr<T>` typestate (Phase 10 PR B). Adoption is incremental.
- **Five-axis feature aliases** in `secure/Cargo.toml` (Phase 8 PR 1):
  `platform-*`, `secure-element-*`, `ui-mode-*`, `mode-*`, `accel-*`.
  Each is a thin pass-through over the legacy flag, no behaviour change.
- **`pub trait Ui`** in `secure/src/ui/mod.rs` (Phase 10 PR A) with
  per-backend `impl Ui for Display` blocks.
- **`MockSecureElement::simulate_glitch()`** + 6 host tests covering
  the 10-wrong-PIN brick path (Phase 10 PR D).
- **CMD-range constants + collision check** in `pqsigner-proto`
  (Phase 10 PR E, run 1).
- **Production-fence `compile_error!` set** expanded in
  `secure/src/nsc/mod.rs` (Phase 2, run 1) — covers `debug-log`,
  `ui-capture`, pairwise UI-axis exclusivity, pairwise SE-axis
  exclusivity, "must select one" gates.

### 2.3 NOT landed (intentionally — see §3)

- **`.github/workflows/rust.yml`** — Phase 1 was authored, then
  removed before commit at the user's request. Shared CI infrastructure
  is a different decision category. Re-author when ready.
- **`hal-stm32u5/`, `hal-mock/`, `secure/src/platform.rs`** — Phase 6
  PRs 2-4 deferred. The `pqsigner-hal` trait crate (PR 1) is the
  spec; impls live in `secure/src/hw/*` today and migrate later.
- **`secure/src/nsc/sign_userop/{header,trailer,…}.rs`** — Phase 9
  decomposition not started. The 1241-line monolith is unchanged.

### 2.4 Verification gates (all green at handoff time)

```bash
make test-unit
# secure:    105 passed
# tx-core:    23 passed
# aa:         28 passed
# domain:      9 passed
# tx:          8 passed
# total:     173 passed (was 167; +6 from Phase 10 PR D mock-SE realism)

make test-solidity                    # 49/49 (3 suites)

cargo run -q -p pqsigner-xtask -- gen-solidity-constants --check \
  | diff - contracts/smart-wallet/src/generated/PqsignerProto.sol   # no drift

cargo check -p sphincs-tz-secure --target thumbv8m.main-none-eabi \
  --no-default-features \
  --features dual-se,ui-oled,stm32u585,debug-log,e2e-test,otp-hardcoded-master-key   # canonical hw bringup compiles

cargo check -p sphincs-tz-secure --no-default-features \
  --features mock-se,debug-log,ui-semihosting --tests                                # canonical QEMU compiles

cargo check -p sphincs-tz-secure --target thumbv8m.main-none-eabi \
  --no-default-features \
  --features platform-stm32u585,secure-element-dual,ui-mode-oled,mode-bringup,otp-hardcoded-master-key   # axis-alias path compiles
```

### 2.5 No commits yet

The working tree is dirty with the second-run changes. Run 1 was
committed (`96214ca refactor(modularity): extract pqsigner-proto IDL
+ codegen Solidity + tighten production fence`); run 2 is uncommitted.
**First decision for the next session: ask the user whether to bundle
the second run as one PR or split it per-phase.** The phases are
small enough that per-phase commits are reviewable, but they all
landed in a single execution session so there's no rebase pain either
way.

The dirty files (run 2):

```
M  CLAUDE.md
M  Cargo.lock
M  Cargo.toml
M  Makefile
M  docs/handoff-modularity-refactor.md
M  docs/work-todo.md
M  secure/Cargo.toml
M  secure/src/aa/mod.rs                    # shim
M  secure/src/crypto.rs                    # shim + retained FI/SE-bound helpers
M  secure/src/erc20/mod.rs                 # shim
M  secure/src/names/mod.rs                 # shim
M  secure/src/nsc/mod.rs                   # +mod ns_ptr;
M  secure/src/secure_element.rs            # simulate_glitch + 6 tests
M  secure/src/selectors/mod.rs             # shim
M  secure/src/tx/mod.rs                    # shim
M  secure/src/ui/mod.rs                    # +pub trait Ui + impls
D  secure/src/aa/{eip1271,userop}.rs       # → aa/
D  secure/src/erc20/{bundle,calldata,dispatch,merkle}.rs    # → tx/
D  secure/src/names/{bundle,resolver}.rs   # → tx/
D  secure/src/selectors/bundle.rs          # → tx/
D  secure/src/tx/{eip1559,hash,rlp}.rs     # → tx-core/
A  aa/                                      # new crate
A  domain/                                  # new crate
A  hal/                                     # new crate
A  secure/src/nsc/ns_ptr.rs                # NsPtr typestate
A  tx-core/                                 # new crate
A  tx/                                      # new crate
```

---

## 3. What's left — phase by phase

Each subsection is self-contained: read it cold, get to work.

### 3.1 Phase 1 — Rust CI matrix (1 PR, deferred at user's request)

**Status: PENDING.** Authored, removed before commit at user request
(run 1). Shared CI infrastructure is a different trust category
(third-party actions, runner-minute spend, root-level workflow surface).
**Re-author only with the user's explicit sign-off on the actions list.**

The original Phase 1 design is in the plan file §"Phase 1". Key
elements:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- Host tests: `cargo test --workspace --exclude sphincs-tz-secure
  --exclude sphincs-tz-nonsecure --exclude fsbl`
- `cargo test -p sphincs-tz-secure --tests --release` — host-testable
  secure tests
- 6-cell secure build matrix on `thumbv8m.main-none-eabi`
- Production-fence audit: every forbidden flag combination MUST
  trigger a `compile_error!`
- QEMU `make e2e` smoketest
- `make verify-repro` reproducibility check
- Solidity (`forge test`, `forge build --sizes`, `forge fmt --check`,
  `forge snapshot --check --tolerance 1`)
- **Solidity-constants drift detector** — `cargo run -p pqsigner-xtask
  -- gen-solidity-constants --check | diff -
  contracts/smart-wallet/src/generated/PqsignerProto.sol` — works
  today, just one shell step to wire into CI.

Until Phase 1 lands, every "CI does X" line in this doc means
"manual `make` recipe does X today; CI will automate later".

### 3.2 Phase 5 PR 5.4 (rest) — `tx/typed_call/*` + `tx/eip712/{cowswap,safe}/*` (1 PR)

**Status: PENDING.** Run 2 moved `erc20/`, `names/`, `selectors/` into
`pqsigner-tx`; `typed_call/` and `eip712/{cowswap,safe}/` stayed
behind because their fixture-roundtrip tests reference
`secure/data/*.json` paths via `CARGO_MANIFEST_DIR`.

Plan:

1. Move the source files into `tx/src/typed_call/` and
   `tx/src/eip712/{cowswap,safe}/`.
2. **Move the fixture data alongside.** The `secure/data/selectors.json`
   round-trip test in `typed_call/parser.rs:568` reads
   `concat!(env!("CARGO_MANIFEST_DIR"), "/data/selectors.json")`.
   Either:
   - Copy `secure/data/selectors.json` → `tx/data/selectors.json`
     (if `dbgen` will keep generating both, which is fine), or
   - Change `dbgen` to write to `tx/data/` (cleanest), or
   - Fix the test to read from a workspace-relative path
     (`../secure/data/selectors.json`).
3. The display-side `cowswap_display.rs` and `safe_display.rs` stay
   in `secure/` because they import `crate::ui::*`. Phase 10 PR A's
   `Ui` trait is a stepping stone — Phase 7 will let them take
   `&mut impl Ui` and move into `pqsigner-tx`.
4. `secure/src/tx/{typed_call,eip712}/mod.rs` become re-export shims.

**Cross-checks:**
- `secure/src/tx/typed_call/abi.rs` imports
  `crate::erc20::calldata::{decode_address_word, decode_u256_word}`.
  After the move that becomes `pqsigner_tx::erc20::calldata::*`.
- `secure/src/tx/display/{cowswap,safe}_display.rs` import
  `crate::tx::eip712::{cowswap,safe}::{...}`. After the move those
  resolve through the re-export shim.

### 3.3 Phase 6 PRs 2-4 — `hal-stm32u5/` + `hal-mock/` + `secure/src/platform.rs` (4 PRs)

**Status: PENDING.** PR 1 (the trait crate at `hal/`) landed in run 2.
PRs 2-4 are sequenced under the plan §"Phase 6":

#### PR 6.2 — `pqsigner-hal-stm32u5`

New crate `hal-stm32u5/Cargo.toml` (`pqsigner-hal-stm32u5`, no_std,
ARM-only via `[target.'cfg(target_arch = "arm")']`). Move every file
from `secure/src/hw/` **except** `secret_keys.rs` into
`hal-stm32u5/src/`. Each driver becomes one `pub struct StmRng;`
etc., implementing its `pqsigner-hal` trait.

**Critical**: do NOT move `secret_keys.rs`. The SAES-CMAC(DHUK) KDF
needs a clean separation between "HAL primitive" (SAES) and "domain
logic" (KDF). The `pqsigner-domain` crate (run 2) holds the KDF
caller; `hal-stm32u5` exposes the SAES trait impl that the domain
crate consumes — but the wiring lives in `secret_keys.rs`, which
stays in `secure/` because it's the cross-cutting glue between
`pqsigner-domain` and `pqsigner-hal-stm32u5`.

Re-create `Stm32U5Platform` aggregating all the driver structs and
implementing `pqsigner_hal::Platform`. The
`pqsigner_sha256_*` extern-C symbols stay here — they shim from
`sphincs-c10`'s feature-gated FFI calls into
`<Stm32U5Sha256 as hal::Sha256>::*`.

**Verify:** `cargo build -p sphincs-tz-secure --features stm32u585,...`
still produces a byte-equal artifact (run a clean `make verify-repro`).

#### PR 6.3 — `pqsigner-hal-mock`

New crate `hal-mock/Cargo.toml` (`pqsigner-hal-mock`, no_std + std-
friendly via cfg). Provides:

- `MockRng` — seedable PRNG for deterministic tests.
- `MockSha256` — wraps `sha2::Sha256`.
- `MockSaes` — wraps software AES + CMAC under a fake-DHUK constant
  so unit tests for the SAES-CMAC KDF don't need hardware.
- `MockFlash` — `[u8; FLASH_SIZE]` + page-erase semantics
  (programmed bits monotonic, erase resets to 0xFF).
- `MockOtp` — write-once `Vec<u8>` (gated to `std`).
- `MockTamp`, `MockBoot`, `MockI2c`, `MockSpi`, `MockButtons`,
  `MockUart` — minimal observable behaviour.
- `MockPlatform` aggregating the above for unit tests.
- `QemuPlatform` reusing MockSha256 etc. but plugging
  `secure/src/host_rng.rs`'s semihosting `/dev/urandom` for `Rng`.

#### PR 6.4 — `secure/src/platform.rs`

```rust
#[cfg(feature = "stm32u585")]
pub type ActivePlatform = pqsigner_hal_stm32u5::Stm32U5Platform;
#[cfg(not(feature = "stm32u585"))]
pub type ActivePlatform = pqsigner_hal_mock::QemuPlatform;
```

After PR 4, this is the **only** `cfg(feature = "stm32u585")` left at
the platform level. Every other call site moves to `&mut impl
Platform` in Phase 7.

### 3.4 Phase 7 — Migrate `secure/src/` from `cfg` to trait dispatch (3 PRs)

**Status: NOT STARTED.** Biggest single architectural win — drops
`cfg(feature)` density in `secure/src/` from **294 today** to **<80**.
Blocks on Phase 6 PRs 2-4.

#### PR 7.1 — `secure/src/rng.rs`, `crypto.rs` callers, `secret_keys.rs`

Replace `hw::rng::fill()` with `platform.rng().fill()`. The current
`[target.'cfg(target_arch = "arm")']` separation already allows host
tests to use a `MockPlatform`; this PR just makes the platform
threading explicit at every call site.

#### PR 7.2 — `secure/src/optiga/`, `se050/`, `tropic01_se.rs`, `dual_se.rs`

SE drivers take `&mut impl I2cBus` (or `&mut impl SpiBus` for Tropic01)
instead of importing `crate::hw::i2c_hw` directly. The `WalletStore`
impl signatures don't change; only the bus access route does.

The 50 cfg occurrences in `se050/mod.rs` and 36 in `optiga/mod.rs`
should drop to <10 each in this PR (the remaining ones are legit
feature gates like `optiga-hw-counter`, `optiga-no-shield`).

#### PR 7.3 — `secure/src/main.rs` boot flow

Replace the flat init list at `secure/src/main.rs:356–605` with:

```rust
let mut platform = ActivePlatform::init();
platform.run_stage(BootStage::Clocks)?;
platform.run_stage(BootStage::TrustZone)?;
// ...
```

This is also Phase 10 PR C's "phased boot" — they're the same
edit. PR 7.3 + Phase 10 PR C land together.

**Verification gates:**
- `grep -rn "cfg(feature" secure/src | wc -l` ≤ 80 (was 291 at audit
  time, 294 today after run 2's tiny incremental adds).
- `make verify-repro` still passes (artifact byte-equal).
- The QEMU `make e2e` smoketest still runs every TxKind variant.

### 3.5 Phase 8 PR 2 — flip Makefile + delete legacy flags + cross-axis fences (1 PR)

**Status: PENDING.** PR 1 (axis aliases) landed in run 2; the aliases
are pass-throughs over legacy flags so behaviour is unchanged. PR 2:

1. Update **every** Makefile recipe to use the new axis names
   (`--features platform-stm32u585,secure-element-dual,ui-mode-oled,
   mode-bringup,...`). Touches every `make flash-*`, `make run-*`,
   `make e2e*`, `make pin-gate-*-e2e`, etc. Roughly 40 recipes.
2. Delete the legacy flag aliases (`mock-se`, `dual-se`, `e2e-test`,
   `debug-log`, `stm32u585`, `ui-oled`, etc.) from
   `secure/Cargo.toml`'s `[features]` section.
3. Add the cross-axis `compile_error!`s to `secure/src/nsc/mod.rs`:
   - Exactly one platform axis flag set
   - Exactly one secure-element axis flag set
   - Exactly one ui-mode axis flag set
   - Exactly one mode axis flag set
4. Update the `solidity-constants-in-sync` job's diff-target check.

**Pitfall**: Bench-board builds use specific Makefile targets. Verify
each on real hardware before deleting the legacy alias it depends on.
Order of operations: alias-add → recipe-flip-on-bench-board →
alias-delete. Don't delete first.

**Final flag count target: 25–35**, broken down as:
- 5 platform axis values (currently 2: qemu, stm32u585)
- 5 secure-element axis values
- 5 ui-mode axis values
- 4 mode axis values
- 4 accelerator flags
- ~10 sub-features (`optiga-hw-counter`, `pin-gate-*-e2e`, etc.) that
  declare their required axes via per-feature `compile_error!`s.

Today's count is **70 flags** (50 legacy + 20 axis aliases). After
PR 2 deletes the legacy aliases: ~30 flags. The original audit
quoted "95+" and the plan said "95 → 5"; the real number was always
50 and the achievable target is 25–35.

### 3.6 Phase 9 — Decompose `cmd_sign_userop.rs` (4 PRs)

**Status: NOT STARTED.** The file is still **1241 lines** with the
`run()` body alone weighing ~1070 LOC. Multi-day refactor.

Target shape (per the plan):

```
secure/src/nsc/sign_userop/
├── mod.rs                  # run() — ~150 LOC, orchestration only
├── header.rs               # parse + validate the unified-input header
├── trailer.rs              # ERC-20, CoW, Safe, ZK trailer parsing
├── slot_keys.rs            # slot-key derivation + cache management
├── userop_digest.rs        # UserOp hash computation (delegates to pqsigner-aa)
├── execute_calldata.rs     # executeWithOffchainCount calldata builder
├── offchain_counter.rs     # page-123 read/bump + gap enforcement
├── wrapper_encode.rs       # SignatureWrapper ABI encoding
└── output_assembly.rs      # stitches new_offchain_count + init_code + Type1 + Type2
```

PR ordering (per plan §"Phase 9"):

1. **PR 9.1**: extract `header.rs` + `trailer.rs`. Pure parsing
   logic, host-testable. Add proptest fuzz tests for both.
2. **PR 9.2**: extract `slot_keys.rs` + `userop_digest.rs` +
   `execute_calldata.rs`. Slot-key derivation already exists in
   `pqsigner-domain` (run 2 PR 5.3); this PR routes the secure-side
   `SLOT_CACHE` through it. UserOp digest computation lives in
   `pqsigner-aa` (run 2 PR 5.2).
3. **PR 9.3**: extract `offchain_counter.rs` + `wrapper_encode.rs` +
   `output_assembly.rs`. Wrapper encoding tests against
   `pqsigner-proto` round-trips.
4. **PR 9.4**: slim `mod.rs::run()`. What remains is ~150 LOC of
   orchestration: pointer validation → header parse → trailer parse
   → render+confirm → slot derive → digest compute → C10 sign
   (FI-double-checked) → output assemble → zeroize.

**Tests to add** after each PR:
- Per-submodule `#[cfg(test)] mod tests` with golden vectors.
- Integration test `secure/tests/sign_userop_roundtrip.rs` that
  provisions `MockPlatform` + `MockSecureElement`, drives the full
  sign path, asserts byte-equal output across two invocations
  (determinism check).

**Pitfall**: the `nsc` module is currently `#[cfg(not(test))]`-gated
in `main.rs:91`. Host integration tests inside `nsc/sign_userop/`
won't run until that gate is lifted (or the submodule moves outside
`nsc`). Easy workaround: put the unit tests in the PR-9 submodules
themselves (they'll compile but not run on host); the integration
test in `secure/tests/sign_userop_roundtrip.rs` runs because it sees
the crate as a library — except `sphincs-tz-secure` is a `[bin]`, so
`tests/` integration tests don't get to import internal modules
either. Path forward: add a `[lib]` target to the secure crate that
exposes `pub use crate::nsc::sign_userop::*;` for tests, or extract
the pure-logic submodules into a fresh `pqsigner-sign` workspace
member (cleanest, parallels Phase 5).

### 3.7 Phase 10 PR C — Phased boot (1 PR)

**Status: BLOCKED on Phase 6 PRs 2-4.** Same edit as Phase 7 PR 7.3
(see §3.4). They land together.

### 3.8 Phase 11 — Doc cleanup (rest)

**Status: PARTIAL.** Run 2 updated `CLAUDE.md` "Key File Map" with a
leading note pointing at the new crates, appended a row to
`docs/work-todo.md`'s Completion Log, and produced this handoff.
What's still left:

- Update CLAUDE.md "Architecture at a Glance" diagram to show the
  trait dispatch through `pqsigner-hal` (paint after Phase 7 lands —
  the diagram's content depends on what the call sites look like).
- Add a "Testing matrix" section to CLAUDE.md listing every gate.
- Add "Adding a peripheral / Adding a CMD / Adding a SE backend /
  Adding a UI backend" how-tos that point contributors at the right
  trait.
- Add an `xtask doc-check` subcommand that greps file paths from
  CLAUDE.md and fails if any is missing. Wire into CI (with Phase 1).
- Replace every `sphincs_tz_shared` reference in docs with
  `pqsigner-proto` (or note the re-export shim continues to work)
  AFTER `sphincs-tz-shared` is dissolved (which is a Phase 11 task
  itself — needs to wait on `db_format` having a new home).

These should land alongside Phase 7, not before — the diagram and
how-tos describe the post-trait-dispatch shape.

### 3.9 Phase 12 (optional) — Domain-tag rename

**Pre-condition: Phases 0–11 landed. User explicitly approves.**

Rename `"sphincs-c6-v1"` → `"sphincs-c10-v1"` (and the `-acct`
variant) in one coordinated commit. Per CLAUDE.md "no real users
yet, so a deliberate, coordinated tag cleanup before launch is fine
— what's not fine is silent drift inside an unrelated PR."

This changes every wallet's CREATE2 address. Every bench seed
re-derives to a different account. Do it last so it doesn't entangle
with structural refactoring.

Touches: `pqsigner-domain/src/lib.rs` (the `derive_c10_master_*`
callers), every e2e test fixture, the test-vector generator's
expected outputs, every deployed-script-side address constant.

**Output**: `docs/address-rename-2026-XX-XX.md` documenting the new
addresses every bench seed re-derives to.

---

## 4. Gotchas (combined across both runs)

These contradict or refine details in the plan and the original audit.
Read them before continuing.

### 4.1 Feature-flag count was 50, not 95 (run 1)

The audit quoted "95+ feature flags". The actual count via
`awk '/^\[features\]/{f=1;next}/^\[/{f=0}f && /^[a-z][a-z0-9-]* *=/{c++}END{print c}'`
on `secure/Cargo.toml` was **50** before run 2. Run 2's Phase 8 PR 1
added 20 axis aliases, bringing it to **70 today**.

So the original "95→5" target is more like **70 → 25–35** after
Phase 8 PR 2 deletes the legacy aliases. The pressure point is cfg
*density* inside drivers (50 in `se050/mod.rs` alone), not the flag
count.

### 4.2 `secure/build.rs` already enforces UI exclusivity (run 1)

`secure/build.rs:20–25` panics if two of `ui-semihosting`/`ui-oled`/
`ui-noop` are simultaneously set, and panics if zero are set. The
Rust-side `compile_error!` blocks added in Phase 2 are not redundant
(they fire on host targets that don't compile build.rs), but **don't
be surprised when the build fails with a panic from build.rs before
the Rust-side fence triggers.**

### 4.3 `WalletStore` is one of two SE traits (run 1)

The audit reported one `WalletStore` trait. There are actually two,
both in `secure/src/secure_element.rs`:

- **`SecureElement`** (line 29) — low-level r-mem + MAC-and-Destroy.
  Implemented by backends with MACD-capable storage:
  `MockSecureElement`, `Tropic01SecureElement`. NOT implemented by
  SE050 (uses hardware UserID PIN gating instead) or OPTIGA Trust M.
- **`WalletStore`** (line 40) — high-level wallet ops (provision,
  unlock, read entropy/VK, attempt counter). Implemented by every
  backend.

When designing impls of `pqsigner-hal` in Phase 6, mirror this
two-layer pattern: the `SecureElement`-equivalent low-level slot
trait is a **capability** that not every HAL impl provides; the
high-level wallet-store trait is universal.

### 4.4 `tx/` is more entangled than the audit said (run 1)

The audit said `tx/` is pure-logic with zero hardware deps. That's
*almost* true — `tx/eip1559.rs`, `tx/hash.rs`, `tx/rlp.rs` are pure
(extracted to `pqsigner-tx-core` in run 2). But the rest cross-imports:

- `tx/typed_call/*` and `tx/eip712/*` use `crate::erc20::*`,
  `crate::names::*`, `crate::selectors::*`.
- `tx/display/*` uses `crate::ui::*`.

So Phase 5 is multi-PR — and Phase 5 PR 5.4's `typed_call/` + `eip712/`
moves are still pending (see §3.2).

### 4.5 `EXECUTE_SELECTOR` was duplicated — RESOLVED in run 2 (run 2)

`secure/src/aa/userop.rs:72` and `proto/src/lib.rs:794` both
declared `EXECUTE_SELECTOR = [0x14, 0x44, 0x3c, 0x57]`. They agreed.
Run 2 PR 5.2 deleted the local const and added `pub use
pqsigner_proto::EXECUTE_SELECTOR;` to `aa/src/userop.rs`. Done.

### 4.6 `cargo check -p secure` without features fails informatively (run 1)

After Phase 2, `cargo build -p sphincs-tz-secure` (no flags, no
target) fails because `cortex_m_semihosting` is referenced
unconditionally somewhere in `secure/src/main.rs`. This is
pre-existing (not caused by the refactor), but the fence added in
Phase 2 would also fire on a real ARM build with no features. **Don't
be alarmed by an `unresolved import cortex_m_semihosting` error when
poking at the secure crate without a target.** Use
`--target thumbv8m.main-none-eabi --features ...` for real builds, or
`--no-default-features --features mock-se,debug-log,ui-semihosting
--tests` for host tests.

### 4.7 The `dual-se` flag composes; SE-axis fence handles this (run 1)

In `secure/Cargo.toml`: `dual-se = ["optiga-trust-m", "se050"]`. So
when `dual-se` is set, both component flags are also set. The pairwise
SE-axis `compile_error!`s in `nsc/mod.rs` are *only* between mock-se ×
real SEs and tropic01-se × any real SE. The `optiga-trust-m + se050`
combo is **expected** (it's exactly what `dual-se` produces) and is
NOT fenced.

Phase 8 PR 2's cross-axis fences must respect this: the
`secure-element-dual` axis flag implies both component flags, and
the fence cannot fire on the implication.

### 4.8 Default-feature flip required Makefile and CI updates (run 1)

`secure/Cargo.toml` `default = []` → must pass
`--no-default-features --features ...` everywhere. Updated:

- `Makefile` `test-unit:` recipe (and run 2 added `pqsigner-tx-core`,
  `pqsigner-aa`, `pqsigner-domain`, `pqsigner-tx` test runs).
- (`.github/workflows/rust.yml` `test-secure-host` job was authored
  but not committed; still pending under Phase 1).

If you add a new `make` recipe or CI job that touches the secure
crate, **you must pass explicit features** or it'll fail at the
`compile_error!` "must select one UI backend" / "must select one SE
backend" gates.

### 4.9 The drift detector exists but isn't enforced (run 1)

After Phase 4 the `pqsigner-xtask gen-solidity-constants --check`
subcommand exists and works. **If you edit a `pub const` in
`pqsigner-proto`, you MUST also run `cargo run -p pqsigner-xtask --
gen-solidity-constants` and commit the regenerated
`PqsignerProto.sol` in the same PR.** Until Phase 1 (CI) lands, this
is a discipline gate, not an automated one. Add it to PR review
checklists.

### 4.10 `zk-test` master had a stale path (run 1)

Pre-existing on master: `zk-test/src/main.rs:16` referenced
`../../secure/src/zk/poseidon_constants.rs` but the file is at
`../../secure/src/zk/generated/poseidon_constants.rs`. Fixed in run
1 as a drive-by because CI now exercises the workspace and would
fail. **If you're rebasing this work on a newer master, check that
this fix is still applicable.**

### 4.11 `MockSecureElement::is_provisioned()` has a too-small read buffer (run 2)

`secure/src/secure_element.rs:240`-style `is_provisioned()` uses a
128-byte read buffer to probe `RMEM_ENCRYPTED_ENTROPY` (60 B, fits),
`RMEM_PIN_STATE` (481 B, **does not fit**), and `RMEM_VERIFYING_KEY`
(32 B, fits). The PIN_STATE read fails with
`SeError::InvalidParameter`, so `is_provisioned()` returns `false`
even on a freshly-provisioned mock. Nothing in the production path
relies on this for the mock (real backends override it correctly),
but the Phase 10 PR D `provision_populates_slots` host test had to
work around it by probing slots directly. Fix at leisure — bump the
buffer to `PIN_STATE_MAX_LEN = 481` or change the contract to "slot
occupied" rather than "fully readable".

### 4.12 Adding a new workspace member needs a lockfile refresh (run 2)

`make test-unit` runs `cargo test --locked`, which refuses to update
the lockfile. After adding a new workspace member, **run any cargo
command without `--locked` first** (e.g. `cargo check -p
new-crate`) so the lockfile updates. Then `make test-unit` can
proceed.

### 4.13 `secure/src/nsc/ns_ptr.rs` host tests are dormant (run 2)

The `nsc` module is `#[cfg(not(test))]`-gated in
`secure/src/main.rs:91`, so the unit tests inside `ns_ptr.rs` never
run during `cargo test`. The tests are still useful as documentation;
they activate when Phase 7 lifts that gate (or when `ns_ptr` moves
outside `nsc`). Same applies to any `#[cfg(test)] mod tests` block
added inside `nsc/`.

### 4.14 The five-axis aliases in Phase 8 PR 1 are additive only (run 2)

No `compile_error!` enforces "exactly one platform axis flag" yet.
The legacy flags retain the existing build.rs / `nsc/mod.rs` fences.
Phase 8 PR 2 lands the cross-axis enforcement after every Makefile
recipe has been flipped to use the new axis names.

### 4.15 `pqsigner-tx` depends on `sphincs-tz-shared` for `db_format::*` (run 2)

`pqsigner-tx`'s `names/bundle.rs` and `selectors/bundle.rs` import
`sphincs_tz_shared::db_format::{NAMES_MAX_LEN, NAMES_WILDCARD_CHAIN_ID,
SELECTOR_TEXT_SIG_MAX_LEN}`. When `sphincs-tz-shared` is dissolved
in Phase 11, those constants either move into `pqsigner-proto`
(cleanest) or directly into `pqsigner-tx`. Either is straightforward
because the constants are leaf-imports — no other Rust code depends
on them inside `pqsigner-tx`'s callers.

Note that `db_format` is also used by `nonsecure/`, `dbgen/`, and
`secure/src/zk/`, so when it moves, all four import sites update.

### 4.16 `cfg-feature` density grew slightly across run 2 (run 2)

Baseline (audit time): **291** sites of `cfg(feature` in
`secure/src/`. After run 2: **294**. The +3 came from the
production-fence `compile_error!` fence and a few aliases. Phase 7
target is **<80**.

### 4.17 `cmd_sign_userop.rs` is unchanged at 1241 LOC (run 2)

Phase 9 not started. The file's complexity (FI guards, error
reporting, intermixed parse/derive/sign state) makes any partial
extraction leave the file in an awkward halfway state, so run 2
deferred it entirely rather than do a token decomposition. The
right path is the full 4-PR sequence (§3.6).

### 4.18 `pqsigner-hal` trait crate is unused so far (run 2)

PR 1 of Phase 6 lands the trait definitions but no impl crate has
been built yet. The trait surface is the **specification** — anyone
adding a new peripheral or a new MCU port should match the
signatures verbatim so the eventual cfg→trait migration is a
name-change-only diff. Until PR 2 lands, the existing `secure/src/hw/*`
drivers continue to be called via direct paths.

### 4.19 Two run-1-and-run-2-compatible domain reductions (run 2)

A few `pub use sphincs_tz_shared::*;` re-exports in `aa/src/userop.rs`
were collapsed to `pub use pqsigner_proto::*;` directly. Both work
identically (sphincs-tz-shared is a re-export shim over
pqsigner-proto), but the proto-direct form is more honest about
where the constants live. When a future PR removes
`sphincs-tz-shared` entirely, those re-exports don't have to change.

---

## 5. First actions for the next session

In this order:

1. **Read** §1, §2, §3, §4 of this doc. The plan file is still
   authoritative for design; this doc supplements with execution
   context.

2. **Re-run the verification gates** (§2.4) to confirm the tree is
   still green. If anything is red, the working tree may have been
   committed or a dependency moved on master:
   ```bash
   make test-unit
   make test-solidity
   cargo run -q -p pqsigner-xtask -- gen-solidity-constants --check \
     | diff - contracts/smart-wallet/src/generated/PqsignerProto.sol
   ```

3. **Decide whether to commit run 2's dirty tree** (§2.5). Default
   approach: ask the user. Bundle into one PR is fine; per-phase
   commits are fine too.

4. **Pick up at Phase 6 PR 2** (move `secure/src/hw/*` except
   `secret_keys.rs` into `hal-stm32u5/`). The trait crate (`hal/`)
   is already in place — PR 2 is a verbatim file relocation +
   `Cargo.toml` boilerplate. Bench-board reproducibility check
   (`make verify-repro`) is the gate.

5. **Phase 6 PRs 3–4** follow immediately. PR 4 wires a `Platform`
   selector into a new `secure/src/platform.rs`.

6. **Then Phase 7** — the big migration. PR-by-PR, one cfg cluster
   at a time, reproducibility gate after each.

7. **Phase 8 PR 2** can run in parallel with Phase 7 PR 3 if desired
   — they touch disjoint files (Makefile + `Cargo.toml` axis section
   vs. `secure/src/`).

8. **Phase 9** (cmd_sign_userop split) is independent and can be
   slipped between Phase 7 PRs.

If Phase 6+7 takes longer than expected, **Phase 9** is the
highest-value cleanup you can land in isolation: it un-monolithises
the 1241-line sign handler without depending on any other phase.

If the user pushes back on commit strategy or wants a different
phase order, defer to them — the plan file is a guide, not a
contract.

---

## 6. Verification matrix

Apply to every commit in every phase:

| Gate | How |
|---|---|
| Workspace compiles (host) | `cargo build --workspace --exclude sphincs-tz-secure --exclude sphincs-tz-nonsecure --exclude pqsigner-fsbl` |
| Host tests | `make test-unit` (173 today; will rise as more crates extract) |
| Solidity tests | `make test-solidity` (49 today) |
| Solidity drift | `cargo run -p pqsigner-xtask -- gen-solidity-constants --check \| diff - contracts/smart-wallet/src/generated/PqsignerProto.sol` |
| Secure builds matrix | `cargo check -p sphincs-tz-secure --target thumbv8m.main-none-eabi` with each canonical feature combo (see §2.4) |
| QEMU e2e | `make e2e` |
| Reproducibility | `make verify-repro` |
| Production fence | Manual: try `cargo check -p sphincs-tz-secure --release --target thumbv8m.main-none-eabi --no-default-features --features stm32u585,dual-se,ui-oled,$X` for each forbidden $X — must trigger `compile_error!`. Phase 1 CI will automate this. |
| No CFG regression | `grep -rn "cfg(feature" secure/src \| wc -l` ≤ baseline (294 today; target <80 after Phase 7) |
| No new heap | `cargo bloat -p sphincs-tz-secure` shows zero `alloc::*` |
| Hardware (if available) | `make test-key-speed`, `make e2e-hw`, `make pin-gate-hw-counter-e2e`, `make pin-gate-wipe-e2e`, `make optiga-hw-counter-e2e` |

---

## 7. Cross-cutting quality bars (from the plan)

Applies to every PR in every remaining phase:

- **No new `cfg(feature = ...)` blocks** outside
  `secure/src/platform.rs` (Phase 6 lands this), the production-fence
  `compile_error!`s in `nsc/mod.rs`, and legitimate sub-feature gates
  (`optiga-hw-counter`, etc.). When a piece of code branches on
  backend, that's a missed trait.
- **No new heap usage.** `#![no_std]`, no `alloc`. Stack-only.
- **Every secret type is `ZeroizeOnDrop` and `!Copy + !Clone`.**
- **Every `unsafe` block has a `// SAFETY:` comment.**
- **Constant-time comparisons via `subtle`.**
- **`#[repr(C)]`** on every type that crosses S/NS or appears in a
  wire layout.
- **Reproducibility** — every commit must pass `make verify-repro`.
- **Trait surfaces match the `pqsigner-hal` spec verbatim** — so
  Phase 7's cfg→trait migration is a name-change-only diff.

---

## 8. Risks to watch

| Risk | Mitigation |
|---|---|
| HAL trait migration silently breaks an FI-hardened path | Phase 7 PR-by-PR with reproducibility gate. The C10 verify-before-release double-check stays in `secure/src/crypto.rs` (it depends on `crate::fi`), NOT moved into the trait crate. |
| `pqsigner-proto` typo ships to Solidity | Phase 4 codegen drift detector is on. Verified to fire when Rust and Solidity drift. |
| Feature-axis flip miscompiles a make recipe | Phase 8 PR 1 lands aliases (no behaviour change). Each Makefile flip in PR 2 is one recipe at a time; bench-board verification gates each flip. |
| `cmd_sign_userop` decomposition leaves an orphaned trailer-parser | Baseline e2e includes every TxKind variant; Phase 9 integration test asserts each variant still passes byte-equal. |
| Reproducibility regression from unstable iteration order | `make verify-repro` is a CI gate from Phase 1 onward. |
| Mock-SE behaviour drifts from real SE | Phase 10 PR D's host tests pin the mock's brick path; expand whenever a new real-SE behaviour needs host coverage. |
| `is_provisioned()` quirk masks a real provisioning failure | §4.11 — fix the buffer size, OR migrate callers to the slot-probe pattern from `provision_populates_slots`. |

---

## 9. Out of scope (entire plan)

These came up during the audit but are independent work tracks:

- **GTZC2_TZSC base-address discovery** (`secure/src/sau.rs:95–102`).
  Bring-up regression of invariant #4 in CLAUDE.md. Separate hardware
  investigation.
- **ML-KEM-1024 inner wrap** for SE channels. Separate cryptographic
  work, listed as "NOT STARTED" in CLAUDE.md Tier 2.
- **Production OTP burn / RDP-2 lockdown / WRP1A FSBL freeze.**
  Pre-ship validation work, separate checklist.
- **Solidity contract restructuring** beyond importing the generated
  constants. The contracts are small, immutable post-launch, and
  currently fine.
- **Deeper Solidity ↔ Rust integration tests** (sign in Rust, verify
  via Foundry against the *whole* `validateUserOp`, not just the
  verifier). Worth doing eventually but not part of this refactor.
- **`sphincs-tz-shared` dissolution** — the shim still hosts the
  `apdu_framing` and `db_format` modules. When those get a new home
  (Phase 11 or a separate cleanup), the shim itself goes away. Until
  then, depending on it from `pqsigner-tx` is fine.

---

## 10. Single-line summary

> Two execution runs landed Phases 0+2+3+4+5(partial)+6 PR 1+8 PR 1+
> 10 A/B/D/E + Phase 11 partial. Pure-logic IS extracted (`pqsigner-
> proto`/`-tx-core`/`-aa`/`-domain`/`-tx`); HAL trait surface IS
> defined (`pqsigner-hal` PR 1). The big architectural work (Phase 6
> PRs 2-4 HAL impls + Phase 7 cfg→trait migration) and the
> 1241-line `cmd_sign_userop.rs` decomposition (Phase 9) remain. CI
> matrix (Phase 1) is gated on user sign-off. Plan file is the
> design spec; this doc is the execution map. Pick up at Phase 6
> PR 2; verification gates at §2.4.
