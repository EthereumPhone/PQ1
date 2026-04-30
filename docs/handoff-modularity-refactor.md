# Handoff — Modularity Refactor (in progress)

> **Read order:** start with §1 (orientation), then §2 (current state),
> then jump to whichever phase you're picking up. The plan file
> (`/home/markus/.claude/plans/ok-make-a-plan-logical-lobster.md`) is
> still the authoritative spec; this doc supplements it with operational
> details discovered during the first execution run on 2026-04-30.
>
> **NOTE on Phase 1 (CI):** the original plan included an
> `.github/workflows/rust.yml` Rust CI matrix as Phase 1. It was
> authored, then **removed before commit at user's request** —
> shared CI infrastructure (third-party actions trust, runner-minute
> spend, root-level workflow surface that didn't exist before) is a
> different category of change than source-code refactoring and needs
> its own deliberate decision. **Phase 1 is therefore PENDING.** Every
> CI-style verification this doc references must currently be run
> manually via the `make` recipes listed in §5.

---

## 1. Orientation

### 1.1 Why this refactor exists

Audit on 2026-04-30 found that PQSigner OS has the right *boundaries*
(S↔NS split, dual-SE entropy XOR, on-chain `ISPHINCSVerifier`) but the
wrong *interfaces between them*: most polymorphism is `cfg`-gated rather
than trait-routed, the Rust↔Solidity wire format is duplicated by hand
on both sides without an IDL, and CI runs Foundry tests but no Rust tests.

Pre-production status (no devices shipped, no funded wallets) means
domain tags and CREATE2 salt preimages can still move without breaking
real users — this is the cheapest possible window.

### 1.2 Plan structure

`/home/markus/.claude/plans/ok-make-a-plan-logical-lobster.md` contains
12 phases (0–11 + optional 12). Phases are sequenced so each commit
leaves a green tree. Approved by the user. **Phases 0–4 + Phase 10
PR E landed in the first run; phases 5–11 are pending.**

### 1.3 Critical artifacts to read before continuing

| What | Where |
|---|---|
| The plan | `/home/markus/.claude/plans/ok-make-a-plan-logical-lobster.md` |
| Baseline metrics | `docs/work-todo.md` — section "Modularity refactor — baseline (2026-04-30)" |
| Completion log entry summarizing what landed | `docs/work-todo.md` — last row of "Completion Log" table |
| Project context (invariants, file map) | `CLAUDE.md` |
| Pre-production status (do/don't) | `~/.claude/projects/-home-markus-Documents-sphincs-rust/memory/project_pre_production_status.md` |

---

## 2. Current state (what landed on 2026-04-30)

### 2.1 New workspace members

- **`proto/`** — `pqsigner-proto` crate. Single source of truth for
  every protocol-level constant (CMD_*, NscStatus, wire sizes, region
  bounds, domain tags, on-chain caps). `no_std`, zero deps. Today it's
  a single `lib.rs` mirroring the original `shared/src/lib.rs` content
  plus the four constants that previously lived only on the Solidity
  side or in per-file Rust consts (`MAX_BOOTSTRAP_USES`,
  `OWNER_BYTES_LEN`, `FACTORY_ADD_SLOT_DOMAIN`, `EXECUTE_SELECTOR`).
  Plus `CMD_BASE_*` range markers and a `const _: () = { … }`
  compile-time CMD-collision check.

- **`xtask/`** — `pqsigner-xtask` host-only binary. Subcommand
  `gen-solidity-constants` renders
  `contracts/smart-wallet/src/generated/PqsignerProto.sol` from
  `pqsigner-proto`'s public consts. `--check` mode emits to stdout for
  CI drift detection.

- **`contracts/smart-wallet/src/generated/PqsignerProto.sol`** —
  AUTO-GENERATED Solidity library imported by `PQSmartWallet`,
  `PQSmartWalletFactory`, `PQMultiOwnable`. Source of truth is Rust;
  CI fails on drift.

- *(removed — see top-of-doc note)* `.github/workflows/rust.yml` was
  drafted as Phase 1 but pulled before commit. Until Phase 1 actually
  lands, every "CI does X" reference below should be read as "manual
  `make` recipe does X today; Phase 1 will automate it."

### 2.2 Files in the landed commit

```
A proto/Cargo.toml                                  # new pqsigner-proto crate
A proto/src/lib.rs                                  # IDL constants + CMD-collision check
A xtask/Cargo.toml                                  # new pqsigner-xtask crate
A xtask/src/main.rs                                 # gen-solidity-constants subcommand
A contracts/smart-wallet/src/generated/PqsignerProto.sol  # auto-generated
A docs/handoff-modularity-refactor.md               # this doc
M Cargo.lock
M Cargo.toml                                        # added proto + xtask members, pqsigner-proto workspace dep
M Makefile                                          # test-unit now passes explicit features
M contracts/smart-wallet/src/PQMultiOwnable.sol     # imports PqsignerProto.OWNER_BYTES_LEN
M contracts/smart-wallet/src/PQSmartWallet.sol      # imports PqsignerProto.{C10_SIG_LEN, MAX_BOOTSTRAP_USES, MAX_SLOT_USES}
M contracts/smart-wallet/src/PQSmartWalletFactory.sol  # imports PqsignerProto.FACTORY_ADD_SLOT_DOMAIN
M docs/work-todo.md                                 # baseline + completion log entry
M secure/Cargo.toml                                 # default = []
M secure/src/nsc/mod.rs                             # compile_error fence expanded: ui-capture, debug-log, UI/SE axis pairs
M shared/Cargo.toml                                 # depends on pqsigner-proto, forwards stm32u585 feature
M shared/src/lib.rs                                 # rewritten as `pub use pqsigner_proto::*;` re-export shim
M zk-test/src/main.rs                               # drive-by fix: stale path to poseidon_constants.rs
```

### 2.3 Verification gates — all green

```bash
make test-unit                        # 167/167 host tests
make test-solidity                    # 49/49 Solidity tests
cargo run -q -p pqsigner-xtask -- gen-solidity-constants --check \
  | diff - contracts/smart-wallet/src/generated/PqsignerProto.sol   # no drift
cargo check -p sphincs-tz-secure --target thumbv8m.main-none-eabi \
  --no-default-features \
  --features dual-se,ui-oled,stm32u585,debug-log,e2e-test,otp-hardcoded-master-key   # canonical hw bringup compiles
cargo check -p sphincs-tz-secure --no-default-features \
  --features mock-se,debug-log,ui-semihosting --tests                # canonical QEMU compiles
```

### 2.4 No commits made

The user did not request a commit. The working tree is dirty with the
above files. **First action for the next session: ask the user whether
to commit Phases 0–4 as one bundled PR before continuing into Phase 5,
or to land each remaining phase as its own PR atop the dirty tree.**

---

## 3. Gotchas learned during execution

These contradict or refine details in the plan and the original audit.
Read them before continuing.

### 3.1 Feature-flag count was 50, not 95

The audit report quoted "95+ feature flags". The actual count via
`awk '/^\[features\]/{f=1;next}/^\[/{f=0}f && /^[a-z][a-z0-9-]* *=/{c++}END{print c}'`
on `secure/Cargo.toml` is **50**. The cfg *density* across `secure/src/`
is **291**. So:
- "95→5" target in Phase 8 is more like **50→25–35**.
- The pressure point is cfg density inside drivers (50 in
  `se050/mod.rs`), not flag count.

### 3.2 `secure/build.rs` already enforces UI exclusivity

`secure/build.rs:20–25` panics if two of `ui-semihosting/ui-oled/ui-noop`
are simultaneously set, and panics if zero are set. This was unknown to
the audit. The Rust-side `compile_error!` blocks I added in
`secure/src/nsc/mod.rs` are not redundant (they fire on host targets
that don't compile build.rs), but **don't be surprised when the build
fails with a panic from build.rs before the Rust-side fence triggers.**

### 3.3 `WalletStore` is one of two SE traits

The audit reported one `WalletStore` trait. There are actually two,
both in `secure/src/secure_element.rs`:

- **`SecureElement`** (line 29) — low-level r-mem + MAC-and-Destroy.
  Implemented by backends with MACD-capable storage: `MockSecureElement`,
  `Tropic01SecureElement`. NOT implemented by SE050 (uses hardware
  UserID PIN gating instead) or OPTIGA Trust M.
- **`WalletStore`** (line 40) — high-level wallet ops (provision,
  unlock, read entropy/VK, attempt counter). Implemented by every
  backend.

When designing `pqsigner-hal` in Phase 6, mirror this two-layer pattern:
the `SecureElement`-equivalent low-level slot trait is a *capability*
that not every HAL impl provides; the high-level wallet-store trait is
universal.

### 3.4 `tx/` is more entangled than the audit said

The audit said `tx/` is pure-logic with zero hardware deps. That's
*almost* true — `tx/eip1559.rs`, `tx/hash.rs`, `tx/rlp.rs` are pure.
But the rest cross-imports:
- `tx/typed_call/*` and `tx/eip712/*` use `crate::erc20::*`,
  `crate::names::*`, `crate::selectors::*`
- `tx/display/*` uses `crate::ui::*`

So Phase 5's "extract `pqsigner-tx`" is not a single move. The clean
partition is:
- `pqsigner-tx-core` (eip1559/hash/rlp) — truly pure, no deps beyond
  `pqsigner-proto` and crypto crates.
- `pqsigner-tx` (typed_call/eip712) — needs erc20, names, selectors
  extracted alongside or stub traits passed in.
- `tx/display/*` stays in `secure/` (depends on `crate::ui`).

`aa/` is genuinely pure but depends on `tx::eip1559`/`tx::hash`. So
Phase 5 PR ordering should be:
1. `pqsigner-tx-core` first
2. `pqsigner-aa` second (depends on tx-core)
3. `pqsigner-tx` and `pqsigner-domain` after — these need erc20/names/
   selectors first or trait stubs for them.

### 3.5 `EXECUTE_SELECTOR` is duplicated

`secure/src/aa/userop.rs:72` and `proto/src/lib.rs:794` both declare
`EXECUTE_SELECTOR = [0x14, 0x44, 0x3c, 0x57]`. They currently agree.
**Phase 5 PR 2 (extracting `pqsigner-aa`) MUST resolve this** by
deleting the local const and importing from `pqsigner-proto` (or, when
aa moves to its own crate, importing from there). Until then, drift is
possible.

### 3.6 `cargo check -p secure` without features fails informatively now

After Phase 2, `cargo build -p sphincs-tz-secure` (no flags, no target)
fails because `cortex_m_semihosting` is referenced unconditionally
somewhere in `secure/src/main.rs`. This is pre-existing (not caused by
my changes), but the fence I added would also fire on a real ARM build
with no features. **Don't be alarmed by an `unresolved import
cortex_m_semihosting` error when poking at the secure crate without a
target.** Use `--target thumbv8m.main-none-eabi --features ...` for
real builds, or `--no-default-features --features mock-se,debug-log,
ui-semihosting --tests` for host tests.

### 3.7 The `dual-se` flag composes; SE-axis fence handles this

In `secure/Cargo.toml`: `dual-se = ["optiga-trust-m", "se050"]`. So
when `dual-se` is set, both component flags are also set. The pairwise
SE-axis `compile_error!`s in `nsc/mod.rs` are *only* between mock-se ×
real SEs and tropic01-se × any real SE. The `optiga-trust-m + se050`
combo is **expected** (it's exactly what `dual-se` produces) and is
NOT fenced.

### 3.8 Default-feature flip required Makefile and CI updates

`secure/Cargo.toml` `default = []` → must pass `--no-default-features
--features ...` everywhere. Updated:
- `Makefile` `test-unit:` recipe
- `.github/workflows/rust.yml` `test-secure-host` job

If you add a new `make` recipe or CI job that touches the secure crate,
**you must pass explicit features** or it'll fail at the
`compile_error!` "must select one UI backend" / "must select one SE
backend" gates.

### 3.9 The drift detector exists but isn't enforced (no CI yet)

After Phase 4 the `pqsigner-xtask gen-solidity-constants --check`
subcommand exists and works (run it locally to verify). **If you edit
a `pub const` in `pqsigner-proto`, you MUST also run
`cargo run -p pqsigner-xtask -- gen-solidity-constants` and commit
the regenerated `PqsignerProto.sol` in the same PR.** Until Phase 1
(CI) lands, this is a discipline gate, not an automated one. Add it
to PR review checklists.

### 3.10 `zk-test` master had a stale path

Pre-existing on master: `zk-test/src/main.rs:16` referenced
`../../secure/src/zk/poseidon_constants.rs` but the file is at
`../../secure/src/zk/generated/poseidon_constants.rs`. Fixed in this
session as a drive-by because CI now exercises the workspace and would
fail. **If you're rebasing this work on a newer master, check that
this fix is still applicable.**

---

## 4. What's left — phase-by-phase handoff

Each subsection is self-contained: read it cold, get to work.

### 4.0 Phase 1 — Rust CI matrix (1 PR, deferred)

**Status: PENDING.** Authored on 2026-04-30, removed before commit at
the user's request because shared CI infrastructure is a different
trust category (third-party actions, runner-minute spend, root-level
workflow surface). Re-author when ready, with the user's explicit
sign-off on the actions list.

The original Phase 1 design is in
`/home/markus/.claude/plans/ok-make-a-plan-logical-lobster.md` §"Phase 1".
Key elements: fmt + clippy + host tests + 6-cell `cargo check` build
matrix + production-fence audit + QEMU `make e2e` + `make verify-repro`
+ Solidity (forge build/test/fmt/snapshot) + Solidity-constants drift
detector. The drift detector now has a working subcommand
(`pqsigner-xtask gen-solidity-constants --check`) so wiring it into
CI is one shell step.

Until Phase 1 lands, every "CI does X" line in this doc means "manual
`make` recipe does X today; CI will automate later".

### 4.1 Phase 5 — Extract `pqsigner-aa`, `pqsigner-tx-core`, `pqsigner-domain` (3–4 PRs)

**Goal.** Move pure-logic modules out of `secure/` so they can be
tested on host independently, depended on by `fwsign`, and shared with
future host-side reference signers.

**Revised PR ordering** (per §3.4 above):

#### PR 5.1 — `pqsigner-tx-core` first

Move only the truly-pure tx primitives:

- `secure/src/tx/eip1559.rs` → `tx-core/src/eip1559.rs`
- `secure/src/tx/hash.rs` → `tx-core/src/hash.rs`
- `secure/src/tx/rlp.rs` → `tx-core/src/rlp.rs`

New crate: `tx-core/Cargo.toml`, package `pqsigner-tx-core`, `no_std`,
deps: `pqsigner-proto`, `sha3`. Keep `secure/src/tx/mod.rs` as a
re-export shim:

```rust
// secure/src/tx/mod.rs
pub use pqsigner_tx_core::{eip1559, hash, rlp};
pub mod display;
pub mod eip712;
pub mod typed_call;
```

Verify: `make test-unit` and `make test-solidity` and the QEMU `cargo
check` matrix.

#### PR 5.2 — `pqsigner-aa` second

Move `secure/src/aa/{mod.rs, userop.rs, eip1271.rs}` to a new crate
`aa/Cargo.toml`, `pqsigner-aa`, deps: `pqsigner-proto`,
`pqsigner-tx-core`, `sha2`, `sha3`. Replace local `EXECUTE_SELECTOR`
with `pqsigner_proto::EXECUTE_SELECTOR` (resolves §3.5).

`secure/src/aa/mod.rs` becomes `pub use pqsigner_aa::*;`.

#### PR 5.3 — `pqsigner-domain` (crypto) next

Move `secure/src/crypto.rs` into a new `domain/` crate. Define a
`SecretKdf` trait so the dev-HKDF path and the production
`SAES-CMAC(DHUK)` path implement the same interface. The HW
implementation stays in `secure/src/hw/secret_keys.rs` until Phase 6.

Deps: `pqsigner-proto`, `pqsigner-bip39`, `sha2`, `hmac`, `aes`, `cmac`,
`subtle`, `zeroize`.

#### PR 5.4 — extract `erc20/`, `names/`, `selectors/`, then full `pqsigner-tx`

Big lift. `erc20/`, `names/`, `selectors/` are also pure-logic but
moderately interconnected. Once they're in their own crates, the
remaining `tx/typed_call/*` and `tx/eip712/*` can move into
`pqsigner-tx`.

**Defer `tx/display/*`** — it imports `crate::ui::*` and stays in
`secure/`. Eventually (Phase 10 PR A) `display/` takes a `&mut dyn Ui`
parameter; until then, leave it where it is.

**Tests to add** after each PR:
- `aa/tests/userop_hash_vectors.rs` — known-answer tests for
  `compute_user_op_hash` against three reference UserOps.
- `aa/tests/signature_wrapper_roundtrip.rs` — encode wrapper in Rust,
  decode in Rust, byte-equal.
- Move every existing `#[cfg(test)] mod tests` from the moved files
  into the new crates.

**Verification gate**: `make test-unit` passes (host count rises);
artifact sizes within ±1% of baseline.

### 4.2 Phase 6 — `pqsigner-hal` trait crate + `hal-stm32u5` + `hal-mock` (4 PRs)

**Goal.** Replace `cfg`-only HAL polymorphism with traits so QEMU and
STM32 backends can coexist in the same binary, host tests can mock
peripherals, and porting to a backup MCU is trait-implementation work
rather than parallel branches.

Per §3.3, mirror the existing two-layer SE pattern:
- `pqsigner-hal` defines per-peripheral traits (`Rng`, `Sha256`,
  `Saes`, `Flash`, `Otp`, `BootState`, `Tamp`, `ConsumptionMask`,
  `I2cBus`, `SpiBus`, `Buttons`, `Uart`) + a `Platform` aggregate.
- `pqsigner-hal-stm32u5` moves every file from `secure/src/hw/*`
  EXCEPT `secret_keys.rs` (which has the `SecretKdf` trait wiring
  from Phase 5 PR 3).
- `pqsigner-hal-mock` provides `MockPlatform` for unit tests and
  `QemuPlatform` (semihosting RNG, software SHA256/AES, RAM-backed
  flash with monotonic-program/reset-on-erase semantics).

**Critical**: do not move `secret_keys.rs` to `hal-stm32u5/`. The
SAES-CMAC(DHUK) KDF needs a clean separation between "HAL primitive"
(SAES) and "domain logic" (KDF). The domain crate from Phase 5 PR 3
holds the KDF; `hal-stm32u5` exposes the SAES trait impl that the
domain crate consumes.

**Test landed in PR 4**: `secure/src/platform.rs` has only ONE
remaining `cfg(feature = "stm32u585")`:

```rust
#[cfg(feature = "stm32u585")]
pub type ActivePlatform = pqsigner_hal_stm32u5::Stm32U5Platform;
#[cfg(not(feature = "stm32u585"))]
pub type ActivePlatform = pqsigner_hal_mock::QemuPlatform;
```

Every other call site in `secure/src/` switches to `&mut impl Platform`
in Phase 7.

### 4.3 Phase 7 — Migrate `secure/src/` from `cfg` to trait dispatch (3 PRs)

**Goal.** Drop `cfg(feature = "stm32u585")` density from 291 to <80.

Order:
1. `secure/src/rng.rs`, `crypto.rs` callers, `secret_keys.rs` callers
   take `&mut impl Platform` / `&mut impl Rng` etc.
2. `secure/src/optiga/`, `se050/`, `tropic01_se.rs`, `dual_se.rs` take
   `&mut impl I2cBus` / `&mut impl SpiBus`. Per §3.4 of the audit, the
   50 cfg occurrences in `se050/mod.rs` and 36 in `optiga/mod.rs`
   should drop to <10 each. Remaining cfgs are legit feature gates
   (`optiga-hw-counter`, `optiga-no-shield`, etc.).
3. `secure/src/main.rs` boot flow: `let mut platform =
   ActivePlatform::init();` followed by stage-by-stage init. The
   phased-boot pattern (BootStage enum) lands in Phase 10 PR C; this
   PR just renames the existing flat init list.

**Verification gates**:
- `grep -rn "cfg(feature" secure/src | wc -l` ≤ 80 (was 291).
- `make verify-repro` still passes (artifact byte-equal).
- The QEMU `make e2e` smoketest still runs all TxKind variants.

### 4.4 Phase 8 — Feature-axis consolidation (2 PRs)

**Goal.** Reduce 50 ad-hoc flags to 5 orthogonal axes
(`platform`, `secure_element`, `ui`, `mode`, `accelerators`) plus
~10 sub-features. Mutual exclusivity enforced by `compile_error!`.

**PR ordering** (preserves green builds throughout):
1. **Add aliases** — declare new axis flags in `secure/Cargo.toml` as
   thin aliases over existing flags (`platform-stm32u585 = ["stm32u585"]`
   etc.). Behaviour-equivalent. Verify all Makefile recipes pass.
2. **Flip Makefile + delete legacy** — update every Makefile recipe to
   use new axis names, then delete the old flag aliases. Add the
   cross-axis `compile_error!`s. Update the
   `solidity-constants-in-sync` job's diff-target check.

**Pitfall**: the audit assumed the per-flag count was 95+; it's
actually 50 (per §3.1). The "95→5" target is more like "50→25–35"
once sub-features are accounted for.

### 4.5 Phase 9 — Decompose `cmd_sign_userop.rs` (4 PRs)

**Goal.** Split the 1241-line monolith at
`secure/src/nsc/cmd_sign_userop.rs` into 8 testable submodules at
`secure/src/nsc/sign_userop/{header,trailer,slot_keys,userop_digest,
execute_calldata,offchain_counter,wrapper_encode,output_assembly}.rs`.

Reference: the agent-produced outline (in the original audit) maps
which line ranges belong to which concern. The single `run()` function
goes from 1070 LOC to ~150 LOC of orchestration only.

PR ordering: header+trailer → slot_keys+userop_digest+execute_calldata →
offchain_counter+wrapper_encode+output_assembly → slim `run()`.

**Tests to add**: per-submodule golden vectors + a new
`secure/tests/sign_userop_roundtrip.rs` that provisions
`MockPlatform` + `MockSecureElement`, drives the full sign path, and
asserts byte-equal output across two invocations (determinism check).

### 4.6 Phase 10 — Polish (4 PRs remaining)

PR E (CMD-range constants + collision check) **landed in this run**.
Remaining:

#### PR A — `trait Ui` + axis enforcement

Define `pub trait Ui { fn draw_line(...); fn flush(); ... }` in
`secure/src/ui/mod.rs`. Every backend (`semihosting`, `oled`, `noop`,
`mirror`, `capture`) implements it. Per §3.2, **`secure/build.rs`
already panics** if 0 or ≥2 backends are set; the new trait makes
typo'd method signatures a compile error too.

#### PR B — `NsPtr<T>` typestate

New module `secure/src/nsc/ns_ptr.rs` with `NsPtr<T>` →
`validate_read()` → `ReadPtr<T>` (only thing with `Deref`). Migrate
every `cmd_*.rs` to take `NsPtr<T>` instead of `u32`. Forgetting to
validate becomes a type error. The existing `ptr_validate` module
stays as the implementation; only the public API changes.

#### PR C — Phased boot

Replace the flat init list at `secure/src/main.rs:356–605` with:

```rust
let mut platform = ActivePlatform::init();
platform.run_stage(BootStage::Clocks)?;
platform.run_stage(BootStage::TrustZone)?;
// ...
```

Requires Phase 6 (`Platform` trait exists).

#### PR D — Mock-SE realism

Add to `MockSecureElement` (`secure/src/secure_element.rs`):
- Persistent `wrong_attempts: u8` field; `unlock()` bumps it; locks at
  `MAX_ATTEMPTS = 10`; `factory_reset_admin` requires admin PIN check.
- `simulate_glitch()` API for FI-pattern unit tests.
- New `tests/mock_pin_lockout.rs` exercising the brick path on host.

This unblocks the brick-path test in `make pin-gate-wipe-e2e` running
on host instead of only real hardware.

### 4.7 Phase 11 — Doc cleanup (1 PR)

- Update CLAUDE.md "Key File Map" for the new crate layout.
- Replace every `sphincs_tz_shared` reference in docs with
  `pqsigner-proto` (or note the re-export shim continues to work).
- Update the "Architecture at a Glance" diagram to show
  `pqsigner-hal` trait dispatch.
- Add a "Testing matrix" section listing every gate.
- Add "Adding a peripheral / CMD / SE backend / UI backend" how-tos
  pointing at the right trait.
- Add an `xtask doc-check` subcommand that greps file paths from
  CLAUDE.md and fails if any is missing. Wire into CI.

### 4.8 Phase 12 (optional) — Domain-tag rename

**Pre-condition**: Phases 0–11 landed. User explicitly approves.

Rename `"sphincs-c6-v1"` → `"sphincs-c10-v1"` (and the `-acct` variant)
in one coordinated commit. Touches `pqsigner-domain/src/lib.rs`, every
e2e test fixture, the test-vector generator, every deployed-script-side
address constant.

**Output**: `docs/address-rename-2026-XX-XX.md` documenting the new
addresses every bench seed re-derives to.

---

## 5. Verification matrix

Apply to every commit in every phase:

| Gate | How |
|---|---|
| Workspace compiles (host) | `cargo build --workspace --exclude sphincs-tz-secure --exclude sphincs-tz-nonsecure --exclude pqsigner-fsbl` |
| Host tests | `make test-unit` (167 today, will rise as crates extract) |
| Solidity tests | `make test-solidity` (49 today) |
| Solidity drift | `cargo run -p pqsigner-xtask -- gen-solidity-constants --check \| diff - contracts/smart-wallet/src/generated/PqsignerProto.sol` |
| Secure builds matrix | The 6 `cargo check` cells in `.github/workflows/rust.yml` |
| QEMU e2e | `make e2e` |
| Reproducibility | `make verify-repro` |
| Production fence | Manual: try `cargo check -p sphincs-tz-secure --release --target thumbv8m.main-none-eabi --no-default-features --features stm32u585,dual-se,ui-oled,$X` for each forbidden $X — must trigger `compile_error!`. Phase 1 CI will automate this. |
| No CFG regression | `grep -rn "cfg(feature" secure/src \| wc -l` ≤ baseline (291 today; target <80 after Phase 7) |
| No new heap | `cargo bloat -p sphincs-tz-secure` shows zero `alloc::*` |
| Hardware (if available) | `make test-key-speed`, `make e2e-hw`, `make pin-gate-hw-counter-e2e`, `make pin-gate-wipe-e2e`, `make optiga-hw-counter-e2e` |

---

## 6. Cross-cutting quality bars (from the plan)

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

---

## 7. Risks to watch

| Risk | Mitigation |
|---|---|
| HAL trait migration silently breaks an FI-hardened path | Phase 7 PR-by-PR with reproducibility gate. The C10 verify-before-release double-check stays in `secure/`, NOT moved into `hal-mock`. |
| `pqsigner-proto` typo ships to Solidity | Phase 4 codegen drift detector is on. Verified to fire when Rust and Solidity drift. |
| Feature-axis flip miscompiles a make recipe | Phase 8 PR 1 lands aliases (no behaviour change). Each Makefile flip in PR 2 is one recipe at a time; CI watches. |
| `cmd_sign_userop` decomposition leaves an orphaned trailer-parser | Baseline e2e includes every TxKind variant; Phase 9 integration test asserts each variant still passes. |
| Reproducibility regression from unstable iteration order | `make verify-repro` is a CI gate from Phase 1 onward. |

---

## 8. Out of scope for the entire plan

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

---

## 9. First actions for the next session

In this order:

1. **Read** §1, §2, §3 of this doc. The plan file is still authoritative
   for design; this doc supplements with execution context.
2. **Re-run gates** to confirm the tree is still green:
   ```bash
   make test-unit
   make test-solidity
   cargo run -q -p pqsigner-xtask -- gen-solidity-constants --check \
     | diff - contracts/smart-wallet/src/generated/PqsignerProto.sol
   ```
4. **Pick up at Phase 5 PR 5.1** (extract `pqsigner-tx-core`). It's
   the smallest extraction with the cleanest dependency surface, and
   it unblocks Phase 5 PR 5.2 (`pqsigner-aa`).

If the user pushes back on commit strategy or wants a different phase
order, defer to them — the plan file is a guide, not a contract.

---

## 10. Single-line summary

> Phases 0–4 + Phase 10 PR E delivered the foundational layers
> (Rust CI, production fence, `pqsigner-proto` IDL crate, Solidity
> codegen, CMD-collision check). Phases 5–11 still pending; each is
> well-scoped and can land independently. Plan file is the design
> spec; this handoff is the execution map.
