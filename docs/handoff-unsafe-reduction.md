# Handoff — `unsafe` reduction (in progress)

> **Read order:** §1 (what's landed) → §2 (the pattern) → §3 (queue) →
> §4 (categories that can't shrink) → §5 (first action).
>
> Started 2026-05-07. Phase 1 + 2 are merged; Phase 3 is a single-file
> proof-of-concept (`hw/hash.rs`). The rest of the per-peripheral
> migrations are the work this handoff describes.

---

## 1. What's landed

### 1.1 Phase 1 — outright deletions (−21 unsafe)

| Change | Count | Mechanism |
|---|---|---|
| `core::str::from_utf8_unchecked` on ASCII-by-construction buffers | 19 | Replaced with `crate::ui::ascii_str(buf) -> &str` (calls `from_utf8(...).unwrap_or("?")`; validator is O(≤64 B), negligible vs. the OLED I2C flush that follows). Helper lives in `secure/src/ui/mod.rs`. |
| `unsafe impl Send/Sync` on `Stm32U5UsbOtgFs` | 2 | The struct is a unit ZST → `Send + Sync` are auto-derived; the `unsafe impl` lines were redundant. `nonsecure/src/usb/mod.rs`. |

### 1.2 Phase 3 — MMIO encapsulation, proof-of-concept

New module `secure/src/hw/mmio.rs` exposes typed register handles:

```rust
pub struct Reg32 { addr: *mut u32 }
impl Reg32 {
    pub const unsafe fn new(addr: u32) -> Self;     // construct once
    pub fn read(self) -> u32;                       // safe
    pub fn write(self, v: u32);                     // safe
    pub fn modify(self, f: impl FnOnce(u32) -> u32);// safe
    pub fn set_bits(self, mask: u32);               // safe
    pub fn clear_bits(self, mask: u32);             // safe
}
pub struct RoReg32 { addr: *const u32 }
impl RoReg32 {
    pub const unsafe fn new(addr: u32) -> Self;
    pub fn read(self) -> u32;
    pub unsafe fn read_at(self, offset: usize) -> u32;  // contiguous bank
}
```

`secure/src/hw/hash.rs` migrated as the reference implementation. Result:

- 5 `unsafe fn` → 3 (`wait_ready`, `write_word`, `debug_log_safe`,
  most of `init_clock`'s body became safe).
- ~25 implicit unsafe ops (covered by the old `unsafe fn` umbrellas)
  → 7 explicitly-annotated tight `unsafe { }` blocks, each with a
  `// SAFETY:` comment.
- All MMIO reads/writes inside the file are now safe method calls.
- `#![deny(unsafe_op_in_unsafe_fn)]` (per `CLAUDE.md`) is now properly
  respected in this file — previously it was silently bypassed by
  wholesale `unsafe fn` body coverage.

**Read `secure/src/hw/hash.rs` end-to-end before starting the next
peripheral** — it's the canonical example of the pattern.

### 1.3 Documentation

- `CLAUDE.md` Code Conventions: added an `unsafe` taxonomy line
  listing the five irreducible categories and pointing at
  `hw::mmio::{Reg32, RoReg32}` as the avoidable case.
- `CLAUDE.md` File Map: added `secure/src/hw/mmio.rs` row.

---

## 2. The migration pattern

For each peripheral driver under `secure/src/hw/` (and similar register-
heavy code under `secure/src/optiga/`, `secure/src/se050/`):

### 2.1 Recipe

1. **Identify register addresses.** Search for `*mut u32`, `*const u32`,
   `read_volatile`, `write_volatile` in the file.

2. **Build a `Regs` struct.** One field per register, typed as
   `Reg32` / `RoReg32`. Field names should match the datasheet
   (lowercase, e.g. `cr`, `sr`, `dr`, `cfgr1`).

3. **Bind once at module scope** with a single `unsafe { ... }` block:
   ```rust
   const REG: FooRegs = unsafe {
       FooRegs {
           cr: Reg32::new(FOO_BASE + 0x00),
           sr: Reg32::new(FOO_BASE + 0x04),
           ...
       }
   };
   ```
   This is **the only `unsafe` block** for register addresses in the
   whole file. The `// SAFETY:` comment goes here, once.

4. **Replace each access** with the safe method form:
   - `read_volatile(FOO_CR)` → `REG.cr.read()`
   - `write_volatile(FOO_CR, v)` → `REG.cr.write(v)`
   - `let x = read_volatile(FOO_CR); write_volatile(FOO_CR, x | M)` →
     `REG.cr.set_bits(M)`
   - `let x = read_volatile(FOO_CR); write_volatile(FOO_CR, x & !M)` →
     `REG.cr.clear_bits(M)`
   - `let x = read_volatile(FOO_CR); write_volatile(FOO_CR, f(x))` →
     `REG.cr.modify(f)`

5. **Drop `unsafe fn` markers** from helpers whose bodies are now
   register-touch-free safe code (`wait_ready`-style polling loops,
   bit-manipulation helpers). The marker stays only when the function
   has a real precondition (e.g. "must call after `rcc::init`",
   "touches `static mut`", FFI ABI).

6. **Build both targets.** Host tests AND the firmware target:
   ```
   cargo test -p sphincs-tz-secure --tests
   cargo check -p sphincs-tz-secure --target thumbv8m.main-none-eabi \
       --features stm32u585,ui-oled,dual-se,hw-sha256
   ```

### 2.2 Footguns

- **Bit-banding / atomic-set registers (BSRR, BCRR style).** Wrap them
  in their own typed accessor (`pub fn set(self, mask)` that does
  `self.write(mask)` rather than read-modify-write). Don't use
  `set_bits` on a BSRR-style register — you'd be writing 0s to bits
  you wanted to leave alone.
- **Reserved-bit-respecting writes.** STM32 RM often says "writes to
  reserved bits must preserve the reset value." Use `modify` with an
  explicit `reset_value | (data & mask)` to be safe.
- **Word-alignment.** `Reg32::new` does **not** check alignment.
  All STM32 peripherals are 4-byte-aligned by spec; if you're touching
  a packed peripheral RAM region (USB OTG FIFO, e.g.), use the
  peripheral's own typed wrapper, not `Reg32`.
- **Volatile across DMA.** DMA descriptors and shared buffers need
  more than `volatile` — they need memory barriers and careful
  lifetime management. **Don't** wrap DMA memory in `Reg32`; keep
  those drivers' existing structures.
- **Static mut still needs `unsafe`.** Several drivers (`hash.rs`'s
  4-byte merge buffer, `consumption_mask` PWM RNG state) keep a
  `static mut` for streaming state. That stays unsafe; the goal is
  to make the surrounding register access safe, not to remove all
  `unsafe`.

### 2.3 What "done" looks like for a single file

Compare against `hw/hash.rs`:

- Module-level: exactly one `unsafe { Regs { ... } }` block.
- No remaining `read_volatile` / `write_volatile` calls.
- `// SAFETY:` comment on every remaining `unsafe { }` block, each
  scoped to a single op (FFI ptr deref, `static mut` access,
  contiguous-bank `read_at`).
- `unsafe fn` markers only on functions with a documented precondition
  in a `# Safety` doc-comment.

---

## 3. Migration queue (priority order)

Each row is one file. The "current" column is grep'd token count of
"unsafe" — a rough proxy for how much work is involved. The "expected"
column is where the file lands after the pattern is applied.

| Priority | File | Current | Expected | Notes |
|---|---|---|---|---|
| **P1** | `secure/src/hw/flash.rs` | 58 | ~10 | Highest impact. Bank-2 raw writes, page-124 attempt counter, ICACHE invalidate. ICACHE writes need a barrier, not just volatile — keep that detail. The flash unlock sequence is its own state machine; don't rewrap *that*, just the register reads inside it. |
| **P1** | `secure/src/hw/spi.rs` | 10 | ~3 | SPI for Tropic01. `transfer_inplace` does many register touches per byte; this one will get the cleanest `before/after` story. |
| **P1** | `secure/src/hw/saes.rs` | 7 (post-Phase-1) | ~2 | SAES driver. Already used as the Tier-1 KDF; the on-chain SAES self-test (`make saes-self-test-hw`) is the regression check. |
| **P2** | `secure/src/hw/pka.rs` | 9 | ~2 | PKA accelerator under `pka-accel`. Smaller register set than SAES. |
| **P2** | `secure/src/hw/otp.rs` | 16 | ~5 | OTP read/program. Programming is one-way per word; **do not** wrap programming in a "safe" method that hides which writes are committing — keep the unsafe at the program-word level for visibility. |
| **P2** | `secure/src/hw/boot_state.rs` | 8 | ~3 | Try-once / active-slot tracking via flash. |
| **P3** | `secure/src/hw/usb_hw.rs` | (small, check) | minimal | DWC2 register block. Cross-check with `nonsecure/src/usb/mod.rs` for the NS-side mirror. |
| **P3** | `secure/src/hw/rcc.rs` | (check) | minimal | Clock tree. Touched once at boot; low ROI but easy. |
| **P3** | `secure/src/hw/rng.rs` | (check) | minimal | TRNG. Polled register read. Low ROI. |
| **P3** | `secure/src/hw/uart.rs` | (check) | minimal | USART1 VCP. Touched only under `uart-console`. |
| **P3** | `secure/src/hw/consumption_mask.rs` | 7 | ~2 | TIM2 CH1 PWM. |
| **P3** | `secure/src/hw/buttons.rs` | 6 | ~2 | GPIO + EXTI. |
| **P3** | `secure/src/hw/i2c_hw.rs`, `secure/src/hw/spi_hw.rs` | (check) | minimal | Bring-up shims — if they're already mostly safe, skip. |

### 3.1 Non-`hw/` files in the top-30

These have unsafe but it's mostly **not** MMIO and the `mmio` pattern
won't help them. Different work, lower priority:

| File | Current | Why it's there | Reduction strategy |
|---|---|---|---|
| `secure/src/main.rs` | 45 | SAU/GTZC config, vector relocation, NS branch — all one-shot boot operations. | Wrap the SCB/SAU/GTZC blocks in typed register handles (the same `Reg32` pattern works). Estimated reduction: 45 → 15. |
| `secure/src/optiga/mod.rs` | 30 | I2C MMIO + Shielded Connection buffers. | I2C registers can use `mmio`. Shielded Connection buffers are NOT MMIO — leave alone. |
| `nonsecure/src/nsc_api.rs` | 28 | **Calls into S-world veneers.** Each NSC call is `unsafe extern "C"`. | **Cannot reduce.** TrustZone ABI mandate. |
| `nonsecure/src/usb/commands.rs` | 27 | USB HID buffer aliasing, `static mut` response buffers. | Static-mut bookkeeping; replace with `cortex_m::singleton!` or `OnceCell`. Out of scope for this handoff. |
| `secure/src/nsc/mod.rs` | 24 | NS pointer validation + deref via `NsPtr<T>`. | **Cannot reduce.** The validation proof is the type; deref still needs `unsafe`. |
| `secure/src/se050/mod.rs` | 22 | SCP03 + I2C registers. | Same split as OPTIGA: I2C regs go through `mmio`, SCP03 buffers stay. |
| `secure/src/optiga/apdu.rs` | 19 | Mostly buffer manipulation with `static mut` IFX I2C frame storage. | Static-mut; out of scope. |
| `secure/src/offchain_state.rs` | 17 | Page-123 log-structured flash reads/writes. | Reads can wrap via `mmio` once `flash.rs` is migrated and exposes a `read_at(addr, buf)` helper. Writes stay `unsafe` (commit semantics). |
| `secure/src/se050/apdu.rs` | 16 | SCP03 buffer + APDU frame. | See se050/mod.rs. |
| `nonsecure/src/e2e_test.rs` | 16 | Calls NSC veneers. | Cannot reduce. |

### 3.2 Estimated total reduction if P1+P2 land

Rough budget assuming the pattern works as it did on `hash.rs`:

```
flash.rs:    58 → 10   (−48)
optiga/mod:  30 → 18   (−12, I2C only)
se050/mod:   22 → 14   (−8,  I2C only)
otp.rs:      16 →  5   (−11)
spi.rs:      10 →  3   (−7)
pka.rs:       9 →  2   (−7)
boot_state:   8 →  3   (−5)
saes.rs:      7 →  2   (−5)
main.rs:     45 → 15   (−30)
others:                (−15..30)
                       --------
                       ~−150 unsafe-token mentions
```

Combined with the −21 already landed in Phase 1+2, that's a realistic
ceiling of ~170 fewer unsafe sites in the firmware (current total: 644).

---

## 4. Categories that **cannot** shrink

Future maintainers may try to "clean these up." Don't.

1. **CMSE `unsafe extern "C"` veneers** — TrustZone ABI mandates the
   `cmse-nonsecure-entry` calling convention; the function signature
   is structurally `unsafe extern "C"`. ~19 fns in `secure/src/nsc/*`.
2. **NS pointer deref after `NsPtr<T>` validation** — the `NsPtr` /
   `ReadPtr` / `WritePtr` typestate proves the pointer is valid, but
   the actual deref still needs `unsafe`. The proof is in the *type*;
   removing the unsafe would defeat the lint that flags new
   unvalidated derefs. ~30 sites in `secure/src/nsc/`.
3. **`unsafe extern "C"` SHA-256 hooks** consumed by `sphincs-c10`
   under `hw-sha256` — these are FFI symbols by design.
4. **FI volatile read/write helpers** in `secure/src/fi.rs` — the
   `read_volatile` / `write_volatile` are the *point* of the file.
   They defeat the compiler's ability to fold double-checked verifies.
   Removing would defeat the FI hardening.
5. **`static mut` bookkeeping** — single-threaded, non-preemptive
   secure-world driver state (`hash.rs` 4-byte merge buffer, USB EP
   memory, response buffers). Replacement with `cortex_m::singleton!` /
   `critical_section::Mutex` is a separate refactor with its own ROI;
   not part of unsafe reduction.

When in doubt: if removing the `unsafe` would change the runtime
behavior or weaken a safety property, leave it.

---

## 5. First action

1. Read `secure/src/hw/hash.rs` end-to-end (before & after diff is in
   `git log`).
2. Read `secure/src/hw/mmio.rs`.
3. Pick **`secure/src/hw/spi.rs`** as the first migration — it's
   small (10 unsafe), self-contained, and the SPI path is exercised by
   `make e2e` (Tropic01 driver).
4. Apply the recipe from §2.1.
5. Run both build commands from §2.1 step 6.
6. Update this file's §3 table with the new actual count.
7. If the diff goes smoothly, do `flash.rs` next — that's the biggest
   single win in the queue.

If you hit a peripheral where the `Reg32` shape doesn't fit (DMA
descriptors, USB EP RAM, GPIO BSRR-style atomic sets), document the
shape in §2.2 and add a sibling type to `mmio.rs` rather than
inventing a one-off in the driver.

---

## 6. Verification harness

After each peripheral migration:

```
# host tests
cargo test -p sphincs-tz-secure --tests --release

# both build configs
cargo check -p sphincs-tz-secure --target thumbv8m.main-none-eabi \
    --features stm32u585,ui-oled,dual-se,hw-sha256
cargo check -p sphincs-tz-secure --target thumbv8m.main-none-eabi \
    --features stm32u585,ui-oled,dual-se,hw-sha256,saes-dhuk
```

For peripherals with hardware-only validation paths:

| File migrated | Hardware regression target |
|---|---|
| `flash.rs`, `boot_state.rs`, `otp.rs` | `make pin-gate-hw-counter-e2e`, `make pin-gate-wipe-e2e` |
| `saes.rs` | `make saes-self-test-hw` |
| `spi.rs` | `make e2e-hw` (Tropic01 path) |
| `hash.rs` (already done) | `make test-key-speed` — first-sign ≤ 3 s |

Don't merge a peripheral migration without running its hardware
regression target. The compiler can't catch a swapped register offset.
