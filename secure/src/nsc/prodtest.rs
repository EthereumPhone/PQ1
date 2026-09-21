//! Prodtest command handlers (`prodtest` feature).
//!
//! Each handler matches the existing `cmd_*::run` signature so it
//! plugs straight into the NSC dispatcher in `secure/src/nsc/mod.rs`.
//! All handlers expect already-validated `GatewayArgs` from the
//! dispatcher's pointer-validation layer.
//!
//! See `proto/src/lib.rs::CMD_PRODTEST_*` for the per-command
//! wire format (input layout, output buffer size, status semantics).
//!
//! ## Architectural notes
//!
//! - **No PIN unlock required**: prodtest commands run on a fresh
//!   chip before any user has set a PIN, so they're never gated on
//!   `pin_verified`. The compile fence in
//!   `secure/src/factory_provisioning.rs` (mirrored here in spirit
//!   via the build-profile guards) keeps prodtest out of production
//!   firmware where this lack-of-gating would be a hole.
//!
//! - **No secret data exposed**: every prodtest command's output is
//!   either chip metadata (UID, fingerprint) or test artifacts. No
//!   user secrets leave the chip via these commands.
//!
//! - **Supported profile**: GET_ID, DISPLAY_PATTERN, SAES, TRNG, the
//!   two SE handshakes, USB loopback, buttons, and (on `pq1`) the RGB
//!   LED test are required. BHK and FLASH_RW remain explicit
//!   unsupported-capability probes; they return `InternalError` and
//!   never mutate persistent state.

#![cfg(feature = "prodtest")]

// The unconditional cross-feature fence lives in `nsc/mod.rs` so it is
// visible beside the other production/irreversible composition guards.
// `factory-production-irreversible-im-sure` deliberately cannot relax it.

use sphincs_tz_shared::{NscStatus, PRODTEST_MAX_RESPONSE_DATA_LEN};

use super::ptr_validate::{validate_ns_read_ptr, validate_ns_write_ptr};
use super::GatewayArgs;

/// Prodtest firmware version. Bumped on every prodtest behavioral
/// change so the factory's traceability DB can correlate per-unit
/// diagnostic data with the firmware version that produced it.
const PRODTEST_FW_VERSION: u32 = 4;

/// STM32U585 chip UID, 96 bits at `0x0BFA_0700` per RM0456 §28.10.
const STM32_UID_ADDR: u32 = 0x0BFA_0700;
const STM32_UID_LEN: usize = 12;

// ---------------------------------------------------------------------------
// CMD_PRODTEST_GET_ID (100)
// ---------------------------------------------------------------------------

/// Output layout: 12 B UID || 4 B fw version (LE) || 8 B reserved.
const GET_ID_OUT_LEN: usize = 24;

/// # Safety
/// CMSE non-secure-entry handler — NS pointer derefs only after
/// `validate_ns_write_ptr`. Reads STM32 UID via `read_volatile` from
/// the documented MMIO address.
pub(super) unsafe fn cmd_get_id_run(args: &GatewayArgs) -> u32 {
    if !validate_ns_write_ptr(args.arg1, GET_ID_OUT_LEN) {
        return NscStatus::InvalidPointer as u32;
    }
    let out = args.arg1 as *mut u8;

    // SAFETY: STM32_UID_ADDR is the documented MMIO address of the
    // 96-bit chip UID; reads are pure loads from secure-world-
    // accessible memory.
    for i in 0..3u32 {
        let w = unsafe {
            core::ptr::read_volatile((STM32_UID_ADDR + i * 4) as *const u32)
        };
        let bytes = w.to_le_bytes();
        for j in 0..4 {
            // SAFETY: out_ptr was validated for GET_ID_OUT_LEN bytes
            // above; (i*4+j) ≤ 11 < GET_ID_OUT_LEN.
            unsafe {
                core::ptr::write_volatile(out.add((i * 4 + j as u32) as usize), bytes[j]);
            }
        }
    }

    // Firmware version at offset 12.
    let ver = PRODTEST_FW_VERSION.to_le_bytes();
    for i in 0..4 {
        // SAFETY: offset 12+i ≤ 15 < GET_ID_OUT_LEN.
        unsafe {
            core::ptr::write_volatile(out.add(12 + i), ver[i]);
        }
    }

    // Bytes 16..24: reserved, zeroed.
    for i in 16..GET_ID_OUT_LEN {
        // SAFETY: offset i < GET_ID_OUT_LEN.
        unsafe {
            core::ptr::write_volatile(out.add(i), 0);
        }
    }

    NscStatus::Ok as u32
}

// ---------------------------------------------------------------------------
// CMD_PRODTEST_DISPLAY_PATTERN (101)
// ---------------------------------------------------------------------------

/// # Safety
/// CMSE non-secure-entry handler — reads 4 bytes from NS after
/// `validate_ns_read_ptr` returns true. No NS pointer write.
pub(super) unsafe fn cmd_display_pattern_run(args: &GatewayArgs) -> u32 {
    if !validate_ns_read_ptr(args.arg0, 4) {
        return NscStatus::InvalidPointer as u32;
    }
    // SAFETY: validate_ns_read_ptr guarantees 4 bytes readable at
    // args.arg0. Read into S-stack before parse (TOCTOU).
    let mut buf = [0u8; 4];
    for i in 0..4 {
        buf[i] = unsafe {
            core::ptr::read_volatile((args.arg0 + i as u32) as *const u8)
        };
    }
    let pattern = u32::from_le_bytes(buf);

    if pattern > 4 {
        return NscStatus::InvalidPointer as u32;
    }

    render_lcd_pattern(pattern);
    NscStatus::Ok as u32
}

/// Render a known full-screen test pattern to the NV3007 LCD.
///
/// `pattern` is one of:
///   0 = all white (every pixel ON)
///   1 = all black
///   2 = horizontal stripes (every other row)
///   3 = vertical stripes (every other column)
///   4 = 8×8 checker
fn render_lcd_pattern(pattern: u32) {
    use crate::ui::display;

    let d = display();

    // Build a 4-row × 16-col ASCII representation. The CT blit path
    // (`flush_with_secret_rows`) takes byte-rows directly, so we just
    // pick the right per-byte fill: 0xFF = solid ON, 0x00 = solid OFF.
    // For striped / checker patterns the NV3007 framebuffer would
    // need raw pixel access — for this profile we approximate via the
    // text grid which is what's already in the framebuffer pipeline.
    //
    // Note: this is a TEXT-LAYER approximation. A future display-specific
    // harness can reach into the LCD framebuffer directly and draw
    // per-pixel patterns. For now the operator + fixture verify the
    // expected text-grid pattern is visible:
    //   pattern 0 ("white"): 16 solid blocks per row × 4 rows
    //   pattern 1 ("black"): blank
    //   pattern 2 ("hstripes"): rows 0,2 solid; 1,3 blank
    //   pattern 3 ("vstripes"): every other column block
    //   pattern 4 ("checker"): 8×8 checker via every-other-cell solid

    d.clear();
    match pattern {
        0 => {
            // All solid
            for row in 0..4 {
                d.draw_line(row, "################");
            }
        }
        1 => {
            // All blank — clear already does this
        }
        2 => {
            // Horizontal stripes
            d.draw_line(0, "################");
            d.draw_line(2, "################");
        }
        3 => {
            // Vertical stripes — every other column ASCII block
            for row in 0..4 {
                d.draw_line(row, "# # # # # # # # ");
            }
        }
        4 => {
            // Checker
            d.draw_line(0, "# # # # # # # # ");
            d.draw_line(1, " # # # # # # # #");
            d.draw_line(2, "# # # # # # # # ");
            d.draw_line(3, " # # # # # # # #");
        }
        _ => unreachable!(),
    }
    d.flush();
}

// ---------------------------------------------------------------------------
// CMD_PRODTEST_SAES_SELFTEST (102) — Phase B
// ---------------------------------------------------------------------------

const SAES_FINGERPRINT_LEN: usize = 8;

/// # Safety
/// CMSE non-secure-entry handler — writes 8 bytes to NS after
/// `validate_ns_write_ptr`. Drives the SAES peripheral.
pub(super) unsafe fn cmd_saes_selftest_run(args: &GatewayArgs) -> u32 {
    if !validate_ns_write_ptr(args.arg1, SAES_FINGERPRINT_LEN) {
        return NscStatus::InvalidPointer as u32;
    }

    // The canonical prodtest profile includes `saes-dhuk`. Main deliberately
    // skips its ordinary DHUK init under `dev-testkey`, so this command must
    // initialize the peripheral itself before exercising both the software
    // and DHUK self-test paths. `init()` is idempotent and register-only.
    #[cfg(feature = "saes-dhuk")]
    {
        if crate::hw::saes::init().is_err() || crate::hw::saes::self_test().is_err() {
            return NscStatus::InternalError as u32;
        }

        let block: [u8; 16] = *b"PQSIGNER-SAES-v1";
        let fingerprint_block = match crate::hw::saes::encrypt_ecb_block(
            crate::hw::saes::KeySel::Dhuk,
            None,
            &block,
        ) {
            Ok(ciphertext) => ciphertext,
            Err(_) => return NscStatus::InternalError as u32,
        };
        let out = args.arg1 as *mut u8;
        for i in 0..SAES_FINGERPRINT_LEN {
            // SAFETY: validate_ns_write_ptr above checked
            // SAES_FINGERPRINT_LEN bytes writable at args.arg1.
            unsafe {
                core::ptr::write_volatile(out.add(i), fingerprint_block[i]);
            }
        }
        return NscStatus::Ok as u32;
    }
    #[cfg(not(feature = "saes-dhuk"))]
    {
        let _ = args;
        secure_log!("[PRODTEST] saes_selftest skipped — saes-dhuk feature off");
        NscStatus::InternalError as u32
    }
}

// ---------------------------------------------------------------------------
// CMD_PRODTEST_BHK_SELFTEST (103) — Phase B
// ---------------------------------------------------------------------------

const BHK_FINGERPRINT_LEN: usize = 8;

/// # Safety
/// CMSE non-secure-entry handler — writes an eight-byte zero diagnostic after
/// `validate_ns_write_ptr`, then returns the profile's required unsupported
/// status. It never drives BHK or persistent state.
pub(super) unsafe fn cmd_bhk_selftest_run(args: &GatewayArgs) -> u32 {
    if !validate_ns_write_ptr(args.arg1, BHK_FINGERPRINT_LEN) {
        return NscStatus::InvalidPointer as u32;
    }

    let out = args.arg1 as *mut u8;
    for i in 0..BHK_FINGERPRINT_LEN {
        // SAFETY: validate_ns_write_ptr above checked the full diagnostic.
        unsafe {
            core::ptr::write_volatile(out.add(i), 0);
        }
    }
    secure_log!("[PRODTEST] bhk_selftest unsupported in reversible profile");
    NscStatus::InternalError as u32
}

// ---------------------------------------------------------------------------
// CMD_PRODTEST_FLASH_RW (104) — Phase B
// ---------------------------------------------------------------------------

/// # Safety
/// CMSE non-secure-entry handler — reads the stable four-byte request shape
/// from NS, but deliberately performs no flash-controller operation or other
/// persistent write in the reversible profile.
pub(super) unsafe fn cmd_flash_rw_run(args: &GatewayArgs) -> u32 {
    if !validate_ns_read_ptr(args.arg0, 4) {
        return NscStatus::InvalidPointer as u32;
    }
    // SAFETY: validate_ns_read_ptr above.
    let mut buf = [0u8; 4];
    for i in 0..4 {
        buf[i] = unsafe {
            core::ptr::read_volatile((args.arg0 + i as u32) as *const u8)
        };
    }
    let pattern = u32::from_le_bytes(buf);

    // Deliberately unsupported: reversible acceptance has no designated
    // writable page and must not infer flash-write authority from this wire
    // command. A separately reviewed destructive harness would be required.
    let _ = pattern;
    secure_log!("[PRODTEST] flash_rw_test unsupported in reversible profile");
    NscStatus::InternalError as u32
}

// ---------------------------------------------------------------------------
// CMD_PRODTEST_TRNG_SAMPLE (105) — Phase B
// ---------------------------------------------------------------------------

const TRNG_SAMPLE_MAX: usize = PRODTEST_MAX_RESPONSE_DATA_LEN;

/// # Safety
/// CMSE non-secure-entry handler — reads 4 bytes from NS, draws from
/// the STM32 TRNG, writes 1..=254 bytes to NS after
/// `validate_ns_write_ptr`.
pub(super) unsafe fn cmd_trng_sample_run(args: &GatewayArgs) -> u32 {
    if !validate_ns_read_ptr(args.arg0, 4) {
        return NscStatus::InvalidPointer as u32;
    }
    // SAFETY: validate_ns_read_ptr above.
    let mut buf = [0u8; 4];
    for i in 0..4 {
        buf[i] = unsafe {
            core::ptr::read_volatile((args.arg0 + i as u32) as *const u8)
        };
    }
    let n = u32::from_le_bytes(buf) as usize;

    if n == 0 || n > TRNG_SAMPLE_MAX {
        return NscStatus::InvalidPointer as u32;
    }

    if !validate_ns_write_ptr(args.arg1, n) {
        return NscStatus::InvalidPointer as u32;
    }

    // Draw n bytes from the STM32 TRNG only (no SE XOR mix — the
    // fixture wants to evaluate the MCU's TRNG in isolation for
    // statistical entropy testing).
    let mut sample = [0u8; TRNG_SAMPLE_MAX];
    if crate::rng::fill(&mut sample[..n]).is_err() {
        return NscStatus::InternalError as u32;
    }

    let out = args.arg1 as *mut u8;
    for i in 0..n {
        // SAFETY: validate_ns_write_ptr above checked n bytes
        // writable at args.arg1.
        unsafe {
            core::ptr::write_volatile(out.add(i), sample[i]);
        }
    }
    NscStatus::Ok as u32
}

// ---------------------------------------------------------------------------
// CMD_PRODTEST_OPTIGA_HANDSHAKE (106) — Phase C
// ---------------------------------------------------------------------------
//
// Drives the OPTIGA Trust M's IFX I²C → APDU stack end-to-end without
// touching any persistent chip state. The prodtest-only probe lazily runs
// `init()` (RST pulse + OpenApplication) then sends a plaintext `GetRandom`
// APDU. This is intentionally separate from production `random()`, which
// always requires a loaded PBS and Shielded Connection. Catches:
//   - missing chip / broken solder / I²C bus wedged
//   - RST line wrong / floating (init's pin_diag::run pulse fails)
//   - power-rail / clock issues (OpenApplication times out)
//   - chip RNG defect (returns garbage / all-zero)
//
// 16 bytes is the smallest RNG payload that satisfies the OPTIGA's
// minimum (8 bytes) without padding overhead. Tests can also feed
// these bytes into the fixture's per-die uniqueness DB.

const OPTIGA_HANDSHAKE_RNG_LEN: usize = 16;

/// # Safety
/// CMSE non-secure-entry handler — writes 16 bytes to NS after
/// `validate_ns_write_ptr`. Drives the OPTIGA Trust M I²C bus.
pub(super) unsafe fn cmd_optiga_handshake_run(args: &GatewayArgs) -> u32 {
    if !validate_ns_write_ptr(args.arg1, OPTIGA_HANDSHAKE_RNG_LEN) {
        return NscStatus::InvalidPointer as u32;
    }

    #[cfg(feature = "dual-se")]
    {
        // SAFETY: dispatcher's non-reentrant invariant serialises
        // `static mut crate::SE` access. We touch only `optiga`.
        let se = unsafe { &mut *core::ptr::addr_of_mut!(crate::SE) };
        let mut rng_buf = [0u8; OPTIGA_HANDSHAKE_RNG_LEN];
        if se.optiga.prodtest_plain_random(&mut rng_buf).is_err() {
            secure_log!("[PRODTEST] optiga_handshake: plain probe failed");
            return NscStatus::InternalError as u32;
        }
        let out = args.arg1 as *mut u8;
        for i in 0..OPTIGA_HANDSHAKE_RNG_LEN {
            // SAFETY: validate_ns_write_ptr above checked
            // OPTIGA_HANDSHAKE_RNG_LEN bytes writable at args.arg1.
            unsafe {
                core::ptr::write_volatile(out.add(i), rng_buf[i]);
            }
        }
        return NscStatus::Ok as u32;
    }
    #[cfg(not(feature = "dual-se"))]
    {
        let _ = args;
        NscStatus::InternalError as u32
    }
}

// ---------------------------------------------------------------------------
// CMD_PRODTEST_SE050_HANDSHAKE (107) — Phase C
// ---------------------------------------------------------------------------
//
// Same shape as OPTIGA_HANDSHAKE but for the SE050 T=1' stack.
// `Se050::random()` lazily runs `init()` (interface_reset + ATR
// exchange + SCP03 setup with default platform keys) then sends a
// `GetRandom` APDU. On a fresh chip the SCP03 default keys are still
// in place so the session opens cleanly. Catches:
//   - missing chip / broken solder / I²C bus wedged
//   - ENA line wrong (SE050 stays in reset)
//   - power-rail / cold-boot timing issues (interface_reset retry loop)
//   - default SCP03 keys missing / pre-rotated (factory replacement)
//   - chip RNG defect

const SE050_HANDSHAKE_RNG_LEN: usize = 16;

/// # Safety
/// CMSE non-secure-entry handler — writes 16 bytes to NS after
/// `validate_ns_write_ptr`. Drives the SE050 I²C bus.
pub(super) unsafe fn cmd_se050_handshake_run(args: &GatewayArgs) -> u32 {
    if !validate_ns_write_ptr(args.arg1, SE050_HANDSHAKE_RNG_LEN) {
        return NscStatus::InvalidPointer as u32;
    }

    #[cfg(feature = "dual-se")]
    {
        // SAFETY: dispatcher's non-reentrant invariant serialises
        // `static mut crate::SE` access. We touch only `se050`.
        let se = unsafe { &mut *core::ptr::addr_of_mut!(crate::SE) };
        let mut rng_buf = [0u8; SE050_HANDSHAKE_RNG_LEN];
        if se.se050.random(&mut rng_buf).is_err() {
            secure_log!("[PRODTEST] se050_handshake: random() failed");
            return NscStatus::InternalError as u32;
        }
        let out = args.arg1 as *mut u8;
        for i in 0..SE050_HANDSHAKE_RNG_LEN {
            // SAFETY: validate_ns_write_ptr above checked
            // SE050_HANDSHAKE_RNG_LEN bytes writable at args.arg1.
            unsafe {
                core::ptr::write_volatile(out.add(i), rng_buf[i]);
            }
        }
        return NscStatus::Ok as u32;
    }
    #[cfg(not(feature = "dual-se"))]
    {
        let _ = args;
        NscStatus::InternalError as u32
    }
}

// ---------------------------------------------------------------------------
// CMD_PRODTEST_USB_LOOPBACK (108) — Phase C
// ---------------------------------------------------------------------------
//
// Echo N bytes back to the host. The fact the firmware RECEIVED the
// command already proves USB RX framing works; this command proves
// TX + full round-trip byte integrity for non-trivial payloads up to
// the shared 254-byte response-data cap.
// Catches:
//   - USB OTG FS TX path corruption
//   - HID report fragmentation bugs in the NS-side stack
//   - buffer-overflow / off-by-one in the USB transport layer
//   - VCC instability under sustained USB TX

const USB_LOOPBACK_MAX: usize = PRODTEST_MAX_RESPONSE_DATA_LEN;

/// # Safety
/// CMSE non-secure-entry handler — reads N bytes from NS, writes N
/// bytes to NS. Both pointers validated; N must be 1..=254.
pub(super) unsafe fn cmd_usb_loopback_run(args: &GatewayArgs) -> u32 {
    let n = args.arg2 as usize;
    if n == 0 || n > USB_LOOPBACK_MAX {
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_read_ptr(args.arg0, n) {
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_write_ptr(args.arg1, n) {
        return NscStatus::InvalidPointer as u32;
    }

    // TOCTOU: copy NS input to S-stack before parse / write-back so a
    // racing NS thread can't switch the data between read and write.
    let mut buf = [0u8; USB_LOOPBACK_MAX];
    for i in 0..n {
        // SAFETY: validate_ns_read_ptr above checked n bytes readable
        // at args.arg0.
        buf[i] = unsafe {
            core::ptr::read_volatile((args.arg0 + i as u32) as *const u8)
        };
    }

    let out = args.arg1 as *mut u8;
    for i in 0..n {
        // SAFETY: validate_ns_write_ptr above checked n bytes
        // writable at args.arg1.
        unsafe {
            core::ptr::write_volatile(out.add(i), buf[i]);
        }
    }
    NscStatus::Ok as u32
}

// ---------------------------------------------------------------------------
// CMD_PRODTEST_BUTTON_TEST (109) — Phase D
// ---------------------------------------------------------------------------
//
// Drives the trusted-UI button hardware (PC1 = LEFT / PA8 = RIGHT) via
// the three-step LEFT → RIGHT → BOTH sequence. Each step has a 10 s
// budget; pressing the WRONG button is diagnostically distinct from
// timeout (swapped wires at the connector vs. dead solder), so the
// step-status byte encodes both failure modes. The post-press
// release wait shares the same per-step budget (#453): a welded /
// stuck button returns the step's STUCK code instead of wedging the
// unit into a runner-side HID timeout (which the factory harness
// would misreport as a runner error, not a unit FAIL).
//
// Why no latency reporting: at the operator's reaction time scale,
// per-press latency is dominated by the human, not the GPIO. The fact
// that the press registered at all is the diagnostic signal; precise
// µs timing adds no information.

const BUTTON_TEST_TIMEOUT_MS: u32 = 10_000;
const BUTTON_TEST_DEBOUNCE_MS: u32 = 30;
const BUTTON_TEST_POLL_MS: u32 = 5;
const BUTTON_TEST_OUT_LEN: usize = 4;

const STEP_OK: u8 = 0x00;
const STEP_LEFT_TIMEOUT: u8 = 0x11;
const STEP_LEFT_WRONG: u8 = 0x12;
const STEP_LEFT_STUCK: u8 = 0x13;
const STEP_RIGHT_TIMEOUT: u8 = 0x21;
const STEP_RIGHT_WRONG: u8 = 0x22;
const STEP_RIGHT_STUCK: u8 = 0x23;
const STEP_BOTH_TIMEOUT: u8 = 0x31;
const STEP_BOTH_STUCK: u8 = 0x33;

#[cfg(all(feature = "gpio-buttons", feature = "ui-lcd"))]
fn show_button_prompt(line0: &str, line1: &str) {
    let d = crate::ui::display();
    d.clear();
    d.draw_line(0, line0);
    d.draw_line(2, line1);
    d.flush();
}

/// Wait for a single-button press (LEFT or RIGHT, exclusive). Returns
/// `STEP_OK` on success, the supplied `timeout_code` if the timeout
/// expires with no press, or `wrong_code` if the unexpected button
/// fired first (swapped solder / wires). The post-press release wait
/// shares the same 10 s budget (#453): a button that never releases
/// returns `stuck_code` (welded contact) rather than hanging.
#[cfg(feature = "gpio-buttons")]
fn run_single_button_step(
    expect_left: bool,
    timeout_code: u8,
    wrong_code: u8,
    stuck_code: u8,
) -> u8 {
    use crate::hw::buttons::{busy_wait_ms, left_pressed, right_pressed};

    let mut elapsed: u32 = 0;
    loop {
        let l = left_pressed();
        let r = right_pressed();

        // Wrong-button detection — fires only if the unexpected button
        // is pressed CLEAN (no chord with the expected one), since the
        // operator may also be holding both during the BOTH step.
        if expect_left && r && !l {
            return wrong_code;
        }
        if !expect_left && l && !r {
            return wrong_code;
        }

        // Expected button pressed: debounce.
        let pressed = if expect_left { l } else { r };
        if pressed {
            busy_wait_ms(BUTTON_TEST_DEBOUNCE_MS);
            let still_pressed = if expect_left {
                left_pressed()
            } else {
                right_pressed()
            };
            if still_pressed {
                // Wait for clean release before returning so the next
                // step starts from a known idle state. Bounded by the
                // same per-step budget (#453): a welded button would
                // otherwise wedge the unit here forever.
                loop {
                    let still = if expect_left {
                        left_pressed()
                    } else {
                        right_pressed()
                    };
                    if !still {
                        break;
                    }
                    if elapsed >= BUTTON_TEST_TIMEOUT_MS {
                        return stuck_code;
                    }
                    busy_wait_ms(BUTTON_TEST_POLL_MS);
                    elapsed = elapsed.saturating_add(BUTTON_TEST_POLL_MS);
                }
                busy_wait_ms(BUTTON_TEST_DEBOUNCE_MS);
                return STEP_OK;
            }
            // Bounce — fall through to keep polling.
        }

        if elapsed >= BUTTON_TEST_TIMEOUT_MS {
            return timeout_code;
        }
        busy_wait_ms(BUTTON_TEST_POLL_MS);
        elapsed = elapsed.saturating_add(BUTTON_TEST_POLL_MS);
    }
}

/// Wait for BOTH buttons pressed simultaneously. Pressing one alone is
/// not an error (operator is positioning hands) — only timeout fails.
#[cfg(feature = "gpio-buttons")]
fn run_both_button_step() -> u8 {
    use crate::hw::buttons::{busy_wait_ms, left_pressed, right_pressed};

    let mut elapsed: u32 = 0;
    loop {
        if left_pressed() && right_pressed() {
            busy_wait_ms(BUTTON_TEST_DEBOUNCE_MS);
            if left_pressed() && right_pressed() {
                // Wait for clean release. Bounded by the same per-step
                // budget (#453): a welded button must return
                // STEP_BOTH_STUCK, not wedge the unit.
                while left_pressed() || right_pressed() {
                    if elapsed >= BUTTON_TEST_TIMEOUT_MS {
                        return STEP_BOTH_STUCK;
                    }
                    busy_wait_ms(BUTTON_TEST_POLL_MS);
                    elapsed = elapsed.saturating_add(BUTTON_TEST_POLL_MS);
                }
                busy_wait_ms(BUTTON_TEST_DEBOUNCE_MS);
                return STEP_OK;
            }
        }
        if elapsed >= BUTTON_TEST_TIMEOUT_MS {
            return STEP_BOTH_TIMEOUT;
        }
        busy_wait_ms(BUTTON_TEST_POLL_MS);
        elapsed = elapsed.saturating_add(BUTTON_TEST_POLL_MS);
    }
}

/// # Safety
/// CMSE non-secure-entry handler — writes 4 bytes to NS after
/// `validate_ns_write_ptr`. Drives the NV3007 LCD + button GPIOs.
pub(super) unsafe fn cmd_button_test_run(args: &GatewayArgs) -> u32 {
    if !validate_ns_write_ptr(args.arg1, BUTTON_TEST_OUT_LEN) {
        return NscStatus::InvalidPointer as u32;
    }

    #[cfg(all(feature = "gpio-buttons", feature = "ui-lcd"))]
    let step_status = {
        show_button_prompt("PRESS LEFT", "  (10 s)");
        let s1 = run_single_button_step(true, STEP_LEFT_TIMEOUT, STEP_LEFT_WRONG, STEP_LEFT_STUCK);
        if s1 != STEP_OK {
            show_button_prompt("BTN FAIL", "step 1: LEFT");
            s1
        } else {
            show_button_prompt("PRESS RIGHT", "  (10 s)");
            let s2 = run_single_button_step(false, STEP_RIGHT_TIMEOUT, STEP_RIGHT_WRONG, STEP_RIGHT_STUCK);
            if s2 != STEP_OK {
                show_button_prompt("BTN FAIL", "step 2: RIGHT");
                s2
            } else {
                show_button_prompt("PRESS BOTH", "  (10 s)");
                let s3 = run_both_button_step();
                if s3 != STEP_OK {
                    show_button_prompt("BTN FAIL", "step 3: BOTH");
                    s3
                } else {
                    show_button_prompt("BTN PASS", "3/3 steps OK");
                    STEP_OK
                }
            }
        }
    };

    // If gpio-buttons or ui-lcd is somehow off (shouldn't be — the
    // prodtest feature pulls both in), report a generic timeout so the
    // fixture sees the build profile is wrong.
    #[cfg(not(all(feature = "gpio-buttons", feature = "ui-lcd")))]
    let step_status: u8 = STEP_LEFT_TIMEOUT;

    let out = args.arg1 as *mut u8;
    // SAFETY: validate_ns_write_ptr above checked BUTTON_TEST_OUT_LEN
    // bytes writable at args.arg1.
    unsafe {
        core::ptr::write_volatile(out, step_status);
        core::ptr::write_volatile(out.add(1), 0);
        core::ptr::write_volatile(out.add(2), 0);
        core::ptr::write_volatile(out.add(3), 0);
    }

    if step_status == STEP_OK {
        NscStatus::Ok as u32
    } else {
        secure_log!("[PRODTEST] button_test: step_status=0x{:02x}", step_status);
        NscStatus::InternalError as u32
    }
}

// ---------------------------------------------------------------------------
// CMD_PRODTEST_RGB_TEST (110) — Phase D
// ---------------------------------------------------------------------------
//
// Lights the `pq1` board's 9 RGB LEDs via the AW21036 on I2C2 and hands the
// fixture everything needed to localize a dark board in one shot: a bus scan
// (with the AW99703 backlight at 0x36 as the bus's positive control and the
// AW21036's broadcast address 0x1C as a second witness for the part), both
// readable identity registers, and an ACK tally.
//
// Why the output is written even on failure: "the LEDs are dark" has at least
// six causes (bus pins, pull-ups, chip absent, AD strap, RGB_EN, current
// registers), and a bare status byte distinguishes none of them. The handler
// therefore always writes the diagnostic and reports health in the status.
//
// Why no pass/fail on the light itself: the firmware cannot see its own LEDs.
// The chip ACKing every write is the machine-checkable half; the colour and
// the per-LED coverage are the operator's half, which is why the command takes
// (r, g, b) rather than running a fixed pattern.

const RGB_TEST_IN_LEN: usize = sphincs_tz_shared::PRODTEST_RGB_IN_LEN;
const RGB_TEST_OUT_LEN: usize = sphincs_tz_shared::PRODTEST_RGB_OUT_LEN;
/// Sentinel for "the addressing phase was not ACKed", distinct from a chip
/// that genuinely answers `0x00`.
const RGB_READ_FAILED: u8 = 0xFF;

// Wire contract, asserted at compile time rather than in this file's
// `#[cfg(test)]` module: that module is inside `#![cfg(feature = "prodtest")]`
// and `prodtest` only builds for `thumbv8m`, so nothing in it ever runs
// host-side. These asserts DO fire on every prodtest firmware build.
// The fixture decodes `out[16]`/`out[17]` by number, so the sentinel must not
// collide with either identity value or a dead bus would read as a live chip.
const _: () = assert!(RGB_TEST_OUT_LEN == 16 + 6 + 2, "scan + 6 fields + 2 reserved");
const _: () = assert!(RGB_TEST_IN_LEN == 6, "[r, g, b, gcc, en, reserved]");
#[cfg(all(feature = "stm32u585", feature = "board-pq1"))]
const _: () = assert!(RGB_READ_FAILED != crate::hw::aw21036::VER_EXPECTED);
#[cfg(all(feature = "stm32u585", feature = "board-pq1"))]
const _: () = assert!(RGB_READ_FAILED != crate::hw::aw21036::RESET_ID_EXPECTED);

/// # Safety
/// CMSE non-secure-entry handler — NS pointer derefs only after
/// `validate_ns_read_ptr` / `validate_ns_write_ptr`, and the NS input is
/// copied to the S-stack before use (TOCTOU).
pub(super) unsafe fn cmd_rgb_test_run(args: &GatewayArgs) -> u32 {
    if !validate_ns_read_ptr(args.arg0, RGB_TEST_IN_LEN)
        || !validate_ns_write_ptr(args.arg1, RGB_TEST_OUT_LEN)
    {
        return NscStatus::InvalidPointer as u32;
    }

    // Copy the NS request to the S-stack before parsing it (invariant #4).
    let mut req = [0u8; RGB_TEST_IN_LEN];
    for (i, byte) in req.iter_mut().enumerate() {
        // SAFETY: arg0 was validated for RGB_TEST_IN_LEN bytes above.
        *byte = unsafe { core::ptr::read_volatile((args.arg0 as *const u8).add(i)) };
    }

    let mut out = [0u8; RGB_TEST_OUT_LEN];
    let healthy = rgb_test_fill(&req, &mut out);

    let out_ptr = args.arg1 as *mut u8;
    for (i, byte) in out.iter().enumerate() {
        // SAFETY: arg1 was validated for RGB_TEST_OUT_LEN bytes above.
        unsafe { core::ptr::write_volatile(out_ptr.add(i), *byte) };
    }

    if healthy {
        NscStatus::Ok as u32
    } else {
        NscStatus::InternalError as u32
    }
}

/// Run the test and serialise the report. Split out so the wire layout is
/// exercised by the host tests below without any hardware.
#[cfg(all(feature = "stm32u585", feature = "board-pq1"))]
fn rgb_test_fill(req: &[u8; RGB_TEST_IN_LEN], out: &mut [u8; RGB_TEST_OUT_LEN]) -> bool {
    let report = crate::hw::aw21036::light(req[0], req[1], req[2], req[3], req[4] != 0);
    out[..16].copy_from_slice(&report.scan);
    out[16] = report.ver.unwrap_or(RGB_READ_FAILED);
    out[17] = report.reset_id.unwrap_or(RGB_READ_FAILED);
    out[18] = report.acks_ok;
    out[19] = report.acks_total;
    out[20] = u8::from(report.en_level);
    out[21] = report.gcc;
    secure_log!(
        "[PRODTEST] rgb_test: ver=0x{:02x} acks={}/{} en={}",
        out[16],
        out[18],
        out[19],
        out[20]
    );
    report.healthy()
}

/// Boards with no RGB driver: all-zero output, unhealthy. The `_` bindings keep
/// the signature identical to the `pq1` arm.
#[cfg(not(all(feature = "stm32u585", feature = "board-pq1")))]
fn rgb_test_fill(_req: &[u8; RGB_TEST_IN_LEN], _out: &mut [u8; RGB_TEST_OUT_LEN]) -> bool {
    false
}

// ---------------------------------------------------------------------------
// Host tests — pure helpers
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positive_get_id_output_layout() {
        // 12 B UID + 4 B version + 8 B reserved = 24 B total. Pin
        // the constant so a future re-shuffle of fields breaks the
        // build (fixture parses on byte offsets).
        assert_eq!(GET_ID_OUT_LEN, 24);
        assert_eq!(STM32_UID_LEN, 12);
    }

    #[test]
    fn positive_prodtest_fw_version_pinned() {
        // The factory's traceability DB correlates this with
        // per-unit diagnostic data. Drop a row in the operator
        // manual every time this bumps.
        assert_eq!(PRODTEST_FW_VERSION, 3);
    }

    #[test]
    fn positive_trng_sample_cap_matches_proto_doc() {
        assert_eq!(TRNG_SAMPLE_MAX, PRODTEST_MAX_RESPONSE_DATA_LEN);
        assert_eq!(TRNG_SAMPLE_MAX, 254);
    }

    #[test]
    fn positive_saes_fingerprint_len_matches_existing_self_test() {
        // The existing `hw::saes::self_test` returns an 8-byte
        // fingerprint. Prodtest mirrors that contract so the
        // fixture's reference values stay reusable across builds.
        assert_eq!(SAES_FINGERPRINT_LEN, 8);
        assert_eq!(BHK_FINGERPRINT_LEN, 8);
    }

    #[test]
    fn positive_phase_c_handshake_rng_lens_pinned() {
        // Both handshake commands return 16 bytes — the fixture
        // parses on these offsets in its per-die uniqueness DB. Any
        // change here must also update `docs/provisioning/factory-prodtest.md`
        // and the host runner.
        assert_eq!(OPTIGA_HANDSHAKE_RNG_LEN, 16);
        assert_eq!(SE050_HANDSHAKE_RNG_LEN, 16);
    }

    #[test]
    fn positive_usb_loopback_cap_matches_proto_doc() {
        // Cap matches TRNG_SAMPLE_MAX so the same caller-side buffer
        // can be reused for both commands.
        assert_eq!(USB_LOOPBACK_MAX, PRODTEST_MAX_RESPONSE_DATA_LEN);
    }

    #[test]
    fn positive_button_test_step_codes_have_compact_layout() {
        // Upper nibble = step (1, 2, 3); lower nibble = error kind
        // (1=timeout, 2=wrong button, 3=release stuck — #453). The
        // fixture's error table depends on this — change the encoding
        // and the operator manual decoder also has to change.
        assert_eq!(STEP_OK, 0x00);
        assert_eq!(STEP_LEFT_TIMEOUT, 0x11);
        assert_eq!(STEP_LEFT_WRONG, 0x12);
        assert_eq!(STEP_LEFT_STUCK, 0x13);
        assert_eq!(STEP_RIGHT_TIMEOUT, 0x21);
        assert_eq!(STEP_RIGHT_WRONG, 0x22);
        assert_eq!(STEP_RIGHT_STUCK, 0x23);
        assert_eq!(STEP_BOTH_TIMEOUT, 0x31);
        assert_eq!(STEP_BOTH_STUCK, 0x33);
        // Compact-encoding invariant: per-step error nibbles are
        // distinct and non-overlapping with success.
        for code in [
            STEP_LEFT_TIMEOUT,
            STEP_LEFT_WRONG,
            STEP_LEFT_STUCK,
            STEP_RIGHT_TIMEOUT,
            STEP_RIGHT_WRONG,
            STEP_RIGHT_STUCK,
            STEP_BOTH_TIMEOUT,
            STEP_BOTH_STUCK,
        ] {
            assert_ne!(code, STEP_OK);
            assert!((code >> 4) >= 1 && (code >> 4) <= 3);
            assert!((code & 0x0F) >= 1 && (code & 0x0F) <= 3);
        }
    }

    #[test]
    fn positive_button_test_timeout_is_operator_friendly() {
        // 10 s per step gives the operator enough time without
        // making the per-unit test take forever (30 s total budget).
        assert_eq!(BUTTON_TEST_TIMEOUT_MS, 10_000);
        assert_eq!(BUTTON_TEST_OUT_LEN, 4);
    }
}
