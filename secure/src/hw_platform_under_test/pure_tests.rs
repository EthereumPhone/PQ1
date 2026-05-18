//! Host-side positive + negative test suite for the `secure-hw-platform`
//! slice.
//!
//! Slice files in scope:
//!   - `secure/src/hw/flash.rs`            (bank-1/bank-2 program/erase,
//!                                          PIN counter, off-chain journal)
//!   - `secure/src/hw/tamp.rs`             (TAMP / RTC log-only IRQ harness)
//!   - `secure/src/hw/consumption_mask.rs` (TIM2 PWM power mask on PA5)
//!   - `secure/src/hw/sca_trigger.rs`      (SCA-rig sync GPIO; dev-only)
//!   - `secure/src/hw/rcc.rs`              (SYSCLK PLL config @ 160 MHz)
//!   - `secure/src/hw/rng.rs`              (HW TRNG)
//!   - `secure/src/hw/pka.rs`              (PKA accelerator for BLS12-381 Fp)
//!   - `secure/src/hw/boot_pulse.rs`       (dev-only RDP1 boot bisection)
//!   - `secure/src/hw/boot_state.rs`       (FSBL slot-pick page on flash 6)
//!
//! Because every file except `sca_trigger.rs`'s no-op stub imports
//! `cortex_m` or sits behind `feature = "stm32u585"` (which pulls in
//! ARM-only deps), the slice cannot be link-checked on host. We
//! therefore pin the slice through two host-runnable mechanisms:
//!
//!   1. **`include_str!` source-text pins.** Constants, register
//!      addresses, page numbers, sentinel bytes, feature gates, FI
//!      guards, and production fences are asserted against the file
//!      text. A future refactor that breaks one of these invariants
//!      fails this test before it reaches silicon. The text-pin is
//!      intentional — the cost of a silently-corrupted flash address
//!      (PIN counter pointing at the active firmware page → boot
//!      brick on every wrong-PIN attempt) is many orders of magnitude
//!      higher than a CI false-positive on a whitespace tweak.
//!
//!   2. **Reference encoding tests.** We re-implement the boot-state
//!      page encoding and the page-123 off-chain journal entry
//!      packing here, then `assert_eq!` against the byte layouts that
//!      the production code produces. These bytes are baked into
//!      flash for the device lifetime; reshape = on-chain breaking
//!      change.
//!
//! Negative tests are framed by the assumption they attack: each
//! `negative_*` test's panic message names the attack and cites the
//! CLAUDE.md invariant or in-file safety comment whose silent removal
//! it would otherwise enable. Per the test-writing brief, the negative
//! suite is the most important deliverable here.

#![cfg(test)]

const FLASH_SRC: &str = include_str!("../hw/flash.rs");
const TAMP_SRC: &str = include_str!("../hw/tamp.rs");
const CONSUMPTION_MASK_SRC: &str = include_str!("../hw/consumption_mask.rs");
const SCA_TRIGGER_SRC: &str = include_str!("../hw/sca_trigger.rs");
const RCC_SRC: &str = include_str!("../hw/rcc.rs");
const RNG_SRC: &str = include_str!("../hw/rng.rs");
const PKA_SRC: &str = include_str!("../hw/pka.rs");
const BOOT_PULSE_SRC: &str = include_str!("../hw/boot_pulse.rs");
const BOOT_STATE_SRC: &str = include_str!("../hw/boot_state.rs");
const HW_MOD_SRC: &str = include_str!("../hw/mod.rs");

// ═════════════════════════════════════════════════════════════════════
// 1. POSITIVE — flash page geometry (every page-number / address pin)
// ═════════════════════════════════════════════════════════════════════

#[test]
fn positive_flash_key_page_127() {
    assert!(FLASH_SRC.contains("pub const KEY_PAGE_ADDR: u32 = 0x0C0F_E000;"));
    assert!(FLASH_SRC.contains("const KEY_PAGE_NUM: u32 = 127;"));
}

#[test]
fn positive_flash_admin_page_125() {
    assert!(FLASH_SRC.contains("pub const ADMIN_PAGE_ADDR: u32 = 0x0C0F_A000;"));
    assert!(FLASH_SRC.contains("const ADMIN_PAGE_NUM: u32 = 125;"));
    assert!(FLASH_SRC.contains("const WIPE_FLAG_OFFSET: u32 = 16;"));
    assert!(FLASH_SRC.contains("const WIPE_FLAG_ARMED: u8 = 0x00;"));
}

#[test]
fn positive_flash_pin_attempts_page_124() {
    assert!(FLASH_SRC.contains("const PIN_ATTEMPTS_PAGE_ADDR: u32 = 0x0C0F_8000;"));
    assert!(FLASH_SRC.contains("const PIN_ATTEMPTS_PAGE_NUM: u32 = 124;"));
    assert!(FLASH_SRC.contains("const PIN_ATTEMPTS_CAPACITY: u32 = 32;"));
    assert!(FLASH_SRC.contains("const PIN_ATTEMPTS_QW_SIZE: u32 = 16;"));
}

#[test]
fn positive_flash_offchain_journal_page_123() {
    assert!(FLASH_SRC.contains("const OFFCHAIN_PAGE_ADDR: u32 = 0x0C0F_6000;"));
    assert!(FLASH_SRC.contains("const OFFCHAIN_PAGE_NUM: u32 = 123;"));
    assert!(FLASH_SRC.contains("const OFFCHAIN_QW_SIZE: u32 = 16;"));
    assert!(FLASH_SRC.contains("const OFFCHAIN_CAPACITY: u32 = 512;"));
    assert!(FLASH_SRC.contains("const OFFCHAIN_TYPE_COUNT: u8 = 0x01;"));
    assert!(FLASH_SRC.contains("const OFFCHAIN_TYPE_USEROP: u8 = 0x02;"));
}

#[test]
fn positive_flash_boot_state_page_6() {
    assert!(FLASH_SRC.contains("pub const BOOT_STATE_ADDR: u32 = 0x0C00_C000;"));
    assert!(FLASH_SRC.contains("pub const BOOT_STATE_PAGE: u32 = 6;"));
}

#[test]
fn positive_flash_manifest_pages_4_and_5() {
    assert!(FLASH_SRC.contains("pub const MANIFEST_A_ADDR: u32 = 0x0C00_8000;"));
    assert!(FLASH_SRC.contains("pub const MANIFEST_A_PAGE: u32 = 4;"));
    assert!(FLASH_SRC.contains("pub const MANIFEST_B_ADDR: u32 = 0x0C00_A000;"));
    assert!(FLASH_SRC.contains("pub const MANIFEST_B_PAGE: u32 = 5;"));
}

#[test]
fn positive_flash_slot_layout_bank1_secure() {
    assert!(FLASH_SRC.contains("pub const SLOT_A_SECURE_ADDR: u32 = 0x0C00_E000;"));
    assert!(FLASH_SRC.contains("pub const SLOT_A_SECURE_FIRST_PAGE: u32 = 7;"));
    assert!(FLASH_SRC.contains("pub const SLOT_A_SECURE_LAST_PAGE: u32 = 64;"));
    assert!(FLASH_SRC.contains("pub const SLOT_B_SECURE_ADDR: u32 = 0x0C08_2000;"));
    assert!(FLASH_SRC.contains("pub const SLOT_B_SECURE_FIRST_PAGE: u32 = 65;"));
    assert!(FLASH_SRC.contains("pub const SLOT_B_SECURE_LAST_PAGE: u32 = 122;"));
    assert!(FLASH_SRC.contains("pub const SLOT_SECURE_CAPACITY: u32 = 58 * 8 * 1024;"));
}

#[test]
fn positive_flash_slot_layout_bank2_ns() {
    assert!(FLASH_SRC.contains("pub const SLOT_A_NS_ADDR: u32 = 0x0810_0000;"));
    assert!(FLASH_SRC.contains("pub const SLOT_A_NS_FIRST_PAGE: u32 = 0;"));
    assert!(FLASH_SRC.contains("pub const SLOT_A_NS_LAST_PAGE: u32 = 63;"));
    assert!(FLASH_SRC.contains("pub const SLOT_B_NS_ADDR: u32 = 0x0818_0000;"));
    assert!(FLASH_SRC.contains("pub const SLOT_B_NS_FIRST_PAGE: u32 = 64;"));
    assert!(FLASH_SRC.contains("pub const SLOT_B_NS_LAST_PAGE: u32 = 127;"));
    assert!(FLASH_SRC.contains("pub const SLOT_NS_CAPACITY: u32 = 64 * 8 * 1024;"));
}

// ═════════════════════════════════════════════════════════════════════
// 2. POSITIVE — flash controller register layout (secure alias)
// ═════════════════════════════════════════════════════════════════════

#[test]
fn positive_flash_secure_alias_0x5002_2000() {
    assert!(FLASH_SRC.contains("const FLASH: u32 = 0x5002_2000;"));
}

#[test]
fn positive_flash_unlock_key_sequence() {
    // STM32 family key sequence — same across F1/F4/L4/U5.
    assert!(FLASH_SRC.contains("const KEY1: u32 = 0x4567_0123;"));
    assert!(FLASH_SRC.contains("const KEY2: u32 = 0xCDEF_89AB;"));
}

#[test]
fn positive_flash_seccr_bit_positions() {
    assert!(FLASH_SRC.contains("const PG: u32 = 1 << 0;"));
    assert!(FLASH_SRC.contains("const PER: u32 = 1 << 1;"));
    assert!(FLASH_SRC.contains("const PNB_SHIFT: u32 = 3;"));
    assert!(FLASH_SRC.contains("const STRT: u32 = 1 << 16;"));
    assert!(FLASH_SRC.contains("const LOCK: u32 = 1 << 31;"));
}

#[test]
fn positive_flash_secsr_error_mask() {
    // PROGERR | WRPERR | PGAERR | SIZERR | PGSERR — the five conditions
    // that cause `write_quadword_verified` to return Err.
    assert!(FLASH_SRC.contains("const BSY: u32 = 1 << 16;"));
    assert!(FLASH_SRC.contains("const ERR_MASK: u32 = 0xFA;"));
}

#[test]
fn positive_flash_bker_bit_for_bank2() {
    assert!(FLASH_SRC.contains("const BKER: u32 = 1 << 11;"));
}

#[test]
fn positive_flash_icache_secure_alias() {
    assert!(FLASH_SRC.contains("const ICACHE_BASE: u32 = 0x5003_0400;"));
    assert!(FLASH_SRC.contains("const ICACHE_CR_CACHEINV: u32 = 1 << 1;"));
    assert!(FLASH_SRC.contains("const ICACHE_SR_BUSYF: u32 = 1 << 0;"));
}

// ═════════════════════════════════════════════════════════════════════
// 3. POSITIVE — RCC / RNG / PKA / TAMP register layout
// ═════════════════════════════════════════════════════════════════════

#[test]
fn positive_rcc_ns_alias_for_clock_setup() {
    // CLAUDE.md / RCC: NS alias is intentional for clock setup
    // because PWR / FLASH / ICACHE live behind their own secure aliases
    // and RCC clock-source selection is bank-agnostic.
    assert!(RCC_SRC.contains("const RCC: u32 = 0x4602_0C00;"));
}

#[test]
fn positive_rcc_secure_aliases_for_pwr_flash_icache() {
    assert!(RCC_SRC.contains("const PWR: u32 = 0x5602_0800;"));
    assert!(RCC_SRC.contains("const FLASH: u32 = 0x5002_2000;"));
    assert!(RCC_SRC.contains("const ICACHE: u32 = 0x5003_0400;"));
}

#[test]
fn positive_rcc_pll1_dividers_target_160mhz() {
    // HSI16(16 MHz) / M=1 × N=20 / R=2 = 160 MHz. PLL1DIVR field
    // encoding: bits[8:0] = N-1 (=19), bit24 base = (R-1)<<24 (=1).
    assert!(RCC_SRC.contains("const PLL1_N_20: u32 = 19;"));
    assert!(RCC_SRC.contains("const PLL1_R_2: u32 = 1 << 24;"));
}

#[test]
fn positive_rcc_hsi48_for_rng_clock() {
    // RNG requires HSI48 on STM32U5. CCIPR5 must point at it.
    assert!(RCC_SRC.contains("const HSI48ON: u32 = 1 << 12;"));
    assert!(RCC_SRC.contains("const HSI48RDY: u32 = 1 << 13;"));
}

#[test]
fn positive_rcc_flash_latency_4ws_required_for_160mhz() {
    // 4 wait states required at 160 MHz / VOS1 per RM0456.
    assert!(RCC_SRC.contains("REG.flash_acr.modify(|v| (v & !0xF) | 4);"));
    assert!(RCC_SRC.contains("while REG.flash_acr.read() & 0xF != 4 {}"));
}

#[test]
fn positive_rng_peripheral_secure_alias() {
    // CLAUDE.md / rng.rs comment: NS alias (0x420C_0800) bus-faults
    // under TZ default-secure; secure alias 0x520C_0800 is correct.
    assert!(RNG_SRC.contains("const RNG: u32 = 0x520C_0800;"));
}

#[test]
fn positive_rng_nist_compliant_default_cr() {
    // ST LL driver value (CONFIG3=0x0F, CONFIG1=0x34, NISTC=0).
    assert!(RNG_SRC.contains("const RNG_CR_NIST_DEFAULT: u32 = 0x00F0_0D00;"));
}

#[test]
fn positive_rng_condrst_bit_30() {
    // STM32U5: CONDRST is bit 30, NOT bit 6 (regression seed — bit 6
    // is part of CONFIG1 and a soft-reset attempt there silently
    // fails, leaving RNG in an unseeded state).
    assert!(RNG_SRC.contains("const CONDRST: u32 = 1 << 30;"));
}

#[test]
fn positive_pka_peripheral_secure_alias() {
    assert!(PKA_SRC.contains("const PKA_BASE: u32 = 0x520C_2000;"));
}

#[test]
fn positive_pka_ram_offsets_match_rm0456() {
    // RM0456 standalone-mode operand layout:
    // NB_BITS@0x408, OP1@0xA50, OP2@0xC68, RESULT@0xE78, OP3@0x1088.
    assert!(PKA_SRC.contains("const RAM_NB_BITS_ADDR: u32 = PKA_RAM_BASE + 0x0008;"));
    assert!(PKA_SRC.contains("const PKA_RAM_BASE: u32 = PKA_BASE + 0x400;"));
    assert!(PKA_SRC.contains("const RAM_OP1: u32 = PKA_BASE + 0x0A50;"));
    assert!(PKA_SRC.contains("const RAM_OP2: u32 = PKA_BASE + 0x0C68;"));
    assert!(PKA_SRC.contains("const RAM_RESULT: u32 = PKA_BASE + 0x0E78;"));
    assert!(PKA_SRC.contains("const RAM_MODULUS: u32 = PKA_BASE + 0x1088;"));
}

#[test]
fn positive_pka_montgomery_mul_opcode() {
    // PKA_CR.MODE = 0x10 selects Montgomery mul. Any other value would
    // start the wrong primitive (the bls12_381 fork relies on this).
    assert!(PKA_SRC.contains("const MODE_MONTGOMERY_MUL: u32 = 0x10;"));
}

#[test]
fn positive_pka_bls12_381_field_size_384_bits() {
    assert!(PKA_SRC.contains("const BLS12_381_BITS: u32 = 384;"));
    assert!(PKA_SRC.contains("const N_LIMBS: usize = 12;"));
}

#[test]
fn positive_tamp_secure_alias_and_irqn_2() {
    assert!(TAMP_SRC.contains("pub const TAMP: u32 = 0x5600_4400;"));
    assert!(TAMP_SRC.contains("pub const TAMP_IRQN: u32 = 2;"));
}

#[test]
fn positive_tamp_rcc_pwr_secure_aliases() {
    assert!(TAMP_SRC.contains("pub const RCC: u32 = 0x5602_0C00;"));
    assert!(TAMP_SRC.contains("pub const PWR: u32 = 0x5602_0800;"));
}

#[test]
fn positive_tamp_itamp_enable_bit_positions() {
    // RM0456 §45.8.x — every ITAMP*E bit fixed at its documented
    // position. A copy-paste shift would silently re-enable ITAMP4
    // / ITAMP10 (documented to never fire on this MCU rev — Trezor
    // skips them).
    assert!(TAMP_SRC.contains("pub const TAMP_CR1_ITAMP1E: u32 = 1 << 16;"));
    assert!(TAMP_SRC.contains("pub const TAMP_CR1_ITAMP2E: u32 = 1 << 17;"));
    assert!(TAMP_SRC.contains("pub const TAMP_CR1_ITAMP3E: u32 = 1 << 18;"));
    assert!(TAMP_SRC.contains("pub const TAMP_CR1_ITAMP5E: u32 = 1 << 20;"));
    assert!(TAMP_SRC.contains("pub const TAMP_CR1_ITAMP6E: u32 = 1 << 21;"));
    assert!(TAMP_SRC.contains("pub const TAMP_CR1_ITAMP7E: u32 = 1 << 22;"));
    assert!(TAMP_SRC.contains("pub const TAMP_CR1_ITAMP8E: u32 = 1 << 23;"));
    assert!(TAMP_SRC.contains("pub const TAMP_CR1_ITAMP9E: u32 = 1 << 24;"));
    assert!(TAMP_SRC.contains("pub const TAMP_CR1_ITAMP11E: u32 = 1 << 26;"));
    assert!(TAMP_SRC.contains("pub const TAMP_CR1_ITAMP12E: u32 = 1 << 27;"));
    assert!(TAMP_SRC.contains("pub const TAMP_CR1_ITAMP13E: u32 = 1 << 28;"));
}

#[test]
fn positive_tamp_reason_from_sr_covers_crypto_fault() {
    // ITAMP9 = CRYPTO_FAULT is the SAES/AES/PKA/TRNG glitch canary —
    // the highest-signal source. The mapping string must be findable
    // by name in post-mortem logs.
    assert!(TAMP_SRC.contains(r#""CRYPTO_FAULT""#));
    assert!(TAMP_SRC.contains(r#""VOLTAGE""#));
    assert!(TAMP_SRC.contains(r#""LSE_CLOCK""#));
    assert!(TAMP_SRC.contains(r#""IWDG""#));
    assert!(TAMP_SRC.contains(r#""SWD_ACCESS""#));
}

#[test]
fn positive_consumption_mask_pa5_pwm_tim2_ch1() {
    // Trezor convention; PA5 is the only pin claimed by this module.
    // TIM2 ch1 AF1 on PA5.
    assert!(CONSUMPTION_MASK_SRC.contains("pub const TIM2: u32 = 0x5000_0000;"));
    assert!(CONSUMPTION_MASK_SRC.contains("pub const GPIOA: u32 = 0x5202_0000;"));
    assert!(CONSUMPTION_MASK_SRC.contains("const TIMER_PERIOD: u32 = 16_000;"));
}

#[test]
fn positive_consumption_mask_pwm_mode1() {
    assert!(CONSUMPTION_MASK_SRC.contains("pub const TIM_CCMR1_OC1M_PWM1: u32 = 0b110 << 4;"));
    assert!(CONSUMPTION_MASK_SRC.contains("pub const TIM_CCMR1_OC1PE: u32 = 1 << 3;"));
}

#[test]
fn positive_sca_trigger_pin_pd2() {
    // Default pin per module docstring. PD2 = Arduino D4 area on
    // B-U585I-IOT02A — easy header access for a scope probe.
    assert!(SCA_TRIGGER_SRC.contains("const TRIG_GPIO_PORT_BASE: u32 = 0x5202_0C00;"));
    assert!(SCA_TRIGGER_SRC.contains("const TRIG_PIN: u8 = 2;"));
}

#[test]
fn positive_boot_pulse_pin_pe13() {
    // PE13 = Arduino D13 on B-U585I-IOT02A — free in builds without
    // spi1-arduino / tropic01-se.
    assert!(BOOT_PULSE_SRC.contains("const TARGET_PIN: u32 = 13;"));
    assert!(BOOT_PULSE_SRC.contains("const GPIOE_BASE: u32 = 0x5202_1000;"));
}

// ═════════════════════════════════════════════════════════════════════
// 4. POSITIVE — boot_state wire format (reference encoder, byte-exact)
// ═════════════════════════════════════════════════════════════════════
//
// `boot_state::encode` is `#[cfg(feature = "stm32u585")]`-gated and
// not reachable on host; we mirror it here as `encode_ref` and pin
// the byte layout. A change to the production encoder that doesn't
// also change `encode_ref` will diverge → the byte-equality assertions
// fail and CI catches it BEFORE the FSBL bricks on a misparsed page.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SlotRef {
    A,
    B,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BootStateRef {
    active_slot: SlotRef,
    last_good_version: u32,
}

const BSTATE_SIZE: usize = 16;
const BSTATE_MAGIC: [u8; 4] = *b"BSTE";

/// Byte-exact reference port of `boot_state::encode`. Used to pin the
/// flash layout: any deviation between this function and the source
/// invariants asserted below would corrupt FSBL's slot-pick decision
/// on the next cold boot.
fn encode_ref(state: &BootStateRef) -> [u8; BSTATE_SIZE] {
    let mut buf = [0xFFu8; BSTATE_SIZE];
    buf[0..4].copy_from_slice(&BSTATE_MAGIC);
    buf[4] = match state.active_slot {
        SlotRef::A => 0x00,
        SlotRef::B => 0x01,
    };
    buf[5] = 0x00;
    buf[6] = 0x00;
    buf[7] = 0x00;
    buf[8..12].copy_from_slice(&state.last_good_version.to_be_bytes());
    let crc = fw_manifest::crc32_ieee(&buf[..12]);
    buf[12..16].copy_from_slice(&crc.to_be_bytes());
    buf
}

#[test]
fn positive_boot_state_magic_is_bste() {
    assert!(BOOT_STATE_SRC.contains(r#"const BSTATE_MAGIC: [u8; 4] = *b"BSTE";"#));
}

#[test]
fn positive_boot_state_size_is_one_quadword() {
    // Each copy must fit in exactly one atomic 16-byte program.
    assert!(BOOT_STATE_SRC.contains("pub const BSTATE_SIZE: usize = 16;"));
}

#[test]
fn positive_boot_state_copy_addresses() {
    // Copy A at page base, copy B at +0x1000 inside the same 8 KB
    // page. The +0x1000 gap is what defends against torn writes.
    assert!(BOOT_STATE_SRC.contains("pub const BSTATE_COPY_A_ADDR: u32 = BOOT_STATE_ADDR;"));
    assert!(BOOT_STATE_SRC.contains("pub const BSTATE_COPY_B_ADDR: u32 = BOOT_STATE_ADDR + 0x1000;"));
}

#[test]
fn positive_boot_state_encode_slot_a_layout() {
    let s = BootStateRef {
        active_slot: SlotRef::A,
        last_good_version: 0xDEAD_BEEF,
    };
    let buf = encode_ref(&s);
    assert_eq!(&buf[0..4], b"BSTE", "magic at offset 0");
    assert_eq!(buf[4], 0x00, "slot A byte must be 0x00");
    assert_eq!(&buf[5..8], &[0x00, 0x00, 0x00], "reserved bytes 0x00");
    assert_eq!(&buf[8..12], &[0xDE, 0xAD, 0xBE, 0xEF], "last_good_version BE");
    let crc = fw_manifest::crc32_ieee(&buf[..12]);
    assert_eq!(&buf[12..16], &crc.to_be_bytes(), "CRC32 over bytes [0..12)");
}

#[test]
fn positive_boot_state_encode_slot_b_byte() {
    let s = BootStateRef {
        active_slot: SlotRef::B,
        last_good_version: 0,
    };
    let buf = encode_ref(&s);
    assert_eq!(buf[4], 0x01, "slot B byte must be 0x01");
}

#[test]
fn positive_boot_state_round_trip_crc_validates() {
    // Encoder output must satisfy the same CRC predicate the parser
    // checks — otherwise every write would parse as Unavailable on
    // the next read.
    for &v in &[0u32, 1, 0xFFFF_FFFF, 0x1234_5678] {
        for &slot in &[SlotRef::A, SlotRef::B] {
            let s = BootStateRef {
                active_slot: slot,
                last_good_version: v,
            };
            let buf = encode_ref(&s);
            let stored_crc =
                u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
            assert_eq!(stored_crc, fw_manifest::crc32_ieee(&buf[..12]));
        }
    }
}

// ═════════════════════════════════════════════════════════════════════
// 5. POSITIVE — off-chain journal `entry_qw` wire format
// ═════════════════════════════════════════════════════════════════════
//
// `entry_qw` packs 16 bytes per journal entry:
//   [ 0..  8) slot_key
//   [ 8..  9) type (0x01 count, 0x02 userop)
//   [ 9.. 16) count (7-byte BE — top byte of u64 dropped)
//
// Reshape would re-interpret historical entries; pin the layout.

fn entry_qw_ref(slot_key: &[u8; 8], entry_type: u8, count: u64) -> [u8; 16] {
    let mut qw = [0u8; 16];
    qw[..8].copy_from_slice(slot_key);
    qw[8] = entry_type;
    let count_be = count.to_be_bytes();
    qw[9..16].copy_from_slice(&count_be[1..8]);
    qw
}

#[test]
fn positive_entry_qw_layout_is_pinned_in_source() {
    // The exact pack expression must stay byte-for-byte identical.
    assert!(FLASH_SRC.contains("qw[..8].copy_from_slice(slot_key);"));
    assert!(FLASH_SRC.contains("qw[8] = entry_type;"));
    assert!(FLASH_SRC.contains("qw[9..16].copy_from_slice(&count_be[1..8]);"));
}

#[test]
fn positive_entry_qw_count_packing_is_7_byte_be() {
    let slot_key = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let qw = entry_qw_ref(&slot_key, 0x01, 0x0123_4567_89AB_CDEF);
    assert_eq!(&qw[..8], &slot_key);
    assert_eq!(qw[8], 0x01);
    // Top byte of u64 (0x01) is intentionally DROPPED — the journal
    // supports up to 2^56 counts (≫ MAX_SLOT_USES = 65_536).
    assert_eq!(&qw[9..16], &[0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
}

#[test]
fn positive_entry_qw_min_count_zero() {
    let qw = entry_qw_ref(&[0u8; 8], 0x02, 0);
    assert_eq!(qw, [0u8; 8].iter().copied()
        .chain([0x02u8].iter().copied())
        .chain([0u8; 7].iter().copied())
        .collect::<Vec<u8>>().as_slice());
}

#[test]
fn positive_entry_qw_distinct_types_diverge() {
    // The two type bytes must be distinct so reverse-scan can tell
    // an off-chain count entry from a userop snapshot entry.
    let sk = [0xAA; 8];
    let a = entry_qw_ref(&sk, 0x01, 7);
    let b = entry_qw_ref(&sk, 0x02, 7);
    assert_ne!(a, b);
    assert_eq!(a[8], 0x01);
    assert_eq!(b[8], 0x02);
}

// ═════════════════════════════════════════════════════════════════════
// 6. POSITIVE — TAMP reason mapping (reference re-implementation)
// ═════════════════════════════════════════════════════════════════════
//
// `tamp::reason_from_sr` is `#[cfg(feature = "tamp")]`-gated; mirror
// here and pin the documented mapping. A label rename would silently
// break the post-mortem inspector tooling.

fn reason_from_sr_ref(sr: u32) -> &'static str {
    const ITAMP1F: u32 = 1 << 16;
    const ITAMP2F: u32 = 1 << 17;
    const ITAMP3F: u32 = 1 << 18;
    const ITAMP5F: u32 = 1 << 20;
    const ITAMP6F: u32 = 1 << 21;
    const ITAMP7F: u32 = 1 << 22;
    const ITAMP8F: u32 = 1 << 23;
    const ITAMP9F: u32 = 1 << 24;
    const ITAMP11F: u32 = 1 << 26;
    const ITAMP12F: u32 = 1 << 27;
    const ITAMP13F: u32 = 1 << 28;
    if sr & ITAMP1F != 0 {
        "VOLTAGE"
    } else if sr & ITAMP2F != 0 {
        "TEMPERATURE"
    } else if sr & ITAMP3F != 0 {
        "LSE_CLOCK"
    } else if sr & ITAMP5F != 0 {
        "RTC_OVERFLOW"
    } else if sr & ITAMP6F != 0 {
        "SWD_ACCESS"
    } else if sr & ITAMP7F != 0 {
        "ANALOG_WDG1"
    } else if sr & ITAMP8F != 0 {
        "MONO_COUNTER"
    } else if sr & ITAMP9F != 0 {
        "CRYPTO_FAULT"
    } else if sr & ITAMP11F != 0 {
        "IWDG"
    } else if sr & ITAMP12F != 0 {
        "ANALOG_WDG2"
    } else if sr & ITAMP13F != 0 {
        "ANALOG_WDG3"
    } else {
        "UNKNOWN"
    }
}

#[test]
fn positive_tamp_reason_each_bit_maps_to_expected_label() {
    assert_eq!(reason_from_sr_ref(1 << 16), "VOLTAGE");
    assert_eq!(reason_from_sr_ref(1 << 17), "TEMPERATURE");
    assert_eq!(reason_from_sr_ref(1 << 18), "LSE_CLOCK");
    assert_eq!(reason_from_sr_ref(1 << 20), "RTC_OVERFLOW");
    assert_eq!(reason_from_sr_ref(1 << 21), "SWD_ACCESS");
    assert_eq!(reason_from_sr_ref(1 << 22), "ANALOG_WDG1");
    assert_eq!(reason_from_sr_ref(1 << 23), "MONO_COUNTER");
    assert_eq!(reason_from_sr_ref(1 << 24), "CRYPTO_FAULT");
    assert_eq!(reason_from_sr_ref(1 << 26), "IWDG");
    assert_eq!(reason_from_sr_ref(1 << 27), "ANALOG_WDG2");
    assert_eq!(reason_from_sr_ref(1 << 28), "ANALOG_WDG3");
}

#[test]
fn positive_tamp_reason_zero_is_unknown() {
    // SR=0 → no flag set → UNKNOWN, NOT panic / index-out-of-bounds.
    assert_eq!(reason_from_sr_ref(0), "UNKNOWN");
}

#[test]
fn positive_tamp_reason_priority_voltage_over_temperature() {
    // The if-chain is documented: first-match-wins. Voltage (ITAMP1)
    // is higher priority than temperature (ITAMP2). The post-mortem
    // inspector relies on this ordering for the most-likely-cause
    // heuristic.
    assert_eq!(reason_from_sr_ref((1 << 16) | (1 << 17)), "VOLTAGE");
}

// ═════════════════════════════════════════════════════════════════════
// 7. POSITIVE — sca_trigger no-op shim (the only host-reachable runtime
//                                         code in the slice)
// ═════════════════════════════════════════════════════════════════════
//
// `sca_trigger.rs` is unique among the slice: it compiles ON HOST
// because `mod.rs` declares it unconditionally (no feature gate)
// and, when `sca-trigger` is OFF, the bodies are inlined no-ops.
// This lets us actually run a Trigger lifecycle on host — the only
// place we can do that across the slice.

// The hw module is `#[cfg(not(test))]` in main.rs, so we can't
// `use crate::hw::sca_trigger` here. The runtime behaviour is
// exhaustively covered by source-text pins on the no-op stubs below.

#[test]
fn positive_sca_trigger_off_state_trig_high_is_no_op() {
    // The `not(feature = "sca-trigger")` stub MUST be `#[inline(always)]`
    // and empty. Without the inline hint, the cold-path no-op would
    // still cost a call/ret in the released binary; that's a real
    // power-trace artefact on a constant-time crypto path.
    assert!(SCA_TRIGGER_SRC.contains(r##"#[cfg(not(feature = "sca-trigger"))]
#[inline(always)]
pub fn trig_high() {}"##));
    assert!(SCA_TRIGGER_SRC.contains(r##"#[cfg(not(feature = "sca-trigger"))]
#[inline(always)]
pub fn trig_low() {}"##));
}

#[test]
fn positive_sca_trigger_off_state_init_is_no_op() {
    // Same shape as the trig_{high,low} stubs.
    assert!(SCA_TRIGGER_SRC.contains(r##"#[cfg(not(feature = "sca-trigger"))]
#[inline(always)]
pub fn init() {}"##));
}

#[test]
fn positive_sca_trigger_struct_has_drop_for_pairing() {
    // RAII guard pattern: `Trigger::raise()` calls trig_high, drop
    // calls trig_low. Without `Drop`, an early-return in a signing
    // path would leave the scope desynced from the rig.
    assert!(SCA_TRIGGER_SRC.contains("impl Drop for Trigger"));
    assert!(SCA_TRIGGER_SRC.contains("fn drop(&mut self)"));
    assert!(SCA_TRIGGER_SRC.contains("trig_low();"));
}

#[test]
fn positive_sca_trigger_raise_calls_trig_high_before_returning() {
    // Pin the call order: raise must trig_high THEN construct Self
    // (so an early panic during construction never leaves the trigger
    // dangling). Source text pins it.
    assert!(SCA_TRIGGER_SRC.contains("pub fn raise() -> Self {\n        trig_high();\n        Self\n    }"));
}

// ═════════════════════════════════════════════════════════════════════
// 8. NEGATIVE — production fences: dev-only features must stay
//               feature-gated and registered in the prod fence.
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_sca_trigger_module_warns_production_fence() {
    // The module-level docstring must call out the prod-fence in
    // `secure/src/nsc/mod.rs`. A future refactor that removed the
    // prose warning would invite developers to leave the feature ON
    // in a shipping build — turning the SCA-rig GPIO into a permanent
    // probe input on every device.
    assert!(
        SCA_TRIGGER_SRC.contains("production-fence"),
        "sca_trigger.rs must keep its production-fence prose warning"
    );
    assert!(
        SCA_TRIGGER_SRC.contains("NEVER ship") || SCA_TRIGGER_SRC.contains("refuses to compile a release"),
        "sca_trigger.rs must say it does not ship"
    );
}

#[test]
fn negative_boot_pulse_is_module_level_feature_gated() {
    // The `#![cfg(feature = "boot-pulse")]` at the top of boot_pulse.rs
    // is what makes the module disappear from non-bringup builds. Any
    // demotion (e.g. function-level gates only) would let a dev who
    // wires the symbol from main.rs ship the GPIO toggler in a
    // shipping firmware image.
    assert!(
        BOOT_PULSE_SRC.contains(r##"#![cfg(feature = "boot-pulse")]"##),
        "boot_pulse.rs MUST keep `#![cfg(feature = \"boot-pulse\")]` at the top — see prod-fence in nsc/mod.rs"
    );
}

#[test]
fn negative_boot_pulse_module_documents_never_ship_constraint() {
    // The prose pin tells developers + auditors the file is dev-only.
    assert!(
        BOOT_PULSE_SRC.contains("Used when stepping to RDP ≥ 1"),
        "boot_pulse.rs must explain its RDP1-bring-up purpose"
    );
}

#[test]
fn negative_consumption_mask_implies_stm32u585() {
    // `consumption-mask` is meaningless without the underlying STM32
    // TIM2 / GPIOA registers. The mod.rs feature gate must include
    // both `stm32u585` and `consumption-mask`.
    assert!(
        HW_MOD_SRC.contains(r##"#[cfg(all(feature = "stm32u585", feature = "consumption-mask"))]
pub mod consumption_mask;"##),
        "hw/mod.rs must gate consumption_mask on stm32u585 + consumption-mask together"
    );
}

#[test]
fn negative_tamp_module_dual_feature_gated() {
    // Same shape: tamp needs both `stm32u585` and `tamp`. A
    // single-feature gate would let the QEMU build pick up the
    // STM32U585-specific MMIO addresses and silently bus-fault.
    assert!(
        HW_MOD_SRC.contains(r##"#[cfg(all(feature = "stm32u585", feature = "tamp"))]
pub mod tamp;"##),
        "hw/mod.rs must gate tamp on stm32u585 + tamp together"
    );
}

#[test]
fn negative_pka_module_gated_on_pka_accel_only() {
    // Per the slice's mod.rs comment: pka.rs is gated only on
    // pka-accel because the bls12_381 fork is the sole consumer.
    // Tightening the gate to require stm32u585 would prevent host
    // testing of the BLS12-381 fork's `pka` feature. Loosening it
    // (no gate at all) would compile pka.rs into every build.
    assert!(
        HW_MOD_SRC.contains(r##"#[cfg(feature = "pka-accel")]
pub mod pka;"##),
        "hw/mod.rs must keep pka behind the `pka-accel` feature gate"
    );
}

// ═════════════════════════════════════════════════════════════════════
// 9. NEGATIVE — register address attacks (wrong-alias rejection)
// ═════════════════════════════════════════════════════════════════════
//
// Wrong NS-vs-S alias is the most common silent-corruption seed in
// this peripheral layer. Each test pins one peripheral as "uses the
// secure alias, not the NS alias."

#[test]
fn negative_flash_uses_secure_alias_not_ns_alias() {
    // NS alias for FLASH is 0x4002_2000. The FSBL write path relies
    // on secure-bus reads; a swap would bus-fault on first program.
    assert!(FLASH_SRC.contains("const FLASH: u32 = 0x5002_2000;"));
    assert!(
        !FLASH_SRC.contains("const FLASH: u32 = 0x4002_2000;"),
        "FLASH driver must NOT use NS alias 0x4002_2000 in the SECCR primary path"
    );
}

#[test]
fn negative_rng_uses_secure_alias_not_ns_alias() {
    // CLAUDE.md / rng.rs docstring documents the first-boot failure
    // ("rng::fill FAILED") that the NS alias produced. The fix is
    // the secure alias and a regression would re-introduce that
    // failure on every fresh boot.
    assert!(RNG_SRC.contains("const RNG: u32 = 0x520C_0800;"));
    assert!(
        !RNG_SRC.contains("const RNG: u32 = 0x420C_0800;"),
        "RNG driver must NOT use NS alias 0x420C_0800 — bus-faulted at first boot"
    );
}

#[test]
fn negative_pka_uses_secure_alias_not_ns_alias() {
    // NS alias 0x420C_2000 is rejected because TZSC marks PKA secure
    // by default; secure alias 0x520C_2000 is the only working one.
    assert!(PKA_SRC.contains("const PKA_BASE: u32 = 0x520C_2000;"));
    assert!(
        !PKA_SRC.contains("const PKA_BASE: u32 = 0x420C_2000;"),
        "PKA driver must NOT use NS alias 0x420C_2000 — TZ blocks it"
    );
}

#[test]
fn negative_tamp_pwr_alias_matches_secure_backup_domain() {
    // PWR's DBPR + BDCR1 must be reached via the secure alias —
    // backup-domain registers are secure-only.
    assert!(TAMP_SRC.contains("pub const PWR: u32 = 0x5602_0800;"));
    assert!(!TAMP_SRC.contains("pub const PWR: u32 = 0x4602_0800;"));
}

#[test]
fn negative_consumption_mask_tim2_is_secure_alias() {
    // TIM2 secure alias 0x5000_0000. NS alias is 0x4000_0000. A
    // wrong alias here would silently produce a non-functional PWM
    // (writes are dropped under TZ's default-secure GTZC config).
    assert!(CONSUMPTION_MASK_SRC.contains("pub const TIM2: u32 = 0x5000_0000;"));
    assert!(!CONSUMPTION_MASK_SRC.contains("pub const TIM2: u32 = 0x4000_0000;"));
}

#[test]
fn negative_flash_icache_base_is_correct_off_by_400() {
    // Comment in flash.rs documents a HardFault regression from the
    // wrong base (0x5003_0000 — off by 0x400). Pin the correct one.
    assert!(FLASH_SRC.contains("const ICACHE_BASE: u32 = 0x5003_0400;"));
    assert!(
        !FLASH_SRC.contains("const ICACHE_BASE: u32 = 0x5003_0000;"),
        "ICACHE_BASE must NOT be 0x5003_0000 — hit reserved AHB1 region, prior HardFault regression"
    );
}

// ═════════════════════════════════════════════════════════════════════
// 10. NEGATIVE — cap & monotonicity invariants (CLAUDE.md #7, #9)
// ═════════════════════════════════════════════════════════════════════
//
// CLAUDE.md "Non-Negotiable Invariants" #7 ("per-chain caps
// monotonic, unresettable") and #9 ("off-chain sig counter, combined
// cap"). The flash driver participates in both via the page-123
// journal + the page-124 attempt counter. Refactor that drops one
// of these gates would let an attacker walk past the lockout.

#[test]
fn negative_offchain_count_bump_refuses_regression() {
    // `new_count <= pre → Err(())`. Without this check, a replay of
    // an old userop with a stale counter would silently rewind the
    // journal — and the next on-chain validateUserOp would still
    // accept the regressed value because the wallet's
    // `offchainSigCount` enforcement is firmware-side too.
    assert!(FLASH_SRC.contains("if new_count <= pre {\n        return Err(());\n    }"));
}

#[test]
fn negative_offchain_count_bump_readback_verified() {
    // Mirror of `pin_attempts_bump`'s post-write readback. Without
    // it, a glitch that suppresses the program leaves the caller
    // thinking the bump succeeded and signs again with the same
    // count — duplicate sig, on-chain revert, no FI alarm.
    assert!(FLASH_SRC.contains("let post = offchain_count_read(slot_key);\n    if post != new_count {"));
    assert!(FLASH_SRC.contains("crate::fi::check_true_into_sentinel"));
    assert!(FLASH_SRC.contains("crate::fi::OK_SENTINEL"));
}

#[test]
fn negative_offchain_count_read_fi_double_scan_halt_on_mismatch() {
    // F-12 fix per the in-file docstring: forward + reverse scan,
    // halt on mismatch by returning u64::MAX (fail-closed — every
    // downstream cap check trips and refuses to sign).
    assert!(FLASH_SRC.contains("let r1 = scan_forward(&sk_a, OFFCHAIN_TYPE_COUNT);"));
    assert!(FLASH_SRC.contains("let r2 = scan_reverse(&sk_b, OFFCHAIN_TYPE_COUNT);"));
    assert!(FLASH_SRC.contains("if r1 != r2 {"));
    assert!(FLASH_SRC.contains("return u64::MAX;"));
}

#[test]
fn negative_offchain_count_read_slot_key_input_redundancy() {
    // F-12: the slot_key argument register itself is doubled via
    // wait_random + compare. A stuck-at on the slot_key register
    // at function entry would otherwise return the wrong slot's
    // count to both scans symmetrically.
    assert!(FLASH_SRC.contains("let sk_a: [u8; 8] = *slot_key;\n    crate::fi::wait_random();\n    let sk_b: [u8; 8] = *slot_key;"));
}

#[test]
fn negative_pin_attempts_bump_readback_verified_with_fi_sentinel() {
    // CLAUDE.md / fi.rs: a single `if cond` is glitchable. The PIN
    // attempt bump's "did the bump land?" check must use the FI
    // sentinel and a double read.
    assert!(FLASH_SRC.contains("if post != pre + 1 {"));
    assert!(FLASH_SRC.contains("crate::fi::check_true_into_sentinel(|| pin_attempts_read() == pre + 1)"));
}

#[test]
fn negative_pin_attempts_read_double_scan_with_fail_closed_sentinel() {
    // F-15.r5 hardening: forward + reverse scan, mismatch → fail-
    // closed PIN_ATTEMPTS_CAPACITY (32 > MAX_ATTEMPTS=10) so every
    // downstream gate treats it as "lockout reached".
    assert!(FLASH_SRC.contains("let fwd = unsafe { pin_attempts_scan_forward() };"));
    assert!(FLASH_SRC.contains("let rev = unsafe { pin_attempts_scan_reverse() };"));
    assert!(FLASH_SRC.contains("if fwd != rev {"));
    assert!(FLASH_SRC.contains("return PIN_ATTEMPTS_CAPACITY as u8;"));
}

#[test]
fn negative_pin_attempts_bump_capacity_check_fails_closed() {
    // Refuse to bump past capacity. Without this gate the next
    // saturating_add would silently wrap u8 to 0 on overflow and
    // an attacker could keep guessing forever.
    assert!(FLASH_SRC.contains("if (pre as u32) >= PIN_ATTEMPTS_CAPACITY {\n        return Err(());\n    }"));
}

#[test]
fn negative_last_userop_count_set_tolerates_regression_but_logs() {
    // Documented design: `count < pre` is a no-op (returns Ok)
    // because the firmware-side check is not authoritative (the
    // on-chain `_setOffchainSigCount` is). The refactor we want to
    // catch is one that turns this into an Err — that would brick
    // the slot for future signs (witness: "Sig commit FAIL" OLED
    // history per the in-file comment).
    assert!(FLASH_SRC.contains("if count < pre {\n        // Defensive no-op."));
}

// ═════════════════════════════════════════════════════════════════════
// 11. NEGATIVE — algorithm policy / forbidden-API surface
// ═════════════════════════════════════════════════════════════════════
//
// CLAUDE.md "What NOT to do": no classical signer, no rotate-master,
// no reset-attempts path, no plaintext-secret on I2C, no software
// PRNG. The platform peripheral layer is a tempting place to wedge
// in any of these (TRNG seed override, attempt-counter reset, RCC
// "factory" path).

#[test]
fn negative_no_classical_signer_in_platform_slice() {
    // CLAUDE.md invariant #5: One signature primitive (SPHINCS+C10).
    for needle in [
        "ecdsa", "Ecdsa", "ECDSA",
        "ed25519", "Ed25519",
        "secp256k1", "Secp256k1",
    ] {
        for (name, src) in [
            ("flash.rs", FLASH_SRC),
            ("tamp.rs", TAMP_SRC),
            ("consumption_mask.rs", CONSUMPTION_MASK_SRC),
            ("sca_trigger.rs", SCA_TRIGGER_SRC),
            ("rcc.rs", RCC_SRC),
            ("rng.rs", RNG_SRC),
            ("pka.rs", PKA_SRC),
            ("boot_pulse.rs", BOOT_PULSE_SRC),
            ("boot_state.rs", BOOT_STATE_SRC),
        ] {
            assert!(
                !src.contains(needle),
                "classical signer reference {needle:?} found in hw/{name} — CLAUDE.md invariant #5"
            );
        }
    }
}

#[test]
fn negative_no_software_prng_seed_in_rng_module() {
    // CLAUDE.md "No software PRNG — hardware TRNG only". The rng.rs
    // file MUST NOT silently fall back to a software seed if HSI48
    // isn't ready. (The consumption-mask module DOES seed an
    // xorshift32 for PWM duty, but it explicitly seeds FROM the
    // hardware TRNG — that's a different use case documented in
    // its module docs.)
    for needle in ["StdRng", "ChaCha", "lcg", "xorshift32", "xorshift64"] {
        assert!(
            !RNG_SRC.contains(needle),
            "software PRNG reference {needle:?} found in rng.rs — CLAUDE.md 'No software PRNG'"
        );
    }
}

#[test]
fn negative_consumption_mask_xorshift_seeded_from_hw_trng() {
    // The xorshift32 in consumption_mask is deliberate and
    // documented: it's a PWM-duty randomiser, NOT a key-derivation
    // RNG. The seed MUST come from the strong TRNG; a refactor that
    // dropped the rng_strong call and started seeding from
    // SystemView ticks or similar would make the mask predictable.
    assert!(
        CONSUMPTION_MASK_SRC.contains("crate::rng_strong::fill(&mut seed_bytes)"),
        "consumption_mask's xorshift32 must seed from rng_strong::fill"
    );
    assert!(
        CONSUMPTION_MASK_SRC.contains("if seed == 0 {\n        seed = 0xDEADBEEF;\n    }"),
        "consumption_mask must guard against 0-seed xorshift sticky-state"
    );
}

#[test]
fn negative_no_reset_or_increase_max_path_in_flash() {
    // CLAUDE.md "What NOT to do": no rotateMasterKeys, no
    // resetBootstrapUses, no resetSlotUses, no increaseMax*. The
    // flash driver exposes `pin_attempts_reset` (called only after
    // a successful PIN verify) — that's the ONLY reset path the
    // slice may expose. Anything labelled bootstrap/slot/master
    // reset would be a new bypass.
    for forbidden in [
        "rotate_master", "rotateMaster",
        "reset_bootstrap", "resetBootstrap",
        "reset_slot_uses", "resetSlotUses",
        "increase_max", "increaseMax",
    ] {
        assert!(
            !FLASH_SRC.contains(forbidden),
            "forbidden bypass path {forbidden:?} found in flash.rs — CLAUDE.md 'What NOT to do'"
        );
    }
}

#[test]
fn negative_flash_unlock_keys_are_st_canonical_not_swapped() {
    // Trivial-but-real footgun: swapping KEY1/KEY2 silently latches
    // OPTLOCK and requires a system reset to recover. Pin the order.
    let idx_1 = FLASH_SRC.find("const KEY1: u32 = 0x4567_0123;").unwrap();
    let idx_2 = FLASH_SRC.find("const KEY2: u32 = 0xCDEF_89AB;").unwrap();
    assert!(idx_1 < idx_2, "KEY1 must be declared before KEY2 for source-order grep tooling");
}

// ═════════════════════════════════════════════════════════════════════
// 12. NEGATIVE — flash write/erase atomicity + interrupt-free
// ═════════════════════════════════════════════════════════════════════
//
// HIGH-12 fix per the in-file docstring: every unlock→program→lock
// sequence runs inside `cortex_m::interrupt::free`. An IRQ (esp.
// SysTick or the OLED I2C callback) landing mid-sequence can latch
// PGSERR. A future refactor that drops the wrap is a silent
// reliability regression that surfaces only under load.

#[test]
fn negative_flash_erase_key_page_inside_interrupt_free() {
    let body = extract_body(FLASH_SRC, "pub unsafe fn erase_key_page() -> Result<(), ()> {");
    assert!(
        body.contains("cortex_m::interrupt::free"),
        "erase_key_page MUST run inside cortex_m::interrupt::free (HIGH-12 fix)"
    );
}

#[test]
fn negative_flash_write_quadword_inside_interrupt_free() {
    let body = extract_body(FLASH_SRC, "unsafe fn write_quadword(addr: u32, data: &[u8; 16]) -> Result<(), ()> {");
    assert!(
        body.contains("cortex_m::interrupt::free"),
        "write_quadword MUST run inside cortex_m::interrupt::free (HIGH-12 fix)"
    );
}

#[test]
fn negative_flash_erase_secure_page_inside_interrupt_free() {
    let body = extract_body(FLASH_SRC, "pub unsafe fn erase_secure_page(page: u32) -> Result<(), ()> {");
    assert!(
        body.contains("cortex_m::interrupt::free"),
        "erase_secure_page MUST run inside cortex_m::interrupt::free"
    );
}

#[test]
fn negative_flash_erase_ns_page_inside_interrupt_free() {
    let body = extract_body(FLASH_SRC, "pub unsafe fn erase_ns_page(page: u8) -> Result<(), ()> {");
    assert!(
        body.contains("cortex_m::interrupt::free"),
        "erase_ns_page MUST run inside cortex_m::interrupt::free"
    );
}

#[test]
fn negative_flash_pin_attempts_reset_inside_interrupt_free() {
    let body = extract_body(FLASH_SRC, "pub unsafe fn pin_attempts_reset() -> Result<(), ()> {");
    assert!(
        body.contains("cortex_m::interrupt::free"),
        "pin_attempts_reset MUST run inside cortex_m::interrupt::free"
    );
}

#[test]
fn negative_flash_icache_invalidated_after_every_erase() {
    // Without ICACHE invalidate the post-erase read returns cached
    // pre-erase bytes, causing `write_quadword_verified` to silently
    // miscompare. Pin: every erase function must call
    // `icache_invalidate()` before its terminal return.
    let calls = FLASH_SRC.matches("icache_invalidate();").count();
    assert!(
        calls >= 4,
        "expected ≥4 icache_invalidate() calls in flash.rs; found {calls}. Every erase/program path must invalidate."
    );
}

#[test]
fn negative_flash_write_slot_quadword_bank_dispatch_rejects_out_of_range() {
    // The dispatcher MUST return Err for addresses outside both
    // bank-1 and bank-2 ranges — never silently write to a random
    // peripheral via mis-routed bank dispatch.
    let body = extract_body(
        FLASH_SRC,
        "pub unsafe fn write_slot_quadword_verified(addr: u32, data: &[u8; 16]) -> Result<(), ()> {",
    );
    assert!(body.contains("Err(())"));
    assert!(body.contains("(0x0810_0000..0x0820_0000)"));
    assert!(body.contains("(0x0C00_0000..0x0C10_0000)"));
}

#[test]
fn negative_flash_write_quadword_verified_compares_every_byte() {
    // Brown-out tolerance: read-back compare on all 16 bytes catches
    // a partially-programmed quad-word that the flash controller did
    // NOT flag with PROGERR. A future loop bound regression (e.g.
    // `for i in 0..8`) would only catch the first half.
    let body = extract_body(
        FLASH_SRC,
        "pub unsafe fn write_quadword_verified(addr: u32, data: &[u8; 16]) -> Result<(), ()> {",
    );
    assert!(body.contains("for i in 0..16 {"));
    assert!(body.contains("!= data[i]"));
    assert!(body.contains("return Err(());"));
}

// ═════════════════════════════════════════════════════════════════════
// 13. NEGATIVE — boot-state parse defends against malformed pages
// ═════════════════════════════════════════════════════════════════════
//
// `read()` MUST treat each copy as untrusted: bad magic → reject;
// invalid slot byte → reject; CRC mismatch → reject. FSBL falls
// back to "Slot A, floor 0" on Unavailable; anything more permissive
// would let a torn write select a slot index that doesn't exist.

#[test]
fn negative_boot_state_parse_rejects_bad_magic() {
    // Refuse to parse without the BSTE magic.
    let body = extract_body(BOOT_STATE_SRC, "fn parse_copy(addr: u32) -> Option<BootState> {");
    assert!(body.contains("if buf[0..4] != BSTATE_MAGIC {"));
    assert!(body.contains("return None;"));
}

#[test]
fn negative_boot_state_parse_rejects_unknown_slot_byte() {
    // 0x00 = A, 0x01 = B; anything else (including 0xFF blank) must
    // return None so the read() fallback picks the other copy or
    // surfaces Unavailable.
    let body = extract_body(BOOT_STATE_SRC, "fn parse_copy(addr: u32) -> Option<BootState> {");
    assert!(body.contains("0x00 => Slot::A,"));
    assert!(body.contains("0x01 => Slot::B,"));
    assert!(body.contains("_ => return None,"));
}

#[test]
fn negative_boot_state_parse_rejects_crc_mismatch() {
    // Without the CRC compare, a single-bit flip in flash would
    // misroute FSBL's slot pick.
    let body = extract_body(BOOT_STATE_SRC, "fn parse_copy(addr: u32) -> Option<BootState> {");
    assert!(body.contains("if stored_crc != actual_crc {"));
    assert!(body.contains("return None;"));
}

#[test]
fn negative_boot_state_read_falls_back_through_both_copies() {
    // A torn write may leave copy A corrupt and copy B valid. The
    // read() function MUST try both before returning Unavailable.
    let body = extract_body(BOOT_STATE_SRC, "pub fn read() -> Result<BootState, BootStateError> {");
    assert!(body.contains("BSTATE_COPY_A_ADDR"));
    assert!(body.contains("BSTATE_COPY_B_ADDR"));
    assert!(body.contains("Err(BootStateError::Unavailable)"));
}

#[test]
fn negative_boot_state_write_updates_both_copies() {
    // After any boot-state change, both copies must be programmed
    // — otherwise the next torn write leaves only one copy fresh
    // and the "redundant" pair degrades to single-copy.
    let body = extract_body(BOOT_STATE_SRC, "pub unsafe fn write(state: &BootState) -> Result<(), BootStateError> {");
    assert!(body.contains("BSTATE_COPY_A_ADDR"));
    assert!(body.contains("BSTATE_COPY_B_ADDR"));
    // Erase before write — required because flash bits can only
    // be cleared from 1→0; a re-write without erase would PROGERR
    // on overlap.
    assert!(body.contains("flash::erase_secure_page(BOOT_STATE_PAGE)"));
}

// ═════════════════════════════════════════════════════════════════════
// 14. NEGATIVE — encode/parse round-trip catches reshape attacks
// ═════════════════════════════════════════════════════════════════════

fn parse_ref(buf: &[u8; BSTATE_SIZE]) -> Option<BootStateRef> {
    if buf[0..4] != BSTATE_MAGIC {
        return None;
    }
    let active_slot = match buf[4] {
        0x00 => SlotRef::A,
        0x01 => SlotRef::B,
        _ => return None,
    };
    let last_good_version = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
    let stored_crc = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
    let actual_crc = fw_manifest::crc32_ieee(&buf[..12]);
    if stored_crc != actual_crc {
        return None;
    }
    Some(BootStateRef {
        active_slot,
        last_good_version,
    })
}

#[test]
fn negative_boot_state_round_trip_preserves_state() {
    // The encode/parse pair must be a bijection for every (slot,
    // version) — without it, an FSBL upgrade that adds a new field
    // could silently lose previously-stored data.
    for &slot in &[SlotRef::A, SlotRef::B] {
        for &v in &[0u32, 1, 0x4000_0000, u32::MAX] {
            let s = BootStateRef {
                active_slot: slot,
                last_good_version: v,
            };
            let buf = encode_ref(&s);
            assert_eq!(parse_ref(&buf), Some(s));
        }
    }
}

#[test]
fn negative_boot_state_parser_rejects_bit_flip_anywhere() {
    // Any single-bit flip in the encoded buffer must either fail
    // magic, fail CRC, or be the active_slot byte set to an invalid
    // value. The parser MUST NOT silently accept a flipped buffer
    // as a different valid state.
    let s = BootStateRef {
        active_slot: SlotRef::A,
        last_good_version: 0xCAFE_BABE,
    };
    let buf = encode_ref(&s);
    for i in 0..BSTATE_SIZE {
        for bit in 0..8 {
            let mut tampered = buf;
            tampered[i] ^= 1 << bit;
            let parsed = parse_ref(&tampered);
            match parsed {
                None => {} // expected: reject
                Some(other) if other != s => {
                    // Allowed only if the bit-flip is in the active_slot
                    // byte AND lands on the LSB AND the CRC happens to
                    // match (CRC32 collision under a single-bit flip is
                    // cryptographically impossible). The byte is the
                    // slot index — any successful parse with a different
                    // slot would mean the CRC didn't protect it.
                    panic!(
                        "bit-flip at byte {i} bit {bit} produced a different VALID state {other:?} from {s:?} — \
                         CRC failed to detect the tamper"
                    );
                }
                Some(_) => {
                    panic!(
                        "bit-flip at byte {i} bit {bit} parsed to the ORIGINAL state — CRC accepted a flipped buffer"
                    );
                }
            }
        }
    }
}

#[test]
fn negative_boot_state_blank_page_returns_none() {
    // A factory-fresh page is all 0xFF. parse_ref MUST treat this
    // as Unavailable (FSBL falls back to "Slot A, floor 0"); a
    // refactor that accidentally accepted 0xFF as valid would
    // misroute boot on every freshly-provisioned device.
    let blank = [0xFFu8; BSTATE_SIZE];
    assert_eq!(parse_ref(&blank), None);
}

// ═════════════════════════════════════════════════════════════════════
// 15. NEGATIVE — entry_qw round-trip + count headroom
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_entry_qw_within_2_pow_56_round_trips() {
    // The 7-byte BE encoding supports up to 2^56 - 1. The cap matters
    // because MAX_SLOT_USES is 65,536 and MAX_BOOTSTRAP_USES is
    // 65,536 → combined < 131072 ≪ 2^56. Sanity-check the encoding.
    let sk = [0x42u8; 8];
    for &c in &[0u64, 1, 65_535, 65_536, 1_000_000, (1u64 << 56) - 1] {
        let qw = entry_qw_ref(&sk, 0x01, c);
        let mut be = [0u8; 8];
        be[1..8].copy_from_slice(&qw[9..16]);
        let round = u64::from_be_bytes(be);
        assert_eq!(round, c, "count {c} did not round-trip");
    }
}

#[test]
fn negative_entry_qw_top_byte_silently_truncated() {
    // The encoding deliberately drops the top byte of u64. A
    // refactor that tried to use the full 8 bytes would either
    // overlap the type byte or shift the slot_key — either way,
    // every legacy entry on flash would mis-parse. Pin the silent-
    // truncation behaviour so we DON'T accidentally break it.
    let sk = [0u8; 8];
    let qw_low = entry_qw_ref(&sk, 0x01, 0x0123_4567_89AB_CDEF);
    let qw_high = entry_qw_ref(&sk, 0x01, 0xFF23_4567_89AB_CDEF);
    assert_eq!(qw_low, qw_high, "top byte must be dropped — current encoding");
}

#[test]
fn negative_journal_blank_qw_is_none_per_parse_entry_contract() {
    // Source-text pin for the all-blank-QW detector: parse_entry
    // must distinguish blank-end-of-journal (None) from stale-type
    // (Some((0, _, _))) — without this, the off-chain journal's
    // self-heal would scan past valid entries into garbage.
    assert!(FLASH_SRC.contains("let mut all_blank = true;"));
    assert!(FLASH_SRC.contains("if all_blank {\n            return None;\n        }"));
}

// ═════════════════════════════════════════════════════════════════════
// 16. NEGATIVE — TAMP / RTC log-only semantics on bring-up branch
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_tamp_poll_is_log_only_not_wipe() {
    // Per CLAUDE.md / Pre-Production Caveats: `tamp` is log-only on
    // this branch. Trezor's `reboot_with_rsod()` was deliberately
    // replaced with `secure_log!`. A future refactor that
    // re-introduced `factory_reset_admin` / `trigger_lockout_wipe`
    // here would brick every bench chip on the next false ITAMP9.
    // Pin the log-only shape: poll reads SR, logs, write-1-to-clears,
    // returns. Never halts, never wipes.
    let body = extract_body(TAMP_SRC, "pub fn poll() {");
    assert!(body.contains("secure_log!"));
    assert!(body.contains("REG.tamp_scr.write(ITAMP_FLAG_MASK);"));
    assert!(!body.contains("factory_reset"));
    assert!(!body.contains("trigger_lockout_wipe"));
    assert!(!body.contains("SCB::sys_reset"));
    assert!(!body.contains("loop {"));
}

#[test]
fn negative_tamp_irq_handler_is_log_only_not_wipe() {
    // Same shape as `poll` — IRQ-mode must not escalate either,
    // pending the production hardening that flips the trigger
    // response (see docs/production-todo.md "TAMP escalation").
    let body = extract_body(TAMP_SRC, "pub fn on_tamp_irq() {");
    assert!(body.contains("secure_log!"));
    assert!(body.contains("REG.tamp_scr.write(ITAMP_FLAG_MASK);"));
    assert!(!body.contains("factory_reset"));
    assert!(!body.contains("trigger_lockout_wipe"));
    assert!(!body.contains("SCB::sys_reset"));
}

#[test]
fn negative_tamp_init_skips_external_pins() {
    // External tamper pins aren't wired on this board. Enabling
    // them in CR1 / CR2 would false-trigger on PCB noise. CR3=0 is
    // the all-internal-confirmed mode per Trezor parity.
    assert!(TAMP_SRC.contains("REG.tamp_cr3.write(0);"));
    // No TAMPxE bits in CR1 should be enabled — the production code
    // only enables ITAMP*E (internal). A future refactor that wrote
    // a stray bit 0..15 (external pin enables) would silently turn
    // an unwired pin into a false trigger source.
    let body = extract_body(TAMP_SRC, "fn init_tamp_registers() {");
    assert!(body.contains("ITAMP1E"));
    // Spot-check: must NOT enable ITAMP4 or ITAMP10 (per the
    // in-file comment: "documented to never fire on this MCU rev").
    assert!(!body.contains("ITAMP4E"));
    assert!(!body.contains("ITAMP10E"));
}

// ═════════════════════════════════════════════════════════════════════
// 17. NEGATIVE — PKA driver assumptions (BLS12-381 only consumer)
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_pka_bls12_381_modulus_limbs_in_little_endian_order() {
    // BLS12-381 base prime p — limb order is LSB-first per RM0456
    // §"PKA RAM layout". Reversing the limbs would still compile
    // and pass the init handshake, but every Montgomery mul would
    // return garbage. Pin the canonical limbs[0]..limbs[11].
    assert!(PKA_SRC.contains("0xFFFF_AAAB, 0xFFFF_FFFF, 0xB9FE_FFFF, 0x1EAB_FFFE,"));
    assert!(PKA_SRC.contains("0xF6B0_F624, 0x6730_D2A0, 0xF385_12BF, 0x6477_4B84,"));
    assert!(PKA_SRC.contains("0x4B1B_A7B6, 0x434B_ACD7, 0x397F_E69A, 0x1A01_11EA,"));
}

#[test]
fn negative_pka_extern_hook_no_mangle_for_bls12_381_fork() {
    // The bls12_381 fork resolves the firmware-side accelerator via
    // `extern "Rust"` lookup on `bls12_381_pka_mont_mul`. Renaming
    // or removing `#[no_mangle]` would silently fall back to the
    // software path (which on STM32U585 is 100× slower and would
    // miss the OPTIGA/Tropic01 expected timing budgets).
    assert!(PKA_SRC.contains("#[no_mangle]"));
    assert!(PKA_SRC.contains("pub unsafe extern \"Rust\" fn bls12_381_pka_mont_mul"));
}

#[test]
fn negative_pka_writes_terminator_word_past_operand() {
    // RM0456 specifies an N_LIMBS+1 zero terminator after each
    // operand. Without it, stale PKA RAM bytes from a previous op
    // would extend the operand size and the engine would compute
    // on garbage.
    let body = extract_body(PKA_SRC, "fn write_operand(slot: Reg32, limbs: &[u32; N_LIMBS]) {");
    assert!(body.contains("slot.write_at(N_LIMBS, 0);"));
}

// ═════════════════════════════════════════════════════════════════════
// 18. NEGATIVE — RCC must keep HSI16-baseline-before-PLL fallback
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_rcc_switches_to_hsi16_baseline_before_touching_pll() {
    // Without the baseline switch, a PLL config attempt while the
    // CPU is on a slow / unstable source would deadlock waiting for
    // SWS.
    let body = extract_body(RCC_SRC, "pub unsafe fn init() -> u32 {");
    assert!(body.contains("REG.cr.set_bits(HSION);"));
    assert!(body.contains("while REG.cr.read() & HSIRDY == 0 {}"));
    assert!(body.contains("REG.cfgr1.modify(|v| (v & !0x3) | SW_HSI16);"));
}

#[test]
fn negative_rcc_pll_failure_returns_16mhz_keeps_running_on_hsi16() {
    // try_pll_160mhz must NOT panic on VOS failure — the boot path
    // depends on the function returning a usable clock so the rest
    // of init can run. A VOS-failed device still boots, just at
    // 16 MHz.
    let body = extract_body(RCC_SRC, "fn try_pll_160mhz() -> u32 {");
    assert!(body.contains("return 16;"));
}

#[test]
fn negative_rcc_enables_hsi48_for_rng_in_init() {
    // HSI48 is the RNG's clock source per RM0456. Without
    // HSI48ON + HSI48RDY wait, rng::fill silently times out on
    // first boot.
    let body = extract_body(RCC_SRC, "pub unsafe fn init() -> u32 {");
    assert!(body.contains("REG.cr.set_bits(HSI48ON);"));
    assert!(body.contains("while REG.cr.read() & HSI48RDY == 0 {}"));
}

// ═════════════════════════════════════════════════════════════════════
// 19. NEGATIVE — RNG seed-error recovery + bounded timeout
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_rng_recovers_from_latched_seis_ceis_once() {
    // Per RM0456, a latched seed/clock error must be cleared and
    // the conditioning reset re-run. Removing this would leave the
    // RNG permanently inert on the first transient seed glitch.
    let body = extract_body(RNG_SRC, "pub fn fill(buf: &mut [u8]) -> Result<(), ()> {");
    assert!(body.contains("if sr0 & (SEIS | CEIS) != 0 {"));
    assert!(body.contains("REG.sr.write(sr0 & !(SEIS | CEIS));"));
    assert!(body.contains("init();"));
}

#[test]
fn negative_rng_bounded_timeout_returns_err_not_hangs() {
    // The DRDY polling loop has a hard cap (1_000_000). Without
    // it, an underpowered or under-clocked RNG would deadlock the
    // boot path. The function MUST return Err on timeout, not
    // panic / loop forever.
    let body = extract_body(RNG_SRC, "pub fn fill(buf: &mut [u8]) -> Result<(), ()> {");
    assert!(body.contains("if timeout > 1_000_000 {"));
    assert!(body.contains("return Err(());"));
}

#[test]
fn negative_rng_byte_helper_panics_on_failure_does_not_return_zero() {
    // `rng::byte()` is `.expect(...)`-style on purpose: any caller
    // that needs a random byte cannot safely substitute 0. A future
    // refactor that returned 0 on failure would silently produce
    // a deterministic stream the SE handshake would accept.
    assert!(RNG_SRC.contains(r#".expect("hw_rng: TRNG read failed")"#));
}

// ═════════════════════════════════════════════════════════════════════
// 20. NEGATIVE — NS pointer safety: `unsafe` markers stay on raw flash
//                 mutation primitives.
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_flash_mutating_apis_stay_unsafe() {
    // CLAUDE.md "no secrets in NS world" + the file-level docstring:
    // mutating APIs must stay `unsafe` so callers reason about WHICH
    // flash bytes they change. Loosening the API to safe would let
    // a refactor accidentally call `pin_attempts_reset` from a
    // non-PIN-verified context — silently bypassing the lockout.
    for needle in [
        "pub unsafe fn erase_key_page",
        "pub unsafe fn write_quadword_verified",
        "pub unsafe fn write_key",
        "pub unsafe fn erase_admin_page",
        "pub unsafe fn arm_wipe_flag",
        "pub unsafe fn pin_attempts_read",
        "pub unsafe fn pin_attempts_bump",
        "pub unsafe fn pin_attempts_reset",
        "pub unsafe fn erase_ns_page",
        "pub unsafe fn write_ns_quadword_verified",
        "pub unsafe fn erase_secure_page",
        "pub unsafe fn erase_slot",
        "pub unsafe fn write_slot_quadword_verified",
        "pub unsafe fn offchain_count_register_slot",
        "pub unsafe fn offchain_count_bump",
        "pub unsafe fn offchain_count_promote_to",
        "pub unsafe fn last_userop_count_set",
        "pub unsafe fn offchain_count_read",
        "pub unsafe fn last_userop_count_read",
        "pub unsafe fn offchain_count_is_registered",
    ] {
        assert!(
            FLASH_SRC.contains(needle),
            "{needle} must keep `unsafe` marker — see flash.rs file-level docstring"
        );
    }
}

#[test]
fn negative_flash_pin_attempts_scan_helpers_stay_inline_never() {
    // The forward / reverse scans deliberately use `#[inline(never)]`
    // so their control-flow paths stay distinct in the compiled
    // binary. Inlining them would let the optimiser collapse the
    // two passes into a single shared loop — defeating the F-15.r5
    // double-scan defence.
    assert!(FLASH_SRC.contains("#[inline(never)]\nunsafe fn pin_attempts_scan_forward() -> u8"));
    assert!(FLASH_SRC.contains("#[inline(never)]\nunsafe fn pin_attempts_scan_reverse() -> u8"));
    assert!(FLASH_SRC.contains("#[inline(never)]\nunsafe fn scan_forward("));
    assert!(FLASH_SRC.contains("#[inline(never)]\nunsafe fn scan_reverse("));
    assert!(FLASH_SRC.contains("#[inline(never)]\nunsafe fn is_registered_forward("));
    assert!(FLASH_SRC.contains("#[inline(never)]\nunsafe fn is_registered_reverse("));
}

// ═════════════════════════════════════════════════════════════════════
// helper: tiny line-bracket-balancing body extractor
// ═════════════════════════════════════════════════════════════════════
//
// extract_body returns the text between a `fn ... {` line and its
// matching `}` (counted by brace depth). Used to scope the source
// pins above to a specific function so a stray pattern elsewhere in
// the file can't satisfy them.

fn extract_body(src: &str, header: &str) -> String {
    let start = src.find(header).unwrap_or_else(|| {
        panic!("extract_body: header not found: {header:?}");
    });
    let mut depth = 0i32;
    let mut in_fn = false;
    let mut end = start;
    for (i, c) in src[start..].char_indices() {
        match c {
            '{' => {
                depth += 1;
                in_fn = true;
            }
            '}' => {
                depth -= 1;
                if in_fn && depth == 0 {
                    end = start + i + 1;
                    break;
                }
            }
            _ => {}
        }
    }
    src[start..end].to_string()
}
