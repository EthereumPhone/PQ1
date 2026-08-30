//! Host-side positive + negative test suite for the `secure-hw-io`
//! slice.
//!
//! Slice files in scope:
//!   - `secure/src/hw/i2c_hw.rs`     (I2C1 SE050 init — hw only, no API)
//!   - `secure/src/hw/i2c2_probe.rs` (I2C2 bus-scan — `stsafe-probe` dev)
//!   - `secure/src/hw/spi_hw.rs`     (SPI2/SPI1 init — NV3007 LCD bus)
//!   - `secure/src/hw/usb_hw.rs`     (USB OTG FS init — flips NS pins)
//!   - `secure/src/hw/uart.rs`       (debug-console UART, `uart-console`)
//!   - `secure/src/board/{mod,iota2,pq1}.rs` (per-board pin maps)
//!   - `secure/src/hw/buttons.rs`    (PA8 / PC1 GPIO trusted-UI buttons)
//!   - `secure/src/hw/mod.rs`        (feature gates for every IO module)
//!
//! The `hw/*` files all sit behind `feature = "stm32u585"` (or
//! `usb` / `gpio-buttons` / `uart-console` /
//! `stsafe-probe`) and pull in `cortex_m` MMIO machinery that does not
//! link on host. We therefore pin the slice through `include_str!`
//! source-text invariants.
//!
//! The `board/*` files are pinned for a different reason: they are the
//! single point of truth for every per-board pin and peripheral base, so a
//! constant that used to be a literal inside a driver is now asserted
//! there instead — **for both boards**, so neither loses coverage when the
//! other is the one being built. (Their peripheral *base addresses* are
//! additionally diffed against ST's own CMSIS header by
//! `scripts/check_mmio_addresses.py`, which is a stronger check than text
//! matching and is where a wrong nibble gets caught.)
//!
//! Either way, every constant whose silent regression
//! would matter for security (wrong alias = SE bus on NS side, wrong
//! AF = no comms, stray SECCFGR bit = SE pin exposed to NS world,
//! stray MODER bit on PA13/PA14 = SWD port bricked) is asserted
//! against the file text.
//!
//! Each `negative_*` test names the assumption being challenged in its
//! panic message and cites the invariant (CLAUDE.md "Non-Negotiable
//! Invariants" or in-file safety comment) whose silent removal it
//! would otherwise enable. Per the test-writing brief, the negative
//! suite is the most important deliverable here.

#![cfg(test)]

const I2C_HW_SRC: &str = include_str!("../hw/i2c_hw.rs");
const I2C2_PROBE_SRC: &str = include_str!("../hw/i2c2_probe.rs");
const SPI_HW_SRC: &str = include_str!("../hw/spi_hw.rs");
const USB_HW_SRC: &str = include_str!("../hw/usb_hw.rs");
const UART_SRC: &str = include_str!("../hw/uart.rs");
/// The two board pin maps. Constants that used to be literals inside the
/// driver files now live here, so the pins below assert against these
/// instead — for BOTH boards, so no board loses coverage.
const BOARD_IOTA2_SRC: &str = include_str!("../board/iota2.rs");
const BOARD_PQ1_SRC: &str = include_str!("../board/pq1.rs");
const BOARD_MOD_SRC: &str = include_str!("../board/mod.rs");
const BUTTONS_SRC: &str = include_str!("../hw/buttons.rs");
const HW_MOD_SRC: &str = include_str!("../hw/mod.rs");

/// Returns true if `needle` appears in any non-comment line of `src`.
/// A line is treated as comment-only after the first `//` token; the
/// portion before `//` (if any) is still scanned. Block comments
/// (`/* ... */`) are not used in this slice — none of the source
/// files in scope contain `/*`.
fn contains_in_code(src: &str, needle: &str) -> bool {
    for line in src.lines() {
        let code = match line.find("//") {
            Some(i) => &line[..i],
            None => line,
        };
        if code.contains(needle) {
            return true;
        }
    }
    false
}

// ═════════════════════════════════════════════════════════════════════
// 1. POSITIVE — SE I2C hardware init (i2c_hw.rs + board/*.rs)
//
// `i2c_hw.rs` no longer holds a peripheral base, a pin number or an
// alternate function: it iterates `board::SE_I2C_BUSES`. The pins below
// therefore assert against the BOARD tables — for both boards — plus the
// derivation logic that consumes them. That is more coverage than the
// pre-split suite, which pinned one board's PB8/PB9/AF4 and nothing else.
//
// The peripheral BASE addresses in `board/mod.rs` are additionally diffed
// against ST's own CMSIS header by `scripts/check_mmio_addresses.py`, which
// catches a wrong nibble that text matching cannot.
// ═════════════════════════════════════════════════════════════════════

#[test]
fn positive_i2c_hw_secure_alias_base() {
    // Both boards put OPTIGA on I2C1; only pq1 adds I2C4 for the SE050.
    assert!(BOARD_MOD_SRC.contains("pub const I2C1_S: u32 = 0x5000_5400;"));
    assert!(BOARD_MOD_SRC.contains("pub const I2C4_S: u32 = 0x5000_8400;"));
    assert!(BOARD_IOTA2_SRC.contains("pub const OPTIGA_I2C_BASE: u32 = I2C1_S;"));
    assert!(BOARD_PQ1_SRC.contains("pub const OPTIGA_I2C_BASE: u32 = I2C1_S;"));
    // iota2 shares one bus; pq1 splits them. This pair is the whole
    // difference, so assert BOTH sides of it rather than one.
    assert!(BOARD_IOTA2_SRC.contains("pub const SE050_I2C_BASE: u32 = I2C1_S;"));
    assert!(BOARD_PQ1_SRC.contains("pub const SE050_I2C_BASE: u32 = I2C4_S;"));
}

#[test]
fn positive_i2c_hw_rcc_secure_alias() {
    assert!(BOARD_MOD_SRC.contains("pub const RCC_S: u32 = 0x5602_0C00;"));
    // The driver must reach RCC only through that constant.
    assert!(contains_in_code(I2C_HW_SRC, "board::RCC_S"));
}

#[test]
fn positive_i2c_hw_gpiob_secure_alias() {
    // Every SE I2C pin on both boards is on port B.
    assert!(BOARD_MOD_SRC.contains("pub const GPIOB_S: u32 = 0x5202_0400;"));
    assert_eq!(
        BOARD_IOTA2_SRC.matches("port: GPIOB_S,").count(),
        1,
        "iota2 has exactly one SE I2C bus, on port B"
    );
    assert_eq!(
        BOARD_PQ1_SRC.matches("port: GPIOB_S,").count(),
        2,
        "pq1 has exactly two SE I2C buses, both on port B"
    );
}

#[test]
fn positive_i2c_hw_400khz_timing_at_160mhz() {
    // PRESC=1, SCLDEL=9, SDADEL=0, SCLH=55, SCLL=143 → 400 kHz FM.
    // Shared by every bus: I2C1 and I2C4 both take PCLK1 at their reset
    // clock-source setting, and rcc::init leaves APB1 at /1.
    assert!(BOARD_MOD_SRC.contains("pub const I2C_TIMING_400KHZ: u32 = 0x1090_378F;"));
    assert!(contains_in_code(I2C_HW_SRC, "board::I2C_TIMING_400KHZ"));
}

#[test]
fn positive_i2c_hw_pin_mode_af_open_drain_pullup() {
    // AF mode + open-drain + pull-up, now derived from the pin number
    // rather than written as PB8/PB9 literals.
    assert!(I2C_HW_SRC.contains("(0b10 << pin2)")); // MODER = alternate function
    assert!(I2C_HW_SRC.contains("otyper.set_bits(1 << pin)")); // open-drain
    assert!(I2C_HW_SRC.contains("(0b01 << pin2)")); // pull-up
    assert!(I2C_HW_SRC.contains("(af << shift)")); // AF nibble from the board
}

#[test]
fn positive_i2c_hw_bus_pins_and_af_per_board() {
    // iota2: one bus, PB8/PB9, AF4.
    assert!(BOARD_IOTA2_SRC.contains("scl_pin: 8,"));
    assert!(BOARD_IOTA2_SRC.contains("sda_pin: 9,"));
    assert_eq!(BOARD_IOTA2_SRC.matches("af: 4,").count(), 1);

    // pq1: OPTIGA keeps PB8/PB9 AF4; SE050 is PB6/PB7 AF5.
    assert!(BOARD_PQ1_SRC.contains("scl_pin: 6,"));
    assert!(BOARD_PQ1_SRC.contains("sda_pin: 7,"));
    assert_eq!(BOARD_PQ1_SRC.matches("af: 4,").count(), 1, "pq1 OPTIGA bus is AF4");
    assert_eq!(BOARD_PQ1_SRC.matches("af: 5,").count(), 1, "pq1 SE050 bus is AF5");
}

/// The sharpest silent failure in the whole board port.
///
/// PB6/PB7 carry **I2C4 under AF5 and I2C1 under AF4**. An AF4 typo on the
/// pq1 SE050 bus would not fail — it would quietly attach the SE050's pins
/// to the OPTIGA bus, giving a bus that looks alive and answers for the
/// wrong chip.
#[test]
fn negative_pq1_se050_bus_is_af5_not_af4() {
    let se050_block = BOARD_PQ1_SRC
        .split("name: \"I2C4 (SE050 0x48)\"")
        .nth(1)
        .expect("pq1 must declare an I2C4 bus for the SE050");
    let decl = &se050_block[..se050_block.find("},").unwrap_or(se050_block.len())];
    assert!(
        decl.contains("af: 5,"),
        "pq1's SE050 bus must select I2C4 with AF5"
    );
    assert!(
        !decl.contains("af: 4,"),
        "AF4 on PB6/PB7 is I2C1, not I2C4 — this typo does not fail, it \
         silently puts the SE050's pins on the OPTIGA bus"
    );
}

/// The enable/reset registers differ between the two I2C instances, and
/// using I2C1's for I2C4 leaves the peripheral unclocked and silent.
#[test]
fn negative_pq1_i2c4_uses_apb1_bank2_registers() {
    assert!(BOARD_MOD_SRC.contains("pub const RCC_APB1ENR2_OFF: u32 = 0xA0;"));
    assert!(BOARD_MOD_SRC.contains("pub const RCC_APB1RSTR2_OFF: u32 = 0x78;"));
    assert!(BOARD_MOD_SRC.contains("pub const RCC_I2C4EN_BIT: u32 = 1 << 1;"));
    assert!(BOARD_MOD_SRC.contains("pub const RCC_I2C4RST_BIT: u32 = 1 << 1;"));

    let se050_block = BOARD_PQ1_SRC
        .split("name: \"I2C4 (SE050 0x48)\"")
        .nth(1)
        .expect("pq1 must declare an I2C4 bus");
    let decl = &se050_block[..se050_block.find("},").unwrap_or(se050_block.len())];
    assert!(decl.contains("rcc_enr_off: RCC_APB1ENR2_OFF,"));
    assert!(decl.contains("rcc_rstr_off: RCC_APB1RSTR2_OFF,"));
    assert!(
        !decl.contains("rcc_enr_off: RCC_APB1ENR1_OFF,"),
        "I2C4's enable is in APB1ENR2, not APB1ENR1 — the wrong bank leaves \
         the peripheral unclocked and the bus silent"
    );
}

/// Independent recomputation of the AFR half + shift for every SE I2C pin
/// on both boards, so a regression in `i2c_hw`'s expression is caught by
/// arithmetic rather than by matching the same text twice.
#[test]
fn positive_i2c_hw_afr_derivation_covers_both_boards() {
    fn afr_off(pin: u32) -> u32 {
        if pin < 8 {
            0x20
        } else {
            0x24
        }
    }
    fn afr_shift(pin: u32) -> u32 {
        (pin % 8) * 4
    }

    // iota2 + pq1-OPTIGA: PB8/PB9 -> AFRH, nibbles 0 and 4. These are the
    // literals the pre-split driver hard-coded as `+ 0x24` and
    // `(4 << 0) | (4 << 4)`.
    assert_eq!((afr_off(8), afr_shift(8)), (0x24, 0));
    assert_eq!((afr_off(9), afr_shift(9)), (0x24, 4));

    // pq1-SE050: PB6/PB7 -> AFRL, nibbles 24 and 28. A driver that kept the
    // old fixed AFRH would write these into PB14/PB15's nibbles instead.
    assert_eq!((afr_off(6), afr_shift(6)), (0x20, 24));
    assert_eq!((afr_off(7), afr_shift(7)), (0x20, 28));

    assert!(I2C_HW_SRC.contains("if pin < 8 {"));
    assert!(I2C_HW_SRC.contains("(pin % 8) * 4"));
}

#[test]
fn positive_i2c_hw_init_has_no_public_data_path() {
    // The SE050 driver layers its own SCP03 framing on top — i2c_hw.rs
    // must only expose `init()`, never a plaintext `write` or `read`.
    // Count CODE occurrences only: the module header legitimately explains
    // that this file exposes "a single `pub fn init`", and a raw substring
    // count would read that sentence as a second definition.
    let init_count = I2C_HW_SRC
        .lines()
        .map(|line| match line.find("//") {
            Some(i) => &line[..i],
            None => line,
        })
        .filter(|code| code.contains("pub fn init"))
        .count();
    assert_eq!(init_count, 1, "i2c_hw.rs must expose exactly `pub fn init`");
    // Code-scoped, for the same reason as the count above: the module header
    // explains that a `pub fn write` here would be an NS-reachable path onto
    // the SE bus, and a raw substring match reads that warning as the thing
    // it warns about. `contains_in_code` still catches a real definition —
    // it only ignores prose after `//`.
    assert!(
        !contains_in_code(I2C_HW_SRC, "pub fn write"),
        "i2c_hw.rs must NOT expose a public write — SE050 frames are SCP03-wrapped at a higher layer (CLAUDE.md invariant #3)",
    );
    assert!(
        !contains_in_code(I2C_HW_SRC, "pub fn read"),
        "i2c_hw.rs must NOT expose a public read — SE050 frames are SCP03-wrapped at a higher layer (CLAUDE.md invariant #3)",
    );
}

// ═════════════════════════════════════════════════════════════════════
// 3. POSITIVE — I2C2 probe (i2c2_probe.rs, STSAFE-A110)
// ═════════════════════════════════════════════════════════════════════

#[test]
fn positive_i2c2_probe_secure_alias_base() {
    assert!(I2C2_PROBE_SRC.contains("const I2C2: u32 = 0x5000_5800;"));
}

#[test]
fn positive_i2c2_probe_gpioh_secure_alias() {
    assert!(I2C2_PROBE_SRC.contains("const GPIOH_S: u32 = 0x5202_1C00;"));
}

#[test]
fn positive_i2c2_probe_pin_mapping_ph4_ph5_af4() {
    // PH4 = SCL bits [9:8], PH5 = SDA bits [11:10], AF mode (0b10).
    assert!(I2C2_PROBE_SRC.contains("(0b10 << 8) | (0b10 << 10)"));
    // AF4 for both pins via AFRL.
    assert!(I2C2_PROBE_SRC.contains("(4 << 16) | (4 << 20)"));
}

#[test]
fn positive_i2c2_probe_stsafe_default_address_0x20() {
    assert!(I2C2_PROBE_SRC.contains("const STSAFE_ADDR: u8 = 0x20;"));
}

#[test]
fn positive_i2c2_probe_scan_range_0x08_to_0x77() {
    // Reserved addresses skipped — only 0x08..=0x77 are probed.
    assert!(I2C2_PROBE_SRC.contains("if addr < 0x08 || addr > 0x77"));
}

#[test]
fn positive_i2c2_probe_halts_after_scan() {
    // The probe is a dev-only one-shot — never returns.
    assert!(I2C2_PROBE_SRC.contains("pub unsafe fn run_probe() -> !"));
    assert!(I2C2_PROBE_SRC.contains("cortex_m::asm::wfi()"));
}

// ═════════════════════════════════════════════════════════════════════
// 5. POSITIVE — SPI hardware init (spi_hw.rs, NV3007 LCD)
// ═════════════════════════════════════════════════════════════════════

#[test]
fn positive_spi_hw_default_spi2_base() {
    assert!(SPI_HW_SRC.contains("pub const SPI_BASE: u32 = 0x5000_3800; // SPI2"));
}

#[test]
fn positive_spi_hw_arduino_spi1_base() {
    assert!(SPI_HW_SRC.contains("pub const SPI_BASE: u32 = 0x5001_3000; // SPI1"));
}

#[test]
fn positive_spi_hw_rcc_secure_alias() {
    assert!(SPI_HW_SRC.contains("const RCC_S: u32 = 0x5602_0C00;"));
}

#[test]
fn positive_spi_hw_gpiob_default_gpioe_arduino() {
    assert!(SPI_HW_SRC.contains("const GPIO_BASE: u32 = 0x5202_0400; // GPIOB"));
    assert!(SPI_HW_SRC.contains("const GPIO_BASE: u32 = 0x5202_1000; // GPIOE"));
}

#[test]
fn positive_spi_hw_cs_pin_12() {
    assert!(SPI_HW_SRC.contains("pub const CS_PIN: u32 = 12;"));
}

#[test]
fn positive_spi_hw_ssi_high_before_master_mode() {
    // RM0456: SSI must be 1 before MASTER is set in CFG2 or the chip
    // sees a false NSS-low (mode fault) and clears MASTER. Pin the
    // write order via the explicit comment + CR1 write.
    assert!(SPI_HW_SRC.contains("REG.spi_cr1.write(1 << 12); // SSI=1, SPE=0"));
    assert!(SPI_HW_SRC.contains("SSI (bit 12) must be 1 before MASTER"));
}

#[test]
fn positive_spi_hw_cfg1_baud_gated_dsize_8bit() {
    // SPI1 baud is gated on `ui-lcd` (2026-06-09): ÷8 (20 MHz) for the NV3007
    // LCD (dropped from ÷4/40 MHz — the dev board's blue LED on PE13=SCK loads
    // the line and corrupts 40 MHz edges), ÷32 (5 MHz) conservative for non-LCD
    // builds. DSIZE = 7 (8-bit); only MBR nibble [30:28] moves.
    assert!(SPI_HW_SRC.contains("const MBR: u32 = 0b010;")); // ÷8 → 20 MHz (ui-lcd)
    assert!(SPI_HW_SRC.contains("const MBR: u32 = 0b100;")); // ÷32 → 5 MHz (default)
    assert!(SPI_HW_SRC.contains("REG.spi_cfg1.write((MBR << 28) | 7);"));
}

#[test]
fn positive_spi_hw_cfg2_master_software_nss_only() {
    // MASTER bit 22, SSM bit 26. CPOL/CPHA = 0 (SPI Mode 0). COMM=00
    // (full-duplex), LSBFRST=0 (MSB first), SSOE/SSOM=0.
    assert!(SPI_HW_SRC.contains("REG.spi_cfg2.write((1 << 22) | (1 << 26));"));
}

#[test]
fn positive_spi_hw_no_interrupts() {
    assert!(SPI_HW_SRC.contains("REG.spi_ier.write(0);"));
}

#[test]
fn positive_spi_hw_cs_asserts_low_via_bsrr_reset() {
    // BR12 = bit (CS_PIN + 16). Low (asserted) for CS, high (deasserted)
    // = BS12 = bit CS_PIN.
    assert!(SPI_HW_SRC.contains("REG.gpio_bsrr.write(1 << (CS_PIN + 16)); // BR12 = reset"));
    assert!(SPI_HW_SRC.contains("REG.gpio_bsrr.write(1 << CS_PIN); // BS12 = set"));
}

#[test]
fn positive_spi_hw_af5_for_sck_miso_mosi() {
    // AF5 for pins 13 (SCK), 14 (MISO), 15 (MOSI).
    assert!(SPI_HW_SRC.contains("(5 << 20)"));
    assert!(SPI_HW_SRC.contains("(5 << 24)"));
    assert!(SPI_HW_SRC.contains("(5 << 28)"));
}

// ═════════════════════════════════════════════════════════════════════
// 6. POSITIVE — USB OTG FS init (usb_hw.rs)
// ═════════════════════════════════════════════════════════════════════

#[test]
fn positive_usb_rcc_secure_alias() {
    assert!(USB_HW_SRC.contains("const RCC_S: u32 = 0x5602_0C00;"));
}

#[test]
fn positive_usb_pwr_secure_alias() {
    assert!(USB_HW_SRC.contains("const PWR: u32 = 0x5602_0800;"));
}

#[test]
fn positive_usb_gpioa_gpiob_secure_alias() {
    assert!(USB_HW_SRC.contains("const GPIOA_S: u32 = 0x5202_0000;"));
    assert!(USB_HW_SRC.contains("const GPIOB_S: u32 = 0x5202_0400;"));
}

#[test]
fn positive_usb_ucpd1_secure_alias() {
    assert!(USB_HW_SRC.contains("const UCPD1: u32 = 0x5000_DC00;"));
}

#[test]
fn positive_usb_svmcr_usv_bit_28() {
    assert!(USB_HW_SRC.contains("const USV: u32 = 1 << 28;"));
}

#[test]
fn positive_usb_otg_fs_clock_bit_14() {
    assert!(USB_HW_SRC.contains("REG.rcc_ahb2enr1.set_bits(1 << 14);"));
    assert!(USB_HW_SRC.contains("REG.rcc_ahb2rstr1.set_bits(1 << 14);"));
}

#[test]
fn positive_usb_pa11_pa12_af10() {
    // AF10 = USB. AFRH bits [12+:4] for PA11, [16+:4] for PA12.
    assert!(USB_HW_SRC.contains("(10 << 12) | (10 << 16)"));
}

#[test]
fn positive_usb_ns_pin_classification_only_usb_and_tcpp03() {
    // The ONLY pins that get marked NS via GPIOA SECCFGR are PA11/12/15.
    assert!(USB_HW_SRC.contains(
        "REG.gpioa_seccfgr.clear_bits((1 << 11) | (1 << 12) | (1 << 15)); // PA11,12,15 = NS"
    ));
    // The ONLY pins that get marked NS via GPIOB SECCFGR are PB5/PB15.
    assert!(USB_HW_SRC.contains(
        "REG.gpiob_seccfgr.clear_bits((1 << 5) | (1 << 15)); // PB5,15 = NS"
    ));
}

#[test]
fn positive_usb_tcpp03_pb5_drive_high() {
    assert!(USB_HW_SRC.contains("REG.gpiob_bsrr.write(1 << 5);"));
}

#[test]
fn positive_usb_ucpd_sink_mode_with_dead_battery_disabled() {
    // Commit b325dd8 fixed two register bugs in `init_ucpd`:
    //   1. CC1TCDIS/CC2TCDIS were being set, which DISABLES the Type-C
    //      voltage detectors (per ST's `LL_UCPD_TypeCDetectionCC1Disable`
    //      = `SET_BIT(CC1TCDIS)`) — blinding UCPD_SR so the host's Rp
    //      was never sensed. Now LEFT CLEAR.
    //   2. Dead-battery was never disabled. The CORRECT disable is
    //      `PWR_UCPDR.UCPD_DBDIS` bit 0 — `LL_PWR_DisableUCPDDeadBattery`.
    // Pin both invariants so a refactor can't quietly regress them.
    assert!(USB_HW_SRC.contains("(0b11 << 10)  // CCENABLE"));
    assert!(USB_HW_SRC.contains("| (1 << 9);              // ANAMODE: sink"));
    // Check that the bit-SET syntax `| (1 << 20)` / `| (1 << 21)` is
    // absent (those are the literal lines that used to set
    // CC1TCDIS/CC2TCDIS). The CCxTCDIS *name* still appears in the
    // explanatory comment above the CR write — that's fine, what we
    // care about is that the bits aren't being set.
    assert!(
        !USB_HW_SRC.contains("| (1 << 20)") && !USB_HW_SRC.contains("| (1 << 21)"),
        "CC1TCDIS (bit 20) / CC2TCDIS (bit 21) must NOT be OR'd into the \
         UCPD_CR write — those are the Type-C voltage *detector* disables \
         (blinding UCPD_SR), not dead-battery. Dead-battery is disabled \
         via PWR_UCPDR.UCPD_DBDIS instead. See commit b325dd8."
    );
    assert!(
        USB_HW_SRC.contains("REG.pwr_ucpdr.set_bits(1 << 0); // UCPD_DBDIS"),
        "dead-battery must be disabled via PWR_UCPDR.UCPD_DBDIS (bit 0) — \
         the correct register per ST's `LL_PWR_DisableUCPDDeadBattery()`."
    );
}

#[test]
fn positive_usb_ucpd_cfg1_constants() {
    // HBITCLKDIV=13, IFRGAP=16, TRANSWIN=7, PSC_USBPDCLK=÷2 (HSI16/2 = 8 MHz),
    // UCPDEN=1.
    assert!(USB_HW_SRC.contains("(13 << 0)"));
    assert!(USB_HW_SRC.contains("(16 << 6)"));
    assert!(USB_HW_SRC.contains("(7 << 11)"));
    assert!(USB_HW_SRC.contains("(0b01 << 17)"));
    assert!(USB_HW_SRC.contains("(1 << 31);             // UCPDEN"));
}

// ═════════════════════════════════════════════════════════════════════
// 7. POSITIVE — debug-console UART (uart.rs + board/*.rs, `uart-console`)
//
// `uart.rs` no longer carries a peripheral base or a pin number: it reads
// them from `crate::board`. So the pins that used to sit on the driver now
// assert against BOTH board maps. That is strictly more coverage than
// before, not less — the previous suite pinned one board's USART1/PA9;
// this one pins that AND pq1's USART2/PA2, and would catch either being
// silently swapped for the other.
// ═════════════════════════════════════════════════════════════════════

#[test]
fn positive_uart_iota2_usart1_secure_alias() {
    // Unchanged from the pre-board-split value, just relocated.
    assert!(BOARD_IOTA2_SRC.contains("pub const CONSOLE_UART_BASE: u32 = USART1_S;"));
    assert!(BOARD_MOD_SRC.contains("pub const USART1_S: u32 = 0x5001_3800;"));
}

#[test]
fn positive_uart_pq1_usart2_secure_alias() {
    // pq1's console is USART2 on PA2/PA3 (header J211), NOT USART1: PA9 is
    // the USB VBUS sense node on that board.
    assert!(BOARD_PQ1_SRC.contains("pub const CONSOLE_UART_BASE: u32 = USART2_S;"));
    assert!(BOARD_MOD_SRC.contains("pub const USART2_S: u32 = 0x5000_4400;"));
}

#[test]
fn positive_uart_rcc_secure_alias() {
    // The NS RCC alias silently drops GPIOxEN writes at TZEN=1.
    assert!(BOARD_MOD_SRC.contains("pub const RCC_S: u32 = 0x5602_0C00;"));
}

#[test]
fn positive_uart_gpioa_secure_alias() {
    // Both boards put the console TX on port A; only the pin differs.
    assert!(BOARD_MOD_SRC.contains("pub const GPIOA_S: u32 = 0x5202_0000;"));
    assert!(BOARD_IOTA2_SRC.contains("pub const CONSOLE_TX_PORT: u32 = GPIOA_S;"));
    assert!(BOARD_PQ1_SRC.contains("pub const CONSOLE_TX_PORT: u32 = GPIOA_S;"));
}

#[test]
fn positive_uart_brr_115200_at_160mhz() {
    // 160_000_000 / 115_200 ≈ 1389 (0.064% baud error). iota2's USART1 runs
    // off PCLK2 and pq1's USART2 off PCLK1, but rcc::init leaves both APB
    // prescalers at /1, so the divisor is the same on both boards.
    assert!(BOARD_IOTA2_SRC.contains("pub const CONSOLE_BRR: u32 = 1389;"));
    assert!(BOARD_PQ1_SRC.contains("pub const CONSOLE_BRR: u32 = 1389;"));
    assert!(UART_SRC.contains("REG.brr.write(board::CONSOLE_BRR);"));
    assert_eq!(160_000_000u32 / 115_200, 1388); // sanity — 1388 rounds to 1389
}

#[test]
fn positive_uart_enable_bits_differ_per_board() {
    // iota2: USART1EN is RCC_APB2ENR bit 14.
    assert!(BOARD_MOD_SRC.contains("pub const RCC_USART1EN_BIT: u32 = 1 << 14;"));
    assert!(BOARD_MOD_SRC.contains("pub const RCC_APB2ENR_OFF: u32 = 0xA4;"));
    assert!(BOARD_IOTA2_SRC.contains("pub const CONSOLE_UART_RCC_ENR_OFF: u32 = RCC_APB2ENR_OFF;"));
    assert!(BOARD_IOTA2_SRC.contains("pub const CONSOLE_UART_RCC_EN_BIT: u32 = RCC_USART1EN_BIT;"));

    // pq1: USART2EN is a DIFFERENT register — RCC_APB1ENR1 bit 17. Enabling
    // the wrong one leaves the peripheral unclocked and the console silent.
    assert!(BOARD_MOD_SRC.contains("pub const RCC_USART2EN_BIT: u32 = 1 << 17;"));
    assert!(BOARD_MOD_SRC.contains("pub const RCC_APB1ENR1_OFF: u32 = 0x9C;"));
    assert!(BOARD_PQ1_SRC.contains("pub const CONSOLE_UART_RCC_ENR_OFF: u32 = RCC_APB1ENR1_OFF;"));
    assert!(BOARD_PQ1_SRC.contains("pub const CONSOLE_UART_RCC_EN_BIT: u32 = RCC_USART2EN_BIT;"));
}

#[test]
fn positive_uart_tx_pin_and_af_per_board() {
    // iota2 PA9 AF7 (ST-LINK VCP); pq1 PA2 AF7 (J211 pin 1).
    assert!(BOARD_IOTA2_SRC.contains("pub const CONSOLE_TX_PIN: u32 = 9;"));
    assert!(BOARD_IOTA2_SRC.contains("pub const CONSOLE_TX_AF: u32 = 7;"));
    assert!(BOARD_PQ1_SRC.contains("pub const CONSOLE_TX_PIN: u32 = 2;"));
    assert!(BOARD_PQ1_SRC.contains("pub const CONSOLE_TX_AF: u32 = 7;"));
}

#[test]
fn positive_uart_afr_half_is_derived_not_hardcoded() {
    // The old driver hard-coded AFRH (+0x24) and shift 4, which is correct
    // for PA9 and WRONG for PA2 — pins 0..7 live in AFRL (+0x20). The split
    // must therefore be derived from the pin number.
    assert!(UART_SRC.contains("if board::CONSOLE_TX_PIN < 8 { 0x20 } else { 0x24 }"));
    assert!(UART_SRC.contains("(board::CONSOLE_TX_PIN % 8) * 4"));
}

/// Independent recomputation of the AFR half + shift for each board's TX
/// pin, so a regression in the `uart.rs` expression is caught by arithmetic
/// rather than by matching the same text twice.
#[test]
fn positive_uart_afr_derivation_matches_both_boards() {
    fn afr_off(pin: u32) -> u32 {
        if pin < 8 {
            0x20
        } else {
            0x24
        }
    }
    fn afr_shift(pin: u32) -> u32 {
        (pin % 8) * 4
    }

    // iota2 PA9 -> AFRH, nibble [7:4] — exactly what the pre-split driver
    // wrote as the literals `+ 0x24` and `(0x7 << 4)`.
    assert_eq!(afr_off(9), 0x24);
    assert_eq!(afr_shift(9), 4);

    // pq1 PA2 -> AFRL, nibble [11:8].
    assert_eq!(afr_off(2), 0x20);
    assert_eq!(afr_shift(2), 8);
}

/// The GPIO-port clock-enable bit must follow the 0x400 base stride.
#[test]
fn positive_uart_gpio_rcc_bit_derivation() {
    assert!(BOARD_MOD_SRC.contains("1 << ((port_base - GPIOA_S) / 0x400)"));
    // GPIOA -> bit 0 (what the pre-split driver hard-coded), GPIOB -> bit 1.
    assert_eq!(1u32 << ((0x5202_0000u32 - 0x5202_0000u32) / 0x400), 1 << 0);
    assert_eq!(1u32 << ((0x5202_0400u32 - 0x5202_0000u32) / 0x400), 1 << 1);
}

/// pq1 bonds only ports A, B and PC13. A console TX on any other port
/// would be driving a pad that does not exist — and would do so silently,
/// because the port logic is still on the die.
#[test]
fn negative_pq1_console_tx_is_on_a_bonded_port() {
    assert!(
        BOARD_PQ1_SRC.contains("pub const CONSOLE_TX_PORT: u32 = GPIOA_S;"),
        "pq1 console TX must be on GPIOA or GPIOB — the 48-pin UFQFPN package \
         bonds no other full port, and writes to an unbonded port succeed \
         silently instead of faulting"
    );
}

/// pq1's PA9 is the USB VBUS sense divider, not a console pin. If the
/// iota2 TX pin ever leaked into the pq1 map, the driver would push a
/// push-pull output into that divider.
#[test]
fn negative_pq1_console_tx_is_not_pa9() {
    assert!(
        !BOARD_PQ1_SRC.contains("pub const CONSOLE_TX_PIN: u32 = 9;"),
        "pq1 PA9 is USB_FS_VBUS (sense divider) — driving it as USART TX \
         fights the divider and loses the console"
    );
}

#[test]
fn positive_uart_init_ue_then_te_sequence() {
    // RM0456 sequence — UE must be set BEFORE TE; the comment cites the
    // ambiguous-hardware-behaviour rationale.
    assert!(UART_SRC.contains("REG.cr1.write(CR1_UE);\n    REG.cr1.write(CR1_UE | CR1_TE);"));
    // Comment spans two lines (// wrap) — match on a single-line substring.
    assert!(UART_SRC.contains("enable edge must happen AFTER UE is high"));
}

#[test]
fn positive_uart_init_bounded_teack_wait() {
    // The TEACK loop is bounded — if the peripheral is wedged, init()
    // returns rather than hangs.
    assert!(UART_SRC.contains("let mut t: u32 = 10_000_000;"));
    assert!(UART_SRC.contains("if t == 0 {\n            return;\n        }"));
}

#[test]
fn positive_uart_write_hex_8_lowercase() {
    assert!(UART_SRC.contains("b\"0123456789abcdef\""));
    assert!(UART_SRC.contains("pub fn write_hex_8(bytes: &[u8; 8])"));
}

#[test]
fn positive_uart_flush_waits_tc() {
    assert!(UART_SRC.contains("const ISR_TC: u32 = 1 << 6;"));
    assert!(UART_SRC.contains("while REG.isr.read() & ISR_TC == 0 {}"));
}

// ═════════════════════════════════════════════════════════════════════
// 8. POSITIVE — GPIO buttons (buttons.rs)
// ═════════════════════════════════════════════════════════════════════

#[test]
fn positive_buttons_left_pc1_right_pa8_pin_bits() {
    assert!(BUTTONS_SRC.contains("const LEFT_BIT: u32 = 1 << 1;"));
    assert!(BUTTONS_SRC.contains("const RIGHT_BIT: u32 = 1 << 8;"));
}

#[test]
fn positive_buttons_gpioa_gpioc_secure_alias() {
    assert!(BUTTONS_SRC.contains("const GPIOA_S: u32 = 0x5202_0000;"));
    assert!(BUTTONS_SRC.contains("const GPIOC_S: u32 = 0x5202_0800;"));
}

#[test]
fn positive_buttons_rcc_secure_alias() {
    assert!(BUTTONS_SRC.contains("const RCC_S: u32 = 0x5602_0C00;"));
}

#[test]
fn positive_buttons_active_low_pressed_reads_zero() {
    // pressed = pin reads 0 (shorted to GND).
    assert!(BUTTONS_SRC.contains("REG.gpioc_idr.read() & LEFT_BIT == 0"));
    assert!(BUTTONS_SRC.contains("REG.gpioa_idr.read() & RIGHT_BIT == 0"));
}

#[test]
fn positive_buttons_pullup_internal_pupdr_01() {
    // PUPDR 0b01 = pull-up for both LEFT (PC1, bits [3:2]) and RIGHT (PA8, bits [17:16]).
    assert!(BUTTONS_SRC.contains("(0b01 << 2)"));
    assert!(BUTTONS_SRC.contains("(0b01 << 16)"));
}

#[test]
fn positive_buttons_timings() {
    assert!(BUTTONS_SRC.contains("const DEBOUNCE_MS: u32 = 30;"));
    assert!(BUTTONS_SRC.contains("const LONG_PRESS_MS: u32 = 500;"));
    assert!(BUTTONS_SRC.contains("const POLL_MS: u32 = 5;"));
    assert!(BUTTONS_SRC.contains("const COMBO_WINDOW_MS: u32 = 80;"));
}

#[test]
fn positive_buttons_combo_emits_right_long() {
    // The both-buttons-chord is synthesized as (Right, Long) so every
    // existing confirm UI path treats it as a confirm.
    assert!(BUTTONS_SRC.contains("return Some((Button::Right, Press::Long));"));
}

#[test]
fn positive_buttons_idle_check_returns_none() {
    // wait_event returns None if idle_check fires — caller wipes secrets.
    assert!(BUTTONS_SRC.contains("if idle_check() {\n            return None;\n        }"));
}

#[test]
fn positive_button_release_hold_carries_the_wait_abort_predicate() {
    assert!(BUTTONS_SRC.contains("wait_release(is_pressed, idle_check)"));
    let release = BUTTONS_SRC
        .find("fn wait_release(is_pressed: fn() -> bool, idle_check: &mut dyn FnMut() -> bool)")
        .expect("deadline-aware GPIO release loop must exist");
    let release_body = &BUTTONS_SRC[release..];
    assert!(release_body.contains("if idle_check() {\n            return false;\n        }"));
    assert!(release_body.contains("return true;"));
    assert!(
        release_body.find("if idle_check()").unwrap()
            < release_body.find("delay_ms(POLL_MS)").unwrap()
    );
}

#[test]
fn positive_buttons_gpio_clocks_a_and_c() {
    // AHB2ENR1 bit 0 = GPIOAEN, bit 2 = GPIOCEN.
    assert!(BUTTONS_SRC.contains("REG.rcc_ahb2enr1.set_bits((1 << 0) | (1 << 2));"));
}

#[test]
fn positive_buttons_sysclk_detection_via_cfgr_sws() {
    // 0b11 → 160 (PLL1), 0b01 → 16 (HSI16), default → 4 (MSI).
    assert!(BUTTONS_SRC.contains("0b11 => 160"));
    assert!(BUTTONS_SRC.contains("0b01 => 16"));
}

// ═════════════════════════════════════════════════════════════════════
// 9. POSITIVE — hw/mod.rs feature gates
// ═════════════════════════════════════════════════════════════════════

#[test]
fn positive_mod_i2c_hw_se_gate() {
    assert!(HW_MOD_SRC.contains(
        "#[cfg(all(feature = \"stm32u585\", any(feature = \"se050\", feature = \"optiga-trust-m\")))]\npub mod i2c_hw;"
    ));
}

#[test]
fn positive_mod_spi_hw_lcd_gate() {
    // `spi_hw` serves the NV3007 LCD driver (`hw::lcd_nv3007`, direct
    // TXDR access — no SpiDevice abstraction).
    assert!(HW_MOD_SRC.contains(
        "#[cfg(all(feature = \"stm32u585\", feature = \"ui-lcd\"))]\npub mod spi_hw;"
    ));
}

#[test]
fn positive_mod_usb_gate() {
    assert!(HW_MOD_SRC.contains(
        "#[cfg(all(feature = \"stm32u585\", feature = \"usb\"))]\npub mod usb_hw;"
    ));
}

#[test]
fn positive_mod_uart_console_gate() {
    assert!(HW_MOD_SRC.contains("#[cfg(feature = \"uart-console\")]\npub mod uart;"));
}

#[test]
fn positive_mod_buttons_gate() {
    assert!(HW_MOD_SRC.contains("#[cfg(feature = \"gpio-buttons\")]\npub mod buttons;"));
}

#[test]
fn positive_mod_i2c2_probe_gate() {
    assert!(HW_MOD_SRC.contains("#[cfg(feature = \"stsafe-probe\")]\npub mod i2c2_probe;"));
}

// ═════════════════════════════════════════════════════════════════════
// 10. NEGATIVE — Secure-alias enforcement (invariant #3, #4)
//
// Every bus / clock peripheral in this slice must be accessed via the
// Secure alias (0x5*). A regression to the Non-Secure alias would
// either silently break (TZEN=1 ignores NS writes to secure-classified
// peripherals) or — worse, for the future TZSC reclassification — let
// the non-secure world re-route the SE bus and steal frames.
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_i2c_hw_does_not_use_ns_alias_for_i2c1() {
    assert!(
        !contains_in_code(I2C_HW_SRC, "0x4000_5400"),
        "SE050 I2C1 NS alias forbidden in code — Secure alias only (invariant #3)",
    );
}

#[test]
fn negative_i2c2_probe_does_not_use_ns_alias() {
    assert!(
        !contains_in_code(I2C2_PROBE_SRC, "0x4000_5800"),
        "I2C2 NS alias forbidden in code (invariant #3)",
    );
}

#[test]
fn negative_spi_hw_does_not_use_ns_alias_for_spi2_or_spi1() {
    assert!(
        !contains_in_code(SPI_HW_SRC, "0x4000_3800"),
        "SPI2 NS alias forbidden in code — trusted-display bus must stay in Secure world (invariant #4)",
    );
    assert!(
        !contains_in_code(SPI_HW_SRC, "0x4001_3000"),
        "SPI1 NS alias forbidden in code — trusted-display bus must stay in Secure world (invariant #4)",
    );
}

#[test]
fn negative_usb_hw_does_not_use_ns_rcc_alias() {
    assert!(
        !contains_in_code(USB_HW_SRC, "0x4602_0C00"),
        "RCC NS alias forbidden in code — GPIOAEN/USBEN writes via NS alias are silently dropped on TZEN=1",
    );
}

#[test]
fn negative_uart_does_not_use_ns_aliases() {
    assert!(
        !contains_in_code(UART_SRC, "0x4001_3800"),
        "USART1 NS alias forbidden in code",
    );
    assert!(
        !contains_in_code(UART_SRC, "0x4602_0C00"),
        "RCC NS alias forbidden in code — see uart.rs RCC_S comment about silent drop",
    );
}

#[test]
fn negative_buttons_does_not_use_ns_aliases() {
    assert!(
        !contains_in_code(BUTTONS_SRC, "0x4202_0000"),
        "GPIOA NS alias forbidden in code",
    );
    assert!(
        !contains_in_code(BUTTONS_SRC, "0x4202_0800"),
        "GPIOC NS alias forbidden in code",
    );
}

// ═════════════════════════════════════════════════════════════════════
// 11. NEGATIVE — USB SECCFGR clearance must NOT expose SE buses to NS
//
// `usb_hw::init` is the ONLY file in this slice that flips GPIO pins
// from Secure → Non-Secure via SECCFGR. The exact set of pins is
// load-bearing: any extra `clear_bits` would silently expose the
// SE050 I2C1 bus (PB8/PB9), the secure SPI2 bus (PB12/13/14), or
// other secure GPIO to the non-secure world.
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_usb_must_not_mark_i2c1_pins_pb8_pb9_ns() {
    // The expected GPIOB SECCFGR clear pattern is exactly `(1 << 5) | (1 << 15)`.
    // Any extra bit — especially PB8 or PB9 — would expose the SE050 I2C1 bus.
    assert!(
        USB_HW_SRC.contains("REG.gpiob_seccfgr.clear_bits((1 << 5) | (1 << 15))"),
        "usb_hw::init must clear GPIOB SECCFGR bits exactly PB5 and PB15",
    );
    let gpiob_seccfgr_calls = USB_HW_SRC.matches("gpiob_seccfgr.clear_bits").count();
    assert_eq!(
        gpiob_seccfgr_calls, 1,
        "usb_hw::init must call gpiob_seccfgr.clear_bits exactly once (extra calls would expose SE buses to NS)",
    );
    // Pin-by-pin reject: scan for any clear-bits expression containing PB8/PB9/PB12-14.
    for pin in [8u32, 9, 12, 13, 14] {
        let needle = format!("(1 << {pin})");
        // Allow `(1 << 14)` if the surrounding line is a clock-enable on AHB2 (USB OTG FS = bit 14),
        // which is unambiguously a different register. Reject only if it appears within a
        // *_seccfgr.clear_bits call.
        let pattern = format!("seccfgr.clear_bits({needle})");
        assert!(
            !USB_HW_SRC.contains(&pattern),
            "usb_hw must NOT mark PB{pin} as NS — it would expose a secure bus (PB8/9 = SE050 I2C1, PB12-14 = SPI2)",
        );
    }
}

#[test]
fn negative_usb_must_not_mark_arbitrary_gpioa_pins_ns() {
    // The expected GPIOA SECCFGR clear pattern is exactly PA11/PA12/PA15.
    assert!(
        USB_HW_SRC.contains("REG.gpioa_seccfgr.clear_bits((1 << 11) | (1 << 12) | (1 << 15))"),
        "usb_hw::init must clear GPIOA SECCFGR bits exactly PA11, PA12, PA15",
    );
    let gpioa_seccfgr_calls = USB_HW_SRC.matches("gpioa_seccfgr.clear_bits").count();
    assert_eq!(
        gpioa_seccfgr_calls, 1,
        "usb_hw::init must call gpioa_seccfgr.clear_bits exactly once",
    );
    // Pin-by-pin reject for PA8 (RIGHT button), PA9 (UART TX), PA13/PA14 (SWD).
    for pin in [8u32, 9, 13, 14] {
        let pattern = format!("gpioa_seccfgr.clear_bits((1 << {pin}))");
        assert!(
            !USB_HW_SRC.contains(&pattern),
            "usb_hw must NOT mark PA{pin} as NS — it would expose a secure peripheral pin",
        );
    }
}

// ═════════════════════════════════════════════════════════════════════
// 12. NEGATIVE — SWD debug port protection
//
// `buttons::init` MUST NOT touch PA13 (SWDIO) or PA14 (SWCLK) MODER
// bits, otherwise the SWD debug connection breaks immediately. The
// PUPDR fields for those pins must also remain untouched.
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_buttons_must_not_touch_swd_pins_pa13_pa14() {
    // Confirm the documented comment.
    assert!(BUTTONS_SRC.contains("PA13 (SWDIO) and PA14 (SWCLK) are untouched"));

    // The only MODER bits buttons.rs may clear on GPIOA are bits [17:16]
    // (PA8). Reject MODER writes touching bits 26/27 (PA13) or 28/29
    // (PA14).
    for shift in [26u32, 28] {
        let needle1 = format!("gpioa_moder.modify(|v| (v & !(0b11 << {shift}))");
        let needle2 = format!("gpioa_moder.set_bits(0b11 << {shift}");
        assert!(
            !BUTTONS_SRC.contains(&needle1),
            "buttons must NOT clear GPIOA MODER bits at shift {shift} — would brick SWD (PA13/14)",
        );
        assert!(
            !BUTTONS_SRC.contains(&needle2),
            "buttons must NOT set GPIOA MODER bits at shift {shift} — would brick SWD (PA13/14)",
        );
    }
}

// ═════════════════════════════════════════════════════════════════════
// 13. NEGATIVE — No classical-signer algorithm leaked into IO modules
//
// Invariant #5: SPHINCS+C10 is the only signature primitive. No bus
// driver should ever reference ECDSA / secp256k1 / Ed25519 / FORS+C
// either by name or by suggestive constants.
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_no_classical_signer_referenced_in_hw_io() {
    let banned: &[&str] = &[
        "ecdsa",
        "ECDSA",
        "secp256k1",
        "Secp256k1",
        "ed25519",
        "Ed25519",
        "fors+c",
        "FORS+C",
    ];
    for src in [
        I2C_HW_SRC, I2C2_PROBE_SRC, SPI_HW_SRC, USB_HW_SRC, UART_SRC,
        BUTTONS_SRC, HW_MOD_SRC,
    ] {
        for needle in banned {
            assert!(
                !src.contains(needle),
                "hw IO slice must reference NO classical signer (invariant #5); found `{needle}`",
            );
        }
    }
}

// ═════════════════════════════════════════════════════════════════════
// 14. NEGATIVE — No PIN/secret material handled by hw IO modules
//
// Invariant #2: PIN compare in SE silicon, never in MCU. Invariant
// #4: all secrets only in TrustZone secure world. The bus drivers
// must not parse, compare, or emit PIN material themselves — that
// lives one or more layers above (`nsc::gated_unlock`, SE050 UserID,
// OPTIGA F1D0).
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_no_software_pin_compare_in_hw_io() {
    // The hw IO modules must not contain functions that compare PIN
    // bytes (e.g. ConstantTimeEq on a `&[u8; PIN_LEN]`, or hand-rolled
    // PIN-byte comparison). The bus layer just moves bytes; PIN
    // verification happens inside the SE.
    let banned_substrings: &[&str] = &[
        "enter_pin",
        "verify_pin",
        "compare_pin",
        "ct_eq", // subtle::ConstantTimeEq::ct_eq — should never appear in a bus driver
        "PIN_LEN",
        "MAX_ATTEMPTS",
    ];
    for src in [
        I2C_HW_SRC, I2C2_PROBE_SRC, SPI_HW_SRC, USB_HW_SRC, UART_SRC,
        BUTTONS_SRC,
    ] {
        for needle in banned_substrings {
            assert!(
                !src.contains(needle),
                "hw IO slice must contain NO PIN logic (invariant #2: PIN compare in SE silicon only); found `{needle}`",
            );
        }
    }
}

// ═════════════════════════════════════════════════════════════════════
// 15. NEGATIVE — No heap / String / Vec / format!(...) in hw IO
//
// `#![no_std]`, no allocator. A regression that pulls in `String` /
// `Vec` would break the build OR silently introduce heap allocation.
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_no_heap_types_in_hw_io_sources() {
    let banned: &[&str] = &["String::new", "Vec::new", "Box::new", "vec![", "alloc::"];
    for src in [
        I2C_HW_SRC, I2C2_PROBE_SRC, SPI_HW_SRC, USB_HW_SRC, UART_SRC,
        BUTTONS_SRC,
    ] {
        for needle in banned {
            assert!(
                !src.contains(needle),
                "hw IO slice must not use heap types (no_std, no allocator); found `{needle}`",
            );
        }
    }
}

// ═════════════════════════════════════════════════════════════════════
// 16. NEGATIVE — Dev-only features documented as "NEVER ship"
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_uart_console_documents_rdp_dev_only_usage() {
    // uart.rs exists only for the RDP1 SAES self-test — a dev-only
    // diagnostic that must not leak into production.
    assert!(
        UART_SRC.contains("RDP1 SAES self-test"),
        "uart.rs must document its RDP1 dev-only purpose so reviewers know it has no shipping role",
    );
    assert!(
        UART_SRC.contains("survives both UART silence AND SWD-halt denial")
            || UART_SRC.contains("survives RDP ≥ 1"),
        "uart.rs must cite the survives-RDP justification",
    );
}

#[test]
fn negative_uart_emits_no_secret_via_write_str() {
    // uart.rs only owns the byte-egress primitives — it must not embed
    // string literals that look like secret-bearing labels.
    let banned: &[&str] = &[
        "master_secret",
        "mnemonic",
        "seed_word",
    ];
    for needle in banned {
        assert!(
            !UART_SRC.to_lowercase().contains(&needle.to_lowercase()),
            "uart.rs must not contain potential secret-bearing label `{needle}`",
        );
    }
}

#[test]
fn negative_i2c2_probe_module_is_dev_only_gated() {
    // i2c2_probe is for a one-shot dev bus-scan. It must:
    //  (a) be gated by the `stsafe-probe` feature,
    //  (b) have run_probe declared with `-> !` so it cannot return to
    //      a production code path.
    assert!(HW_MOD_SRC.contains("#[cfg(feature = \"stsafe-probe\")]\npub mod i2c2_probe;"));
    assert!(I2C2_PROBE_SRC.contains("pub unsafe fn run_probe() -> !"));
}

#[test]
fn negative_buttons_run_test_only_under_button_test_feature() {
    // The hardware button-test harness (`run_test`) must be gated.
    assert!(
        BUTTONS_SRC.contains("#[cfg(feature = \"button-test\")]\npub unsafe fn run_test() -> !"),
        "buttons::run_test must be feature-gated behind `button-test` (dev-only)",
    );
}

// ═════════════════════════════════════════════════════════════════════
// 18. NEGATIVE — I2C SE bus stays SECURE (no GTZC reclassification)
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_i2c_hw_does_not_reclassify_se_bus_to_ns() {
    // i2c_hw.rs must not touch any SECCFGR register in code — the SE050
    // I2C bus must stay fully secure (invariant #3). Doc-comment
    // mentions are fine; what matters is no actual register access.
    assert!(
        !contains_in_code(I2C_HW_SRC, "seccfgr"),
        "i2c_hw must not access SECCFGR in code — SE bus stays Secure (CLAUDE.md invariant #3)",
    );
    assert!(
        !contains_in_code(I2C_HW_SRC, "SECCFGR"),
        "i2c_hw must not access SECCFGR in code — SE bus stays Secure",
    );
    // Confirm the module-docstring claim.
    assert!(
        I2C_HW_SRC.contains("(no GTZC/SECCFGR changes)"),
        "i2c_hw module doc must explicitly state no GTZC/SECCFGR changes",
    );
}

#[test]
fn negative_spi_hw_does_not_reclassify_lcd_bus_to_ns() {
    // spi_hw.rs must not touch any SECCFGR register in code — the
    // trusted-display SPI bus must stay fully secure.
    assert!(
        !contains_in_code(SPI_HW_SRC, "seccfgr"),
        "spi_hw must not access SECCFGR in code — trusted-display bus stays Secure (invariant #4)",
    );
    assert!(
        !contains_in_code(SPI_HW_SRC, "SECCFGR"),
        "spi_hw must not access SECCFGR in code — trusted-display bus stays Secure",
    );
    assert!(
        SPI_HW_SRC.contains("(no GTZC/SECCFGR changes)"),
        "spi_hw module doc must explicitly state no GTZC/SECCFGR changes",
    );
}

// ═════════════════════════════════════════════════════════════════════
// 19. NEGATIVE — Bounded loops everywhere (no unbounded busy-wait)
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_i2c2_probe_busy_wait_is_bounded() {
    assert!(I2C2_PROBE_SRC.contains("const TIMEOUT: u32 = 500_000;"));
}

// ═════════════════════════════════════════════════════════════════════
// 20. NEGATIVE — No unsafe MMIO outside Reg32/RoReg32 or documented sites
//
// `mmio` encapsulates the `unsafe { read_volatile / write_volatile }`
// once per peripheral so drivers expose safe `.read()/.write()/.modify()`.
// The legacy `read_volatile` / `write_volatile` calls survive in
// `i2c2_probe.rs` (dev-only) and `spi.rs` (8-bit FIFO accesses,
// documented SAFETY blocks). They must not bleed into i2c.rs /
// i2c_hw.rs / spi_hw.rs / usb_hw.rs / uart.rs / buttons.rs.
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_i2c_hw_no_raw_volatile_ops() {
    assert!(
        !I2C_HW_SRC.contains("read_volatile") && !I2C_HW_SRC.contains("write_volatile"),
        "i2c_hw.rs must funnel all MMIO through `hw::mmio::{{Reg32, RoReg32}}`",
    );
}

#[test]
fn negative_spi_hw_no_raw_volatile_ops() {
    assert!(
        !SPI_HW_SRC.contains("read_volatile") && !SPI_HW_SRC.contains("write_volatile"),
        "spi_hw.rs must funnel all MMIO through `hw::mmio::{{Reg32, RoReg32}}`",
    );
}

#[test]
fn negative_uart_no_raw_volatile_ops() {
    assert!(
        !UART_SRC.contains("read_volatile") && !UART_SRC.contains("write_volatile"),
        "uart.rs must funnel all MMIO through `hw::mmio::{{Reg32, RoReg32}}`",
    );
}

#[test]
fn negative_buttons_no_raw_volatile_ops() {
    assert!(
        !BUTTONS_SRC.contains("read_volatile") && !BUTTONS_SRC.contains("write_volatile"),
        "buttons.rs must funnel all MMIO through `hw::mmio::{{Reg32, RoReg32}}`",
    );
}

// usb_hw.rs has one debug-log-gated `read_volatile` for the SECCFGR offset
// probe (legitimate dev-loop reading multiple offsets in a list). Pin it
// so the diagnostic doesn't migrate from debug-log into the main path.
#[test]
fn negative_usb_hw_raw_volatile_only_under_debug_log_diagnostic() {
    let count = USB_HW_SRC.matches("read_volatile").count();
    assert!(count <= 1, "usb_hw.rs may have at most one raw read_volatile (the debug-log SECCFGR offset probe)");
    assert!(
        !USB_HW_SRC.contains("write_volatile"),
        "usb_hw.rs must NOT use raw write_volatile — all writes through Reg32",
    );
    // The single allowed read_volatile must be inside a debug-log cfg block.
    assert!(
        USB_HW_SRC.contains("#[cfg(feature = \"debug-log\")]"),
        "usb_hw.rs must keep any raw read_volatile gated behind #[cfg(feature = \"debug-log\")]",
    );
}

// ═════════════════════════════════════════════════════════════════════
// 22. NEGATIVE — Buttons trusted-UI invariants
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_buttons_combo_waits_for_full_release_before_emitting() {
    // wait_combo_release must wait for BOTH buttons to be debounced-
    // released before returning. Without this, the confirm event could
    // emit while one finger is still on the button → user-perceivable
    // double-press / accidental confirm of a follow-up dialog.
    assert!(BUTTONS_SRC.contains("if !left_pressed() && !right_pressed() {"));
    assert!(BUTTONS_SRC.contains("fn wait_combo_release"));
}

#[test]
fn negative_buttons_long_press_threshold_is_500ms() {
    // The Long/Short threshold is load-bearing for the trusted-UI
    // confirm semantics — short = navigate, long = confirm. A
    // regression to e.g. 100 ms could cause accidental confirms during
    // navigation.
    assert!(BUTTONS_SRC.contains("const LONG_PRESS_MS: u32 = 500;"));
    // Also confirm the threshold is compared against `held_ms`.
    assert!(BUTTONS_SRC.contains("if held_ms >= LONG_PRESS_MS {"));
}

#[test]
fn negative_buttons_must_not_consume_extra_swd_pins() {
    // GPIOC moder is touched at bits [3:2] (PC1) and [27:26] (PC13). No
    // other shifts allowed.
    let allowed_c_modes = ["!(0b11 << 2)", "!(0b11 << 26)"];
    for line in BUTTONS_SRC.lines() {
        if line.contains("gpioc_moder.modify") {
            let mut ok = false;
            for allowed in allowed_c_modes {
                if line.contains(allowed) {
                    ok = true;
                    break;
                }
            }
            assert!(ok, "buttons gpioc_moder.modify touches unexpected bits: `{line}`");
        }
    }
}

// ═════════════════════════════════════════════════════════════════════
// 23. NEGATIVE — UART defends against TEACK wedge
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_uart_teack_wait_is_bounded_not_unbounded_while() {
    // The TEACK wait is `while ... { t -= 1; if t == 0 { return; } }`
    // — bounded. Reject any `while ... {}` that doesn't decrement.
    assert!(UART_SRC.contains("while REG.isr.read() & ISR_TEACK == 0 {"));
    assert!(UART_SRC.contains("t -= 1;"));
}

#[test]
fn negative_uart_write_byte_has_no_secret_param() {
    // write_byte / write_bytes / write_str take ordinary `u8` /
    // `&[u8]` / `&str` — they MUST NOT take a `&Secret<...>` /
    // `Zeroizing<...>` / similar wrapped-secret type because uart.rs
    // is the byte-egress primitive: anything wrapped that arrives here
    // is being copied to the wire by definition.
    assert!(UART_SRC.contains("pub fn write_byte(b: u8)"));
    assert!(UART_SRC.contains("pub fn write_bytes(bytes: &[u8])"));
    assert!(UART_SRC.contains("pub fn write_str(s: &str)"));
    let banned: &[&str] = &["Secret", "Zeroizing", "ZeroizeOnDrop"];
    for needle in banned {
        assert!(
            !UART_SRC.contains(needle),
            "uart.rs must not import secret-wrapper types; found `{needle}`",
        );
    }
}

// ═════════════════════════════════════════════════════════════════════
// 24. NEGATIVE — Public surface stays minimal
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_i2c_hw_public_surface_only_init() {
    // i2c_hw.rs is hardware-init only — no data-path API.
    let pub_fns: Vec<_> = I2C_HW_SRC
        .lines()
        .filter(|l| l.trim_start().starts_with("pub fn ") || l.trim_start().starts_with("pub unsafe fn "))
        .collect();
    assert_eq!(
        pub_fns.len(), 1,
        "i2c_hw.rs must expose exactly 1 public fn (init); found {:?}", pub_fns,
    );
}

#[test]
fn negative_spi_hw_public_surface_only_init_cs() {
    // spi_hw.rs: init() + cs_assert() + cs_deassert() — three small
    // helpers. Nothing else.
    let pub_fns: Vec<_> = SPI_HW_SRC
        .lines()
        .filter(|l| l.trim_start().starts_with("pub fn ") || l.trim_start().starts_with("pub unsafe fn "))
        .collect();
    assert_eq!(
        pub_fns.len(), 3,
        "spi_hw.rs must expose exactly 3 public fns (init, cs_assert, cs_deassert); found {:?}", pub_fns,
    );
}

// ═════════════════════════════════════════════════════════════════════
// 25. POSITIVE — pin-mapping cross-check vs CLAUDE.md
//
// CLAUDE.md / module docstrings nail down PA8 = RIGHT button, PC1 =
// LEFT button. The bit positions derived from these pin numbers must
// match the register encoding (pin N → MODER bits [2N+1:2N], etc.).
// This is a "math agrees with naming" pin.
// ═════════════════════════════════════════════════════════════════════

#[test]
fn positive_buttons_bit_positions_match_pin_numbers() {
    // PC1 = pin 1, so LEFT_BIT = 1 << 1.
    let left_pin: u32 = 1;
    assert!(BUTTONS_SRC.contains(&format!("const LEFT_BIT: u32 = 1 << {left_pin};")));
    // PA8 = pin 8, so RIGHT_BIT = 1 << 8.
    let right_pin: u32 = 8;
    assert!(BUTTONS_SRC.contains(&format!("const RIGHT_BIT: u32 = 1 << {right_pin};")));

    // MODER bits for pin N are [2N+1:2N].
    let pc1_moder_shift = 2 * left_pin; // 2
    let pa8_moder_shift = 2 * right_pin; // 16
    assert!(BUTTONS_SRC.contains(&format!("!(0b11 << {pc1_moder_shift})")));
    assert!(BUTTONS_SRC.contains(&format!("!(0b11 << {pa8_moder_shift})")));
    // PUPDR bits same shift as MODER (2N+1:2N).
    assert!(BUTTONS_SRC.contains(&format!("(0b01 << {pc1_moder_shift})")));
    assert!(BUTTONS_SRC.contains(&format!("(0b01 << {pa8_moder_shift})")));
}
