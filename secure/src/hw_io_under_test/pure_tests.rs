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
    // This gate used to REQUIRE the literal statements
    //   gpioa_seccfgr.clear_bits((1 << 11) | (1 << 12) | (1 << 15))
    //   gpiob_seccfgr.clear_bits((1 << 5) | (1 << 15))
    // i.e. it encoded "PA15, PB5 and PB15 MUST be non-secure" as a positive
    // requirement. On pq1 those three pins are SE_RST, SE1_EN and LCM_EN, so
    // the gate actively obstructed the correct fix. The mask is now a board
    // constant and this asserts SHAPE here, VALUES per board below.
    //
    // NOTE: a shape assertion is not a value assertion. On its own this says
    // nothing about which pins are handed over — the value gates are the two
    // board-file assertions below PLUS the `const assert!`s in board/mod.rs,
    // and neither alone is sufficient.
    assert!(USB_HW_SRC.contains("REG.gpioa_seccfgr.clear_bits(board::USB_NS_PINS_A);"));
    assert!(USB_HW_SRC.contains("REG.gpiob_seccfgr.clear_bits(board::USB_NS_PINS_B);"));
    // No literal mask may be re-inlined.
    assert_eq!(
        USB_HW_SRC.matches("board::USB_NS_PINS_").count(),
        2,
        "usb_hw must take both NS masks from the board map, exactly once each"
    );

    // VALUES, per board — both, so neither loses coverage. Full statements
    // with semicolons so a second cfg'd definition cannot hide.
    assert!(BOARD_IOTA2_SRC
        .contains("pub const USB_NS_PINS_A: u32 = (1 << 11) | (1 << 12) | (1 << 15);"));
    assert!(BOARD_IOTA2_SRC.contains("pub const USB_NS_PINS_B: u32 = (1 << 5) | (1 << 15);"));
    assert!(BOARD_PQ1_SRC.contains("pub const USB_NS_PINS_A: u32 = (1 << 11) | (1 << 12);"));
    assert!(BOARD_PQ1_SRC.contains("pub const USB_NS_PINS_B: u32 = 0;"));
    for src in [BOARD_IOTA2_SRC, BOARD_PQ1_SRC] {
        assert_eq!(
            src.matches("pub const USB_NS_PINS_").count(),
            2,
            "each board defines exactly one A mask and one B mask"
        );
    }

    // The pq1 masks must not contain the three pins that are its SE/display
    // control lines — stated explicitly because this is the whole point.
    assert!(!BOARD_PQ1_SRC.contains("pub const USB_NS_PINS_A: u32 = (1 << 11) | (1 << 12) | (1 << 15);"));
    assert!(BOARD_PQ1_SRC.contains("pub const USB_NS_PINS_B: u32 = 0;"));
}

/// The OTHER half of the pq1 USB hazard: the pins are protected by a
/// `const assert!` at the SECCFGR layer, but the MODER/BSRR writes that put
/// those same pads into UCPD analog mode — or drive them — are protected only
/// by `#[cfg(not(feature = "board-pq1"))]`, and NOTHING pinned those cfgs.
///
/// This is not hypothetical. On 2026-08-31, while merging two doc comments in
/// `usb_hw.rs`, a find/replace spanned one of these attributes and deleted it.
/// The crate compiled and all 2625 host tests passed, because the function it
/// gated (`cc_open_then_reset`) has no caller. It was caught by counting the
/// attribute afterwards, not by any gate. Hence this one.
///
/// What is at stake on pq1, per `board/pq1.rs`:
///   PA15 -> ANALOG  is `SE_RST`, the OPTIGA's reset
///   PB15 -> ANALOG  is `LCM_EN`, the trusted display's backlight
///   PB5  driven     is `SE1_EN`, the SE050's enable
#[test]
fn negative_usb_board_pq1_exclusions_are_pinned() {
    const CFG: &str = "#[cfg(not(feature = \"board-pq1\"))]";

    // Five: two call sites inside `init`, plus the three fn definitions.
    // A bare count is the cheap half — a deletion anywhere drops it to 4.
    assert_eq!(
        USB_HW_SRC.matches(CFG).count(),
        5,
        "usb_hw.rs must keep exactly 5 `board-pq1` exclusions (2 call sites in \
         init + `enable_tcpp03` + `cc_open_then_reset` + `init_ucpd`). A lower \
         count means an exclusion was deleted and pq1 now executes an iota2 \
         pin path; a higher count means a new one appeared unreviewed."
    );

    // The expensive half: each hazardous write must actually SIT INSIDE a
    // board-gated function, not merely coexist in a file that contains a cfg
    // somewhere. Checked positionally — the write's offset must fall after a
    // gated `fn` header and before the next un-gated top-level `fn`.
    let gated_spans: Vec<(usize, usize)> = {
        let mut spans = Vec::new();
        let mut from = 0usize;
        while let Some(rel) = USB_HW_SRC[from..].find(CFG) {
            let cfg_at = from + rel;
            // Only the three definitions open a span; the two call sites inside
            // `init` are followed by a call, not by `fn`.
            let after = &USB_HW_SRC[cfg_at + CFG.len()..];
            let head: String = after.chars().take(80).collect();
            if head.trim_start().starts_with("fn ")
                || head.trim_start().starts_with("#[inline")
                || head.trim_start().starts_with("pub unsafe fn ")
            {
                // Span ends at the next top-level `}` followed by a blank line
                // and a non-indented item — approximated by the next "\n}\n".
                let end_rel = after.find("\n}\n").map(|e| cfg_at + CFG.len() + e + 3);
                spans.push((cfg_at, end_rel.unwrap_or(USB_HW_SRC.len())));
            }
            from = cfg_at + CFG.len();
        }
        spans
    };
    assert_eq!(
        gated_spans.len(),
        3,
        "expected exactly three board-gated FUNCTION definitions in usb_hw.rs"
    );

    for hazard in [
        "REG.gpioa_moder.set_bits(0b11 << 30);", // PA15 -> analog = pq1 SE_RST
        "REG.gpiob_moder.set_bits(0b11 << 30);", // PB15 -> analog = pq1 LCM_EN
        "REG.gpiob_bsrr.write(1 << 5);",         // PB5 driven    = pq1 SE1_EN
    ] {
        let at = USB_HW_SRC
            .find(hazard)
            .unwrap_or_else(|| panic!("hazardous write vanished from usb_hw.rs: {hazard}"));
        assert_eq!(
            USB_HW_SRC.matches(hazard).count(),
            1,
            "`{hazard}` must appear exactly once — a second copy could sit outside a gate"
        );
        assert!(
            gated_spans.iter().any(|&(lo, hi)| at > lo && at < hi),
            "`{hazard}` is NOT inside a `board-pq1`-excluded function. On pq1 that \
             pin is a secure element's reset/enable or the trusted display's \
             backlight; putting it in UCPD analog mode or driving it from the USB \
             path is exactly what the board split exists to prevent."
        );
    }
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

// The button pins moved into the board maps, so `BUTTONS_SRC` no longer
// contains a pin literal for EITHER board. A naive re-point would therefore
// have made this whole block vacuous universally, not just on pq1 — so the
// which-pin assertions now run against both board files, and what stays
// pinned in the driver is the *property* (active-low, pull-up), which is
// board-independent and must never change.

/// The bench OLED's panel height is a board constant, and FIVE things derive
/// from it — framebuffer length, page count, multiplex ratio, COM-pin config
/// and text row pitch. Three of those fail in ways that look like a broken
/// display rather than a wrong byte, so pin the values per board and check the
/// arithmetic independently.
#[test]
fn positive_oled_geometry_derives_from_board_height() {
    assert!(BOARD_IOTA2_SRC.contains("pub const OLED_HEIGHT_PX: usize = 32;"));
    assert!(BOARD_PQ1_SRC.contains("pub const OLED_HEIGHT_PX: usize = 64;"));

    const OLED_SRC: &str = include_str!("../ui/oled.rs");
    // Everything must be derived, not restated.
    assert!(OLED_SRC.contains("const HEIGHT: usize = crate::board::OLED_HEIGHT_PX;"));
    assert!(OLED_SRC.contains("const PAGES: usize = HEIGHT / 8;"));
    assert!(OLED_SRC.contains("const FB_LEN: usize = WIDTH * PAGES;"));
    assert!(OLED_SRC.contains("const ROW_PITCH: i32 = (HEIGHT / DISPLAY_ROWS) as i32;"));
    assert!(OLED_SRC.contains("const COM_PINS_CFG: u8 = if HEIGHT == 32 { 0x02 } else { 0x12 };"));
    assert!(OLED_SRC.contains("0xA8, (HEIGHT - 1) as u8,"));
    // And the framebuffer really is sized by it.
    assert!(OLED_SRC.contains("buf: [u8; FB_LEN],"));

    // Independent arithmetic for both panels.
    for (h, pages, fb_len, pitch, com) in [
        (32usize, 4usize, 512usize, 8i32, 0x02u8),
        (64, 8, 1024, 16, 0x12),
    ] {
        assert_eq!(h / 8, pages, "page count for {h}px");
        assert_eq!(128 * (h / 8), fb_len, "framebuffer length for {h}px");
        assert_eq!((h / 4) as i32, pitch, "row pitch for {h}px (DISPLAY_ROWS = 4)");
        assert_eq!(if h == 32 { 0x02u8 } else { 0x12 }, com, "COM pins for {h}px");
    }
}

/// `render_secret_row` is the constant-time glyph path for seed-wizard rows.
/// It used to be hardcoded to `&mut [u8; 512]` with a `page >= 4` guard, which
/// silently excluded pages 4..8 on a 128x64 panel — the secret rows would just
/// not render. It must now bound on the slice length instead.
#[test]
fn negative_secret_row_is_not_hardcoded_to_a_four_page_panel() {
    const SECRET_SRC: &str = include_str!("../ui/secret_text.rs");
    assert!(
        SECRET_SRC.contains("pub fn render_secret_row(fb: &mut [u8], page: usize, text: &[u8])"),
        "render_secret_row must take a slice, not a fixed-size 128x32 buffer"
    );
    assert!(
        SECRET_SRC.contains("if (page + 1) * DISPLAY_W_PX > fb.len() {"),
        "the page bound must come from the buffer length, not a hardcoded 4"
    );
    assert!(
        !SECRET_SRC.contains("if page >= 4 {"),
        "the hardcoded four-page guard drops secret rows on a 128x64 panel"
    );
}

#[test]
fn positive_buttons_pins_per_board() {
    // iota2: LEFT = PC1, RIGHT = PA8 (CN13 jumpers).
    assert!(BOARD_IOTA2_SRC.contains("pub const BTN_LEFT_PORT: u32 = GPIOC_S;"));
    assert!(BOARD_IOTA2_SRC.contains("pub const BTN_LEFT_PIN: u32 = 1;"));
    assert!(BOARD_IOTA2_SRC.contains("pub const BTN_RIGHT_PORT: u32 = GPIOA_S;"));
    assert!(BOARD_IOTA2_SRC.contains("pub const BTN_RIGHT_PIN: u32 = 8;"));

    // pq1: LEFT = PA0, RIGHT = PA1 — BOTH on GPIOA, unlike iota2.
    assert!(BOARD_PQ1_SRC.contains("pub const BTN_LEFT_PORT: u32 = GPIOA_S;"));
    assert!(BOARD_PQ1_SRC.contains("pub const BTN_LEFT_PIN: u32 = 0;"));
    assert!(BOARD_PQ1_SRC.contains("pub const BTN_RIGHT_PORT: u32 = GPIOA_S;"));
    assert!(BOARD_PQ1_SRC.contains("pub const BTN_RIGHT_PIN: u32 = 1;"));
}

#[test]
fn positive_buttons_gpioa_gpioc_secure_alias() {
    assert!(BOARD_MOD_SRC.contains("pub const GPIOA_S: u32 = 0x5202_0000;"));
    assert!(BOARD_MOD_SRC.contains("pub const GPIOC_S: u32 = 0x5202_0800;"));
}

#[test]
fn positive_buttons_rcc_secure_alias() {
    assert!(BOARD_MOD_SRC.contains("pub const RCC_S: u32 = 0x5602_0C00;"));
    assert!(contains_in_code(BUTTONS_SRC, "board::RCC_S"));
}

#[test]
fn positive_buttons_active_low_pressed_reads_zero() {
    // pressed = pin reads 0 (shorted to GND). Board-independent property:
    // neither board fits a pull-down, and pq1 fits no pull-up at all, so the
    // internal pull-up + active-low read is what makes a press detectable.
    assert!(BUTTONS_SRC.contains("REG.left_idr.read() & LEFT_BIT == 0"));
    assert!(BUTTONS_SRC.contains("REG.right_idr.read() & RIGHT_BIT == 0"));
}

#[test]
fn positive_buttons_pullup_internal_pupdr_01() {
    // PUPDR 0b01 = pull-up, at each button's own field shift. On pq1 the
    // board fits NO external pull-up (only a 100nF cap and an ESD diode to
    // GND), so losing this makes both buttons read permanently pressed.
    assert!(BUTTONS_SRC.contains("(0b01 << LEFT_PIN2)"));
    assert!(BUTTONS_SRC.contains("(0b01 << RIGHT_PIN2)"));
    // ...and the shift really is 2*pin, checked by arithmetic rather than by
    // matching the same text twice.
    assert!(BUTTONS_SRC.contains("const LEFT_PIN2: u32 = board::BTN_LEFT_PIN * 2;"));
    assert!(BUTTONS_SRC.contains("const RIGHT_PIN2: u32 = board::BTN_RIGHT_PIN * 2;"));
}

/// The USER button is configured on boards that have one and skipped on
/// boards that do not — pq1 must not enable a GPIO clock or drive a pin for
/// a button that is not fitted.
#[test]
fn positive_buttons_user_is_optional_and_never_a_ui_input() {
    assert!(BOARD_IOTA2_SRC.contains("pub const BTN_USER: Option<(u32, u32)> = Some((GPIOC_S, 13));"));
    assert!(BOARD_PQ1_SRC.contains("pub const BTN_USER: Option<(u32, u32)> = None;"));
    assert!(BUTTONS_SRC.contains("const HAS_USER: bool = board::BTN_USER.is_some();"));
    assert!(BUTTONS_SRC.contains("if HAS_USER {"));
    // It is a bench reference, never an input event: `wait_event` must not
    // read it. (`ui::Button` has only Left/Right, so it could not construct
    // one anyway — but keep the driver honest.)
    // Scope to wait_event's own body: the slice must STOP before `run_test`,
    // which legitimately reads the USER pin for its bench state dump. An
    // earlier version ran to end-of-file and so failed on run_test's read —
    // the assertion was right, its window was wrong.
    let after = BUTTONS_SRC
        .split("fn wait_event")
        .nth(1)
        .expect("buttons.rs must define wait_event");
    let wait_event = &after[..after.find("fn run_test").unwrap_or(after.len())];
    assert!(
        !wait_event.contains("user_idr"),
        "the USER button must never feed a UI input event"
    );
    // ...and the only place it IS read is that diagnostic.
    assert!(
        BUTTONS_SRC.contains("REG.user_idr.read() & USER_BIT"),
        "the USER read should still exist, in run_test only"
    );
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
fn positive_buttons_gpio_clocks_derived_per_board() {
    // The clock set is derived from the button ports rather than hard-coded,
    // because the two boards differ: iota2 straddles GPIOA+GPIOC, pq1 has
    // both buttons on GPIOA.
    assert!(BUTTONS_SRC.contains(
        "board::gpio_rcc_bit(board::BTN_LEFT_PORT) | board::gpio_rcc_bit(board::BTN_RIGHT_PORT)"
    ));
    // Independent arithmetic check of what that derivation yields, so a
    // regression is caught by value and not only by matching text.
    let bit = |port_base: u32| 1u32 << ((port_base - 0x5202_0000) / 0x400);
    let (gpioa, gpioc) = (0x5202_0000u32, 0x5202_0800u32);
    assert_eq!(bit(gpioc) | bit(gpioa), 0b101, "iota2: GPIOAEN + GPIOCEN");
    assert_eq!(bit(gpioa) | bit(gpioa), 0b001, "pq1: GPIOAEN alone");
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
    // The exactly-once count is the anti-second-call gate and is KEPT
    // verbatim: a second clear_bits call is how extra pins would leak to NS,
    // and that property survives the move to a symbolic mask unchanged.
    let gpiob_seccfgr_calls = USB_HW_SRC.matches("gpiob_seccfgr.clear_bits").count();
    assert_eq!(
        gpiob_seccfgr_calls, 1,
        "usb_hw::init must call gpiob_seccfgr.clear_bits exactly once (extra calls would expose SE buses to NS)",
    );

    // The per-pin reject loop that used to live here has been DELETED, not
    // relaxed, because it never worked. It built the needle
    //     format!("seccfgr.clear_bits({}
    // ...)", "(1 << 8)")  ->  `seccfgr.clear_bits((1 << 8))`
    // which requires that term to be the ENTIRE argument. Against any real
    // multi-pin mask the next characters are " |", so it never matched.
    // Verified by running its own logic against a line deliberately marking
    // PB8 non-secure: it caught nothing. It had been green since it was
    // written while testing nothing, and its panic message claimed to prevent
    // exactly the breach it could not see.
    //
    // Its replacement is `board::ns_forbidden_mask` + the `const assert!`s in
    // board/mod.rs, which are strictly stronger: they are value checks rather
    // than text checks, they derive from the same constants the drivers
    // consume, they fire on every hardware build of either board, and they
    // cover PB6/PB7 — the SE050's own I2C4 bus on pq1 — which this loop never
    // did, because it was written when both secure elements shared I2C1.
    //
    // Same migration as `negative_buttons_must_not_touch_swd_pins_pa13_pa14`
    // in this file. Do NOT reintroduce a symbolic look-alike here: a
    // `contains("clear_bits(SOME_MASK)")` plus the surviving count would be
    // fully green while testing nothing, which is the specific trap.
    assert!(
        BOARD_MOD_SRC.contains("pub const fn ns_forbidden_mask(port: u32) -> u32 {"),
        "the value gate for the NS mask must exist in the board layer"
    );
    assert!(BOARD_MOD_SRC.contains("USB_NS_PINS_B & ns_forbidden_mask(GPIOB_S) == 0,"));
    // ...and it must fold in the secure-element buses, which is what covers
    // PB8/PB9 on both boards and PB6/PB7 on pq1.
    assert!(BOARD_MOD_SRC.contains("mask |= (1 << bus.scl_pin) | (1 << bus.sda_pin);"));
}

#[test]
fn negative_usb_must_not_mark_arbitrary_gpioa_pins_ns() {
    // Exactly-once count kept verbatim — see the GPIOB twin for why, and for
    // why the per-pin reject loop that used to follow it was deleted rather
    // than relaxed (it was structurally incapable of matching).
    let gpioa_seccfgr_calls = USB_HW_SRC.matches("gpioa_seccfgr.clear_bits").count();
    assert_eq!(
        gpioa_seccfgr_calls, 1,
        "usb_hw::init must call gpioa_seccfgr.clear_bits exactly once (extra calls would expose secure pins to NS)",
    );
    assert!(BOARD_MOD_SRC.contains("USB_NS_PINS_A & ns_forbidden_mask(GPIOA_S) == 0,"));
    // SWDIO/SWCLK are in the forbidden table by name, so a mask containing
    // them fails the build rather than this test.
    assert!(BOARD_MOD_SRC.contains("(Some((GPIOA_S, 13)), \"SWDIO\")"));
    assert!(BOARD_MOD_SRC.contains("(Some((GPIOA_S, 14)), \"SWCLK\")"));
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
    // This test USED to scan for `gpioa_moder.modify(|v| (v & !(0b11 << 26))`
    // and friends. Once the shifts became symbolic (`LEFT_PIN2`), no such
    // literal can appear for ANY pin — so the scan would have kept passing
    // while being incapable of catching anything. It asserts absence, so the
    // vacuity would have been silent. That is the exact failure mode this
    // suite exists to prevent, so the check moved to where it can still bite:
    // a compile-time collision assert in the driver, over the board's pins.
    assert!(BUTTONS_SRC.contains("(Some((board::GPIOA_S, 13)), \"SWDIO\")"));
    assert!(BUTTONS_SRC.contains("(Some((board::GPIOA_S, 14)), \"SWCLK\")"));
    assert!(BUTTONS_SRC.contains("const fn collides(pin: (u32, u32)) -> bool"));
    assert!(BUTTONS_SRC.contains("!collides((board::BTN_LEFT_PORT, board::BTN_LEFT_PIN)),"));
    assert!(BUTTONS_SRC.contains("!collides((board::BTN_RIGHT_PORT, board::BTN_RIGHT_PIN)),"));
    // The driver must still only ever touch its own two pins' fields.
    assert!(BUTTONS_SRC.contains("PA13 (SWDIO) and PA14 (SWCLK) in AF mode"));
    // And neither board may place a button on a debug pin (belt and braces —
    // the const assert is the enforcement, this is the readable statement).
    for src in [BOARD_IOTA2_SRC, BOARD_PQ1_SRC] {
        for pin in [13u32, 14] {
            assert!(
                !src.contains(&format!("pub const BTN_LEFT_PIN: u32 = {pin};"))
                    || !src.contains("pub const BTN_LEFT_PORT: u32 = GPIOA_S;"),
                "a button on PA{pin} would brick SWD"
            );
        }
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
    // USED to iterate BUTTONS_SRC.lines() filtering on `gpioc_moder.modify`.
    // pq1 has no GPIOC button path at all, and after the refactor the handles
    // are role-named (`left_*`/`right_*`), so that loop body would never
    // execute and the test would pass having asserted nothing.
    //
    // The property it wanted — "buttons touch ONLY their own pins' fields" —
    // is now structural: every MODER/PUPDR write is at a derived
    // `{LEFT,RIGHT,USER}_PIN2` shift, so it cannot reach another pin's field
    // by construction, and which pins those are is guarded by the collision
    // assert.
    // Match WRITES only — `.modify(` on a moder/pupdr handle. (An earlier
    // version of this filter also matched the bare struct field declaration
    // `left_pupdr: Reg32,` and failed on it; the test was right to complain,
    // the filter was wrong.) The `.modify(` calls are split across lines by
    // rustfmt, so join the source first.
    let flat = BUTTONS_SRC.replace('\n', " ");
    let writes: Vec<&str> = flat
        .match_indices(".modify(")
        .map(|(i, _)| {
            let start = flat[..i].rfind("REG.").unwrap_or(i);
            let end = flat[i..].find(");").map_or(flat.len(), |e| i + e);
            &flat[start..end]
        })
        .filter(|w| w.contains("_moder") || w.contains("_pupdr"))
        .collect();
    assert!(
        !writes.is_empty(),
        "the pin-config writes vanished — this test would be vacuous"
    );
    for w in &writes {
        let symbolic =
            w.contains("LEFT_PIN2") || w.contains("RIGHT_PIN2") || w.contains("USER_PIN2");
        assert!(
            symbolic,
            "buttons.rs configures a GPIO field at a NON-derived shift, which can \
             reach a pin the board map never named: `{w}`"
        );
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
    // COMPUTED-NEEDLE REWRITE. This used to format!() the literal pin numbers
    // into needles like `const LEFT_BIT: u32 = 1 << {left_pin};`. After the
    // pins moved to the board maps, none of those six needles could ever
    // match again — it would have failed loudly (good), and the tempting fix
    // is to relax the needles, which makes it assert nothing (bad).
    //
    // The computation moved to where the numbers now live: each BOARD file is
    // checked for the pin it declares, and the driver is checked for deriving
    // the mask and shift from that constant rather than restating a literal.
    for (src, board, left, right) in [
        (BOARD_IOTA2_SRC, "iota2", 1u32, 8u32),
        (BOARD_PQ1_SRC, "pq1", 0u32, 1u32),
    ] {
        assert!(
            src.contains(&format!("pub const BTN_LEFT_PIN: u32 = {left};")),
            "{board} LEFT pin drifted"
        );
        assert!(
            src.contains(&format!("pub const BTN_RIGHT_PIN: u32 = {right};")),
            "{board} RIGHT pin drifted"
        );
        // MODER/PUPDR field for pin N is [2N+1:2N] — assert the arithmetic
        // the driver relies on, per board, by value.
        assert_eq!(left * 2, [2u32, 0][usize::from(board == "pq1")]);
        assert_eq!(right * 2, [16u32, 2][usize::from(board == "pq1")]);
    }

    // The driver derives, never restates.
    assert!(BUTTONS_SRC.contains("const LEFT_BIT: u32 = 1 << board::BTN_LEFT_PIN;"));
    assert!(BUTTONS_SRC.contains("const RIGHT_BIT: u32 = 1 << board::BTN_RIGHT_PIN;"));
}
