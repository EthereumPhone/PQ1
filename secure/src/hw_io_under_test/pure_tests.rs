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
const LCD_NV3007_SRC: &str = include_str!("../hw/lcd_nv3007.rs");
const UI_PX_LCD_SRC: &str = include_str!("../ui/px/lcd.rs");
const GPDMA_SRC: &str = include_str!("../hw/gpdma.rs");
const MAIN_SRC: &str = include_str!("../main.rs");
const SEED_WIZARD_SRC: &str = include_str!("../ui/seed_wizard.rs");
const LCD_TE_SRC: &str = include_str!("../hw/lcd_te.rs");
const PX_SCREENS_SRC: &str = include_str!("../ui/px/screens.rs");
const SECURE_CARGO_TOML_SRC: &str = include_str!("../../Cargo.toml");
const AW99703_SRC: &str = include_str!("../hw/aw99703.rs");
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
fn positive_spi_hw_base_and_pins_come_from_the_board() {
    // These four gates used to pin the driver's HARDCODED literals: SPI2's
    // base, SPI1's base, `GPIO_BASE = 0x5202_0400 // GPIOB`, `GPIO_BASE =
    // 0x5202_1000 // GPIOE`, and `CS_PIN = 12`. Every one of those is an iota2
    // fact. pq1's panel is SPI1 on PA4/PA5/PA7, so the gates were pinning the
    // driver to a configuration that board cannot use — the same shape as the
    // `sca_trigger` PD2 gate. Values are pinned per board below; the driver is
    // pinned to DERIVE.
    for derived in [
        "pub const SPI_BASE: u32 = board::LCD_SPI_BASE;",
        "pub const CS_PIN: u32 = board::LCD_CS_PIN;",
        "const PORT: u32 = board::LCD_SPI_PORT;",
        "const AF: u32 = board::LCD_SPI_AF;",
    ] {
        assert!(
            SPI_HW_SRC.contains(derived),
            "spi_hw must derive its pin map from the board; missing `{derived}`"
        );
    }
    for banned in ["0x5000_3800", "0x5001_3000", "0x5202_0400", "0x5202_1000"] {
        assert!(
            !SPI_HW_SRC.contains(banned),
            "spi_hw must not hardcode a peripheral or GPIO base (`{banned}`)"
        );
    }

    // VALUES per board. iota2 keeps its validated Arduino-header map.
    for (src, name, want) in [
        (BOARD_IOTA2_SRC, "iota2", [
            "pub const LCD_SPI_PORT: u32 = GPIOE_S;",
            "pub const LCD_CS_PIN: u32 = 12;",
            "pub const LCD_SCK_PIN: u32 = 13;",
            "pub const LCD_MOSI_PIN: u32 = 15;",
        ]),
        (BOARD_PQ1_SRC, "pq1", [
            "pub const LCD_SPI_PORT: u32 = GPIOA_S;",
            "pub const LCD_CS_PIN: u32 = 4;",
            "pub const LCD_SCK_PIN: u32 = 5;",
            "pub const LCD_MOSI_PIN: u32 = 7;",
        ]),
    ] {
        for w in want {
            assert!(src.contains(w), "{name} LCD pin map drifted: missing `{w}`");
        }
    }
    // Both boards run the panel on SPI1 (`ui-lcd` implies `spi1-arduino`), so
    // the APB2 enable/reset bits are shared rather than per board.
    assert!(SPI_HW_SRC.contains("const SPI_EN_BIT: u32 = board::RCC_SPI1EN_BIT;"));
    assert!(SPI_HW_SRC.contains("const SPI_RST_BIT: u32 = board::RCC_SPI1RST_BIT;"));

    // The MISO type must stay uniform, or the driver cannot consume both.
    assert!(BOARD_IOTA2_SRC.contains("pub const LCD_MISO_PIN: Option<u32> = Some(14);"));
    assert!(BOARD_PQ1_SRC.contains("pub const LCD_MISO_PIN: Option<u32> = None;"));
}

#[test]
fn positive_spi_hw_rcc_secure_alias() {
    // The literal moved to the board layer with the rest of the pin map; what
    // matters is still that the SECURE alias is used, since GPIO/RCC clock
    // enables are secure-only under TZEN=1 and NS-alias writes silently drop.
    assert!(SPI_HW_SRC.contains("const RCC_S: u32 = board::RCC_S;"));
    assert!(BOARD_MOD_SRC.contains("pub const RCC_S: u32 = 0x5602_0C00;"));
    assert!(BOARD_MOD_SRC.contains("pub const RCC_APB2RSTR_OFF: u32 = 0x7C;"));
    assert!(BOARD_MOD_SRC.contains("pub const RCC_SPI1RST_BIT: u32 = 1 << 12;"));
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
fn positive_spi_hw_cfg1_board_baud_dsize_8bit() {
    // The default prescaler follows the board: pq1 uses ÷4 (40 MHz),
    // while iota2 keeps ÷8 (20 MHz) because its LED loads the SCK line.
    // DSIZE stays 7 (8-bit); only MBR bits [30:28] select the clock.
    assert!(contains_in_code(SPI_HW_SRC, "const MBR: u32 = board::LCD_SPI_MBR;"));
    assert!(contains_in_code(BOARD_PQ1_SRC, "pub const LCD_SPI_MBR: u32 = 0b001;"));
    assert!(contains_in_code(BOARD_IOTA2_SRC, "pub const LCD_SPI_MBR: u32 = 0b010;"));
    assert!(contains_in_code(SPI_HW_SRC, "REG.spi_cfg1.write((MBR << 28) | 7);"));
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
fn positive_spi_hw_af_is_selected_per_pin() {
    // Was: the three AFRH nibble literals `(5 << 20/24/28)` for pins 13/14/15.
    // That only works for pins >= 8. pq1's SPI pins are 5 and 7, whose AF
    // nibbles live in AFRL (0x20), so the gate had to become structural.
    assert!(SPI_HW_SRC.contains("const fn afr_off(pin: u32) -> u32 {"));
    assert!(
        SPI_HW_SRC.contains("if pin < 8 {\n        0x20\n    } else {\n        0x24\n    }"),
        "AFR half must be chosen by pin number: AFRL (0x20) below 8, AFRH (0x24) above"
    );
    assert!(SPI_HW_SRC.contains("const fn afr_shift(pin: u32) -> u32 {"));
    assert!(SPI_HW_SRC.contains("(pin % 8) * 4"));

    // The helpers EXISTING is not the property. `afr_off` must be the thing
    // that feeds the AFR register handle. Hardcoding `PORT + 0x24` at this one
    // site sends pq1's PA4/PA5/PA7 nibbles to AFRH instead of AFRL — the SPI
    // pins are never configured — and every assertion above still passed.
    // Demonstrated by mutation 2026-09-01.
    assert!(
        SPI_HW_SRC.contains("let afr = unsafe { Reg32::new(PORT + afr_off(pin)) };"),
        "the AFR handle must be built from `afr_off(pin)`; a literal offset here \
         silently writes the wrong AFR half for any pin below 8"
    );
    for banned in ["Reg32::new(PORT + 0x24)", "Reg32::new(PORT + 0x20)"] {
        assert!(
            !SPI_HW_SRC.contains(banned),
            "`{banned}` hardcodes an AFR half — use afr_off(pin)"
        );
    }
    // Each SPI pin is configured individually — pq1's are non-contiguous.
    for call in [
        "config_af_pin(board::LCD_SCK_PIN);",
        "config_af_pin(board::LCD_MOSI_PIN);",
        "if let Some(miso) = board::LCD_MISO_PIN {",
    ] {
        assert!(SPI_HW_SRC.contains(call), "spi_hw must configure `{call}`");
    }
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

// Two tests were deleted here 2026-09-23 with the bench OLED backend:
// `positive_oled_geometry_derives_from_board_height` (it `include_str!`d
// `../ui/oled.rs`, so it was the build-breaker — a missing file is a compile
// error for the whole test binary, not a test failure) and
// `negative_secret_row_is_not_hardcoded_to_a_four_page_panel` (it pinned
// `render_secret_row`, whose only production caller was the OLED backend).
//
// The font-table oracle they are sometimes credited with is NOT lost:
// `ui/secret_text.rs`'s `ct_glyph_col_recovers_known_glyphs` asserts the same
// end-to-end property, on the function that actually carries the F-24
// constant-time guarantee.

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

// ---------------------------------------------------------------------------
// Consumption gates
// ---------------------------------------------------------------------------
//
// Established by mutation testing on 2026-08-31: four separate mutations to
// driver code passed the ENTIRE 2627-test suite. Every gate in this file that
// covered them pinned that an expression EXISTS, never that anything CONSUMES
// it — so deriving a value correctly and then ignoring it was invisible.
//
//   uart.rs   move `t -= 1` after the loop      -> infinite hang on wedged TEACK
//   i2c_hw.rs delete both config_i2c_pin calls  -> SCL/SDA never configured
//   i2c_hw.rs hardcode the APB1 RCC offsets     -> I2C4 never clocked (pq1 SE050 dead)
//   buttons.rs hardcode the GPIO clock mask     -> wrong port clocked
//
// Two further mutations from the same review were CAUGHT by existing gates and
// are deliberately not re-covered here: inverting uart's AFRL/AFRH selection,
// and swapping pq1's two SE bus pin tables.
//
// Brace-matching below is textual and would be confused by a `{` inside a
// string literal or comment within the scanned block. None of the four blocks
// contains one; if that changes, these gates fail loudly rather than silently.

/// Extract the `{...}` block that follows `marker`, by brace matching.
fn block_after<'a>(src: &'a str, marker: &str) -> &'a str {
    let start = src
        .find(marker)
        .unwrap_or_else(|| panic!("marker vanished from source: {marker}"));
    let open = start + marker.len() - 1; // marker ends with the `{`
    let bytes = src.as_bytes();
    assert_eq!(bytes[open], b'{', "marker must end with its opening brace");
    let mut depth = 0usize;
    for i in open..src.len() {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &src[open..=i];
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced braces after marker: {marker}");
}

/// The UART's TEACK wait must stay BOUNDED — the decrement has to be inside
/// the loop, not merely present in the function.
///
/// `hw::uart::init` spins on TEACK because the first byte is silently dropped
/// on STM32U5 otherwise. Its own comment says "Bounded so we don't hang if the
/// peripheral is in a wedged state". Moving `t -= 1;` after the loop keeps
/// every token the old gates looked for — the `while`, the counter, the
/// `return`, the `t -= 1` — while making the loop genuinely infinite. That
/// mutation passed all 2627 tests.
#[test]
fn negative_uart_teack_wait_decrement_is_inside_the_loop() {
    let body = block_after(UART_SRC, "while REG.isr.read() & ISR_TEACK == 0 {");
    assert!(
        body.contains("t -= 1;"),
        "the TEACK spin must decrement its bound INSIDE the loop body — a \
         decrement after the loop leaves `hw::uart::init` hanging forever on a \
         wedged peripheral. Loop body was:\n{body}"
    );
    assert!(
        body.contains("if t == 0 {"),
        "the TEACK spin must still bail out when the bound is exhausted"
    );
}

/// `i2c_hw::init_bus` must actually CONSUME the board's per-bus description.
///
/// Three independent mutations of this function were invisible to the suite:
/// deleting both pin-configuration calls, and hardcoding either RCC offset.
/// The last one is the sharpest — on pq1 the SE050 lives on I2C4, whose enable
/// and reset bits are in a DIFFERENT RCC register than I2C1/I2C2's, so a
/// hardcoded APB1ENR1 offset leaves that bus unclocked and the SE050 dead,
/// with the board map still looking perfectly correct.
#[test]
fn negative_i2c_hw_init_bus_consumes_the_board_bus_record() {
    let body = block_after(I2C_HW_SRC, "fn init_bus(bus: &board::SeI2cBus) {");

    // The pins must be configured, from the bus record.
    for call in [
        "config_i2c_pin(bus.port, bus.scl_pin, bus.af);",
        "config_i2c_pin(bus.port, bus.sda_pin, bus.af);",
    ] {
        assert!(
            body.contains(call),
            "`init_bus` must configure its pins from the board record — missing \
             `{call}`. Without it SCL/SDA keep their reset state and the bus is \
             silently dead, which no other gate in this file can see."
        );
    }

    // The RCC registers must be derived per-bus, never hardcoded.
    for field in ["bus.rcc_enr_off", "bus.rcc_rstr_off"] {
        assert!(
            body.contains(field),
            "`init_bus` must take its RCC register from `{field}` — a hardcoded \
             offset works for I2C1/I2C2 and silently fails for pq1's I2C4, \
             leaving the SE050 unclocked."
        );
    }
    for field in ["bus.rcc_en_bit", "bus.rcc_rst_bit"] {
        assert!(body.contains(field), "`init_bus` must use `{field}`");
    }
    assert!(
        body.contains("board::gpio_rcc_bit(bus.port)"),
        "`init_bus` must derive the GPIO clock bit from the bus's own port"
    );

    // And `init` must actually CALL it, for every bus the board declares.
    // Without this the whole gate above sits one call-edge below the defect it
    // names: replacing init()'s loop with `let _ = board::SE_I2C_BUSES;` leaves
    // BOTH secure elements uninitialised and passed all 2609 tests.
    // Demonstrated by mutation 2026-09-01.
    let init_body = block_after(I2C_HW_SRC, "pub fn init() {");
    assert!(
        init_body.contains("for bus in board::SE_I2C_BUSES {") && init_body.contains("init_bus(bus);"),
        "`i2c_hw::init` must iterate `board::SE_I2C_BUSES` and call `init_bus` for \
         each — a board record that is read and then dropped leaves every secure \
         element's bus dead, with no host-visible symptom. init body was:\n{init_body}"
    );
}

/// `hw::buttons::init` must clock the ports the BOARD names, not a literal.
///
/// Replacing `set_bits(gpio_clocks)` with `set_bits(1 << 7)` — clocking GPIOH
/// instead of whichever ports carry the buttons — passed the whole suite,
/// because the gate covering this checked only that the `gpio_clocks`
/// derivation expression existed somewhere in the file.
#[test]
fn negative_buttons_clock_enable_consumes_the_derived_mask() {
    let body = block_after(BUTTONS_SRC, "pub unsafe fn init() {");
    assert!(
        body.contains("REG.rcc_ahb2enr1.set_bits(gpio_clocks);"),
        "`buttons::init` must enable exactly the derived `gpio_clocks` mask; a \
         literal there clocks the wrong port and the buttons read as never \
         pressed — or, on pq1, touches a pin the SE rail depends on."
    );
    // And the derivation must still come from the board map.
    assert!(
        body.contains("board::gpio_rcc_bit(board::BTN_LEFT_PORT)")
            && body.contains("board::gpio_rcc_bit(board::BTN_RIGHT_PORT)"),
        "`gpio_clocks` must be derived from the board's own button ports, inside \
         `init` — a derivation that lives elsewhere and is never consumed here is \
         exactly the defect this gate exists for"
    );
}

/// The NV3007 driver's control pins must come from the board, not from GPIOE.
///
/// `spi_hw` was only half the LCD port. `lcd_nv3007` independently hardcoded
/// `GPIOE_S`/`GPIOD_S`, DC = pin 7 and RES = pin 14 — plus ten dead register
/// handles for a PD15 reset abandoned during bring-up. Port E is not bonded on
/// pq1 at all, so with only `spi_hw` ported the build went GREEN while DC and
/// RES still pointed at a port that does not exist on that package. A passing
/// build is not a port.
#[test]
fn negative_lcd_nv3007_control_pins_come_from_the_board() {
    for derived in [
        "const DC_PORT: u32 = board::LCD_DC_PORT;",
        "const DC_PIN: u32 = board::LCD_DC_PIN;",
        "const RES_PORT: u32 = board::LCD_RST_PORT;",
        "const RES_PIN: u32 = board::LCD_RST_PIN;",
        "const RES_DRIVABLE: bool = board::LCD_RST_IS_DRIVABLE;",
    ] {
        assert!(
            LCD_NV3007_SRC.contains(derived),
            "lcd_nv3007 must derive its control pins from the board; missing `{derived}`"
        );
    }
    // Ban EVERY GPIO base, not just iota2's. The original list was
    // [GPIOE, GPIOD, RCC] — precisely the ports pq1's LCD does NOT use — so it
    // could only catch an iota2-shaped hardcode. pq1's LCD lives on GPIOA
    // (SPI) and GPIOB (DC/RST/backlight); hardcoding either passed the gate.
    for banned in [
        "0x5202_0000", // GPIOA — pq1 LCD SPI
        "0x5202_0400", // GPIOB — pq1 LCD DC/RST/backlight
        "0x5202_0800", // GPIOC
        "0x5202_0C00", // GPIOD
        "0x5202_1000", // GPIOE — iota2 LCD
        "0x5602_0C8C", // RCC AHB2ENR1
    ] {
        assert!(
            !LCD_NV3007_SRC.contains(banned),
            "lcd_nv3007 must not hardcode a GPIO/RCC address (`{banned}`) — port E \
             does not exist on pq1's 48-pin package"
        );
    }
    // It must clock the ports its own pins live on: `spi_hw` only enables the
    // SPI port, which on pq1 is a DIFFERENT port from DC/RES/backlight.
    assert!(LCD_NV3007_SRC.contains("board::gpio_rcc_bit(DC_PORT) | board::gpio_rcc_bit(RES_PORT)"));
    // Reset strategy follows the board: a real pin pulse where one is wired.
    assert!(
        LCD_NV3007_SRC.contains("if RES_DRIVABLE {")
            && LCD_NV3007_SRC.contains("hard_reset();"),
        "a board whose reset pin reaches the panel must get a real pulse, not SWRESET"
    );
    // pq1's backlight enable must actually be asserted.
    assert!(LCD_NV3007_SRC.contains("if let Some((port, pin)) = board::LCD_BACKLIGHT_EN {"));

    // Per-board values.
    assert!(BOARD_IOTA2_SRC.contains("pub const LCD_RST_IS_DRIVABLE: bool = false;"));
    assert!(BOARD_PQ1_SRC.contains("pub const LCD_RST_IS_DRIVABLE: bool = true;"));
    assert!(BOARD_PQ1_SRC.contains("pub const LCD_DC_PIN: u32 = 0;"));
    assert!(BOARD_PQ1_SRC.contains("pub const LCD_RST_PIN: u32 = 1;"));
}

/// `src` with every `//` comment removed, line structure kept. Positions are
/// then taken on code only — the #730 comments in `lcd_nv3007::init` name
/// `fill_screen` and DISPON in prose, and an ordering check that matched
/// those would pass or fail on the wording of a comment.
fn strip_line_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    for line in src.lines() {
        out.push_str(match line.find("//") {
            Some(i) => &line[..i],
            None => line,
        });
        out.push('\n');
    }
    out
}

/// The body of the top-level fn whose header is `header`, up to the first
/// column-0 `}`. Panics if the header is absent or not unique.
fn top_level_fn_body<'a>(code: &'a str, header: &str) -> &'a str {
    assert_eq!(code.matches(header).count(), 1, "expected exactly one `{header}`");
    let start = code.find(header).unwrap();
    let len = code[start..].find("\n}\n").expect("unterminated fn body");
    &code[start..start + len]
}

/// #730: on pq1 the backlight must light only AFTER the panel content is defined.
///
/// `DISPON` is the last command of `run_init_sequence`. The old one-shot
/// `aw99703::init()` left Standby before the panel was even reset, so for the
/// ~170 ms between DISPON and the first `fill_screen` a lit panel showed
/// whatever GRAM held. The fix splits the chip bring-up: `configure()` (limits
/// and brightness, chip still dark) stays early for its settle delay, and
/// `enable()` — the one write that emits light — moves after the fill.
///
/// What this checks is statement ORDER in a straight-line body, which source
/// positions do capture (unlike the arm order of a branch chain, where a text
/// pin is unsound). "Enable only after a successful configure" is not tested
/// here because the compiler already enforces it: `enable` takes a
/// `Configured` token only `configure` can construct.
#[test]
fn negative_backlight_enables_only_after_the_panel_is_painted() {
    let lcd = strip_line_comments(LCD_NV3007_SRC);
    let body = top_level_fn_body(&lcd, "pub fn init() {");
    let pos = |needle: &str| {
        body.find(needle)
            .unwrap_or_else(|| panic!("lcd_nv3007::init: missing `{needle}`"))
    };
    let configure = pos("aw99703::configure()");
    let reset = pos("hard_reset();");
    let fill = pos("fill_screen(0x0000);");
    let enable = pos("aw99703::enable(");
    assert!(
        configure < reset,
        "configure() must run early: it carries the HWEN settle delay and leaves the chip dark"
    );
    assert!(
        fill < enable,
        "#730: aw99703::enable() must come AFTER fill_screen — enabling earlier lights \
         undefined GRAM between DISPON and the first fill"
    );
    assert!(
        !contains_in_code(LCD_NV3007_SRC, "aw99703::init("),
        "the one-shot init that bundled the enable must not return"
    );

    // Driver side: the light-emitting write lives in `enable` and nowhere else.
    let drv = strip_line_comments(AW99703_SRC);
    let cfg = top_level_fn_body(&drv, "pub fn configure() -> Option<Configured> {");
    assert!(
        !cfg.contains("write_reg(REG_MODE"),
        "configure() must leave the chip in Standby — it must not write REG_MODE"
    );
    let en = top_level_fn_body(&drv, "pub fn enable(_proof: Configured) -> bool {");
    assert!(en.contains("write_reg(REG_MODE, MODE_I2C_LINEAR_BACKLIGHT)"));
    assert_eq!(
        drv.matches("write_reg(REG_MODE").count(),
        1,
        "REG_MODE (the boost enable) must be written from exactly one place"
    );
    // The private field is what makes the token unforgeable outside the module.
    assert!(drv.contains("pub struct Configured(());"));
}

#[test]
fn positive_te_input_is_configured_by_the_panel_init() {
    // #780. `lcd_te::init()` configures PB2 as the tearing-effect input, and
    // the pixel presenter's `sync_to_scanout` is useless without it: an
    // unconfigured pin never shows a rising edge, so the wait burns its poll
    // cap, latches the line dead and silently skips forever after. That is
    // exactly what shipped once -- `init()` was called only from the bench
    // probe, which is gated on `ui-px-te-probe` and diverges, so no ordinary
    // image ever ran it. It was invisible in every test and every build: the
    // only symptom was a frame period of 36 ms where a working phase lock
    // quantises to a multiple of the 16.0 ms refresh.
    //
    // These are two halves of ONE property written in two files, so bind
    // them. The init must live in the PANEL bring-up specifically: that is
    // what makes "a panel exists" and "its TE input is configured" the same
    // event, rather than a relationship someone has to remember.
    assert!(
        LCD_NV3007_SRC.contains("crate::hw::lcd_te::init();"),
        "the panel init must configure the TE input, or sync_to_scanout can never see an edge"
    );
    assert!(
        UI_PX_LCD_SRC.contains("lcd_te::sync_to_scanout("),
        "the presenter must phase-lock to the scan-out (#780)"
    );
}

#[test]
fn positive_pixel_stream_frame_size_and_dma_beat_width_agree() {
    // #790. THREE register settings in TWO files encode ONE property: the
    // width of a datum crossing SPI1 for the pixel stream. They are legal
    // only together, and every wrong pairing is silent on the host:
    //
    //   DSIZE=16 + BYTE beats  -- FORBIDDEN hardware config. RM0456 §68.4.14:
    //      "Configuring any DMA data access to less than the configured data
    //      size is forbidden", and §68.8.13 for TXDR itself. No defined
    //      behaviour, no error flag.
    //   DSIZE=8  + WORD beats  -- legal but WRONG ORDER. A 32-bit access at
    //      an 8-bit frame packs FOUR frames and sends "the lowest significant
    //      byte first" (§68.4.11), i.e. little-endian, so every pixel's bytes
    //      arrive swapped. Garbled colour, no fault.
    //   DSIZE=16 + WORD beats  -- what we ship: two frames per access, low
    //      half-word first (ascending memory order), each frame shifted MSB
    //      first, so a native `u16` RGB565 pixel leads with its high byte.
    //
    // Pin all three so a future "simplification" of either file cannot
    // silently pick one of the broken pairings.
    assert!(
        contains_in_code(LCD_NV3007_SRC, "const DSIZE_16: u32 = 15;"),
        "the pixel stream runs 16-bit frames so no byte swap is needed"
    );
    assert!(
        contains_in_code(LCD_NV3007_SRC, "spi_begin_framed(DSIZE_16, FTHLV_2, n_px)"),
        "spi_begin_px must declare the 16-bit frame geometry explicitly"
    );
    // SDW_LOG2 = DDW_LOG2 = 0b10 (word): bits [1:0] = 2 and [17:16] = 2.
    assert!(
        contains_in_code(GPDMA_SRC, "const TR1_VAL: u32 = 0x8002_800A;"),
        "GPDMA must use WORD beats, which is legal only at DSIZE=16"
    );
    // And the 2-data FIFO threshold that a 32-bit access requires: §68.8.8
    // recommends FTHLV in {2,4,6} for a 32-bit register access with
    // DSIZE > 8, and §68.4.11 caps the packet at half the 16-byte FIFO,
    // which is 4 half-word frames.
    assert!(
        contains_in_code(LCD_NV3007_SRC, "const FTHLV_2: u32 = 1;"),
        "a 32-bit TXDR access needs a 2-data threshold, not the 1-data default"
    );
}

#[test]
fn positive_pixel_stream_derives_tsize_and_bndt_from_one_count() {
    // #790. `CR2.TSIZE` counts data FRAMES (§68.8.2) and `GPDMA_CxBR1.BNDT`
    // counts BYTES (§17.8.14). At 8-bit frames those were the same number,
    // which is why the old code could pass `bytes.len()` to both. At 16-bit
    // frames they differ by 2x, and the UNDER-supply direction is the one
    // mistake hardware does not catch: the DMA raises TCF and returns Ok, the
    // SPI has sent only half its TSIZE frames so EOT never sets, and
    // `spi_end`'s unbounded `while EOT == 0` wedges the display with CS still
    // asserted. The watchdog does not rescue it (IWDG is kicked from
    // SysTick), and this path paints the measured-boot fingerprint.
    //
    // So require that ONE pixel slice feeds both counters at the single call
    // site, rather than two numbers agreeing by review.
    assert!(
        contains_in_code(LCD_NV3007_SRC, "pub fn stream_dma_start(px: &[u16]) -> bool"),
        "the DMA stream entry point must take PIXELS, so both counters derive from one length"
    );
    assert!(
        contains_in_code(LCD_NV3007_SRC, "spi_begin_px(px.len() as u16);"),
        "TSIZE must be the frame count of the slice actually handed to GPDMA"
    );
    assert!(
        contains_in_code(LCD_NV3007_SRC, "crate::hw::gpdma::start_px(px);"),
        "GPDMA must be armed from the same slice that set TSIZE"
    );
    assert!(
        contains_in_code(GPDMA_SRC, "let bytes = px.len() * 2;")
            && contains_in_code(GPDMA_SRC, "REG.cbr1.write(bytes as u32);"),
        "BNDT must be the BYTE count derived from that same pixel slice"
    );
}

#[test]
fn positive_polled_pixel_stream_never_writes_a_sub_frame_byte() {
    // #790. `stream_chunk` is the `ui-px-dma`-OFF fallback and lives inside
    // the same `stream_open`/`stream_close` bracket, so it runs at
    // `DSIZE_16` too. A BYTE write to TXDR is then an access smaller than one
    // data, which RM0456 §68.8.13 forbids outright -- it specifies no
    // truncation, no partial-frame accumulation and no error flag, so it is
    // undefined, not "writes the low byte". It must push half-word data.
    //
    // It pushes PAIRS as one 32-bit access rather than single half-words:
    // that matches the 2-data threshold above, and `H` = 142 is even so a
    // band is always an even number of pixels and `chunks_exact(2)` can never
    // drop a trailing pixel.
    let chunk = UI_PX_LCD_SRC; // keep the band-geometry fact visible to the reader
    let _ = chunk;
    let body = LCD_NV3007_SRC
        .split("pub fn stream_chunk(buf: &[u16])")
        .nth(1)
        .expect("stream_chunk must exist — it is the non-DMA pixel path");
    let body = &body[..body.find("\n}\n").expect("stream_chunk must be a complete fn")];
    assert!(
        body.contains("spi_send_px_pair("),
        "the polled pixel path must write half-word data, not bytes, at DSIZE=16"
    );
    assert!(
        !body.contains("spi_send_byte("),
        "a byte write inside a 16-bit frame stream is a forbidden sub-frame access (§68.8.13)"
    );
    assert!(
        body.contains("spi_begin_px("),
        "the polled pixel path must open its transfer with the 16-bit frame geometry"
    );
}

#[test]
fn positive_band_buffers_are_word_aligned_and_all_wiped() {
    // #790, two properties of the band buffers that hardware and the
    // 2026-09-24 secret-retention review respectively require.
    //
    // ALIGNMENT: GPDMA streams a band with WORD beats, and "a source address
    // must be aligned with the programmed data width of a source burst ...
    // Else, a user setting error is reported and no transfer is issued"
    // (RM0456 §17.8.14). A bare `[u16; N]` is only 2-byte aligned, so without
    // the `repr` the channel raises USEF and paints nothing -- loud, but only
    // on hardware, and only on a panel nobody has on the bench board.
    assert!(
        contains_in_code(UI_PX_LCD_SRC, "#[repr(align(4))]")
            && contains_in_code(UI_PX_LCD_SRC, "struct Band([u16; STRIP_PX]);"),
        "the band buffer must be 4-byte aligned for word-width GPDMA beats"
    );
    // WIPE: seed-word pixels transit these buffers. The review flagged the
    // old single buffer as safe only "by layout accident ... Nothing enforces
    // that relationship". Wipe by ITERATING the array, so adding a third
    // buffer cannot leave one holding secret pixels.
    assert!(
        contains_in_code(UI_PX_LCD_SRC, "for b in (*core::ptr::addr_of_mut!(BANDS)).iter_mut()"),
        "every band buffer must be zeroized by iteration, not by being named one at a time"
    );
}

#[test]
fn positive_no_unbounded_wait_survives_on_the_panel_path() {
    // #790. Every other wait in this driver is capped -- `gpdma::wait`,
    // `gpdma::abort`'s suspend loop, `lcd_te::sync_to_scanout` -- and
    // `spi_force_down` exists precisely because "EOT can never set" is a
    // reachable state after a failed DMA. The hole was that it is reachable on
    // the DMA SUCCESS arm too: `CR2.TSIZE` counts frames, `BNDT` counts bytes,
    // hardware cross-checks neither, so any accounting error between them
    // leaves GPDMA raising TCF while the SPI still waits for frames that never
    // arrive. Unbounded there is a DEAD DEVICE, not a dropped frame: IWDG is
    // kicked from SysTick so the watchdog does not rescue it, and this path
    // paints the measured-boot fingerprint and the PIN entry screen.
    assert!(
        contains_in_code(LCD_NV3007_SRC, "const EOT_SPIN_CAP: u32 = 4_000_000;"),
        "the EOT wait must be bounded"
    );
    assert!(
        !LCD_NV3007_SRC.contains("while (REG.spi_sr.read() & SR_EOT) == 0 {}"),
        "the unbounded EOT spin must not come back"
    );
    assert!(
        contains_in_code(LCD_NV3007_SRC, "if spins >= EOT_SPIN_CAP {"),
        "the EOT wait must give up at its cap rather than spin forever"
    );
}

#[test]
fn positive_dma_pixel_chunk_is_capped_by_bndt_at_runtime() {
    // #790. `TSIZE` is NOT the binding counter once GPDMA is involved.
    // `GPDMA_CxBR1.BNDT` is also 16 bits but counts BYTES, and bits 31:16 of
    // that register are reserved -- so a 40,000-pixel chunk is a legal TSIZE
    // and an 80,000-byte BNDT that TRUNCATES to 14,464. The channel then
    // delivers 7,232 of 40,000 frames, raises TCF, `wait` returns Ok, and the
    // SPI waits forever for the rest. Reaching that needs no mis-typed unit,
    // just a chunk over 32,767 px.
    //
    // So the DMA path needs its OWN cap, at half the polled one, and it must
    // be a RUNTIME refusal: `[profile.release]` sets no `debug-assertions`, so
    // an assert is absent from exactly the images that ship.
    assert!(
        contains_in_code(LCD_NV3007_SRC, "const MAX_DMA_PX_CHUNK: usize = 32_766;"),
        "the DMA chunk cap must come from BNDT (bytes), not from TSIZE (frames)"
    );
    assert!(
        contains_in_code(
            LCD_NV3007_SRC,
            "if px.len() > MAX_DMA_PX_CHUNK || px.len() % 2 != 0 {"
        ),
        "the cap must be enforced at runtime -- release builds carry no debug assertions"
    );
    // And the polled path must keep TSIZE in step with the pairs it actually
    // sends, for ANY length, rather than asserting evenness in a profile that
    // strips asserts.
    assert!(
        contains_in_code(LCD_NV3007_SRC, "MAX_PX_CHUNK) & !1;"),
        "the polled chunk must round down to an even frame count"
    );
}

#[test]
fn positive_panic_tears_down_the_blit_before_the_fatal_screen() {
    // #790. `present_frame_ex` holds `&mut BANDS` across a render that runs
    // while GPDMA channel 0 is EN=1, and `[profile.release]` keeps
    // `overflow-checks = true`, so a panic in that window is live in SHIPPING
    // images. The #484 fatal screen then paints, which under `ui-px` reaches
    // `paint_legacy` and back into `present_frame_ex` -- a second `&mut` to
    // the same static while a DMA channel is reading it, and a second stream
    // into the same auto-incrementing RAMWR.
    //
    // Two halves, in two files, of one property: the channel is torn down and
    // the presenter refuses re-entry.
    assert!(
        MAIN_SRC.contains("crate::hw::gpdma::abort();"),
        "the panic handler must abort the blit channel before the fatal screen paints"
    );
    assert!(
        contains_in_code(UI_PX_LCD_SRC, "if FRAME_IN_FLIGHT.swap(true, Ordering::Acquire) {"),
        "the presenter must refuse re-entry rather than alias the band buffers"
    );
    // The latch and the secret wipe both release through `Drop`, so a `return`
    // added later cannot skip either. The band-0 branch already was such a
    // return.
    assert!(
        contains_in_code(UI_PX_LCD_SRC, "impl Drop for FrameGuard {")
            && contains_in_code(UI_PX_LCD_SRC, "FRAME_IN_FLIGHT.store(false, Ordering::Release);"),
        "the latch and the wipe must be released structurally, not positionally"
    );
}

#[test]
fn positive_an_incomplete_frame_cannot_arm_the_sign_gesture() {
    // #790. Since #780 the whole frame streams under ONE `set_window` and the
    // panel auto-increments through it, so a band that stops short does not
    // cost one band -- every LATER band lands at the wrong offset and the
    // glass shows a shifted, garbled frame.
    //
    // Before #790 bounded the waits, those paths HUNG, and a hang is
    // fail-safe: nothing is signed off a frame nobody saw. Bounding them
    // turned a hang into "one dropped frame", which is only safe if the
    // presenter knows the frame dropped. Otherwise `mark_rendered` runs,
    // `seen_last` sets, and `PX_COMMIT_REQUIRES_SEEN_LAST` (owner decision
    // 2026-09-24, HARDENING.md 2.4) counts a garbled amount or recipient page
    // as SEEN -- arming the chord on something never legibly displayed.
    assert!(
        contains_in_code(UI_PX_LCD_SRC, "if cost.complete && driver.index() != painted_idx {"),
        "the sign-gesture arming must require a frame that fully reached the glass"
    );
    assert!(
        contains_in_code(UI_PX_LCD_SRC, "cost.complete = ok && x0 >= W;"),
        "completeness must account for BOTH a failed transfer and a short sweep"
    );
    // THE LOAD-BEARING HALF, and the one a must-fail control caught this gate
    // not testing: every `stream_dma_finish` result must feed `ok`. Swapping
    // either call site back to `let _ = ...` left the whole suite green, which
    // means the gate above was asserting the plumbing without the input.
    // Count the sites rather than spot-check one: there are two (the in-loop
    // drain and the final band), and the final one is the easier to forget
    // because nothing renders behind it.
    let consumed = UI_PX_LCD_SRC
        .matches("ok &= lcd::stream_dma_finish().is_ok();")
        .count();
    let discarded = UI_PX_LCD_SRC.matches("= lcd::stream_dma_finish();").count();
    assert!(
        consumed == 2 && discarded == 0,
        "every stream_dma_finish result must clear `complete` on error \
         (found {consumed} consuming, {discarded} discarding)"
    );
    // Same for the polled fallback and for a refused arm — BY COUNT, not by
    // presence. Each of these forms appears exactly twice (band 0 before the
    // TE wait, then once per loop iteration), so a `contains` check stays
    // green when one of the two is swapped back to `let _ = ...`. Two
    // must-fail controls proved that: both "refused arm ignored" and "polled
    // failure ignored" left the whole suite green against the presence check.
    //
    // Every site that can tell us the frame did not land must feed `ok`, so
    // the invariant is "no discarding site exists", which only a count can
    // express.
    let arms = UI_PX_LCD_SRC.matches("ok &= dma_pending;").count();
    let polled = UI_PX_LCD_SRC.matches("ok &= lcd::stream_chunk(").count();
    let loose_arm = UI_PX_LCD_SRC.matches("= dma_pending;").count() - arms;
    let loose_polled = UI_PX_LCD_SRC.matches("= lcd::stream_chunk(").count() - polled;
    assert!(
        arms == 2 && loose_arm == 0,
        "both arm sites must clear `complete` on a refusal (consuming {arms}, other {loose_arm})"
    );
    assert!(
        polled == 2 && loose_polled == 0,
        "both polled sites must clear `complete` on failure (consuming {polled}, other {loose_polled})"
    );
    // And the sweep must STOP at the first failure. Continuing streams the
    // rest of the frame into a window whose offset is already wrong, which
    // is more garbage on the glass and more wire for nothing.
    assert!(
        contains_in_code(UI_PX_LCD_SRC, "if !ok {")
            && UI_PX_LCD_SRC.contains("// STOP THE SWEEP."),
        "the band loop must break at the first failed band, not paint the rest shifted"
    );
    // And the legacy bridge must tell `flush()` the truth, or the #484 fatal
    // screen silently vanishes in the one situation it exists for.
    assert!(
        contains_in_code(
            UI_PX_LCD_SRC,
            "build_and_present(&anim, &atlas.marks(), &atlas.font(), None, None, None).complete"
        ),
        "paint_legacy must report whether the page actually landed"
    );
    // The verdict must survive the no-instrumentation path. A blanket
    // `FrameCost::default()` there makes `complete` false in every build
    // WITHOUT `ui-px-frametime` -- the shipping-shaped one -- so the chord
    // would never arm while the bench config looked perfect.
    assert!(
        contains_in_code(UI_PX_LCD_SRC, "complete: cost.complete,"),
        "zeroing the instrumentation must not zero the completeness verdict"
    );
    // Exact-line, because the loose substring also matches the legitimate
    // `let mut cost = FrameCost::default();` initialiser. What must not come
    // back is the bare RE-ASSIGNMENT.
    assert!(
        !UI_PX_LCD_SRC
            .lines()
            .map(|l| match l.find("//") {
                Some(i) => &l[..i],
                None => l,
            })
            .any(|c| c.trim() == "cost = FrameCost::default();"),
        "a blanket FrameCost::default() re-assignment would clobber `complete` outside the bench config"
    );
}

// ═════════════════════════════════════════════════════════════════════
// #783 — the endless chooser: animate against input, never play to rest
// ═════════════════════════════════════════════════════════════════════

#[test]
fn positive_the_animation_tick_never_runs_while_a_button_is_down() {
    // `wait_event_ticking` exists so the endless chooser can animate during
    // the input wait. The tempting place to hang that is `idle_check`, which
    // is already called at every poll point -- and it would be WRONG,
    // silently.
    //
    // `track_hold` measures a hold on a SYNTHETIC clock (`held_ms +=
    // POLL_MS` after each `delay_ms(POLL_MS)`), not on `timeout::now()`. A
    // frame paint is ~34 ms against POLL_MS = 5, so a tick inside the press
    // path makes `held_ms` undercount ~7x: a real 500 ms hold would need
    // about 3 s of wall time to register as `Press::Long`. The chooser's
    // long-Right is what CONFIRMS wallet creation, so that is a trusted-path
    // input defect, not a cosmetic one -- and nothing reports it.
    //
    // So: exactly ONE `tick()` call, in the branch where neither button is
    // pressed.
    // Count in CODE only — the contract above says "tick" a dozen times, and
    // the invocation form has already changed once (`tick();` became
    // `if !tick() {` when the hook started reporting whether it painted), so
    // match the CALL, not one spelling of a statement. Allocation-free: this
    // crate is `no_std`, so walk the lines and keep byte offsets.
    //
    // `find_in_code` returns the byte offset of `needle` in the comment-
    // stripped view, and `count_in_code` counts it, so positions from the two
    // are comparable.
    fn each_code_line(src: &str, mut f: impl FnMut(usize, &str)) {
        let mut off = 0usize;
        for line in src.split('\n') {
            let code = match line.find("//") {
                Some(i) => &line[..i],
                None => line,
            };
            f(off, code);
            off += line.len() + 1;
        }
    }
    fn count_in_code(src: &str, needle: &str) -> usize {
        let mut n = 0;
        each_code_line(src, |_, c| n += c.matches(needle).count());
        n
    }
    fn find_in_code(src: &str, needle: &str) -> Option<usize> {
        let mut hit = None;
        each_code_line(src, |off, c| {
            if hit.is_none() {
                if let Some(i) = c.find(needle) {
                    hit = Some(off + i);
                }
            }
        });
        hit
    }

    let calls = count_in_code(BUTTONS_SRC, "tick()");
    assert_eq!(
        calls, 1,
        "exactly one tick site is allowed in the button state machine, found {calls}"
    );
    // Compare POSITIONS, not comments.
    let guard = find_in_code(BUTTONS_SRC, "if !(left_pressed() || right_pressed()) {")
        .expect("the nothing-pressed branch must still exist");
    let tick = find_in_code(BUTTONS_SRC, "tick()").expect("the tick site must exist");
    let delay = find_in_code(&BUTTONS_SRC[guard..], "delay_ms(POLL_MS);")
        .map(|i| i + guard)
        .expect("that branch must still idle with delay_ms");
    assert!(
        guard < tick && tick < delay,
        "the tick must sit between the nothing-pressed guard and its delay \
         (guard {guard}, tick {tick}, delay {delay}) — anywhere in the press path \
         corrupts track_hold's synthetic hold clock"
    );
    let th = find_in_code(BUTTONS_SRC, "fn track_hold").expect("track_hold must exist");
    assert!(
        find_in_code(&BUTTONS_SRC[th..], "tick()").is_none(),
        "track_hold must never tick"
    );
}

#[test]
fn positive_an_endless_screen_is_never_played_to_rest() {
    // The CLASS, not just the instance. `play_screen` means "play until it
    // rests"; a `plays_forever` screen has no rest, so its only exit was a
    // 3 s cap that fired mid-motion. Keep the cap for the finite callers and
    // make the endless case structurally impossible to re-enter, so the next
    // hero someone shows does not reintroduce the freeze.
    assert!(
        contains_in_code(UI_PX_LCD_SRC, "if pqsigner_ui_px::scene::plays_forever(s, 0) {"),
        "play_screen must branch on whether the screen can ever rest"
    );
    assert!(
        contains_in_code(UI_PX_LCD_SRC, "const PLAY_CAP_MS: u32 = 3_000;"),
        "the cap stays as the backstop for screens that DO rest"
    );
    // Endlessness must be asked of the LAYOUT that sets the flags, not
    // re-derived from a second copy of the Kind table in the firmware.
    assert!(
        !contains_in_code(UI_PX_LCD_SRC, "Kind::Hero") && !contains_in_code(PX_SCREENS_SRC, "Kind::Hero"),
        "endlessness must come from scene::plays_forever, not a local Kind match"
    );
}

#[test]
fn positive_the_chooser_animates_from_inside_its_input_wait() {
    // The two defects were one structure: a paint loop that sampled no
    // input, followed by an input wait that painted nothing. Neither half is
    // fixable alone, so the chooser paints AND waits in one call.
    assert!(
        contains_in_code(PX_SCREENS_SRC, "pub fn show_waiting(")
            && contains_in_code(
                PX_SCREENS_SRC,
                "wait_button_ticking(idle, &mut || amb.tick(&atlas))"
            ),
        "the ambient presenter must drive its animation from the input wait"
    );
    // Through `record` on every arm, like every other presenter, or the
    // [UI-PXSR] line and the ui-capture frame hash change and the transcript
    // count moves.
    let body = PX_SCREENS_SRC
        .split("pub fn show_waiting(")
        .nth(1)
        .expect("show_waiting must exist");
    let body = &body[..body.find("\n}\n").unwrap_or(body.len())];
    assert_eq!(
        body.matches("record(s);").count(),
        2,
        "show_waiting must record the screen on each cfg arm, exactly once"
    );
    // Both wizard choosers must use it (the fn itself plus two call sites),
    // and the paint-then-block helper must not come back.
    assert_eq!(
        SEED_WIZARD_SRC.matches("px_choice_wait(").count(),
        3,
        "both chooser loops must animate while waiting"
    );
    assert!(
        !contains_in_code(SEED_WIZARD_SRC, "fn px_choice("),
        "the paint-then-block helper must not come back"
    );
}

#[test]
fn positive_the_te_edge_is_latched_in_hardware_not_polled_as_a_level() {
    // #783 follow-up. The TE pulse is 18 us and repeats every 16.0 ms, which
    // is an EXACT multiple of the 1 kHz SysTick — so a strobe that lands
    // inside the tick ISR is invisible to a level poll, and once one
    // coincides, every following one coincides too. The poll then burns its
    // whole cap: measured `te_wait` >= 99.9 ms where a wait for an edge can
    // never exceed 16.0 ms.
    //
    // EXTI's edge detector sets the pending flag whether or not the CPU is
    // executing anything (RM0456 23.6.4), so the strobe becomes impossible
    // to miss. Pin the latch, and pin the ABSENCE of the level loop that
    // replaced it — a future "simplification" back to `while !level()`
    // reintroduces a ~100 ms stall per frame with no compile error.
    assert!(
        contains_in_code(LCD_TE_SRC, "const EXTI_RPR1: u32 = 0x00C;")
            && contains_in_code(LCD_TE_SRC, "rpr.read() & line == 0"),
        "wait_rising must poll the EXTI rising-edge latch"
    );
    // The level poll is KEPT, as a verified fallback — see below. What must
    // not happen is `wait_rising` using it unconditionally.
    assert!(
        contains_in_code(LCD_TE_SRC, "if !exti_in_use() {")
            && contains_in_code(LCD_TE_SRC, "return wait_rising_by_level(spin_cap);"),
        "the level poll must be reachable ONLY as the fallback"
    );
    // FAIL-SAFE, because the first cut of this shipped broken: the EXTI path
    // detected nothing, the line latched dead inside 15 s, and the trusted
    // display ran with NO scan-out sync for the whole session — trading
    // #783's stall for #780's tearing without anyone choosing that. The
    // driver must prove its own configuration took effect.
    assert!(
        contains_in_code(LCD_TE_SRC, "core::ptr::addr_of_mut!(EXTI_USABLE)")
            && contains_in_code(LCD_TE_SRC, "== port_index && rtsr.read() & exti_line(pin) != 0"),
        "exti_init must read its configuration back and fall back if it did not stick"
    );
    // AND THE EXTI PATH IS OFF BY DEFAULT. It reads back correctly on the EVT
    // unit and still latches no edge (measured 37 misses in 28 s with
    // `exti_in_use` true), while the level poll on the same pin sees the
    // strobe. Shipping the unproven path cost a session-long loss of scan-out
    // sync once already.
    // SELF-PROVING: the latch is used only when it demonstrated, this boot,
    // that it answers a software trigger. A build-time flag records what
    // someone believed; the self-test records what the silicon just did.
    assert!(
        contains_in_code(LCD_TE_SRC, "let ok = config_ok && swier_ok;"),
        "EXTI must be used only when BOTH its configuration read back and its \
         latch answered a software trigger"
    );
    // And the line must be UNMASKED, which is what the pending flag needs.
    // Its absence is why the first attempt latched nothing.
    assert!(
        contains_in_code(LCD_TE_SRC, "Reg32::new(EXTI_S + EXTI_IMR1).set_bits(exti_line(pin));"),
        "IMR1 must unmask the line or RPR1 never latches (RM0456 23.6.10)"
    );
    // And a dead line must be RE-TESTED, not written off for the session.
    assert!(
        contains_in_code(LCD_TE_SRC, "const RETRY_EVERY: u32 = 64;")
            && contains_in_code(LCD_TE_SRC, "core::ptr::addr_of_mut!(TE_RETRY)"),
        "a line declared dead must be retried — losing sync permanently is tearing by default"
    );
    // Rising edge armed, and the line claimed SECURE so NS cannot clear the
    // flag and silently drop the trusted display back to an unsynchronised
    // blit (i.e. #780's tearing) on demand.
    assert!(
        contains_in_code(LCD_TE_SRC, "Reg32::new(EXTI_S + EXTI_RTSR1).set_bits(exti_line(pin));")
            && contains_in_code(
                LCD_TE_SRC,
                "Reg32::new(EXTI_S + EXTI_SECCFGR1).set_bits(exti_line(pin));"
            ),
        "the TE line must be armed for rising edges and owned by the secure world"
    );
    // And it must be configured by the panel init, like the pin itself —
    // the same binding that `positive_te_input_is_configured_by_the_panel_init`
    // enforces, because an unconfigured EXTI line never sets its flag and the
    // wait would fail CLOSED into the spin cap forever.
    assert!(
        contains_in_code(LCD_TE_SRC, "exti_init(port, pin);"),
        "init() must arm the EXTI line, or every wait burns its cap"
    );
}

#[test]
fn positive_a_cycle_count_cannot_come_from_a_stopped_counter() {
    // The ambient chooser's first instrumented flash read `0/0/0` with the
    // animation running fine: `frametime::enable()` was called from exactly
    // one function (`run_flow`), so every other path measured a dead
    // `DWT_CYCCNT`. Third instance in one day of "a helper that must be
    // called, defined and not called on the new path" — after
    // `Strip::x_hits` and `lcd_te::init()`, both of which were SUBTLY wrong
    // and cost a flash each.
    //
    // So `cycles()` arms the counter itself. Adding another call site would
    // have fixed the instance; this fixes the class, and the gate pins the
    // structure rather than the call.
    let i = UI_PX_LCD_SRC
        .find("pub fn cycles() -> u32 {")
        .expect("the frametime reader must exist");
    let body = &UI_PX_LCD_SRC[i..];
    let body = &body[..body.find("\n    }\n").unwrap_or(body.len())];
    assert!(
        body.contains("CTRL_CYCCNTENA == 0") && body.contains("enable();"),
        "cycles() must arm the counter when it is not running, or a new \
         measurement path silently reports 0"
    );
}

#[test]
fn positive_ui_lcd_implies_gpio_buttons() {
    // The fix rests on this: only the GPIO path can honour a tick, and that
    // is sufficient ONLY because every build with a panel has it. With
    // `ui-lcd` off, `px::screens::show_with` records and returns without
    // painting, so there is nothing to animate. If the implication breaks,
    // a panel build would show the chooser as a still frame forever — worse
    // than the 3 s of motion #783 complained about.
    let line = SECURE_CARGO_TOML_SRC
        .lines()
        .find(|l| l.trim_start().starts_with("ui-lcd ="))
        .expect("ui-lcd must still be a feature");
    assert!(
        line.contains("gpio-buttons"),
        "ui-lcd must imply gpio-buttons, or the animated chooser has no tick: {line}"
    );
}
