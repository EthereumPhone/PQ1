//! Host-side positive + negative test suite for the `secure-main-sau`
//! slice.
//!
//! # Scope
//!
//! Three production files:
//!   * `secure/src/main.rs`         — secure-world `cortex_m_rt::entry`,
//!                                    SysTick / PendSV / DefaultHandler /
//!                                    panic_handler exception trampolines,
//!                                    `ArchRegs` MMIO bindings,
//!                                    SE-backend `static mut`, secure-log
//!                                    macro, reset-cause integration.
//!   * `secure/src/sau.rs`          — ARMv8-M SAU region layout and
//!                                    GTZC1 MPCBB / TZSC SECCFGR config.
//!   * `secure/src/reset_cause.rs`  — RCC_CSR sticky-flag classification
//!                                    (`ResetCause`, `classify_bits`,
//!                                    `is_abnormal`, `tag`).
//!
//! # Why source-text invariants dominate
//!
//! All three files are gated `#[cfg(not(test))]` at the crate root (see
//! `secure/src/main.rs` near the `mod sau;` / `mod reset_cause;`
//! declarations) because their non-test code paths depend on hardware-
//! only deps (`cortex_m`, `cortex_m_rt`, MMIO register bindings, linker
//! symbols `__veneer_base` / `__veneer_limit`, the secure-element
//! `static mut`). Even the inner `#[cfg(test)] mod tests` block in
//! `reset_cause.rs` never compiles on host because its parent `mod`
//! declaration is `#[cfg(not(test))]`-excluded — see the existing
//! `#[cfg(not(test))] mod reset_cause;` in `main.rs`.
//!
//! The slice is therefore pinned host-side through:
//!
//!   1. **Pure-logic mirrors.** A local re-implementation of
//!      `classify_bits` + the `ResetCause` enum + `is_abnormal` is
//!      exercised exhaustively against every combination of sticky
//!      flags. The mirror's bit constants are pinned against the
//!      production source text so a silent renumber surfaces here.
//!   2. **`include_str!` source-text invariants.** Register addresses,
//!      SAU region boundaries, GTZC1 TZSC bit positions, panic-handler
//!      ordering, DefaultHandler dispatch arms, the `secure_log!` macro
//!      shape, and the SE-backend `static mut` set are pinned to the
//!      file text. A future refactor that silently moves a bit, drops
//!      a dispatch arm, or removes the panic-handler zeroize call
//!      fails this suite before it reaches silicon.
//!
//! Negative tests name the assumption being attacked and the security
//! property whose silent removal they would otherwise enable. Many
//! cite CLAUDE.md Invariant #4 ("NS never sees secure-world
//! peripherals") and the brownout-hardening contract documented in
//! `docs/brownout-hardening.md` (referenced from `reset_cause.rs:7`).

#![cfg(test)]

// ═════════════════════════════════════════════════════════════════════
// 0. Source fixtures
// ═════════════════════════════════════════════════════════════════════

const MAIN_SRC: &str = include_str!("main.rs");
const SAU_SRC: &str = include_str!("sau.rs");
const RESET_CAUSE_SRC: &str = include_str!("reset_cause.rs");

// ═════════════════════════════════════════════════════════════════════
// 1. reset_cause.rs — local mirror + pure-logic tests
//
// `classify_bits` is a pure function on a `u32`. We reimplement it
// here against the same bit-position constants as the production
// code so the test exhausts every documented branch. The constants
// themselves are pinned against the production source text below to
// guarantee the mirror stays in sync.
// ═════════════════════════════════════════════════════════════════════

const RMVF: u32 = 1 << 23;
const OBLRSTF: u32 = 1 << 25;
const PINRSTF: u32 = 1 << 26;
const BORRSTF: u32 = 1 << 27;
const SFTRSTF: u32 = 1 << 28;
const IWDGRSTF: u32 = 1 << 29;
const WWDGRSTF: u32 = 1 << 30;
const LPWRRSTF: u32 = 1 << 31;

const ANY_RESET_FLAG: u32 =
    OBLRSTF | PINRSTF | BORRSTF | SFTRSTF | IWDGRSTF | WWDGRSTF | LPWRRSTF;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum ResetCause {
    Cold,
    Software,
    Watchdog,
    LowPower,
    OptionByte,
    Unknown,
}

impl ResetCause {
    fn is_abnormal(self) -> bool {
        matches!(
            self,
            ResetCause::Watchdog | ResetCause::LowPower | ResetCause::Unknown
        )
    }

    fn tag(self) -> &'static str {
        match self {
            ResetCause::Cold => "cold",
            ResetCause::Software => "software",
            ResetCause::Watchdog => "watchdog",
            ResetCause::LowPower => "low-power",
            ResetCause::OptionByte => "option-byte",
            ResetCause::Unknown => "unknown",
        }
    }
}

fn classify_bits(csr: u32) -> ResetCause {
    let flags = csr & ANY_RESET_FLAG;

    if flags == 0 {
        return ResetCause::Unknown;
    }
    if csr & OBLRSTF != 0 {
        return ResetCause::OptionByte;
    }
    if csr & (IWDGRSTF | WWDGRSTF) != 0 {
        return ResetCause::Watchdog;
    }
    if csr & LPWRRSTF != 0 {
        return ResetCause::LowPower;
    }
    if csr & SFTRSTF != 0 {
        return ResetCause::Software;
    }
    if csr & BORRSTF != 0 {
        return ResetCause::Cold;
    }
    ResetCause::Unknown
}

// ───── Positive: every documented branch of classify_bits ─────

#[test]
fn positive_classify_cold_is_bor_plus_pin_only() {
    assert_eq!(classify_bits(BORRSTF | PINRSTF), ResetCause::Cold);
}

#[test]
fn positive_classify_software_is_sft_plus_pin() {
    assert_eq!(classify_bits(SFTRSTF | PINRSTF), ResetCause::Software);
}

#[test]
fn positive_classify_iwdg_is_watchdog() {
    assert_eq!(classify_bits(IWDGRSTF | PINRSTF), ResetCause::Watchdog);
}

#[test]
fn positive_classify_wwdg_is_watchdog() {
    assert_eq!(classify_bits(WWDGRSTF | PINRSTF), ResetCause::Watchdog);
}

#[test]
fn positive_classify_lpwr_is_low_power() {
    assert_eq!(classify_bits(LPWRRSTF | PINRSTF), ResetCause::LowPower);
}

#[test]
fn positive_classify_obl_is_option_byte() {
    assert_eq!(
        classify_bits(OBLRSTF | PINRSTF | BORRSTF),
        ResetCause::OptionByte
    );
}

#[test]
fn positive_classify_no_flags_is_unknown() {
    assert_eq!(classify_bits(0), ResetCause::Unknown);
}

#[test]
fn positive_classify_pinrst_alone_is_unknown() {
    // PIN bit alone without BOR/SFT/etc — the BORRSTF-asserted-on-every-
    // power-on rule isn't satisfied so we treat conservatively.
    assert_eq!(classify_bits(PINRSTF), ResetCause::Unknown);
}

#[test]
fn positive_is_abnormal_classification_is_exact() {
    // The brownout-hardening contract (reset_cause.rs:62-77) says
    // exactly these three causes are abnormal — Cold/Software/OptionByte
    // are safe-by-construction.
    assert!(ResetCause::Watchdog.is_abnormal());
    assert!(ResetCause::LowPower.is_abnormal());
    assert!(ResetCause::Unknown.is_abnormal());
    assert!(!ResetCause::Cold.is_abnormal());
    assert!(!ResetCause::Software.is_abnormal());
    assert!(!ResetCause::OptionByte.is_abnormal());
}

#[test]
fn positive_tag_is_one_word_lowercase_for_every_variant() {
    for (variant, expected) in [
        (ResetCause::Cold, "cold"),
        (ResetCause::Software, "software"),
        (ResetCause::Watchdog, "watchdog"),
        (ResetCause::LowPower, "low-power"),
        (ResetCause::OptionByte, "option-byte"),
        (ResetCause::Unknown, "unknown"),
    ] {
        assert_eq!(variant.tag(), expected);
        assert!(
            !variant.tag().contains(' '),
            "tag '{}' must be a single token for grep-friendly boot logs",
            variant.tag()
        );
        assert_eq!(variant.tag(), variant.tag().to_lowercase().as_str());
    }
}

// ───── Negative: priority + masking invariants ─────

#[test]
fn negative_watchdog_takes_priority_over_bor_when_both_set() {
    // A glitched chip that latches both BOR (every power-on) AND a
    // watchdog flag must surface as a watchdog event — silently
    // classifying it as Cold would skip the abnormal-reset SRAM
    // zeroize path in main.rs:800-803, leaving secrets from the
    // pre-watchdog session in SRAM for the next firmware to find.
    assert_eq!(
        classify_bits(IWDGRSTF | BORRSTF | PINRSTF),
        ResetCause::Watchdog,
        "Watchdog must beat BOR — losing this priority skips the abnormal-reset SRAM wipe"
    );
}

#[test]
fn negative_watchdog_takes_priority_over_sft() {
    // SFTRSTF + IWDGRSTF: a software reset that fired while the
    // watchdog had already bitten. The watchdog is the more diagnostic
    // signal (it means firmware was wedged) — treating it as Software
    // would hide the wedge and skip the abnormal-cause SRAM wipe.
    assert_eq!(
        classify_bits(SFTRSTF | IWDGRSTF | PINRSTF),
        ResetCause::Watchdog
    );
    assert_eq!(
        classify_bits(SFTRSTF | WWDGRSTF | PINRSTF),
        ResetCause::Watchdog
    );
}

#[test]
fn negative_obl_takes_priority_over_every_other_flag() {
    // An external provisioner that triggered OBL_LAUNCH while the
    // chip happened to also latch IWDG/SFT/LPWR must be classified as
    // OptionByte. If a watchdog-style classification leaked through
    // here, every option-byte reload would zeroize SRAM — annoying
    // bench UX, but more importantly hides the OBL signal entirely
    // from the boot log.
    assert_eq!(
        classify_bits(
            OBLRSTF | PINRSTF | BORRSTF | SFTRSTF | IWDGRSTF | WWDGRSTF | LPWRRSTF
        ),
        ResetCause::OptionByte,
        "OBL must beat every other flag — see reset_cause.rs:133-135"
    );
}

#[test]
fn negative_lpwr_takes_priority_over_sft_and_bor() {
    // An illegal Stop/Standby transition that left SFT and BOR
    // sticky must surface as LowPower — otherwise the abnormal-
    // cause wipe is skipped.
    assert_eq!(
        classify_bits(LPWRRSTF | SFTRSTF | PINRSTF),
        ResetCause::LowPower
    );
    assert_eq!(
        classify_bits(LPWRRSTF | BORRSTF | PINRSTF),
        ResetCause::LowPower
    );
}

#[test]
fn negative_classifier_ignores_rmvf_bit() {
    // RMVF is the "clear sticky flags" control bit, NOT a reset cause.
    // If a future refactor accidentally folded it into ANY_RESET_FLAG
    // every classify_bits call after a clear would return non-Unknown,
    // masking the real cause.
    assert_eq!(classify_bits(RMVF), ResetCause::Unknown);
    assert_eq!(classify_bits(RMVF | PINRSTF), ResetCause::Unknown);
    assert_eq!(
        ANY_RESET_FLAG & RMVF,
        0,
        "RMVF must NOT be in the reset-cause mask"
    );
}

#[test]
fn negative_classifier_ignores_garbage_low_bits() {
    // Bits 0..22 are not reset-cause bits in RCC_CSR. classify_bits
    // must mask them off before classification — feeding 0xFFFFFF
    // (all the low bits set, no reset bits) must return Unknown.
    assert_eq!(classify_bits(0x007F_FFFF), ResetCause::Unknown);
}

#[test]
fn negative_csr_with_only_obl_bit_classifies_option_byte() {
    // Even without PINRSTF (which the chip asserts on essentially
    // every reset), an OBL signal alone must classify as OptionByte
    // rather than falling through to Unknown.
    assert_eq!(classify_bits(OBLRSTF), ResetCause::OptionByte);
}

#[test]
fn negative_abnormal_set_does_not_include_optionbyte() {
    // OptionByte resets come from the external provisioner — never
    // from a chip wedge. Including OptionByte in the abnormal set
    // would force a defensive SRAM wipe on every flash/OB write,
    // breaking iterative bench provisioning of the dual-SE objects.
    assert!(
        !ResetCause::OptionByte.is_abnormal(),
        "OptionByte must NOT be abnormal — see reset_cause.rs:62-77 + brownout-hardening doc"
    );
}

#[test]
fn negative_abnormal_set_does_not_include_software() {
    // Software resets always originate from code that zeroized first
    // (the panic handler, lockout-wipe path, etc.); re-zeroizing in
    // the boot path would be wasted cycles but also could mask a
    // real abnormal cause that piggybacked on the SFT flag.
    assert!(!ResetCause::Software.is_abnormal());
}

#[test]
fn negative_abnormal_set_does_not_include_cold() {
    // SRAM contents on cold boot are already physically gone (Vdd
    // off); zeroizing would lengthen boot for no benefit.
    assert!(!ResetCause::Cold.is_abnormal());
}

#[test]
fn negative_classifier_is_total_on_arbitrary_inputs() {
    // Sanity-check that no input combination panics. Iterating the
    // 8-bit upper-nibble cross-product (bits 23..31) covers every
    // documented sticky-flag configuration.
    for hi in 0u32..(1 << 9) {
        let csr = hi << 23;
        let _ = classify_bits(csr); // must not panic
    }
}

// ───── Source-text pins on the production constants ─────

#[test]
fn positive_source_pins_rcc_csr_address_and_base() {
    assert!(
        RESET_CAUSE_SRC.contains("const RCC: u32 = 0x4602_0C00;"),
        "RCC base address must be the NS-alias AHB3 mirror per hw/rcc.rs"
    );
    assert!(
        RESET_CAUSE_SRC.contains("const RCC_CSR: *mut u32 = (RCC + 0xF4) as *mut u32;"),
        "RCC_CSR must be at offset 0xF4 (RM0456 §11)"
    );
}

#[test]
fn positive_source_pins_sticky_flag_bit_positions() {
    // Empirically verified on real silicon (see file header) — these
    // bit positions must NEVER drift without re-validating on hardware,
    // because a silent off-by-one re-classifies every SW reset as a
    // watchdog (or vice-versa) and either spams the abnormal-cause
    // wipe or skips it entirely.
    for (name, expected) in [
        ("const RMVF: u32 = 1 << 23;", RMVF),
        ("const OBLRSTF: u32 = 1 << 25;", OBLRSTF),
        ("const PINRSTF: u32 = 1 << 26;", PINRSTF),
        ("const BORRSTF: u32 = 1 << 27;", BORRSTF),
        ("const SFTRSTF: u32 = 1 << 28;", SFTRSTF),
        ("const IWDGRSTF: u32 = 1 << 29;", IWDGRSTF),
        ("const WWDGRSTF: u32 = 1 << 30;", WWDGRSTF),
        ("const LPWRRSTF: u32 = 1 << 31;", LPWRRSTF),
    ] {
        assert!(
            RESET_CAUSE_SRC.contains(name),
            "production bit constant `{name}` must equal {expected:#010x}"
        );
    }
}

#[test]
fn negative_classify_and_clear_uses_volatile_mmio() {
    // RCC_CSR is sticky/clear-on-write; the classifier MUST use
    // volatile reads/writes so the compiler doesn't elide either the
    // read (cached `0x14004400` is meaningless after a real bit-set)
    // or the write (RMVF clear is the whole point — without it the
    // next reset sees stale flags ORed with whatever fired).
    assert!(
        RESET_CAUSE_SRC.contains("read_volatile(RCC_CSR)"),
        "classify_and_clear must read RCC_CSR via read_volatile"
    );
    assert!(
        RESET_CAUSE_SRC.contains("write_volatile(RCC_CSR, csr | RMVF);"),
        "classify_and_clear must set RMVF via write_volatile"
    );
    assert!(
        RESET_CAUSE_SRC.contains("write_volatile(RCC_CSR, csr & !RMVF);"),
        "classify_and_clear must clear RMVF afterwards so the next reset's flags aren't masked"
    );
}

#[test]
fn negative_classify_and_clear_is_marked_unsafe() {
    // Raw MMIO on a single-instance peripheral requires the caller to
    // promise this runs once, very early. Stripping `unsafe` would
    // let any module call it from any thread and silently lose the
    // first-call ordering guarantee documented in the safety comment.
    assert!(
        RESET_CAUSE_SRC.contains("pub unsafe fn classify_and_clear()"),
        "classify_and_clear must remain `unsafe` — see SAFETY block at lines 99-101"
    );
}

#[test]
fn negative_qemu_branch_does_not_touch_mmio() {
    // QEMU mps2-an505 has no RCC_CSR — touching it would HardFault.
    // The non-stm32u585 branch must return a hard-coded `(Cold, 0)`
    // without any read/write. A regression that "unified" the branches
    // would crash QEMU boots immediately.
    let start = RESET_CAUSE_SRC
        .find("#[cfg(not(feature = \"stm32u585\"))]\npub unsafe fn classify_and_clear()")
        .expect("QEMU branch of classify_and_clear must exist");
    let tail = &RESET_CAUSE_SRC[start..];
    let end = tail.find("\n}\n").expect("QEMU branch must close");
    let body = &tail[..end];
    assert!(
        !body.contains("read_volatile") && !body.contains("write_volatile"),
        "QEMU classify_and_clear must NOT do MMIO — would HardFault on the AN505 fabric"
    );
    assert!(
        body.contains("(ResetCause::Cold, 0)"),
        "QEMU classify_and_clear must return `(Cold, 0)` — full reset between QEMU runs"
    );
}

// ═════════════════════════════════════════════════════════════════════
// 2. sau.rs — register addresses, region layout, GTZC SECCFGR pins
// ═════════════════════════════════════════════════════════════════════

#[test]
fn positive_sau_register_addresses_are_armv8m_canonical() {
    // SCB→SAU block, ARMv8-M architectural constants. Same on every
    // M33 part; a typo would silently program a wrong region or no
    // region at all and break TrustZone enforcement from boot.
    for (line, expected) in [
        ("const SAU_CTRL_ADDR: u32 = 0xE000_EDD0;", 0xE000_EDD0u32),
        ("const SAU_RNR_ADDR: u32 = 0xE000_EDD8;", 0xE000_EDD8),
        ("const SAU_RBAR_ADDR: u32 = 0xE000_EDDC;", 0xE000_EDDC),
        ("const SAU_RLAR_ADDR: u32 = 0xE000_EDE0;", 0xE000_EDE0),
    ] {
        assert!(
            SAU_SRC.contains(line),
            "SAU register {line} must remain at {expected:#010x}"
        );
    }
}

#[test]
fn positive_sau_init_sequence_is_disable_program_enable_with_barriers() {
    // The sequence SAU.ctrl.write(0) ... configure regions ...
    // SAU.ctrl.write(1) ... dsb ... isb is load-bearing on ARMv8-M:
    // the dsb/isb pair flushes the pipeline so the new attribution
    // takes effect before the next memory access. Without them the
    // first NS-targeted load can race the SAU update.
    let init_start = SAU_SRC.find("pub fn init()").expect("init() must exist");
    let init = &SAU_SRC[init_start..];
    let disable = init
        .find("SAU.ctrl.write(0);")
        .expect("init() must disable SAU before programming regions");
    let enable = init
        .find("SAU.ctrl.write(1);")
        .expect("init() must re-enable SAU after programming");
    assert!(
        disable < enable,
        "SAU disable must precede re-enable in init()"
    );
    let after_enable = &init[enable..];
    assert!(
        after_enable.contains("cortex_m::asm::dsb();")
            && after_enable.contains("cortex_m::asm::isb();"),
        "init() must dsb+isb AFTER enabling SAU so the new attribution is visible"
    );
}

#[test]
fn positive_sau_region_count_is_four() {
    // The boot path programs exactly four regions: NS flash, NSC
    // veneers, NS data SRAM, NS peripherals. A fifth region would
    // need an extra `configure_sau_region(4, ...)` call — pin the
    // expected list so a silent addition surfaces here.
    assert!(SAU_SRC.contains("configure_sau_region(0,"));
    assert!(SAU_SRC.contains("configure_sau_region(1,"));
    assert!(SAU_SRC.contains("configure_sau_region(2,"));
    assert!(SAU_SRC.contains("configure_sau_region(3,"));
    // Region 4 must NOT be programmed — there are only 8 SAU regions
    // on Cortex-M33 (M33 RM §3.4.4) but our boot wants exactly 4.
    assert!(
        !SAU_SRC.contains("configure_sau_region(4,"),
        "adding a fifth SAU region without a CLAUDE.md note is a TrustZone-layout regression"
    );
}

#[test]
fn positive_only_region_1_is_nsc() {
    // Region 1 is the NSC veneers — that's the only place CMSE
    // veneer code can live. Marking any other region NSC would let
    // NS world call into S-world code outside the veneer table,
    // which is an arbitrary-code-execution-in-S-world bug.
    assert!(
        SAU_SRC.contains("configure_sau_region(1, veneer_base, nsc_end, true);"),
        "region 1 must be the NSC veneer block (`nsc = true`)"
    );
    assert!(
        SAU_SRC.contains(", false); // bank 2 NS"),
        "region 0 STM32U585 branch must be NS flash (`nsc = false`)"
    );
    assert!(
        SAU_SRC.contains(", false); // SRAM2 NS"),
        "region 2 STM32U585 branch must be NS SRAM (`nsc = false`)"
    );
    assert!(
        SAU_SRC.contains("configure_sau_region(3, 0x4000_0000, 0x4FFF_FFFF, false);"),
        "region 3 must be NS peripherals (`nsc = false`)"
    );
}

#[test]
fn negative_configure_sau_region_sets_enable_bit() {
    // RLAR bit 0 = ENABLE. Forgetting it makes the region completely
    // unprogrammed — the SAU treats unprogrammed regions as fully
    // secure by default on TZEN=1, which would silently lock the NS
    // world out of its own flash/SRAM/peripherals and brick boot.
    assert!(
        SAU_SRC.contains("SAU.rlar.write((limit & 0xFFFF_FFE0) | nsc_bit | 1);"),
        "RLAR must always OR in the enable bit (0x1) — see ARMv8-M ARM §B8.6.7"
    );
}

#[test]
fn negative_configure_sau_region_uses_nsc_bit_1() {
    // RLAR.NSC is bit 1. Bit 2 is reserved on M33; using the wrong
    // bit would silently make region 1 a plain NS region — NS code
    // could then call ANY S-world address as if it were a veneer.
    assert!(
        SAU_SRC.contains("let nsc_bit = if nsc { 1 << 1 } else { 0 };"),
        "NSC must be RLAR bit 1 — using bit 2 leaks S-world entry points to NS"
    );
}

#[test]
fn negative_configure_sau_region_aligns_to_32_bytes() {
    // SAU regions must be 32-byte aligned (M33 RM §3.4.4). The
    // address-mask 0xFFFF_FFE0 truncates the low 5 bits. Without it
    // an off-by-N base address could make the actual programmed
    // region different from the intended one — a hostile attacker
    // chaining off-by-one regions could open a gap between NS-flash
    // and NSC-veneers and execute attacker-chosen code as if in S.
    assert!(
        SAU_SRC.contains("SAU.rbar.write(base & 0xFFFF_FFE0);"),
        "RBAR must mask base to 32-byte alignment"
    );
    assert!(
        SAU_SRC.contains("(limit & 0xFFFF_FFE0)"),
        "RLAR must mask limit to 32-byte alignment"
    );
}

#[test]
fn negative_stm32_gtzc_seccfgr3_protects_full_crypto_block() {
    // CLAUDE.md Invariant #4 — the AES/HASH/RNG/PKA/SAES block must
    // be SECURE so the NS world cannot read TRNG, run a parallel
    // AES op, snoop hash state, or steal SAES-derived keys. Pin the
    // SECCFGR3 mask byte-for-byte (positions per CMSIS
    // `GTZC_CFGR3_*_Pos`).
    for (name, _bit) in [
        ("const SECCFGR3_AES_BIT:  u32 = 1 << 11;", 11u32),
        ("const SECCFGR3_HASH_BIT: u32 = 1 << 12;", 12),
        ("const SECCFGR3_RNG_BIT:  u32 = 1 << 13;", 13),
        ("const SECCFGR3_PKA_BIT:  u32 = 1 << 14;", 14),
        ("const SECCFGR3_SAES_BIT: u32 = 1 << 15;", 15),
    ] {
        assert!(
            SAU_SRC.contains(name),
            "GTZC SECCFGR3 bit `{name}` is load-bearing for CLAUDE.md invariant #4"
        );
    }
    // The seccfgr3 expression must include every five bits.
    assert!(SAU_SRC.contains("let seccfgr3 = SECCFGR3_AES_BIT"));
    assert!(SAU_SRC.contains("| SECCFGR3_HASH_BIT"));
    assert!(SAU_SRC.contains("| SECCFGR3_RNG_BIT"));
    assert!(SAU_SRC.contains("| SECCFGR3_PKA_BIT"));
    assert!(SAU_SRC.contains("| SECCFGR3_SAES_BIT;"));
}

#[test]
fn negative_stm32_gtzc_seccfgr3_does_not_mark_otg_secure() {
    // USB OTG FS lives at bit 10 in SECCFGR3 and must remain NS so
    // the NS-side HID transport keeps owning DWC2. If a refactor
    // ever flipped OTG to SECURE the next boot would silently brick
    // USB enumeration — and given the device's "USB only" companion
    // path, that's a denied-recovery state.
    //
    // Easiest pin: assert the comment listing OTG as "stays NS" is
    // present, and that seccfgr3 explicitly does NOT mention an
    // OTG bit constant.
    assert!(
        SAU_SRC.contains("OTG (bit 10): USB OTG FS — **stays NS**"),
        "OTG NS contract must remain documented in SECCFGR3"
    );
    assert!(
        !SAU_SRC.contains("SECCFGR3_OTG_BIT"),
        "no `SECCFGR3_OTG_BIT` allowed — OTG stays NS, so it must not appear in the secure mask"
    );
}

#[test]
fn negative_stm32_gtzc_seccfgr1_protects_se_buses() {
    // I2C1 is the OPTIGA + SE050 driver bus; I2C2 carries the
    // on-board STSAFE probe. Both carry plaintext SCP03/shielded-
    // connection bytes — if NS could touch either bus it could
    // race a transfer and steal session-key material.
    assert!(SAU_SRC.contains("const SECCFGR1_I2C1_BIT: u32 = 1 << 13;"));
    assert!(SAU_SRC.contains("const SECCFGR1_I2C2_BIT: u32 = 1 << 14;"));
    assert!(SAU_SRC.contains("let seccfgr1 = SECCFGR1_I2C1_BIT | SECCFGR1_I2C2_BIT;"));
}

#[test]
fn negative_stm32_tzsc_base_is_5003_2400_not_5003_2800() {
    // The pre-fix `0x5003_2800` was actually the TZIC interrupt
    // controller — writes were silently no-op'd and the chip booted
    // with TZSC at its NS-everywhere reset default. Pin the correct
    // 0x5003_2400 so a regression to the TZIC address surfaces here
    // rather than at "NS read of RNG_DR succeeded" runtime.
    assert!(
        SAU_SRC.contains("const TZSC_BASE: u32 = 0x5003_2400;"),
        "TZSC_BASE must be 0x5003_2400 — 0x5003_2800 is TZIC and writes there silently no-op"
    );
    assert!(
        !SAU_SRC.contains("const TZSC_BASE: u32 = 0x5003_2800;"),
        "TZSC_BASE must never re-regress to 0x5003_2800 (TZIC address)"
    );
}

#[test]
fn negative_stm32_gtzc_postwrite_self_check_is_present() {
    // The post-write readback catches base-addr typos and clock-not-
    // enabled glitches. Dropping it would let a botched GTZC config
    // boot silently into "TZSC writes go to /dev/null and every
    // peripheral is NS" — i.e., a stealthy regression of CLAUDE.md
    // invariant #4.
    assert!(SAU_SRC.contains("let r1 = GTZC.tzsc_seccfgr1.read();"));
    assert!(SAU_SRC.contains("let r2 = GTZC.tzsc_seccfgr2.read();"));
    assert!(SAU_SRC.contains("let r3 = GTZC.tzsc_seccfgr3.read();"));
    assert!(
        SAU_SRC.contains("debug_assert_eq!(r1, seccfgr1,"),
        "SECCFGR1 must self-check via debug_assert_eq! after the write"
    );
    assert!(SAU_SRC.contains("debug_assert_eq!(r3, seccfgr3,"));
}

#[test]
fn negative_stm32_mpcbb1_is_all_secure_mpcbb2_is_all_nonsecure() {
    // SRAM1 = secure stack/heap (192 KB, 24 SECCFGR words). SRAM2 = NS
    // data (64 KB, 8 SECCFGR words). Flipping either is an immediate
    // CLAUDE.md invariant #4 violation — NS could read the secure-
    // world signing-key cache or vice-versa.
    assert!(SAU_SRC.contains("for i in 0..24u32 {"));
    assert!(SAU_SRC.contains("mpcbb_seccfgr(MPCBB1_BASE, i).write(0xFFFF_FFFF);"));
    assert!(SAU_SRC.contains("for i in 0..8u32 {"));
    assert!(SAU_SRC.contains("mpcbb_seccfgr(MPCBB2_BASE, i).write(0x0000_0000);"));
}

#[test]
fn negative_qemu_mpc_partitioning_matches_documented_layout() {
    // MPC0 first 2MB secure (ns_start at LUT idx 64) — that's the
    // S-world code block. MPC1 first 128KB secure (ns_start at LUT
    // idx 4) — that's the S-world stack. Flipping the boundaries
    // would either leak the secure code/stack into NS or starve NS
    // of its expected memory window.
    assert!(SAU_SRC.contains("configure_mpc_partial_ns(&MPC0, 64);"));
    assert!(SAU_SRC.contains("configure_mpc_partial_ns(&MPC1, 4);"));
}

#[test]
fn negative_tzic_is_armed_with_same_masks_as_tzsc() {
    // Without TZIC the AHB bridge silently RAZ/WI's illegal NS
    // accesses and the secure world never learns the violation
    // happened. Arming TZIC with the same masks turns each violation
    // into NVIC IRQ 8, which DefaultHandler routes to
    // `hw::tzic::on_violation`. A regression that dropped this call
    // would silently downgrade "GTZC blocks the access" to "GTZC
    // blocks but nobody notices" — fatal for the SCA validation
    // path that's the whole point of the GTZC config.
    assert!(
        SAU_SRC.contains("crate::hw::tzic::configure(seccfgr1, seccfgr2, seccfgr3, 0);"),
        "TZIC must be armed with the same SECCFGR masks as TZSC"
    );
}

// ═════════════════════════════════════════════════════════════════════
// 3. main.rs — entry, panic, exception handlers, ARCH bindings,
//             reset-cause integration
// ═════════════════════════════════════════════════════════════════════

#[test]
fn positive_arch_register_addresses_are_armv8m_canonical() {
    // Architectural M33 registers — must always be at the documented
    // addresses; a wrong SYST_CSR address would silently drop SysTick
    // and freeze the inactivity timer.
    for line in [
        "syst_csr: hw::mmio::Reg32::new(0xE000_E010),",
        "syst_rvr: hw::mmio::Reg32::new(0xE000_E014),",
        "syst_cvr: hw::mmio::Reg32::new(0xE000_E018),",
        "icsr: hw::mmio::Reg32::new(0xE000_ED04),",
        "demcr: hw::mmio::Reg32::new(0xE000_EDFC),",
        "dwt_lar: hw::mmio::Reg32::new(0xE000_1FB0),",
        "dwt_ctrl: hw::mmio::Reg32::new(0xE000_1000),",
        "dwt_cyccnt: hw::mmio::Reg32::new(0xE000_1004),",
        "dhcsr: hw::mmio::RoReg32::new(0xE000_EDF0),",
    ] {
        assert!(
            MAIN_SRC.contains(line),
            "ARCH register binding `{line}` must keep its ARMv8-M canonical address"
        );
    }
}

#[test]
fn positive_dhcsr_is_read_only_to_avoid_unlock_key_writes() {
    // DHCSR is the Debug Halting Control & Status Register. Writes
    // require a magic key (0xA05F) the firmware doesn't have — and
    // we only ever READ C_DEBUGEN to decide whether semihosting is
    // safe. Binding DHCSR via RoReg32 enforces "never write" at the
    // type level.
    assert!(MAIN_SRC.contains("dhcsr: hw::mmio::RoReg32,"));
    assert!(MAIN_SRC.contains("dhcsr: hw::mmio::RoReg32::new(0xE000_EDF0),"));
}

#[test]
fn positive_dwt_lar_unlock_key_is_documented_magic() {
    // 0xC5AC_CE55 unlocks DWT lock access (ARMv8-M ARM §C1.16). Any
    // other value silently leaves the DWT locked, freezing CYCCNT
    // at 0 — and the NS-side perf bench would report bogus cycle
    // numbers without a runtime error.
    assert!(
        MAIN_SRC.contains("ARCH.dwt_lar.write(0xC5AC_CE55);"),
        "DWT_LAR unlock key must be 0xC5AC_CE55 (ARMv8-M magic)"
    );
}

#[test]
fn positive_reset_cause_runs_before_any_peripheral_init() {
    // The brownout-hardening design (reset_cause.rs:3-9) requires the
    // classify_and_clear call to happen first. Specifically: before
    // RCC_CSR is touched by anything else (e.g. hw::rcc::init or any
    // SAU/GTZC init that might toggle clocks). Pin the textual
    // ordering by asserting the call appears before sau::init() and
    // before any rcc::init() in the source.
    let classify_pos = MAIN_SRC
        .find("let (reset_cause, reset_csr_raw) = unsafe { reset_cause::classify_and_clear() };")
        .expect("main() must call reset_cause::classify_and_clear early");
    let sau_init_pos = MAIN_SRC
        .find("sau::init();")
        .expect("main() must call sau::init()");
    assert!(
        classify_pos < sau_init_pos,
        "reset_cause::classify_and_clear must run BEFORE sau::init"
    );
    let rcc_init_pos = MAIN_SRC
        .find("let mhz = hw::rcc::init();")
        .expect("main() must call hw::rcc::init()");
    assert!(
        classify_pos < rcc_init_pos,
        "reset_cause::classify_and_clear must run BEFORE hw::rcc::init (which touches RCC_CSR)"
    );
}

#[test]
fn positive_reset_cause_drives_abnormal_zeroize() {
    // The abnormal-reset SRAM zeroize is the load-bearing reason
    // the classifier exists in the first place. Dropping the
    // `if reset_cause.is_abnormal()` block — or replacing
    // `zeroize_sensitive_state` with anything narrower — silently
    // leaves stale secrets in SRAM across watchdog/lpwr/glitch
    // resets, exactly the brownout-hardening invariant.
    assert!(
        MAIN_SRC.contains("if reset_cause.is_abnormal() {"),
        "main() must branch on reset_cause.is_abnormal() — see brownout-hardening contract"
    );
    assert!(MAIN_SRC.contains("nsc::zeroize_sensitive_state();"));
}

#[test]
fn positive_reset_cause_is_logged_with_csr_raw() {
    // The boot log line `[S] Reset cause: <tag> (RCC_CSR=0x...)` is
    // the only on-hardware diagnostic for "why did the chip reboot".
    // Both the symbolic tag AND the raw bits are required: the tag
    // is for at-a-glance scanning, the raw bits prove there isn't a
    // sticky-flag combo the classifier silently mis-classified.
    assert!(
        MAIN_SRC.contains("Reset cause: {} (RCC_CSR=0x{:08x})"),
        "main() must log both the tag and the raw RCC_CSR — drop either and silent classifier bugs go unnoticed"
    );
    assert!(MAIN_SRC.contains("reset_cause.tag(), reset_csr_raw"));
}

#[test]
fn negative_panic_handler_zeroizes_before_halting() {
    // The panic handler is the LAST line of defence: a crash in any
    // S-world handler ends up here, and if it doesn't wipe the
    // master_secret / pin / SE session keys before parking the CPU,
    // a glitch-rebooting attacker can read them out of SRAM on the
    // next boot before our defensive zeroize runs. The zeroize
    // call must be the first statement in the panic handler.
    let panic_start = MAIN_SRC
        .find("fn panic(_info: &core::panic::PanicInfo)")
        .expect("panic_handler must exist");
    let body_start = panic_start
        + MAIN_SRC[panic_start..]
            .find('{')
            .expect("panic body must open");
    let body_end =
        body_start + MAIN_SRC[body_start..].find("loop {").unwrap_or(usize::MAX / 2);
    let body = &MAIN_SRC[body_start..body_end];
    assert!(
        body.contains("nsc::zeroize_sensitive_state();"),
        "panic handler must call nsc::zeroize_sensitive_state BEFORE halting"
    );
}

#[test]
fn negative_panic_handler_halts_with_wfi_not_bkpt() {
    // BKPT without a debugger attached escalates to HardFault, which
    // re-enters our exception path and could glitch through to NS.
    // WFI is the safe halt — pin it so a future "let's get a clean
    // crash trap" refactor doesn't reintroduce BKPT.
    let panic_start = MAIN_SRC
        .find("fn panic(_info: &core::panic::PanicInfo)")
        .expect("panic_handler must exist");
    let panic_body = &MAIN_SRC[panic_start..];
    let end = panic_body
        .find("\n}\n")
        .expect("panic handler must close");
    let body = &panic_body[..end];
    assert!(
        body.contains("cortex_m::asm::wfi();"),
        "panic handler must halt via wfi() — BKPT HardFaults without a debugger"
    );
    assert!(
        !body.contains("cortex_m::asm::bkpt"),
        "panic handler must NEVER bkpt() — would HardFault on standalone boots"
    );
}

#[test]
fn negative_panic_handler_is_test_excluded() {
    // The `#[panic_handler]` attribute is global; having it in the
    // host `cargo test` build conflicts with std's panic handler.
    // Pin the cfg gate so a future refactor doesn't accidentally
    // break host tests with a duplicate-panic-handler link error.
    assert!(
        MAIN_SRC.contains("#[cfg(not(test))]\n#[panic_handler]"),
        "#[panic_handler] must be `#[cfg(not(test))]`-gated"
    );
}

#[test]
fn negative_default_handler_dispatches_tzic_to_on_violation() {
    // IRQ 8 = GTZC1 illegal access. Without a dispatch arm here, an
    // NS attempt to touch a secure peripheral silently logs into
    // "unexpected irqn" and the chip parks in WFE — the GTZC test
    // harness (`gtzc-enforcement-hw`) reads the violation counter
    // to confirm enforcement works. No dispatch arm = silent
    // enforcement check, and any future regression to TZSC has no
    // alarm bell.
    let dh_start = MAIN_SRC
        .find("unsafe fn DefaultHandler(irqn: i16)")
        .expect("DefaultHandler must exist");
    let dh = &MAIN_SRC[dh_start..];
    let dh_end = dh.find("\n}\n").expect("DefaultHandler must close");
    let dh_body = &dh[..dh_end];
    assert!(
        dh_body.contains("8 => unsafe { hw::tzic::on_violation() },"),
        "DefaultHandler must dispatch IRQ 8 (GTZC) to hw::tzic::on_violation"
    );
}

#[test]
fn negative_default_handler_logs_unexpected_irqs_instead_of_silent_drop() {
    // Without the catch-all `_ =>` arm, any other IRQ that fires
    // silently re-enters DefaultHandler's tail (which is undefined
    // behaviour on cortex-m-rt). The catch-all is required even
    // though we don't currently unmask anything other than TAMP +
    // GTZC — it documents the invariant and traps regressions.
    let dh_start = MAIN_SRC
        .find("unsafe fn DefaultHandler(irqn: i16)")
        .expect("DefaultHandler must exist");
    let dh = &MAIN_SRC[dh_start..];
    let dh_end = dh.find("\n}\n").expect("DefaultHandler must close");
    let dh_body = &dh[..dh_end];
    assert!(
        dh_body.contains("_ => {"),
        "DefaultHandler must keep its catch-all arm — see Safety contract at lines 2779-2782"
    );
    assert!(
        dh_body.contains("cortex_m::asm::wfe();"),
        "Unmatched IRQ must park in WFE rather than fall through"
    );
}

#[test]
fn negative_pendsv_uses_gated_unlock_not_raw_unlock() {
    // PendSV re-unlock fires after an idle wipe. If it called
    // `SE.unlock` directly instead of `nsc::gated_unlock`, the MCU
    // page-126 attempt counter would be bypassed and an attacker
    // who can keep the device idle long enough could brute-force
    // the PIN past MAX_ATTEMPTS. The CLAUDE.md "What NOT to do"
    // entry on PIN compares + invariant #2 hangs on this.
    let pendsv_start = MAIN_SRC
        .find("fn PendSV()")
        .expect("PendSV handler must exist");
    let pendsv = &MAIN_SRC[pendsv_start..];
    let pendsv_end = pendsv.find("\n}\n").expect("PendSV handler must close");
    let pendsv_body = &pendsv[..pendsv_end];
    assert!(
        pendsv_body.contains("nsc::gated_unlock(se, &pin)"),
        "PendSV must route re-unlock through nsc::gated_unlock — see CLAUDE.md invariant #2"
    );
}

#[test]
fn negative_pendsv_has_reentry_guard() {
    // SysTick can re-pend PendSV while PendSV is already in the PIN
    // loop. Re-entering an exception is UB on M33; the static-mut
    // PENDSV_IN_FLIGHT guard returns early on nested entry. Pin
    // both the static and the early-return check.
    assert!(MAIN_SRC.contains("static mut PENDSV_IN_FLIGHT: u32 = 0;"));
    assert!(MAIN_SRC
        .contains("if core::ptr::read_volatile(core::ptr::addr_of!(PENDSV_IN_FLIGHT)) != 0 {"));
}

#[test]
fn negative_pendsv_zeroizes_pin_after_use() {
    // Local PIN buffer must be zeroized before the loop continues
    // (next iteration overwrites the binding but the bytes survive
    // on the secure-world stack otherwise). Pin the zeroize +
    // zeroize_barrier pair.
    let pendsv_start = MAIN_SRC.find("fn PendSV()").expect("PendSV must exist");
    let pendsv = &MAIN_SRC[pendsv_start..];
    let pendsv_end = pendsv.find("\n}\n").expect("PendSV must close");
    let body = &pendsv[..pendsv_end];
    assert!(body.contains("pin.zeroize();"));
    assert!(body.contains("crate::fi::zeroize_barrier();"));
}

#[test]
fn negative_systick_idle_wipe_skips_when_handler_is_busy() {
    // HIGH-7 fix: if a long-running gateway handler (e.g. sign) is
    // holding stack-local copies of master_secret, zeroizing the BSS
    // copy from SysTick would let the handler finish signing against
    // a session the user no longer has unlocked. The
    // `!nsc::handler_is_busy()` guard prevents this. Drop the guard
    // and the bug returns silently — no other test catches it.
    let systick_start = MAIN_SRC.find("fn SysTick()").expect("SysTick must exist");
    let systick = &MAIN_SRC[systick_start..];
    let systick_end = systick
        .find("\n/// Catch-all device-IRQ handler.")
        .expect("SysTick must close before DefaultHandler doc");
    let body = &systick[..systick_end];
    assert!(
        body.contains("if timeout::is_idle() && nsc::is_unlocked() && !nsc::handler_is_busy()"),
        "SysTick idle-wipe must keep the `!nsc::handler_is_busy()` guard (HIGH-7 fix)"
    );
}

#[test]
fn negative_systick_idle_wipe_pends_pendsv_for_reunlock() {
    // The idle-wipe ISR is too short to drive the PIN UI; it pends
    // PendSV (low-priority) to run the re-unlock loop outside the
    // SysTick interrupt. Pin the PENDSVSET bit position (ICSR
    // bit 28) so a typo silently stalls re-unlock and leaves the
    // device showing "Ready" indefinitely while actually locked.
    assert!(
        MAIN_SRC.contains("ARCH.icsr.write(1 << 28); // PENDSVSET"),
        "idle-wipe must trigger PendSV via ICSR.PENDSVSET (bit 28)"
    );
}

#[test]
fn negative_se_static_mut_is_unique_per_backend() {
    // Every SE-backend cfg block must define exactly one
    // `static mut SE: ... = ...::new();`. If a refactor accidentally
    // emitted two definitions for overlapping cfgs, the build would
    // succeed but only one would actually be used — the other gets
    // shadowed and silently never receives `provision/unlock` calls,
    // meaning entropy half-O or half-E might never be persisted.
    let count = MAIN_SRC.matches("static mut SE:").count();
    assert_eq!(
        count, 5,
        "exactly five backend-cfg'd `static mut SE:` definitions expected (mock, tropic01, se050, optiga, dual)"
    );
}

#[test]
fn negative_panic_handler_debug_log_dhcsr_check_is_present() {
    // Under `debug-log`, the panic handler tries to emit a message
    // via semihosting. BKPT-based semihosting without a debugger
    // HardFaults — gating the print on DHCSR.C_DEBUGEN means
    // standalone production-builds-with-debug-log don't crash twice.
    assert!(
        MAIN_SRC.contains("if ARCH.dhcsr.read() & 1 != 0 {"),
        "debug-log panic path must check DHCSR.C_DEBUGEN before semihosting"
    );
}

#[test]
fn negative_secure_log_macro_compiles_to_nop_without_debug_log() {
    // The fallback arm of secure_log! must expand to a literal
    // no-op so production builds (no debug-log) emit zero bytes
    // to the semihosting channel — otherwise a stripped firmware
    // would have observable BKPT instructions an attacker could
    // count to learn boot timing.
    assert!(
        MAIN_SRC.contains("#[cfg(any(not(feature = \"debug-log\"), test))]\nmacro_rules! secure_log {"),
        "secure_log! must have a no-op arm gated on `not(debug-log)` or `test`"
    );
    assert!(
        MAIN_SRC.contains("($($arg:tt)*) => {};"),
        "secure_log! no-op arm body must be empty"
    );
}

#[test]
fn negative_reset_cause_module_declaration_is_test_excluded() {
    // The `reset_cause` module pulls in raw MMIO and `cortex_m` —
    // gating it `#[cfg(not(test))]` keeps host `cargo test` linkable.
    // The host pure-logic mirror in this very file fills in the
    // testing coverage. A refactor that removed the gate would
    // break `cargo test -p sphincs-tz-secure` instantly.
    assert!(
        MAIN_SRC.contains("#[cfg(not(test))]\nmod reset_cause;"),
        "reset_cause must remain `#[cfg(not(test))] mod reset_cause;` in main.rs"
    );
}

#[test]
fn negative_sau_module_declaration_is_test_excluded() {
    // Same shape as reset_cause: sau.rs imports `crate::hw::mmio` +
    // extern linker symbols + (on STM32U585) `crate::hw::tzic` —
    // none link on host. Gate must stay.
    assert!(
        MAIN_SRC.contains("#[cfg(not(test))]\nmod sau;"),
        "sau must remain `#[cfg(not(test))] mod sau;` in main.rs"
    );
}

// ═════════════════════════════════════════════════════════════════════
// 4. Cross-file: reset_cause flag positions vs main.rs RCC_CSR logging
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_no_classical_signer_referenced_in_slice() {
    // CLAUDE.md "What NOT to do": no ECDSA, no Ed25519, no FORS+C
    // anywhere in firmware. The slice has no signing code, but a
    // copy-paste from another module could sneak one in via boot
    // setup. Lock it out at the slice level.
    for forbidden in &[
        "secp256k1",
        "ecdsa::",
        "ed25519",
        "fors_c",
        "rotateMasterKeys",
        "resetBootstrapUses",
        "resetSlotUses",
    ] {
        assert!(
            !MAIN_SRC.contains(forbidden),
            "main.rs must not reference forbidden symbol `{forbidden}` (CLAUDE.md What NOT to do)"
        );
        assert!(
            !SAU_SRC.contains(forbidden),
            "sau.rs must not reference forbidden symbol `{forbidden}`"
        );
        assert!(
            !RESET_CAUSE_SRC.contains(forbidden),
            "reset_cause.rs must not reference forbidden symbol `{forbidden}`"
        );
    }
}

#[test]
fn negative_systick_reload_is_documented_25khz_on_qemu() {
    // QEMU mps2-an505 SysTick clock is 25 MHz; 25_000 / tick = 1 ms.
    // Any drift breaks the inactivity-timer "120 s" expectation in
    // CLAUDE.md and the brownout-hardening doc. Pin the constant.
    assert!(MAIN_SRC.contains("const SYSTICK_RELOAD: u32 = 25_000;"));
}

#[test]
fn negative_ns_flash_base_constants_match_proto_layout() {
    // NS_FLASH_BASE is duplicated in `main.rs` for use by the
    // `boot_ns::boot()` hop and in `pqsigner-proto::mem_layout` for
    // NS pointer validation. The two must agree exactly — otherwise
    // either the boot hop runs into a non-NS address or the
    // gateway rejects every legitimate NS pointer.
    assert!(MAIN_SRC.contains("const NS_FLASH_BASE: u32 = 0x0020_0000;"));
    assert!(MAIN_SRC.contains("const NS_FLASH_BASE: u32 = 0x0810_0000;"));
}

#[test]
fn positive_duress_pin_collected_only_on_first_boot_and_threaded() {
    // §32 P4: the duress-PIN dialog must run ONLY on the unprovisioned
    // first-boot path (so it doesn't re-prompt on every unlock), and the
    // collected PIN must be threaded into provisioning. Pin both: the
    // collect call + that provision_from_mnemonic receives duress_pin
    // (NOT the hardcoded `None` the e2e auto-provision path passes).
    assert!(
        MAIN_SRC.contains("ui::seed_wizard::collect_duress_pin(&pin)"),
        "first-boot wizard must collect a duress PIN",
    );
    assert!(
        MAIN_SRC.contains("&pin, duress_pin.as_ref())"),
        "the wizard's provision_from_mnemonic must thread the collected duress PIN",
    );
    // Belt-and-braces: the collect call sits AFTER run_first_boot_wizard
    // (the unprovisioned branch), not in the already-provisioned unlock
    // loop which uses enter_pin() directly.
    let collect_pos = MAIN_SRC.find("collect_duress_pin(&pin)").expect("collect present");
    let wizard_pos = MAIN_SRC.find("run_first_boot_wizard();").expect("wizard present");
    assert!(collect_pos > wizard_pos, "duress collection must follow run_first_boot_wizard");
}
