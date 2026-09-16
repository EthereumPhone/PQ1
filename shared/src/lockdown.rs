//! Pure silicon-lockdown option-byte decode logic (host-testable).
//!
//! The STM32U585 option-byte *reads* are MMIO and live in the `stm32u585`-gated
//! `secure/src/hw/flash.rs`, which the host test build never compiles (`mod hw`
//! is `#[cfg(not(test))]`). The decode/compare logic below is pure arithmetic
//! with no hardware dependency, so it lives here in the host-compiled `shared`
//! crate and is unit-tested — mirroring how `ns_ptr_validate` keeps the pure
//! NS-pointer window check host-testable while the MMIO deref stays in `secure`.
//!
//! Silicon-lockdown adversarial-review playbook: SL1 (reversible-state-mistaken-
//! for-locked), SL2/SL3 (boot-redirect detectability), SL7 (RDP-verify-in-boot).

/// STM32U585 readout-protection (RDP) level, decoded from `FLASH_OPTR.RDP[7:0]`
/// per RM0456: `0xAA` = Level 0, `0xCC` = Level 2, `0x55` = Level 0.5 (valid
/// only with `TZEN=1`), and **any other value** = Level 1 (the catch-all — RDP1
/// is deliberately NOT a single code). A shipping image should only ever run at
/// Level 2, where SWD/JTAG is disabled in silicon.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum RdpLevel {
    L0,
    L0_5,
    L1,
    L2,
}

/// Pure decode of the `FLASH_OPTR.RDP` byte.
#[must_use]
pub const fn rdp_level_from_byte(rdp: u8) -> RdpLevel {
    match rdp {
        0xAA => RdpLevel::L0,
        0x55 => RdpLevel::L0_5,
        0xCC => RdpLevel::L2,
        _ => RdpLevel::L1,
    }
}

/// `SECBOOTADD0R` layout, per **RM0456 §7.9.16** (offset `0x4C`, ST production
/// value **`0x0C00_007C`**): `SECBOOTADD0[24:9]` occupies bits `[31:16]` and
/// `SECBOOTADD0[8:0]` bits `[15:7]` — i.e. the 25-bit address field sits at
/// bits `[31:7]` — with **`BOOT_LOCK` at bit 0** and bits `[6:1]` reserved.
/// The boot address is therefore `field << 7`, so the register reconstructs it
/// as `reg & !0x7F`.
///
/// The previous code masked the LOW 25 bits and compared them to
/// `boot_addr >> 7`, which can never match real silicon: this board reads
/// `0x0C00_007C` (the ST production value), whose low bits are `0x7C`. That
/// mismatch halted the FSBL tz-1 tripwire on every boot and would have halted
/// first-boot Phase A before the RDP-2 burn. The archived work-todo flagged the
/// exact contradiction ("`0x0C00_007C` vs the ob-configurator's `0x0018_0000`
/// for the same boot address") and deferred it as unconfirmed; RM0456 plus a
/// bench read now confirm it.
///
/// NOTE on the two encodings, because conflating them is the whole bug:
/// `0x0C00_007C` is the REGISTER word (address in bits `[31:7]`), while
/// `0x0018_0000` is CubeProgrammer's OPTION-BYTE FIELD value (`addr >> 7`).
/// Both describe boot address `0x0C00_0000`. Bench boards boot correctly
/// because every Makefile recipe programs option bytes via
/// `STM32_Programmer_CLI --optionbytes SECBOOTADD0=0x180000`, which takes the
/// field form and encodes for us. Writing the field value straight to the
/// register selects `0x0018_0000` instead — the defect that
/// `tools/ob-configurator` carried until it was deleted (issue #37).
const SECBOOTADD0_ADDR_SHIFT_MASK: u32 = 0xFFFF_FF80;
/// `BOOT_LOCK` — bit 0 (RM0456 §7.9.16). Pinned here so the deferred
/// BOOT_LOCK assertion has a confirmed bit to build on.
pub const SECBOOTADD0_BOOT_LOCK: u32 = 1 << 0;

/// Does the `SECBOOTADD0R` register value select `expected_boot_addr` as the
/// secure boot entry? A target shipping image must select the approved FSBL
/// base (`expected_boot_addr = 0x0C00_0000`); a different address is a boot
/// redirect (SL2). This predicate proves only the address selection, not the
/// FSBL extent, WRP mapping, or lifecycle state. The high control bits are
/// masked out so that *setting* `BOOT_LOCK` (whose exact bit position is
/// doc-ambiguous) does not read as a wrong address.
#[must_use]
pub const fn secboot_selects(secbootadd0r: u32, expected_boot_addr: u32) -> bool {
    // Reconstruct the address from bits [31:7]; BOOT_LOCK (bit 0) and the
    // reserved bits [6:1] are deliberately ignored here, so SETTING BOOT_LOCK
    // never reads as "wrong boot address".
    (secbootadd0r & SECBOOTADD0_ADDR_SHIFT_MASK) == expected_boot_addr
}

// ===========================================================================
// Option-byte CONTROL registers — which register carries which command bit.
//
// This block exists because its absence was a live defect class. Everything
// host-testable here previously covered only the option-byte VALUE registers
// (`OPTR`, `SECWM*R1`, `SECBOOTADD0R`), so nothing in the workspace pinned
// *which control register* a commit must be written to. Three separate places
// then reached for the wrong one, and none was caught:
//
//   1. `tools/ob-configurator` declared `SECCR1 = FLASH_S + 0x24` and
//      `SECSR = FLASH_S + 0x2C` — inverted — and wrote its commit bits there.
//      Deleted (#37).
//   2. `secure/src/hw/flash.rs`'s `program_rdp_level2_and_launch` writes
//      `OPTSTRT` / `OBL_LAUNCH` and reads `OPTLOCK` from `SECCR`, which has
//      none of those bits, so the irreversible RDP-2 burn cannot commit yet
//      returns `Ok(())`. Reported, NOT fixed here (#268) — it sits next to an
//      irreversible operation and wants an owner decision plus a sacrificial
//      -silicon plan, so this module only supplies the facts to fix it against.
//   3. The `flash.rs` provenance comments cited (1) as their authority.
//
// Enumerated from the vendor SVD (`STM32CubeProgrammer/SVD/STM32U585.svd`,
// 2026-09-16), listing EVERY field of each register rather than probing for
// expected names — probing is what hid this. Note the SVD prefixes register
// names (`FLASH_SECCR`, not `SECCR`); searching the bare name returns nothing
// and reads as absence.
//
// The split is coherent, not an SVD gap: option bytes are global to the
// device, so their control bits live in the NON-SECURE control register, while
// `SECCR` carries the secure-only error/invalidate bits instead.
// ===========================================================================

/// `FLASH_NSSR` offset — non-secure status (adds `OPTWERR` bit 13 and the
/// OEM-lock status bits, which `SECSR` does not carry).
pub const FLASH_NSSR_OFF: u32 = 0x20;
/// `FLASH_SECSR` offset — secure status. Error flags plus read-only `BSY`
/// (bit 16) and `WDW` (bit 17). Carries NO command bits.
pub const FLASH_SECSR_OFF: u32 = 0x24;
/// `FLASH_NSCR` offset — non-secure control. **This is the register that owns
/// every option-byte command bit** ([`FLASH_OPTSTRT`], [`FLASH_OBL_LAUNCH`],
/// [`FLASH_OPTLOCK`]).
pub const FLASH_NSCR_OFF: u32 = 0x28;
/// `FLASH_SECCR` offset — secure control. Has `STRT` (16), `RDERRIE` (26),
/// `INV` (29) and `LOCK` (31), and **none** of the option-byte command bits.
pub const FLASH_SECCR_OFF: u32 = 0x2C;

/// `OPTSTRT` — commit staged option bytes. `FLASH_NSCR` bit 17 ONLY.
pub const FLASH_OPTSTRT: u32 = 1 << 17;
/// `OBL_LAUNCH` — reload option bytes (triggers a system reset).
/// `FLASH_NSCR` bit 27 ONLY.
pub const FLASH_OBL_LAUNCH: u32 = 1 << 27;
/// `OPTLOCK` — cleared by the `OPTKEYR` key sequence. `FLASH_NSCR` bit 30 ONLY.
pub const FLASH_OPTLOCK: u32 = 1 << 30;
/// `BSY` — bit 16 of both status registers, read-only in each.
pub const FLASH_SR_BSY: u32 = 1 << 16;

/// Does `reg_off` name the register that option-byte commands must be written
/// to? Exactly one offset qualifies, so a driver can assert its own binding.
#[must_use]
pub const fn is_optbyte_command_register(reg_off: u32) -> bool {
    reg_off == FLASH_NSCR_OFF
}

/// Can `bits` legally be written to `FLASH_SECCR`? The option-byte command
/// bits cannot: `SECCR` does not implement bit 17, 27 or 30, so such a write
/// is silently inert — it neither commits nor errors.
#[must_use]
pub const fn seccr_accepts(bits: u32) -> bool {
    (bits & (FLASH_OPTSTRT | FLASH_OBL_LAUNCH | FLASH_OPTLOCK)) == 0
}

// ===========================================================================
// Ship option-byte profile (work-todo #36 — first-boot RDP-2 self-lock).
//
// Devices ship at RDP-0 with a batch-uniform image; the first field boot
// verifies the option bytes against this profile BEFORE programming RDP=0xCC.
// A mismatch means the unit did not leave the factory in the published state
// (or a transit attacker tampered with the option bytes) → the first-boot
// flow halts UNLOCKED with a numbered fault (never bricks a bad unit into
// RDP-2). The open-source RDP-0 verifier tool reuses these same const fns so
// the published profile and the on-device check can never diverge.
//
// Register layout confidence (STM32U585, RM0456 §7.11):
//   CONFIRMED (RM0456 + bench read, 2026-09-16): TZEN=bit31 of FLASH_OPTR;
//     RDP=OPTR[7:0]; SECWM*R1 PSTRT=[6:0]/PEND=[22:16] compared as FIELDS (the
//     registers read back with reserved bits set — this board reads
//     0xFFFFFF80 / 0xFF80FFFF); SECBOOTADD0 address field at bits [31:7] with
//     BOOT_LOCK at bit 0 (RM0456 7.9.16, ST production value 0x0C00_007C).
//     Provenance is the vendor SVD (`STM32CubeProgrammer/SVD/STM32U585.svd`)
//     plus RM0456 and a bench read — NOT the former `tools/ob-configurator`,
//     which encoded SECBOOTADD0 wrongly (see `secboot_selects`), swapped the
//     SECSR/SECCR offsets, and was once mis-cited here as confirmation for the
//     watermark word compares. It was deleted rather than repaired (#37).
//   BENCH-CONFIRM (exact bit positions are an RM0456 pin — see the #36
//     deferred silicon-validation runbook): BOR_LEV field, WRP1A page span,
//     and the OEM1/OEM2 key-lock status bits. These live behind the single
//     named constants below so one bench correction fixes every caller. The
//     host tests below exercise the comparator LOGIC, not the silicon truth.
// ===========================================================================

/// `FLASH_OPTR.TZEN` — TrustZone enable (bit 31). Must be set in the ship
/// profile (secure world is mandatory).
pub const OPTR_TZEN: u32 = 1 << 31;

/// Expected `FLASH_OPTR.RDP` byte in the *ship* state (RDP Level 0). The
/// first-boot flow only programs `0xCC` (Level 2) after this verifies.
pub const SHIP_RDP_BYTE: u8 = 0xAA;

/// Expected `FLASH_OPTR.RDP` byte once the device has locked ITSELF (Level 2).
/// Pairs with [`SHIP_RDP_BYTE`]: those are the only two RDP bytes a genuine
/// unit may present, and which one is expected depends on the lifecycle phase
/// (see [`phase_profile`]).
pub const LOCKED_RDP_BYTE: u8 = 0xCC;

/// `SECWM1R1` FIELD values that mark all of bank 1 secure (`PSTRT=0, PEND=0x7F`).
/// This is what a programmer WRITES, NOT what the register reads back: `SECWM1R1`/`SECWM2R1` are option-byte shadow registers
/// whose unprogrammed bits read as 1s (SVD reset value `0xFF00FF00`). A correctly
/// configured pq1 board reads `0xFFFFFF80` / `0xFF80FFFF`. Compare FIELDS, never
/// the whole word — see [`secwm_bank1_all_secure`].
pub const SECWM1_ALL_SECURE: u32 = 0x007F_0000;
/// `SECWM2R1` field values that mark all of bank 2 non-secure (`PSTRT=0x7F > PEND=0`).
pub const SECWM2_ALL_NS: u32 = 0x0000_007F;

/// `PSTRT` occupies bits `[6:0]` and `PEND` bits `[22:16]` of both `SECWM*R1`
/// registers (SVD `FLASH_SECWM1R1`/`FLASH_SECWM2R1`). Every other bit is
/// reserved and reads back as 1 on real silicon.
const SECWM_PSTRT_MASK: u32 = 0x7F;
const SECWM_PEND_SHIFT: u32 = 16;

/// Extract `(PSTRT, PEND)` from a raw `SECWM*R1` read.
#[must_use]
pub const fn secwm_fields(secwmr1: u32) -> (u32, u32) {
    (
        secwmr1 & SECWM_PSTRT_MASK,
        (secwmr1 >> SECWM_PEND_SHIFT) & SECWM_PSTRT_MASK,
    )
}

/// BENCH-CONFIRM (RM0456): `FLASH_OPTR.BOR_LEV` field position. Best-effort
/// per RM0456; pin against silicon in the #36 runbook before this field is
/// treated as load-bearing (it is advisory today — see `ShipProfile`).
pub const BOR_LEV_SHIFT: u32 = 8;
pub const BOR_LEV_MASK: u32 = 0x7;

/// BENCH-CONFIRM (RM0456): OEM1/OEM2 key-lock status bits. A shipped unit must
/// have NO OEM key provisioned — otherwise a transit attacker could pre-plant
/// an OEM2 password enabling a later RDP-2 → RDP-1 regression. Exact register
/// (FLASH_NSSR vs FLASH_OPTSR) + bit positions are a runbook pin; the mask is
/// isolated here so the correction is one line.
///
/// Fail direction (playbook SL8): a wrong register/bit guess makes the mask
/// read constant-0 bits, so a naive `oem_status & mask == 0` would pass
/// VACUOUSLY — fail-open, letting a unit with a planted OEM2 regression
/// password sail through the one gate that exists to catch it. That is why the
/// load-bearing gate `oem_locks_absent` is now gated on
/// [`OEM_LOCK_MASK_PINNED`] and FAILS CLOSED until the register/bits are pinned
/// on silicon. Host tests exercise only the comparator on synthetic values,
/// never the shipped register read.
pub const OEM1LOCK: u32 = 1 << 26;
pub const OEM2LOCK: u32 = 1 << 27;

/// Silicon-pin status for the BENCH-CONFIRM OEM-lock mask above. While `false`,
/// [`oem_locks_absent`] FAILS CLOSED (playbook SL8): an unpinned register/bit
/// guess must never vacuously wave a unit through. Flip to `true` ONLY in the
/// commit that records BOTH (a) the RM0456 §7 citation for the OEM-lock status
/// register and the OEM1/OEM2LOCK bit positions, AND (b) a positive bench
/// detection — provision an OEM1 key on a sacrificial RDP-0 board and confirm
/// this gate rejects it (issue #46 / #387). Until then every first boot halts
/// at the OEM-lock check; that is the intended posture (the `rdp2-self-lock`
/// flow cannot ship before this pin exists anyway).
pub const OEM_LOCK_MASK_PINNED: bool = false;

/// Which option-byte field failed verification — drives the numbered
/// first-boot fault screen so a mismatch reports *what* was wrong.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ObField {
    Tzen,
    Rdp,
    Secwm1,
    Secwm2,
    SecBootAdd0,
    Wrp1a,
    OemLock,
}

/// The confirmed, load-bearing half of the ship option-byte profile. Fields
/// whose exact bit layout is still an RM0456 bench pin (BOR_LEV, WRP1A span)
/// are checked by the separate `bor_lev_ok` / `wrp1a_covers_fsbl` const fns
/// and are advisory until pinned.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct ShipProfile {
    /// Expected secure boot entry (WRP1A-locked FSBL base).
    pub boot_addr: u32,
    /// Expected `FLASH_OPTR.RDP` byte at ship (Level 0).
    pub rdp_byte: u8,
}

/// The STM32U585 ship profile (RDP-0, TZEN=1, all-bank-1-secure, FSBL boot).
pub const SHIP_PROFILE_U585: ShipProfile = ShipProfile {
    boot_addr: 0x0C00_0000,
    rdp_byte: SHIP_RDP_BYTE,
};

/// The same profile AFTER the first-boot lock ceremony: identical boot address,
/// `RDP = 0xCC`. Draft 1.2 §3 row 2 requires the every-boot read-back to compare
/// against the *phase-appropriate* profile, so a locked unit presenting the ship
/// byte — or a ship unit presenting `0xCC` — is a mismatch in both directions.
pub const LOCKED_PROFILE_U585: ShipProfile = ShipProfile {
    boot_addr: 0x0C00_0000,
    rdp_byte: LOCKED_RDP_BYTE,
};

/// Pick the phase-appropriate profile from the live `FLASH_OPTR`.
///
/// `RDP == 0xCC` selects the locked profile. EVERY other byte selects the
/// pre-ceremony ship profile (`0xAA`), including an erased or garbage byte,
/// which [`rdp_level_from_byte`] maps to Level 1. That is the fail-closed
/// direction: a tampered RDP byte is compared against `0xAA`, mismatches, and
/// surfaces as [`ObField::Rdp`] instead of selecting a profile that accepts it.
#[must_use]
pub const fn phase_profile(optr: u32) -> &'static ShipProfile {
    match rdp_level_from_byte((optr & 0xFF) as u8) {
        RdpLevel::L2 => &LOCKED_PROFILE_U585,
        _ => &SHIP_PROFILE_U585,
    }
}

/// Verify `FLASH_OPTR` matches the ship profile's TZEN + RDP fields.
///
/// NOTE (playbook SL9): this is deliberately a PARTIAL mask — the remaining
/// OPTR bits (SWAP_BANK, nSWBOOT0, nBOOT0, NRST_MODE, …) are not compared
/// here and are preserved verbatim into the permanent RDP-2 state. The exact
/// masked compare (full expected OPTR + don't-care mask) is being handled
/// separately; do not describe this check as verifying the full ship OPTR.
#[must_use]
pub const fn optr_matches_ship(optr: u32, p: &ShipProfile) -> Result<(), ObField> {
    if optr & OPTR_TZEN == 0 {
        return Err(ObField::Tzen);
    }
    if (optr & 0xFF) as u8 != p.rdp_byte {
        return Err(ObField::Rdp);
    }
    Ok(())
}

/// Does `secwm1r1` mark all of bank 1 secure (`PSTRT=0, PEND=0x7F`)?
///
/// FIELD compare, not word compare. The previous `secwm1r1 == SECWM1_ALL_SECURE`
/// form could never match real silicon — the reserved bits read as 1s — so it
/// halted every boot that consulted it (the FSBL tz-1 tripwire) and would have
/// halted first-boot Phase A before the RDP-2 burn on every genuine unit.
/// Measured on pq1 (die 002f0023-30465002-2033314c): raw `0xFFFFFF80`, fields
/// `PSTRT=0, PEND=0x7F`, matching CubeProgrammer's own decode.
#[must_use]
pub const fn secwm_bank1_all_secure(secwm1r1: u32) -> bool {
    let (pstrt, pend) = secwm_fields(secwm1r1);
    pstrt == 0 && pend == 0x7F
}

/// Does `secwm2r1` leave all of bank 2 non-secure (`PSTRT > PEND`, the
/// watermark-disabled encoding)? Field compare, same reasoning as above;
/// measured raw `0xFF80FFFF` => `PSTRT=0x7F, PEND=0`.
#[must_use]
pub const fn secwm_bank2_all_ns(secwm2r1: u32) -> bool {
    let (pstrt, pend) = secwm_fields(secwm2r1);
    pstrt > pend
}

/// Does the WRP1A option register lock (write-protect) FSBL pages 0..=3?
///
/// BENCH-CONFIRM (RM0456): the `WRP1AR` layout is `STRT` in bits `[6:0]`,
/// `END` in bits `[22:16]`, `UNLOCK` in bit `[31]` (0 = locked). We require
/// `UNLOCK==0` and the `[STRT..=END]` span to cover pages 0..=3. The exact
/// bit fields are a runbook pin; kept in one place for a one-line fix.
///
/// Fail direction per sub-field (playbook SL8), under a wrong layout guess
/// whose misread bits return constant 0: `UNLOCK` passes vacuously (fail-open
/// — a cleared write-protect goes unreported); `STRT==0` passes vacuously
/// (fail-open — a span starting past page 0 goes unreported); `END>=3` FAILS
/// (fail-closed — the false-halt direction bricks every genuine first boot:
/// a reliability hazard, not a security hole). Because two of the three
/// sub-fields fail OPEN, and WRP1A is the load-bearing check of invariant #10
/// (WRP must be verified-set before RDP-2 makes it permanent), the wrapper
/// [`wrp1a_covers_fsbl`] gates on [`WRP1A_MASK_PINNED`] and fails CLOSED until
/// the layout is pinned on silicon.
///
/// Silicon-pin status for the BENCH-CONFIRM `WRP1AR` layout. While `false`,
/// `wrp1a_covers_fsbl` fails closed. Flip to `true` ONLY in the commit that
/// records the RM0456 `WRP1AR` layout (`STRT[6:0]`, `END[22:16]`, `UNLOCK[31]`)
/// citation + a bench readback (issue #46).
pub const WRP1A_MASK_PINNED: bool = false;

/// Raw "WRP1A write-protects FSBL pages 0..=3" compare over the BENCH-CONFIRM
/// layout (`UNLOCK==0 && STRT==0 && END>=3`), independent of the silicon pin.
#[must_use]
pub const fn wrp1a_covers_fsbl_bits(wrp1ar: u32) -> bool {
    let unlock = (wrp1ar >> 31) & 1;
    let strt = wrp1ar & 0x7F;
    let end = (wrp1ar >> 16) & 0x7F;
    unlock == 0 && strt == 0 && end >= 3
}

/// Does WRP1A confirm-verifiably write-protect the FSBL pages? **Fail-closed**
/// while the layout is unpinned (`WRP1A_MASK_PINNED == false`): an unpinned
/// guess whose `UNLOCK`/`STRT` sub-fields misread as constant-0 must never
/// vacuously wave a removable-WRP unit through the one check invariant #10
/// hangs on. Once pinned, this is exactly `wrp1a_covers_fsbl_bits`.
#[must_use]
pub const fn wrp1a_covers_fsbl(wrp1ar: u32) -> bool {
    WRP1A_MASK_PINNED && wrp1a_covers_fsbl_bits(wrp1ar)
}

/// Raw "both OEM lock bits clear" compare, independent of the silicon pin.
/// Host-testable in both directions: a SET OEM1/OEM2 bit is always "not clear".
#[must_use]
pub const fn oem_bits_clear(oem_status: u32) -> bool {
    oem_status & (OEM1LOCK | OEM2LOCK) == 0
}

/// Are BOTH OEM key-lock bits confirmed-readably clear (no OEM key provisioned
/// at ship)? **Fail-closed** while the mask register/bits are unpinned
/// (`OEM_LOCK_MASK_PINNED == false`): "cannot confirm absent" MUST halt Phase A,
/// never pass. Once pinned, this is exactly `oem_bits_clear`. A set lock bit is
/// a fail in either pin state — there is no wrong-guess mode that passes a
/// planted OEM key.
#[must_use]
pub const fn oem_locks_absent(oem_status: u32) -> bool {
    OEM_LOCK_MASK_PINNED && oem_bits_clear(oem_status)
}

/// Advisory BOR-level check (BENCH-CONFIRM position). Returns the decoded
/// 3-bit BOR level so the caller can log/compare; not yet a hard gate because
/// the shipped BOR_LEV target is still being pinned (#36).
#[must_use]
pub const fn bor_lev(optr: u32) -> u32 {
    (optr >> BOR_LEV_SHIFT) & BOR_LEV_MASK
}

/// Full ship-profile verification over the raw option-byte register reads.
/// Returns the first failing field, or `Ok(())` if every load-bearing field
/// matches. Ordered most-fundamental-first (TZEN → RDP → windows → boot addr →
/// WRP → OEM locks) so the fault screen names the most basic discrepancy.
///
/// The caller (first-boot Phase A) additionally blank-checks the per-device
/// flash pages 123..=127 — that lives in the hw layer since it reads flash,
/// not option bytes.
#[must_use]
pub const fn verify_ship_profile(
    optr: u32,
    secwm1r1: u32,
    secwm2r1: u32,
    secbootadd0r: u32,
    wrp1ar: u32,
    oem_status: u32,
    p: &ShipProfile,
) -> Result<(), ObField> {
    if let Err(f) = optr_matches_ship(optr, p) {
        return Err(f);
    }
    if !secwm_bank1_all_secure(secwm1r1) {
        return Err(ObField::Secwm1);
    }
    if !secwm_bank2_all_ns(secwm2r1) {
        return Err(ObField::Secwm2);
    }
    if !secboot_selects(secbootadd0r, p.boot_addr) {
        return Err(ObField::SecBootAdd0);
    }
    if !wrp1a_covers_fsbl(wrp1ar) {
        return Err(ObField::Wrp1a);
    }
    if !oem_locks_absent(oem_status) {
        return Err(ObField::OemLock);
    }
    Ok(())
}

/// Verify ONLY the option-byte fields whose register layout is CONFIRMED:
/// `TZEN`, `RDP` (against the caller's phase profile), both secure watermarks,
/// and the secure boot address.
///
/// Deliberately WEAKER than [`verify_ship_profile`], and not a substitute for
/// it. It omits the two pin-gated predicates ([`wrp1a_covers_fsbl`],
/// [`oem_locks_absent`]) which fail CLOSED while [`WRP1A_MASK_PINNED`] /
/// [`OEM_LOCK_MASK_PINNED`] are `false`.
///
/// Why the split exists. First-boot Phase A MUST keep calling
/// `verify_ship_profile`: it gates an irreversible RDP-2 burn, where "cannot
/// confirm WRP is set" must halt. The every-boot FSBL tripwire (tz-1) cannot
/// use that verdict — a fail-closed `WRP1A` arm would halt every genuine board,
/// since bench units carry no WRP at all and no unit has a pinned layout yet —
/// so it checks this confirmed subset instead.
///
/// The limit, stated plainly: a unit whose WRP was cleared before RDP-2 PASSES
/// this subset. Closing [`WRP1A_MASK_PINNED`] (issue #46) is what buys that
/// detection; until then the tripwire covers TZEN / RDP / watermarks / boot
/// address only.
#[must_use]
pub const fn verify_confirmed_fields(
    optr: u32,
    secwm1r1: u32,
    secwm2r1: u32,
    secbootadd0r: u32,
    p: &ShipProfile,
) -> Result<(), ObField> {
    if let Err(f) = optr_matches_ship(optr, p) {
        return Err(f);
    }
    if !secwm_bank1_all_secure(secwm1r1) {
        return Err(ObField::Secwm1);
    }
    if !secwm_bank2_all_ns(secwm2r1) {
        return Err(ObField::Secwm2);
    }
    if !secboot_selects(secbootadd0r, p.boot_addr) {
        return Err(ObField::SecBootAdd0);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A well-formed LOCKED-state OPTR: TZEN set, RDP=0xCC.
    const GOOD_OPTR_LOCKED: u32 = OPTR_TZEN | 0xCC;
    /// The `SECBOOTADD0R` value that selects the FSBL base.
    /// RM0456 7.9.16 ST production value: address field in bits [31:7]
    /// (0x0C00_0000 >> 7 = 0x180000), BOOT_LOCK clear, reserved bits [6:1] set.
    /// The old fixture held the bare shifted value, which no STM32U585 reads.
    const GOOD_SECBOOT: u32 = 0x0C00_007C;
    /// RM0456 7.9.17 ST production value. "Reserved bits are read as 1", which
    /// is why the watermark predicates compare FIELDS, never the whole word.
    const ST_SECWM1_PRODUCTION: u32 = 0xFFFF_FF80;
    /// This board's configured bank-2 value: watermark DISABLED (PSTRT > PEND).
    /// RM0456 7.9.21's production default is 0xFFFF_FF80; we deliberately
    /// program bank 2 the other way, and both must satisfy the predicate.
    const PQ1_SECWM2_CONFIGURED: u32 = 0xFF80_FFFF;

    #[test]
    fn phase_profile_tracks_the_rdp_byte() {
        assert_eq!(phase_profile(GOOD_OPTR).rdp_byte, SHIP_RDP_BYTE);
        assert_eq!(phase_profile(GOOD_OPTR_LOCKED).rdp_byte, LOCKED_RDP_BYTE);
        // Only 0xCC may select the locked profile; every other byte (erased,
        // garbage, 0x55) selects the ship profile so the compare fails closed.
        for b in 0u16..=255 {
            let b = b as u8;
            assert_eq!(
                phase_profile(OPTR_TZEN | u32::from(b)).rdp_byte == LOCKED_RDP_BYTE,
                b == LOCKED_RDP_BYTE,
                "only 0xCC may select the locked profile (byte {b:#04x})"
            );
        }
    }

    #[test]
    fn confirmed_subset_accepts_both_phases_and_rejects_cross_phase() {
        assert_eq!(
            verify_confirmed_fields(
                GOOD_OPTR,
                SECWM1_ALL_SECURE,
                SECWM2_ALL_NS,
                GOOD_SECBOOT,
                &SHIP_PROFILE_U585
            ),
            Ok(())
        );
        assert_eq!(
            verify_confirmed_fields(
                GOOD_OPTR_LOCKED,
                SECWM1_ALL_SECURE,
                SECWM2_ALL_NS,
                GOOD_SECBOOT,
                &LOCKED_PROFILE_U585
            ),
            Ok(())
        );
        // Cross-phase mismatches must be caught in BOTH directions.
        assert_eq!(
            verify_confirmed_fields(
                GOOD_OPTR,
                SECWM1_ALL_SECURE,
                SECWM2_ALL_NS,
                GOOD_SECBOOT,
                &LOCKED_PROFILE_U585
            ),
            Err(ObField::Rdp)
        );
        assert_eq!(
            verify_confirmed_fields(
                GOOD_OPTR_LOCKED,
                SECWM1_ALL_SECURE,
                SECWM2_ALL_NS,
                GOOD_SECBOOT,
                &SHIP_PROFILE_U585
            ),
            Err(ObField::Rdp)
        );
    }

    #[test]
    fn confirmed_subset_rejects_each_confirmed_field() {
        let chk = |optr, w1, w2, sb| verify_confirmed_fields(optr, w1, w2, sb, &SHIP_PROFILE_U585);
        assert_eq!(
            chk(
                GOOD_OPTR & !OPTR_TZEN,
                SECWM1_ALL_SECURE,
                SECWM2_ALL_NS,
                GOOD_SECBOOT
            ),
            Err(ObField::Tzen)
        );
        assert_eq!(
            chk(GOOD_OPTR, 0, SECWM2_ALL_NS, GOOD_SECBOOT),
            Err(ObField::Secwm1)
        );
        assert_eq!(
            chk(GOOD_OPTR, SECWM1_ALL_SECURE, 0, GOOD_SECBOOT),
            Err(ObField::Secwm2)
        );
        assert_eq!(
            chk(GOOD_OPTR, SECWM1_ALL_SECURE, SECWM2_ALL_NS, 0),
            Err(ObField::SecBootAdd0)
        );
    }

    /// The load-bearing DIFFERENCE between the two comparators, pinned in both
    /// directions so neither can drift into the other: the confirmed subset
    /// ignores WRP1A / OEM locks by design, while the full ship-profile check
    /// still fails closed on them today.
    #[test]
    fn confirmed_subset_ignores_unpinned_fields_but_full_check_does_not() {
        assert_eq!(
            verify_confirmed_fields(
                GOOD_OPTR,
                SECWM1_ALL_SECURE,
                SECWM2_ALL_NS,
                GOOD_SECBOOT,
                &SHIP_PROFILE_U585
            ),
            Ok(()),
            "the subset must not depend on WRP1A / OEM state"
        );
        assert_eq!(
            verify_ship_profile(
                GOOD_OPTR,
                SECWM1_ALL_SECURE,
                SECWM2_ALL_NS,
                GOOD_SECBOOT,
                GOOD_WRP1A,
                0,
                &SHIP_PROFILE_U585
            ),
            Err(ObField::Wrp1a),
            "full check fails closed while WRP1A_MASK_PINNED is false"
        );
        // The CONSTANT is the thing under test: tz-1's reduced scope is only
        // justified while the WRP1A layout is unpinned, so this trips the day
        // the pin flips. clippy flags asserting on a constant; that is the point.
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(
                !WRP1A_MASK_PINNED,
                "WRP1A_MASK_PINNED flipped — revisit tz-1's scope and this control"
            );
        }
    }

    /// Legacy bench FSBL base; the target shipping entry remains gated by the
    /// production geometry, WRP/option-byte ceremony, and silicon receipts.
    const FSBL_BASE: u32 = 0x0C00_0000;

    #[test]
    fn rdp_decode_only_cc_is_level2() {
        assert_eq!(rdp_level_from_byte(0xAA), RdpLevel::L0);
        assert_eq!(rdp_level_from_byte(0xCC), RdpLevel::L2);
        assert_eq!(rdp_level_from_byte(0x55), RdpLevel::L0_5);
        assert_eq!(rdp_level_from_byte(0x00), RdpLevel::L1);
        assert_eq!(rdp_level_from_byte(0xFF), RdpLevel::L1);
        // SL1 (reversible-state-mistaken-for-locked): ONLY 0xCC may decode as
        // Level 2. No erased/garbage byte may read as RDP2, or the boot check
        // would pass on an unlocked part.
        for b in 0u16..=255 {
            let b = b as u8;
            assert_eq!(
                rdp_level_from_byte(b) == RdpLevel::L2,
                b == 0xCC,
                "only 0xCC may decode as RDP2 (byte {b:#04x})"
            );
        }
    }

    #[test]
    fn secboot_selects_fsbl_base_and_tolerates_control_bits() {
        // RM0456 7.9.16 ST production value, and what this board actually
        // reads: address field in bits [31:7], BOOT_LOCK at bit 0.
        const ST_PRODUCTION: u32 = 0x0C00_007C;
        assert!(
            secboot_selects(ST_PRODUCTION, FSBL_BASE),
            "the ST production value must select the FSBL base (regression: low-mask compare)"
        );
        // BOOT_LOCK set must NOT read as a wrong address.
        assert!(
            secboot_selects(FSBL_BASE | SECBOOTADD0_BOOT_LOCK, FSBL_BASE),
            "BOOT_LOCK tolerated"
        );
        // Reserved bits [6:1] likewise.
        assert!(secboot_selects(FSBL_BASE | 0x7E, FSBL_BASE), "reserved bits tolerated");
        // The OLD encoding must now FAIL — it addressed 0x0018_0000 << 7.
        assert!(
            !secboot_selects(0x0018_0000, FSBL_BASE),
            "the bare shifted value is NOT a valid SECBOOTADD0R word"
        );
        // A redirected / erased / off-by-one boot address must FAIL (the SL2
        // boot-redirect signal).
        assert!(!secboot_selects(0x0000_0000, FSBL_BASE), "erased/zero must fail");
        assert!(!secboot_selects(0x0018_0001, FSBL_BASE), "off-by-one addr must fail");
        assert!(!secboot_selects(0x0C08_0000 >> 7, FSBL_BASE), "redirected addr must fail");
        // A control bit WITHIN the address field must still fail (it changes the
        // address) — proves the mask is [24:0], not wider.
        assert!(!secboot_selects(0x0018_0000 | (1 << 24), FSBL_BASE), "addr-field bit changes address");
    }

    // --- Ship option-byte profile (work-todo #36) ---------------------------

    /// A well-formed ship-state OPTR: TZEN set, RDP=0xAA, plausible BOR field.
    const GOOD_OPTR: u32 = OPTR_TZEN | (0x3 << BOR_LEV_SHIFT) | (SHIP_RDP_BYTE as u32);
    /// WRP1A locking pages 0..=3: UNLOCK=0, STRT=0, END=3.
    const GOOD_WRP1A: u32 = (3 << 16) | 0;

    #[test]
    fn optr_ship_requires_tzen_and_rdp0() {
        assert_eq!(optr_matches_ship(GOOD_OPTR, &SHIP_PROFILE_U585), Ok(()));
        // TZEN clear → Tzen fault.
        assert_eq!(
            optr_matches_ship(GOOD_OPTR & !OPTR_TZEN, &SHIP_PROFILE_U585),
            Err(ObField::Tzen)
        );
        // RDP already 0xCC (Level 2) at "ship" → not a fresh RDP-0 unit.
        let optr_l2 = (GOOD_OPTR & !0xFF) | 0xCC;
        assert_eq!(optr_matches_ship(optr_l2, &SHIP_PROFILE_U585), Err(ObField::Rdp));
        // RDP Level 1 (garbage byte) → Rdp fault (only 0xAA passes at ship).
        let optr_l1 = (GOOD_OPTR & !0xFF) | 0x11;
        assert_eq!(optr_matches_ship(optr_l1, &SHIP_PROFILE_U585), Err(ObField::Rdp));
    }

    /// The guard whose absence let three separate places write option-byte
    /// command bits to the wrong FLASH register (see the block comment above
    /// `FLASH_NSSR_OFF`). Enumerated from the vendor SVD 2026-09-16 by listing
    /// EVERY field of each register — probing for expected names is what hid
    /// this, since the SVD prefixes them (`FLASH_SECCR`, not `SECCR`).
    #[test]
    fn optbyte_command_bits_live_only_in_nscr() {
        // Offsets, straight from the SVD's addressOffset fields.
        assert_eq!(FLASH_NSSR_OFF, 0x20, "FLASH_NSSR");
        assert_eq!(FLASH_SECSR_OFF, 0x24, "FLASH_SECSR");
        assert_eq!(FLASH_NSCR_OFF, 0x28, "FLASH_NSCR");
        assert_eq!(FLASH_SECCR_OFF, 0x2C, "FLASH_SECCR");
        // Command bit positions.
        assert_eq!(FLASH_OPTSTRT, 1 << 17, "OPTSTRT is NSCR bit 17");
        assert_eq!(FLASH_OBL_LAUNCH, 1 << 27, "OBL_LAUNCH is NSCR bit 27");
        assert_eq!(FLASH_OPTLOCK, 1 << 30, "OPTLOCK is NSCR bit 30");
        assert_eq!(FLASH_SR_BSY, 1 << 16, "BSY is bit 16 of both status regs");

        // Exactly ONE register may receive an option-byte command. The
        // control/status registers are adjacent (0x20/0x24/0x28/0x2C), which
        // is why an off-by-one-register bug is easy to write and invisible.
        assert!(is_optbyte_command_register(FLASH_NSCR_OFF));
        for off in [
            FLASH_NSSR_OFF,
            FLASH_SECSR_OFF,
            FLASH_SECCR_OFF,
            0x0C, // SECKEYR
            0x10, // OPTKEYR
            0x40, // OPTR
            0x4C, // SECBOOTADD0R
        ] {
            assert!(
                !is_optbyte_command_register(off),
                "only FLASH_NSCR (0x28) owns the option-byte command bits; \
                 offset {off:#04X} must not qualify"
            );
        }

        // Two-sided. SECCR silently ignores each command bit — no commit, no
        // error — which is exactly why the #268 defect reports success.
        assert!(!seccr_accepts(FLASH_OPTSTRT), "SECCR has no bit 17");
        assert!(!seccr_accepts(FLASH_OBL_LAUNCH), "SECCR has no bit 27");
        assert!(!seccr_accepts(FLASH_OPTLOCK), "SECCR has no bit 30");
        assert!(
            !seccr_accepts(FLASH_OPTSTRT | (1 << 16)),
            "a write mixing STRT with OPTSTRT is still not acceptable to SECCR"
        );
        // ...but it does implement STRT (16) and LOCK (31), so those pass.
        assert!(seccr_accepts(1 << 16), "SECCR implements STRT");
        assert!(seccr_accepts(1 << 31), "SECCR implements LOCK");
        assert!(seccr_accepts(0), "a no-op write is trivially acceptable");
    }

    #[test]
    fn secwm_window_exact_match() {
        // MEASURED silicon values are the positive case. The old test only ever
        // fed in the idealised constants, so it stayed green while the
        // predicate could not match any real board (reserved bits read as 1s).
        const PQ1_SECWM1_RAW: u32 = 0xFFFF_FF80; // PSTRT=0,    PEND=0x7F
        const PQ1_SECWM2_RAW: u32 = 0xFF80_FFFF; // PSTRT=0x7F, PEND=0
        assert_eq!(secwm_fields(PQ1_SECWM1_RAW), (0, 0x7F));
        assert_eq!(secwm_fields(PQ1_SECWM2_RAW), (0x7F, 0));
        assert!(
            secwm_bank1_all_secure(PQ1_SECWM1_RAW),
            "a correctly configured board must PASS (regression: word compare)"
        );
        assert!(
            secwm_bank2_all_ns(PQ1_SECWM2_RAW),
            "watermark-disabled bank 2 must PASS (regression: word compare)"
        );
        // The written field values must also pass, so whatever programs the
        // watermarks and this reader cannot disagree.
        assert!(secwm_bank1_all_secure(SECWM1_ALL_SECURE));
        assert!(secwm_bank2_all_ns(SECWM2_ALL_NS));
        // RM0456 production values (7.9.17 / 7.9.21) must pass too.
        assert!(
            secwm_bank1_all_secure(ST_SECWM1_PRODUCTION),
            "RM0456 7.9.17 ST production value must pass"
        );
        assert!(
            secwm_bank2_all_ns(PQ1_SECWM2_CONFIGURED),
            "watermark-disabled bank 2 as configured on pq1 must pass"
        );
        // Two-sided: genuinely wrong spans must still FAIL.
        assert!(
            !secwm_bank1_all_secure(0xFFFF_FF81),
            "PSTRT=1 leaves page 0 non-secure"
        );
        assert!(
            !secwm_bank1_all_secure(0xFFFE_FF80),
            "PEND=0x7E leaves the last page non-secure"
        );
        assert!(
            !secwm_bank2_all_ns(0x007F_0000),
            "PSTRT=0 <= PEND=0x7F would mark bank 2 SECURE"
        );
    }

    #[test]
    fn wrp1a_must_lock_and_span_fsbl() {
        // Raw bit compare is pin-independent.
        assert!(wrp1a_covers_fsbl_bits(GOOD_WRP1A), "STRT=0 END=3 UNLOCK=0 covers pages 0..=3");
        assert!(wrp1a_covers_fsbl_bits((7 << 16) | 0), "wider span still covers 0..=3");
        // UNLOCK=1 (bit31 set) → write-protect removable → NOT covered.
        assert!(!wrp1a_covers_fsbl_bits(GOOD_WRP1A | (1 << 31)), "UNLOCK=1 fails");
        // Span starting at page 1 leaves FSBL page 0 unprotected.
        assert!(!wrp1a_covers_fsbl_bits((3 << 16) | 1), "STRT=1 leaves page 0 open");
        // Span ending at page 2 leaves page 3 unprotected.
        assert!(!wrp1a_covers_fsbl_bits((2 << 16) | 0), "END=2 leaves page 3 open");
        // The load-bearing gate is fail-closed until pinned: even a good WRP1A
        // only PASSES once the layout is silicon-pinned (invariant #10).
        assert_eq!(wrp1a_covers_fsbl(GOOD_WRP1A), WRP1A_MASK_PINNED, "good WRP passes iff pinned");
        // A removable WRP fails regardless of the pin (never a false pass).
        assert!(!wrp1a_covers_fsbl(GOOD_WRP1A | (1 << 31)), "UNLOCK=1 fails (pin-independent)");
    }

    #[test]
    fn oem_locks_must_be_absent_at_ship() {
        // Raw bit compare is pin-independent: a set OEM lock bit is never clear.
        assert!(oem_bits_clear(0), "no OEM key → bits clear");
        assert!(!oem_bits_clear(OEM1LOCK), "OEM1 provisioned → bits not clear");
        assert!(!oem_bits_clear(OEM2LOCK), "OEM2 provisioned → bits not clear");
        assert!(!oem_bits_clear(OEM1LOCK | OEM2LOCK), "both → bits not clear");
        assert!(oem_bits_clear(1 << 3), "unrelated bit ignored");
        // The load-bearing gate is fail-closed until the mask is pinned: even
        // the all-clear reading only PASSES once pinned.
        assert_eq!(oem_locks_absent(0), OEM_LOCK_MASK_PINNED, "all-clear passes iff pinned");
        // A set lock bit fails regardless of the pin (never a false pass).
        assert!(!oem_locks_absent(OEM1LOCK), "OEM1 provisioned → fail (pin-independent)");
        assert!(!oem_locks_absent(OEM2LOCK), "OEM2 provisioned → fail (pin-independent)");
        assert!(!oem_locks_absent(OEM1LOCK | OEM2LOCK), "both → fail");
    }

    #[test]
    fn verify_ship_profile_orders_and_passes_good_state() {
        // With every load-bearing field good, the remaining gates are the
        // fail-closed WRP1A and OEM checks (in that order): the good state
        // passes only once BOTH masks are silicon-pinned; while unpinned the
        // first fail-closed gate (WRP1A) is the reported field.
        assert_eq!(
            verify_ship_profile(
                GOOD_OPTR, SECWM1_ALL_SECURE, SECWM2_ALL_NS,
                GOOD_SECBOOT, GOOD_WRP1A, 0, &SHIP_PROFILE_U585,
            ),
            if !WRP1A_MASK_PINNED {
                Err(ObField::Wrp1a)
            } else if !OEM_LOCK_MASK_PINNED {
                Err(ObField::OemLock)
            } else {
                Ok(())
            },
        );
        // Each corruption surfaces its own field, in fundamental-first order.
        assert_eq!(
            verify_ship_profile(GOOD_OPTR & !OPTR_TZEN, SECWM1_ALL_SECURE, SECWM2_ALL_NS, GOOD_SECBOOT, GOOD_WRP1A, 0, &SHIP_PROFILE_U585),
            Err(ObField::Tzen)
        );
        assert_eq!(
            verify_ship_profile(GOOD_OPTR, 0, SECWM2_ALL_NS, GOOD_SECBOOT, GOOD_WRP1A, 0, &SHIP_PROFILE_U585),
            Err(ObField::Secwm1)
        );
        assert_eq!(
            verify_ship_profile(GOOD_OPTR, SECWM1_ALL_SECURE, 0, GOOD_SECBOOT, GOOD_WRP1A, 0, &SHIP_PROFILE_U585),
            Err(ObField::Secwm2)
        );
        assert_eq!(
            verify_ship_profile(GOOD_OPTR, SECWM1_ALL_SECURE, SECWM2_ALL_NS, 0, GOOD_WRP1A, 0, &SHIP_PROFILE_U585),
            Err(ObField::SecBootAdd0)
        );
        // A removable WRP (UNLOCK=1) fails the WRP1A gate regardless of the pin.
        assert_eq!(
            verify_ship_profile(GOOD_OPTR, SECWM1_ALL_SECURE, SECWM2_ALL_NS, GOOD_SECBOOT, GOOD_WRP1A | (1 << 31), 0, &SHIP_PROFILE_U585),
            Err(ObField::Wrp1a)
        );
        // An OEM key present reaches the OEM gate only once WRP1A is pinned;
        // while WRP1A is unpinned the fail-closed WRP1A gate reports first.
        assert_eq!(
            verify_ship_profile(GOOD_OPTR, SECWM1_ALL_SECURE, SECWM2_ALL_NS, GOOD_SECBOOT, GOOD_WRP1A, OEM2LOCK, &SHIP_PROFILE_U585),
            if WRP1A_MASK_PINNED { Err(ObField::OemLock) } else { Err(ObField::Wrp1a) },
        );
    }
}
