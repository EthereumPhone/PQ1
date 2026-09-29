//! Non-destructive address probe for the secure-element I2C buses.
//!
//! Answers one question and nothing else: **does the chip that should be at
//! this address on this bus acknowledge its address?**
//!
//! ## The contract, which must not grow
//!
//! Every probe is a zero-data-byte transfer: `START → address → ACK/NACK →
//! STOP`, with `NBYTES = 0` and `AUTOEND = 1`. Not one byte of payload
//! reaches either part. That matters because on a production board the
//! OPTIGA is **virgin**, and its pairing / lifecycle transitions are
//! irreversible — a probe that "just sends one byte to see what happens" is
//! not a probe, it is a provisioning step with a hopeful name.
//!
//! Concretely, what each part sees:
//!
//! - **OPTIGA Trust M** — a bus-level ACK from the IFX I2C layer. No
//!   register pointer is set, no APDU is framed, no lifecycle state moves.
//! - **SE050** — a START/ADDR/STOP with no T=1' frame, which its transport
//!   layer discards. No session, no SCP03, no NVM write.
//!
//! **Do not add a handshake step to this module.** If you want a handshake,
//! `flash-hw-optiga-shield-handshake-only` already exists — and it is *not*
//! non-destructive on a virgin part. The entire value of this file is that
//! it is safe to run on hardware you cannot replace.
//!
//! ## Why the zero-byte form, and not the usual scanner
//!
//! `hw::i2c2_probe` (the dev-board STSAFE scanner) writes a dummy `0x00` to
//! `TXDR` on ACK so `AUTOEND` has a byte to finish. That is fine against a
//! part you are willing to lose; it is not fine here. RM0456's controller-
//! transmit section gives the escape: with `RELOAD = 0`, once the `NBYTES`
//! bytes are transferred `AUTOEND = 1` sends STOP on its own — and `NBYTES`
//! may be zero, so the address phase *is* the whole transfer. On a NACK the
//! reference manual is explicit that "the TXIS flag is not set and a STOP
//! condition is automatically sent", with `NACKF` set. So both outcomes end
//! in `STOPF`, and `NACKF` is what discriminates them. This module waits for
//! `STOPF` and then reads `NACKF`, which is deterministic either way.
//!
//! ## Reading the output
//!
//! The point is to separate failure modes, so the report is the whole chain
//! rather than a verdict. On `pq1` in particular:
//!
//! | Symptom | Most likely cause |
//! |---|---|
//! | Both addresses NACK | The `VDD1_3V3` rail never rose — check `LDO2_EN` (PA8) and meter the rail |
//! | Only `0x48` (SE050) NACKs | `SE1_EN` (PB5), or probed before the part finished booting |
//! | Only `0x30` (OPTIGA) NACKs | I2C1 pin/AF configuration, or `SE_RST` |
//! | An address ACKs on a later attempt | The part is fine; the settle time is too short |
//!
//! The per-bus line also reports the **read-back** `AFRL`/`AFRH` nibbles, so
//! a wrong alternate function is visible directly. On `pq1` that is the one
//! that matters most: PB6/PB7 are I2C4 under AF5 and **I2C1 under AF4**, so
//! an AF4 typo silently attaches the SE050's pins to the OPTIGA bus, giving
//! a bus that looks alive and answers for the wrong chip. The build-time
//! gate catches that; this is the run-time confirmation of it.
//!
//! ## Timing caveat — UNVERIFIED
//!
//! `ENABLE_SETTLE_MS` in `hw::se_power` is not derived from a datasheet
//! figure for "SE050 `ENA` asserted → ready to ACK": that number is in the
//! SE050 product data sheet, which is not in this repo. AN12413 (the APDU
//! spec) does not carry it, and the only related figure the tree records is
//! `se050/t1oi2c.rs`'s "up to 5 ms for interface reset" — a *floor*, not the
//! cold-boot time. This module therefore retries with a bounded backoff and
//! **reports the attempt on which the address answered**, because "ACKed on
//! attempt 3" and "never ACKed" are completely different diagnoses and a
//! single-shot probe cannot tell them apart.

#![cfg(all(
    feature = "stm32u585",
    any(feature = "se050", feature = "optiga-trust-m")
))]

use crate::board;
use crate::hw::i2c_hw::I2cRegs;
use crate::hw::mmio::Reg32;
// `secure_log!` is a textually-scoped `macro_rules!` defined at the top of
// `main.rs`, not `#[macro_export]`ed — it is in scope for every module
// declared after it and must NOT be imported (a `use crate::secure_log`
// makes the name ambiguous and breaks the macro's own definition site).

/// Attempts per address before declaring it absent.
///
/// Ten attempts at `RETRY_GAP_MS` covers roughly an order of magnitude more
/// than the 5 ms interface-reset figure the tree records, which is the
/// closest documented analogue to an SE050 cold boot. Cheap: this runs once,
/// on a bring-up build only.
const PROBE_ATTEMPTS: u32 = 10;

/// Gap between attempts, milliseconds.
const RETRY_GAP_MS: u32 = 5;

/// Spin budget for a single flag wait. At 400 kHz an address phase is under
/// 30 µs, so this is a hang-guard, not a timing parameter.
const FLAG_SPIN: u32 = 1_000_000;

// I2C_ISR / I2C_ICR bits (RM0456).
const ISR_BUSY: u32 = 1 << 15;
const ISR_NACKF: u32 = 1 << 4;
const ISR_STOPF: u32 = 1 << 5;
const ISR_BERR: u32 = 1 << 8;
const ISR_ARLO: u32 = 1 << 9;
const ICR_NACKCF: u32 = 1 << 4;
const ICR_STOPCF: u32 = 1 << 5;
const ICR_BERRCF: u32 = 1 << 8;
const ICR_ARLOCF: u32 = 1 << 9;

// I2C_CR2 bits.
const CR2_START: u32 = 1 << 13;
const CR2_AUTOEND: u32 = 1 << 25;

/// Outcome of probing one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    /// The address was acknowledged, on this attempt (1-based).
    Ack { attempt: u32 },
    /// Every attempt was answered with NACK — nothing at that address.
    Nack,
    /// The peripheral never reached a terminal state. Distinct from `Nack`:
    /// a NACK means the bus worked and nobody answered, a timeout means the
    /// bus itself did not complete a transfer (unclocked peripheral, SCL
    /// held low, no pull-ups).
    Timeout,
    /// The transfer aborted on a bus error or lost arbitration.
    BusError,
}

fn delay_ms(ms: u32) {
    cortex_m::asm::delay(160_000 * ms);
}

/// One zero-data-byte address probe.
///
/// Returns `Ok(true)` on ACK, `Ok(false)` on NACK, `Err(Probe)` for a
/// non-answer (timeout / bus error) that should not be retried as if the
/// address were simply empty.
fn probe_once(regs: &I2cRegs, addr: u8) -> Result<bool, Probe> {
    // Wait for the bus to be idle before driving a START.
    let mut spin = FLAG_SPIN;
    while regs.isr.read() & ISR_BUSY != 0 {
        spin -= 1;
        if spin == 0 {
            return Err(Probe::Timeout);
        }
    }

    // Clear stale flags so this transfer's result is unambiguous.
    regs.icr.write(ICR_NACKCF | ICR_STOPCF | ICR_BERRCF | ICR_ARLOCF);

    // START + 7-bit address, write direction, **NBYTES = 0**, AUTOEND.
    // NBYTES is CR2[23:16] and is deliberately left zero: the address phase
    // is the entire transfer, so no payload byte can reach the chip.
    let cr2 = (u32::from(addr) << 1) | CR2_START | CR2_AUTOEND;
    regs.cr2.write(cr2);

    // Both ACK and NACK end in STOPF (see the module header), so wait for
    // that single terminal flag rather than racing TXIS against NACKF.
    spin = FLAG_SPIN;
    loop {
        let isr = regs.isr.read();
        if isr & (ISR_BERR | ISR_ARLO) != 0 {
            regs.icr.write(ICR_BERRCF | ICR_ARLOCF | ICR_STOPCF | ICR_NACKCF);
            return Err(Probe::BusError);
        }
        if isr & ISR_STOPF != 0 {
            let nacked = isr & ISR_NACKF != 0;
            regs.icr.write(ICR_STOPCF | ICR_NACKCF);
            return Ok(!nacked);
        }
        spin -= 1;
        if spin == 0 {
            // Leave the peripheral clean for the next address.
            regs.icr.write(ICR_STOPCF | ICR_NACKCF | ICR_BERRCF | ICR_ARLOCF);
            return Err(Probe::Timeout);
        }
    }
}

/// Probe one address, retrying so a slow-booting part is distinguishable
/// from an absent one.
fn probe_addr(regs: &I2cRegs, addr: u8) -> Probe {
    let mut last_err = Probe::Nack;
    for attempt in 1..=PROBE_ATTEMPTS {
        match probe_once(regs, addr) {
            Ok(true) => return Probe::Ack { attempt },
            Ok(false) => last_err = Probe::Nack,
            Err(e) => last_err = e,
        }
        if attempt < PROBE_ATTEMPTS {
            delay_ms(RETRY_GAP_MS);
        }
    }
    last_err
}

/// Read back the alternate-function nibble actually programmed for `pin`.
///
/// This is the check that separates "configured right, nobody answered"
/// from "configured wrong" — the latter being the failure that otherwise
/// presents as a working bus answering for the wrong chip.
fn read_af(port: u32, pin: u32) -> u32 {
    let off = if pin < 8 { 0x20 } else { 0x24 };
    // SAFETY: `port` is a GPIO base from `crate::board`; `+0x20`/`+0x24` are
    // its AFRL/AFRH registers. Read-only.
    let afr = unsafe { Reg32::new(port + off) };
    (afr.read() >> ((pin % 8) * 4)) & 0xF
}

/// Probe every secure-element bus this board declares.
///
/// Returns `true` when every expected address acknowledged. Logs the full
/// chain either way — the log is the deliverable, not the boolean.
///
/// Must run after `hw::se_power::init()` and `hw::i2c_hw::init()`.
pub fn run() -> bool {
    secure_log!(
        "[S][se-probe] board={} buses={}",
        board::BOARD_NAME,
        board::SE_I2C_BUSES.len()
    );

    let mut all_ok = true;

    for bus in board::SE_I2C_BUSES {
        let scl_af = read_af(bus.port, bus.scl_pin);
        let sda_af = read_af(bus.port, bus.sda_pin);
        let af_ok = scl_af == bus.af && sda_af == bus.af;

        secure_log!(
            "[S][se-probe] bus {} base=0x{:08x} SCL=P{}{} SDA=P{}{} AF want={} got=({},{}) {}",
            bus.name,
            bus.base,
            if bus.port == board::GPIOA_S { "A" } else { "B" },
            bus.scl_pin,
            if bus.port == board::GPIOA_S { "A" } else { "B" },
            bus.sda_pin,
            bus.af,
            scl_af,
            sda_af,
            if af_ok { "OK" } else { "MISMATCH" }
        );
        if !af_ok {
            all_ok = false;
        }

        // SAFETY: `bus.base` is a real I2C peripheral base from the board
        // map, already brought up by `hw::i2c_hw::init`.
        let regs = unsafe { I2cRegs::new(bus.base) };

        for &(addr, label) in bus.probe_addrs {
            let result = probe_addr(&regs, addr);
            // NOTE: every `secure_log!` below is a STATEMENT (braced arm,
            // trailing semicolon). The macro expands to `#[cfg] { .. }`
            // blocks, and an attribute on a block is only legal in statement
            // position — using it as a match-arm or block-tail EXPRESSION
            // fails with "attributes on expressions are experimental".
            match result {
                Probe::Ack { attempt } => {
                    secure_log!(
                        "[S][se-probe]   0x{:02x} {} -> ACK (attempt {}/{})",
                        addr,
                        label,
                        attempt,
                        PROBE_ATTEMPTS
                    );
                }
                _ => {
                    all_ok = false;
                    secure_log!(
                        "[S][se-probe]   0x{:02x} {} -> {:?} after {} attempts",
                        addr,
                        label,
                        result,
                        PROBE_ATTEMPTS
                    );
                }
            }
        }
    }

    if all_ok {
        secure_log!("[S][se-probe] === PASS === every expected address acknowledged");
    } else {
        secure_log!(
            "[S][se-probe] === FAIL === see the table in hw/se_i2c_probe.rs for which \
             failure pattern means what; if BOTH addresses NACK on pq1, meter VDD1_3V3"
        );
    }
    all_ok

}
