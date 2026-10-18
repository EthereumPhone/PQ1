//! Read-only "deep" conformance steps (feature `optiga-probe`, switched on at
//! build time with `OPTIGA_PROBE_DEEP=1`). These extend the R0–R9 read-only
//! probe with the two checks DVT rows 6A.2 and 6A.7 ask for and that can be
//! met *without* sending an arbitrary APDU:
//!
//! - **R10 (6A.2):** map the IFX I2C register space — read the documented
//!   registers and probe the rest for an ACK.
//! - **R12 (6A.7):** draw `GetRandom` across the soft-reset and power-cycle
//!   boundaries and in bulk, checking the stream never repeats, shares a
//!   prefix, or sticks.
//!
//! **Not here:** the undocumented-command / Param sweep (6A.3 / 6A.4). That
//! step inherently sends raw command opcodes, which means the general-purpose
//! `transceive` path the read-only write-path invariant deliberately forbids
//! in this module (`source_invariants::optiga_probe_readonly_names_no_write_path`).
//! It belongs in a separately fenced, human-supervised probe, not this
//! unsupervised read-only build.
//!
//! **Contract — identical to `readonly.rs`.** Only register *reads*
//! (`probe_read_register`), `GetRandom` (`get_random_plain_probe` — a read
//! command that cannot write), `OpenApplication`, the IFX soft reset and the
//! chip power-cycle reach the chip. No write/key-generation command, and no
//! raw-APDU send, is built or sent.

use super::super::apdu;
use super::{hex, Probe};

/// `OPTIGA_PROBE_DEEP=1` at build time runs R10 + R12 after R9.
pub(super) fn deep_enabled() -> bool {
    matches!(option_env!("OPTIGA_PROBE_DEEP"), Some("1"))
}

fn all_same(b: &[u8]) -> bool {
    !b.is_empty() && b.iter().all(|&x| x == b[0])
}

/// R10 — IFX I2C register map (DVT 6A.2).
unsafe fn r10_registers(p: &mut Probe) {
    out!("STEP R10 regmap");
    // Documented registers and widths (ifx-i2c-protocol.md §Register Map).
    // 0x88 (SOFT_RESET) is write-only — never read it.
    const DOCUMENTED: &[(u8, usize, &str)] = &[
        (0x80, 4, "DATA"),
        (0x81, 2, "DATA_REG_LEN"),
        (0x82, 4, "I2C_STATE"),
        (0x84, 4, "MAX_SCL_FREQU"),
        (0x85, 4, "GUARD_TIME"),
        (0x86, 4, "TRANS_TIMEOUT"),
        (0x87, 4, "PWR_SAVE_TIMEOUT"),
        (0x89, 2, "I2C_MODE"),
    ];
    let mut h = [0u8; 8];
    for &(reg, len, name) in DOCUMENTED {
        let mut buf = [0u8; 4];
        match unsafe { p.dev.ifx.probe_read_register(reg, &mut buf[..len]) } {
            Ok(()) => out!("REG reg={:02x} name={} res=ok val={}", reg, name, hex(&buf[..len], &mut h)),
            Err(e) => out!("REG reg={:02x} name={} res=err {:?}", reg, name, e),
        }
    }
    // Probe the rest by CONTENT, not ACK. On IFX I2C the ACK is at the
    // device-address level (0x30), so every sub-address "answers" a read —
    // an ACK proves nothing. An *unimplemented* register reads back all-0xFF.
    // So flag only a non-documented address that returns something other than
    // 0xFFFFFFFF: that would be a real hidden register with content. 0x88
    // (write-only SOFT_RESET) is excluded.
    let mut content = 0u32;
    for reg in 0x00u8..=0xFFu8 {
        if (0x80..=0x9F).contains(&reg) || reg == 0x88 {
            continue;
        }
        let mut b = [0u8; 4];
        if unsafe { p.dev.ifx.probe_read_register(reg, &mut b) }.is_ok() && b != [0xFF; 4] {
            content += 1;
            out!("REG reg={:02x} name=? res=ok val={}", reg, hex(&b, &mut h));
            p.finding("REG_UNDOCUMENTED", format_args!("register {:02x} returned content {}", reg, hex(&b, &mut h)));
        }
    }
    // 0x90..=0x9F APP_STATE are documented read registers; log, don't flag.
    for reg in 0x90u8..=0x9Fu8 {
        let mut b = [0u8; 4];
        if let Ok(()) = unsafe { p.dev.ifx.probe_read_register(reg, &mut b) } {
            out!("REG reg={:02x} name=APP_STATE res=ok val={}", reg, hex(&b, &mut h));
        }
    }
    out!("R10 done undocumented_content={}", content);
    let _ = unsafe { p.cold_restart("R10-end") };
}

/// Draw `out.len()` plaintext random bytes through the typed read-only
/// helper. Returns true on an exact-length success.
unsafe fn plain_random(p: &mut Probe, out: &mut [u8]) -> bool {
    matches!(unsafe { apdu::get_random_plain_probe(&mut p.dev.ifx, out) }, Ok(n) if n == out.len())
}

/// R12 — TRNG freshness across resets and in bulk (DVT 6A.7).
unsafe fn r12_random(p: &mut Probe) {
    out!("STEP R12 random");
    let mut h = [0u8; 16];
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    let mut c = [0u8; 32];

    let oka = unsafe { plain_random(p, &mut a) };
    out!("RAND draw=A reset=none ok={} prefix={}", oka as u8, hex(&a[..8], &mut h));

    let _ = unsafe { p.dev.ifx.soft_reset() };
    let _ = unsafe { apdu::open_application(&mut p.dev.ifx) };
    let okb = unsafe { plain_random(p, &mut b) };
    out!("RAND draw=B reset=soft ok={} prefix={}", okb as u8, hex(&b[..8], &mut h));

    let _ = unsafe { p.cold_restart("R12-power") };
    let okc = unsafe { plain_random(p, &mut c) };
    out!("RAND draw=C reset=power ok={} prefix={}", okc as u8, hex(&c[..8], &mut h));

    if oka && okb && okc {
        if a == b || b == c || a == c {
            p.finding("RAND_REPEAT_ACROSS_RESET", format_args!("two post-reset draws equal"));
        }
        if a[..8] == b[..8] || b[..8] == c[..8] || a[..8] == c[..8] {
            p.finding("RAND_PREFIX_SHARE", format_args!("two draws share an 8-byte prefix"));
        }
        for (name, blk) in [("A", &a), ("B", &b), ("C", &c)] {
            if all_same(blk) {
                p.finding("RAND_STUCK", format_args!("draw {} is a constant byte", name));
            }
        }
    } else {
        out!("R12 note: a plaintext draw failed (ok A={} B={} C={})", oka as u8, okb as u8, okc as u8);
    }

    // Bulk: 64 × 32-byte blocks, checking for a repeated or constant block.
    let mut prev = [0u8; 32];
    let mut have_prev = false;
    let (mut blocks, mut repeats, mut stuck) = (0u32, 0u32, 0u32);
    for _ in 0..64u32 {
        let mut blk = [0u8; 32];
        if !unsafe { plain_random(p, &mut blk) } {
            break;
        }
        blocks += 1;
        if all_same(&blk) {
            stuck += 1;
        }
        if have_prev && blk == prev {
            repeats += 1;
        }
        prev = blk;
        have_prev = true;
    }
    out!("RAND bulk blocks={} repeats={} stuck={}", blocks, repeats, stuck);
    if repeats > 0 {
        p.finding("RAND_BULK_REPEAT", format_args!("{} repeated 32B blocks", repeats));
    }
    if stuck > 0 {
        p.finding("RAND_BULK_STUCK", format_args!("{} constant 32B blocks", stuck));
    }
    out!("R12 done");
    let _ = unsafe { p.cold_restart("R12-end") };
}

/// Entry: R10 + R12. Returns `false` only on an abort that should mark the
/// whole run incomplete (currently never — both steps log and continue).
pub(super) unsafe fn run(p: &mut Probe) -> bool {
    out!("BEGIN deep ver=1");
    unsafe { r10_registers(p) };
    unsafe { r12_random(p) };
    out!("END deep findings={}", p.findings);
    true
}
