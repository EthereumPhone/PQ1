//! Read-only probe steps R0–R9 (feature `optiga-probe`).
//!
//! **Contract:** only `GetDataObject` (data and metadata), the Last Error
//! Code read, `OpenApplication`, the Shielded Connection handshake and a
//! shielded `GetRandom` reach the chip. The handshake is the one step that
//! changes chip state at all: it raises the Security Event Counter by one per
//! handshake, which decays by one every 5 s, and it only runs when E140 is
//! proven to hold this build's PBS (a wrong PBS would wedge the PRL until
//! power is cycled).
//!
//! `fsbl-tests/tests/source_invariants.rs::optiga_probe_readonly_names_no_write_path`
//! fails the build if this file or `mod.rs` names a write path.

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::inventory::{self, Class, INVENTORY};
use super::{fp, hex, Probe, Res, ResFmt, OID_UID};

/// `OPTIGA_PROBE_SWEEP=1` at build time adds R8, the 0x0000–0xFFFF metadata
/// sweep (several minutes).
pub(super) fn sweep_enabled() -> bool {
    matches!(option_env!("OPTIGA_PROBE_SWEEP"), Some("1"))
}

/// `OPTIGA_PROBE_FORCE_SHIELD=1` runs R7 even when E140 could not be compared
/// in plaintext. A handshake under the wrong PBS leaves the chip in the PRL
/// alert state; R7 power-cycles afterwards to clear it.
fn force_shield() -> bool {
    matches!(option_env!("OPTIGA_PROBE_FORCE_SHIELD"), Some("1"))
}

/// Number of handshakes R7 performs (sequence-number evidence for the open
/// CCM nonce issue). Each one is one SEC event.
const HANDSHAKES: u32 = 3;

pub(super) unsafe fn run(p: &mut Probe) -> bool {
    // R0 — fresh power, so no wedge or session from an earlier image leaks in.
    if !unsafe { p.cold_restart("R0") } {
        out!("ABORT step=R0 reason=chip did not come up (see RESTART line)");
        return false;
    }

    // R1 — the fresh driver has no PBS and no session: everything below is
    // plaintext until R7 says otherwise.
    if p.dev.shield.pbs_loaded || p.dev.shield.active {
        out!("ABORT step=R1 reason=shield state not fresh");
        return false;
    }
    out!("STEP R1 open=ok");

    // R2 — identity and SEC baseline.
    let mut uid = [0u8; 64];
    let mut h = [0u8; 128];
    let r = unsafe { p.data(OID_UID, 0, &mut uid) };
    if let Res::Ok(n) = r {
        let n = core::cmp::min(n, p.uid.len());
        p.uid[..n].copy_from_slice(&uid[..n]);
        p.uid_len = n;
        out!("UID hex={}", hex(&uid[..n], &mut h));
    } else {
        out!("UID {}", ResFmt(r));
    }
    if !unsafe { p.sec_check("R2") } {
        out!("ABORT step=R2 reason=SEC unreadable or too high");
        return false;
    }

    // R3 — metadata of every documented object (snapshot for R9).
    out!("STEP R3 objects={}", inventory::N);
    if !unsafe { p.dump_metadata("R3", true) } {
        out!("ABORT step=R3 reason=SEC watchdog");
        return false;
    }

    // R4/R5 — one plaintext DATA read per object. Whether the outcome
    // matches the object's Read AC is the host's call; secrets are
    // fingerprinted, never printed.
    out!("STEP R4");
    for obj in INVENTORY.iter().filter(|o| !matches!(o.class, Class::Key | Class::Session)) {
        let _ = unsafe { p.read_object(obj, "R4", "plain") };
    }
    if !unsafe { p.sec_check("R4") } {
        out!("ABORT step=R4 reason=SEC watchdog");
        return false;
    }
    // Key and session objects last: the SRM forbids reading their data part
    // whatever the metadata says, so success here is a finding in itself.
    out!("STEP R5");
    for obj in INVENTORY.iter().filter(|o| matches!(o.class, Class::Key | Class::Session)) {
        if unsafe { p.read_object(obj, "R5", "plain") }.is_ok() {
            p.finding(
                "KEY_DATA_READABLE",
                format_args!("{:04X} returned data to GetDataObject (SRM forbids)", obj.oid),
            );
        }
    }
    if !unsafe { p.sec_check("R5") } {
        out!("ABORT step=R5 reason=SEC watchdog");
        return false;
    }

    // R6 — which PBS is E140 paired to? Compared in constant time, logged
    // as a match bit plus SHA-256 fingerprints.
    out!("STEP R6");
    let pbs_match = unsafe { r6_compare_pbs(p) };

    // R7 — shielded checks, only when the handshake is known to succeed.
    if pbs_match || force_shield() {
        out!("STEP R7 forced={}", (!pbs_match) as u8);
        unsafe { r7_shielded(p) };
    } else {
        out!("STEP R7 skipped=pbs-unknown-or-mismatch");
    }

    // R8 — undocumented OID sweep.
    if sweep_enabled() {
        out!("STEP R8");
        // The driver logs 2-3 lines per transaction; over 131k transactions
        // semihosting would dominate the run. Probe lines are unaffected.
        super::mute_driver_logs(true);
        let swept = unsafe { r8_sweep(p) };
        super::mute_driver_logs(false);
        if !swept {
            out!("ABORT step=R8 reason=SEC watchdog or link loss");
            return false;
        }
    } else {
        out!("STEP R8 skipped=sweep-off");
    }

    // R9 — nothing may have changed.
    out!("STEP R9");
    p.sec_allow_rise(false);
    unsafe { p.dump_metadata("R9", false) }
}

/// R6. Returns `true` iff E140 was readable in plaintext and equals this
/// build's PBS (dev-testkey under `otp-hardcoded-master-key`).
unsafe fn r6_compare_pbs(p: &mut Probe) -> bool {
    let mut e140 = [0u8; 64];
    let n = p.take_e140(&mut e140);
    let mut f1 = [0u8; 16];
    let mut f2 = [0u8; 16];
    let mut h = [0u8; 16];
    let build = crate::hw::secret_keys::current_pbs();
    let result = match build {
        Ok(mut pbs) => {
            let bfp: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(pbs).into();
            // The build PBS prefix is the same 8 bytes `load_pbs` logs at
            // boot (`[OPTIGA] PBS fingerprint:`); under the dev root it is
            // derived from a constant in the source tree.
            let prefix = hex(&pbs[..8], &mut h);
            let m = if n == 64 {
                let efp: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(e140).into();
                let eq: bool = e140.ct_eq(&pbs).into();
                out!(
                    "PBS e140=read match={} e140_fp={} build_fp={} build_prefix={}",
                    eq as u8,
                    fp(&efp, &mut f1),
                    fp(&bfp, &mut f2),
                    prefix
                );
                eq
            } else {
                out!(
                    "PBS e140=unreadable len={} build_fp={} build_prefix={}",
                    n,
                    fp(&bfp, &mut f2),
                    prefix
                );
                false
            };
            pbs.zeroize();
            m
        }
        Err(_) => {
            out!("PBS build=unavailable");
            false
        }
    };
    e140.zeroize();
    result
}

/// R7. Handshakes, then shielded reads that must still be refused without
/// an Auto() authorization, then a shielded GetRandom.
unsafe fn r7_shielded(p: &mut Probe) {
    p.sec_allow_rise(true);
    p.dev.load_pbs();
    let mut established = false;
    for n in 1..=HANDSHAKES {
        if n > 1 {
            // Drop the session on both sides; the next handshake starts fresh.
            if let Err(e) = p.dev.hard_reset_and_reinit() {
                out!("SHIELD n={} reset_err={:?}", n, e);
                break;
            }
        }
        match p.dev.ensure_shield() {
            Ok(()) => {
                out!("SHIELD n={} ok=1", n);
                established = true;
            }
            Err(e) => {
                out!("SHIELD n={} ok=0 err={:?}", n, e);
                established = false;
                break;
            }
        }
    }
    if established {
        for &oid in &[0xF1D0u16, 0xF1D1, 0xF1D2, 0xF1D3, 0xF1D4, 0xF1D8, 0xF1D9, 0xF1DA, 0xF1DB, 0xF1D6] {
            if let Some(obj) = INVENTORY.iter().find(|o| o.oid == oid) {
                let _ = unsafe { p.read_object(obj, "R7", "shield") };
            }
        }
        let mut rnd = [0u8; 32];
        // SAFETY: shield active; one protected APDU.
        let r = unsafe { super::super::apdu::get_random(&mut p.dev.ifx, &mut p.dev.shield, &mut rnd) };
        out!("RANDOM ch=shield ok={} len={}", r.is_ok() as u8, r.unwrap_or(0));
        rnd.zeroize();
    }
    let _ = p.sec_check("R7");
    // Always end on clean power: drops the session, clears any alert state.
    let _ = unsafe { p.cold_restart("R7-end") };
    p.sec_allow_rise(false);
    let _ = p.sec_check("R7-post");
}

/// R8. Metadata read of every OID outside the inventory. Anything that is
/// not "invalid OID" (Last Error Code 0x01) is reported.
unsafe fn r8_sweep(p: &mut Probe) -> bool {
    let mut m = [0u8; 256];
    let mut h = [0u8; 512];
    let mut hits = 0u32;
    let mut link_run = 0u32;
    let mut oid: u32 = 0;
    while oid <= 0xFFFF {
        let o = oid as u16;
        oid += 1;
        if o & 0x0FFF == 0 {
            out!("SWEEP progress={:04X} hits={}", o, hits);
        }
        if o & 0x00FF == 0 && o != 0 && !unsafe { p.sec_check("R8") } {
            return false;
        }
        if inventory::contains(o) {
            continue;
        }
        let r = unsafe { p.meta(o, &mut m) };
        match r {
            Res::Ok(n) => {
                hits += 1;
                link_run = 0;
                out!("SWEEP oid={:04X} meta={}", o, hex(&m[..n], &mut h));
            }
            Res::Chip { lec: Some(0x01), .. } => link_run = 0,
            Res::Chip { .. } => {
                hits += 1;
                link_run = 0;
                out!("SWEEP oid={:04X} {}", o, ResFmt(r));
            }
            Res::Link(_) => {
                link_run += 1;
                out!("SWEEP oid={:04X} {}", o, ResFmt(r));
                if link_run >= 4 {
                    if !unsafe { p.cold_restart("R8-link") } {
                        return false;
                    }
                    link_run = 0;
                }
            }
        }
    }
    out!("SWEEP done hits={}", hits);
    unsafe { p.sec_check("R8-end") }
}
