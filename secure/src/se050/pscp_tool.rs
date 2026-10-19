//! SE050 platform-SCP bench tool (`se050-platform-scp-tool`, #989, terminal).
//!
//! `make se050-platform-scp-hw ACTION=status|require|release|cycle BOARD=pq1`.
//! Measures the applet's platform-SCP requirement (AN12413 §4.6.2) after an SE
//! rail power cycle, and — on ONE die only — sets it through the production
//! path ([`Se050::ensure_platform_scp_required`]) or clears it
//! ([`Se050::release_platform_scp`], which exists only in this image).
//!
//! Every mutation is bound to the die: the SE050 unique ID read over SCP03
//! must equal the compiled-in `PQ_SE050_PSCP_UID`, so an image built for one
//! board cannot change another. A refusing chip only talks SCP03, so never run
//! this with an image whose SCP03 keys do not match the die.
//!
//! One `[PSCP] …` line per fact over semihosting, then `=== PSCP DONE OK ===`
//! or `=== PSCP DONE FAIL ===`; the caller exits via `SYS_EXIT`.

use super::{apdu, PlatformScpState, Se050};

macro_rules! out {
    ($($arg:tt)*) => {{
        if crate::ARCH.dhcsr.read() & 1 != 0 {
            cortex_m_semihosting::hprintln!("[PSCP] {}", format_args!($($arg)*));
        }
    }};
}

macro_rules! marker {
    ($s:literal) => {{
        if crate::ARCH.dhcsr.read() & 1 != 0 {
            cortex_m_semihosting::hprintln!($s);
        }
    }};
}

/// `status` (default), `require`, `release` or `cycle`.
const ACTION: &str = match option_env!("PQ_SE050_PSCP_ACTION") {
    Some(a) => a,
    None => "status",
};

/// The die every mutation is bound to: the 18-byte SE050 unique ID, lowercase
/// hex (`make se050-probe-hw` prints it as 6B.2).
const EXPECT_UID: Option<&str> = option_env!("PQ_SE050_PSCP_UID");

/// Rail-off time; the SE050 probe uses the same.
const POWER_OFF_MS: u32 = 100;

fn hex<'a>(data: &[u8], buf: &'a mut [u8]) -> &'a str {
    const H: &[u8; 16] = b"0123456789abcdef";
    let n = data.len().min(buf.len() / 2);
    for (i, b) in data[..n].iter().enumerate() {
        buf[2 * i] = H[(b >> 4) as usize];
        buf[2 * i + 1] = H[(b & 0xf) as usize];
    }
    crate::ui::ascii_str(&buf[..2 * n])
}

fn state_line(tag: &str, s: PlatformScpState) {
    match s {
        PlatformScpState::NotRequired => out!("{} platform_scp=not_required sw=0x9000", tag),
        PlatformScpState::Refused(sw) => out!("{} platform_scp=required sw=0x{:04x}", tag, sw),
        PlatformScpState::Unknown => out!("{} platform_scp=unknown", tag),
    }
}

/// SE rail power cycle (no session survives), then one plain measurement.
///
/// # Safety
/// Single-threaded boot path; drives only the SE050 and its rail.
unsafe fn measure_cold(se: &mut Se050, tag: &str) -> PlatformScpState {
    let cycled = crate::hw::se_power::power_cycle(POWER_OFF_MS);
    crate::hw::i2c_hw::init();
    if !cycled {
        out!("{} WARNING: no SE rail enable on this board; a session left by an earlier image may mask the result", tag);
    }
    let s = se.measure_platform_scp();
    state_line(tag, s);
    s
}

/// Is `0x7FFF0207` on the chip? `None` on a link error.
fn credential_present(se: &mut Se050) -> Option<bool> {
    se.init().ok()?;
    let (t1, scp) = se.t1_scp03_mut();
    // SAFETY: single-threaded boot path; one SCP03 APDU.
    unsafe { apdu::check_exists(t1, scp, apdu::PLATFORM_SCP_OBJ) }.ok()
}

/// The die's unique ID equals `PQ_SE050_PSCP_UID`.
fn uid_bound(se: &mut Se050) -> bool {
    let Some(want) = EXPECT_UID else {
        out!("REFUSED: no PQ_SE050_PSCP_UID compiled in; mutations are bound to one die");
        return false;
    };
    if se.init().is_err() {
        out!("REFUSED: SE050 init failed; cannot read the unique ID");
        return false;
    }
    let mut uid = [0u8; 32];
    let (t1, scp) = se.t1_scp03_mut();
    // SAFETY: single-threaded boot path; one SCP03 read of a public object.
    let n = match unsafe { apdu::read_object_scp03_probe(t1, scp, apdu::UNIQUE_ID_OBJ, &mut uid) } {
        Ok(n) => n,
        Err(e) => {
            out!("REFUSED: unique-ID read failed {:?}", e);
            return false;
        }
    };
    let mut hb = [0u8; 64];
    let got = hex(&uid[..n], &mut hb);
    let ok = got == want;
    out!("uid={} expected={} match={}", got, want, ok as u8);
    ok
}

fn require(se: &mut Se050) -> bool {
    match se.ensure_platform_scp_required() {
        Ok(o) => {
            out!("require result={:?}", o);
            true
        }
        Err(e) => {
            out!("require FAILED {:?} code=E{:04X}", e, e.code());
            false
        }
    }
}

fn release(se: &mut Se050) -> bool {
    match se.release_platform_scp() {
        Ok(()) => {
            out!("release result=ok (requirement off, credential deleted)");
            true
        }
        Err(e) => {
            out!("release FAILED {:?}", e);
            false
        }
    }
}

/// Run the tool. Returns `true` when the action completed and verified.
///
/// # Safety
/// Single-threaded boot path; nothing else has touched the SE050 and nothing
/// will after this block (the caller does `SYS_EXIT` / `wfe`).
pub(crate) unsafe fn run(se: &mut Se050) -> bool {
    marker!("=== PSCP START ===");
    out!("action={}", ACTION);
    let before = measure_cold(se, "before");
    match credential_present(se) {
        Some(p) => out!("credential 0x7fff0207 present={}", p as u8),
        None => out!("credential 0x7fff0207 present=err"),
    }

    let ok = match ACTION {
        "status" => !matches!(before, PlatformScpState::Unknown),
        "require" => {
            uid_bound(se)
                && require(se)
                && matches!(measure_cold(se, "after-require"), PlatformScpState::Refused(_))
        }
        "release" => {
            uid_bound(se)
                && release(se)
                && measure_cold(se, "after-release") == PlatformScpState::NotRequired
        }
        "cycle" => {
            uid_bound(se)
                && require(se)
                && matches!(measure_cold(se, "after-require"), PlatformScpState::Refused(_))
                && release(se)
                && measure_cold(se, "after-release") == PlatformScpState::NotRequired
        }
        other => {
            out!("unknown ACTION={} (status|require|release|cycle)", other);
            false
        }
    };
    match credential_present(se) {
        Some(p) => out!("credential 0x7fff0207 present={} (end)", p as u8),
        None => out!("credential 0x7fff0207 present=err (end)"),
    }
    if ok {
        marker!("=== PSCP DONE OK ===");
    } else {
        marker!("=== PSCP DONE FAIL ===");
    }
    ok
}
