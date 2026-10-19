//! SE050 on-silicon read-only probe (`se050-probe`, bench-only, terminal).
//!
//! The SE050 analogue of [`crate::optiga::probe`]. It checks that the chip's
//! identity, object inventory, free memory and *plain-command surface* are
//! what the firmware and the DVT checklist (§6B) claim, by asking the chip
//! directly — and it never creates, writes, deletes or authenticates an
//! object. The only writes the whole image performs are the T=1 and SCP03
//! handshake frames the driver sends to bring the link up, plus one SE rail
//! power cycle (pq1 `LDO2_EN`) before the pre-session leg; no application
//! command mutates chip state.
//!
//! It covers the read-only §6B rows: 6B.1 (identity + GetVersionExt `Le`
//! variants, #444/F-10), 6B.2 (unique ID + stability across a reset), 6B.3
//! (full `ReadIDList` inventory with per-object type/size; 6B.3b settles
//! whether the `ReadIDList` offset counts entries or bytes), 6B.4 (free
//! memory), 6B.5 (platform-SCP presence), 6B.6 (the plain / no-SCP03
//! read-class acceptance matrix — the bus attacker's free surface — in three
//! link states: power-on before SELECT, after a plain SELECT with no session
//! ever opened, and with the probe's SCP03 session up). EVT-3D21 2026-10-19:
//! the SE050E2 answers the plain commands in the second state, i.e. platform
//! SCP is not mandatory (default `SCP_NOT_REQUIRED`, AN12413 §4.6.2).
//!
//! It emits one `[SPROBE] …` line per fact over semihosting; the host parser
//! `tools/se050_probe/report.py` decodes them. Entry is from `main.rs`, in the
//! same early-boot slot as the OPTIGA probe and `se-i2c-probe`; the caller
//! exits via `SYS_EXIT` and nothing after this module runs in a probe image.
//!
//! **Read-only is pinned.** `fsbl-tests/tests/source_invariants.rs`'s
//! `se050_probe_readonly_names_no_write_path` fails if this file names any
//! write/auth/delete/rotate/provision path. The typed read helpers it calls
//! live in `se050::apdu` (which legitimately reaches `send_apdu` /
//! `t1.transceive`), never here.

use super::apdu;
use super::t1oi2c::T1State;
use super::Se050;

/// Emit one probe line. Every line the host parses starts with `[SPROBE]`.
/// Prints directly (not via `secure_log!`) and guards on `DHCSR.C_DEBUGEN`
/// so a probe image never HardFaults on BKPT with no debugger attached.
macro_rules! out {
    ($($arg:tt)*) => {{
        if crate::ARCH.dhcsr.read() & 1 != 0 {
            cortex_m_semihosting::hprintln!("[SPROBE] {}", format_args!($($arg)*));
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

/// Hex-encode into a caller buffer; returns the written `&str`.
fn hex<'a>(data: &[u8], buf: &'a mut [u8]) -> &'a str {
    const H: &[u8; 16] = b"0123456789abcdef";
    let n = data.len().min(buf.len() / 2);
    for (i, b) in data[..n].iter().enumerate() {
        buf[2 * i] = H[(b >> 4) as usize];
        buf[2 * i + 1] = H[(b & 0xf) as usize];
    }
    crate::ui::ascii_str(&buf[..2 * n])
}

/// Classify an object ID for the inventory (6B.3).
fn classify(id: u32) -> &'static str {
    match id {
        0 => "zero",
        // #989: the RESERVED_ID_PLATFORM_SCP credential the firmware creates
        // to set SCP_REQUIRED. Absent on a factory E2.
        super::apdu::PLATFORM_SCP_OBJ => "platform-scp-cred",
        _ if (id & 0xFFFF_0000) == 0x7FFF_0000 => "nxp-reserved",
        _ if (id & 0xFFF0_0000) == 0x7DA0_0000 => "demo-auth",
        _ if id >= 0xF000_0000 => "iot-trust-prov",
        0x7B10_0000..=0x7B10_FFFF => "PRODUCTION(v6)",
        0x7B5E_0000..=0x7B5E_FFFF => "stress-carveout",
        0x7B5F_0000..=0x7B5F_FFFF => "stress-stranded",
        0x7B07_0000..=0x7B07_FFFF
        | 0x7B09_0000..=0x7B09_FFFF
        | 0x7B0A_0000..=0x7B0A_FFFF
        | 0x7B0B_0000..=0x7B0B_FFFF
        | 0x7B0D_0000..=0x7B0D_FFFF => "e2e-test",
        0x7B00_0000..=0x7B0E_FFFF => "retired-prod",
        _ => "UNEXPECTED",
    }
}

/// Classes that should never survive on a die: an e2e run or a retired
/// firmware generation was meant to delete them. Not unexpected (we know what
/// wrote them) but still a cleanup finding, so the probe reports them instead
/// of leaving them for a human to spot in the listing.
fn is_leftover(class: &str) -> bool {
    matches!(class, "e2e-test" | "retired-prod")
}

/// `GetFreeMemory` reports at most `0x7FFF` ("0x7FFF as response means at
/// least 32768 bytes are available", NXP `Se05x_API_GetFreeMemory`), and an
/// E2 has up to 50 kB of user memory, so at the cap the value is a floor and
/// cannot show a leak.
const FREE_MEMORY_CAP: u16 = 0x7FFF;

/// Rail-off time for the pre-session power cycle. The OPTIGA probe uses the
/// same 100 ms; the SE050 datasheet's Deep Power-Down needs far less.
const PRE_SESSION_POWER_OFF_MS: u32 = 100;
/// Interface-reset attempts after the power cycle (~50 ms apart). A cold SE050
/// answers by attempt 3–5 (`Se050::link_bringup`); 20 is that loop's bound.
const RESET_ATTEMPTS: u32 = 20;

/// The 6B.5 line: one fixed plain `CheckExists(UNIQUE_ID)` (the same APDU the
/// production every-boot measurement sends, #989), classified exactly as
/// production classifies it.
///
/// # Safety
/// Single-threaded boot path; drives only this driver's T=1 state.
unsafe fn platform_scp_line(t1: &mut T1State, leg: &str, ok: &mut bool, hb: &mut [u8; 128]) {
    use crate::scp03_logic::{classify_platform_scp_probe, PlatformScpState};
    // SAFETY: caller's contract.
    match unsafe { apdu::platform_scp_plain_probe(t1) } {
        Ok((sw, body, n)) => {
            let state = match classify_platform_scp_probe(sw, &body[..n]) {
                PlatformScpState::NotRequired => "not_required",
                PlatformScpState::Refused(_) => "required",
                PlatformScpState::Unknown => "unknown",
            };
            out!("6B.5 [{}] platform_scp={} sw=0x{:04x} body={}", leg, state, sw, hex(&body[..n], hb));
        }
        Err(e) => {
            out!("6B.5 [{}] platform_scp=unknown ERR {:?}", leg, e);
            *ok = false;
        }
    }
}

/// T=1 interface reset with the cold-boot retry `Se050::link_bringup` uses.
/// Returns the 1-based attempt that succeeded.
///
/// # Safety
/// Single-threaded boot path; drives only this driver's T=1 state.
unsafe fn link_reset_with_retry(t1: &mut T1State) -> Result<u32, ()> {
    for attempt in 1..=RESET_ATTEMPTS {
        // SAFETY: caller's contract.
        if unsafe { t1.interface_reset() }.is_ok() {
            return Ok(attempt);
        }
        cortex_m::asm::delay(8_000_000); // ~50 ms @ 160 MHz
    }
    Err(())
}

/// The §6B.6 matrix: five plain (no-SCP03) read-class commands, one
/// `[SPROBE] 6B.6 plain[<leg>] …` line each. `leg` names the link state
/// (`pre-select`, `pre-session`, `session`). Read-class only by type: the
/// helper takes an `apdu::PlainReadCmd`, so this file cannot name a
/// write/delete/auth header. CheckExists targets the production USERID_OBJ
/// (expected absent); Read targets the user-gated ENTROPY_OBJ, which must
/// never come back in clear.
///
/// # Safety
/// Single-threaded boot path; drives only this driver's T=1 state.
unsafe fn plain_matrix(t1: &mut T1State, leg: &str, ok: &mut bool, hb: &mut [u8; 128]) {
    use apdu::PlainReadCmd as P;
    const CMDS: [(P, &str); 5] = [
        (P::GetVersionExt, "GetVersionExt"),
        (P::GetRandom(8), "GetRandom(8)"),
        (P::ReadIdList, "ReadIDList"),
        (P::CheckExists(super::USERID_OBJ), "CheckExists(USERID_OBJ)"),
        (P::Read(super::ENTROPY_OBJ), "Read(ENTROPY_OBJ)"),
    ];
    let mut o = [0u8; 64];
    for (cmd, name) in CMDS {
        // SAFETY: caller's contract.
        match unsafe { apdu::plain_readclass_probe(t1, cmd, &mut o) } {
            Ok((sw, n)) => {
                if matches!(cmd, P::Read(_)) {
                    out!("6B.6 plain[{}] {} SW=0x{:04x} datalen={}", leg, name, sw, n);
                    if sw == 0x9000 && n > 0 {
                        out!("6B.6 FINDING: a plain [{}] read of the production entropy object returned {} bytes", leg, n);
                        *ok = false;
                    }
                } else {
                    out!("6B.6 plain[{}] {} SW=0x{:04x} datalen={} data={}", leg, name, sw, n, hex(&o[..n], hb));
                }
            }
            Err(e) => {
                out!("6B.6 plain[{}] {} ERR {:?}", leg, name, e);
                *ok = false;
            }
        }
    }
}

/// Run the read-only SE050 probe. Returns `true` if no finding fired.
///
/// # Safety
/// Single-threaded boot path; nothing else has touched the SE050 and nothing
/// will after this block (the caller does `SYS_EXIT` / `wfe`).
pub(crate) unsafe fn run(se: &mut Se050) -> bool {
    marker!("=== SPROBE START ===");
    let mut ok = true;
    let mut hb = [0u8; 128];

    // -- 6B.6 pre-session legs: power-on, no SCP03 session ever opened -------
    // The in-session matrix (end of `run`) cannot tell "platform SCP is
    // mandatory" from "a session is up, so plain commands are refused". This
    // leg removes the session: drop the SE rail (no SCP03 state survives a
    // power loss; a probe-rs reset alone does not power-cycle the SE), bring
    // only the T=1 link up, and send the same five plain read-class commands
    // twice — before the applet SELECT and after it — then the SELECT
    // response itself, which is plain by design. Nothing here authenticates.
    marker!("=== SPROBE 6B.6 pre-session ===");
    {
        let cycled = crate::hw::se_power::power_cycle(PRE_SESSION_POWER_OFF_MS);
        crate::hw::i2c_hw::init();
        out!("6B.6 pre-session power_cycled={} off_ms={}", cycled as u8, PRE_SESSION_POWER_OFF_MS);
        if !cycled {
            out!("6B.6 FINDING: no SE rail enable on this board, so the pre-session legs cannot rule out a session left by an earlier image");
            ok = false;
        }
        let (t1, _scp) = se.t1_scp03_mut();
        match link_reset_with_retry(t1) {
            Ok(attempt) => {
                out!("6B.6 pre-session interface reset OK attempt={}", attempt);
                plain_matrix(t1, "pre-select", &mut ok, &mut hb);
                let mut o = [0u8; 64];
                match apdu::select_applet_probe(t1, &mut o) {
                    Ok((sw, n)) => {
                        out!("6B.6 plain[pre-session] SELECT(applet) SW=0x{:04x} data={}", sw, hex(&o[..n], &mut hb));
                        plain_matrix(t1, "pre-session", &mut ok, &mut hb);
                        platform_scp_line(t1, "pre-session", &mut ok, &mut hb);
                    }
                    Err(e) => {
                        out!("6B.6 plain[pre-session] SELECT(applet) ERR {:?}", e);
                        ok = false;
                    }
                }
            }
            Err(()) => {
                out!("6B.6 pre-session interface reset FAILED after {} attempts", RESET_ATTEMPTS);
                ok = false;
            }
        }
    }

    // -- bring the link + SCP03 up (handshake frames only) -----------------
    if let Err(e) = se.init() {
        out!("6B.0 init FAILED: {:?} — chip not reachable, aborting", e);
        marker!("=== SPROBE ABORT ===");
        return false;
    }
    out!("6B.0 SE050 link + SCP03 established (factory E2/A921 keyset)");

    // -- 6B.1 identity -----------------------------------------------------
    {
        let (t1, scp) = se.t1_scp03_mut();
        let mut v = [0u8; 64];
        match apdu::get_version_ext(t1, scp, &mut v) {
            Ok(n) => {
                out!("6B.1 GetVersionExt(SCP03,Le) len={} raw={}", n, hex(&v[..n], &mut hb));
                // VersionInfo: 7-byte core (major.minor.patch, 2B appletConfig,
                // 2B secureBox) is the first 7 of whatever the stack returns.
                if n >= 7 {
                    let cfg = ((v[3] as u16) << 8) | v[4] as u16;
                    let sb = ((v[5] as u16) << 8) | v[6] as u16;
                    out!(
                        "6B.1 applet v{}.{}.{} AppletConfig=0x{:04x} SecureBox=0x{:04x}",
                        v[0], v[1], v[2], cfg, sb
                    );
                }
            }
            Err(e) => {
                out!("6B.1 GetVersionExt(SCP03) ERR {:?}", e);
                ok = false;
            }
        }
    }

    // -- 6B.4 free memory (also the R-reversibility baseline) --------------
    for (name, kind) in [
        ("persistent", apdu::MEM_PERSISTENT),
        ("transient-reset", apdu::MEM_TRANSIENT_RESET),
        ("transient-deselect", apdu::MEM_TRANSIENT_DESELECT),
    ] {
        let (t1, scp) = se.t1_scp03_mut();
        match apdu::get_free_memory_probe(t1, scp, kind) {
            Ok(free) if free == FREE_MEMORY_CAP => out!(
                "6B.4 free-memory[{}] = {} bytes (SATURATED at 0x7FFF: a floor, blind to leaks)",
                name, free
            ),
            Ok(free) => out!("6B.4 free-memory[{}] = {} bytes", name, free),
            Err(e) => {
                out!("6B.4 free-memory[{}] ERR {:?}", name, e);
                ok = false;
            }
        }
    }

    // -- 6B.3 inventory: ReadIDList (paged) + ReadType/ReadSize ------------
    // The first page is kept for the 6B.3b offset-unit check below.
    let mut first = [0u32; 64];
    let mut first_n = 0usize;
    {
        let mut offset: u16 = 0u16;
        let mut page = 0u32;
        let mut total = 0u32;
        let mut unexpected = 0u32;
        let mut leftover = 0u32;
        let mut truncated = false;
        loop {
            let mut ids = [0u32; 64];
            let (more, listed, count) = {
                let (t1, scp) = se.t1_scp03_mut();
                match apdu::read_id_list_probe(t1, scp, offset, &mut ids) {
                    Ok(r) => r,
                    Err(e) => {
                        out!("6B.3 ReadIDList page {} ERR {:?}", page, e);
                        ok = false;
                        break;
                    }
                }
            };
            out!("6B.3 ReadIDList page={} listed={} more=0x{:02x}", page, listed, more);
            if more != apdu::MORE_INDICATOR_MORE && more != apdu::MORE_INDICATOR_NO_MORE {
                out!("6B.3 FINDING: page {} more-indicator 0x{:02x} is neither NO_MORE nor MORE", page, more);
                ok = false;
            }
            if count < listed {
                out!(
                    "6B.3 FINDING: page {} listed {} IDs but only {} fit — inventory incomplete",
                    page, listed, count
                );
                truncated = true;
                ok = false;
            }
            if page == 0 {
                first = ids;
                first_n = count;
            }
            for &id in &ids[..count] {
                let class = classify(id);
                if class == "UNEXPECTED" || class == "PRODUCTION(v6)" {
                    unexpected += 1;
                }
                if is_leftover(class) {
                    leftover += 1;
                }
                let mut ty = [0u8; 16];
                let (t1, scp) = se.t1_scp03_mut();
                let tystr = match apdu::read_object_type_probe(t1, scp, id, &mut ty) {
                    Ok(n) => hex(&ty[..n], &mut hb),
                    Err(_) => "err",
                };
                // ReadSize wants its own borrow after the hex() above.
                let size = {
                    let (t1, scp) = se.t1_scp03_mut();
                    apdu::read_object_size_probe(t1, scp, id)
                };
                match size {
                    Ok(size) => out!(
                        "6B.3   id=0x{:08x} class={} type={} size={}",
                        id, class, tystr, size
                    ),
                    Err(_) => out!(
                        "6B.3   id=0x{:08x} class={} type={} size=err",
                        id, class, tystr
                    ),
                }
                total += 1;
            }
            // The offset is an index into the list (not bytes): advance by
            // what the chip listed, even if `ids` could not hold all of it.
            offset = offset.saturating_add(listed as u16);
            page += 1;
            if more != apdu::MORE_INDICATOR_MORE || listed == 0 {
                break;
            }
            if page > 8 {
                out!("6B.3 FINDING: still MORE after {} pages — page cap hit, inventory incomplete", page);
                truncated = true;
                ok = false;
                break;
            }
        }
        out!(
            "6B.3 inventory total={} unexpected/production={} leftover={} complete={}",
            total, unexpected, leftover, !truncated
        );
        // Like the unexpected-range FINDING below, a leftover does not clear
        // `ok`: the probe itself worked and the die is known. `report.py`
        // turns both into a failing exit; the firmware marker stays DONE OK.
        if leftover != 0 {
            out!(
                "6B.3 FINDING: {} stale e2e/retired object(s) — a run that should have deleted them did not",
                leftover
            );
        }
        if unexpected != 0 {
            out!(
                "6B.3 FINDING: {} object(s) in a production/unexpected range — classify before trusting this die",
                unexpected
            );
            // Not a probe failure by itself (could be a known leftover); the
            // host report decides. Record it loudly.
        }
    }

    // -- 6B.3b ReadIDList offset unit (entries vs bytes) -------------------
    // The wipe (`apdu::sweep`) and the loop above page by ENTRY index, per
    // NXP's `Se05x_API_ReadIDList` doc; NXP's own DeleteAll sample passes a
    // BYTE count. Settle it read-only: re-list from offsets 4 and 8. Entry
    // semantics start those lists at first[4] / first[8]; byte semantics at
    // first[1] / first[2].
    if first_n >= 9 {
        let mut agree_entries = 0u32;
        let mut agree_bytes = 0u32;
        for off in [4u16, 8] {
            let o = off as usize;
            let mut ids = [0u32; 4];
            let r = {
                let (t1, scp) = se.t1_scp03_mut();
                apdu::read_id_list_probe(t1, scp, off, &mut ids)
            };
            match r {
                Ok((_, listed, count)) if count > 0 => {
                    out!(
                        "6B.3b ReadIDList offset={} listed={} first=0x{:08x} entries-expect=0x{:08x} bytes-expect=0x{:08x}",
                        off, listed, ids[0], first[o], first[o / 4]
                    );
                    if ids[0] == first[o] {
                        agree_entries += 1;
                    }
                    if ids[0] == first[o / 4] {
                        agree_bytes += 1;
                    }
                }
                Ok((_, listed, _)) => out!("6B.3b ReadIDList offset={} listed={} (empty)", off, listed),
                Err(e) => out!("6B.3b ReadIDList offset={} ERR {:?}", off, e),
            }
        }
        if agree_entries == 2 && agree_bytes == 0 {
            out!("6B.3b ReadIDList offset unit = ENTRIES (matches apdu::sweep paging)");
        } else {
            out!(
                "6B.3b FINDING: ReadIDList offset unit is not entries (entries={}/2 bytes={}/2) — apdu::sweep paging is wrong",
                agree_entries, agree_bytes
            );
            ok = false;
        }
    } else {
        out!("6B.3b skipped: only {} IDs on the first page (need 9)", first_n);
    }

    // -- 6B.2 unique ID + stability across a soft reset --------------------
    let mut uid1 = [0u8; 32];
    let mut uid1_len = 0usize;
    {
        let (t1, scp) = se.t1_scp03_mut();
        match apdu::read_object_scp03_probe(t1, scp, apdu::UNIQUE_ID_OBJ, &mut uid1) {
            Ok(n) => {
                uid1_len = n;
                out!("6B.2 UniqueID(0x7FFF0206) len={} = {}", n, hex(&uid1[..n], &mut hb));
            }
            Err(e) => {
                out!("6B.2 UniqueID read ERR {:?}", e);
                ok = false;
            }
        }
    }
    // reinit = full SELECT + fresh SCP03 (soft reset of our session).
    match se.reinit() {
        Ok(()) => {
            let (t1, scp) = se.t1_scp03_mut();
            let mut uid2 = [0u8; 32];
            match apdu::read_object_scp03_probe(t1, scp, apdu::UNIQUE_ID_OBJ, &mut uid2) {
                Ok(n) => {
                    let stable = n == uid1_len && uid2[..n] == uid1[..uid1_len];
                    out!("6B.2 UniqueID after reinit stable={} = {}", stable, hex(&uid2[..n], &mut hb));
                    if !stable {
                        out!("6B.2 FINDING: UniqueID changed across reinit");
                        ok = false;
                    }
                }
                Err(e) => {
                    out!("6B.2 UniqueID re-read ERR {:?}", e);
                    ok = false;
                }
            }
        }
        Err(e) => {
            out!("6B.2 reinit ERR {:?} (session recovery)", e);
            ok = false;
        }
    }

    // -- 6B.6 plain (no-SCP03) read-class acceptance matrix, in-session -----
    // The same five commands as the pre-session legs at the top of `run`,
    // sent OUTSIDE the SCP03 channel while the probe's own session is up.
    // Kept so the two states can be compared line by line.
    marker!("=== SPROBE 6B.6 plain matrix (session up) ===");
    {
        let (t1, _scp) = se.t1_scp03_mut();
        plain_matrix(t1, "session", &mut ok, &mut hb);
    }

    // -- 6B.6 reselect leg: does a T=1 reset + plain SELECT end the session? --
    // #989 review: the production measurement runs after a fresh link
    // bring-up (T=1 reset + SELECT) but WITHOUT a power cycle. If that left
    // an SCP03 session from an earlier boot alive, a warm reset could make a
    // chip that still answers plain commands look "required". The answer
    // here, compared with the pre-session leg, settles it read-only.
    marker!("=== SPROBE 6B.6 reselect (T=1 reset + plain SELECT, no power cycle) ===");
    {
        let (t1, _scp) = se.t1_scp03_mut();
        match link_reset_with_retry(t1) {
            Ok(attempt) => {
                out!("6B.6 reselect interface reset OK attempt={}", attempt);
                let mut o = [0u8; 64];
                match apdu::select_applet_probe(t1, &mut o) {
                    Ok((sw, n)) => {
                        out!("6B.6 plain[reselect] SELECT(applet) SW=0x{:04x} data={}", sw, hex(&o[..n], &mut hb));
                        plain_matrix(t1, "reselect", &mut ok, &mut hb);
                        platform_scp_line(t1, "reselect", &mut ok, &mut hb);
                    }
                    Err(e) => {
                        out!("6B.6 plain[reselect] SELECT(applet) ERR {:?}", e);
                        ok = false;
                    }
                }
            }
            Err(()) => {
                out!("6B.6 reselect interface reset FAILED after {} attempts", RESET_ATTEMPTS);
                ok = false;
            }
        }
    }

    if ok {
        marker!("=== SPROBE DONE OK ===");
    } else {
        marker!("=== SPROBE DONE FINDINGS ===");
    }
    ok
}
