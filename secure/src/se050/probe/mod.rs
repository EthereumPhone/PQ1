//! SE050 on-silicon read-only probe (`se050-probe`, bench-only, terminal).
//!
//! The SE050 analogue of [`crate::optiga::probe`]. It checks that the chip's
//! identity, object inventory, free memory and *plain-command surface* are
//! what the firmware and the DVT checklist (§6B) claim, by asking the chip
//! directly — and it never creates, writes, deletes or authenticates an
//! object. The only writes the whole image performs are the T=1 and SCP03
//! handshake frames the driver sends to bring the link up; no application
//! command mutates chip state.
//!
//! It covers the read-only §6B rows: 6B.1 (identity + GetVersionExt `Le`
//! variants, #444/F-10), 6B.2 (unique ID + stability across a reset), 6B.3
//! (full `ReadIDList` inventory with per-object type/size), 6B.4 (free
//! memory), 6B.5 (platform-SCP presence), 6B.6 (the plain / no-SCP03
//! read-class acceptance matrix — the bus attacker's free surface).
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

/// `GetFreeMemory` reports at most `0x7FFF`; the chip has more persistent
/// memory than that, so this value is a floor and cannot show a leak.
const FREE_MEMORY_CAP: u16 = 0x7FFF;

/// Run the read-only SE050 probe. Returns `true` if no finding fired.
///
/// # Safety
/// Single-threaded boot path; nothing else has touched the SE050 and nothing
/// will after this block (the caller does `SYS_EXIT` / `wfe`).
pub(crate) unsafe fn run(se: &mut Se050) -> bool {
    marker!("=== SPROBE START ===");
    let mut ok = true;
    let mut hb = [0u8; 128];

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
            Err(e) => out!("6B.4 free-memory[{}] ERR {:?}", name, e),
        }
    }

    // -- 6B.3 inventory: ReadIDList (paged) + ReadType/ReadSize ------------
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
            out!("6B.3 ReadIDList page={} listed={} more={}", page, listed, more);
            if count < listed {
                out!(
                    "6B.3 FINDING: page {} listed {} IDs but only {} fit — inventory incomplete",
                    page, listed, count
                );
                truncated = true;
                ok = false;
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
            if !more || listed == 0 || page > 8 {
                break;
            }
        }
        out!(
            "6B.3 inventory total={} unexpected/production={} leftover={} complete={}",
            total, unexpected, leftover, !truncated
        );
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

    // -- 6B.6 plain (no-SCP03) read-class acceptance matrix ----------------
    // Every command here is sent OUTSIDE the SCP03 channel, straight down the
    // T=1 link. A chip that requires platform SCP refuses all of them; a chip
    // that does not exposes exactly this surface to a keyless bus attacker.
    // Read-class only, by type: the helper takes an `apdu::PlainReadCmd`, so
    // this file cannot name a write/delete/auth header. GetVersionExt,
    // GetRandom, ReadIDList, CheckExists on the production USERID_OBJ
    // (expected absent) and a Read of the user-gated ENTROPY_OBJ.
    marker!("=== SPROBE 6B.6 plain matrix ===");
    {
        use apdu::PlainReadCmd as P;
        let (t1, _scp) = se.t1_scp03_mut();
        let mut o = [0u8; 64];
        match apdu::plain_readclass_probe(t1, P::GetVersionExt, &mut o) {
            Ok((sw, n)) => out!("6B.6 plain GetVersionExt SW=0x{:04x} data={}", sw, hex(&o[..n], &mut hb)),
            Err(e) => out!("6B.6 plain GetVersionExt ERR {:?}", e),
        }
        match apdu::plain_readclass_probe(t1, P::GetRandom(8), &mut o) {
            Ok((sw, n)) => out!("6B.6 plain GetRandom(8) SW=0x{:04x} data={}", sw, hex(&o[..n], &mut hb)),
            Err(e) => out!("6B.6 plain GetRandom ERR {:?}", e),
        }
        match apdu::plain_readclass_probe(t1, P::ReadIdList, &mut o) {
            Ok((sw, n)) => out!("6B.6 plain ReadIDList SW=0x{:04x} datalen={}", sw, n),
            Err(e) => out!("6B.6 plain ReadIDList ERR {:?}", e),
        }
        match apdu::plain_readclass_probe(t1, P::CheckExists(super::USERID_OBJ), &mut o) {
            Ok((sw, n)) => out!("6B.6 plain CheckExists(USERID_OBJ) SW=0x{:04x} data={}", sw, hex(&o[..n], &mut hb)),
            Err(e) => out!("6B.6 plain CheckExists ERR {:?}", e),
        }
        // Plain Read of the production entropy object (user-gated): must be
        // refused if present, absent otherwise — never return half_E in clear.
        match apdu::plain_readclass_probe(t1, P::Read(super::ENTROPY_OBJ), &mut o) {
            Ok((sw, n)) => {
                out!("6B.6 plain Read(ENTROPY_OBJ) SW=0x{:04x} datalen={}", sw, n);
                if sw == 0x9000 && n > 0 {
                    out!("6B.6 FINDING: a plain read of the production entropy object returned {} bytes", n);
                    ok = false;
                }
            }
            Err(e) => out!("6B.6 plain Read(ENTROPY_OBJ) ERR {:?}", e),
        }
    }

    if ok {
        marker!("=== SPROBE DONE OK ===");
    } else {
        marker!("=== SPROBE DONE FINDINGS ===");
    }
    ok
}
