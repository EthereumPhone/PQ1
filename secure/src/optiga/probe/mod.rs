//! OPTIGA Trust M on-silicon probe (`optiga-probe`, bench-only, terminal).
//!
//! Checks that the chip's configuration is what the firmware and the docs
//! claim, and maps its undocumented surface, by asking the chip directly.
//!
//! - **Read-only mode** (`optiga-probe`, default, [`readonly`]): reads
//!   metadata and data and never sends a write, key-generation, key-use,
//!   counter or protected-update command. Safe on a board you cannot replace.
//!   `source_invariants` pins that: the read-only sources may not name a
//!   write path.
//!
//! The firmware only gathers facts and enforces guards. It emits one
//! `[OPROBE] …` line per fact over semihosting; `tools/optiga_probe/report.py`
//! decodes the metadata, applies the rules and gives the verdict.
//!
//! Entry is from `main.rs`, right after `se_power::init` + `i2c_hw::init` and
//! before `ui::init`, `load_pbs`, `reconcile_pin_attempts`, the wizard or any
//! other SE traffic. The caller exits via `SYS_EXIT`; nothing after this
//! module ever runs in a probe image.

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use super::apdu::{self, OptigaError};
use super::OptigaTrustM;

/// Emit one probe line. Every line the host parses starts with `[OPROBE]`.
/// Defined before the child modules so they see it by textual scope.
///
/// Prints directly rather than through `secure_log!`, so probe lines survive
/// the driver-log mute (`crate::LOG_MUTED`) used during the OID sweep. The
/// `DHCSR.C_DEBUGEN` check keeps a probe image from HardFaulting on BKPT
/// when no debugger is attached.
macro_rules! out {
    ($($arg:tt)*) => {{
        if crate::ARCH.dhcsr.read() & 1 != 0 {
            cortex_m_semihosting::hprintln!("[OPROBE] {}", format_args!($($arg)*));
        }
    }};
}

/// Verdict marker lines (`=== OPROBE … ===`) the Makefile and host grep for.
macro_rules! marker {
    ($s:literal) => {{
        if crate::ARCH.dhcsr.read() & 1 != 0 {
            cortex_m_semihosting::hprintln!($s);
        }
    }};
}

/// Silence the driver's own `secure_log!` lines (not `out!`).
pub(crate) fn mute_driver_logs(on: bool) {
    crate::LOG_MUTED.store(on, core::sync::atomic::Ordering::Relaxed);
}

pub(crate) mod inventory;
mod deep;
mod readonly;

use inventory::{Class, Obj, INVENTORY};

/// Security Event Counter (SRM §"Security Monitor"). Throttling starts at
/// 128; the probe aborts well below that.
pub(crate) const OID_SEC: u16 = 0xE0C5;
pub(crate) const OID_UID: u16 = 0xE0C2;
pub(crate) const SEC_ABORT: u8 = 64;

/// Outcome of one request to the chip.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Res {
    /// Success; payload length.
    Ok(usize),
    /// The chip refused: `Sta` plus the Last Error Code read straight after
    /// (`None` when that follow-up read itself failed).
    Chip { sta: u8, lec: Option<u8> },
    /// Bus / framing / shield fault: the chip's verdict is unknown.
    Link(&'static str),
}

impl Res {
    pub(crate) fn is_ok(self) -> bool {
        matches!(self, Res::Ok(_))
    }
}

/// `res=ok len=…` / `res=deny sta=ff lec=07` / `res=link kind=…`.
pub(crate) struct ResFmt(pub Res);

impl core::fmt::Display for ResFmt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            Res::Ok(n) => write!(f, "res=ok len={}", n),
            Res::Chip { sta, lec: Some(l) } => write!(f, "res=deny sta={:02x} lec={:02x}", sta, l),
            Res::Chip { sta, lec: None } => write!(f, "res=deny sta={:02x} lec=??", sta),
            Res::Link(k) => write!(f, "res=link kind={}", k),
        }
    }
}

/// Lower-case hex of `data`, formatted into `buf` (needs `2 * data.len()`).
/// One `&str` per line keeps semihosting to a handful of SYS_WRITEs.
pub(crate) fn hex<'a>(data: &[u8], buf: &'a mut [u8]) -> &'a str {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let n = core::cmp::min(data.len(), buf.len() / 2);
    for (i, b) in data[..n].iter().enumerate() {
        buf[2 * i] = DIGITS[(b >> 4) as usize];
        buf[2 * i + 1] = DIGITS[(b & 0x0f) as usize];
    }
    core::str::from_utf8(&buf[..2 * n]).unwrap_or("?")
}

/// First 8 bytes of SHA-256, as 16 hex chars in `buf`.
pub(crate) fn fp<'a>(digest: &[u8; 32], buf: &'a mut [u8; 16]) -> &'a str {
    hex(&digest[..8], buf)
}

/// Hex bytes per DATA line.
pub(crate) const BYTES_PER_LINE: usize = 64;

pub(crate) struct Probe {
    pub(crate) dev: OptigaTrustM,
    /// SEC reading at the last checkpoint (`None` until first read).
    sec_last: Option<u8>,
    /// Phases that are expected to raise SEC (handshakes) set this.
    sec_rise_allowed: bool,
    /// Per-inventory SHA-256 prefix of the R3 metadata, for the R9 diff.
    snap: [[u8; 8]; inventory::N],
    snap_ok: [bool; inventory::N],
    /// E140 contents if it was readable in plaintext; consumed (and wiped)
    /// by the R6 PBS comparison.
    e140: [u8; 64],
    e140_len: usize,
    pub(crate) uid: [u8; 32],
    pub(crate) uid_len: usize,
    pub(crate) findings: u32,
}

impl Probe {
    pub(crate) const fn new() -> Self {
        Self {
            dev: OptigaTrustM::new(),
            sec_last: None,
            sec_rise_allowed: false,
            snap: [[0; 8]; inventory::N],
            snap_ok: [false; inventory::N],
            e140: [0; 64],
            e140_len: 0,
            uid: [0; 32],
            uid_len: 0,
            findings: 0,
        }
    }

    /// Report something the host must flag regardless of its own rules.
    pub(crate) fn finding(&mut self, id: &str, msg: core::fmt::Arguments<'_>) {
        self.findings += 1;
        out!("FINDING id={} msg={}", id, msg);
    }

    // -- Chip primitives (read-only) ---------------------------------------

    /// Turn a driver error into a [`Res`], reading the Last Error Code for a
    /// chip refusal. Bare `0x01` read: it does not clear before reading.
    unsafe fn classify(&mut self, e: OptigaError) -> Res {
        match e {
            OptigaError::Status(sta) => {
                // SAFETY: caller holds `&mut self`; one APDU on the OPTIGA bus.
                let lec = unsafe { apdu::read_last_error(&mut self.dev.ifx, &mut self.dev.shield) };
                Res::Chip { sta, lec }
            }
            OptigaError::I2c => Res::Link("i2c"),
            OptigaError::Transport => Res::Link("transport"),
            OptigaError::Crc => Res::Link("crc"),
            OptigaError::Shield => Res::Link("shield"),
            OptigaError::BufferOverflow => Res::Link("overflow"),
            OptigaError::PinIncorrect | OptigaError::PinLocked | OptigaError::NotProvisioned => {
                Res::Link("driver")
            }
        }
    }

    /// GetDataObject(metadata).
    pub(crate) unsafe fn meta(&mut self, oid: u16, out: &mut [u8; 256]) -> Res {
        // SAFETY: caller holds `&mut self`.
        match unsafe { apdu::get_metadata(&mut self.dev.ifx, &mut self.dev.shield, oid, out) } {
            Ok(n) => Res::Ok(n),
            Err(e) => unsafe { self.classify(e) },
        }
    }

    /// GetDataObject(data) of up to `out.len()` bytes at `offset`.
    pub(crate) unsafe fn data(&mut self, oid: u16, offset: u16, out: &mut [u8]) -> Res {
        let len = core::cmp::min(out.len(), 256) as u16;
        // SAFETY: caller holds `&mut self`.
        match unsafe {
            apdu::get_data_object(&mut self.dev.ifx, &mut self.dev.shield, oid, offset, len, out)
        } {
            Ok(n) => Res::Ok(n),
            Err(e) => unsafe { self.classify(e) },
        }
    }

    /// Read SEC, log it, and enforce the watchdog. Returns `false` when the
    /// caller must stop its current phase (an unexpected rise) or the whole
    /// run (`aborted` is then also set by the caller via the return of
    /// [`Self::sec_abort`]).
    pub(crate) unsafe fn sec_check(&mut self, phase: &str) -> bool {
        let mut b = [0u8; 4];
        let r = unsafe { self.data(OID_SEC, 0, &mut b[..1]) };
        let Res::Ok(1) = r else {
            out!("SEC phase={} {}", phase, ResFmt(r));
            // Unknown SEC: do not continue blind.
            return false;
        };
        let v = b[0];
        out!("SEC phase={} val={}", phase, v);
        let rose = matches!(self.sec_last, Some(prev) if v > prev);
        self.sec_last = Some(v);
        if v >= SEC_ABORT {
            self.finding("SEC_HIGH", format_args!("SEC={} at {} — stopping before throttling", v, phase));
            return false;
        }
        if rose && !self.sec_rise_allowed {
            self.finding("SEC_RISE", format_args!("SEC rose to {} during read-only phase {}", v, phase));
            return false;
        }
        true
    }

    /// Re-baseline SEC after a phase that may legitimately raise it.
    pub(crate) fn sec_allow_rise(&mut self, allow: bool) {
        self.sec_rise_allowed = allow;
    }

    /// SEC value at the last checkpoint.
    pub(crate) fn sec_value(&self) -> Option<u8> {
        self.sec_last
    }

    /// Metadata of every inventory OID. With `snapshot`, record the R3
    /// fingerprints; otherwise diff against them (R9).
    pub(crate) unsafe fn dump_metadata(&mut self, phase: &str, snapshot: bool) -> bool {
        let mut m = [0u8; 256];
        let mut h = [0u8; 512];
        for (i, obj) in INVENTORY.iter().enumerate() {
            let r = unsafe { self.meta(obj.oid, &mut m) };
            match r {
                Res::Ok(n) => {
                    out!("META phase={} oid={:04X} name={} hex={}", phase, obj.oid, obj.name, hex(&m[..n], &mut h));
                    let d: [u8; 32] = Sha256::digest(&m[..n]).into();
                    let mut p = [0u8; 8];
                    p.copy_from_slice(&d[..8]);
                    if snapshot {
                        self.snap[i] = p;
                        self.snap_ok[i] = true;
                    } else if !self.snap_ok[i] || self.snap[i] != p {
                        self.finding(
                            "META_CHANGED",
                            format_args!("{:04X} metadata differs from the start of the run", obj.oid),
                        );
                    }
                }
                _ => {
                    out!("META phase={} oid={:04X} name={} {}", phase, obj.oid, obj.name, ResFmt(r));
                    if !snapshot && self.snap_ok[i] {
                        self.finding(
                            "META_CHANGED",
                            format_args!("{:04X} metadata was readable at start, now {}", obj.oid, ResFmt(r)),
                        );
                    }
                }
            }
        }
        unsafe { self.sec_check(phase) }
    }

    /// Read one object's DATA part in 256-byte chunks, logging per class.
    /// `ch` names the channel (`plain` / `shield`) for the log line.
    pub(crate) unsafe fn read_object(&mut self, obj: &Obj, phase: &str, ch: &str) -> Res {
        let mut buf = [0u8; 256];
        let mut h = [0u8; 2 * BYTES_PER_LINE];
        let mut f = [0u8; 16];
        if obj.class == Class::MetaOnly {
            out!("DATA phase={} oid={:04X} ch={} skipped=meta-only", phase, obj.oid, ch);
            return Res::Ok(0);
        }
        let probe_len = match obj.class {
            Class::Key | Class::Session => 1,
            _ => 256,
        };
        let mut hasher = Sha256::new();
        let mut total = 0usize;
        let mut off: u16 = 0;
        let first = loop {
            let r = unsafe { self.data(obj.oid, off, &mut buf[..probe_len]) };
            match r {
                Res::Ok(n) => {
                    hasher.update(&buf[..n]);
                    if obj.class == Class::Public {
                        for (k, chunk) in buf[..n].chunks(BYTES_PER_LINE).enumerate() {
                            out!(
                                "DATA phase={} oid={:04X} ch={} off={} hex={}",
                                phase,
                                obj.oid,
                                ch,
                                off as usize + k * BYTES_PER_LINE,
                                hex(chunk, &mut h)
                            );
                        }
                    }
                    if obj.oid == super::apdu::OID_PBS && off == 0 && n <= self.e140.len() && ch == "plain" {
                        self.e140[..n].copy_from_slice(&buf[..n]);
                        self.e140_len = n;
                    }
                    total += n;
                    buf.zeroize();
                    if n < probe_len || probe_len == 1 || total >= 0x2000 {
                        break Res::Ok(total);
                    }
                    off = off.wrapping_add(n as u16);
                }
                // Reading past the end of an object whose length is a
                // multiple of 256 ends with "boundary exceeded" (08).
                Res::Chip { lec: Some(0x08), .. } if total > 0 => break Res::Ok(total),
                _ if total > 0 => {
                    out!("DATA phase={} oid={:04X} ch={} off={} tail {}", phase, obj.oid, ch, off, ResFmt(r));
                    break Res::Ok(total);
                }
                _ => break r,
            }
        };
        let d: [u8; 32] = hasher.finalize().into();
        match first {
            Res::Ok(n) => out!(
                "READ phase={} oid={:04X} name={} ch={} class={} res=ok len={} fp={}",
                phase,
                obj.oid,
                obj.name,
                ch,
                class_name(obj.class),
                n,
                fp(&d, &mut f)
            ),
            r => out!(
                "READ phase={} oid={:04X} name={} ch={} class={} {}",
                phase,
                obj.oid,
                obj.name,
                ch,
                class_name(obj.class),
                ResFmt(r)
            ),
        }
        first
    }

    /// Power-cycle both SEs (pq1) or just reset the OPTIGA (iota2), then
    /// re-open the application on a fresh host-side state.
    pub(crate) unsafe fn cold_restart(&mut self, why: &str) -> bool {
        let cycled = crate::hw::se_power::power_cycle(100);
        crate::hw::i2c_hw::init();
        // Fresh host-side transport and session state; keep nothing.
        self.dev = OptigaTrustM::new();
        let r = self.dev.init();
        out!("RESTART why={} power_cycled={} init={}", why, cycled as u8, r.is_ok() as u8);
        r.is_ok()
    }

    pub(crate) fn take_e140(&mut self, out: &mut [u8; 64]) -> usize {
        let n = self.e140_len;
        out[..n].copy_from_slice(&self.e140[..n]);
        self.e140.zeroize();
        self.e140_len = 0;
        n
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        self.e140.zeroize();
    }
}

pub(crate) fn class_name(c: Class) -> &'static str {
    match c {
        Class::Public => "public",
        Class::Secret => "secret",
        Class::Key => "key",
        Class::Session => "session",
        Class::MetaOnly => "meta-only",
    }
}

/// Enable the DWT cycle counter (for latency measurements).
pub(crate) fn enable_cycle_counter() {
    const DEMCR: *mut u32 = 0xE000_EDFC as *mut u32;
    const DWT_CTRL: *mut u32 = 0xE000_1000 as *mut u32;
    const DWT_LAR: *mut u32 = 0xE000_1FB0 as *mut u32;
    // SAFETY: core debug block registers, always accessible to secure code;
    // single-threaded probe image.
    unsafe {
        core::ptr::write_volatile(DEMCR, core::ptr::read_volatile(DEMCR) | (1 << 24));
        core::ptr::write_volatile(DWT_LAR, 0xC5AC_CE55);
        core::ptr::write_volatile(DWT_CTRL, core::ptr::read_volatile(DWT_CTRL) | 1);
    }
}

/// Free-running DWT cycle counter (160 MHz).
pub(crate) fn cycles() -> u32 {
    const DWT_CYCCNT: *const u32 = 0xE000_1004 as *const u32;
    // SAFETY: plain read of the free-running cycle counter.
    unsafe { core::ptr::read_volatile(DWT_CYCCNT) }
}

/// Probe entry point. Returns `true` when the run completed (findings or
/// not); `false` on an abort (the host log says why).
///
/// # Safety
/// Owns the OPTIGA bus for the rest of the boot. The caller must not touch
/// either secure element afterwards (main.rs exits via `SYS_EXIT`).
pub(crate) unsafe fn run() -> bool {
    enable_cycle_counter();
    let mut p = Probe::new();

    out!("BEGIN mode=readonly ver=1 board={} sweep={} deep={}", board_name(), readonly::sweep_enabled() as u8, deep::deep_enabled() as u8);
    let mut ok = unsafe { readonly::run(&mut p) };
    // Deep read-only steps R10–R12 run after R9 when OPTIGA_PROBE_DEEP=1.
    // They only read registers/objects, draw GetRandom, soft-reset and
    // power-cycle; never a write. Gated behind the read-only completion so a
    // failed R9 still reports an abort.
    if ok && deep::deep_enabled() {
        ok = unsafe { deep::run(&mut p) };
    }
    out!("END findings={} ok={}", p.findings, ok as u8);
    if ok {
        marker!("=== OPROBE DONE ===");
    } else {
        marker!("=== OPROBE ABORT ===");
    }
    ok
}

pub(crate) fn board_name() -> &'static str {
    if cfg!(feature = "board-pq1") {
        "pq1"
    } else {
        "iota2"
    }
}
