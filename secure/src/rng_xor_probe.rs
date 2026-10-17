//! Strong-RNG composition probe (`rng-xor-probe` feature, DVT rows 4.9 and the
//! three-source XOR check).
//!
//! Runs once at boot right after the SE rail and buses come up, before any
//! code path that writes to either secure element, then parks. It never writes
//! to either chip:
//! - SE050: `Se050::init` opens SCP03 on the published factory keyset (this
//!   feature does not enable `se050-derived-scp03`, so there is no PUT KEY).
//! - OPTIGA: the shielded session is opened under the PBS already in E140,
//!   read in place at LcsO=creation (`bench_load_pbs_in_place`). The normal
//!   first-boot pairing, which overwrites E140, is never reached.
//!
//! Part 1 (XOR): calls the production `rng_strong::fill` and records every
//! source contribution through hooks in `rng_strong` (platform bytes) and
//! `se_random_{optiga,se050}` (each chip block). It prints them with the
//! output, so the host can recompute `out == STM32 ^ OPTIGA ^ SE050`
//! independently; the device does the same check and prints a verdict.
//!
//! Part 2 (row 4.9, fail-closed): makes the SE050 unreachable (its I2C4 pins
//! taken off the peripheral; `SE1_EN` low alone did not stop it, which is
//! recorded separately), restores it and checks recovery, then holds the
//! OPTIGA in reset (`SE_RST` locked as a pulled-down input, so the driver's
//! own reset pulse cannot release it). In each case `rng_strong::fill`
//! must return `Err` with a zeroed buffer. It also replays `enter_pin`'s pad
//! randomisation lines to show what the PIN pad starts at when a source fails.
//!
//! Output is semihosting; run under `probe-rs run`. Bench only; never ship.

use cortex_m_semihosting::hprintln;

const MAX_PLATFORM: usize = 128;
const MAX_REC: usize = 16;
const SRC_OPTIGA: u8 = b'O';
const SRC_SE050: u8 = b'S';

#[derive(Clone, Copy)]
struct Rec {
    src: u8,
    ok: bool,
    len: usize,
    bytes: [u8; 32],
}

const EMPTY: Rec = Rec { src: 0, ok: false, len: 0, bytes: [0; 32] };

struct Log {
    platform: [u8; MAX_PLATFORM],
    platform_len: usize,
    platform_calls: u32,
    recs: [Rec; MAX_REC],
    nrec: usize,
    overflow: bool,
}

static mut LOG: Log = Log {
    platform: [0; MAX_PLATFORM],
    platform_len: 0,
    platform_calls: 0,
    recs: [EMPTY; MAX_REC],
    nrec: 0,
    overflow: false,
};

fn log() -> &'static mut Log {
    // SAFETY: single-threaded boot context; SysTick/NSC are not running yet.
    unsafe { &mut *core::ptr::addr_of_mut!(LOG) }
}

fn reset_log() {
    let l = log();
    l.platform_len = 0;
    l.platform_calls = 0;
    l.nrec = 0;
    l.overflow = false;
}

/// Hook in `rng_strong::fill_with_source_draw`, right after the platform fill.
pub fn record_platform(buf: &[u8]) {
    let l = log();
    l.platform_calls += 1;
    if buf.len() > MAX_PLATFORM {
        l.overflow = true;
        return;
    }
    l.platform[..buf.len()].copy_from_slice(buf);
    l.platform_len = buf.len();
}

/// Hook in `se_random_optiga` / `se_random_se050`, after the chip call.
pub fn record_se(optiga: bool, ok: bool, buf: &[u8]) {
    let l = log();
    if l.nrec >= MAX_REC || buf.len() > 32 {
        l.overflow = true;
        return;
    }
    let mut r = EMPTY;
    r.src = if optiga { SRC_OPTIGA } else { SRC_SE050 };
    r.ok = ok;
    r.len = buf.len();
    r.bytes[..buf.len()].copy_from_slice(buf);
    l.recs[l.nrec] = r;
    l.nrec += 1;
}

struct Hex<'a>(&'a [u8]);

impl core::fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for b in self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

/// Recompute `platform ^ optiga ^ se050` from the log, chunk by chunk in the
/// order the fold drew them (OPTIGA then SE050 per chunk).
fn device_xor_verdict(out: &[u8]) -> &'static str {
    let l = log();
    if l.overflow || l.platform_calls != 1 || l.platform_len != out.len() {
        return "XOR-UNCHECKABLE";
    }
    let mut expect = [0u8; MAX_PLATFORM];
    expect[..out.len()].copy_from_slice(&l.platform[..out.len()]);
    let mut off = 0;
    let mut i = 0;
    while i + 1 < l.nrec {
        let (o, s) = (&l.recs[i], &l.recs[i + 1]);
        if o.src != SRC_OPTIGA || s.src != SRC_SE050 || !o.ok || !s.ok || o.len != s.len {
            return "XOR-UNCHECKABLE";
        }
        if off + o.len > out.len() {
            return "XOR-UNCHECKABLE";
        }
        for k in 0..o.len {
            expect[off + k] ^= o.bytes[k] ^ s.bytes[k];
        }
        off += o.len;
        i += 2;
    }
    if i != l.nrec || off != out.len() {
        return "XOR-UNCHECKABLE";
    }
    if expect[..out.len()] == *out {
        "XOR-OK"
    } else {
        "XOR-MISMATCH"
    }
}

fn dump_call(tag: &str, n: usize, ok: bool, out: &[u8]) {
    let l = log();
    hprintln!("[xor] CALL {} n={} result={}", tag, n, if ok { "Ok" } else { "Err" });
    hprintln!("[xor] P {}", Hex(&l.platform[..l.platform_len]));
    for r in &l.recs[..l.nrec] {
        hprintln!(
            "[xor] {} ok={} len={} {}",
            r.src as char,
            r.ok as u8,
            r.len,
            Hex(&r.bytes[..r.len])
        );
    }
    hprintln!("[xor] OUT {}", Hex(out));
}

fn delay_ms(ms: u32) {
    cortex_m::asm::delay(160_000 * ms);
}

/// Drive a secure GPIO output pin high or low via BSRR.
fn gpio_out(port: u32, pin: u32, high: bool) {
    // SAFETY: secure-alias GPIO registers of a port `se_power::init` already
    // clocked; BSRR is write-only set/reset, MODER RMW touches only `pin`.
    unsafe {
        let moder = (port + 0x00) as *mut u32;
        let bsrr = (port + 0x18) as *mut u32;
        core::ptr::write_volatile(bsrr, if high { 1 << pin } else { 1 << (pin + 16) });
        let m = core::ptr::read_volatile(moder);
        core::ptr::write_volatile(moder, (m & !(0b11 << (2 * pin))) | (0b01 << (2 * pin)));
    }
}

fn gpio_idr(port: u32, pin: u32) -> bool {
    // SAFETY: read of a secure-alias GPIO IDR.
    unsafe { core::ptr::read_volatile((port + 0x10) as *const u32) & (1 << pin) != 0 }
}

/// Make `pin` an input with pull-down and lock its configuration until the
/// next reset (RM0456 GPIOx_LCKR sequence), so no driver can re-drive it.
fn gpio_lock_input_pulldown(port: u32, pin: u32) -> bool {
    // SAFETY: as `gpio_out`; LCKR (0x1C) write sequence per RM0456.
    unsafe {
        let moder = (port + 0x00) as *mut u32;
        let pupdr = (port + 0x0C) as *mut u32;
        let lckr = (port + 0x1C) as *mut u32;
        let m = core::ptr::read_volatile(moder);
        core::ptr::write_volatile(moder, m & !(0b11 << (2 * pin)));
        let p = core::ptr::read_volatile(pupdr);
        core::ptr::write_volatile(pupdr, (p & !(0b11 << (2 * pin))) | (0b10 << (2 * pin)));
        let lckk = 1u32 << 16;
        let bit = 1u32 << pin;
        core::ptr::write_volatile(lckr, lckk | bit);
        core::ptr::write_volatile(lckr, bit);
        core::ptr::write_volatile(lckr, lckk | bit);
        let _ = core::ptr::read_volatile(lckr);
        core::ptr::read_volatile(lckr) & lckk != 0
    }
}

/// One `rng_strong::fill` into a buffer pre-set to 0xAA; true iff it returned
/// `Err` and left the buffer all zero.
fn expect_fail_closed(tag: &str) -> bool {
    reset_log();
    let mut buf = [0xAAu8; 32];
    let r = crate::rng_strong::fill(&mut buf);
    let zero = buf.iter().all(|&b| b == 0);
    dump_call(tag, buf.len(), r.is_ok(), &buf);
    let pass = r.is_err() && zero;
    hprintln!(
        "[4.9] {}: result={} buffer_all_zero={} -> {}",
        tag,
        if r.is_ok() { "Ok" } else { "Err" },
        zero,
        if pass { "FAIL-CLOSED" } else { "NOT-FAIL-CLOSED" }
    );
    pass
}

/// The exact pad-randomisation lines of `ui::pin_entry::enter_pin`.
fn pin_pad_start(tag: &str) {
    let mut pin = [0u8; sphincs_tz_shared::PIN_LEN];
    let mut rand_bytes = [0u8; sphincs_tz_shared::PIN_LEN];
    let r = crate::rng_strong::fill(&mut rand_bytes);
    for i in 0..sphincs_tz_shared::PIN_LEN {
        pin[i] = rand_bytes[i] % 10;
    }
    hprintln!(
        "[4.9] {}: PIN-pad fill={} start digits {:?}",
        tag,
        if r.is_ok() { "Ok" } else { "Err" },
        pin
    );
}

pub fn run_and_halt(se: &mut crate::dual_se::DualSecureElement) -> ! {
    hprintln!("[xor] === RNG-XOR-PROBE start (no SE writes) ===");

    match se.optiga.bench_load_pbs_in_place() {
        Ok(fp) => hprintln!("[xor] OPTIGA: E140 read in place, sha256[..8]={}", Hex(&fp)),
        Err(e) => {
            hprintln!("[xor] OPTIGA: E140 read FAILED {:?}; stopping", e);
            park();
        }
    }

    // ---- Part 1: XOR composition --------------------------------------
    let sizes: [usize; 14] = [32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 8, 33, 72, 100];
    let mut ok_calls = 0;
    let mut xor_ok = 0;
    for (i, &n) in sizes.iter().enumerate() {
        reset_log();
        let mut out = [0u8; 100];
        let r = crate::rng_strong::fill(&mut out[..n]);
        let mut tag = [0u8; 2];
        tag[0] = b'0' + (i / 10) as u8;
        tag[1] = b'0' + (i % 10) as u8;
        dump_call(crate::ui::ascii_str(&tag), n, r.is_ok(), &out[..n]);
        let v = if r.is_ok() { device_xor_verdict(&out[..n]) } else { "FILL-ERR" };
        hprintln!("[xor] VERDICT {} {}", crate::ui::ascii_str(&tag), v);
        if r.is_ok() {
            ok_calls += 1;
        }
        if v == "XOR-OK" {
            xor_ok += 1;
        }
    }
    hprintln!("[xor] SUMMARY calls={} ok={} xor_ok={}", sizes.len(), ok_calls, xor_ok);

    // ---- Part 3: OPTIGA handshake-nonce soak (DVT 6.3) -----------------
    // `RNG_PROBE_SKIP_SOAK=1` at build time skips the ~2-minute soak (for
    // debug-log builds, where its draws would flood semihosting).
    let soak = if option_env!("RNG_PROBE_SKIP_SOAK").is_some() {
        "SKIPPED"
    } else {
        optiga_nonce_soak(se)
    };

    // ---- Part 2a-i: SE1_EN low (informational) --------------------------
    // Run 1 found the SE050 still answering 50 ms after SE1_EN went low, so
    // this leg only records whether a longer hold stops it.
    let (se050_port, se050_pin) = crate::board::SE050_EN.expect("board has SE050_EN");
    gpio_out(se050_port, se050_pin, false);
    delay_ms(2000);
    hprintln!("[4.9] SE1_EN low 2 s: idr={}", gpio_idr(se050_port, se050_pin) as u8);
    reset_log();
    let mut probe = [0u8; 32];
    let r = crate::rng_strong::fill(&mut probe);
    let se050_answered = log().recs[..log().nrec].iter().any(|r| r.src == SRC_SE050 && r.ok);
    hprintln!(
        "[4.9] se1en-low: fill={} se050_answered={}",
        if r.is_ok() { "Ok" } else { "Err" },
        se050_answered as u8
    );
    gpio_out(se050_port, se050_pin, true);
    delay_ms(100);

    // ---- Part 2a-ii: SE050 unreachable (I2C4 pins taken off the bus) ----
    let bus = crate::board::SE_I2C_BUSES
        .iter()
        .find(|b| b.probe_addrs.iter().any(|&(a, _)| a == 0x48))
        .expect("SE050 bus");
    let moder = bus.port;
    // SAFETY: secure-alias GPIO MODER of the SE050 bus port (clocked by
    // i2c_hw::init); the saved value is restored below.
    let saved = unsafe { core::ptr::read_volatile(moder as *const u32) };
    let clear = (0b11 << (2 * bus.scl_pin)) | (0b11 << (2 * bus.sda_pin));
    unsafe { core::ptr::write_volatile(moder as *mut u32, saved & !clear) };
    delay_ms(10);
    hprintln!("[4.9] SE050 bus pins set to input (SCL/SDA off the I2C4 peripheral)");
    let a = expect_fail_closed("se050-unreachable");
    pin_pad_start("se050-unreachable");

    unsafe { core::ptr::write_volatile(moder as *mut u32, saved) };
    delay_ms(100);
    let mut recovered = false;
    for attempt in 0..3 {
        let mut buf = [0u8; 32];
        let r = crate::rng_strong::fill(&mut buf);
        hprintln!("[4.9] se050 back on, attempt {}: {}", attempt, if r.is_ok() { "Ok" } else { "Err" });
        if r.is_ok() {
            recovered = true;
            break;
        }
    }

    // ---- Part 2b: OPTIGA held in reset (SE_RST locked low) -------------
    let (rst_port, rst_pin) = crate::board::OPTIGA_RST.expect("board has OPTIGA_RST");
    let locked = gpio_lock_input_pulldown(rst_port, rst_pin);
    delay_ms(10);
    hprintln!(
        "[4.9] OPTIGA reset held: lock={} SE_RST idr={}",
        locked as u8,
        gpio_idr(rst_port, rst_pin) as u8
    );
    let b = expect_fail_closed("optiga-reset");
    pin_pad_start("optiga-reset");
    hprintln!(
        "[4.9] after: SE_RST idr={} (must still read 0)",
        gpio_idr(rst_port, rst_pin) as u8
    );

    hprintln!(
        "[xor] === RNG-XOR-PROBE DONE: xor_ok={}/{} soak={} se050_unreachable={} se050_recovered={} optiga_reset={} ===",
        xor_ok,
        sizes.len(),
        soak,
        if a { "FAIL-CLOSED" } else { "NOT-FAIL-CLOSED" },
        recovered as u8,
        if b { "FAIL-CLOSED" } else { "NOT-FAIL-CLOSED" }
    );
    park();
}

/// Distance, in records, from the session's next host record / next chip
/// reply to the nonce a handshake Finished message used; `None` when the
/// handshake value is already behind the counter (no reuse possible).
fn handshake_gaps(s: (u32, u32, u32, u32)) -> (Option<u32>, Option<u32>) {
    let (enc, dec, enc_hs, dec_hs) = s;
    let tx = if enc_hs >= enc { Some(enc_hs - enc) } else { None };
    let rx = if dec_hs > dec { Some(dec_hs - dec - 1) } else { None };
    (tx, rx)
}

/// Drive shielded OPTIGA draws through the production `random` path (which
/// runs `ensure_shield`, and so the F-1 guard, before every draw) until the
/// session walks up to a handshake nonce. PASS: the firmware renegotiates with
/// at least one record of distance left, never at zero, and draws keep
/// succeeding afterwards.
fn optiga_nonce_soak(se: &mut crate::dual_se::DualSecureElement) -> &'static str {
    const MAX_DRAWS: u32 = 70_000;
    let Some(first) = se.optiga.bench_shield_sequences() else {
        hprintln!("[6.3] soak: no active shield session; skipped");
        return "NO-SESSION";
    };
    let (gtx, grx) = handshake_gaps(first);
    hprintln!(
        "[6.3] soak start: enc_seq={:#x} dec_seq={:#x} slave_seq={:#x} master_seq={:#x} gap_tx={:?} gap_rx={:?}",
        first.0, first.1, first.2, first.3, gtx, grx
    );
    if gtx.is_none() && grx.is_none() {
        hprintln!("[6.3] soak: handshake numbers already behind both counters; nothing to reach");
        return "NOTHING-TO-REACH";
    }
    let mut prev = first;
    let mut min_gap = u32::MAX;
    let mut renegotiations = 0u32;
    let mut errors = 0u32;
    let mut zero_gap_seen = false;
    let mut draws_after = 0u32;
    let mut i = 0u32;
    while i < MAX_DRAWS {
        i += 1;
        let mut b = [0u8; 8];
        if se.optiga.random(&mut b).is_err() {
            errors += 1;
            hprintln!("[6.3] soak: draw {} failed (errors={})", i, errors);
            if errors >= 5 {
                break;
            }
            continue;
        }
        let Some(s) = se.optiga.bench_shield_sequences() else {
            continue;
        };
        if (s.2, s.3) != (prev.2, prev.3) {
            renegotiations += 1;
            let (ptx, prx) = handshake_gaps(prev);
            hprintln!(
                "[6.3] soak: RENEGOTIATED at draw {}: before enc={:#x} dec={:#x} hs=({:#x},{:#x}) gap_tx={:?} gap_rx={:?}; after enc={:#x} dec={:#x} hs=({:#x},{:#x})",
                i, prev.0, prev.1, prev.2, prev.3, ptx, prx, s.0, s.1, s.2, s.3
            );
        } else {
            let (tx, rx) = handshake_gaps(s);
            for g in [tx, rx].into_iter().flatten() {
                min_gap = min_gap.min(g);
                if g == 0 {
                    zero_gap_seen = true;
                }
            }
        }
        if renegotiations > 0 {
            draws_after += 1;
            if draws_after >= 200 {
                break;
            }
        }
        if i % 5000 == 0 {
            let (tx, rx) = handshake_gaps(s);
            hprintln!("[6.3] soak: {} draws, gap_tx={:?} gap_rx={:?}", i, tx, rx);
        }
        prev = s;
    }
    let pass = renegotiations >= 1 && !zero_gap_seen && errors == 0 && draws_after >= 200;
    hprintln!(
        "[6.3] soak end: draws={} renegotiations={} min_gap_before_renegotiation={} zero_gap_seen={} errors={} draws_after_renegotiation={} -> {}",
        i, renegotiations, min_gap, zero_gap_seen, errors, draws_after,
        if pass { "PASS" } else { "NOT-PASS" }
    );
    if pass { "PASS" } else { "NOT-PASS" }
}

fn park() -> ! {
    // End the `probe-rs run` session; the verdict is in the log.
    cortex_m_semihosting::debug::exit(cortex_m_semihosting::debug::EXIT_SUCCESS);
    loop {
        cortex_m::asm::wfe();
    }
}
