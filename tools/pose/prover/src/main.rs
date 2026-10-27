//! PQ1 proof-of-secure-erasure prover (EVT experiment).
//!
//! Design: `docs/security/user-device-verification.md` § USB path. The prover
//! sits in bank-1 pages `0..PROVER_PAGES` and boots from SECBOOTADD0 in the
//! secure state. Over USB HID it lets the host:
//!
//! - erase and program every flash page outside its own pages (space 0);
//! - read ALL of flash back, its own pages included;
//! - write/read an SRAM3 canary, backup SRAM and the TAMP backup registers;
//! - read the option-byte registers, UID and OTP (space 4, the info blob).
//!
//! It has no option-byte, OTP or RDP write path, never powers the secure
//! elements, and refuses any flash write below `PROVER_BYTES`.
//!
//! Wire format: 64-byte reports, byte 0 is the opcode. See `tools/pose/README.md`.

#![no_std]
#![no_main]

use core::ptr::{read_volatile, write_volatile};

use cortex_m_rt::entry;
use panic_halt as _;
use synopsys_usb_otg::{PhyType, UsbBus, UsbPeripheral};
use usb_device::prelude::*;

mod hid;

// ---- Layout (keep PROVER_PAGES in step with memory.x) ----------------------

const PROVER_PAGES: u32 = 2;
const PAGE: u32 = 0x2000;
const BANK_LEN: u32 = 128 * PAGE;
const FLASH_LEN: u32 = 2 * BANK_LEN;
const PROVER_BYTES: u32 = PROVER_PAGES * PAGE;
/// Bank 1, secure alias (SECWM1 covers the whole bank on the EVT).
const BANK1: u32 = 0x0C00_0000;
/// Bank 2, non-secure alias (SECWM2 empty on the EVT).
const BANK2: u32 = 0x0810_0000;

const CANARY: u32 = 0x3004_0000; // SRAM3, secure alias
const CANARY_LEN: u32 = 0x1_0000;
#[cfg(feature = "cheat-ram-hold")]
const HOLD: u32 = 0x3005_0000; // SRAM3, after the canary
#[cfg(feature = "cheat-ram-hold")]
const HOLD_LEN: u32 = 0x1_0000;
const BKPSRAM: u32 = 0x5003_6400;
const BKPSRAM_LEN: u32 = 0x800;
const TAMP_BKP: u32 = 0x5600_7C00 + 0x100;
const TAMP_BKP_LEN: u32 = 32 * 4;
const INFO_LEN: u32 = 640;

// ---- Registers -------------------------------------------------------------

const RCC: u32 = 0x5602_0C00;
const PWR: u32 = 0x5602_0800;
const FLASH_S: u32 = 0x5002_2000;
const FLASH_NS: u32 = 0x4002_2000;
const GPIOA: u32 = 0x5202_0000;
const CRS_NS: u32 = 0x4000_6000;
const OTG: u32 = 0x4204_0000;
const OTP: u32 = 0x0BFA_0000;
const UID: u32 = 0x0BFA_0700;
const FLASHSIZE: u32 = 0x0BFA_07A0;

const BSY: u32 = 1 << 16;
const ERR_MASK: u32 = 0xFA;
const PG: u32 = 1 << 0;
const PER: u32 = 1 << 1;
const BKER: u32 = 1 << 11;
const STRT: u32 = 1 << 16;
const LOCK: u32 = 1 << 31;

fn rd(a: u32) -> u32 {
    // SAFETY: every caller passes a 4-byte-aligned MMIO or memory address
    // from the tables above, inside a region this image owns.
    unsafe { read_volatile(a as *const u32) }
}

fn wr(a: u32, v: u32) {
    // SAFETY: as `rd`.
    unsafe { write_volatile(a as *mut u32, v) }
}

fn set(a: u32, bits: u32) {
    wr(a, rd(a) | bits);
}

// ---- Bring-up (lifted from secure/src/hw/{rcc,usb_hw,sau}.rs) --------------

fn clocks() {
    set(RCC + 0x94, 1 << 2); // AHB3ENR.PWREN
    set(PWR + 0x2C, 1 << 0); // UCPDR.UCPD_DBDIS (pq1)
    set(RCC, 1 << 8); // HSION
    while rd(RCC) & (1 << 10) == 0 {}
    wr(PWR + 0x0C, (rd(PWR + 0x0C) & !(0b111 << 16)) | (0b11 << 16) | (1 << 18)); // VOS1 + BOOSTEN
    while rd(PWR + 0x0C) & (1 << 15) == 0 {}
    wr(FLASH_S, (rd(FLASH_S) & !0xF) | 4); // 4 wait states; ICACHE stays off
    while rd(FLASH_S) & 0xF != 4 {}
    wr(RCC + 0x28, 0b10 | (0b11 << 2) | (1 << 18)); // PLL1: HSI16, 8-16 MHz, R out
    wr(RCC + 0x34, 19 | (1 << 24)); // N = 20, R = 2 -> 160 MHz
    set(RCC, 1 << 24);
    while rd(RCC) & (1 << 25) == 0 {}
    wr(RCC + 0x1C, (rd(RCC + 0x1C) & !0x3) | 0b11);
    while rd(RCC + 0x1C) & (0x3 << 2) != (0x3 << 2) {}
    set(RCC, 1 << 12); // HSI48ON (OTG kernel clock)
    while rd(RCC) & (1 << 13) == 0 {}
}

fn sau() {
    const CTRL: u32 = 0xE000_EDD0;
    let region = |n: u32, base: u32, limit: u32| {
        wr(0xE000_EDD8, n);
        wr(0xE000_EDDC, base & !0x1F);
        wr(0xE000_EDE0, (limit & !0x1F) | 1);
    };
    wr(CTRL, 0);
    region(0, BANK2, BANK2 + BANK_LEN - 1); // bank 2 through its NS alias
    region(1, 0x4000_0000, 0x4FFF_FFFF); // NS peripherals (OTG, CRS, NS flash regs)
    wr(CTRL, 1);
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
}

fn usb_hw() {
    set(RCC + 0x8C, 1 << 0); // GPIOAEN
    set(PWR + 0x10, 1 << 28); // SVMCR.USV
    set(RCC + 0x8C, 1 << 14); // OTGEN
    set(RCC + 0x64, 1 << 14);
    wr(RCC + 0x64, rd(RCC + 0x64) & !(1 << 14));
    set(RCC + 0x9C, 1 << 24); // CRSEN
    wr(CRS_NS, rd(CRS_NS) & !((1 << 6) | (1 << 5)));
    wr(CRS_NS + 0x04, (0b10 << 28) | (0x22 << 16) | 0xBB7F); // sync to USB SOF
    set(CRS_NS, (1 << 6) | (1 << 5));
    wr(GPIOA + 0x30, rd(GPIOA + 0x30) & !((1 << 11) | (1 << 12))); // PA11/12 -> NS
    wr(GPIOA, (rd(GPIOA) & !(0xF << 22)) | (0b1010 << 22)); // AF mode
    set(GPIOA + 0x08, 0xF << 22); // very high speed
    wr(GPIOA + 0x24, (rd(GPIOA + 0x24) & !(0xFF << 12)) | (0xAA << 12)); // AF10
}

fn backup_domain() {
    set(RCC + 0x88, 1 << 28); // AHB1ENR.BKPSRAMEN
    set(RCC + 0xA8, 1 << 21); // APB3ENR.RTCAPBEN
    set(RCC + 0x8C, (1 << 30) | (1 << 31)); // SRAM2EN | SRAM3EN
    wr(PWR + 0x28, 1); // DBPR.DBP: backup domain writable
    set(PWR + 0x20, 1); // BDCR1.BREN: worst case, keep backup SRAM on VBAT
}

struct OtgFs;

// SAFETY: OTG_FS register block at its NS alias (SAU region 1); the DWC2
// FIFO depth and endpoint count match `nonsecure/src/usb/mod.rs`.
unsafe impl UsbPeripheral for OtgFs {
    const REGISTERS: *const () = OTG as *const ();
    const HIGH_SPEED: bool = false;
    const FIFO_DEPTH_WORDS: usize = 320;
    const ENDPOINT_COUNT: usize = 6;

    fn enable() {}

    fn ahb_frequency_hz(&self) -> u32 {
        160_000_000
    }

    fn phy_type(&self) -> PhyType {
        PhyType::InternalFullSpeed
    }
}

/// The DWC2 core ID of the U5 is unknown to synopsys-usb-otg 0.4, so force
/// B-session valid by hand after the driver's core reset
/// (`nonsecure/src/usb/mod.rs::configure_vbus_u5`).
fn vbus_override() {
    wr(OTG + 0x38, rd(OTG + 0x38) & !(1 << 21));
    set(OTG, 0b11 << 6);
}

// ---- Flash -----------------------------------------------------------------

struct Ctl {
    keyr: u32,
    sr: u32,
    cr: u32,
}

const SEC: Ctl = Ctl { keyr: FLASH_S + 0x0C, sr: FLASH_S + 0x24, cr: FLASH_S + 0x2C };
const NS: Ctl = Ctl { keyr: FLASH_NS + 0x08, sr: FLASH_NS + 0x20, cr: FLASH_NS + 0x28 };

impl Ctl {
    fn begin(&self) {
        while rd(self.sr) & BSY != 0 {}
        wr(self.sr, rd(self.sr) & ERR_MASK);
        wr(self.keyr, 0x4567_0123);
        wr(self.keyr, 0xCDEF_89AB);
    }

    fn end(&self) -> Result<(), u32> {
        while rd(self.sr) & BSY != 0 {}
        wr(self.cr, 0);
        let sr = rd(self.sr);
        set(self.cr, LOCK);
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
        if sr & ERR_MASK != 0 {
            wr(self.sr, sr & ERR_MASK);
            Err(sr)
        } else {
            Ok(())
        }
    }
}

/// Flash offset (0..FLASH_LEN) -> (controller, CPU address, bank-2 flag).
fn locate(off: u32) -> (&'static Ctl, u32, bool) {
    if off < BANK_LEN {
        (&SEC, BANK1 + off, false)
    } else {
        (&NS, BANK2 + off - BANK_LEN, true)
    }
}

fn erase_page(page: u32) -> Result<(), u32> {
    if page < PROVER_PAGES || page >= 2 * 128 {
        return Err(0);
    }
    let (ctl, _, bank2) = locate(page * PAGE);
    let cr = PER | if bank2 { BKER } else { 0 } | ((page % 128) << 3);
    ctl.begin();
    wr(ctl.cr, cr);
    wr(ctl.cr, cr | STRT);
    ctl.end()
}

fn program_qw(off: u32, data: &[u8]) -> Result<(), u32> {
    if off < PROVER_BYTES || off >= FLASH_LEN || off % 16 != 0 {
        return Err(0);
    }
    #[cfg(feature = "cheat-skip-page")]
    if (BANK_LEN + 64 * PAGE..BANK_LEN + 65 * PAGE).contains(&off) {
        return Ok(());
    }
    let (ctl, addr, _) = locate(off);
    ctl.begin();
    wr(ctl.cr, PG);
    for i in 0..4 {
        let w = u32::from_le_bytes([data[4 * i], data[4 * i + 1], data[4 * i + 2], data[4 * i + 3]]);
        wr(addr + 4 * i as u32, w);
    }
    ctl.end()
}

// ---- Address spaces --------------------------------------------------------

const SP_FLASH: u8 = 0;
const SP_CANARY: u8 = 1;
const SP_BKPSRAM: u8 = 2;
const SP_TAMP: u8 = 3;
const SP_INFO: u8 = 4;

static mut INFO: [u8; INFO_LEN as usize] = [0; INFO_LEN as usize];

fn space(sp: u8) -> Option<(u32, u32)> {
    match sp {
        SP_FLASH => Some((0, FLASH_LEN)),
        SP_CANARY => Some((CANARY, CANARY_LEN)),
        SP_BKPSRAM => Some((BKPSRAM, BKPSRAM_LEN)),
        SP_TAMP => Some((TAMP_BKP, TAMP_BKP_LEN)),
        SP_INFO => Some((core::ptr::addr_of!(INFO) as u32, INFO_LEN)),
        _ => None,
    }
}

fn in_range(sp: u8, off: u32, len: u32) -> Option<u32> {
    let (base, size) = space(sp)?;
    (off % 4 == 0 && off <= size && len <= size - off).then_some(base)
}

fn read_word(sp: u8, base: u32, off: u32) -> u32 {
    if sp != SP_FLASH {
        return rd(base + off);
    }
    #[cfg(feature = "cheat-ram-hold")]
    if off >= FLASH_LEN - HOLD_LEN {
        return rd(HOLD + off - (FLASH_LEN - HOLD_LEN));
    }
    rd(locate(off).1)
}

fn write_chunk(sp: u8, off: u32, data: &[u8]) -> Result<(), u32> {
    let base = in_range(sp, off, data.len() as u32).ok_or(0u32)?;
    match sp {
        SP_FLASH => {
            for (i, qw) in data.chunks_exact(16).enumerate() {
                let o = off + 16 * i as u32;
                #[cfg(feature = "cheat-ram-hold")]
                if o >= FLASH_LEN - HOLD_LEN {
                    for (j, w) in qw.chunks_exact(4).enumerate() {
                        let v = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
                        wr(HOLD + o - (FLASH_LEN - HOLD_LEN) + 4 * j as u32, v);
                    }
                    continue;
                }
                program_qw(o, qw)?;
            }
            Ok(())
        }
        SP_CANARY | SP_BKPSRAM | SP_TAMP => {
            for (i, w) in data.chunks_exact(4).enumerate() {
                wr(base + off + 4 * i as u32, u32::from_le_bytes([w[0], w[1], w[2], w[3]]));
            }
            Ok(())
        }
        _ => Err(0),
    }
}

fn build_info() {
    let mut words = [0u32; 21];
    for (i, reg) in [0x40u32, 0x44, 0x48, 0x4C, 0x50, 0x54, 0x58, 0x5C, 0x60, 0x64, 0x68, 0x6C, 0xC0]
        .iter()
        .enumerate()
    {
        words[i] = rd(FLASH_S + reg);
    }
    words[13] = rd(UID);
    words[14] = rd(UID + 4);
    words[15] = rd(UID + 8);
    words[16] = rd(FLASHSIZE) & 0xFFFF;
    words[17] = rd(PWR + 0x20);
    words[18] = PROVER_PAGES;
    words[19] = cfg!(feature = "cheat-skip-page") as u32 | (cfg!(feature = "cheat-ram-hold") as u32) << 1;
    words[20] = rd(FLASH_NS + 0x20); // NSSR: OEM1LOCK/OEM2LOCK (lockdown.rs, unpinned)
    // SAFETY: single-threaded, no interrupts; INFO is only read by the
    // response streamer after this returns.
    let info = unsafe { &mut *core::ptr::addr_of_mut!(INFO) };
    for (i, w) in words.iter().enumerate() {
        info[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
    }
    for i in 0..128 {
        info[128 + 4 * i..132 + 4 * i].copy_from_slice(&rd(OTP + 4 * i as u32).to_le_bytes());
    }
}

// ---- Protocol --------------------------------------------------------------

const OP_HELLO: u8 = 0x01;
const OP_ERASE: u8 = 0x03;
const OP_WRITE: u8 = 0x04;
const OP_READ: u8 = 0x05;
const OP_STATUS: u8 = 0x07;
const REPLY_ERR: u8 = 0x8F;
const READ_DATA: usize = 56;
const WRITE_DATA: usize = 48;

struct Stream {
    sp: u8,
    base: u32,
    off: u32,
    end: u32,
    left: u16,
}

#[derive(Default)]
struct Status {
    failed: bool,
    sp: u8,
    off: u32,
    sr: u32,
    writes: u32,
}

fn u32_at(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

#[entry]
fn main() -> ! {
    clocks();
    sau();
    usb_hw();
    backup_domain();
    build_info();

    let ep_mem = cortex_m::singleton!(: [u32; 320] = [0; 320]).unwrap();
    let alloc = UsbBus::new(OtgFs, ep_mem);
    let mut hid = hid::Hid::new(&alloc);
    let mut dev = UsbDeviceBuilder::new(&alloc, UsbVidPid(0x1209, 0x7051))
        .strings(&[StringDescriptors::default()
            .manufacturer("PQSigner")
            .product("PQ1 PoSE prover")
            .serial_number("pose")])
        .unwrap()
        .max_packet_size_0(64)
        .unwrap()
        .build();
    vbus_override();

    let mut stream: Option<Stream> = None;
    let mut reply: Option<[u8; 64]> = None;
    let mut status = Status::default();
    let mut rx = [0u8; 64];

    loop {
        dev.poll(&mut [&mut hid]);

        if let Some(r) = reply {
            if hid.write(&r) {
                reply = None;
            }
            continue;
        }
        if let Some(s) = stream.as_mut() {
            let mut out = [0u8; 64];
            out[0] = 0x85;
            out[1] = s.sp;
            out[2..6].copy_from_slice(&s.off.to_le_bytes());
            for w in 0..READ_DATA / 4 {
                let o = s.off + 4 * w as u32;
                // The last report of a space may run past its end: pad with 0.
                let v = if o < s.end { read_word(s.sp, s.base, o) } else { 0 };
                out[6 + 4 * w..10 + 4 * w].copy_from_slice(&v.to_le_bytes());
            }
            if hid.write(&out) {
                s.off += READ_DATA as u32;
                s.left -= 1;
                if s.left == 0 {
                    stream = None;
                }
            }
            continue;
        }
        if !hid.read(&mut rx) {
            continue;
        }

        let mut out = [0u8; 64];
        out[0] = rx[0] | 0x80;
        match rx[0] {
            OP_HELLO => {
                build_info();
                out[1] = 1; // protocol version
                out[2..10].copy_from_slice(b"PQPOSE01");
                out[10..14].copy_from_slice(&PROVER_PAGES.to_le_bytes());
                out[14..18].copy_from_slice(&FLASH_LEN.to_le_bytes());
                reply = Some(out);
            }
            OP_ERASE => {
                let page = u16::from_le_bytes([rx[1], rx[2]]) as u32;
                match erase_page(page) {
                    Ok(()) => out[1] = 1,
                    Err(sr) => out[2..6].copy_from_slice(&sr.to_le_bytes()),
                }
                reply = Some(out);
            }
            OP_WRITE => {
                let off = u32_at(&rx, 2);
                status.writes += 1;
                // rx[6] = byte count (a multiple of 16, at most 48); data at rx[8..].
                let len = (rx[6] as usize).min(WRITE_DATA) & !15;
                if let Err(sr) = write_chunk(rx[1], off, &rx[8..8 + len]) {
                    if !status.failed {
                        status = Status { failed: true, sp: rx[1], off, sr, writes: status.writes };
                    }
                }
            }
            OP_READ => {
                let (sp, off) = (rx[1], u32_at(&rx, 2));
                let count = u16::from_le_bytes([rx[6], rx[7]]);
                // Every report must start inside the space; the tail of the last
                // one is zero-padded by the streamer.
                let len = (count as u32 * READ_DATA as u32).saturating_sub(READ_DATA as u32 - 4);
                match (in_range(sp, off, len), space(sp)) {
                    (Some(base), Some((_, size))) if count > 0 => {
                        stream = Some(Stream { sp, base, off, end: size, left: count })
                    }
                    _ => {
                        out[0] = REPLY_ERR;
                        reply = Some(out);
                    }
                }
            }
            OP_STATUS => {
                out[1] = status.failed as u8;
                out[2] = status.sp;
                out[4..8].copy_from_slice(&status.off.to_le_bytes());
                out[8..12].copy_from_slice(&status.sr.to_le_bytes());
                out[12..16].copy_from_slice(&status.writes.to_le_bytes());
                status = Status::default();
                reply = Some(out);
            }
            _ => {
                out[0] = REPLY_ERR;
                reply = Some(out);
            }
        }
    }
}
