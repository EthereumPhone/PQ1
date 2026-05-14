//! Host-side firmware measurement tool.
//!
//! Reads a secure-world ELF, reconstructs the flash image, SHA-256
//! hashes it, and outputs 8 BIP-39 words. The device displays the
//! same 8 words at boot so the user can visually compare.
//!
//! Usage:
//!
//!   cargo run -p fwmeasure -- path/to/sphincs-tz-secure
//!   cargo run -p fwmeasure -- path/to/image.elf --flash-base 0x0C00_E000
//!
//! Or via the Makefile:
//!
//!   make measure
//!
//! ## Slot-aware measurement
//!
//! The firmware-update subsystem places each A/B slot at a different
//! base address. When measuring a release artifact destined for a
//! specific slot, pass `--flash-base=<hex>` to override the computed
//! base (the default uses the lowest `p_paddr` of the ELF's LOAD
//! segments, which is correct for the whole-firmware measurement but
//! not for per-slot measurement). Optional `--flash-end=<hex>`
//! overrides the measurement end — useful when the ELF was linked
//! at a different base than it will ultimately land.

use object::elf::PT_LOAD;
use object::read::elf::{ElfFile32, ProgramHeader};
use object::{LittleEndian, Object, ObjectSymbol};
use sha2::{Digest, Sha256};
use sphincs_tz_bip39::{hash_to_word_indices, WORDLIST};
use std::fmt::Display;
use std::{env, fs, process};

/// Maximum plausible flash region (2 MB). Used to sanity-check
/// `__veneer_limit` — if it's beyond this offset from flash base,
/// it's in a different memory region (e.g. QEMU NSC at 0x103FF000).
const MAX_FLASH_SIZE: u64 = 2 * 1024 * 1024;

const USAGE: &str = "Usage: fwmeasure <firmware.elf> [--flash-base=0xHEX] [--flash-end=0xHEX]";

/// Parsed command-line arguments.
struct Args {
    elf_path: String,
    flash_base_override: Option<u64>,
    flash_end_override: Option<u64>,
}

/// Resolved flash region for this measurement.
struct FlashLayout {
    base: u64,
    end: u64,
}

impl FlashLayout {
    fn size(&self) -> usize {
        (self.end - self.base) as usize
    }
}

fn die(msg: impl Display) -> ! {
    eprintln!("{msg}");
    process::exit(1);
}

fn parse_args() -> Args {
    let mut elf_path: Option<String> = None;
    let mut flash_base_override: Option<u64> = None;
    let mut flash_end_override: Option<u64> = None;

    for arg in env::args().skip(1) {
        if let Some(rest) = arg.strip_prefix("--flash-base=") {
            flash_base_override = Some(parse_hex(rest));
        } else if let Some(rest) = arg.strip_prefix("--flash-end=") {
            flash_end_override = Some(parse_hex(rest));
        } else if let Some(prev) = elf_path.as_deref() {
            die(format_args!("Multiple ELF paths: {prev:?} and {arg:?}"));
        } else {
            elf_path = Some(arg);
        }
    }

    Args {
        elf_path: elf_path.unwrap_or_else(|| die(USAGE)),
        flash_base_override,
        flash_end_override,
    }
}

fn parse_hex(s: &str) -> u64 {
    let cleaned = s.trim_start_matches("0x").replace('_', "");
    u64::from_str_radix(&cleaned, 16)
        .unwrap_or_else(|e| die(format_args!("Cannot parse hex address {s:?}: {e}")))
}

fn require_symbol(elf: &ElfFile32<LittleEndian>, name: &str) -> u64 {
    find_symbol(elf, name).unwrap_or_else(|| die(format_args!("ELF missing {name} symbol")))
}

fn find_symbol(elf: &ElfFile32<LittleEndian>, name: &str) -> Option<u64> {
    elf.symbols()
        .find(|s| s.name() == Ok(name))
        .map(|s| s.address())
}

/// Resolve the flash region to measure.
///
/// Base defaults to the lowest `p_paddr` of any non-empty LOAD
/// segment (this is where probe-rs writes during download). End
/// defaults to `__veneer_limit` when it lies inside the plausible
/// flash window, else falls back to `__sidata + (__edata - __sdata)`
/// — needed on QEMU where `build.rs` redirects `.gnu.sgstubs` to a
/// separate NSC region above the flash.
fn compute_layout(elf: &ElfFile32<LittleEndian>, args: &Args) -> FlashLayout {
    let le = LittleEndian;
    let computed_base = elf
        .elf_program_headers()
        .iter()
        .filter(|ph| ph.p_type(le) == PT_LOAD && ph.p_filesz(le) > 0)
        .map(|ph| u64::from(ph.p_paddr(le)))
        .min()
        .unwrap_or_else(|| die("No LOAD segments found in ELF"));
    let base = args.flash_base_override.unwrap_or(computed_base);

    let end = args.flash_end_override.unwrap_or_else(|| {
        let veneer_limit = find_symbol(elf, "__veneer_limit");
        match veneer_limit {
            Some(vl) if (base..base + MAX_FLASH_SIZE).contains(&vl) => vl,
            _ => {
                let sidata = require_symbol(elf, "__sidata");
                let sdata = require_symbol(elf, "__sdata");
                let edata = require_symbol(elf, "__edata");
                sidata + (edata - sdata)
            }
        }
    });

    FlashLayout { base, end }
}

/// Reconstruct the on-flash image: erased flash (`0xFF`) overlaid
/// with each LOAD segment at its physical address.
fn build_flash_image(
    elf: &ElfFile32<LittleEndian>,
    elf_data: &[u8],
    layout: &FlashLayout,
) -> Vec<u8> {
    let le = LittleEndian;
    let size = layout.size();
    let mut flash = vec![0xFFu8; size];

    for ph in elf.elf_program_headers() {
        if ph.p_type(le) != PT_LOAD {
            continue;
        }
        let paddr = u64::from(ph.p_paddr(le));
        let filesz = ph.p_filesz(le) as usize;
        if filesz == 0 || paddr < layout.base || paddr >= layout.end {
            continue;
        }

        let offset = (paddr - layout.base) as usize;
        let data = ph
            .data(le, elf_data)
            .unwrap_or_else(|_| die(format_args!("Cannot read segment data at p_paddr {paddr:#010X}")));
        let copy_len = data.len().min(size - offset);
        flash[offset..offset + copy_len].copy_from_slice(&data[..copy_len]);
    }

    flash
}

fn format_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Print the 8 BIP-39 words to stdout, one per line ("N word").
/// `make verify-release` greps stdout for these.
fn print_words(hash: &[u8; 32]) {
    for (i, &idx) in hash_to_word_indices(hash).iter().enumerate() {
        println!("{} {}", i + 1, WORDLIST[idx as usize]);
    }
}

fn main() {
    let args = parse_args();

    let elf_data = fs::read(&args.elf_path)
        .unwrap_or_else(|e| die(format_args!("Cannot read {}: {e}", args.elf_path)));
    let elf = ElfFile32::<LittleEndian>::parse(&*elf_data)
        .unwrap_or_else(|e| die(format_args!("Cannot parse ELF: {e}")));

    let layout = compute_layout(&elf, &args);
    let flash = build_flash_image(&elf, &elf_data, &layout);
    let hash: [u8; 32] = Sha256::digest(&flash).into();

    eprintln!("Flash base:  0x{:08X}", layout.base);
    eprintln!("Flash end:   0x{:08X} ({} bytes)", layout.end, layout.size());
    eprintln!("SHA-256:     {}", format_hex(&hash));
    eprintln!();

    print_words(&hash);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_accepts_prefix_and_underscores() {
        assert_eq!(parse_hex("0x0C00_E000"), 0x0C00_E000);
        assert_eq!(parse_hex("0C00E000"), 0x0C00_E000);
        assert_eq!(parse_hex("0x0"), 0);
    }

    #[test]
    fn format_hex_lowercase_zero_padded() {
        assert_eq!(format_hex(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(format_hex(&[]), "");
    }
}
