//! Host-side firmware measurement tool.
//!
//! Reads a secure-world ELF, reconstructs the flash image, SHA-256
//! hashes it, and outputs 8 BIP-39 words. The device displays the
//! same 8 words at boot so the user can visually compare.
//!
//! Usage:
//!
//!   cargo run -p fwmeasure -- path/to/sphincs-tz-secure
//!
//! Or via the Makefile:
//!
//!   make measure

use object::elf::PT_LOAD;
use object::read::elf::{ElfFile32, ProgramHeader};
use object::{LittleEndian, Object, ObjectSymbol};
use sha2::{Digest, Sha256};
use sphincs_tz_bip39::{hash_to_word_indices, WORDLIST};
use std::{env, fs, process};

/// Maximum plausible flash region (2 MB). Used to sanity-check
/// `__veneer_limit` — if it's beyond this offset from flash base,
/// it's in a different memory region (e.g. QEMU NSC at 0x103FF000).
const MAX_FLASH_SIZE: u64 = 2 * 1024 * 1024;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: fwmeasure <firmware.elf>");
        process::exit(1);
    }

    let elf_data = fs::read(&args[1]).unwrap_or_else(|e| {
        eprintln!("Cannot read {}: {e}", args[1]);
        process::exit(1);
    });

    let elf = ElfFile32::<LittleEndian>::parse(&*elf_data).unwrap_or_else(|e| {
        eprintln!("Cannot parse ELF: {e}");
        process::exit(1);
    });

    // ---- Find linker symbols ------------------------------------------------

    let find_sym = |name: &str| -> Option<u64> {
        elf.symbols()
            .find(|s| s.name() == Ok(name))
            .map(|s| s.address())
    };

    let veneer_limit = find_sym("__veneer_limit");
    let sidata = find_sym("__sidata").expect("ELF missing __sidata symbol");
    let sdata = find_sym("__sdata").expect("ELF missing __sdata symbol");
    let edata = find_sym("__edata").expect("ELF missing __edata symbol");

    // ---- Determine flash base from lowest p_paddr of LOAD segments ----------

    let le = LittleEndian;
    let phdrs = elf.elf_program_headers();

    let flash_base = phdrs
        .iter()
        .filter(|ph| ph.p_type(le) == PT_LOAD && ph.p_filesz(le) > 0)
        .map(|ph| ph.p_paddr(le) as u64)
        .min()
        .expect("No LOAD segments found in ELF");

    // ---- Determine measurement end ------------------------------------------

    // On STM32U585, __veneer_limit is in FLASH (veneers go to > FLASH).
    // On QEMU, build.rs redirects .gnu.sgstubs to > NSC (0x103FF000+),
    // so __veneer_limit is NOT in the flash region. Fall back to the end
    // of .data initial values: __sidata + (__edata - __sdata).
    let measurement_end = match veneer_limit {
        Some(vl) if vl >= flash_base && vl < flash_base + MAX_FLASH_SIZE => vl,
        _ => sidata + (edata - sdata),
    };

    let size = (measurement_end - flash_base) as usize;

    eprintln!(
        "Flash base:  0x{flash_base:08X}");
    eprintln!(
        "Flash end:   0x{measurement_end:08X} ({size} bytes)");

    // ---- Build flash image --------------------------------------------------

    // Initialize to 0xFF (erased flash). LOAD segments are overlaid at
    // their physical addresses (p_paddr), which is where probe-rs writes
    // them during download.
    let mut flash = vec![0xFFu8; size];

    for ph in phdrs.iter() {
        if ph.p_type(le) != PT_LOAD {
            continue;
        }
        let paddr = ph.p_paddr(le) as u64;
        let filesz = ph.p_filesz(le) as usize;

        // Skip segments outside the measurement range.
        if paddr < flash_base || paddr >= measurement_end || filesz == 0 {
            continue;
        }

        let offset = (paddr - flash_base) as usize;
        let data = ph.data(le, &*elf_data).unwrap_or_else(|_| {
            eprintln!("Cannot read segment data at p_paddr 0x{paddr:08X}");
            process::exit(1);
        });
        let copy_len = core::cmp::min(data.len(), size - offset);
        flash[offset..offset + copy_len].copy_from_slice(&data[..copy_len]);
    }

    // ---- Hash and convert to 8 BIP-39 words ---------------------------------

    let hash: [u8; 32] = Sha256::digest(&flash).into();
    let indices = hash_to_word_indices(&hash);

    eprintln!(
        "SHA-256:     {}",
        hash.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    eprintln!();

    for (i, &idx) in indices.iter().enumerate() {
        println!("{} {}", i + 1, WORDLIST[idx as usize]);
    }
}
