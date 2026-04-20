//! ELF → flat flash image conversion.
//!
//! Mirrors exactly what `fwmeasure` does for the boot-time measurement,
//! so the SHA-256 this module computes matches what the device recomputes
//! at boot (and what FSBL checks against `manifest.secure_hash`).
//!
//! The key invariant: the "meaningful" portion of the flash image covers
//! `[lowest p_paddr, measurement_end)`, where `measurement_end` is
//! `__veneer_limit` on real hardware (veneers stay in flash) and
//! `__sidata + (__edata - __sdata)` on QEMU (veneers live in NSC). Any
//! gaps inside this range are filled with 0xFF (erased flash). Anything
//! beyond this range is outside what the device hashes and is not
//! included.

use anyhow::{anyhow, bail, Context, Result};
use object::elf::PT_LOAD;
use object::read::elf::{ElfFile32, ProgramHeader};
use object::{LittleEndian, Object, ObjectSymbol};
use sha2::{Digest, Sha256};

/// Maximum plausible flash region — used to sanity-check `__veneer_limit`.
/// On any build where `__veneer_limit` is outside `[flash_base, flash_base
/// + MAX_FLASH_SIZE)` (e.g. QEMU, where veneers are in NSC at
/// 0x103F_F000) we fall back to the `__sidata + data_size` heuristic.
pub const MAX_FLASH_SIZE: u64 = 2 * 1024 * 1024;

/// Result of flattening an ELF: the meaningful bytes, the base address
/// they're mapped at, and the SHA-256 over them.
pub struct FlatImage {
    pub bytes: Vec<u8>,
    pub base: u64,
    pub hash: [u8; 32],
}

impl FlatImage {
    pub fn len(&self) -> u32 {
        self.bytes.len() as u32
    }
}

/// Reconstruct the measurement-region bytes and compute their SHA-256.
/// Identical logic to `fwmeasure/src/main.rs` — any change here must be
/// mirrored there or the host tool will disagree with on-device
/// measurement.
pub fn flatten_elf(elf_path: &std::path::Path) -> Result<FlatImage> {
    let elf_data = std::fs::read(elf_path)
        .with_context(|| format!("reading ELF {}", elf_path.display()))?;
    let elf = ElfFile32::<LittleEndian>::parse(&*elf_data)
        .map_err(|e| anyhow!("parsing ELF {}: {e}", elf_path.display()))?;

    let find_sym = |name: &str| -> Option<u64> {
        elf.symbols()
            .find(|s| s.name() == Ok(name))
            .map(|s| s.address())
    };

    let veneer_limit = find_sym("__veneer_limit");
    let sidata = find_sym("__sidata")
        .ok_or_else(|| anyhow!("{}: missing __sidata symbol", elf_path.display()))?;
    let sdata = find_sym("__sdata")
        .ok_or_else(|| anyhow!("{}: missing __sdata symbol", elf_path.display()))?;
    let edata = find_sym("__edata")
        .ok_or_else(|| anyhow!("{}: missing __edata symbol", elf_path.display()))?;

    let le = LittleEndian;
    let phdrs = elf.elf_program_headers();

    let flash_base = phdrs
        .iter()
        .filter(|ph| ph.p_type(le) == PT_LOAD && ph.p_filesz(le) > 0)
        .map(|ph| ph.p_paddr(le) as u64)
        .min()
        .ok_or_else(|| anyhow!("{}: no PT_LOAD segments", elf_path.display()))?;

    let measurement_end = match veneer_limit {
        Some(vl) if vl >= flash_base && vl < flash_base + MAX_FLASH_SIZE => vl,
        _ => sidata + (edata - sdata),
    };

    if measurement_end <= flash_base {
        bail!(
            "{}: measurement_end ({measurement_end:#x}) <= flash_base ({flash_base:#x})",
            elf_path.display()
        );
    }

    let size = (measurement_end - flash_base) as usize;
    let mut flash = vec![0xFFu8; size];

    for ph in phdrs.iter() {
        if ph.p_type(le) != PT_LOAD {
            continue;
        }
        let paddr = ph.p_paddr(le) as u64;
        let filesz = ph.p_filesz(le) as usize;
        if paddr < flash_base || paddr >= measurement_end || filesz == 0 {
            continue;
        }
        let offset = (paddr - flash_base) as usize;
        let data = ph
            .data(le, &*elf_data)
            .map_err(|_| anyhow!("cannot read PT_LOAD data at {paddr:#x}"))?;
        let copy_len = core::cmp::min(data.len(), size - offset);
        flash[offset..offset + copy_len].copy_from_slice(&data[..copy_len]);
    }

    let hash: [u8; 32] = Sha256::digest(&flash).into();

    Ok(FlatImage {
        bytes: flash,
        base: flash_base,
        hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build the real secure ELF and confirm we produce the same
    // measurement the device would. Skipped in CI if the ELF isn't
    // already built.
    #[test]
    fn flatten_matches_fwmeasure() {
        let elf = std::path::PathBuf::from(
            "../target/secure/thumbv8m.main-none-eabi/release/sphincs-tz-secure",
        );
        if !elf.exists() {
            eprintln!("skipping — run `make secure` first");
            return;
        }
        let img = flatten_elf(&elf).unwrap();
        // Can only sanity-check; the real validation is that
        // `fwmeasure` and this produce identical hashes. That's
        // checked by the integration test in tests/.
        assert!(!img.bytes.is_empty());
        assert!(img.base > 0);
    }
}
