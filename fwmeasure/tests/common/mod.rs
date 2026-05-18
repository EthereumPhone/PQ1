//! Minimal ELF32 (LE, ARM) builder for `fwmeasure` integration tests.
//!
//! Hand-crafted byte writer — produces an ELF that the `object` crate
//! can parse and whose symbol/program-header surface is exactly what
//! `fwmeasure` reads. Keeps test fixtures hermetic (no dependency on a
//! pre-built `secure.elf`) and lets each test pin a precise input.

#![allow(dead_code)]

use std::process::{Command, Output};

pub const ET_EXEC: u16 = 2;
pub const EM_ARM: u16 = 0x28;
pub const PT_LOAD: u32 = 1;
pub const PT_NOTE: u32 = 4;
pub const PT_PHDR: u32 = 6;

pub const SHT_NULL: u32 = 0;
pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;

pub const STB_GLOBAL: u8 = 1;
pub const STT_NOTYPE: u8 = 0;

pub const ELF_HEADER_SIZE: usize = 52;
pub const PHDR_SIZE: usize = 32;
pub const SHDR_SIZE: usize = 40;
pub const SYM_SIZE: usize = 16;

#[derive(Clone)]
pub struct Segment {
    pub p_type: u32,
    pub paddr: u32,
    pub vaddr: u32,
    pub data: Vec<u8>,
    /// If Some, p_memsz is set explicitly (else equals data.len()).
    pub memsz: Option<u32>,
}

impl Segment {
    pub fn load(paddr: u32, data: Vec<u8>) -> Self {
        Self {
            p_type: PT_LOAD,
            paddr,
            vaddr: paddr,
            data,
            memsz: None,
        }
    }
    pub fn note(data: Vec<u8>) -> Self {
        Self {
            p_type: PT_NOTE,
            paddr: 0,
            vaddr: 0,
            data,
            memsz: None,
        }
    }
}

#[derive(Default, Clone)]
pub struct ElfBuilder {
    pub segments: Vec<Segment>,
    /// (name, value). All symbols get STB_GLOBAL+STT_NOTYPE, st_shndx = 1 (.text-ish).
    pub symbols: Vec<(String, u32)>,
}

impl ElfBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_segment(mut self, seg: Segment) -> Self {
        self.segments.push(seg);
        self
    }

    pub fn add_symbol(mut self, name: &str, value: u32) -> Self {
        self.symbols.push((name.to_string(), value));
        self
    }

    pub fn add_default_symbols(self, sidata: u32, sdata: u32, edata: u32) -> Self {
        self.add_symbol("__sidata", sidata)
            .add_symbol("__sdata", sdata)
            .add_symbol("__edata", edata)
    }

    pub fn build(self) -> Vec<u8> {
        // String table for symbol names (.strtab). Starts with NUL byte
        // (offset 0 → empty name).
        let mut strtab: Vec<u8> = vec![0];
        let mut sym_name_offsets: Vec<u32> = Vec::with_capacity(self.symbols.len());
        for (name, _) in &self.symbols {
            sym_name_offsets.push(strtab.len() as u32);
            strtab.extend_from_slice(name.as_bytes());
            strtab.push(0);
        }

        // Section name string table (.shstrtab).
        // Section indices we will emit:
        //   0: NULL
        //   1: .symtab
        //   2: .strtab
        //   3: .shstrtab
        let mut shstrtab: Vec<u8> = vec![0];
        let symtab_name = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".symtab\0");
        let strtab_name = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".strtab\0");
        let shstrtab_name = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".shstrtab\0");

        // Symbol table bytes. Index 0 must be the null symbol.
        let mut symtab: Vec<u8> = vec![0u8; SYM_SIZE];
        for (i, (_, value)) in self.symbols.iter().enumerate() {
            let mut entry = [0u8; SYM_SIZE];
            entry[0..4].copy_from_slice(&sym_name_offsets[i].to_le_bytes());
            entry[4..8].copy_from_slice(&value.to_le_bytes());
            entry[8..12].copy_from_slice(&0u32.to_le_bytes());
            // st_info: (STB_GLOBAL << 4) | STT_NOTYPE
            entry[12] = (STB_GLOBAL << 4) | STT_NOTYPE;
            entry[13] = 0;
            // st_shndx = 1 → ".symtab" works as a placeholder section
            // index; object's symbol reader only cares that it is
            // non-zero for defined symbols. We use 1 (any valid index).
            entry[14..16].copy_from_slice(&1u16.to_le_bytes());
            symtab.extend_from_slice(&entry);
        }

        let num_segments = self.segments.len();
        let num_sections: u16 = 4; // NULL, .symtab, .strtab, .shstrtab

        // Layout:
        //   [0]                ELF header
        //   [phoff]             program headers
        //   [shoff]             section headers
        //   [shstrtab_off]      .shstrtab bytes
        //   [strtab_off]        .strtab bytes
        //   [symtab_off]        .symtab bytes
        //   [seg_data_off ...]  PT_LOAD/PT_NOTE/etc. data (in order)
        let phoff = ELF_HEADER_SIZE;
        let shoff = phoff + num_segments * PHDR_SIZE;
        let shstrtab_off = shoff + (num_sections as usize) * SHDR_SIZE;
        let strtab_off = shstrtab_off + shstrtab.len();
        let symtab_off = strtab_off + strtab.len();

        // Segment data offsets follow.
        let mut seg_offsets: Vec<u32> = Vec::with_capacity(num_segments);
        let mut cursor = symtab_off + symtab.len();
        for seg in &self.segments {
            seg_offsets.push(cursor as u32);
            cursor += seg.data.len();
        }
        let total_size = cursor;

        let mut out = vec![0u8; total_size];

        // --- ELF header ---
        out[0..4].copy_from_slice(b"\x7FELF");
        out[4] = 1; // ELFCLASS32
        out[5] = 1; // ELFDATA2LSB
        out[6] = 1; // EV_CURRENT
        // 7..16 stay zero
        out[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        out[18..20].copy_from_slice(&EM_ARM.to_le_bytes());
        out[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
        out[24..28].copy_from_slice(&0u32.to_le_bytes()); // e_entry
        out[28..32].copy_from_slice(&(phoff as u32).to_le_bytes());
        out[32..36].copy_from_slice(&(shoff as u32).to_le_bytes());
        out[36..40].copy_from_slice(&0u32.to_le_bytes()); // e_flags
        out[40..42].copy_from_slice(&(ELF_HEADER_SIZE as u16).to_le_bytes());
        out[42..44].copy_from_slice(&(PHDR_SIZE as u16).to_le_bytes());
        out[44..46].copy_from_slice(&(num_segments as u16).to_le_bytes());
        out[46..48].copy_from_slice(&(SHDR_SIZE as u16).to_le_bytes());
        out[48..50].copy_from_slice(&num_sections.to_le_bytes());
        // e_shstrndx: index of .shstrtab section (3 in our layout).
        out[50..52].copy_from_slice(&3u16.to_le_bytes());

        // --- Program headers ---
        for (i, seg) in self.segments.iter().enumerate() {
            let off = phoff + i * PHDR_SIZE;
            let memsz = seg.memsz.unwrap_or(seg.data.len() as u32);
            out[off..off + 4].copy_from_slice(&seg.p_type.to_le_bytes());
            out[off + 4..off + 8].copy_from_slice(&seg_offsets[i].to_le_bytes());
            out[off + 8..off + 12].copy_from_slice(&seg.vaddr.to_le_bytes());
            out[off + 12..off + 16].copy_from_slice(&seg.paddr.to_le_bytes());
            out[off + 16..off + 20].copy_from_slice(&(seg.data.len() as u32).to_le_bytes());
            out[off + 20..off + 24].copy_from_slice(&memsz.to_le_bytes());
            out[off + 24..off + 28].copy_from_slice(&5u32.to_le_bytes()); // p_flags = R+X
            out[off + 28..off + 32].copy_from_slice(&4u32.to_le_bytes()); // p_align
        }

        // --- Section headers ---
        // Section 0: NULL
        // (already zero)

        // Helper to fill one section header.
        let mut write_shdr = |idx: usize,
                              sh_name: u32,
                              sh_type: u32,
                              sh_offset: u32,
                              sh_size: u32,
                              sh_link: u32,
                              sh_entsize: u32| {
            let off = shoff + idx * SHDR_SIZE;
            out[off..off + 4].copy_from_slice(&sh_name.to_le_bytes());
            out[off + 4..off + 8].copy_from_slice(&sh_type.to_le_bytes());
            // sh_flags, sh_addr remain zero
            out[off + 16..off + 20].copy_from_slice(&sh_offset.to_le_bytes());
            out[off + 20..off + 24].copy_from_slice(&sh_size.to_le_bytes());
            out[off + 24..off + 28].copy_from_slice(&sh_link.to_le_bytes());
            // sh_info: for symtab, one past last local symbol.
            // We mark every user-supplied symbol as global, so first
            // global is index 1 → sh_info = 1.
            let sh_info: u32 = if sh_type == SHT_SYMTAB { 1 } else { 0 };
            out[off + 28..off + 32].copy_from_slice(&sh_info.to_le_bytes());
            out[off + 32..off + 36].copy_from_slice(&4u32.to_le_bytes()); // align
            out[off + 36..off + 40].copy_from_slice(&sh_entsize.to_le_bytes());
        };
        // Section 1: .symtab → strtab at section index 2
        write_shdr(
            1,
            symtab_name,
            SHT_SYMTAB,
            symtab_off as u32,
            symtab.len() as u32,
            2,
            SYM_SIZE as u32,
        );
        // Section 2: .strtab
        write_shdr(
            2,
            strtab_name,
            SHT_STRTAB,
            strtab_off as u32,
            strtab.len() as u32,
            0,
            0,
        );
        // Section 3: .shstrtab
        write_shdr(
            3,
            shstrtab_name,
            SHT_STRTAB,
            shstrtab_off as u32,
            shstrtab.len() as u32,
            0,
            0,
        );

        // --- String tables and symtab ---
        out[shstrtab_off..shstrtab_off + shstrtab.len()].copy_from_slice(&shstrtab);
        out[strtab_off..strtab_off + strtab.len()].copy_from_slice(&strtab);
        out[symtab_off..symtab_off + symtab.len()].copy_from_slice(&symtab);

        // --- Segment data ---
        for (i, seg) in self.segments.iter().enumerate() {
            let off = seg_offsets[i] as usize;
            out[off..off + seg.data.len()].copy_from_slice(&seg.data);
        }

        out
    }
}

/// Build a minimal "valid" ELF: one PT_LOAD at `base` containing
/// `payload`, with the four canonical symbols positioned so the
/// `__sidata + (edata - sdata)` fallback yields `flash_end`.
pub fn minimal_elf(base: u32, payload: &[u8], flash_end: u32) -> Vec<u8> {
    // Pick (sidata, sdata, edata) so that sidata + (edata - sdata) == flash_end.
    // Simple choice: sdata = 0, edata = (flash_end - sidata), sidata = base.
    // → sidata + (edata - sdata) = base + flash_end - base = flash_end.
    let sidata = base;
    let sdata = 0;
    let edata = flash_end.saturating_sub(base);
    ElfBuilder::new()
        .add_segment(Segment::load(base, payload.to_vec()))
        .add_default_symbols(sidata, sdata, edata)
        .build()
}

/// Spawn the `fwmeasure` binary with the given args. Returns the full
/// process output (stdout/stderr/status).
pub fn run_fwmeasure<I, S>(args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let exe = env!("CARGO_BIN_EXE_fwmeasure");
    Command::new(exe)
        .args(args)
        .output()
        .expect("spawning fwmeasure")
}

/// Parse the 8 "N word" lines from `fwmeasure` stdout into a vector
/// of (index, word) pairs.
pub fn parse_words(stdout: &str) -> Vec<(u32, String)> {
    stdout
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(2, ' ');
            let idx = parts.next()?.parse::<u32>().ok()?;
            let word = parts.next()?.to_string();
            Some((idx, word))
        })
        .collect()
}
