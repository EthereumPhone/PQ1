//! Slot geometry constants — copied from `secure/src/hw/flash.rs` so the
//! FSBL has no dependency on the secure crate.
//!
//! **Keep these in sync.** Changing the slot layout in one place and
//! not the other will make FSBL boot into the wrong address, which is
//! caught by the image-hash check but wastes a commit cycle. There's a
//! sanity test in `tests/slot_layout_matches_secure.rs` (in fsbl/
//! crate) that imports `fw-manifest` + the secure-side constants and
//! compares them — but that test has to compile on the host, so the
//! actual constants here are the source of truth for FSBL and a TODO
//! is to extract them into a tiny shared crate.

/// A/B slot identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    A,
    B,
}

impl Slot {
    #[allow(dead_code)]
    pub const fn other(self) -> Self {
        match self {
            Slot::A => Slot::B,
            Slot::B => Slot::A,
        }
    }
}

// --- Manifest page addresses ---
pub const MANIFEST_A_ADDR: usize = 0x0C00_8000;
pub const MANIFEST_B_ADDR: usize = 0x0C00_A000;

pub const fn manifest_addr(slot: Slot) -> usize {
    match slot {
        Slot::A => MANIFEST_A_ADDR,
        Slot::B => MANIFEST_B_ADDR,
    }
}

// --- Slot image addresses ---
pub const SLOT_A_SECURE_ADDR: usize = 0x0C00_E000;
pub const SLOT_B_SECURE_ADDR: usize = 0x0C08_2000;
pub const SLOT_A_NS_ADDR: usize = 0x0810_0000;
pub const SLOT_B_NS_ADDR: usize = 0x0818_0000;

pub const fn slot_secure_addr(slot: Slot) -> usize {
    match slot {
        Slot::A => SLOT_A_SECURE_ADDR,
        Slot::B => SLOT_B_SECURE_ADDR,
    }
}

pub const fn slot_ns_addr(slot: Slot) -> usize {
    match slot {
        Slot::A => SLOT_A_NS_ADDR,
        Slot::B => SLOT_B_NS_ADDR,
    }
}

/// Secure-slot capacity — 58 pages × 8 KB.
pub const SLOT_SECURE_CAPACITY: u32 = 58 * 8 * 1024;
/// NS-slot capacity — 64 pages × 8 KB.
pub const SLOT_NS_CAPACITY: u32 = 64 * 8 * 1024;
