//! Slot geometry constants — copied from `secure/src/hw/flash.rs` so the
//! FSBL has no dependency on the secure crate.
//!
//! **Keep these in sync.** Changing the slot layout in one place and
//! not the other will make FSBL boot into the wrong address, which is
//! caught by the image-hash check but wastes a commit cycle.
//!
//! Under `devunit-ab` every address comes from `fw_manifest::devunit`, the
//! one table the secure world and the host tools also read.

/// A/B slot identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    A,
    B,
}

// --- Manifest page addresses ---
const MANIFEST_A_ADDR: usize = 0x0C00_8000;
const MANIFEST_B_ADDR: usize = 0x0C00_A000;

pub const fn manifest_addr(slot: Slot) -> usize {
    match slot {
        Slot::A => MANIFEST_A_ADDR,
        Slot::B => MANIFEST_B_ADDR,
    }
}

// --- Slot image addresses ---
#[cfg(not(feature = "devunit-ab"))]
const SLOT_A_SECURE_ADDR: usize = 0x0C00_E000;
#[cfg(not(feature = "devunit-ab"))]
const SLOT_B_SECURE_ADDR: usize = 0x0C08_2000;
#[cfg(not(feature = "devunit-ab"))]
const SLOT_A_NS_ADDR: usize = 0x0810_0000;
#[cfg(not(feature = "devunit-ab"))]
const SLOT_B_NS_ADDR: usize = 0x0818_0000;

#[cfg(feature = "devunit-ab")]
const SLOT_A_SECURE_ADDR: usize = fw_manifest::devunit::SLOT_A_SECURE_ADDR as usize;
#[cfg(feature = "devunit-ab")]
const SLOT_B_SECURE_ADDR: usize = fw_manifest::devunit::SLOT_B_SECURE_ADDR as usize;
#[cfg(feature = "devunit-ab")]
const SLOT_A_NS_ADDR: usize = fw_manifest::devunit::SLOT_A_NS_ADDR as usize;
#[cfg(feature = "devunit-ab")]
const SLOT_B_NS_ADDR: usize = fw_manifest::devunit::SLOT_B_NS_ADDR as usize;

// The manifest pages did not move.
#[cfg(feature = "devunit-ab")]
const _: () = assert!(
    MANIFEST_A_ADDR == fw_manifest::devunit::MANIFEST_A_ADDR as usize
        && MANIFEST_B_ADDR == fw_manifest::devunit::MANIFEST_B_ADDR as usize
);

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

/// Slot capacities are shared with the updater and host signing tools.
#[cfg(not(feature = "devunit-ab"))]
pub use fw_manifest::{SLOT_NS_CAPACITY, SLOT_SECURE_CAPACITY};
#[cfg(feature = "devunit-ab")]
pub use fw_manifest::devunit::{
    NS_SLOT_CAPACITY as SLOT_NS_CAPACITY, SECURE_SLOT_CAPACITY as SLOT_SECURE_CAPACITY,
};

/// The `fw_manifest` slot id (`SLOT_A` / `SLOT_B`) for a slot.
#[cfg(feature = "devunit-ab")]
pub const fn id(slot: Slot) -> u8 {
    match slot {
        Slot::A => fw_manifest::SLOT_A,
        Slot::B => fw_manifest::SLOT_B,
    }
}
