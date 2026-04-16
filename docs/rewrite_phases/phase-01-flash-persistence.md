# Phase 1 — Flash persistence module (✅ done)

**Status:** complete. Documented here retrospectively so later phases have the
integration surface ready to cite.

## What was built

A double-buffered slot-state store at the top of secure flash bank 1. Each
commit writes a 128-byte record to whichever of two reserved pages is
currently idle, using a monotonic sequence number to decide which record is
the authoritative one on read. Keccak-256 integrity tag + "valid marker" byte
at the end of the record catch torn writes.

## Files added / modified

| File | What |
|---|---|
| `secure/src/nsc/jardin_flash.rs` | **New module.** `SlotState` struct, `read_latest()`, `write()`, record serialization, STM32U585 backend (real flash) + QEMU backend (static RAM). |
| `secure/src/nsc/mod.rs` | Added `pub(crate) mod jardin_flash;` |
| `secure/memory-stm32u585.x` | Shrunk `FLASH LENGTH` from 1000K → 984K to reserve pages 123–124 at `0x0C0F_6000` and `0x0C0F_8000`. |

## Public API (what downstream phases should use)

```rust
use crate::nsc::jardin_flash::{
    SlotState, FlashError, FLAG_SLOT_REGISTERED,
    read_latest, write,
};

// Check if a slot is already active:
let cur: Option<SlotState> = read_latest();

// Commit new state (module assigns seq internally):
let state = SlotState {
    seq: 0,                         // ignored by write(); read-back value is authoritative
    chain_id: 1,
    slot_index: 0,
    next_q: 1,
    flags: FLAG_SLOT_REGISTERED,
    h_r: [/* 32 bytes */],
    sub_pk_seed: [/* 16 bytes */],
    sub_pk_root: [/* 16 bytes */],
};
write(&state)?;
```

`write()` assigns `seq = current_max_seq + 1` under the hood and commits
to whichever page isn't currently holding the latest record.

## Record layout (frozen on-disk format)

```
off  len  field
---  ---  -----------------------------------------
  0    4  magic              = 0x4A41_5244 ("JARD")
  4    4  version            = 1
  8    8  seq                (u64 LE, monotonic)
 16    8  chain_id           (u64 LE)
 24    4  slot_index         (u32 LE)
 28    4  next_q             (u32 LE)
 32    4  flags              (bit 0 = slot_registered)
 36    4  reserved
 40   32  h_r                (keccak256(r), on-chain slotKey)
 72   16  sub_pk_seed        (N-masked)
 88   16  sub_pk_root        (N-masked)
104    4  integrity          (first 4B of keccak256(bytes[0..104]))
108   19  reserved
127    1  valid_marker       (0x00 = written, 0xFF = blank)
```

`valid_marker` in the final byte ensures torn writes leave the record
indistinguishable from a blank page.

## Wear budget

1 page erase per commit. Two pages alternate. STM32U585 flash endurance is
~10K cycles per page → 20K commits headroom. At worst-case "one commit per
signature" that's 20K signatures over device lifetime. Good enough for MVP.
Log-structured appends within a page would give ~64× more headroom; deferred.

## Known limitations (things later phases must work around)

- **Single active chain at a time.** If the user signs on chain A, then
  switches to chain B, the old state is overwritten. A later phase could add
  a small array of per-chain states within the record if multi-chain support
  is needed (the reserved bytes at offset 108–126 have room for it).
- **No unit test execution on host.** The `nsc` module is gated out of host
  test builds by project convention (`#[cfg(not(test))]` on `mod nsc` in
  `main.rs`). Tests are exercised via QEMU e2e instead. If you need host
  unit tests for the serialization layer, factor it into a new workspace
  crate (`jardin-flash-core/`) that's not gated.
- **QEMU backend is not persistent.** It's backed by two `static mut [u8;
  RECORD_LEN]` buffers that reset on each firmware load. Fine for testing
  the state-machine logic; actual persistence only exists on STM32U585.

## Verification

Firmware compiles clean:

```bash
CARGO_TARGET_THUMBV8M_MAIN_NONE_EABI_RUSTFLAGS="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x" \
  cargo build --release --target thumbv8m.main-none-eabi \
  --target-dir target/secure -p sphincs-tz-secure \
  --no-default-features --features mock-se,debug-log,ui-semihosting
```
