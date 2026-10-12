COMMENT_ON: 46
---
**OEM-lock mask: the constants point at reserved bits (from the 2026-10-11 security frontier research, defect C3).**

`shared/src/lockdown.rs:278-279` at master `0feea78a` defines

```rust
pub const OEM1LOCK: u32 = 1 << 26;
pub const OEM2LOCK: u32 = 1 << 27;
```

RM0456 Rev 7, section 7.9.7 (FLASH_NSSR), gives **bit 18 = OEM1LOCK** and **bit 19 = OEM2LOCK**. Bits 31:22 of that register are reserved. The research agents found the same positions in the vendor SVD and the CMSIS header; I re-checked the reference manual text myself.

Why it is harmless today and dangerous later: the gate fails closed because `OEM_LOCK_MASK_PINNED = false` (`shared/src/lockdown.rs:290`). If that flag were flipped to `true` without correcting the two constants, the mask would read reserved bits that are always 0, `oem_locks_absent` would pass vacuously, and a unit with a planted OEM2 regression key would sail through Phase A. That is exactly the fail-open the doc comment at `:270-277` warns about.

Suggested additions to this issue's checklist:

- [ ] Correct `OEM1LOCK` / `OEM2LOCK` to bits 18 / 19, with a host test bound to the SVD values. This needs no silicon.
- [ ] Keep `OEM_LOCK_MASK_PINNED = false` until the positive bench detection is done with an **OEM2** key, not only OEM1 (#387, #45).
- [ ] Add `FLASH_NSSR` bits 18 and 19 to the per-unit factory record (#595) and to the user-side read set.

Severity as rated by the research: latent-high, none today. Evidence: code read plus reference manual; not exercised on silicon.
