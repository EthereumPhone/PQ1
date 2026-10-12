COMMENT_ON: 270
---
**Widening the tripwire needs a ship / bench profile split, and it has a deadline (2026-10-11 security frontier research, item M02).**

State at master: `fsbl/src/optbytes.rs:68` calls `lockdown::verify_confirmed_fields`. The tripwire checks TZEN, the RDP byte for the current phase, both secure watermarks, the boot address and SWAP_BANK. It does not look at WRP1A, WRP2A, the OEM lock bits, BOOT_LOCK or the brown-out level. The 2026-09-16 comment above already records WRP1A and the OEM locks as open "while their layouts are unpinned". What the research adds:

- **Pinning the layouts (#46) does not by itself make the full check usable in the bootloader.** With `WRP1A_MASK_PINNED` true, `verify_ship_profile` requires write protection over pages 0 to 4 in both banks (`shared/src/lockdown.rs:564`, `shared/src/lockdown.rs:572`). Bench and EVT boards carry no write protection, no BOOT_LOCK and the default brown-out level, and the bootloader still links into pages 0 to 3 (#540). A tripwire switched to the full profile would halt every one of them. It needs an explicit ship profile and bench profile chosen at build time, with a fence that keeps the bench one out of a shipping image (the same kind of fence #753 asks for BOOT_LOCK). The test at `shared/src/lockdown.rs:765` already forces a revisit when the flag flips; it does not say what the answer is.
- **The field list has grown since this issue was written.** Add WRP2A and BOOT_LOCK (both checkable since 2026-09-24), the brown-out level, and SRAM_RST (#848).
- **What the wider check buys is narrow.** After RDP-2 these fields cannot change: RM0456 Rev 7 section 7.6.2 excepts only SWAP_BANK, which the tripwire already checks. Phase A checks them before the burn. So the every-boot compare only catches a unit whose Phase A was skipped by a fault or never ran. It is a fault tripwire, not a new detector, and it does nothing against an attacker who rewrote flash at RDP-0, because it lives in that flash.
- **It is still worth deciding now, because of the freeze.** A wider compare that is not in the frozen bootloader can never be added. The research estimates 100 to 200 bytes. That is not measured.

Suggested checklist additions:

- [ ] Ship / bench profile split for the tripwire, with a compile-time fence.
- [ ] Extend the compare to WRP1A, WRP2A, OEM locks, BOOT_LOCK, brown-out level and SRAM_RST once #46 pins them. Keep it read-only, two-pass and halt-only, with no wipe and no option-byte write (the 2026-07-23 decision recorded at `fsbl/src/optbytes.rs:3`).
- [ ] Measure the flash and stack cost on the pq1 bootloader and enter it in the #541 link.

**Bootloader firmware only. It must land, or be explicitly declined, before the first unit is locked.**

Not checked: nothing was built or run. The byte estimate is the research's.

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item M02, section 6). Report priority P1 is a research rating, not an owner decision (the reviewer put this part at P2). Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
