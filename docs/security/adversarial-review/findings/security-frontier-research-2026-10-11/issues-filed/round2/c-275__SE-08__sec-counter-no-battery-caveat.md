COMMENT_ON: 275
---
**Two constraints for this item, from the 2026-10-11 security frontier research (item SE-08). Line numbers are at master `c2fab970`.**

No code reads the Security Event Counter today: a search of `secure/src`, `shared/src`, `proto/src` and `nonsecure/src` for `E0C5` finds nothing. The object is listed in the in-repo table at `docs/secure-elements/OPTIGATRUSTM/commands-and-oids.md:402`.

- **Trezor's handling cannot be ported whole.** By the research's reading of Trezor's driver and the vendor manual (not re-checked by me), the counter decays only while the chip is powered, and Trezor keeps the chip powered until it has decayed, in builds that have a real-time clock. pq1 has no battery, and the supply to both secure elements is switched by a microcontroller pin (`secure/src/board/pq1.rs:39`). So on pq1 the reading can inform, but the firmware cannot wait the counter down while the device is unplugged.
- **Where the reading is useful on pq1.** A chip that is throttling because the counter is high answers slowly. On the unlock path a slow or missing answer already costs a PIN attempt (#119). Reading the counter before the PIN verify would let the firmware tell "throttled, wait and retry" from "wedged". That use changes control flow, which is more than the "advisory only (log and display)" scope written here, so it needs its own review.
- [ ] Decide whether the throttled-versus-wedged classification is in scope for this issue or belongs under #119.
- [ ] Whatever is decided, the reading must never be able to delay or cancel a wipe, and must not be wired into the tamper wipe (as the body already says).

<sub>**Provenance.** Security frontier research, 2026-10-11 (report item SE-08, section 7). Report priority P2 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
