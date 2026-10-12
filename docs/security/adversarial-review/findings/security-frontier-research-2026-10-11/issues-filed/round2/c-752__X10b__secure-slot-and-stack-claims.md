COMMENT_ON: 752
---
**Secure-slot and secure-stack claims from the 2026-10 research, for open item 2 (2026-10-11 security frontier research, item X10b).**

Open item 2 here is "Restore the production capacity gate". The research adds three things to it.

1. **The blocking CI gate measures a smoke image against the legacy cap.** `.github/workflows/ci.yml:487` runs `make size-report` on the `build-hw` image, which `Makefile:397` calls non-shippable. `fwmeasure --require-secure-slot` compares against `fw_manifest::SLOT_SECURE_CAPACITY` (`fwmeasure/src/main.rs:108`), the legacy 58-page slot of 475,136 B (`fw-manifest/src/lib.rs:177`). The v6 slot is 466,944 B (`geometry/src/lib.rs:51`). The ship-shaped measurement, `size-report-px`, is informational and allowed to fail (`.github/workflows/ci.yml:502`). So no blocking check compares a ship-shaped image with the slot it would ship in.
2. **Nobody sums what the open work would add to the secure image.** The research's items each claim secure flash one at a time. Its reviewer totalled the estimates at 25 to 38 KB, against the 34,071 B of headroom this issue quotes for an image without the pixel UI. Only the upper bound exceeds the headroom. The largest single row is a 16 KiB table; without it the estimated rows total 6 to 16 KB, and four rows have no estimate. Every figure is an unmeasured estimate, and estimates do not add under link-time optimisation. With the pixel UI the image is already over the slot, so every such row waits for this issue or for a code diet either way.
3. **The secure stack has no measurement at all.** `-Z emit-stack-sizes` is passed only to the bootloader build (`Makefile:2466`). #374 owns the bound. Work that grows the secure stack should wait for it.

A conflict I am reporting, not resolving: this issue and `docs/security/adversarial-review/findings/flash-geometry-v7-2026-09-24.md:35` record an owner decision to ship the pixel UI as the trusted display. `CLAUDE.md` says the pixel UI stays out of `make release` and calls the flash lever an open owner decision. Which image the capacity gate should measure depends on which record is current.

Suggested checklist additions under item 2:

- [ ] Point the blocking capacity gate at a ship-shaped image and at the slot span from the geometry crate, as a parameter, so that it follows v7 when ratified. Keep a variant without the pixel UI as a reference.
- [ ] Keep one checked-in list of secure-slot claimants (id, estimated flash, estimated stack, measured delta once landed). A landed row replaces its estimate with a measured delta.
- [ ] Use `emit-stack-sizes` output for the secure image only as input to a call-graph tool, together with the on-target high-water mark that #374 asks for. The reviewer warns against presenting a frame sum as a bound for the secure image.
- [ ] Update whichever of the two records above is stale.

Host tooling and CI only. No board dependency. Not tied to the bootloader freeze.

Not checked: I built nothing. The headroom and the estimates are quoted, not re-measured. The true production image cannot be compiled today, so every size here is ship-shaped at best.

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item X10b, section 12). Report priority P2 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
