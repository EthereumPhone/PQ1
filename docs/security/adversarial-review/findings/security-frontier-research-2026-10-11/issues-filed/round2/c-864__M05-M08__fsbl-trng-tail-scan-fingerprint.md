COMMENT_ON: 864
---
The research item behind this issue (M05, a bundle of bootloader changes to land before the freeze) carried design constraints that are not in the body above. They matter here because whatever lands is permanent. Lines are at master `c2fab970`.

**Item 1, a random delay source in the bootloader**

- A true random number generator (TRNG) in the bootloader adds a boot dependency that can never be patched. If the oscillator or the TRNG is dead or marginal on a unit, that unit never boots again. #834 (no fallback) and #835 (the halt sink turned out net-negative in the secure world) show how easy this policy is to get wrong. It needs its own owner decision and should not be inherited from either issue.
- Clock source. The secure world clocks the RNG from HSI48 and waits for it without a bound (`secure/src/hw/rcc.rs:143`, tracked in #642). The bootloader runs on HSI16 (`fsbl/src/clock.rs:1`). Whether the RNG can be clocked from HSI16, which would avoid a second oscillator in frozen code, was **not** checked against the reference manual.
- The bootloader must not set the RNG configuration lock, or must reset the RNG before the handoff. With the lock set, later configuration writes are ignored until an RNG reset (`secure/src/hw/rng.rs:43`), and the secure world writes its own configuration and sets the lock itself (`secure/src/hw/rng.rs:542`).
- The RNG has to be made secure in the TrustZone controller first, as the bootloader already does for the HASH peripheral (`fsbl/src/hash.rs:27`).
- If a TRNG lands, put one delay before each gate and before the branch, not only between the two evaluations inside a gate. Today the first evaluation of every gate sits at a fixed time from reset.
- State the limit in the freeze record. A random delay raises the cost of a blind, fixed-offset double glitch. It does not stop an attacker who triggers on the power signature of the hash or of the display bus, and it is not what closes #847.

**Item 2, the tail scan**

- The bound must not be the capacities the bootloader uses today. `fsbl/src/slot.rs:47` re-exports `fw-manifest/src/lib.rs:177` and `fw-manifest/src/lib.rs:180` (58 and 64 pages). The frozen registry has different spans, `geometry/src/lib.rs:51` (`0x72000`, 57 pages) and `geometry/src/lib.rs:53` (`0x7A000`, 61 pages), and it reserves journal pages 64 and 122 (`geometry/src/lib.rs:203`), which are the last page of each secure slot in the legacy layout. A scan frozen with the legacy bounds would reject every image after the #540 cutover. Take base and span from `pqsigner-geometry`, or freeze the scan only after the cutover.
- The scan verdict must feed the same accumulated verdict as the other gates (#847). A separate `if` is one more branch to skip.
- It runs for both slots when both are valid, so budget boot time for two scans.
- Alternative to weigh: pad and sign images to the full slot span. No scan code is frozen; hashing takes longer.
- Before freezing, check what `FW_ABORT` and a torn update leave in the inactive slot, and that the non-secure length in the manifest covers every section placed in the slot (the pixel-UI glyph atlas sits at a fixed offset of the non-secure slot).

**Two more points from the same research item, for the issues that own them**

- The widened sweep that #847 asks for (#591) should also cover the slot-choice compares in `pick_slot` (`fsbl/src/main.rs:367`), the option-byte tripwire verdict (`fsbl/src/main.rs:250`) and the display verdict (`fsbl/src/main.rs:287`), and it should run on the pq1 build, which links a display stage the iota2 build does not.
- A second, independent target-sum computation in the one-time-signature (WOTS) verifier was proposed only for the case where the sweep in #865 (item 2) finds a single-fault forge there. It would change a crate that the formal-verification extraction pins, so it is not proposed unconditionally.

Suggested additions to the checklist:

- [ ] Owner decision on the bootloader TRNG failure mode and clock source, recorded separately from #834 and #835.
- [ ] Tail-scan bounds taken from `pqsigner-geometry`, or the scan deferred until after #540.
- [ ] Tail-scan verdict folded into the accumulated verdict of #847.

Not checked: any byte or boot-time cost. The research estimates were made on an older build and are not repeated here.

---

**More constraints for items 2 and 3, from a second item of the same research (M08). Some of the tail-scan points repeat the ones above from a different review; both are kept.**

**Item 2, the blank scan of the slot tail.** The research's independent reviewer kept the check and corrected four things about it:

- **It is a brick lever on a one-slot unit.** When no slot is admissible the bootloader halts (`fsbl/src/main.rs:220`). A unit as shipped has one valid slot. A dirty tail there is a permanent halt once the unit is at RDP-2, because the update commands are the only repair path (#696) and they need a booted image. The scan should not land in the bootloader until #696's bootable-fallback proof covers this refusal.
- **With two valid slots it forces a downgrade.** A planted tail in the active slot makes the bootloader boot the previous image. An attacker with a secure-world write could already do that by corrupting one image byte, so this is no new capability. It does mean the scan turns hidden bytes into a downgrade or a halt, not into something the user sees.
- **It runs on every slot with a valid manifest, not only on the slot that boots.** `verify_images` is called for slot A and slot B before the pick (`fsbl/src/main.rs:211`, `fsbl/src/main.rs:212`). The `stage-marker` harness behind the measured boot timing uses slot B's manifest page as its marker page (`fsbl/src/marker.rs:45`), so it can only measure the one-slot case. The two-slot cost of today's hashing is itself unmeasured. The reviewer's estimate for the scan is 0.2 to 0.5 s. Not measured.
- **It widens the flash the bootloader reads from about 0.4 MB to about 1 MB per slot.** That raises the stakes of the missing NMI / ECC handler (#854): a persistent double-bit error in a tail word would halt every boot.

Further points from the same review:

- An honest update does not trip the scan: the last chunk is padded with 0xFF to the 16-byte write unit (`secure/src/fw_update/staging.rs:80`).
- Bench recipes that reflash by page leave stale tails from an earlier, larger image. They must erase whole slots, as the body already says for the factory.
- The research's two reviews disagree on the COMMIT half. One says land it now, because it is updatable code and costs no bootloader bytes. The other says defer it, because COMMIT refuses unconditionally today and BEGIN erases the whole slot. I am not picking one.
- Sequencing for the bootloader half: inside the #540 cutover, with the capacity taken from the geometry crate, counted in the #541 link, and both scans added to the #591 sweep.
- What stays unchecked afterwards: slack in the manifest pages, and pages 123 to 127.

**Item 3, what the eight words cover.**

- Widening is already an open box in the vendor-key note under #486 (`docs/security/vendor-signing-key-compromise.md:142`, `docs/security/vendor-signing-key-compromise.md:185`), together with publishing the expected words per release. This issue and that note should point at each other so the decision is taken once.
- Several places derive the words from the secure-image hash today: the bootloader (`fsbl/src/main.rs:286`), the install confirm (`secure/src/fw_update/mod.rs:139`), the secure-world row, and the host tool, which is given the secure ELF only (`Makefile:2255`). They have to change in one commit, or the published words stop matching the device.
- The secure-world row is compiled out of production images (`secure/src/main.rs:278`), so in a shipping image the question concerns the bootloader and the install confirm. In debug builds, a row that reads the stored manifest digest back becomes a copy of the bootloader's row and stops being an independent re-hash.
- The reviewer's assessment of the value: it tells releases apart; it does not detect an attack, because the non-secure image is untrusted by design. Deriving the words from a v6 manifest digest would tie this to the candidate manifest, which is not implementation-approved. Doing it on the legacy format would be redone at any cutover.

Suggested checklist additions:

- [ ] Gate the bootloader half of item 2 on #696 and #854.
- [ ] Measure boot time with both slots populated, before and after the scan.
- [ ] Decide the COMMIT half.
- [ ] Cross-link the item 3 decision with the note under #486.

**The bootloader half of item 2 and the scope of the eight words are fixed for good when the first unit is locked.** No board change is involved. The timing measurement needs the bench board with the debug port and the `stage-marker` build.

Not checked: nothing was built, timed or run. The sizes are from the slot capacities and the bench image lengths recorded in #226.

---

<sub>**Provenance.** Security frontier research, 2026-10-11 (report items M05 and M08, sections 3 and 9). Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading; nothing was built, timed or run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
