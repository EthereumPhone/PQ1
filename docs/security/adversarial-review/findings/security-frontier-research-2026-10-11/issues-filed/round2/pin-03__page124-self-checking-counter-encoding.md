TITLE: Page-124 PIN attempt counter: an all-0xFF read decodes as "zero attempts"; decide on a self-checking record encoding, with an atomic reset designed first
LABELS: enhancement,priority:low,surface:sca-fi,surface:lifecycle,source:frontier-research-2026-10
---
## Summary

The microcontroller's own copy of the PIN attempt counter lives on flash page 124. "No attempts used" is an erased page and "one attempt used" is any non-0xFF byte in the next 16-byte record. A fault that makes the whole page read as 0xFF for the length of the reads therefore decodes as a valid zero. Trezor's storage for the same microcontroller family encodes its PIN log so that an all-ones or all-zeros read is malformed (each bit stored as a pair, the value repeated, all copies required to agree). The research recommends the same idea for page 124 only, as defence in depth. It gives no extra PIN guesses today, because both secure elements still count in silicon, and an earlier fault triage accepted the single-fault case; so this is low priority and starts with a decision. No issue asks for an encoding change: #397 is about proving properties of the current one.

## What the code does today

- `secure/src/hw/flash.rs:768`: a used record is 16 zero bytes, a blank record is 16 bytes of 0xFF.
- `secure/src/hw/flash.rs:847` and `secure/src/hw/flash.rs:881`: the forward scan and the reverse scan use the same test, "any byte not 0xFF". A page that reads uniformly 0xFF makes both scans agree on zero.
- `secure/src/hw/flash.rs:828`: when the two scans disagree the read returns 32, which every caller treats as locked.
- `secure/src/hw/flash.rs:924`: a bump programs 16 zero bytes into the next blank record. `secure/src/hw/flash.rs:955`: a reset is a bare page erase, with nothing written afterwards.
- `secure/src/nsc/mod.rs:1450`, `secure/src/nsc/mod.rs:1452`: the unlock gate reads the counter twice and refuses on a mismatch. `secure/src/nsc/mod.rs:1494`: it then bumps the counter and re-reads before any secure-element call. `secure/src/nsc/mod.rs:1614`: every successful unlock erases the page.
- `secure/src/nsc/mod.rs:1713`: at boot the device wipes when the OPTIGA counter is ahead of page 124, so a read faulted low at boot fails closed.
- `secure/src/main.rs:1947`: at boot the device also wipes when the page-124 read is at or above the maximum. A blank page that an encoding change mapped to "malformed, treat as locked" would land here.
- `secure/src/first_boot/mod.rs:201`: first boot requires pages 123 to 127 to be blank before it locks the part, so a "zero" record could only be written after that check.
- `tools/sca/README.md:428`: an earlier triage (F-4) rated a single fault that leaves page 124 uncharged as minor and recommended accepting it, because the secure-element counters are the real limit.
- `tools/sca/fault_sweep_pin.py:19`: the fault-emulation model uses a fake counter in RAM, so a faulted flash read is outside what it tests.

## What is already tracked elsewhere

- #397 asks for a Kani proof of scan and bump monotonicity for the current page-124 layout. It is verification only.
- #216 models the interleaving of the three counters. #200 is the cold-reboot receipt for the boot cross-check.
- #392 (reset at a swept delay) would exercise any new reset window.
- #835, #715 and #692 are about attempts consumed with no user error. They limit how a malformed counter may fail closed.
- #865 (item 1) covers the fault-emulation harness not building.

So this issue is only about the on-flash encoding of page 124 and the reset protocol it forces.

## Proposed work

- [ ] Decide whether to do this at all, given the earlier "accept", and record the decision here.
- [ ] Design the reset before the encoding. If a blank page stops meaning zero, erase-then-write-zero is not atomic, and the device has no battery, so anyone can cut power between the two steps. Options the review named: (a) reset by appending a "zero" record and erase only when the page is full, which shrinks the window and changes the one-record-per-attempt layout; (b) keep the erase and define an explicit "blank after erase" state that is neither "zero attempts" nor "locked". There is no spare page for a two-page scheme. A power cut must never turn into a wipe.
- [ ] Encoding, page 124 only: store the count in each record with every bit expanded to a pair and the value repeated; accept a record only when all copies agree and decode; require the record at position i to decode to the value expected at i.
- [ ] Put the codec in a workspace crate with host tests and Kani harnesses (fold into #397). Code under `secure/src/hw` is not compiled into host tests.
- [ ] Change every consumer in the same commit: the four reset sites (`secure/src/nsc/mod.rs:1614`, `secure/src/nsc/mod.rs:1735`, `secure/src/nsc/cmd_request_unlock.rs:204`, `secure/src/main.rs:1962`), the boot wipe check, the boot cross-check, the first-boot blank check and the developer wipe target (`secure/src/main.rs:3740`). The test and bench routines that erase the page directly need the same change.
- [ ] Add a "whole page reads 0xFF" and a "tail of the log reads 0xFF" data-fault model to the fault-emulation sweep, once #865 item 1 is fixed.
- [ ] Leave page 123 alone. Its 16-byte record has no room for a repeated value and a blank page is a legal state there. This issue adds no per-signature flash state.

## What it needs

Firmware and host tooling only. The reset protocol should be run under the reset-at-swept-delay harness (#392) on the open bench board, which needs the debug port and no display. Showing that an all-0xFF flash read can be produced at all needs a fault-injection rig; nothing so far shows it can on this part.

## Limits

- No extra PIN guess is gained through this weakness today. The SE050 limits attempts to ten and the OPTIGA to 32 in silicon whatever page 124 says, and the boot cross-check wipes when the OPTIGA is ahead. Page 124 is the redundant counter.
- The fault has to hold across both scans of at least two reads and the reads inside the bump. That is a sustained fault on flash data, not one glitch. Not measured.
- The encoding does not stop a read in which only the tail of the log reads 0xFF. That still decodes to a well-formed lower count. Trezor's scheme has the same limit.
- Trezor's layout is not the same: it rewrites one key-value item holding an absolute count, and repeats the value over six halfwords. This cannot be a straight port.
- Do not count on the flash's error correction to catch a faulted read. A code comment says no interrupt source for it is armed today (`secure/src/main.rs:4711`), and how this part reports a torn or faulted word is undetermined (#94, #854).
- The two research reviewers disagreed: priority 3 against 2, medium against large cost. The values here (priority 3, large) are the more cautious pair.

## Related

#397, #216, #200, #392, #835, #715, #692, #865, #854, #94.

Public source: Trezor's `storage/pinlogs_blockwise.h` in https://github.com/trezor/trezor-firmware (read in a local clone).

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item pin-03, section 8). Report priority P3 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
