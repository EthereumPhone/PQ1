TITLE: Keep a small fault record across the security reset: fault-status registers in backup registers 8 to 31, read through the existing diagnostic command
LABELS: enhancement,priority:medium,surface:runtime,surface:trustzone,source:frontier-research-2026-10
---
## Summary

Every diagnostic the device has today is lost in the reset that its own security response triggers. The fault handlers zeroize and reset without recording anything, and the reset that follows is classified as an ordinary software reset. A unit that keeps resetting, or that comes back from a user, cannot say why. This issue proposes the cheap part of the research's forensics item: after the zeroize, write a small bounded record into the backup registers the firmware does not use, read it at the next boot, and return it through the diagnostic command that already exists. It adds no flash state. It is a diagnostic, not a defence. The parts of the research item that need a flash page or a new disclosure decision are listed under Limits and are not part of this issue.

## What the code does today

- `secure/src/main.rs:4751`: the HardFault handler receives the exception frame as `_ef`, ignores it, zeroizes and calls `sys_reset`. `secure/src/main.rs:4720`: the non-maskable interrupt handler does the same. No fault-status register is read anywhere.
- `secure/src/reset_cause.rs:179`: a reset requested by software classifies as `Software`. A fault-triggered `sys_reset` sets the same flag, so a fault and a deliberate reset look identical at the next boot.
- `secure/src/hw/tzic.rs:83`: the illegal-access counter and the last status word (`secure/src/hw/tzic.rs:88`) are RAM statics. They are gone after the reset that an illegal access causes.
- `secure/src/pin_attempt_log.rs:20`: the PIN-attempt reason ring is documented as RAM-resident; the same comment block names persistence as a follow-up that needs a page decision.
- `secure/src/hw/bhk.rs:59`: the hardware key occupies backup registers 0 to 7. A search of `secure/src` finds no other user of the backup registers, so 8 to 31 are free.
- `proto/src/lib.rs:123`: the diagnostic read command (`CMD_GET_PIN_ATTEMPT_LOG`) already exists and already ships without a PIN gate.
- Debug logging is compiled out of shipping images, so the boot-time reset-cause line is not visible on a real unit.

## What is already tracked elsewhere

- #715: the lockout that nobody could explain, which is why the reason ring exists. Its comments name "persisting the ring at lockout" as the open follow-up.
- #719: the owner decision on whether the RAM ring may be read without a PIN.
- #75 (comment of 2026-10-12): reading the tamper status at boot before clearing it. That covers the tamper half of this topic.
- #81 and #50: making the tamper block and its backup registers secure. Until they land, non-secure code can read and write backup registers 8 to 31.
- #848: setting the option bit that erases secure RAM on every reset. That rules out the other storage the research considered, a RAM area that is skipped at start-up.

So this issue is only about capturing fault information across a warm reset, in registers, with no flash write.

## Proposed work

- [ ] In the HardFault and non-maskable interrupt handlers, **after** `zeroize_sensitive_state`, write a fixed-size record to backup registers in the 8 to 31 range: a magic value, a reason code, the fault-status and fault-address registers, a checksum.
- [ ] Writing a backup register needs backup-domain write access. It is switched on today when the hardware key is loaded (`secure/src/hw/bhk.rs:365`), and #81 plans to switch it off again after that, so the handler must enable it itself before writing. This only works in builds that clock the tamper block, which the ship feature set does.
- [ ] Record the faulting program counter only when the stacked frame came from the secure state. Never follow a non-secure stack pointer to find a frame: an unchecked read published by a PIN-less command would be a secure-memory read primitive. Do not copy the stacked general-purpose registers; they can hold secret data.
- [ ] Bound it. Non-secure code can cause a secure fault whenever it wants, so the record is first-fault-wins with one saturating counter. No list, no unbounded writes.
- [ ] At boot, read the record before anything else touches the backup domain, fold it into the RAM diagnostic state, and clear the registers. Report a fault-triggered reset as its own cause, distinct from `Software`.
- [ ] Return it through the existing diagnostic command, with a version byte so the host tool can tell the formats apart. Whether a locked device may return it without a PIN follows #719.
- [ ] Put the record codec in a workspace crate with host tests. Code under `secure/src/hw` is compiled out of the host test build, so tests placed there never run.
- [ ] Note in the code that a confirmed tamper erases every backup register (`secure/src/hw/tamp.rs:307` sets all tampers to that mode), so a tamper-triggered reset leaves nothing here. Tamper evidence has to come from the status register, which is the #75 comment.

## What it needs

Firmware only. To show it works: the open bench board (debug port, no display needed), a deliberately triggered fault, and a read of the record over USB after the reset.

## Limits

- **The record does not survive a long power loss.** The board has no battery. The backup registers keep their contents across a system reset. Across loss of power they last only as long as the backup supply is held up: the V10 schematic shows a small backup capacitor on that supply ({{H1}}), whose hold time has not been measured and is hours at most by arithmetic. So this gives evidence for a fault followed by a reboot soon after, not for a unit that sat unpowered.
- Until #81 and #50 land, non-secure code can forge or erase the record. Treat it as a hint for a developer, not as evidence.
- Not in this issue, because each needs an owner decision first:
  - **A record that survives power loss or a wipe needs a flash page.** Every per-device page has an owner (123 off-chain counters, 124 PIN attempts, 125 wipe flag, 126 wrapped hardware key, 127 first-boot journal, which is append-only and also holds a key-derivation salt). The project rule is no new flash state beyond the page-123 counter. Any such record would also have to be write-bounded, since non-secure code can trigger faults at will.
  - **Reading a persistent record without a PIN.** The current answer in #719 rests on the ring being in RAM ("a seized powered-off device yields nothing"). A persistent record removes that argument, so the decision would have to be taken again.
- Showing the reason on screen at the next boot is left out. It does not belong in the first-stage bootloader (frozen once the device locks itself to readout protection level 2, size-bounded, holds no secrets), and the bench board has no panel to test a secure-world screen on.
- The research rated this P2 and noted that "parity" is overstated: by its reviewer's reading, Trezor keeps a RAM postmortem for its fatal screen and persists no fault or tamper record either. I did not read the Trezor source.

## Related

#715, #719, #75, #81, #50, #848, #854 (a stack-limit fault would be one of the reasons recorded), #634 (a decommission check must list any new store, including these registers), #484 (closed: the fatal screen).

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item SYS-06, section 11). Report priority P2 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
