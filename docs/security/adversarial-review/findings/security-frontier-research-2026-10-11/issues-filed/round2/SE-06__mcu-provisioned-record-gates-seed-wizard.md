TITLE: Add an MCU-side "wallet provisioned" record as the seed-wizard gate: today the only gate is two secure-element probes that can each be forced to read "blank"
LABELS: enhancement,priority:high,surface:secure-element,surface:lifecycle,source:frontier-research-2026-10
---
## Summary

At boot the firmware starts the first-boot seed wizard when either secure element reports "not provisioned", and running the wizard on a used device overwrites the live wallet. Each probe can report that while its chip still holds a wallet: the SE050 probe returns false on any init or transport error, and the OPTIGA probe returns false on any cleanly framed status, read before the encrypted tunnel is up. Those two defects have their own issues (#111, #121), and so does the consequence (#169), but even fixed probes are answers that arrive over a bus. This issue asks for a third input that lives in the microcontroller's own flash: a "wallet provisioned" record, written after provisioning succeeds and treated as cleared from the moment a wipe starts. While it is set, the wizard is never offered. No issue tracks such a record, and none exists in the code.

## What the code does today

- `secure/src/main.rs:3982`: the wizard branch is taken when `is_provisioned` is false.
- `secure/src/dual_se.rs:142`: in the dual-chip build that value is the AND of the two chips' probes, so the wizard runs when either chip reads "blank".
- `secure/src/se050/mod.rs:1790`: the SE050 probe returns false when `init` fails. `secure/src/se050/mod.rs:1794`: it also turns any error from the existence check into false.
- `secure/src/optiga/mod.rs:982`: the OPTIGA probe treats any chip status as "fresh chip" and returns false on the next line (`secure/src/optiga/mod.rs:983`). The probe reads one byte of the F1E1 object (`secure/src/optiga/mod.rs:968`), whose read access is "always", without the tunnel. Only a transport failure on both of its two passes is reported as "provisioned".
- `secure/src/main.rs:4074`: after the wizard, `provision_from_mnemonic` writes the new wallet to both chips.
- Flash page 125 holds a wipe-in-progress flag (`secure/src/hw/flash.rs:626`) and a duress mode word (`secure/src/hw/flash.rs:710`). I found no wallet-provisioned record there or anywhere else in `secure/src`, `shared/src`, `proto/src` or `geometry/src`.

So one wrong answer is enough: an SE050 init or transport failure that outlasts the driver's own retries, or a single forged status frame on the OPTIGA bus, sends a device that holds a wallet into the wizard. The user would still have to walk through the wizard for the wallet to be overwritten. This is reasoned from the code. It was not demonstrated.

## What is already tracked elsewhere

- #111 covers the SE050 probe failing open. #121 covers the OPTIGA probe (plaintext at cold boot, clean status read as "fresh"). This issue does not repeat either fix.
- #169 covers what the wizard destroys when it misfires. Its fix direction is about provisioning order and error recovery, not about the gate.
- #14 and #215 decide the future of the F1E1 object, which is the chip-side provisioning and reset marker the OPTIGA probe reads: keep it under a reviewed policy, or replace it and its consumers. Neither proposes a microcontroller-side record. The two decisions touch: if F1E1 is kept, the record proposed here is the cross-check on it; if F1E1 is replaced, this record is a candidate for part of the replacement. Decide them together.
- #118 covers the pairing secret being written before the wizard without the tunnel. One note from the research for that issue: once the first-boot journal says the secret was rotated, the write can be skipped at both call sites (`secure/src/optiga/mod.rs:613`, `secure/src/optiga/mod.rs:2111`), because the rotation already proved the value with a handshake.
- #106 covers wipe verdicts that report success without proof. #692 covers a secure-element fault burning PIN attempts.
- #862 (first-boot journal completion bits) is adjacent only. It is a different record with a different purpose.
- #855 needs a home for a per-provisioning salt. That is the same flash-page decision as the one below.

So this issue is only about the microcontroller-side record and the wizard gate that reads it.

## Proposed work

- [ ] **Owner decision first: where the record lives.** Every page of flash bank 1 already has an owner in the geometry registry (`geometry/src/lib.rs:130` to `geometry/src/lib.rs:133`). Page 127 is not suitable: it exists as a journal only under `rdp2-self-lock`, and erasing it to clear the record would also erase the pairing-secret salt, which the code reports as `RotatedSaltMissing` (`secure/src/first_boot/mod.rs:71`), a pairing brick. The candidates are spare quad-words on page 125, or a registry change under #540. Decide it together with the salt in #855.
- [ ] Choose an encoding in which the record reads "clear" from the moment any wipe starts, before the first destructive secure-element command. On page 125 one candidate is to treat an armed wipe flag (`secure/src/hw/flash.rs:682`) as clearing the record, and let the page erase that ends the wipe (`secure/src/hw/flash.rs:633`) remove both. This candidate has not been analysed for power cuts.
- [ ] Write the record only after `provision_from_mnemonic` has returned, so a power cut between the OPTIGA and SE050 provisioning calls (`secure/src/dual_se.rs:207`) leaves the record clear and the device re-enters the wizard as it does today.
- [ ] Gate the wizard: offer it only when the record is clear and the probes read "blank". When the record is set and a probe reads "blank", go to the unlock path with a distinct status, never to the wizard.
- [ ] Clear the record at the start of every wipe entry point: the lockout wipe (`secure/src/nsc/cmd_request_unlock.rs:196`), the boot resume that also completes a tamper wipe (`secure/src/main.rs:1957`), the duress wipe (`secure/src/nsc/mod.rs:1567`), the counter-rollback wipe (`secure/src/nsc/mod.rs:1734`) and the provisioning rollback (`secure/src/crypto.rs:495`). One shared entry is better than five call sites, so a new wipe path cannot forget it.
- [ ] Write down all four combinations of record and probe result, with the way out of each. There must be no state that parks forever: a locked production unit has no service path.
- [ ] Put the decision in code that host tests compile (a workspace crate), with one test per combination and a negative control. `secure/src/main.rs` is not built by the host test suite.
- [ ] Define what happens on bench units that are already provisioned and carry no record (for example, set it on the first successful unlock).
- [ ] Update the lifecycle text in `CLAUDE.md` and the threat model once the behaviour is fixed.

## What it needs

Firmware only, plus the owner decision on the flash page. The fault cases can be exercised on the open bench board through the debug port. The wizard path itself needs a unit with a display panel, which the bench board does not have.

## Limits

- With the record set and a chip that keeps reading "blank" or keeps failing, the device goes to the unlock path. Page 124 is charged before each attempt, so a persistent fault can still spend the ten attempts and end in a wipe (#692). A liveness check before PIN entry, or not charging on transport failures before PIN entry, would be a separate change.
- The record does not protect the pairing secret (#118) and does not replace the probe fixes (#111, #121).
- It is new durable state. If a wipe path fails to clear it, a legitimately wiped unit never offers the wizard again. That is why the clearing has to sit in one shared place and be tested.
- The research considered and dropped two stronger rules. "Refuse all provisioning once the device is locked or rotated" would disable the field wizard, which runs after both. "Park whenever the three inputs disagree" strands a power cut between the two provisioning calls with no way out on a locked unit.
- A handshake-first rule for the pairing-secret write does not stop an active interposer: a corrupted handshake reads as "wrong secret" and would trigger the write. That is why the note above says skip, not probe.
- No vendor precedent is claimed for the record. Trezor's comparable guards are in its factory test firmware, not in field firmware.
- Power-cut ordering between this record, the wipe flag and the secure-element wipe has not been analysed.

## Related

#111, #121, #169, #14, #215, #118, #106, #692, #855, #540, #862.

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item SE-06, section 7). Report priority P1 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
