# pq1 security frontier research

What pq1 does today on every security surface, what Trezor, Ledger and the literature do that it does not, and what to pursue next.

| | |
|---|---|
| Snapshot | 2026-10-11 |
| pq1 tree | Working tree at `c75b0d9c` on `feat/pq1-board-target`, with 28 uncommitted modified files. Five of them are cited here, so their line numbers will not reproduce at the bare commit: `fwsign/src/subcommands/sign.rs`, `pqsigner-fi/src/lib.rs`, `secure/src/hw/consumption_mask.rs`, `docs/security/production-security.md`, `.github/workflows/ci.yml`. |
| Trezor tree | `trezor-firmware` at `6ab39e95` (2026-09-18) |
| Updated | 2026-10-12: sections 13 to 15 added (on-chain policy, next-revision board, STM32U585 feature cross-check); the defect rows behind a new issue or comment re-checked and corrected before filing (already-tracked rows were not re-checked); issues #846 to #867 filed. Master was `0feea78a` on that date, 156 commits ahead of the snapshot commit. Second pass the same day: the 70 recommendation items checked against the tracker and master `c2fab970`; issues #869 to #894 and 50 comments filed; corrections to this report listed in section 16, the main one being that the current board already has a small backup capacitor and both crystals (#869). |
| Status | Research. Nothing here is implementation-approved, and no priority is an owner decision. |
| Evidence level | Code reading and public sources. Nothing in this report was run on silicon. |

## How to read this report

- **Item IDs.** `M01` to `M21` are merged recommendations: the same idea was proposed independently under several surfaces and then merged. Other IDs (`USB-01`, `CS-02`, `pin-05`) are single proposals. `X` IDs come from the completeness pass in section 12.
- **Priority.** P0 means before anything ships or freezes. P1 is high. P2 is medium. P3 is low or gated on a measurement that does not exist yet.
- **Kind.** Firmware, hardware (a board or enclosure change for the next revision), process, or mixed.
- **Novelty.** Parity means at least one vendor ships it. Beyond means none was found shipping it.
- **Status.** Recommended, redesign needed (refuted as written, a narrower residue survives), or rejected.
- **Evidence.** Repository evidence is cited as `path:line`. "Confirmed by code reading" means an agent read the executing code and its callers. It does not mean the behaviour was reproduced.
- **Shipping feature set.** No production image can be built today, because the OPTIGA S-2 fence rejects every `mode-production` build. "Reachable in the shipping feature set" means present in the code that would ship.

- **Update of 2026-10-12.** Sections 13, 14 and 15 are a later focused pass and are not part of the item counts or the master table. The "Live defects" section opens with an update note: it lists what a re-check corrected (including the headline defect, which affects the single-sign handler only) and the issue number for each defect.

## Summary

### The question that started this: can the device detect malicious hardware?

Partly, and the part that works is unproven. The honest answer has four pieces.

1. **Nothing in pq1 detects a hardware implant today.** The panel is write-only, the buttons are raw GPIO, and the 24 words cross the display bus as plain pixels. The repository already records this as an accepted residual.
2. **One firmware technique might detect a cheap soldered tap.** The MCU can time how fast each display line charges through its internal pull-up and compare that with a reference pad. A wire soldered to an MCU input adds roughly 3 to 10 pF. The realistic resolution is about 1 pF, so a buffered or non-contact tap stays below the floor. Every number here is derived from datasheets. None is measured on pq1. Item M10 recommends a bench go/no-go study before any refusal logic is written.
3. **It does not belong in the FSBL.** A threshold frozen by write protection and RDP-2 can never be retuned. The FSBL has about 4 KB free, runs at a tenth of the clock speed, and the threat is foreign hardware under genuine firmware, so an early position buys nothing. The check would live in the updatable secure image.
4. **A self-test has hard limits.** It cannot see the two button lines at all, because each carries a 100 nF capacitor. That matters more than it sounds: restore mode types all 24 words through those two buttons. It cannot catch a board swap, a fake MCU that reports a clean reading, or an implant fitted before the baseline was recorded. No vendor ships any electrical self-check, and the one implant documented from a primary source shrank the battery to make room and spoofed the device's own battery telemetry to cover that, so any check built on on-device power readings must assume the attacker tampers with the sensing path too.

What actually defends against the implant class is mostly not firmware. It is the pre-power verifier that only pq1's ship-at-RDP-0 model allows (M09), a mass-production enclosure with no void behind the panel and the display lines buried between ground planes (M11), and a seed ceremony that does not put the words on a tapped bus. Sections 1 and 2 give the detail.

On the earlier question of masking or encrypting the display data: encryption is impossible, because the panel holds no key. A tap on the bus reads every pixel regardless of encoding. The power channel that broke the 2019 OLED wallets is probably weaker here, because the backlight is a constant-current sink and no longer tracks content. The panel's own scan and supply rail still depend on what is shown, and none of it is measured. A constant-weight colour pair is worth building only after a leakage measurement on the real panel shows something to remove (M03).

### Three headline results

**1. pq1 is ahead of both vendors in design on several surfaces, and behind on execution.** The advantages are real: post-quantum signing only, a seed split across two secure elements from two vendors, PIN comparison in silicon, clear-sign-or-refuse instead of a blind-sign fallback, a verify-before-first-power model no vendor offers, and machine-checked proofs. Most of them exist as design or bench code. The verifier a buyer would run does not read what the invariant says it reads, and the sealed unit has no reachable debug port to run it on.

**2. The research found 93 distinct live defects in current code, option-byte handling, tooling and documentation.** About half already have a tracking issue. They are consolidated in "Live defects found during the research" below. The one that matters most is new: the gateway between the two TrustZone worlds is re-entrant, and the signing handler re-reads the transaction from a shared buffer after the user confirms. Compromised non-secure code could make the device sign something other than what it displayed. I re-read that code path myself and it is as described (`secure/src/nsc/mod.rs:1277-1280`, `secure/src/nsc/cmd_sign_userop.rs:388`, `:1933`, `:2133`). It is traced in source only and needs a compromised non-secure image first. The trigger is a non-secure timer interrupt arriving while the secure handler waits for the user. Trezor runs a SysTick in both its secure monitor and its non-secure kernel on the same STM32U5 family (trezor-firmware `core/embed/sys/task/stm32/system.c:70`, `docs/core/embed-arch/embed-arch.md:57`), so the non-secure timer the attack needs exists on this silicon family. The swap itself has not been reproduced on pq1 or in the emulator.

**3. The largest risk is the freeze, not any single bug.** Write protection plus RDP-2 make the FSBL and the option bytes permanent for each die. Today that would freeze an FSBL whose signature gate fails open on a single skipped instruction in the fault model (not yet tried on silicon), a brown-out level that is not pinned, SRAM protection bits that are not checked, and an OEM-lock check that tests the wrong bits. All of it is fixable now and none of it is fixable afterwards.

### The moves that matter most

| # | Move | Items | Kind |
|---|---|---|---|
| 1 | Close the display-versus-signature gap in the gateway. Refuse nested entry, hash the calldata before the confirm and re-check it after. | USB-01 | Firmware |
| 2 | Take clock, power and tamper control away from the non-secure world. Arm the voltage detector and pin the brown-out level. | M20 | Firmware plus option bytes |
| 3 | Do everything the freeze makes permanent before the freeze: FSBL fault hardening, the option-byte profile, the SRAM protection bits, the vendor-key policy. | M05, M02, M21, M07 | Firmware, factory process |
| 4 | Make verify-before-first-power real: a verifier that reads flash, option bytes, OTP map, UID and OEM-lock state, and a debug route that works on a sealed unit. | M09 | Tooling plus board |
| 5 | Run the assurance that already exists, then measure. Restore the nightly proofs, enrol the tests that run in no workflow, and run the first fault-injection and side-channel campaigns on silicon. | M19, FI-01, SCA-01 | Process |
| 6 | Harden the secure-element path: no wipe on an unauthenticated status word, host freshness on the OPTIGA tunnel, PIN credentials bound to the die, and a wipe that verifies and can be recovered from. | SE-03, SE-05, M16, M14, SE-06 | Firmware |
| 7 | Write the mass-production physical spec: display lines as stripline, no test pads on secure buses, no void behind the panel, potted button region, destructive-open shell. | M11 | Hardware |

### What the completeness pass added

A critic reviewed the consolidated list and named twelve gaps. Ten were pursued and produced 19 further proposals. An independent skeptic lowered the priority of most and rejected none. The ones that change the picture:

- **A restore path that splits the secret between the display and the buttons (X1a).** The device shows a fresh random mapping for each bit and the user presses accordingly, with no echo. A tap on the display bus alone learns nothing. An implant that also taps both button lines recovers everything, so the physical spec stays necessary. It covers restoring an existing phrase, not first backup, and costs several hundred blind presses.
- **The release-signing tool signs once and self-verifies (X2a).** The project's own rule calls that insufficient for hash-based signatures. This is the key the frozen FSBL will trust for the life of every device.
- **A test that pins which gateway commands may release key-derived output without a prompt (X3a).** One command does so today under a recorded owner decision, which this report does not reopen. Nothing currently stops that set from growing.
- **The per-key signature cap holds per device incarnation only (X4a).** A restored or cloned device starts its counters at zero for a key the previous device already used.
- **The glyph atlas is hashed before and after a dialog but read from non-secure flash during it (X5a).** A swap-and-restore between the two hashes is the gap.
- **Multi-signature custody is the systemic answer to one compromised device, including a tapped display (X6a).** pq1 already signs as a Safe owner. The topology is not documented or tested end to end.
- **Budget ledgers (X10a, X10b).** The recommendations compete for the roughly 4 KB left in the FSBL, and their estimated secure-flash cost already exceeds the headroom. They need ranking before any is built.

The critic also argued that several priorities are too low. Those items carry a double dagger in the master table, and the reasons are in section 12. The pattern is real: where two reviewers disagreed, the consolidation took the lower priority.

Two critic items were not pursued and remain open: a public transparency log for release bundles, and an independent lab evaluation with a disclosure channel before mass production.

### Where pq1 is already ahead

- **Supply chain.** No vendor offers a user-run check before first power. Trezor ships blank and relies on seals. The advantage is design-only until item M09 lands.
- **Signing.** Post-quantum only, end to end, including the firmware chain. Trezor's firmware headers remain Ed25519 with a hybrid bootloader header. pq1's double-compute, compare, then verify countermeasure is what RFC 9814 asks for on hash-based signatures.
- **Secure elements.** Two chips from two vendors each hold one share of the seed. A failed OPTIGA tunnel is a hard refusal on pq1. Trezor resets the chip and continues unpaired.
- **PIN.** The comparison happens in silicon, which removes the firmware digit-compare leak class. Faulting one chip's PIN check releases only one share.
- **TrustZone split.** PIN entry, display and transaction parsing run in the secure world. Trezor's own architecture document says its non-secure application can ask for raw secrets and receive them.
- **Clear signing.** A known shape either renders or refuses. Trezor and Ledger fall back to blind signing. pq1 decodes Safe transactions and account-abstraction operations on the device.
- **Display.** Constant-time glyph rendering with forced full-frame streaming has no vendor precedent. It does not stop a bus tap.
- **Assurance design.** A gate that checks the gates, a ledger of hardware assumptions, a locked proof census and on-chain verifier proofs have no Trezor equivalent in the data. Several of those gates are not executing today.

### Where Trezor is ahead today

- It resets the write-only OEM debug-regression keys and checks the full option-byte word on every boot, with a safety erase on mismatch (section 6).
- It checks that the unused tail of a firmware slot is blank (section 9).
- It runs random-delay interrupts on the same STM32U5 silicon (section 3).
- It audits its secure-element configuration at every boot (section 7).
- It applies an escalating delay between PIN attempts and stretches the PIN before it reaches a secure element (sections 7 and 8).
- It has per-die MCU attestation with a factory certificate, a factory channel authenticated to a hardware security module, and an external tamper input with a battery-backed domain (section 1).

### Decisions only the owner can make

These block specific recommendations. Each is recorded inconsistently in the repository today.

1. **Debug access on a sealed unit.** One document puts SWD on the USB-C sideband pins, another uses those pins for the BOOT0 enable, a third keeps internal pads. Internal pads plus a welded shell cancels verify-before-first-power.
2. **A supercapacitor on the backup supply, or none.** Without one, a tamper event can only be acted on at the next powered boot.
3. **Welded opaque shell versus open inspection.** No recorded decision exists.
4. **What the one spare analog pad (PA6) is for.** Mask load, supply sensing, or reference pad. They exclude each other.
5. **Hide-protection (HDP) posture.** A rejected draft disables it deliberately, two open ship-blockers require it, and two documents say deferred.
6. **RAW32 blind signing in production.** Section 5 recommends a compile-time fence that defaults to off.
7. **Seed ceremony.** One word per page with a never-digital warning costs nothing and claims no leakage reduction. A backup path that avoids the display is discussed in section 12.
8. **Restore on a unit whose case was opened.** A case-open wipe that ends at "restore from seed" sends the owner to type the seed on a compromised unit.

## Master table

51 consolidated items came out of 110 raw proposals: 42 recommended, 6 needing a redesign, 3 rejected. The completeness pass added 19 more, listed after them with section number 12. Section numbers: 1 implant, 2 display, 3 fault injection, 4 side channels, 5 clear signing, 6 boot, 7 secure elements, 8 PIN, 9 firmware update, 10 USB and TrustZone, 11 systemic.

| ID | Section | Recommendation | Kind | Cost | Priority | Novelty | Status | Defects | Tracked |
|---|---|---|---|---|---|---|---|---|---|
| USB-01 | 10 | Make the gateway between the two TrustZone worlds non-re-entrant and bind the signed calldata to what was confirmed | firmware | M | P0 | parity | Recommended | 1 | #132 #140 #152 #418 +4 |
| FI-01 | 3 | Run and publish the first on-silicon fault-injection campaign on the STM32U585 | process | L | P0 | parity | Recommended |  | see section |
| M20 | 11 | Take clock, power and tamper control away from the non-secure world; arm the voltage detector; pin the brown-out level | firmware | L | P0 † | parity | Recommended | 7 | #47 #48 #49 #50 +14 |
| M09 | 1 | Buyer-run pre-power verifier plus a host-verified per-unit birth record | mixed | XL | P0 † | beyond | Recommended | 5 | #27 #34 #37 #39 +31 |
| D-07 | 2 | Zeroize pixel-form secret residue and blank the panel on every lock, wipe and idle timeout | firmware | S | P1 | parity | Recommended |  | none |
| CS-01 | 5 | Fence RAW32 blind signing behind a compile-time, default-off tier | firmware | S | P1 ‡ | parity | Recommended | 1 | #338 #381 #692 #700 |
| M05 | 3 | FSBL fault-injection bundle before the freeze: fail-closed gate, encoded branch target, real random delays, tail scan, stack limit | firmware | M | P1 † | parity | Recommended | 6 | #46 #130 #189 #226 +19 |
| M02 | 6 | Option-byte posture: pin the masks on silicon, fix the OEM-lock bits, make silent production verdicts halt | mixed | M | P1 †‡ | parity | Recommended | 4 | #35 #37 #38 #39 +23 |
| SE-03 | 7 | Never wipe or charge a PIN attempt on an unauthenticated secure-element status word | firmware | M | P1 | parity | Redesign | 1 | #7 #104 #105 #106 +8 |
| SE-05 | 7 | Host freshness for the OPTIGA Shielded Connection (liveness probe after every handshake) | firmware | M | P1 | beyond | Recommended | 1 | #1 #4 #117 #123 +5 |
| SE-06 | 7 | Provisioning and first-boot ordering guards; a fail-safe is-provisioned check | firmware | M | P1 | parity | Recommended | 1 | #11 #36 #76 #87 +12 |
| M11 | 1 | Mass-production physical spec: shielded display lines, no test pads on secure buses, no void behind the panel, destructive-open shell | mixed | L | P1 ‡ | parity | Recommended | 3 | #36 #47 #50 #52 +11 |
| M16 | 7 | Bind and salt the PIN credentials given to both secure elements to the die; mask each seed share at rest | firmware | L | P1 ‡ | parity | Recommended | 4 | #5 #12 #124 #200 +13 |
| M14 | 8 | Wipe as a verified, resumable transaction with a designed recovery path after lockout | mixed | L | P1 | parity | Recommended | 6 | #5 #8 #12 #22 +18 |
| M19 | 11 | Make the existing assurance gates execute and block; add emulated fault-injection and glyph-leak regression nets | process | L | P1 | parity | Recommended | 6 | #10 #70 #81 #130 +38 |
| M21 | 11 | Fail-stop memory integrity: stack limits, decoded ECC fault handling, SRAM protection bits pinned in the ship profile | mixed | L | P1 † | parity | Recommended | 5 | #21 #46 #48 #82 +19 |
| pin-05 | 8 | One lockout response for all three unlock entry points | firmware | S | P2 | parity | Recommended | 1 | #75 #104 #120 #125 +5 |
| IMP-09 | 1 | Anti-klepto for the signature randomizer (the host-commit design fails; a companion-side minimality check survives) | firmware | M | P2 | beyond | Redesign |  | see section |
| M03 | 2 | Secret-frame display hardening: constant-time path for typed letters and PIN digit, no re-streaming, measured colour pair | mixed | M | P2 ‡ | parity | Recommended | 4 | #237 #258 #259 #260 +9 |
| M04 | 3 | Fault response without attempt charging: zeroize then reset in the glitch-halt sink, written verdict rules | mixed | M | P2 ‡ | parity | Recommended | 5 | #47 #82 #109 #200 +12 |
| M06 | 3 | Fix the fault-injection delay source, add jitter at gateway entry, then a measurement-gated random-delay interrupt | firmware | M | P2 ‡ | parity | Recommended | 6 | #46 #80 #228 #241 +14 |
| SCA-02 | 4 | Move secure-element tunnel AES from software onto the hardware AES engine | firmware | M | P2 | beyond | Recommended |  | #55 #202 #228 #236 +3 |
| CS-02 | 5 | Custody-change danger class with a mandatory interstitial; same-Safe same-nonce re-sign detection | firmware | M | P2 | beyond | Recommended |  | #329 #377 #474 #600 +5 |
| SE-08 | 7 | Lifetime usage budget on the OPTIGA guess path (the read-path counter as proposed fails) | mixed | M | P2 | parity | Redesign |  | #116 #119 #170 #251 +4 |
| M07 | 9 | One FSBL freeze-review package: vendor-key policy, minimum-version constant, Merkle-leaf signing, rollback-counter input | mixed | M | P2 †‡ | parity | Recommended | 3 | #31 #35 #39 #43 +19 |
| FWU-3 | 9 | Bind board model and hardware revision into the signed firmware manifest | firmware | M | P2 †‡ | parity | Recommended | 1 | #487 #540 #543 #545 |
| USB-06 | 10 | Central deny-first policy table in the gateway dispatcher (redesign of the proposed form) | firmware | M | P2 | parity | Redesign | 1 | #84 #140 #152 #418 +3 |
| SCA-01 | 4 | First on-silicon leakage campaign, aimed at the FORS secret and the pre-PIN tunnel crypto | mixed | L | P2 ‡ | beyond | Recommended | 1 | #228 #229 #236 #241 +4 |
| CS-03 | 5 | Secure-world spending-policy guard evaluated before confirm | mixed | L | P2 | parity | Recommended |  | #280 #343 #474 #636 +1 |
| CS-05 | 5 | Generic EIP-712 field walker gated by a known-domain filter; refuse empty domains | firmware | L | P2 | parity | Recommended |  | #329 #374 #381 #493 +4 |
| M17 | 7 | Per-boot refuse-only secure-element configuration audit; element identity proven host-side against a factory record | mixed | L | P2 | parity | Recommended | 4 | #6 #14 #27 #61 +23 |
| pin-04 | 8 | Ship the duress path only after its policy residuals and counter separation are closed | mixed | L | P2 | parity | Recommended | 1 | #10 #107 #123 #171 +8 |
| USB-08 | 10 | Signing-ceremony anomaly layer: intent fingerprint, changed-since-last-attempt page, repeat cap | firmware | L | P2 | beyond | Recommended |  | #329 #600 #616 #714 +1 |
| SYS-06 | 11 | Fault and tamper forensics that persist across the lockout reset | firmware | L | P2 | parity | Recommended | 1 | #47 #50 #75 #208 +10 |
| FWU-7 | 9 | Review rows for the update journal and versioned FSBL-consumed records (premises about the new design were wrong) | process | S | P3 | parity | Redesign |  | #138 #271 #480 #486 +7 |
| M15 | 4 | Consumption mask: measure it on the signing channel, then load it or demote it | mixed | M | P3 | parity | Recommended | 5 | #6 #53 #228 #229 +14 |
| SCA-03 | 4 | WOTS hash midstate reuse (small leakage gain at best, and it creates a new midstate target; measure first) | firmware | M | P3 | beyond | Redesign |  | #228 #229 #299 |
| CS-07 | 5 | Native decoders for the remaining drain primitives (setApprovalForAll, increaseAllowance, permit, revoke) | firmware | M | P3 | parity | Recommended | 1 | #78 #329 #343 #403 +6 |
| CS-09 | 5 | Address display integrity: checksum casing, chunking, a this-wallet tag | firmware | M | P3 | parity | Recommended |  | #348 #349 #366 #472 +1 |
| M18 | 7 | User-supplied entropy mixed into the seed draw, scoped as a defence against generator failure | firmware | M | P3 | parity | Recommended |  | #237 #238 #369 #370 +12 |
| M12 | 8 | Capped, reboot-surviving delay between PIN attempts; cooldown on host-raised unlock prompts | firmware | M | P3 | parity | Recommended | 2 | #119 #148 #175 #329 +9 |
| M13 | 8 | Device words shown mid-PIN so a substituted unit is noticed before the PIN is complete | firmware | M | P3 | parity | Recommended |  | #206 #249 #268 #280 +6 |
| M08 | 9 | Erased-tail check on the selected firmware slot; optionally widen the boot fingerprint to the signed manifest | mixed | M | P3 † | parity | Recommended | 3 | #226 #268 #486 #540 +5 |
| USB-09 | 10 | Host-compilable command router with fuzzing of the full USB path | mixed | M | P3 | parity | Recommended |  | #130 #136 #313 #428 +5 |
| M10 | 1 | Display-line electrical self-check, gated on a bench go/no-go study | mixed | L | P3 | beyond | Recommended |  | #47 #75 #208 #220 +14 |
| CS-04 | 5 | Render paymaster semantics: sponsor identity and fee-token pull | firmware | L | P3 | beyond | Recommended |  | #324 #328 #337 #353 |
| pin-03 | 8 | Fault-hardened encoding for the attempt-counter and signature-counter flash records | firmware | L | P3 | parity | Recommended |  | #200 #216 #392 #397 +3 |
| CS-10 | 5 | Signed catalogue refresh decoupled from firmware images, with a version floor | mixed | XL | P3 | parity | Recommended |  | #224 #225 #329 #345 +6 |
| SCA-09 | 4 | Masked secret compares for MCU-side checks (rejected) | firmware | S | rejected | parity | Rejected |  | #228 #240 #299 #312 +6 |
| M01 | 6 | Measurement-bound secret release (rejected: one extra FSBL fault defeats it at very high cost) | process | S | rejected | beyond | Rejected | 3 | #35 #39 #43 #46 +17 |
| CS-06 | 5 | On-chain intent commitment (rejected: the chain cannot observe what was displayed) | mixed | XL | rejected | beyond | Rejected |  | #78 #306 #691 |
| X1a | 12 | Masked blind binary restore of an existing 24-word phrase: 264 button bits under a per-bit on-screen mask, no echo. Defeats an unadapted, display-only bus tap | firmware | M | P3 | beyond | Recommended |  | #250 #784 #237 #371 +4 |
| X1b | 12 | Owner decision on a two-share create mode (panel shows only the device share, user share entered blind), and a recorded decline of the USB-pad shape | mixed | M | P3 | beyond | Recommended |  | #371 #250 #237 #772 +1 |
| X2a | 12 | `fwsign`: redundant compute in a second process, stored-signature equality, and a same-top-leaf archive sweep, as an acceptance criterion of the production signer | process | M | P2 | beyond | Recommended |  | #69 #225 #486 #266 +3 |
| X2b | 12 | Vendor-key custody decision record in #69, plus a `fwsign` `digest` / `assemble` split. Appliance firmware is a later, owner-gated item | mixed | M | P2 | beyond | Recommended |  | #69 #225 #486 #67 +3 |
| X3a | 12 | Pin the set of prompt-free key-derived gateway outputs to exactly CMD 15, and amend the acceptance record. The WON'T-FIX is not reopened | process | S | P3 | parity | Recommended |  | #181 #89 #724 |
| X4a | 12 | State the R-incarnation few-time caveat beside P14 and correct the claim sites that call the slot cap a true per-key cap. Fold into #89 | process | S | P2 | parity | Recommended |  | #89 #179 #180 #182 +1 |
| X4b | 12 | Bind the page-123 journal key to a public wallet tag before launch. Keep the page on wipe. Decommission erase is a later, gated part | firmware | M | P3 | beyond | Recommended |  | #182 #180 #634 #123 +3 |
| X5a | 12 | Paint pixel dialogs only from glyph bytes that went through the hasher, and attribute and lock the GPDMA channels | firmware | M | P2 | beyond | Recommended |  | #53 #79 #152 #835 +3 |
| X5b | 12 | BASEPRI_S mask across every verify-paint-proof bracket and the PendSV re-unlock dialog, comment fixes, silicon test with a negative control | firmware | M | P2 | parity | Recommended |  | #152 #835 #700 #692 +3 |
| X6a | 12 | Document pq1 as a required owner of a k-of-n Safe on the shipped on-chain `approveHash` route, with a threat-model row and a real-Safe test | process | M | P2 | parity | Recommended |  | #332 #636 #384 #486 +2 |
| X6b | 12 | Defer the off-chain EIP-1271 Safe co-sign route, add no gap carve-out, add a dbgen refusal of the SafeTx typed format, correct the adapter claim | process | S | P2 | parity | Recommended |  | #179 #381 #89 #691 +1 |
| X7a | 12 | Injective `personal_sign` rendering: labelled hex mode, visible line breaks, byte-length row, fallible renderer | firmware | M | P2 | parity | Recommended |  | #154 |
| X7b | 12 | Structured Sign-In with Ethereum (SIWE, EIP-4361) pages with address and chain consistency checks, shown before the raw message | firmware | L | P3 | beyond | Recommended |  | #154 |
| X8a | 12 | Secure memory protection unit (MPU) execute-never on secure SRAM, plus a stack-guard region, split out of #277 | firmware | S | P2 | parity | Recommended |  | #277 #374 #54 #540 |
| X8b | 12 | Decide FSBL-side execute protection before the freeze, as a default-deny MPU table, folded into M05 / #542 | firmware | S | P3 † | parity | Recommended |  | #540 #542 #54 #277 +2 |
| X9a | 12 | Make FSBL C10 verifier correctness a freeze-gate line in M07: gate-specific near-miss negatives first, then the 246-vector corpus replay, mutation testing, a written proof scope | process | S | P2 † | beyond | Recommended |  | #304 #722 #290 #581 +4 |
| X9b | 12 | Add an unticked owner box to the M07 note: FSBL signature-algorithm agility accepted or declined at freeze review, with its consequence | process | S | P3 † | parity | Recommended |  | #486 #696 #541 #540 +1 |
| X10a | 12 | FSBL pre-freeze claims ledger, report-only in the geometry gate, with an authority column; the #541 combined link stays the verdict | process | S | P2 † | beyond | Recommended |  | #541 #540 #758 #752 +5 |
| X10b | 12 | Secure-slot and secure-stack admission ledger, re-based on the shipping profile and folded into #752 and #374 | process | S | P2 | parity | Recommended |  | #374 #752 #540 #758 +4 |

Markers on the priority column:

- † The item, or part of it, lives in the FSBL or the option bytes. It must land before the first unit is locked, whatever its P-number.
- ‡ The completeness critic argued the item, or a named part of it, is rated too low. See "Priority corrections suggested by the critic" in section 12.

## Method and limits

**Method.**
- Eleven surfaces. For each, one agent inventoried pq1 by reading code, docs and issues, and one read the Trezor tree. Six web sweeps and a separate fact-checked research pass covered Ledger, Trezor's public material, other vendors, implant-detection literature, attacks on hash-based signatures, and clear signing.
- A gap analyst per surface produced 110 proposals.
- Round 1 verified 30 of them with three independent lenses: already implemented or already decided, technical soundness on this board, and vendor precedent.
- Round 2 merged duplicates into 21 clusters. Each cluster got a merger and then an independent skeptic. The remaining 27 single proposals got two lenses each.
- A consolidation pass deduplicated the live defects and re-opened the code for the ten most severe.
- A completeness critic reviewed the result. Follow-up finders proposed 19 more items, and each got an independent skeptic (section 12).

**Limits.**
- Evidence is code reading. No claim here was reproduced on hardware or in the emulator.
- Line numbers were recorded by agents and can be off by a few lines. The headline defect was re-read by hand.
- Verifiers refuted or corrected a large share of the first-round proposals. Refuted parts are kept in each section because the fact that killed them constrains future designs.
- The vendor-precedent lens ran as a separate vote only in round 1. In round 2 the merger and the feasibility lens checked precedent.
- Web claims are as of early October 2026. Several vendor statements are marked as unchecked in the sections.
- Priorities are analyst judgments after an independent review, not decisions.
- The headline defect is source-traced. Its trigger is evidenced on the silicon family through the Trezor tree, not on pq1. Other claims the critic could not verify are listed at the end of section 12.
- Vendor comparisons outside Trezor are weaker than the Trezor ones. Trezor was read as source code. Ledger and the others were read as public statements, and "no vendor ships this" means none was found.
- Incident attribution. Two things are easy to conflate. A teardown by Joe Grand, presented in 2026, documents a tampered Ledger Nano X that sniffed the display bus and sent the seed out over a cellular modem. Separately, press reports and a Ledger support statement from 9 and 10 October 2026 concern devices sold by one reseller. The research could not establish from a primary source that the two are the same hardware, or that the reseller incident explains the reported losses.
- The run was interrupted twice. No completed result was lost, and the interrupted steps were re-run.

**Raw data.** Per-item proposals, verdicts with their evidence, the pq1 inventories, the Trezor readings and the literature claims are in the sibling folder `security-frontier-research-2026-10-11/`. File names cited in the sections (`final/master.json`, `round2/cluster_<key>.json`, `verify/<ID>.json`, `imp/<ID>.json`, `inv_<surface>.json`, `trezor_<surface>.json`, `lit_all.json`, `deep_research.json`) resolve there.

---

## Live defects found during the research

The study surfaced 93 distinct live defects after deduplication by root cause: 34 code defects in the code that would ship (class A), 9 in bench, ui-px, duress-pin or rdp2-self-lock candidate builds (class B), 15 irreversible-at-freeze hazards (class C), 13 assurance or process defects (class D) and 22 documentation claims with no control behind them (class E). The sources are the 81 `merge.live_defects` entries of the 21 round-2 clusters, the skeptic's confirmations, denials and additions, and the 12 single proposals whose feasibility lens set `live_defect.is_defect`. About 45 of the 93 already have a tracking issue that names the defect. About 12 more have only an adjacent issue. The remaining 36 or so have none. The list at the end groups them into 25 entries. No production image can be built today: the OPTIGA S-2 fence (`OPTIGA_S2_PRODUCTION_BLOCKED`) rejects every `mode-production + optiga-trust-m` build, FSBL `mode-production` is a `compile_error`, and `make fsbl-release` hard-errors. "Reachable in the shipping feature set" therefore means "present in the code that would ship under PROD_SHIP_FEATURES / RELEASE_FEATURES (`Makefile:2662`, `Makefile:2718`)". No device has shipped. Almost every row is confirmed by code reading, not on silicon.

Five groups matter most. (1) The NSC (non-secure callable) gateway is re-entrant, so non-secure code can swap the calldata between the confirm screen and the signature (A1). It is the only finding that breaks "what you see is what you sign". It had no issue when this was written and is now #846. (2) The FSBL (first-stage bootloader) admits a manifest on one skipped branch and boots a slot chosen by one unencoded stack word (C1, C2). Write protection plus RDP-2 (readout protection level 2) would freeze that code for the life of the die. (3) The option-byte posture that RDP-2 freezes is wrong or unpinned: the OEM-lock mask points at reserved bits, the SRAM erase and ECC bits are not checked, BOR is advisory, and the RDP-2 burn routine itself is inert (C3 to C6, B1). (4) Unauthenticated secure-element verdicts and the wipe path: a forged 2-byte status word or a replayed OPTIGA session can force a dual-SE wipe, the wipe reports success without verifying, and on the locked profile a wiped device cannot be re-provisioned (A2 to A5, A8). (5) The assurance that should catch these does not execute: 165 rollback and geometry tests run in no workflow, the nightly Kani job has been red for 40 consecutive runs, the FI harness does not build, and master has no branch protection (D1 to D6). I re-opened the code for A1, A2, A6, C1, C2 and C3 (and for A8, A21, B1 and the RCC grep) in the working tree at `c75b0d9c` on `feat/pq1-board-target`. All still read as described and none is downgraded. Line drift: the OEM constants sit at `shared/src/lockdown.rs:278-279` (one cluster cites :279-280), and the bare-status arm is `secure/src/se050/scp03.rs:613-634`. For C2 I confirmed the source shape only (`fsbl/src/branch.rs:38-45` loads MSP and reset vector from the slot address with no re-check); I did not re-run the disassembly.

Conventions: "code read" means confirmed by code reading, not on silicon. Severity is the final value after the skeptic's corrections; where merger and skeptic disagree both are given. Source item is the cluster M-id or the single proposal ID from `final/master.json`.

### Update 2026-10-12: re-check before filing, and where each defect is now tracked

A second pass the same day filed the recommendation items (issues #869 to #894 and 50 comments) and found more errors in this report. They are listed in section 16. One issue from this table was edited: the fourth fix bullet of #849.

Before any issue was filed, the rows behind a new issue or a new comment were re-read by an independent pass that was asked to refute them: 45 rows, of which 32 were confirmed, 12 were partly confirmed and 1 was refuted (full texts in `focused/verify_*_FINAL.md` in the data folder). The author also re-read the rows behind the top issues against the reference manual and the code. **The rows that already had a tracking issue were not re-checked in this round** (for example A3, A7, A9, A11, A12, A17, A20, C5, C6, C8, C9, D2 to D4). The corrections below come from the re-check. The tables that follow are left as first written, except row A1.

One fact about the snapshot: the study ran at `c75b0d9c`. Master is `0feea78a` (2026-10-11), 156 commits later, and `c75b0d9c` is an ancestor of it. 74 of the 99 cited files are unchanged on master. The issues cite master line numbers; the tables below cite `c75b0d9c`.

**Corrections.**

- **A1: the batch handler is not affected.** It commits to each member's calldata digest before confirm and re-binds the encoded calldata to that commitment after the final confirm. Only the single-sign handler re-reads unbound calldata. In that handler every header field (sender, nonce, gas fields, paymaster hash, `to`, `value`) is copied to locals before confirm, so the calldata is the only swappable part. The fix pattern already exists in the tree.
- **A19, brown-out half: refuted.** The runtime's reset code clears `.bss` and `.data` on every reset, and no static escapes that, so treating a brown-out as scrub-worthy would add nothing. What survives a reset is the stack and unused SRAM1, which is the missing `SRAM_RST` bit (C4).
- **A32(b): no victim.** No `wait_random` call runs before the RNG is initialised. Parts (a) and (c) stand.
- **A34: "can never fire" is wrong.** ADC4 is a non-secure peripheral here, so non-secure code could arm a watchdog and raise internal tampers 7, 12 and 13. Internal tamper 3 is dead as well.
- **A24:** the "(RAW) approve" string belongs to the pixel UI only, and a host test does cover the rendering (it asserts the "Revoke approval" label as intended).
- **A4:** mechanism (a), the repeated wipe on every boot, is a consequence of (c) and would heal on the first good unlock. Mechanism (b) is a recorded S-6 trade-off whose stated remedy does not exist per device.
- **A5:** #106 already tracked most of it. New on re-check: because of a cached session, the wipe can return success having deleted nothing, so consuming the result at the call sites is not enough.
- **A15:** the difference between arms is deliberate and commented. The real gap is a lockout raised by a secure element while page 124 is below 10.
- **A16:** the window is much larger than 1 ms. The tamper enables survive a reset, so events during reset hold, the whole FSBL and early secure boot are erased the same way.
- **B5:** stronger than written, and it is ship-set code (`rdp2-self-lock` is forced on for production). The last step commits "all done" without requiring the earlier bits.
- **B6:** the second sentence (secret frames re-streamed during animation) is refuted: one forced frame per call. The first sentence stands, for the pixel UI only.
- **C10:** the lengths are manifest-declared, not signed; they are bound only through the hashes.
- **D5:** worse at the study commit (three harness crates fail to build). On master the C10 sign target was fixed by `ce717f31`; `fi_target` still fails, re-run by the author on master sources.
- **D6:** the compares survive on thumbv8m. It is the recompute that is merged into the first minimum, on every target, so the pending fix does not defend the single-glitch case. The "host-only blind spot" framing was wrong.
- **D7:** worse than written. No swept vector reaches a WOTS target-sum compare or the final root compare.
- **D9:** by source read the wipe-recovery test cannot pass on any current build since the S-6 change; its only recorded pass predates it.
- **D1:** stronger than written. The tool hashes no flash at all today.
- **E12:** the "18 gateway commands" count is correct for the ship set. Only the mechanism name is wrong.
- **E6, E7:** `HARDENING.md` is a requirements document; only its residency table and the lifecycle line in `CLAUDE.md` read as present fact.
- **Tracked column:** "untracked" was wrong for most of A5 (#106) and for A6 in part (#835 H4).

**Where each defect is tracked now.** 22 issues and 14 comments were filed on 2026-10-12, all labelled `source:frontier-research-2026-10`.

| Defect rows | Subject | Issue |
|---|---|---|
| A1, E5 | Gateway re-entrancy and the post-confirm re-read (single-sign handler) | #846 |
| C1, C2, E4 | FSBL signature gate on one skipped branch; unencoded slot word | #847 |
| C3 | OEM-lock mask on reserved bits | comment on #46 |
| C4 (and the stack-residue part of A19) | SRAM_RST missing from the ship profile | #848 |
| B1 | Inert RDP-2 burn | #849 |
| D1, E17 | Verify-before-first-power tool | #850 |
| A4 | Post-wipe recovery mechanisms | comment on #168 |
| A5 | Wipe verdict additions | comment on #106 |
| A6 | halt_on_glitch does not zeroize | #851 |
| A13, D12 | FLASH_ACR lever; wrong RCC_SECCFGR address in #80 | comment on #80 |
| A14 | Watchdog reset during PIN entry | #852 |
| A15, E10 | Lockout response differs by arm | #853 |
| A16 | TAMP_SCR cleared before read | comment on #75 |
| A18, C12 | No MSPLIM; no FSBL NMI or ECC handler | #854 |
| A10, E1 | PIN credentials not die-bound or salted | #855 |
| A21 | SECBOOTADD0 verdict is log-only | #856 |
| A24 | "Revoke approval" on the unknown-token path | #857 |
| A25, A26 | Seed letters and PIN digit on the public glyph path; fixed start letter | #858 |
| B6 | Pixel-UI live PIN digit on a non-forced frame | comment on #784 |
| A27 | cmd_pin_attempt_log bare pointer check | #859 |
| A30, A31 | PIN prompt on demand; scrambler fallback | #860 |
| A32, A33, A34 | Low-severity hardening items | #861 |
| B5 | First-boot done gates | #862 |
| B3 | Duress page-123 discriminator | #863 |
| C7, C10, C11 | FSBL freeze items | #864 |
| D5, D7, D8, D9, B9 | FI and wipe assurance gaps | #865 |
| D6 | fi_min recompute is merged | comments on #777 and #130 |
| E6, E7, E9, E12, E14, E17, E19, E20, E21, E22 | Docs that claim absent controls | #866 |
| E16 | Wrong UID address in #249 | comment on #249 |
| D13 (stale trackers) | Open issues that look fixed in the tree | comments on #418, #136, #370, #70, #239 |
| (section 13) | Pre-launch wallet-contract decision: #131 and the guard hook together; vault as candidate | #867 |

### Class A: code defects reachable in the shipping feature set

| # | Defect | Evidence (path:line) | Preconditions for an attacker | Severity | Evidence level | Tracked issues | Source item |
|---|---|---|---|---|---|---|---|
| A1 | The NSC gateway is re-entrant. `HandlerGuard::enter` only increments a depth counter and never refuses. `SIGN_SNAP_BUF` is a shared `static mut`, and the signed calldata is re-read from it after the confirm dialog. A nested veneer call can replace it. Off-chain signing is not swap-vulnerable. **Corrected 2026-10-12:** the batch handler is not affected. It commits to each member's calldata digest before confirm and re-binds the encoded calldata to that commitment after the final confirm (`cmd_sign_userop_batch.rs:1485`, `:1718`, `:1776-1811`, `:2263`, `:2276-2281` at master `0feea78a`). The first version of this row said the batch handler had the same pattern; that was wrong. | `secure/src/nsc/mod.rs:1277-1280`, `:1923-1990`, `:1026`; `secure/src/nsc/cmd_sign_userop.rs:388`, `:1933`, `:2133-2137`; `secure/src/nsc/cmd_sign_userop_batch.rs:2098`, `:2264`; `secure/src/sau.rs:702` | Non-secure code execution (the NS image is FSBL-measured and updates are signed), a banked NS SysTick or PendSV exception, and a user who confirms. Same `to`, `value` and `data_len`. A brief status flash is visible on the legacy LCD. | High to critical (feasibility lens); high (already-have lens) | Code read, re-opened. No proof of concept. Nested stack depth UNMEASURED. | None for the defect. Adjacent: #152, #140, #418, #835, #600 | USB-01 |
| A2 | SE050 SCP03 accepts a bare 2-byte status word with no MAC. `0x6986` maps to `AuthMethodBlocked`, then `PinLocked`, and the USB unlock arm wipes both secure elements. A forged `0x6985` burns a page-124 attempt on a correct PIN. | `secure/src/se050/scp03.rs:614-634`; `secure/src/se050/apdu.rs:385-395`, `:768`, `:845`; `secure/src/se050/mod.rs:2865-2871`, `:3027-3048`; `secure/src/nsc/cmd_request_unlock.rs:159-163` | Interposer on the SE050 I2C4 bus. The user enters the correct PIN through `CMD_REQUEST_UNLOCK` (OPTIGA errors take precedence). The boot and PendSV arms do not wipe. | Medium (feasibility lens); high candidate (already-have lens). Destructive, no key disclosure. | Code read, re-opened | #104, #105, #106 | SE-03 |
| A3 | The OPTIGA Shielded Connection handshake has no host freshness. Keys and the first nonce are functions of chip-sent values only, and responses are not bound to commands. A recorded session replays, and the MCU re-encrypts under a reused key and nonce. | `secure/src/optiga/shield.rs:698-701`, `:748`, `:757-759`, `:802`, `:915`, `:425-436`; `secure/src/optiga/mod.rs:573-578` | I2C1 interposer that recorded one genuine session under the current PBS (platform binding secret). Impact in dual-SE: forced wipe, forged wipe acknowledgement, stale TRNG contribution. Not a PIN bypass. | Medium-high (feasibility lens); high candidate (already-have lens) | Code read. No bench replay. | #117 (also #123, #396) | SE-05 |
| A4 | A device wiped after lockout cannot be recovered on the locked ship profile. Three mechanisms: (a) E120 is never reset, so every later boot reconciles `E120_used > page124_used` and wipes again; (b) the SE050 `USERID_OBJ` survives the wipe, provisioning refuses with `0x6986` and panics; (c) F1D0 cannot be rewritten, so OPTIGA provisioning fails at its first APDU. | (a) `secure/src/optiga/mod.rs:2795-2801`, `:3243-3271`; `secure/src/nsc/mod.rs:1661-1716`; `secure/src/dual_se.rs:113-136`. (b) `secure/src/se050/mod.rs:2286-2288`, `:1976-2001`; `secure/src/crypto.rs:472-496`. (c) `secure/src/optiga/mod.rs:1123-1131`, `:2832-2840` | Ten wrong PINs, or any forced wipe (A2, A3). (a) also needs the OPTIGA shield up at reconcile, which #127 doubts. Bench builds without `optiga-lock-operational` are not affected by (a). | High (availability, cheap denial of service). Latent, pre-ship. | Code read. `make pin-gate-wipe-e2e` claims an in-run re-provision succeeds (`Makefile:3401-3407`); unreconciled. | (a) #123. (b) #168. (c) none | M14 |
| A5 | The wipe reports success without verifying. The verdict is discarded at every call site, "WALLET WIPED" is shown and page 124 is reset to 0 regardless. `factory_reset_admin` returns `Ok(())` when the admin-PIN derivation fails. Existence checks coerce a transport error to "gone". `admin_exists()` returns false on a transport error, which clears the page-125 resume flag when the SE050 is unreachable. The admin object deletes itself even when data deletes failed. | `secure/src/nsc/cmd_request_unlock.rs:196`, `:204`, `:209`; `secure/src/main.rs:1946-1952`; `secure/src/nsc/mod.rs:1712-1714`; `secure/src/se050/mod.rs:3193-3205`, `:2416`, `:2434`, `:2443`, `:678-686`, `:3222-3224`, `:2329-2377`; `secure/src/dual_se.rs:631-640` | A transient or induced secure-element fault during the wipe. Exposure is bounded: the SE050 UserID and E120 silicon counters still limit guessing. | Medium | Code read | #106, #123 in part. Untracked: `admin_exists()` coercion, admin self-delete, `Ok(())` on derivation failure, unconditional page-124 reset at three sites | M14, M16 |
| A6 | `halt_on_glitch` parks in a bare `wfe` loop without zeroizing. When it trips inside an unlocked gateway handler, `master_secret`, the slot entropy and the cached slot key stay in secure SRAM. HardFault, NMI and panic all zeroize; this is the only park that does not. | `pqsigner-fi/src/lib.rs:273-285`, callers `:144`, `:153`; `secure/src/main.rs:4350`; `secure/src/hw/iwdg.rs:137`, `:287-303` | A detected glitch during signing or unlock, then a second physical capability to read SRAM while the core is parked. Window about 32 s (30,000 busy ticks plus the watchdog period), about 2 s from SysTick context. | Medium-high (merger); medium (skeptic, final) | Code read, re-opened | None. Adjacent: #835 (its H4 closure covers only the deleted TRNG-failure sink) | M04 |
| A7 | RCC, PWR and SYSCFG are not secure-attributed. Non-secure code can reprogram PLL1, the clock switch and the prescalers. It can also stretch the 120 s inactivity wipe, because the timeout counts SysTick ticks on the core clock. | No `RCC_SECCFGR`, `PWR_SECCFGR` or `SYSCFG_SECCFGR` write in `secure/src`, `fsbl/src`, `shared/src` (grep re-run, empty); `secure/src/hw/rcc.rs:10`; `secure/src/timeout.rs:3`, `:27`; `secure/src/main.rs:852-866`, `:1194` | Non-secure code execution. Use as a fault lever against `c10_sign_verified` is not demonstrated. | Medium-high (clock lever); idle stretch medium (merger), low-medium (skeptic) | Code read. Not run on silicon. | #80, #269. The #80 body gives the wrong register address (see D12). | M20 |
| A8 | SE050 `check_provisioned` returns false on any init or transport error. Combined with the OPTIGA leg it can open the seed wizard on a used device, and completing the wizard overwrites the live wallet's objects. | `secure/src/se050/mod.rs:1788-1796`; `secure/src/dual_se.rs:141-143`; `secure/src/main.rs:3971`, `:4062`; `secure/src/optiga/mod.rs:977-984` | A transient or induced SE050 fault, and OPTIGA reporting unprovisioned in the same boot (the legs are AND-combined; an interposer can spoof a status on the plaintext counter read). The user completes the wizard. Funds stay recoverable from the 24 words. | Medium-high (feasibility lens); high candidate (already-have lens) | Code read, re-opened. SE050-side overwrite not traced. | #111, #121, #169 | SE-06 |
| A9 | `provision_user_oid` and `verify_and_lock` return `Ok` on an already-Operational OPTIGA object without comparing its metadata. | `secure/src/optiga/mod.rs:1265`, `:1276-1287`, `:1087-1093`; `secure/src/optiga/apdu.rs:1530-1560` | I2C access before first boot to a chip whose target OID is still `Change=ALW`, to pre-freeze loose metadata. Not confirmed on silicon that a virgin part accepts this. | High per #87, owner-deferred (skeptic). The merger rated the comparator "informational". | Code read | #87 | M17 |
| A10 | PIN credentials are not die-bound or salted. The SE050 UserID credential is the raw 8-digit PIN. The OPTIGA F1D0 secret is an unsalted SHA-256 of the PIN. Extraction of either chip's storage yields the PIN, and the entropy join has no MCU-keyed input. | `secure/src/se050/apdu.rs:794-809`; `secure/src/se050/mod.rs:3025-3029`, `:2938-2943`; `secure/src/dual_se.rs:370-375`, `:455`; `secure/src/optiga/mod.rs:70`, `:916-918`, `:1939-1943`; `domain/src/lib.rs:97-103` | Decap-class read of one EAL6+ secure element on a stolen device, emulation of the destroyed chip on the board, then PIN entry. Or a broken SCP03 session under the accepted Grover residual. | Medium for each credential; medium-high as a claim-versus-code defect (see E1) | Code read. Reasoned, not demonstrated. | #124 (PIN-HMAC as offline dictionary oracle). The die-binding design is untracked. | M16 |
| A11 | The FI-delay source degrades. (a) On a TRNG error every `wait_random` length becomes the last good byte (initially `0x5A`). (b) Inside every `rng::fill`, 31 of 32 FI delays are identical. The fixes exist only on `perf/flash-opt-level-z`. | (a) `secure/src/fi.rs:58-59`, `:72`; `secure/src/rng.rs:115-121`. (b) `secure/src/hw/rng.rs:173`, `:227`, `:287`, `:343`, `:372` | (a) A persistent TRNG error or a per-call fault; one latched error is recovered by `init_locked()` (`secure/src/hw/rng.rs:650-662`). (b) None; it is the normal state. | (a) High (merger); medium (skeptic, final). (b) Medium-high (merger); medium (skeptic). FI hardening degraded, no direct bypass. | (a) Code read. (b) Silicon: #832 measured 32 calls, 31 fallbacks on the EVT unit. | (a) #834, #835. (b) #832, closed without the fix on master. Landing the branch is untracked. | M06 |
| A12 | The TAMP block is not secured: TAMPSEC is never set. Non-secure code can likely disable or clear the internal tampers, and with TAMPSEC=0 can write `TAMP_CR2.BKERASE` (lead). The release set polls tampers at 1 ms (no `tamp-irq`). | `secure/src/hw/bhk.rs:420-421`; `secure/src/sau.rs:672-675`; `secure/src/hw/tamp.rs:84-91`; `Makefile:2662` | Non-secure code execution. | Medium | Code read. TAMP has never run on silicon (#391). | #81, #50, #256, #75 | M20 |
| A13 | `FLASH_ACR` is non-secure by design, so non-secure code keeps a wait-state fault lever even after RCC is secured. | RM0456 section 7.9.1 as cited by the skeptic | Non-secure code execution. | Medium | Reference manual reading | None | M20 |
| A14 | The PIN dialog does not hold `TrustedUiWaitGuard` while `iwdg` is in the ship set. By source read, the USB unlock has about 30 s from veneer entry and the PendSV re-unlock about 4 s of stall budget before the watchdog resets the device mid-entry. | `secure/src/nsc/cmd_request_unlock.rs:35`; `secure/src/hw/iwdg.rs:284-296`, `:137`, `:305-322`; `secure/src/main.rs:4490-4628`; guard taken only at `secure/src/ui/confirm.rs:194`, `secure/src/ui/px/lcd.rs:750` | None; ordinary slow PIN entry. A reset during entry consumes no attempt. | Medium (availability) | Code read only. Not built or run with `iwdg` on. Button PIN entry has never run on pq1 silicon (#700). | None (searches return only #729) | M12 |
| A15 | The lockout response differs by entry arm. Only the USB arm wipes on `PinLocked`. The boot and PendSV arms show a status and break, arm no page-125 flag, and the tenth wrong PIN shows "Wrong PIN, try again". | `secure/src/main.rs:4198-4207`, `:4587-4598`, `:4209-4212`, `:1935-1954`; `secure/src/nsc/cmd_request_unlock.rs:112-164`, `:190` | Ten wrong PINs at the boot or idle prompt, or an SE-originated lockout with page 124 below 10. Both XOR halves stay on the chips until the next powered boot or USB unlock. | Low to medium (feasibility lens); medium (already-have lens) | Code read | None. Adjacent: #715, #104, #168 | pin-05 |
| A16 | `tamp::init` writes `TAMP_SCR = 0x0007_FFFF` before anything reads `TAMP_SR`. A backup-voltage or temperature tamper latched before a reset is erased with no wipe and no record. | `secure/src/hw/tamp.rs:270-272`, `:86`, `:372`, `:364-396`; `secure/src/main.rs:1400`, `:1529`; `secure/src/hw/bhk.rs:27-33` | An NRST pulse or brown-out within about 1 ms of an ITAMP1 or ITAMP2 event. ITAMP5 to ITAMP13 sit outside the clear mask and still wipe. | Medium (merger); low-medium (skeptic, final). Blocking for any external tamper input. | Code read (desk finding) | None. Can be filed under #75. | M11, SYS-06 |
| A17 | The NMI handler zeroizes and resets without reading `FLASH_ECCR`. A torn quadword in page 123 or 124 becomes a reset loop if a double-ECC read raises NMI. | `secure/src/main.rs:4636-4656` | A power cut during a page-123 or page-124 program. Conditional on the STM32U585 raising NMI on a double-ECC flash read. | Medium (availability, fail-secure) | Code read. Silicon behaviour undetermined. | #94 | M21 |
| A18 | No stack limit register (MSPLIM) is set in any image. A secure stack overflow would corrupt RAM silently. | grep for MSPLIM over `fsbl/`, `secure/`, `nonsecure/` returns two comments (`fsbl/src/main.rs:172`, `fsbl/src/manifest.rs:30`) | An input that drives stack depth past the bound; the bound is unproven (#374). | Medium, unproven (skeptic); low for the FSBL | Code read | None. Adjacent: #374 | M21, M05 |
| A19 | Handler stack copies of secrets are not scrubbed on any halt or abnormal reset. The boot scrub clears named statics only, and `SRAM_RST` is not set. A brown-out reset is classified Cold and not scrubbed. | `secure/src/nsc/mod.rs:1729-1745`; `secure/src/main.rs:1311-1333`, `:4344-4348`; `secure/src/reset_cause.rs:95-98`, `:182-185` | Physical SRAM readout after a fast power cycle or reset. | Medium (stack residue); low-medium (BORRSTF) | Code read. Frame layout not measured. | #82. The BORRSTF case is untracked. | M04, M21, M20 |
| A20 | The release set co-enables `tamp + tamp-wipe + bhk` with ITAMP6 and ITAMP9 in confirmed mode. A false ITAMP9 during legitimate SAES or BHK use would erase the BHK and factory-reset both secure elements. Candidate. | `Makefile:2662`; `secure/src/hw/tamp.rs:290-307` | None; a false positive. | High if it occurs; probability UNMEASURED | Code read. Never exercised on silicon. | #208 | M20 |
| A21 | The secure-world SECBOOTADD0 check does nothing in production. The mismatch branch contains only `secure_log!`, which expands to nothing without `debug-log`. | `secure/src/main.rs:1276-1290`, `:62-64` | A fault-skipped Phase A. The field is frozen at RDP-2 and Phase A halts on it before the burn, so no option-byte write reaches the mismatch state after lock. | Low-medium (merger); low (skeptic, final) | Code read, re-opened. Not link-verified. | None | M02 |
| A22 | `fi_min`'s recompute guard is compiled away. The call sites are non-secure USB and HID length clamps, two of which feed a raw `copy_nonoverlapping`. The uncommitted `black_box` fix is itself folded on thumbv8m at `opt-level=s`. | `pqsigner-fi/src/lib.rs:238-249`; `nonsecure/src/usb/commands.rs:862`; `nonsecure/src/usb/transport.rs:167`; `shared/src/apdu_framing.rs:433-434`, `:469-470` | One fault on a single-clamp site. The non-secure world holds no secrets. | Medium-low | Code read plus LLVM IR and assembly probe on standalone call sites, not the LTO image | #130, #777. The defeated fix is untracked. | M19 |
| A23 | `EIP-1271 RAW32` is compiled into every image with only a length check. No feature or runtime switch removes it. | `secure/src/nsc/cmd_sign_offchain.rs:212-218`; `Makefile:2672-2675` | A hostile companion that downgrades typed data to RAW32, and a user who approves the "! BLIND RAW32" page. | Medium (feasibility lens). The already-have lens says it is a tracked policy residual, not a defect. | Code read | #381 (decision only; the fence mechanism is untracked) | CS-01 |
| A24 | `approve(addr,0)` on a contract with no authenticated ERC-20 metadata renders "Revoke approval". ERC-721 `approve(to,tokenId)` shares the selector, so on an NFT contract the call grants token 0. | `secure/src/tx/display/erc20_unknown.rs:90-97`; `secure/src/tx/display/erc20_screens.rs:45`, `:193-194`; `pqsigner-erc7730/src/display/primitives.rs:1236-1238` | A direct call to a contract absent from the token database with tokenId 0. The page still shows "! Unknown token" and "(RAW) approve". | Low-medium | Code read. Not exercised on device or in a host test. | Introduced by #474 (closed). Untracked. Governing gate: #343 | CS-07 |
| A25 | Typed seed letters and the active PIN digit are drawn through the address-keyed public font lookup on the legacy 16x4 path. The letter row is also reached from `verify_mnemonic`, so every new wallet's 3 check words pass through it. | `secure/src/ui/seed_wizard.rs:918-949`, `:624`, `:656`; `secure/src/ui/lcd.rs:153-172`; `secure/src/ui/secret_text.rs:84-93`; `secure/src/ui/pin_entry.rs:187-221` | A measuring attacker near or inside the device during the wizard or PIN entry. | Low-medium (merger); low (skeptic, final). Evidence for the channel is an emulated address trace only. | Code read. Channel emulated only. | None (#784 covers the px path only) | M03 |
| A26 | The seed letter dial starts at a fixed `a` and the candidate cursor at range start, so the press or repaint count reveals each letter. PIN entry has random start digits; letters have no equivalent. | `secure/src/ui/seed_wizard.rs:817`, `:896`, `:963`, `:824` | An observer who can count button presses or SPI repaint bursts. | Low-medium | Code read | None | M03 |
| A27 | `cmd_pin_attempt_log` guards a 36-byte write to a caller-supplied address with one bare boolean branch. It has no sentinel check, no `HandlerGuard` and no PIN gate. | `secure/src/nsc/cmd_pin_attempt_log.rs:23-33`; `secure/src/nsc/mod.rs:2052-2060` | Non-secure code execution to supply the pointer, plus one instruction-skip glitch. The payload is log codes, not attacker-chosen bytes. | Low (feasibility lens); low-medium (already-have lens) | Code read. Fault not demonstrated. | None. Adjacent: #84, #152, #719 | USB-06 |
| A28 | OPTIGA `send_command` sends plaintext whenever `shield.active` is false. | `secure/src/optiga/apdu.rs:523-533`; `secure/src/optiga/mod.rs:265`, `:313`, `:960`, `:994`, `:2752` | A forced session kill. The skeptic found no ship-path secret-bearing command that reaches the plaintext branch; entry points call `ensure_shield` first. | Medium candidate (merger); low to medium, reachability unproven (skeptic) | Code read | #126 | M17 |
| A29 | The consumption-mask periodic reseed is fail-open with no counter or log, and a skipped window costs about 1 s before retry. The pad self-test runs only under `debug-log`. | `secure/src/hw/consumption_mask.rs:166-192`, `:93-110`; `secure/src/consumption_mask_prng.rs:84-93`; `secure/src/main.rs:4329-4337` | None. Impact is bounded because the mask pin drives no load on either board. | Low | Code read. #831 measured zero skips at non-signing load; the rate under signing is UNMEASURED. | #831, #646 | M15, M06 |
| A30 | A locked device paints the trusted PIN dialog on every unsolicited host `INS 0x10` with no rate bound. The host can lock at will and then raise the prompt again. | `nonsecure/src/usb/commands.rs:286`, `:497-500`, `:287`, `:504`; `secure/src/nsc/cmd_request_unlock.rs:29-31`, `:51-54`, `:56-65` | A hostile USB host. No attempt is consumed and no secret is loaded without a physical PIN submit. | Low (nuisance, habituation) | Code read | None (#148 fixed the unlocked case only) | M12 |
| A31 | The PIN-entry digit scrambler falls back to all-zero start digits when `rng_strong::fill` fails; the `Result` is discarded. | `secure/src/ui/pin_entry.rs:73-88` | An attacker able to force the RNG failure regains the press-count channel. | Low | Code read | None | M04 |
| A32 | The first sentinel check after non-secure entry has no preceding random delay, and `wait_random` before `hw::rng::init()` uses the constant `0x5A`. The debug cycle counter is handed to the non-secure world. | `secure/src/nsc/cmd_sign_userop.rs:105-116`; `secure/src/nsc/ns_ptr.rs:84-90`; `secure/src/main.rs:1193`, `:1351`, `:1384`, `:4263-4273` | Two coordinated faults. A hardening gap, not a bypass. | Low | Code read | None for the veneer jitter | M06 |
| A33 | A single disagreeing pair of page-124 reads returns `PinLocked`, which the USB arm converts into a dual-SE factory reset. Deliberate fail-closed design; listed as an owner question. | `secure/src/nsc/mod.rs:1429-1436`; `secure/src/nsc/cmd_request_unlock.rs:160-164` | One transient read fault. An attacker with the device can already force a wipe with 10 wrong PINs. | Low (availability) | Code read | None | M04 |
| A34 | Smaller items in every `usb` or `tamp` build: `GET_DEVICE_INFO` returns a fixed version 3.0.0, 16 zero bytes for the device UID and the serial "0001"; ITAMP7, ITAMP12 and ITAMP13 are enabled but can never fire because no ADC4 driver exists; the page erase at `FW_BEGIN` has no blank read-back. | `nonsecure/src/usb/commands.rs:178-182`, `:416`; `nonsecure/src/usb/mod.rs:199`; `secure/src/hw/tamp.rs:290-307`; `secure/src/hw/flash.rs:1307-1352` | None | Low | Code read | None | M09, M20, M08 |

### Class B: code defects only in bench, ui-px, duress-pin or rdp2-self-lock candidate builds

`rdp2-self-lock` is forced on for `mode-production`, so its rows become class A or C the moment a production build exists.

| # | Defect | Evidence (path:line) | Preconditions for an attacker | Severity | Evidence level | Tracked issues | Source item |
|---|---|---|---|---|---|---|---|
| B1 | The RDP-2 burn is inert. `OPTSTRT`, `OBL_LAUNCH` and `OPTLOCK` are written to `FLASH_SECCR`, where they do not exist, so `program_rdp_level2_and_launch` returns `Ok` without burning. The `OPTWERR` check is also unpinned. | `secure/src/hw/flash.rs:384-394`, `:541-558`, `:560-563` | None. A unit would believe it is locked while it stays at RDP-0. | High for the invariant #10 claim | Code read, re-opened (the defect is documented in place). Never executed. | #268 (recorded there; no dedicated issue) | M09 |
| B2 | Under `rdp2-self-lock` with the journal at Rotated, the salted-final OPTIGA PBS is written to E140 with no `ensure_shield`, so it goes out in plaintext when the shield is down. | `secure/src/optiga/mod.rs:603-618`, `:820-872`; `secure/src/optiga/apdu.rs:529-533`; `secure/src/hw/secret_keys.rs:531` | An active I2C interposer that blocks the handshake and forces an "unprovisioned" reading. A passive tap does not get it in the normal flow. | Medium-high (breaks the invariant #3 tunnel for that device) | Code read | #118 | SE-06 |
| B3 | Duress builds: page-123 counters have no wallet discriminator, so `OFFCHAIN_STATUS` after a decoy unlock exposes the real wallet's counts. SE050 duress objects are absent from the wipe lists. Wipe-on-duress swallows the wipe error and does not reset page 124. | `secure/src/offchain_state.rs:23-33`; `secure/src/nsc/cmd_offchain_status.rs:36`, `:75-79`; `secure/src/nsc/mod.rs:1513-1540`, `:1543-1548`; `secure/src/se050/mod.rs:2266-2288` | A coercer who inspects the device after a decoy unlock or after a wipe. | Medium (deniability failure, no key or fund compromise) | Code read | #107, #636. The page-123 separation and the swallowed duress wipe are untracked. | pin-04, M14 |
| B4 | ui-px: the restore letter row bypasses `blit_secret_run` and the force path and leaves a digest of letter-derived pixels in a static. | `secure/src/ui/px/status_map.rs:297-317`; `secure/src/ui/seed_wizard.rs:915`; `secure/src/ui/px/lcd.rs:319-322`, `:663` | A measuring attacker during restore on a ui-px image. | Medium per the issue | Code read | #784 | M03 |
| B5 | First-boot `done & DONE_*` skip gates are unhardened single branches. This replaces the merger's "dense phase encoding" finding, which the skeptic denied (the step records are CRC-framed). | `secure/src/first_boot/state.rs:306-375` | One fault during first boot. | Low-medium, untraced | Code read | None | M04 |
| B6 | ui-px: the active PIN digit goes out on a non-forced frame, and secret frames are force-streamed repeatedly while the entry animation runs, up to the 3 s cap. The cadence is bounded by the roughly 48.6 ms frame stream time, not 16 ms. | `secure/src/ui/px/status_map.rs:277-290`; `secure/src/ui/px/screens.rs:127-128`; `secure/src/ui/px/lcd.rs:664-690`, `:47`, `:639` | A bus eavesdropper who averages repeated identical transmissions. | Low. Frames per seed page UNMEASURED. | Code read | None (#784 mentions `pin_row` only as the masked case; #783 adjacent) | M03 |
| B7 | `get_version_ext` builds a 5-byte APDU that goes on the wire with no Le. It is the primitive an SE050 variant pin depends on. | `secure/src/se050/apdu.rs:944-950`, `:314-322`, `:337` | None. Not on any boot path; callers are in `se050_stress` only. | Medium (latent prerequisite) | Code read, confirmed by construction | #444 | M17 |
| B8 | A cross-board image signed with the shared dev key is accepted by the firmware update handler. On pq1 an iota2 image leaves the secure-element rail off and hands its reset and enable pins to the non-secure world. | `secure/src/fw_update/mod.rs:468-520`; `secure/src/hw/buttons.rs:108-116`; `Makefile:2913` | A vendor-signed image for the wrong board. Bench only today. | Low (availability; no secret disclosed) | Code read | #487 (its "second board exists" trigger has fired) | FWU-3 |
| B9 | At HEAD the consumption-mask driver carries its own inline xorshift and reseed state while the tested pure module has no production caller. The fix is an uncommitted working-tree diff. | `secure/src/hw/consumption_mask.rs:138`, `:145`, `:194-208` (HEAD); `secure/src/consumption_mask_prng.rs:22-42` | None (test-coverage gap) | Low | Code read | None | M15 |

### Class C: irreversible-at-freeze hazards

No production FSBL is buildable. These paths are unconditional in the only FSBL code that exists, so they are what write protection plus RDP-2 would freeze.

| # | Defect | Evidence (path:line) | Preconditions for an attacker | Severity | Evidence level | Tracked issues | Source item |
|---|---|---|---|---|---|---|---|
| C1 | FSBL signature admission fails open on one instruction skip. After the double-evaluated verify, the caller compares against the sentinel and branches to reject, with accept as the fall-through. No later stage re-checks the verdict. | `fsbl/src/main.rs:343-348`; disassembly `0x0c000e54` to `0x0c000e5e` (iota2 ELF), `0x0c000e5c` to `0x0c000e66` (pq1 ELF) | Attacker-chosen bytes in a slot and manifest page (SWD at RDP-0, or a flash-write primitive after RDP-2), plus one timed skip on every boot. | High in the instruction-skip model (merger); medium, chained (skeptic, final) | Disassembly of bench ELFs plus code read, source re-opened. Emulated sweep (#591) not run on this glue. Silicon feasibility UNMEASURED. | None. Documented as a residual at `tools/sca/README.md:369-394`. | M05 |
| C2 | The FSBL branch target is not bound to the verified slot. The slot is a 2-variant enum spilled to the stack across the 4 s fingerprint hold and decoded as "non-zero means slot B". One data fault or one skip boots the other slot while the panel shows the verified slot's words. `pick_slot` is also steerable to the older valid slot, since no rollback floor works. | `fsbl/src/main.rs:220-222`, `:297`; `fsbl/src/branch.rs:36-50`; `fsbl/src/slot.rs:10-13`; disassembly `0x0c00181c`, `0x0c00192a` to `0x0c00193a` | One fault. Useful when the other slot holds a signed older image, which is the normal state after an update. | Medium-high in model. The skeptic calls it the most reachable FSBL defect. | Disassembly of bench ELFs plus code read. Silicon UNMEASURED. | None | M05 |
| C3 | The OEM1LOCK and OEM2LOCK mask constants are bits 26 and 27 of `FLASH_NSSR`. The vendor header and SVD give bits 18 and 19. The gate fails closed today because `OEM_LOCK_MASK_PINNED = false`. If the flag were flipped without correcting the bits, a planted OEM regression key would pass Phase A. | `shared/src/lockdown.rs:278-279`, `:290`, `:513-514`; `secure/src/hw/flash.rs:478-481` | Access during the RDP-0 or RDP-1 window to plant an OEM key, and a future pin-flag flip without the mask fix. | Latent-high; none today | Code read, re-opened, against the vendor SVD and CMSIS header | None. Can be folded into #46. | M02, M09 |
| C4 | The ship option-byte verifier has no field for `SRAM_RST`, `SRAM2_RST`, `SRAM2_ECC` or `SRAM3_ECC`. The self-lock would freeze whatever the factory left, including defaults with no hardware SRAM erase and no ECC. The only recipe that sets a RAM-erase bit sets `SRAM2_RST`, which erases the non-secure world's RAM. | `shared/src/lockdown.rs:295-312`, `:517-521`; `Makefile:364-380`; `secure/src/reset_cause.rs:96-98` | None; a factory default. | High once the self-lock ships (irreversible per die); none today | Code read | #82 covers the bench recipe only. The verifier fields are untracked. Related: #48 | M21, M04 |
| C5 | PVD is disabled and `BOR_LEV` is unpinned. The ship profile has no BOR field, so a unit can lock at the 1.71 V default. | `shared/src/lockdown.rs:338-345`, `:517-522`; `secure/src/first_boot/mod.rs:245-246`; `Makefile:375-380` | Physical supply control. | Medium (ship-blocker) | Code read | #49, #46, #248 | M20 |
| C6 | No code resets the write-only OEM1 and OEM2 keys before or with the RDP-2 burn. The first-boot candidate can only halt (`0x080A`), and it halts on every unit today because the mask and the WRP1A mask are unpinned. | `shared/src/lockdown.rs:290`, `:485-487`, `:513-515`, `:575`; `secure/src/first_boot/state.rs:77-80`; `fsbl/src/optbytes.rs:24-29` | A key planted during the RDP-0 window. Fails closed. | Medium (ship gate) | Code read | #46, #387, #40 | M09 |
| C7 | Every FI delay in the FSBL is the constant `0x42`. The two evaluations inside the gate are at a fixed separation and a fixed time from reset. | `fsbl/src/fi.rs:31-33`; `movs r0,#66` at `0x0c000846` | A glitch rig. An acknowledged weakening, not a standalone bypass. | Medium | Code read, re-opened; disassembly | None (FSBL TRNG bring-up is untracked) | M05 |
| C8 | The rollback floor can never rise. The FSBL reads the rejected unary OTP tally and no code path writes a floor. `CMD_FW_COMMIT` always refuses, so no update activates through the handler. | `fsbl/src/otp.rs:1-41`; `fsbl/src/main.rs:190`, `:351`; `secure/src/nsc/cmd_fw_commit.rs:332-375` | Any older vendor-signed image. | Ship-blocker, already tracked | Code read | #31 | M07 |
| C9 | After lock, no code checks WRP, OEM locks, BOOT_LOCK or BOR_LEV. The FSBL tripwire covers only TZEN, RDP, SECWM, boot address and SWAP_BANK. | `fsbl/src/optbytes.rs:24-30`, `:66-77`; `secure/src/first_boot/mod.rs:174-176` | A fault-skipped Phase A. The fields are immutable at RDP-2. | Medium (merger); low (skeptic, final) | Code read | #46, #270. The exact OPTR masked compare is #141 (closed without implementation). | M02 |
| C10 | The slot tail beyond the signed lengths is never measured and never verified erased, at boot or at COMMIT. It is outside the hash, the manifest and the 8-word fingerprint. | `fsbl/src/verify.rs:38-108`, `:52-68`; `secure/src/fw_update/verify.rs:42-58`; `fw-manifest/src/lib.rs:177`, `:180` | A prior secure-world write or a faulted erase, plus a later control-flow fault that reaches the tail. A full SWD flash diff at RDP-0 still catches it. | Low-medium (M05); low (M08) | Code read | None | M05, M08 |
| C11 | The boot fingerprint covers the secure image only. Two validly signed releases that differ only in the non-secure image or the version render the same 8 words. | `fsbl/src/verify.rs:109`; `fsbl/src/main.rs:286`; `secure/src/fw_update/mod.rs:135` | A validly signed alternative non-secure image. Not a signature bypass. | Low-medium (merger); low (skeptic) | Code read | None | M08 |
| C12 | The FSBL has no NMI or ECC handler and no stack limit. A persistent double-ECC word in a range it reads would halt every boot, even when the other slot is good. | `fsbl/src/main.rs:76-78`, `:172`; `fsbl/Cargo.toml:131` | A power cut during a slot or manifest program. Conditional on the silicon raising NMI. | Medium (availability), conditional | Code read. Silicon behaviour UNMEASURED. | #94 (ECC behaviour). The handler is untracked. | M21, M08, M05 |
| C13 | The FSBL has no board-model check. The guard must land before the freeze or it can never be added. | `fsbl/src/main.rs:321-353`; `fsbl/build.rs` (no per-board key) | A vendor-signed image for another board or revision. | Low today | Code read | #487 | FWU-3 |
| C14 | The HDP (hide-protection) posture is unratified. #39 as specified hides pages the FSBL executes from and says "code+secrets" although the FSBL holds no secret. A rejected draft says HDP is off "chosen deliberately" while #39 and #43 require it. | `geometry/src/lib.rs:123-125`; `fsbl/src/branch.rs:38-98`; `docs/security/production-security.md:521-528`; `docs/security/threat-model.md:652` | None; a decision defect that must close before the freeze. | Medium (merger); under-specified, not unimplementable (skeptic, downgraded) | Document and issue reading. No HDP write exists in code. | #39, #43, #752 | M01 |
| C15 | A single baked vendor key with no recovery path would be permanent after the freeze. | `fsbl/src/vendor_pubkey.rs:20-23`; `fsbl/src/main.rs:335-346` | Vendor key compromise or loss. | Design residual. The skeptic says it is not a defect: it is the documented default. | Code read | #486, #220, #39 | M07 |

### Class D: assurance and process defects

| # | Defect | Evidence (path:line) | Preconditions for an attacker | Severity | Evidence level | Tracked issues | Source item |
|---|---|---|---|---|---|---|---|
| D1 | The external verifier that invariant #10(a) relies on reads only option bytes and named flash hashes: no OTP, UID, IDCODE, OEM-lock bits or per-device pages. The only checkable profile is the bench one; the ship template is refused. Its write guard is a deny-list although the docstring and Makefile call it an allow-list. No buyer can run it on a sealed unit. | `tools/verify_ship_state.py:84-100`, `:134-157`, `:121-127`, `:53-74` | Transit interdiction of a unit shipped at RDP-0. | High for the invariant #10 claim | Code read | #595, #46 (adjacent). The tool gap itself is untracked. | M09 |
| D2 | Master has no branch protection or rulesets, so every CI result is advisory. The binary never-ship audit and the gateway-ABI check run in no workflow. | `tools/build-evt-image.sh:83` (the only ABI-check caller); `gh api` reports `protected:false` | A refactor that reopens a defect still merges. | Medium | CI configuration read and API query | #456, #604, #735, #690, #701 | M19 |
| D3 | 165 rollback and geometry tests (156 + 9; the merger counted 164), the 6 `geometry_consistency` tests, the FSBL geometry measurement gate, 17 sphincs-c10 tests including the primitive known-answer test, and 21 feature-gated tests run in no workflow. | `.github/workflows/ci.yml` host-tests package list (grep of all 11 workflows empty) | A geometry regression (WRP range, slot map) merges green. | Medium | CI configuration read. The suites pass when run by hand. | #720, #721, #722, #724, #725 | M19 |
| D4 | The nightly Kani and Kani-mutation jobs fail every night. The skeptic counts 40 consecutive failures back to 2026-09-01. Both die from a runner shutdown inside one harness, not a timeout. | `gh run list nightly.yml`; run 38045775090 | Decoder panic-freedom and counter proofs cited in docs are local-run claims only. | Medium | CI run records | #776. A per-harness timeout and memory limit is untracked. | M19 |
| D5 | The FI emulation harness does not build against current `fi.rs` (E0425 `byte_nonsecret`), and the C10 sign target does not model the production signer (plain `sk.sign` twice instead of `sign_with_shuffle`). Every "FI-swept" claim for the `fi.rs` primitives is unreproducible. | `tools/sca/fi_target/src/main.rs:33-38`; `secure/src/fi.rs:58`; `tools/sca/c10_sign_target/src/main.rs:97`, `:99`; `secure/src/crypto.rs:350`, `:358` | None (tooling) | Medium | `cargo check` reproduced | None found. Adjacent: #591, #232, #211 | M19 |
| D6 | `make check-fi-ir` calls a script that was never committed. The script is host-only and counts compares, so it would pass the fix that thumbv8m folds away. #130 has said "FIXED in working tree" for 52 days. | `Makefile:4480-4485`; `scripts/check_fi_ir.sh` (untracked) | None (process) | Medium as a process failure | Git history read plus IR probe | #777, #130. The host-only blind spot is untracked. | M19 |
| D7 | The emulated "clean" verdict for the C10 verifier stops after the first 8,000 instructions, so the target-sum branch (a single bare compare) is unswept. | `tools/sca/README.md:1842-1848`; `sphincs-c10/src/wots.rs:171-180` | In the FSBL the check must be skipped in both evaluations. Round 1 estimated a one-time offline grind of about 2^56 hashes; the order of magnitude was sanity-checked, not re-derived. | Medium (unknown until swept) | Code and document read | None | M05 |
| D8 | Fixes that exist only outside master: the FI-delay source and pool commits on `perf/flash-opt-level-z` (#832 is closed without them), the `fi_min` diff, and the consumption-mask driver refactor. | `secure/src/fi_delay_pool.rs` (absent on master); `secure/src/hw/consumption_mask.rs` (41+/75- uncommitted) | None (process) | Medium | Git history read | #832 (closed), #834, #835. Landing the branch has no issue. | M06, M15, M19 |
| D9 | `make pin-gate-wipe-e2e` proves post-wipe recovery only on a non-locked `otp-hardcoded-master-key` build; its Makefile text reads as if recovery is proven. The lockout-wipe FI suite depends on an uncommitted `WipeFault` and would not execute inside `cfg(not(test))` modules. | `Makefile:3401-3407` | None | Medium | Code read | None | M14 |
| D10 | No leakage harness covers the px glyph path that draws the live PIN digit and seed letters. The `glyph-leak` target covers the legacy font only. `tools/sca/README.md:1280` still names the SSD1306. | `tools/sca/Makefile:231-237`; `pqsigner-ui-px/src/rows.rs:76-88` | None (ui-px only) | Medium (ui-px only) | Code read. Leakage not measured. | #784, #779 (adjacent) | M19, M03 |
| D11 | `sca-trigger` has zero call sites although its module doc lists three. A capture campaign would arm on a pin that never moves. | `secure/src/hw/sca_trigger.rs:25-33` | None (bench tooling) | Low | Code read | #228 has a "wire sca-trigger" checkbox but does not record that the wiring is absent | SCA-01 |
| D12 | Issue #80 gives `0x5602_0C10` for `RCC_SECCFGR`. That address is `RCC_ICSCR3` (HSI trim). Implementing the issue as written would write into the HSI16 calibration register. | `docs/archive/work-todo-retired-2026-07-19.md:54-55` | None (trap for the implementer) | Low | Vendor header comparison | #80 (the defect is in the issue) | M20 |
| D13 | No CI job compiles `duress-pin`. Stale trackers: #418 (guard now present), #370 (already fixed), #136 (looks fixed), #268's confirm-gate checkbox, #120's cited status mapping. | `.github/workflows` (no match) | None | Low | CI and issue read | #636 (parent) | pin-04, M19, M09 |

### Class E: documentation that claims a control which does not exist

| # | Defect | Evidence (path:line) | Preconditions for an attacker | Severity | Evidence level | Tracked issues | Source item |
|---|---|---|---|---|---|---|---|
| E1 | The threat model says the dual-chip split defeats single-chip extraction and that an attacker "still needs to use the chip with its silicon-enforced PIN gate". Either chip's storage yields the PIN (A10). | `docs/security/threat-model.md:226`, `:600`, `:121`, `:222-223` | n/a | Medium-high as a claim-versus-code defect | Document against code | None | M16 |
| E2 | The threat model asserts Shielded Connection freshness that the handshake does not have (A3). | `docs/security/threat-model.md:233`, `:255` | n/a | Medium | Document against code | #117 notes the contradiction; no checkbox | SE-05 |
| E3 | CLAUDE.md invariant #10 calls the geometry registry "CI-pinned". The tests run in no workflow (D3). | CLAUDE.md invariant #10 | n/a | Medium | Document against CI | #720 | M19 |
| E4 | `fsbl/src/fi.rs` states the bar for bypassing the FSBL gate is 2 coordinated faults. The binary implements one (C1). | `fsbl/src/fi.rs:12-16` | n/a | Medium | Re-opened | None | M05 |
| E5 | SAFETY comments call the dispatcher non-reentrant, and a comment asserts that PRIS stops the non-secure world preempting a secure veneer (A1). The threat model has no row for nested entry. | `secure/src/nsc/mod.rs:1001`, `:1024`, `:1915`; `secure/src/nsc/cmd_sign_offchain.rs:131`; `secure/src/sau.rs:716` | n/a | Medium | Code read | None | USB-01 |
| E6 | HARDENING.md describes boot-time SE attestation in the present tense, with an NXP root certificate hardcoded in the image. CLAUDE.md's lifecycle line says "SE attest". No attestation read exists in `secure/src`. | `docs/security/HARDENING.md:178-189`, `:32`, `:176`; contradicted by `docs/security/threat-model.md:505-506` | n/a | Low | Document against code | None | M17 |
| E7 | HARDENING.md describes a PIN credential design that does not exist: an AESKey object, a stretched PIN, PBKDF2, PIN digits collected in the non-secure world. | `docs/security/HARDENING.md:158-163`, `:258-270` | n/a | Low (it is the document a reviewer would trust) | Document against code | None | M16 |
| E8 | The threat model lists "on-device button entry without echo" and "eventual progressive delay" as mitigations. The dialog echoes the live digit and no delay exists. | `docs/security/threat-model.md:431`; `secure/src/ui/pin_entry.rs:25-31` | n/a | Low | Document against code | #637 names it, not as a deliverable | M12 |
| E9 | The production fence comment says the consumption mask keeps the signature "uncorrelated". On pq1 the mask is a 10 kHz PWM into an unconnected pad. The `compile_error` text already admits efficacy is unmeasured; the comment and several docs do not. | `secure/src/nsc/mod.rs:694-705`, `:698`; `secure/src/board/pq1.rs:301-316`; `docs/security/red-teaming.md:694`, `:306`; `README.md:88`, `:261`, `:417` | n/a | Low-medium (merger); low (skeptic, final). The electrical no-op is a physics argument; the dilution is UNMEASURED. | Document against code | #228, #646 (measurement). The rewording is untracked. | M15 |
| E10 | CLAUDE.md invariant #2 and two code comments say `AuthMethodBlocked` maps to the wipe path unconditionally. Only the USB arm wipes (A15). | `secure/src/se050/mod.rs:2860`; `secure/src/nsc/mod.rs:1362` | n/a | Low | Document against code | None | pin-05 |
| E11 | The threat model presents #220's planned FSBL self-check (embedded key against an OTP hash) as the defence against a replaced FSBL. A replaced FSBL would not run the check, and nothing is implemented. | `docs/security/threat-model.md:517-518` | n/a | Low | Document read | #220 | M07 |
| E12 | The threat model names the `NsPtr` typestate as the pointer-validation mechanism and counts "18 gateway commands". The typestate is not adopted across handlers. | `docs/security/threat-model.md:259-263` | n/a | Low | Document against code | #84 (adoption) | USB-06 |
| E13 | `brownout-hardening.md` says single-bit ECC is "always active, no config needed" on SRAM1, SRAM2 and SRAM3. ECC is an option bit, off by default. The NMI handler comment says no NMI source is armed. | `docs/security/brownout-hardening.md:321`; `secure/src/main.rs:4643` | n/a | Low | Document against #48 | #48 | M21 |
| E14 | Tamper docs are stale in both directions: `hardware_requirements.md` says tamp is not wired into `main()` and that the BHK is erased in hardware on any tamper (true only for the runtime copy); a `main.rs` comment says "Log-only; never halts and never wipes", false under `tamp-wipe`. | `docs/hardware/hardware_requirements.md:101-102`; `secure/src/main.rs:1395-1397` | n/a | Low | Document against code | None | M11 |
| E15 | `reproducible-builds.md` says CI runs `verify-repro` on every PR. It is a nightly job, and #456 records that the workflows have not been executing. | `docs/firmware/reproducible-builds.md:241`; `.github/workflows/nightly.yml:130-145` | n/a | Low to medium | Document against CI | #456 | M09 |
| E16 | The device UID address is given as `0x0BFA_0590` (the STM32L5 location) in `production-security.md` and in the #249 body. Code and a silicon receipt use `0x0BFA_0700`. The document contradicts itself at :140. | `docs/security/production-security.md:370`, `:395`, `:424`, `:140`; `secure/src/nsc/prodtest.rs:46-47`; `proto/src/lib.rs:647`, `:902` | n/a | Low (would become a real bug in new tooling) | Document against code | #249 (the wrong address is in the issue) | M09 |
| E17 | `user-device-verification.md` says "No NRST needed (vector catch)", which lets firmware run from power-up until the probe halts it. That contradicts verify-before-first-power. | `docs/security/user-device-verification.md:184-186` | n/a | Low | Document read | None | M09 |
| E18 | The SE050 module header says the admin sweep reclaims the duress objects. The wipe lists do not contain them (B3). | `secure/src/se050/mod.rs:64-71`, `:2266-2288` | n/a | Low | Code read | #107 | M14 |
| E19 | `vendor-signing-key-compromise.md` forecloses measurement binding because the STM32U585 has "no hardware measurement latch". HDP with access-disable is a deny-until-reset latch. The conclusion stands; the reasoning is imprecise. | `docs/security/vendor-signing-key-compromise.md:459-462` | n/a | Low | Document read | None | M01 |
| E20 | FSBL sources still argue against the HASH-peripheral port that is now the default feature. CLAUDE.md and the FSBL linker script quote 28,704 B; the pq1 FSBL is 22,236 B. The 2.93 s boot-work figure is the software-path measurement. | `fsbl/src/verify.rs:5-24`; `fsbl/src/main.rs:40-44`; `fsbl/memory-stm32u585.x:14` | n/a | Info | Document against code | None | M08, M05 |
| E21 | Mask docs are stale: "TIM2 CH1 PWM on PA5" for all boards, a mode-production pq1 image described as unsatisfiable, and a dangling "§9" reference. Two docs disagree on whether the bench can do power analysis without a ChipWhisperer. | `docs/hardware/evt-silicon-validation.md:758-764`, `:175`, `:921-923`; `docs/security/red-teaming.md:99-104`; `docs/hardware/hardware_requirements.md:119-122` | n/a | Low | Document against code | None | M15 |
| E22 | The threat model lists the `wait_random` glitch sentinel as "Planned". It is implemented at 231 call lines. This is an under-claim. | `docs/security/threat-model.md:321` | n/a | Low | Document against code | None | M06 |

### Defects with no tracking issue

Filed on 2026-10-12; the issue numbers are in the update note at the top of this section. The list below is kept as first written.

- A1: re-entrant NSC gateway and the post-confirm re-read of `SIGN_SNAP_BUF` (USB-01). Include the try-enter refusal, a `Busy` status, a source-invariant test, and the false SAFETY comments (E5).
- C1 and C2: FSBL signature-gate single skip and the unencoded slot word, plus `pick_slot` steerability and the false two-fault claim (E4). These must close before the FSBL freeze.
- C3: OEM-lock mask on bits 26 and 27 instead of 18 and 19. Fold into #46.
- C4: `SRAM_RST`, `SRAM2_RST` and the SRAM ECC bits missing from the ship profile, the Phase A verifier and the SWD check.
- B1: a dedicated issue for the inert RDP-2 burn and the unpinned `OPTWERR` check. It is recorded only inside #268.
- D1: a buyer-usable verify-before-first-power tool, the missing ship profile, and the SWD and NRST access decision for the sealed unit.
- A4(c) and the A5 residue: F1D0 not rewritable after a wipe on the locked profile; `admin_exists()` coercion clearing the resume flag; admin object self-delete; `Ok(())` on admin-PIN derivation failure; unconditional page-124 reset.
- A6: zeroize-then-reset in `halt_on_glitch`.
- A13: `FLASH_ACR` wait-state lever for the non-secure world.
- A14: IWDG reset during PIN entry (needs a silicon or `iwdg`-on check first).
- A15: one lockout response for all three unlock arms, and the doc drift in E10.
- A16: `TAMP_SCR` read-before-clear at boot. File under #75.
- A18 and C12: MSPLIM in the secure reset path and the FSBL; an NMI and ECC handler in the FSBL.
- A10 and E1: die-bound, salted PIN credentials, and the false single-chip-extraction claim in the threat model.
- A21: production-silent SECBOOTADD0 verdict, with a source-invariant test against log-only verdicts.
- A24: "Revoke" wording on the unknown-token path for a selector shared with ERC-721.
- A25, A26 and B6: legacy letter row and PIN digit on the public glyph path; fixed start letter and candidate cursor; px PIN digit on a non-forced frame and px secret-frame re-streaming.
- A27: `cmd_pin_attempt_log` bare pointer check.
- A30 and A31: locked-state prompt storm; PIN scrambler RNG fallback.
- A19 (BORRSTF only), A32, A33, A34: brown-out reset not scrubbed; veneer-entry jitter; owner question on single-read `CounterUnstable` wipe; device-info placeholders and the missing blank read-back after erase.
- B3 (page-123 wallet discriminator and swallowed duress wipe), B5 (first-boot done-bitmask gates), B9.
- C7, C10, C11: FSBL TRNG bring-up; erased-tail check; fingerprint derived from the manifest digest.
- D5, D7, D8, D9: FI harness repair; C10 verifier sweep window; landing the `perf/flash-opt-level-z` delay-source commits on master; the wipe-recovery e2e scope and the non-executing lockout-wipe FI suite.
- D6 residue: the uncommitted `fi_min` fix is defeated on thumbv8m and the gate cannot see it; a scheduled job has no blocking consequence.
- Documentation with no issue: E6, E7, E9 (rewording), E12 (the count and mechanism claim), E14, E17, E19, E20, E21, E22.

---

## Hardware, enclosure and factory change requests

This section lists every board, enclosure, bill-of-materials (BOM) and factory-process request that came out of the study, for the owner of the AL_A66_MB board (pq1, STM32U585CIU6, 48-pin UFQFPN). It is compiled from the 21 merged recommendations (M01 to M21), the single proposals of kind hardware or mixed, and the independent skeptic reviews. Nothing here was measured on silicon during the study. Where a fact rests on reading code or documents, the text says so.

Each ask is marked **NEW** or **ALREADY LISTED** against `docs/hardware/hardware_requirements.md` (HR below) and `docs/hardware/evt-silicon-validation.md` (EVT below). Priorities: P0 = do before anything ships or freezes, P1 = high, P2 = medium, P3 = low or gated on a measurement. Cost classes: BOM part, layout only, mechanical tooling, process.

### Package and board facts that constrain every ask

| Fact | Consequence | Source in the data |
|---|---|---|
| The package bonds only PA0-15, PB0-15 (not PB11) and PC13. | No port D/E/H. Every new function competes for three free pads. | `docs/hardware/evt-silicon-validation.md:212` |
| Free pads are PA10, PC13 and PB4. PA6 (pin 16) is not connected (NC) on the board and carries the consumption-mask PWM (TIM3_CH1). | PA6 is the only pad with an ADC4 input that is not already used. Three proposals want it (see G2-2). | `secure/src/board/pq1.rs:345`, `secure/src/board/pq1.rs:301-318` |
| PC13 (pin 2, NC today) is TAMP_IN1 and sits in the VBAT domain. | It is the only external tamper input available. | M11 merge, skeptic pin-table read |
| TAMP_OUT exists only on PA0 and PA1 (the two buttons) and on PC13 itself. | An active tamper mesh needs a button moved. PA10 and PB4 have no TAMP function. | M11 dropped parts |
| The touch-sensing controller (TSC) reaches only PB4-PB7 and PB12-PB14. | TSC cannot measure the display nets (PA4/PA5/PA7, PB0-PB2), the buttons (PA0/PA1) or I2C1 (PB8/PB9). | M10 and M11 dropped parts |
| PA10, PC13 and PB4 have no ADC channel. | A shunt cannot be read directly by a free pad. | M10 dropped parts |
| No battery. USB VBUS is the only supply. Whether V10 populates anything on VBAT (pin 1) is not recorded in the repository. **Correction 2026-10-12:** the V10 schematic records it: an 11 mF backup capacitor (`J102`) with a diode charge path; see section 16 and #869. | A tamper response runs at the next powered boot. Any "armed while unplugged" claim depends on a supercapacitor that may not exist. | M11 and M20 hardware asks |
| The clock tree is HSI16 to PLL1, with HSI48 for the random number generator. HSE and LSE are not used by firmware. | Clock glitching through a crystal is not in the model. Clock-security (CSS) asks do not apply. | `docs/hardware/evt-silicon-validation.md:729-730` |
| Each button pad pair has a 100 nF capacitor and an ESD diode and no board pull-up. | RC-decay sensing of the button nets is impossible. | `docs/hardware/evt-silicon-validation.md:470-471` |
| PA8 is `LDO2_EN`, the enable for the rail (`VDD1_3V3`) that powers both secure elements. `R130` (10 kΩ) pulls it down. | The secure-element rail is off while the MCU is held in reset. | `docs/hardware/evt-silicon-validation.md:387` |
| The board is six-layer. | Stripline routing is physically possible. HR still says "four layers". | `docs/hardware/pcb/README.md` (skeptic read), HR:106, HR:239 |
| The sealed EVT unit has no reachable SWD. The 10-pin connector is removed and the pads are inside the case. | No buyer can run the verification that invariant #10(a) depends on. | `docs/hardware/evt-silicon-validation.md:661-663` |

### Owner decisions that gate the asks

Four recorded texts contradict each other. The board cannot be specified until the owner retires one side of each.

1. **SWD route on a sealed unit.** `docs/security/user-device-verification.md:184-189` puts SWDIO/SWCLK on the USB-C SBU pins. `docs/hardware/evt-debug-pins.md:145-176` uses the SBU net for the BOOT0 LDO enable. README.md:449 and HR:166-173 keep internal pads. Internal pads plus a welded shell is the incompatible combination (M11 skeptic). #695 tracks the sealed-unit access gap.
2. **VBAT retention.** `docs/security/user-device-verification.md:190-191` requires no VBAT retention. HR:139-151, HR:245, `docs/security/brownout-hardening.md:216-250` and #248 require a 0.47 to 1 F supercapacitor. If no-VBAT wins, an unpowered tamper latch does not exist at all.
3. **Destructive-open shell versus open inspection.** No recorded decision exists. Published board photos (`docs/security/user-device-verification.md:166`) lean toward inspection. A welded opaque shell removes it.
4. **What PA6 is for.** Mask load, ADC4 rail sense, or RC reference pad. They are mutually exclusive.

### Group 1: needed for a recommendation at P0 or P1

#### G1-1. SWD, NRST, GND and VTref reachable on the sealed unit without opening it (P0)

- **Change.** Either move USB-C SBU1/SBU2 from the BOOT0 LDO path (U111, R131, R132) to SWDIO/SWCLK with ESD protection, or provide an externally reachable pogo-pad window in the enclosure.
- **Needed by.** M09 leg 1 (verify-before-first-power tool), M11 Tier A item 7, M02 (user SWD checklist), invariant #10(a).
- **Buys.** The only check that is unconditional on factory honesty: an off-device, read-only dump diff of flash, option bytes and OTP at RDP-0. It answers a transit reflash, an option-byte or OTP change, and a planted OEM1/OEM2 regression key.
- **Does not buy.** It proves firmware, not the board. It does not detect an SWD-emulating fake MCU with transplanted secure elements, a display or button implant on genuine chips, or that the OTP transport master (bytes 128..160) was read in transit.
- **Constraint.** On V10 both SBU pins join one net (`docs/hardware/evt-debug-pins.md`), so they must be split. SWDIO and SWCLK then use both SBU pins. NRST still needs its own path, and the data does not say where it goes. `docs/security/user-device-verification.md:184-186` says "No NRST needed (vector catch)". The merger and the skeptic both reject that: without NRST, firmware runs from power-up until the probe halts it. The tool cannot detect whether NRST was asserted before VBUS, so the procedure must order them. The DFU/ROM route is not a substitute: under TZEN=1 it reads the secure bank as zeros, and it runs code.
- **Cost.** Layout only (SBU re-route plus ESD part), or mechanical tooling (pogo window).
- **Status.** ALREADY LISTED as a requirement (HR:21-23, HR:154-156, HR:166-173, HR:231). Not met on the EVT unit (EVT:661-663). The route is NEW and undecided.
- **Priority note.** The skeptic anchors the P0 of M09 on this access decision, not on tool packaging. Final M09 value: P0, cost XL (the merger said L).

#### G1-2. BOOT0 hard strap, with the SBU to U111 to BOOT0 path physically removed (P1)

- **Change.** Strap BOOT0 to GND and delete the LDO path, not merely strap around it. Remove the BOOT0 pad (J211, TP103). Demonstrate on a mass-production (MP) unit that bridging A8 to VBUS no longer enumerates `0483:df11`, plus one teardown.
- **Needed by.** M11 Tier A item 6.
- **Buys.** Removes a ROM-bootloader entry on a sealed unit and frees the SBU pins for G1-1.
- **Does not buy.** Nothing after RDP-2, where system-memory boot is already disabled (M02 skeptic reading of RM0456).
- **Constraint.** `docs/hardware/evt-debug-pins.md` (correction of 2026-09-21) records that the STM32U5 has no empty-check and that the sideband is the ODM's current flashing path. Strapping BOOT0 removes USB flashing entirely. Factory programming then needs SWD or a jig, which is one more reason to settle G1-1 first.
- **Cost.** Layout only, plus a factory-flow change.
- **Status.** The strap is ALREADY the recorded MP plan in `docs/hardware/evt-debug-pins.md`. Removal of the path and the outside test are NEW.

#### G1-3. Display nets buried and shielded (P1)

- **Change.** Route SPI1 (PA4 CS, PA5 SCK, PA7 MOSI), DC (PB0), RST (PB1) and TE (PB2) as stripline between two ground planes, with no outer-layer vias in the display region. The ODM supplies layer-by-layer evidence.
- **Needed by.** M11 Tier A item 1.
- **Buys.** Raises the cost of the one confirmed in-the-wild implant shape: a passive tap on the display bus with glyph matching and radio exfiltration ([Grand, Ledger Nano X implant slides](https://grandideastudio.com/media/ledger_hardware_implant_slides.pdf)). The panel has no MISO, so firmware cannot see such a tap.
- **Does not buy.** The merger called this "the only near-deterministic part". The skeptic rejects that: every net still surfaces at the UFQFPN48 perimeter lands, the flex connector pads, the flex tail and the panel edge. No part of Tier A is deterministic. All of it is attacker cost and evidence. Near-field pickup at the flex or the panel driver is untouched.
- **Constraint.** Nobody has read the L2 to L5 copper plots to see whether V10 already routes these nets on inner layers. That read is a prerequisite.
- **Cost.** Layout only.
- **Status.** PARTLY LISTED. HR:81-83 requires the display bus "kept off any probe-accessible header". The stripline rule is NEW.

#### G1-4. No test pads on secure-world nets at MP (P1)

- **Change.** Delete pads on I2C1 (PB8/PB9, brought out on EVT per `docs/hardware/evt-debug-pins.md:45-46`), I2C4 (PB6/PB7), I2C2 (PB13/PB14), SPI1 and PA0/PA1. UART and SWD connectors not populated.
- **Needed by.** M11 Tier A item 2.
- **Buys.** A tap needs visible rework instead of a clip.
- **Does not buy.** Protection at component pins.
- **Constraint.** The rule must explicitly exempt the SWD/NRST verification access of G1-1, or supersede README.md:449.
- **Cost.** Layout only.
- **Status.** ALREADY LISTED (HR:74, HR:163-165, HR:249, all "board not started").

#### G1-5. Display and button stack with no void, flex under the can, connectors potted (P1)

- **Change.** Bond the panel to a rigid backer with no cavity behind it. Capture the display flex under the EMI can. Pot the display and button connectors. The ODM signs off thermal, ESD and rework consequences.
- **Needed by.** M11 Tier A item 3.
- **Buys.** Removes the space an implant needs. The Nano X attackers had to shrink the battery to fit theirs.
- **Does not buy.** Supercapacitor, USB-C and dome-switch voids remain. Button nets end at mechanical contacts and cannot be buried.
- **Merger versus skeptic.** The merger ranked the display nets above the buttons because "a button tap leaks the PIN press pattern, not the seed". The skeptic shows that is false: the Restore mode enters all 24 words through PA0/PA1 (`secure/src/ui/seed_wizard.rs:3`, `:106`, `:130-166`). Final position: rank the button nets equal to SPI1/DC and give the dome-switch region the same no-void and potting treatment.
- **Cost.** Mechanical tooling plus assembly process.
- **Status.** The EMI can is ALREADY LISTED (HR:112, HR:242). No-void, flex capture and potting are NEW.

#### G1-6. Destructive-open shell (P1, owner decision first)

- **Change.** Ultrasonic weld or an equivalent that cannot be opened without visible damage. State the RMA consequence: no reopen.
- **Needed by.** M11 Tier A item 4.
- **Buys.** Evidence of opening and attacker cost. Vendor parity: [Coldcard](https://coldcard.com/docs/physical-notes/) welded clear case, [Ledger](https://support.ledger.com/article/4404382029329-zd) casing, Cypherock weld ([Keylabs audit](https://www.cypherock.com/keylabs.pdf)).
- **Does not buy.** Prevention. A counterfeit or re-welded shell defeats it unless the user compares against published references. An implant sealed in at the factory is untouched.
- **Constraint.** Incompatible with internal SWD pads. Depends on G1-1.
- **Cost.** Mechanical tooling.
- **Status.** NEW.

#### G1-7. Design evidence delivered into the repository (P1)

- **Change.** No copper. The ODM delivers the netlist and a BOM with exact passives. Someone completes the schematic versus pin-map cross-check and the L2 to L5 copper read. The project publishes reference photos, X-ray and weight of a sealed known-good MP unit.
- **Needed by.** M11 Tier A item 5 and its prerequisites, M10 and M20 schematic questions.
- **Buys.** Detection aids for users, and answers to open schematic questions: series resistors, pulls or ESD parts on the display lines; whether PA6 has a stub; AW35602 `FLAGB` (PB10) polarity and fault coverage.
- **Does not buy.** Anything if users do not inspect.
- **Constraint.** The schematic PDF has no text layer. `docs/hardware/schematics/README.md` says there is no BOM in the repository and the cross-check has not been done.
- **Cost.** Process.
- **Status.** NEW. HR:183-186 covers second sourcing only.

#### G1-8. VBAT: report what V10 populates, then implement the owner's decision (P1)

> **Correction 2026-10-12.** The first half is answered by the schematic (section 16, #869): V10 has a small backup capacitor on VBAT, far smaller than the 0.47 to 1 F this ask and the requirements document assume. Whether it is fitted and how long it holds are the open measurements.

- **Change.** State what is on pin 1 today (supercapacitor, tie to VDD, other). State the backup-domain hold time. Then build to decision 2 above.
- **Needed by.** M11, M09 (so the verifier's backup-register line can be worded honestly), M20 (ITAMP1 backup-domain monitoring and backup-register erase semantics depend on it).
- **Buys.** A defined answer to "is anything armed while unplugged". Hold time is UNMEASURED.
- **Does not buy.** A durable hardware key erase. The backup registers that hold the BHK are reloaded from flash page 126 on every boot (`secure/src/hw/bhk.rs:27-33`), so the only durable tamper response is the software wipe at the next boot.
- **Cost.** BOM part (supercapacitor plus Schottky) or none.
- **Status.** The supercapacitor is ALREADY LISTED (HR:139-151, HR:245). The contradiction with `docs/security/user-device-verification.md:190-191` is NEW.

#### G1-9. Rail characterisation on EVT units before the option-byte profile freezes (P0)

- **Change.** No board change. EVT bench time for a rail sweep, a USB host and cable matrix, the switching transients of the secure-element rail (PA8), and a thermal sweep. If the result demands it, more bulk capacitance.
- **Needed by.** M20 Stage B (BOR level 3 plus PVD level 5 with an SRAM-only zeroize).
- **Buys.** A BOR level that can be frozen at RDP-2 without bricking units on marginal hosts. Thresholds and false-positive rates on pq1 are UNMEASURED.
- **Does not buy.** Detection of 100 to 400 ns glitches. PVD and ADC watchdogs see only slow sags.
- **Cost.** Process, possibly a BOM part.
- **Status.** ALREADY LISTED (HR:128-138, HR:244; EVT:792). The levels disagree between documents, see the option-byte list.

#### G1-10. Secure-element part numbers confirmed with the ODM (P1)

- **Change.** Confirm the production SE050 variant (#697). Confirm that production OPTIGA Trust M parts carry a production Infineon device certificate (#27).
- **Needed by.** M09 leg 3 (host-verified birth record), M17 (the pinned AppletConfig constant).
- **Buys.** A birth record and an anti-substitution check that match the fitted parts. The bench already hit an E2 versus C2 mismatch.
- **Does not buy.** Detection of a transplanted genuine chip on a hostile board.
- **Corrections folded in.** The merger said the variant decides whether attestation key 0xF0000012 exists. The skeptic calls that overstated: per #249 the C, E and F variants carry it, and #697 is about which SCP03 keyset ships. The OPTIGA certificate slot is unconfirmed: the repository records 0xE0E3 as a full device certificate (`secure/src/optiga/reset.rs:33`), while the merger and #27 assume E0E0. Confirm on silicon.
- **Cost.** BOM and process.
- **Status.** PARTLY LISTED (HR:183-186 names the stockout risk; EVT:838-843 lists the C2 fingerprint as uncaptured).

#### G1-11. Sacrificial parts for one-way work (P0 for the fault-injection campaign, P1 otherwise)

- **Change.** No board change. Budget parts that will be destroyed.
- **Needed by and what for.**
  - M02, M09: one STM32U585CIU6 for OEM-key positive detection (provision an OEM2 key, not only OEM1) and the WRP UNLOCK and BOOT_LOCK dry run. Shared with #45.
  - M21: one die to confirm bit position and polarity of SRAM_RST, SRAM2_RST, SRAM2_ECC and SRAM3_ECC, to run a canary-plus-reset residue test, and to see whether a torn flash quad-word raises NMI (#82, #94, #544).
  - M14: one OPTIGA Trust M V3 shield and one SE050 for the wipe and recovery rehearsal.
  - M07 item D and M01, only if the owner reopens them: parts for HDP and ACCDIS behaviour.
  - FI-01 (P0): the feasibility review says not to spend pq1 units on the RDP-2 downgrade sweep. The option-byte loader is a die property shared with the B-U585I-IOT02A kit, so burn kits and keep pq1 silicon for board-level questions.
- **Cost.** BOM (parts).
- **Status.** ALREADY LISTED (EVT:54-55, EVT:88-89).

### Group 2: enables a measurement or an optional defence

#### G2-1. PC13 net routed to an unpopulated case-open and flex-continuity footprint (P3)

- **Change.** Route PC13 to a normally-closed case switch in series with a continuity loop through the display flex, with external pull and RC, kept short and inside the shielded region. Leave it unpopulated.
- **Needed by.** M11 Tier B.
- **Buys.** Detection of clumsy or powered opens, and of a loop still open at the next boot.
- **Does not buy.** Anything in transit: the unit is unpowered at RDP-0 and nothing is armed. An attacker who re-closes the switch or jumpers the two-wire loop is invisible. A fake panel carries the loop through.
- **Merger versus skeptic.** The merger carried Tier B inside one P1 item. The skeptic splits it: Tier A P1, Tier B P3, and unbuilt unless the response is redesigned. As specified, a trip routes the owner to "restore from seed" on the unit that was just opened, where a two-wire button tap captures the whole mnemonic. The response must be a distinct, persistent "case opened, do not restore on this unit" state. The item map keeps M11 at P1 overall. Routing the net costs nothing at respin.
- **Constraints.** A mis-filtered PC13 wipes field units, so false-trip characterisation (ESD, flex, moisture) comes first. The loop must be closed and verified before the first field boot. `secure/src/hw/tamp.rs:272` clears the tamper status before reading it, which is a hard blocker for this input (confirmed by code reading, not on silicon). No button may be moved to free a TAMP_OUT pad.
- **Cost.** Layout only now. BOM part plus mechanical tooling if populated.
- **Status.** The case switch is ALREADY LISTED (HR:108-111, HR:240). The scoping and the response redesign are NEW.

#### G2-2. PA6: one pad, three candidate uses (P3 each, pick at most one)

| Use | Needed by | Change | Verdict from the data |
|---|---|---|---|
| Resistive load for the consumption mask, with a do-not-populate footprint, on the MCU VDD domain and not on `VDD1_3V3` | M15 | BOM part plus layout | Conditional on a positive measurement. Mask efficacy is UNMEASURED on both boards. The skeptic expects the loaded arm to be negative. A positive iota2 result does not justify a pq1 spin by itself. |
| Resistor divider from VBUS or `VDD1_3V3` to PA6 as an ADC4 input | M20 Stage C (P2) | BOM part plus layout | Optional. Log-only slow supply and temperature tamper. |
| Known C0G reference capacitor for the RC-decay self-check | M10 | BOM part plus layout | Only if the Phase 0 bench study returns GO. |

HR:119-122 lists the mask pin as optional and names PA5. That row is stale: on pq1 the mask is on PA6.

#### G2-3. Bench variant of pq1 with a supply shunt and a trigger pad (P2)

- **Change.** A shunt or jumper footprint in the MCU VDD path and an accessible trigger pad (PB3 is the current repoint), on a bench build only. The enclosed EVT unit has neither.
- **Needed by.** SCA-01 (first on-silicon TVLA and CPA campaign), M15 (mask measurement), M06 and M05 (before and after glitch hit rates).
- **Buys.** The first measured side-channel and fault numbers. Every leakage result today is emulation only.
- **Does not buy.** A defence.
- **Constraint.** Two checked-in documents disagree on the capture chain: EVT:919-921 says a ChipWhisperer-Husky is needed, `docs/security/red-teaming.md:99-104` says the Rigol scope plus shunt and differential amplifier suffices. A shunt on a production board conflicts with HR:163-165.
- **Cost.** Layout only on a bench variant, or rework of one unit. Bench gear separately.
- **Status.** NEW.

#### G2-4. Units with a panel, buttons and firmware access (P2)

- **Change.** No design change. Supply LCD-equipped units that can run project firmware with debug or UART output.
- **Needed by.** M03 part C (panel leakage receipt), M10 Phase 0 (at least 5 sealed units plus one sacrificial for tap deltas), validation of M12, M13, M18, pin-04 and D-07.
- **Constraint.** The bench board has no LCD and no buttons. The sealed units are DFU-only through the SBU bridge (#695).
- **Cost.** Process.
- **Status.** NEW as a study prerequisite.

#### G2-5. Display flex shield and panel supply filtering (P2 to P3)

- **Change.** Ask the ODM whether a metal can or foil already covers the display flex and driver IC. If not, add a shield and series filtering or a separate regulator for the panel supply. Keep SCK free of extra load so the 40 MHz re-test for #258 is possible.
- **Needed by.** M03 (final P2; the merger said P1).
- **Buys.** Attenuation of the panel-internal scan and rail channels that no firmware encoding reaches.
- **Does not buy.** Protection from a logic-level tap on MOSI. Leakage on this panel is UNMEASURED.
- **Cost.** BOM part and mechanical.
- **Status.** PARTLY LISTED (HR:112-114 covers the can over the MCU and both secure elements and rail filtering, not the display).

#### G2-6. Input-current sense on VBUS (P3, owner question only)

- **Change.** INA226-class footprint with a Kelvin shunt at the USB-C side of VBUS, on I2C2 (PB13/PB14), supercapacitor charge path downstream. Alert line on a free pad that is not PC13.
- **Needed by.** M10 Phase 2 (final P3; the merger said P2).
- **Buys.** Possible detection of an implant that draws current while awake.
- **Does not buy.** A sleeping implant defeats it. The Nano X implant spoofed the device's own battery telemetry.
- **Constraint.** I2C2 already carries the AW99703 backlight driver at 0x36 and the RGB driver, so an address check is needed.
- **Cost.** BOM part plus layout.
- **Status.** NEW.

#### G2-7. Smaller optional items

- **Guard or ground pour** around the display and button nets (M10, P3, layout only, NEW).
- **Serialised tamper-evident bag** with the number in OTP (M09 leg 4). The skeptic demotes it to P3 and M11 counts it as deterrence only. The OTP word competes with a fully subscribed map (see the factory list). Process, NEW.
- **Bench gear, not board:** voltage and EM glitch rig (#301, #401), shunt and low-noise differential amplifier, and the USB-face rig of USB-09 (about USD 300 per the proposal, #590).

### Group 3: considered and not worth a board change

| Item | Proposed in | Reason it is rejected |
|---|---|---|
| Active tamper mesh (TAMP_OUT driven) | IMP-04 via M11 | TAMP_OUT exists only on the button pads and PC13. With no battery the comparator is dead whenever the unit is drained. A bridge from OUT to IN at the package satisfies it permanently. |
| Passive mesh over all layers into a tamper input | HR:106-107, HR:239 | As a loop into PC13 it detects only a cut that is still open at the next boot. Recommend downgrading the existing row instead of building it. The row also says four layers; the board has six. |
| Moving a button to free a TAMP_OUT pad | M11 | Explicitly excluded. |
| TSC fingerprinting of display, button or secure-element nets | IMP-03, BOOT-10 via M10 | No TSC function on those pads. PB6/PB7 carry 3.3 kΩ pull-ups and would back-power the secure elements with the rail off. |
| RC-decay sensing of the button nets | M10 | 100 nF and an ESD diode per pad. A 5 pF tap changes the time constant by about 50 ppm. Button and PIN logging stays a fully uncovered residual. |
| Shunt read directly by PA10 or PA6, and current sensing on the LCD rail | D-03, IMP-03 via M10 | PA10, PC13 and PB4 have no ADC channel. Backlight current swamps an implant, and a competent implant sleeps. |
| Analog watchdog or PVD events routed into a tamper erase or wipe | M10, M20 | A false trip on a USB-powered device erases the key that roots the SE050 credentials (#712) or wipes wallets on marginal cables. Kept log-only. |
| Consumption mask tied to the backlight enable (PB15) | SCA-07 via M15 | It would modulate trusted-display brightness and load the boost converter, not the MCU rail. |
| Populating a load on PA6 now | M15 | A respin for an effect that is UNMEASURED and physically doubtful. |
| Supply and ground probe points for impedance fingerprinting on MP | IMP-02 via M09 | Conflicts with HR:163-165. Needs a network analyser and an opened case. The literature supports only offline bench methods against a golden reference ([arXiv 2403.12252](https://arxiv.org/abs/2403.12252)). |
| Battery or battery-backed real-time clock | CS-03 (velocity limit), SE-08 (keep the OPTIGA powered until its security-event counter decays), GridPlus-style mesh | HR:196 excludes a battery. The retired work list already ruled time-based quotas not implementable on this platform. Both proposals survive without the time-based part. |
| External clock or CSS hardening | FI-02d via M20 | Firmware uses neither crystal. Selecting LSE for the RTC would add a glitchable crystal, and the clock selection is write-once per backup-domain reset. |
| "Hardware erases the key on tamper" as the response | IMP-04, D-08 | The backup registers are reloaded from flash every boot. |
| Panel reset pulse to clear the frame memory | D-07 | Not a board ask. The feasibility review found that this controller family keeps frame memory across reset. The existing `LCM_EN` (PB15) and `LCM_RST` (PB1) lines are enough for the firmware part. |

No board or enclosure change is required by M01, M02, M04, M05, M06, M07, M08, M12, M13, M14, M16, M17, M18, M19, M21, CS-03, CS-10, SE-08, USB-09 or pin-04. Their hardware lines are sacrificial parts, bench gear or BOM confirmations, all listed above.

### Option-byte and factory-process asks that are irreversible at the RDP-2 freeze

These are not board changes. Each is fixed forever by the first field boot, so each must be in the factory image and the ship profile before any unit leaves.

| Item | Ask | State today | Source |
|---|---|---|---|
| BOR level | Pin BOR level 3 with PVD level 5 in the ship profile after G1-9. | The ship verifier has no BOR field. Documents disagree: EVT:792 says level 4 or higher, `docs/security/production-security.md:98` says "3 or 4", `Makefile:364-380` sets 3. Level 4 with PVD 5 was dropped because the thresholds coincide. The skeptic could not re-read the datasheet, so the ordering rests on the round-1 extract. | M20 |
| SRAM erase on reset | Set SRAM_RST=0 so the bank that holds secrets (SRAM1) is erased on every system reset (#82). | No recipe sets it. The bench recipe sets SRAM2_RST only, which is the non-secure bank. Raising BOR without this creates an unscrubbed-reset path. Bit polarity needs the sacrificial die. | M04, M20, M21 |
| SRAM ECC bits | Decide the secure RAM bank first (ECC part of SRAM3, or swap worlds so the secure side uses SRAM2 as Trezor does), then pin SRAM2_ECC or SRAM3_ECC. | The verifier (`shared/src/lockdown.rs:295-312`) has no SRAM, ECC or BOR field. SRAM1 has no ECC. | M21 |
| OEM keys | Factory writes OEM1KEYR1/R2 and OEM2KEYR1/R2 to 0xFFFFFFFF, then reloads option bytes or power-cycles, then reads FLASH_NSSR bits 18 and 19 as 0. Close #40 in favour of no OEM key. | `shared/src/lockdown.rs:278-279` checks bits 26 and 27, which are wrong per the vendor header and SVD (confirmed by code reading, not on silicon). The gate fails closed today. Whether the all-ones write un-sets a planted lock is unverified. An OEM2 key holder regresses RDP under reset before any instruction runs, so the factory step and the user's SWD read are the only effective controls. | M02, M09 |
| WRP ranges | WRP on the FSBL range in both banks (WRP1A and WRP2A), UNLOCK bit clear, set before RDP-2. | Unpinned. The frozen registry says pages 0..4; the linker still occupies pages 0..3 (#540, #758). Freezing five pages before the cutover freezes an empty page. #193: the check accepts over-wide spans. | M02, invariant #10 |
| HDP | Decide on or off for HDP1 and its bank-2 mirror (#39, #43, #214). | Configured nowhere. It would hide public, reproducible loader code only. #39 does not say where the code that runs after the access-disable write lives. Measurement-bound release on top of it is rejected (M01). The HDP-hidden counter is a P3 review input only (M07 item D). | M01, M07 |
| Boot configuration | Pin BOOT_LOCK, SECBOOTADD0, SECWM1/SECWM2, NSBOOTADD0/1, nBOOT0/nSWBOOT0, SWAP_BANK and TZEN in the profile and in the user tool's read set (#753). | The skeptic corrects the merger: at RDP-2 only SWAP_BANK stays writable (RM0456 Rev 7 §7.6.2), so BOOT_LOCK matters before the lock and for SWAP_BANK after it. | M02, M09 |
| RDP-2 burn routine | Fix #268 before any ceremony and add the option-write error check. Mask PVD during the option-byte write. | `secure/src/hw/flash.rs:384-394` records that the burn writes its control bits to the wrong register and returns Ok without burning. | M09, M20, M21 |
| OTP allocation | One owner-approved map before the factory burns anything. | OTP is program-once. Rollback Draft 1.1 provisionally claims 27 of 32 quad-words; with the master key, the sentinel and #220 the map is fully subscribed. The bag serial, the secure-element identity anchor (#249) and any RC baseline all compete for it. The transport master is readable over SWD at RDP-0. | M09, M10, M17 |
| Per-unit factory record | Record NSSR, WRP1AR/WRP2AR, SECBOOTADD0R, OPTR and the secure-element identifiers per unit (#595, #249). | Not implemented. A public log of identifier tuples is a privacy surface that needs an owner decision. | M02, M09, M17 |
| Vendor keys in the FSBL | Decide one key or two before the measurement profile of #541 freezes, which is earlier than the WRP freeze. | One 32-byte key embedded. A second key also needs secure-image and signing-tool changes. | M07 item A (P1; cluster final P2) |
| Flash state at ship | Factory flashing erases whole slots and leaves pages 123 to 127 blank. | First boot halts on any non-blank per-device page. A tail check would refuse a slot with stale bytes. | M05, M08, first-boot rule |
| Secure-element lifecycle | Fold the post-wipe recovery rule (E120, SE050 UserID, F1D0) into the S-1 ceremony before any OPTIGA lifecycle ratchet. | On the locked profile a wiped unit cannot be re-provisioned, by code reading. The S-1/S-2/S-3 work is deferred by design and stays so. | M14 Tier B, SE-08 |

### Stale rows found in the requirements documents

- HR:106 and HR:239 say "four layers". The board is six-layer.
- HR:119-122 names PA5 for the consumption mask. On pq1 it is PA6 (TIM3_CH1).
- HR:61-63 and HR:234 list SE050 on a separate I2C peripheral as open. pq1 already has it on I2C4 (EVT:222).
- EVT:758-764 says a production pq1 image is unsatisfiable because the mask is on PA5. Stale since the mask moved (M15 skeptic).
- `docs/security/user-device-verification.md:184-186` says NRST is not needed. HR:154-156 and both reviewers require it.

---

## 1. Malicious hardware and supply-chain implant detection

Every pq1 statement here is confirmed by code reading, not on silicon, unless a receipt is named. Nothing has shipped, and no production image can be built today (the S-2 fence rejects every `mode-production + optiga-trust-m` build).

### What pq1 does today

**No code path detects a hardware implant.** The panel is write-only and PA6 (the MISO position) is not connected, so the render verdict only proves the SPI peripheral finished (`fsbl/src/render.rs:1-80`). The seed wizard sends the 24 words over SPI1 as plaintext pixels (`secure/src/ui/seed_wizard.rs:89-96`). Buttons are raw GPIO. `docs/security/user-device-verification.md:163-168` records both as an accepted residual.

**Implemented.**
- Encrypted secure-element (SE) tunnels, so an I2C tap sees ciphertext. The per-device key rotation this rests on is an unapproved candidate, and the OPTIGA handshake carries no host nonce (playbook finding SE5).
- TrustZone ownership of the display, SE buses and timers, with silicon receipts (7/7 iota2, 8/8 pq1). The receipt does not cover the SPI1 bit (#390).
- Internal tamper detectors (TAMP, a Trezor port) with the wipe escalation forced on for shipping images (`secure/src/nsc/mod.rs:727-765`). Never run on silicon (#391, #75).
- Chip-ID gates on the backlight and RGB drivers, factory prodtest receipts, and the 8-word boot fingerprint.

**Partial or fenced off.**
- The external verifier `tools/verify_ship_state.py` checks option bytes and named flash regions against a bench profile only.
- First-boot Phase A (ship-profile check, blank pages 123..127, confirm-gated RDP-2 burn) and Phase B (fresh BHK, SE key rotation) exist only under `rdp2-self-lock`.
- The bootloader (FSBL) option-byte tripwire ignores write-protection and OEM-lock state by design (`fsbl/src/optbytes.rs:24-29`).

**Planned only.** SE genuineness check at boot (#210), the factory manifest and transparency log (#249, #67, #68), the consumer verification procedure (`docs/security/user-device-verification.md:3`), and every board-level anti-tamper row. The V10 board has no tamper net.

**Docs that disagree with code.** Three documents disagree on where pre-power SWD access comes from, and two on whether a VBAT supercapacitor exists. `docs/provisioning/first-boot-provisioning.md:122-134` says the lock confirm gate is missing; `secure/src/first_boot/mod.rs:219-240` implements it.

**Where pq1 is ahead.** Neither Trezor nor Ledger offers verify-before-first-power, and the literature survey rates it the strongest implant counter found. It is ahead in design only until a buyer can run it. pq1 holds no factory secret, keeps no seed bit on the MCU, and secures the display bus, where Trezor drives the display from the non-secure kernel.

### What Trezor, Ledger and others do that pq1 does not

**Trezor** (trezor-firmware at 6ab39e95):
- Resets the write-only OEM regression keys to 0xFFFFFFFF and checks the lock bits every boot (`core/embed/sec/option_bytes/stm32u5/option_bytes.c:213-222`, `:247-250`). A mismatch in any option byte triggers a safety erase (`core/embed/projects/boardloader/main.c:325-340`).
- Per-die MCU attestation with an ML-DSA-44 key and a factory certificate (`core/embed/sec/mcu_attestation/mcu_attestation.c:63-97`). The host requires the same root, serial and common name across all chains (`python/src/trezorlib/authentication.py:673-698`). Trezor fixed a bug in 2026 where [one proof satisfied all three checks](https://trezor.io/vulnerability/authenticity-proofs-not-bounded-to-their-secure-element).
- An external tamper input and a battery-backed backup domain (`core/embed/sec/tamper/stm32u5/tamper.c:157-160`). The shipped secure monitor disarms the external input (`core/embed/projects/secmon/main.c:113-114`).
- A boot-time SE configuration audit (`core/embed/sec/tropic/tropic.c:574-676`), a factory channel authenticated to a hardware security module (HSM) (`core/embed/projects/prodtest/cmd/secure_channel.c:40-84`), and cargo-vet dependency audits (`core/embed/supply-chain/config.toml:1-22`).

**Trezor does not** authenticate the display or its bus, encrypt it, or document tamper-evident construction in the firmware tree. It tolerates a failed OPTIGA secure-channel handshake and continues without attestation keys (`core/embed/sec/optiga/optiga_init.c:54-59`). It has no active-mesh code and no electrical self-measurement.

**Ledger** runs an SE-keyed Genuine Check and [states that it cannot detect spying implants](https://donjon.ledger.com/threat-model/device-genuineness). Its recorded response to the Nano X implant ([Grand's teardown](https://grandideastudio.com/media/ledger_hardware_implant_slides.pdf)) was reference photos, authorised resellers and future hardening. That implant tapped an SE-driven display bus, so an SE-driven screen does not stop it.

**Others.** [Coldcard](https://coldcard.com/mk4) records the bag number in the device. [GridPlus](https://docs.gridplus.io/lattice1/security-features) ships an active mesh with a roughly 5-year battery. Foundation and Keystone tamper claims are unchecked vendor statements.

### Live defects confirmed on this surface

| Defect | Evidence | Reachable in the shipping feature set? | Severity | Tracked |
|---|---|---|---|---|
| The verifier behind invariant #10(a) reads no OTP, UID, IDCODE, OEM-lock bits or per-device pages; bench profile only; write guard is a deny-list | `tools/verify_ship_state.py:134-157`, `:121-127`, `:53-74` | Host tool | High for the invariant #10 claim | No |
| RDP-2 burn is inert: commit bits go to FLASH_SECCR, where they do not exist; returns Ok | `secure/src/hw/flash.rs:384-394`, `:541-558` | Only under `rdp2-self-lock`; latent | High | #268 |
| OEM-lock mask uses bits 26/27; the vendor header and SVD give bits 18/19 (found by the skeptic) | `shared/src/lockdown.rs:278-279` | Latent; fails closed only while `OEM_LOCK_MASK_PINNED = false` | High if the flag is flipped unfixed | No (fits #46; see section 6) |
| No code resets the OEM1/OEM2 keys before the RDP-2 burn; Phase A can only halt (0x080A) | `shared/src/lockdown.rs:290`; `fsbl/src/optbytes.rs:24-29` | Only under `rdp2-self-lock`; fails closed | Medium (ship gate) | No |
| `tamp::init` clears latched tamper flags before reading them; a reset within about 1 ms of a backup-rail-voltage or temperature event skips the wipe | `secure/src/hw/tamp.rs:272`; reads only at `:86`, `:372` | Yes (polled `tamp` + `tamp-wipe`); desk finding (#391) | Low-medium; blocking for any case-open input | No |
| GET_DEVICE_INFO returns fixed version 3.0.0 and a zero UID; USB serial is "0001" | `nonsecure/src/usb/commands.rs:178-182`, `:416`; `nonsecure/src/usb/mod.rs:199` | Yes, every `usb` build | Low | No |
| Docs cite UID address 0x0BFA_0590; code and silicon receipt use 0x0BFA_0700 | `docs/security/production-security.md:370,395,424` versus `:140`; `secure/src/nsc/prodtest.rs:46-47` | Docs and #249 body only | Low | No |
| Docs say verify-repro runs on every PR; it is nightly and has not been executing | `docs/firmware/reproducible-builds.md:241`; `.github/workflows/nightly.yml:130-145` | Process | Low to medium | #456 (partly) |
| Comments and docs say tamper is "log-only" and not wired into `main()`; false under `tamp-wipe` | `secure/src/main.rs:1395-1397`, `:1400`; `secure/src/hw/tamp.rs:78-81`; `docs/hardware/hardware_requirements.md:101-102` | Documentation | Low | No |

### Recommendations

| ID | Recommendation | Kind | Cost | Priority | Novelty | Tracked issues |
|---|---|---|---|---|---|---|
| M09 | Verify-before-first-power tool plus a host-verified birth record, each leg scoped to the attacker it stops | mixed | XL | P0 | beyond | #27 #34 #37 #39 #40 #42 #43 #44 #46 #67 #68 #76 #193 #206 #210 #226 #244 #249 #250 #268 #270 #272 #387 #456 #540 #595 #601 #626 #695 #696 #697 #705 #742 #753 #758 |
| M11 | Mass-production (MP) physical-access spec; optional passive case-open input on PC13; active mesh dropped | mixed | L | P1 | parity | #36 #47 #50 #52 #75 #81 #208 #248 #256 #391 #695 #696 #697 #705 #753 |
| IMP-09 | Anti-klepto for the C10 randomizer (redesign needed; refuted as written) | firmware | M | P2 | beyond | none (#238 is docs-only) |
| M10 | Display-net RC-decay self-check, gated on a bench go/no-go study | mixed | L | P3 | beyond | #47 #75 #208 #220 #248 #249 #258 #260 #268 #540 #595 #601 #695 #705 #712 #758 #784 #835 |

Dropped parts for M09, M10 and M11 are listed with their reasons under "Considered and rejected".

**M09. Verifier and birth record.**
- Threat. Transit or reseller tampering with a unit that ships debug-open at RDP-0; factory overbuild and clones.
- What to do. Leg 1 (P0): a read-only, connect-under-reset `pq1-verify` with a real allow-list of read commands. It reads both flash banks, every option-byte register (including NSBOOTADD0/1, the WRP UNLOCK bits and SECWMxR2), the OEM-lock bits at FLASH_NSSR 18/19, an OTP programmed-word map compared locally, the UID at 0x0BFA_0700, IDCODE and pages 123..127. Anchor the P0 on the hardware-vendor (ODM) decision for SWD and NRST access on the sealed unit, not on tool packaging. Leg 2 (P1): overwrite the OEM keys in the RDP burn after fixing #268; halt first if a lock bit is set. Leg 3 (P1): an HSM-signed per-unit manifest (MCU and SE UIDs, certificate hash, ship profile, release hash) in a public log, verified host-side only, with each proof bound to its own root and a negative test. Leg 4 (P3): bag serial in one OTP word. Leg 5 (P3, owner decision): a per-die C10 key enrolled by the owner, behind a mandatory on-device confirm.
- Evidence pq1 lacks it. `docs/security/user-device-verification.md:3`; no attestation command in `proto/src/lib.rs`.
- Precedent. Attestation legs are parity with Trezor and Ledger. No vendor ships a user-run pre-power verifier.
- Hardware asks. SWD and NRST reachable on the sealed unit (V10 uses the USB-C SBU pins for the BOOT0 enable); a defined SE rail enable (PA8) state under held reset; the VBAT answer; the SE050 variant (#697); serialised bag; sacrificial RDP-0 boards (#46, #387).
- Residual after it lands. A fake MCU that emulates SWD and carries transplanted genuine SEs passes every leg on day one, as do board-level implants. The OTP map cannot show that the transport master was read, so transport keys must be assumed known after transit. A malicious factory or log operator defeats legs 3 and 4.
- Not yet tracked. The tool and its read set; the release descriptor; the OEM overwrite; the bit 18/19 correction; the binding rule and negative test; SE identity readers; whether the seed wizard adopts pre-existing SE state (a lead, not a confirmed gap); the "No NRST needed" line at `docs/security/user-device-verification.md:184-186`; privacy gating of SE identifiers.
- Merger versus skeptic. Cost L versus XL (final XL). Leg 4 P2 versus P3. The skeptic added the inert-burn and wrong-mask defects.

**M11. Physical-access spec.**
- Threat. An attacker opens the unit and solders a logger to the display bus or the buttons.
- What to do. Tier A (P1, hardware only): amend `docs/hardware/hardware_requirements.md` (anti-tamper rows `:239-245`). Route SPI1, DC, RST and TE as stripline between ground planes; remove test pads on secure-world buses, the buttons and BOOT0, with an explicit SWD/NRST exemption; bond the panel with no void; pot the display and button regions; destructive-open shell; publish netlist, pinned BOM, photos, X-ray and weight. First read the V10 inner-layer copper plots. Fix the tamper flag defect with #75 (P2). Tier B (P3): route PC13 to an unpopulated footprint only.
- Evidence pq1 lacks it. All anti-tamper rows read "board not started".
- Precedent. Welded or tamper-evident shells at Ledger, Cypherock, Coldcard and Trezor (vendor pages, unchecked).
- Hardware asks. The items above; BOOT0 strapped to ground with the SBU path removed; an SWD route that does not require opening the shell.
- Residual after it lands. Every part of Tier A is attacker cost and evidence, not prevention: nets still surface at the MCU lands, the connector, the flex tail and the panel edge. A factory-inserted implant is untouched.
- Not yet tracked. The spec; the flag defect; a persistent "case opened" state.
- Merger versus skeptic. The merger said a button tap leaks only the PIN pattern. The skeptic refuted this: Restore mode enters all 24 words through the buttons (`secure/src/ui/seed_wizard.rs:130-166`), and the intrusion wipe ends at "restore from seed" (`secure/src/main.rs:1938-1952`). A case-open wipe would send the owner to retype the seed on a just-opened unit, so Tier B stays unbuilt until a distinct terminal state exists.

**IMP-09. Anti-klepto.**
- Threat. A malicious secure image encodes key bits into the public signature randomizer R. Signatures go on-chain, so no radio is needed.
- What to do. Do not build the proposal as written. Now: add a companion-side check that each WOTS+C count is the minimal one (the count derives from public inputs; `sphincs-c10/src/wots.rs:63-80`, `:157-180`). Then put the real fix to the owner as a design note: a publicly derivable R with a two-round commit and minimal-nonce rules.
- Dropped parts and why. Host-committed OptRand: R is keyed by `sk_seed` (`sphincs-c10/src/fors.rs:98-131`) and no verifier re-derives it, so a malicious image ignores OptRand and keeps about 117 free bits per signature.
- Evidence pq1 lacks it. `secure/src/crypto.rs:206-237` draws OptRand with no host input.
- Precedent. Jade 0.1.24 and BitBox02 9.4.0, for ECDSA only. Trezor has none. No hash-based signer has one.
- Residual after it lands. A public R removes the secret-keyed defence against chosen-message FORS saturation under TRNG failure. The two properties are mutually exclusive without a zero-knowledge proof. Abort and timing channels remain.
- Not yet tracked. The protocol, the minimality check, and the trade-off decision. The verifier rates the real variant L because the proofs must be redone; the item map keeps M.

**M10. Electrical self-check.**
- Threat. A logger soldered to the display nets under genuine firmware.
- What to do. Phase 0 only: a prodtest measurement of RC decay on PA4, PA5, PA7 and PB0 against the unconnected PA6 pad, on at least 5 sealed units, reporting drift, spread and the delta from a real soldered tap. GO only if drift plus spread is under half the smallest tap delta. Write no refusal path before a measured GO. If built, it lives in the secure image, refuses without wiping, and refuses on a blank baseline.
- Evidence pq1 lacks it. No ADC, touch-sensing or comparator use in `secure/src` or `fsbl/src`.
- Precedent. None shipped. Academic: [PACTOR](https://spectrum.ieee.org/hardwired-to-self-destruct) (about 0.5 pF, temperature-sensitive) and [PDNPulse](https://arxiv.org/abs/2204.02482) (offline bench instrument).
- Hardware asks. Sealed units that can run our firmware (#695); display-net passives confirmed from the schematic; optional reference capacitor and input-current monitor footprint.
- Residual after it lands. A buffered tap (about 1 pF or less) sits at the floor. The detector is open source, so the adaptive cost is small. Allowed claim: "raises the cost of direct-soldered loggers on the display nets only".
- Not yet tracked. The Phase 0 issue; an OTP word reservation (rollback Draft 1.1 provisionally assigns 27 of 32 quad-words).
- Merger versus skeptic. P2 versus P3 (final P3). The skeptic removed the button nets and replaced the 0.13 pF resolution with about 1 pF.

### Covered in other sections

- M01, measurement-bound secret release: drop (rejected), section 6.
- M02, option-byte posture: P1, section 6.
- M08, erased-tail check on the selected slot: P3, section 9.
- M13, pre-PIN device words: P3, section 8.
- M17, per-boot SE configuration audit with host-side identity: P2, section 7.

### Considered and rejected

No item written here has status "rejected". These parts were dropped:

- **Factory certificate over a DHUK-derived key.** DHUK is an ST constant at RDP-0 and becomes per-die only after the field lock (`secure/src/main.rs:760-763`), so the factory never sees the key.
- **MCU attestation as a day-one counterfeit or firmware proof.** A fake MCU enrols its own key, everything readable at RDP-0 is copyable, and any secure image can select DHUK.
- **On-device manifest verification with permanent lockdown.** Self-verification is worth nothing against interdiction, and it adds classical verifiers to firmware (invariant #5).
- **Bag serial rendered by the FSBL.** FSBL budget, #705, #540. The secure-world page is equally self-report.
- **Touch-sensing (TSC) capacitance on display or button nets.** That alternate function exists only on PB4-7 and PB12-14.
- **Button-net RC measurement.** Each pad carries 100 nF and an ESD diode (`docs/hardware/evt-silicon-validation.md:470-471`); a 5 pF tap changes the time constant by about 50 ppm.
- **Analog watchdog wired to tamper erase.** A false trip erases the BHK that roots the final SE050 credentials (#712).
- **Self-check in the FSBL; baseline in flash or self-enrolled.** The FSBL is frozen at RDP-2 with 4,064 B free. Flash is rewritable over SWD at RDP-0. Self-enrolment cannot catch an implant already present.
- **Line-to-line ratios; display-rail current sensing.** A sniffer loads all lines about equally; backlight current swamps a sleeping implant.
- **Active tamper mesh; hardware BHK erase as the response.** The 48-pin package has TAMP_OUT only on the two button pads and PC13, and with no battery the comparator is dead when drained. The BHK is reloaded from page 126 every boot (`secure/src/hw/bhk.rs:27-33`), so only the software wipe is durable.

### Open questions and unmeasured claims

- UNMEASURED: display-net capacitance (15-30 pF assumed), pull-up mismatch between pins, lot spread, temperature drift, measurement noise floor, soldered-tap delta, quiescent input current. The on-chip impedance-sensing paper ([eprint 2022/946](https://eprint.iacr.org/2022/946)) failed verification in the deep-research pass, so no peer-reviewed support exists for a runtime detector of a passive tap.
- The tamper stack has never run on silicon (#391), and VBAT wiring is unconfirmed on V10.
- Not verified: whether RM0456 allows overwriting a set OEM key at RDP-0 without mass erase; which OPTIGA object holds the Infineon certificate (the repo observed 0xE0E3, the plan assumes 0xE0E0); whether V10 already routes the display nets on inner layers.
- Owner decisions: #40 (provision an OEM2 key) versus the no-OEM-key posture; SWD route on a sealed unit; VBAT supercapacitor or none; welded shell versus open inspection; public R versus TRNG-failure robustness.
- Incident attribution: the literature file records press reports of an October 2026 reseller incident ([CoinDesk](https://www.coindesk.com/business/2026/10/09/ledger-investigates-potential-wallet-tampering-after-reports-of-usd86-million-in-crypto-stolen)) with Ledger's statements secondary-reported. The deep-research pass verified only Grand's teardown of a unit first reported in August 2025 and could not tie the "CryptoBilis" label to it.

---

## 2. Display and seed-exfiltration side channels

Evidence level for this section: code reading and host tests. No seed-wizard or PIN screen has run on pq1 silicon with a panel (#700).

### What pq1 does today

**Implemented (confirmed by code reading, not on silicon).**

- Constant-time (CT) secret rendering on the legacy 16x4 path. The BIP-39 word fetch does no load addressed by the word index (`secure/src/ui/seed_wizard.rs:576-592`). Secret rows use a 96-entry mask-OR glyph scan (`secure/src/ui/secret_text.rs:51-64`). Every pixel of every cell is always written (`secure/src/ui/lcd.rs:237-278`). The only measurement is an emulated TVLA (test vector leakage assessment) of the memory-address channel, 650.90 leaky against 0.00 CT (`secure/src/ui/secret_text.rs:44-50`).
- Recovery prefix lookup and candidate list are CT (F-25, F-27; `secure/src/ui/seed_wizard.rs:992-1043`, `tools/sca/README.md:1416-1489`).
- Pixel UI (`ui-px`) twin: a 26-glyph CT scan (`pqsigner-ui-px/src/font.rs:272-321`), screen records that hold placeholders instead of words (`secure/src/ui/px/status_map.rs:359-368`), and a "force" rule under which a secret frame streams every strip, records no digest and invalidates the strip cache (`secure/src/ui/px/lcd.rs:300-343`).
- PIN entry masks entered digits and uses a random start digit per position (F-20, `secure/src/ui/pin_entry.rs:10-27`).
- SPI1 is secure-attributed (`secure/src/sau.rs:354-370`) and was in the 2026-05-20 silicon receipt.

**Partial.** The px wizard word cells are zeroized after paint (`secure/src/ui/seed_wizard.rs:97-99`, `:1006-1008`). The pixel buffers and the legacy row storage are not (see D-07). The consumption mask drives no load on either board, so its effect is UNMEASURED (`secure/src/hw/consumption_mask.rs:41-51`); it masks crypto work, not the panel.

**Fenced off or bench-only.** Decoy frames are default-off, legacy-only, and failed on glass at 20 MHz (#258). `ui-capture` is denylisted from production (#186). `ui-px` is outside `make release` and 76,949 B over the secure slot, so every px-side protection covers no shipping image today.

**Docs claim, code does not show.**

- `tools/sca/README.md:1381-1400` cites code and a test deleted with the OLED backend. `:1339-1354` and `secure/src/ui/seed_wizard.rs:315-320` still predict that decoys will work on the LCD.
- `pqsigner-ui-px/src/font.rs:270` names "the tools/sca F-24 harness" as the gate for the px secret run. That harness covers only the legacy font.
- `secure/src/ui/px/screens.rs:14-17` says secrets never enter a record. The active PIN digit and typed letters do (`secure/src/ui/px/status_map.rs:285`, `:303-309`).
- `tools/sca/README.md:1292-1296` says display shielding is tracked separately. No such issue exists.
- #237 still describes an SSD1306 OLED. `docs/security/threat-model.md:323-331` has no display-emanation row.

**Where pq1 is ahead.** A verification lens found no vendor precedent for CT glyph rendering plus forced full-strip streaming: Trezor's constant-time work is in seed processing (`crypto/bip39.c:244-262`), not rendering. pq1 also keeps the renderer and its buffers in the secure world, where Trezor gates an unprivileged renderer by MPU (`core/embed/sys/mpu/stm32u5/mpu.c:407-422`). Neither advantage stops a tap on the panel bus.

### What Trezor, Ledger and others do that pq1 does not

- **Mask re-randomised on every display refresh.** Trezor's OLED models call `consumption_mask_randomize()` in `display_refresh` (`core/embed/io/display/vg-2864/display_driver.c:414-418`) and feed the duty table by DMA at about 10 kHz (`core/embed/sec/consumption_mask/stm32u5/consumption_mask.c:73-142`). pq1 randomises from a software tick. Trezor's TFT models have no mask.
- **Constant lit-pixel count per row.** Trezor One pads the word band (`legacy/oled.c:451-473`) and inverts it (`legacy/firmware/layout2.c:834-838`). Ledger replaced its 2019 noise countermeasure in 2023 with a constant-count PIN screen, stating that physical noise could not hide the dependency ([Ledger 2023](https://www.ledger.com/blog/new-pin-screen), [Ledger 2019](https://www.ledger.com/blog/oled-vuln)). Coldcard 2.1.2 adds masking noise without proof that it closes the leak ([Coinkite](https://blog.coinkite.com/noise-troll/)). pq1's equivalent, #260, is deferred.
- **Ceremony hardening.** One word per screen on Safe 5 and Safe 7 (`layout_delizia/component/share_words.rs:21`, `layout_eckhart/firmware/share_words.rs:210`), an explicit "Show words" gate (`core/src/trezor/ui/layouts/caesar/reset.py:19-70`), and the line "Never put your backup anywhere digital" (`core/translations/en.json:2248`). pq1 shows 3 or 8 words per page with no warning.
- **Backup trust without showing the seed.** Trezor's entropy-check protocol (`core/src/apps/management/reset_device/__init__.py:91-126`) and a build-gated NFC backup (`core/src/apps/management/reset_device/layout.py:236-303`). pq1 has only the 24-word display (#250).
- **Always-on random delay interrupts** at 1 kHz (`core/embed/sec/random_delays/stm32/random_delays.c:166-203`). pq1 has none on display paths (#805, blocked on the "no software PRNG" contract).
- **Lock-time wipe.** Coldcard Mk4 wipes all SRAM on every logout; Trezor One clears its OLED buffer on screensaver (`legacy/firmware/layout2.c:302-310`).

**What vendors do not do.** Trezor has no countermeasure for bus content or in-line taps (`core/embed/io/display/vg-2864/display_driver.c:181-243`), and no vendor ships a constant-weight bus encoding on an SPI panel. The documented Ledger Nano X implant passively tapped the SPI bus between secure element and OLED and template-matched glyphs ([Grand, hardwear.io 2026](https://grandideastudio.com/media/ledger_hardware_implant_slides.pdf)); Ledger's recorded response was procedural. Trezor Core does not zeroize word buffers or clear framebuffers on lock; its lockscreen overwrites by rendering (`core/src/apps/homescreen/__init__.py:83-95`).

### Live defects confirmed on this surface

All rows: confirmed by code reading, not on silicon. Shipping set is `PROD_SHIP_FEATURES` (`Makefile:2718`): `ui-lcd`, no `ui-px`.

| Defect | Evidence | Reachable in the shipping feature set? | Severity | Tracked |
|---|---|---|---|---|
| Typed seed letters use the address-keyed public font lookup, which its own doc forbids for secret rows. Reached on restore and, through `verify_mnemonic`, on the 3 check words of every new wallet. | `secure/src/ui/seed_wizard.rs:918-949`, `:624-656`; `secure/src/ui/lcd.rs:153-172`; `secure/src/ui/secret_text.rs:84-93` | Yes | Merger: low-medium. Skeptic: low (emulated evidence only, one trace per keystroke) | No |
| Letter dial always starts at 'a' and the candidate cursor at range start, so the press count or repaint-burst count gives each letter with no side channel. Letters have no F-20 analogue. | `secure/src/ui/seed_wizard.rs:817`, `:896`, `:963` | Yes | Low-medium (skeptic) | No |
| Active PIN digit rendered in clear through the public lookup (legacy), and on a non-forced frame (px). | `secure/src/ui/pin_entry.rs:187-221`; `secure/src/ui/px/status_map.rs:277-290`; `secure/src/ui/px/lcd.rs:663` | Legacy half yes. px half no | Merger: low-medium. Skeptic: low for the glyph-address channel | No |
| px letter row bypasses the CT run and the force path and leaves a digest of letter pixels in `SHOWN`. | `secure/src/ui/px/status_map.rs:297-317`; `secure/src/ui/seed_wizard.rs:915` | No | Medium per the issue | #784 |
| px secret frames are force-streamed on every animation frame up to the 3 s cap. | `secure/src/ui/px/lcd.rs:664-690`, `:639` | No | Low | No |

### Recommendations

| ID | Recommendation | Kind | Cost | Priority | Novelty | Tracked issues |
|---|---|---|---|---|---|---|
| M03 | Close the shipping-path CT bypass for typed letters and PIN digit, stop re-streaming secret frames, then a constant-weight colour pair gated by an NV3007 leakage receipt | mixed | M | P2 | parity | #237, #258, #259, #260, #700, #772, #779, #780, #783, #784, #786, #794, #805 |
| D-07 | Zeroize pixel-form secret residue and blank the panel on every lock, wipe and idle timeout | firmware | S | P1 | parity | none |

**M03. Secret-frame display hardening**

- **Threat.** Recovery of seed words, typed letters or the active PIN digit by a measuring attacker near or inside the device. Four channels: (1) CPU-side glyph fetch address and strip-skip timing, fixable in firmware; (2) bus content seen by a weight-integrating observer, where firmware can raise cost; (3) bus content seen by a pattern-resolving receiver or logic tap, which no encoding hides; (4) the panel's own source-driver scan and rail, hardware territory.
- **What to do.**
  - (A) On the shipping path, route row 1 of `render_letter_screen` and `render_pin_screen` through `flush_with_secret_rows`. The legacy scan already covers digits. Add a random start letter per position and a random candidate cursor; without them the letter fix is close to cosmetic. Widen #784 to the legacy twin and the px PIN row. On px the entry row needs its own secret run at ring positions with digits added to the scan, because `show_with` paints into word-grid cells. Add a test that every secret-glyph screen uses the secret path, placed outside `secure/src/ui`, which host tests exclude.
  - (B) On px, play the public animation first and add secret cells only on the resting frame. Exempt forced frames from the #786 dirty-window optimisation.
  - (C) Take a fixed-versus-random leakage receipt on the real NV3007: bus near-field and panel rail, with a centre-frequency sweep. Purge the stale README text. Close #258 with one 40 MHz re-test or delete the feature.
  - (D) Only if (C) shows a first-order weight leak and a before/after gain: a per-call secret colour pair with equal Hamming weight, equal transitions and minimum Hamming distance, subject to a contrast floor judged on glass.
  - (E) Re-scope #260 (constant lit-pixel count per row) from (C) data.
  - (F) Owner decision: one word per page and a never-digital warning, with no leakage claim.
  - (G) Add the threat-model row and rewrite #237.
- **Priority disagreement.** The merger rated P1 on part (A). The skeptic rated P2: the address-channel evidence is emulated, press counting bypasses the letter fix, and no device has shipped. Final value: P2.
- **Dropped parts and why.** See "Considered and rejected".
- **Evidence pq1 lacks it.** The defect table; `docs/security/threat-model.md:323`.
- **Precedent.** Trezor and Ledger measures listed above. For (D), [Kuhn 2004](https://www.cl.cam.ac.uk/~mgk25/pet2004-fpd.pdf) describes an equal-transition colour pair and reports that it became readable at another centre frequency. No vendor ships (D). [Screen Gleaning](https://ar5iv.labs.arxiv.org/html/2011.09877) read digits from a phone display cable with a probe at under 1 cm.
- **Hardware asks.** An LCD-equipped EVT unit with a near-field probe and a shunt point on the panel supply. No load on SCK on the EVT, for the 40 MHz test. A shield over the display flex and driver, and filtering or a separate regulator for the panel supply.
- **Residual after it lands.** A logic-level tap still reads every secret pixel. A wideband receiver still resolves the differing bit slots. The panel scan and rail stay content-dependent while a word is shown. (D) does not close F-24 stage E.
- **Not yet tracked.** The four untracked defect rows; the colour pair; the NV3007 receipt; #260's stale precondition; the #786 force exemption; the ceremony decision.

**D-07. Zeroize pixel residue and blank the panel on lock**

- **Threat.** A post-lock SRAM dump or a later secure-world bug recovers rendered words in pixel form. This is defence in depth: non-secure code cannot read secure SRAM. The panel memory (GRAM) threat is physical only, since pq1 has no MISO line (`secure/src/board/pq1.rs:103`).
- **What to do.** Zeroize the legacy `cell` scratch once at the end of `flush_with_secret_rows`, the px `STRIP` static at the end of every forced frame, and the legacy `secret_rows_storage` and `wb`. Use the existing `fi::zeroize_barrier()` (`secure/src/fi.rs:290`). Hook buffer zeroize plus `fill_screen(BG)` into `zeroize_sensitive_state()` so lock, idle, tamper and panic all get it. Optionally turn the pq1 backlight off. Move strip zeroing into `pqsigner-ui-px` so its test runs.
- **Lens notes.** Two lenses seem to conflict on whether the px twins zeroize. They do not: the px word cells are zeroized, the pixel buffer is not. The feasibility lens rated the SRAM half P1 and the GRAM half P2. Final value: P1.
- **Dropped parts and why.** The panel reset pulse and the wider GRAM claim, below.
- **Evidence pq1 lacks it.** `secure/src/ui/lcd.rs:104`; `secure/src/ui/px/lcd.rs:55`, `:695-697`; `secure/src/ui/seed_wizard.rs:584-612`, `:1027-1040`; `secure/src/nsc/cmd_lock.rs:12-13`; `secure/src/nsc/mod.rs:1729-1744`. A grep for zeroize in `secure/src/ui/px/` and `pqsigner-ui-px/` finds nothing.
- **Precedent.** Coldcard Mk4's logout callgate (`wipe_all_sram()`, then screen overwrite) and Trezor One `oledClear()`. Coldcard halts on logout; pq1 would stay re-unlockable. The originally cited Trezor precedent was wrong: `display_fb_clear` on the st-7789 driver runs only on orientation change (`core/embed/io/display/st-7789/display_driver.c:164`).
- **Hardware asks.** None.
- **Residual after it lands.** Backlight-off hides content and does not erase it. A power cut with a secret page on glass leaves GRAM intact until the FSBL clears the panel at next boot (`fsbl/src/render.rs:95`).
- **Not yet tracked.** The entire item. #124 covers secure-element driver buffers only.

### Covered in other sections

- M10, display and button-net RC-decay self-check against a factory baseline: P3, section 1.
- M11, mass-production physical-access spec (shielded display nets, no test pads, destructive-open shell): P1, section 1.
- M13, pre-PIN "device words" against unit substitution: P3, section 8.
- M15, consumption mask, measure first then load or demote: P3, section 4.
- M19, make existing assurance gates run and block, including a glyph-leak regression net: P1, section 11.

### Considered and rejected

No item written here was rejected outright. These parts were dropped.

- **Randomised glyph offsets, colour-LSB jitter, K glyph variants.** The atlas is public; a sliding correlator and a high-bit threshold defeat them. K variants add flash to an over-budget image.
- **Random 0-300 ms pre-display hold.** A passive tap triggers on the bus itself. The archived random-delay rejection is contested by #805, so this rests on that argument alone.
- **Backlight dimming or PWM randomisation as a countermeasure.** The AW99703 is a constant-current sink with PWM dimming disabled (`secure/src/hw/aw99703.rs:104-115`); no content-dependent backlight channel exists.
- **Per-render strip-order shuffle.** Strip order goes out in clear as window commands, and it fights the #780 tear bound.
- **The colour pair as a defence against Kuhn-class or Screen Gleaning receivers.** Those resolve the bit pattern; the pair helps only against integrating observers.
- **Candidate pair 0x0400/0x0002 at "about 7.5:1".** The skeptic computes about 4.1:1 on an ideal panel. A distance-2 pair also forces 1-bit glyphs on px, a typography deviation.
- **Constant lit field around the secret band.** On a TFT it is a subtractable offset.
- **"Periodic TE-synced bus refresh" as the threat.** The NV3007 holds the frame in its own memory, and the legacy path paints each secret cell once. No repetition exists to average there.
- **Decoy frames as a default.** Failed on glass at 20 MHz because the repaint exceeds flicker fusion.
- **Re-randomising the next PIN start digit after each entry.** F-20 already draws eight independent starts; an attacker who could tell the difference reads the PIN from SRAM.
- **Panel reset to clear GRAM.** ST7789-class controllers specify frame memory as unchanged by reset, and the feasibility lens treats the NV3007 as the same family; no NV3007 evidence says otherwise. Only `fill_screen` erases.
- **GRAM residue after normal wizard exit.** The status paint already overwrites every secret cell on both paths.

### Open questions and unmeasured claims

- NV3007 bus and panel-rail leakage: UNMEASURED. Parts (C) to (E) are unevidenced until measured.
- Glyph-address channel strength: UNMEASURED on silicon.
- Frames per px seed page: UNMEASURED. The 16 ms constant is a pacing floor. The skeptic calculates at most about 60 frames in the 3 s cap (`secure/src/hw/spi_hw.rs:203`).
- Whether the px Words screen exits by the 3 s cap (#783): not determined.
- Owner decisions pending: random start letters; one word per page; the `ui-px` flash lever.
- No harness covers the px secret run, so a compiler fold of its barriers would go undetected.
- The M03 skeptic did not re-check the merge's Trezor, Ledger and Kuhn citations, or `aw99703.rs`.

---

## 3. Fault-injection hardening

Evidence level for this section: source reading, host tests and emulation. No physical glitch has ever been applied to this firmware (`docs/hardware/evt-silicon-validation.md:12`). Every defect below is confirmed by code reading, not on silicon.

### What pq1 does today

**Implemented.**
- Shared primitives: Hamming-distant sentinels, an invariant-checked delay loop, double-evaluated `check_true_into_sentinel` (`pqsigner-fi/src/lib.rs:56-62`, `:129-155`, `:170-215`).
- C10 signing: sign twice, constant-time compare, verify before release, relock on a confirmed fault (`secure/src/crypto.rs:350-359`, `:373-391`, `:407-418`).
- PIN gate: double-read counter, page-124 charge before the secure element (SE) verify, fail-into-wipe sentinels (`secure/src/nsc/mod.rs:1427-1437`, `:1473-1495`).
- Zeroize-then-reset on HardFault and NMI (`secure/src/main.rs:4637-4690`); fourteen emulated fault sweeps (`tools/sca/README.md:39-139`).

**Partial.** The first-stage bootloader (FSBL) has no true random number generator (TRNG), so its delay is the constant 0x42 (`fsbl/src/fi.rs:31-33`). The ordinary sign rate limiter is a plain load, compare, store (`secure/src/sign_rate.rs:239-258`). The sweeps are not in CI, and the full C10-sign sweep was only smoke-run (#232).

**Fenced off or bench-only.** Tamper and TrustZone wipe escalation are default-off and never silicon-validated (#391, #208). The first-boot self-lock to readout protection level 2 (RDP-2) is production-only candidate code.

**Docs claim, code does not show.** #834 says the delay no-reuse fix is "Implemented in dd901592", but master still carries the reuse arm (`secure/src/fi.rs:58-72`). `docs/security/HARDENING.md` §4.4-4.7 reads as brown-out posture; none of it is in code.

**Where pq1 is ahead.** No vendor in the data hardens hash-based signing as pq1 does. Double-compute, compare, verify is the countermeasure [RFC 9814](https://www.rfc-editor.org/rfc/rfc9814.html) and [Genêt](https://eprint.iacr.org/2023/042) call for. Trezor verifies SLH-DSA once per key and gets redundancy from an Ed25519 co-signature (`core/embed/sec/image/boot_header.c:66-93`), which invariant #5 forbids.

### What Trezor, Ledger and others do that pq1 does not

- **TRNG delay before every boot check**: `core/embed/projects/boardloader/main.c:111-129`.
- **Default-fail jump target written last**: `core/embed/projects/boardloader/main.c:250-252`, `:356-369`; default-fail function pointer and repeated compare: `core/embed/projects/bootloader/main.c:118-121`, `:593-595`.
- **Padding scan to the end of the flash area**: `core/embed/sec/image/image.c:437-523`. pq1 hashes only the signed length.
- **All runtime RAM cleared on a fresh stack at every halt or reboot**: `core/embed/sys/startup/stm32/sysutils.c:31-137`, `core/embed/sys/startup/stm32/bootutils.c:103-138`. pq1 clears named statics only.
- **Periodic random delay interrupt (RDI)**, 1 ms, in the secure monitor: `core/embed/sec/random_delays/stm32/random_delays.c:105-180`. pq1 has call-site jitter only.

**What Trezor does not do.** Its bootloader does not start the RDI. Its delay generator returns the constant 128 on lock contention (`core/embed/sec/random_delays/stm32/random_delays.c:72-85`), and `wait_random` is compiled out in prodtest (`:187`). Its `ensure()` is a single branch, the same one-skip residual as pq1's idiom. It charges the PIN counter on a detected fault only inside `storage/storage.c:1815-1844`. Neither Trezor nor Ledger has published an on-silicon campaign on the STM32U5; Ledger wrote on 2025-03-12 that no U5 FI attack was public ([source](https://www.ledger.com/why-secure-elements-make-a-crucial-difference-to-hardware-wallet-security)).

### Live defects confirmed on this surface

No production FSBL can be built today (`fsbl/src/main.rs:67-70`); FSBL rows describe the code that would be frozen. "Yes" means the ship feature set (`Makefile:2718`).

| Defect | Evidence | Reachable in the shipping feature set? | Severity | Tracked |
|---|---|---|---|---|
| FSBL slot word is a plain stack value; any non-zero decodes as slot B. One data fault boots the other slot under the verified slot's fingerprint | `fsbl/src/branch.rs:36-50`, `fsbl/src/slot.rs:10-13` | Needs only an older signed image in the other slot | Medium-high (skip model) | No |
| FSBL signature gate accepts on one skipped branch; `fsbl/src/fi.rs:12-16` claims two faults | `fsbl/src/main.rs:343-348`, `tools/sca/README.md:369-394` | Needs a post-RDP-2 flash write and a glitch every boot | Medium, chained (merger: high) | No |
| A fault on the `pick_slot` version compare selects the older valid slot with a matching fingerprint | `fsbl/src/main.rs:383-411` | Yes; no working rollback floor | Not rated; found by skeptic | No |
| FSBL delay is constant 0x42 | `fsbl/src/fi.rs:31-33` | Yes | Medium, acknowledged | No |
| Slot tail beyond the signed length is unmeasured; no stack limit register in the FSBL | `fsbl/src/verify.rs:38-108`, `fsbl/src/main.rs:172` | Yes; hardening gaps | Low-medium, low | No |
| C10 verifier sweep stops at 8,000 instructions; the target-sum compare is unswept | `tools/sca/README.md:1842-1848`, `sphincs-c10/src/wots.rs:178` | Tooling gap, no demonstrated forge | Unknown until swept | No |
| `halt_on_glitch` parks without zeroizing; secrets stay in secure SRAM about 32 s | `pqsigner-fi/src/lib.rs:273-285`, `secure/src/hw/iwdg.rs:137` | Yes | Medium (merger: medium-high) | #835 wrongly records it closed |
| Handler stack copies of secrets survive every reset | `secure/src/main.rs:1311-1333`, `secure/src/nsc/mod.rs:1729-1745` | Yes; frame contents UNMEASURED | Medium | #82 |
| First-boot `done & DONE_*` gates are bare branches; one skip omits an SE credential rotation. Replaces the merger's "dense phase words" defect, denied by the skeptic | `secure/src/first_boot/state.rs:306-375` | Only under `rdp2-self-lock` | Low-medium, untraced | No |
| PIN digit scrambler falls back to all-zero starts on RNG failure | `secure/src/ui/pin_entry.rs:73-88` | Yes | Low | No |
| One disagreeing page-124 read pair ends in a dual-SE wipe | `secure/src/nsc/mod.rs:1429-1436`, `secure/src/nsc/cmd_request_unlock.rs:160-164` | Yes; deliberate design | Low, availability | No |
| A persistent TRNG error makes every delay the last good byte | `secure/src/fi.rs:58-59`, `secure/src/rng.rs:115-121` | Yes; one latched error is recovered (`secure/src/hw/rng.rs:650-662`) | Medium (merger: high) | #834, #835; fix not on master |
| 31 of 32 delays inside `rng::fill` are identical | `secure/src/hw/rng.rs:620`; measured on silicon in #832 | Yes | Medium | #832, closed without the fix on master |
| Consumption-mask reseed fails open silently; no jitter before the first gate after the LCD flush; delays before RNG init are the constant 0x5A | `secure/src/hw/consumption_mask.rs:183`, `secure/src/nsc/cmd_sign_userop.rs:105-116`, `secure/src/main.rs:1384` | Yes; hardening gaps | Low | #831 for the first only |
| Docs: `docs/security/threat-model.md:321` lists `wait_random` as "Planned"; `secure/src/hw/sca_trigger.rs:27-34` documents trigger call sites that do not exist | as cited | n/a | Low | No |

### Recommendations

| ID | Recommendation | Kind | Cost | Priority | Novelty | Tracked issues |
|---|---|---|---|---|---|---|
| FI-01 | First on-silicon FI campaign, published with scripts and traces | process | L | P0 | parity | None as one gate. Sub-items: #401, #301, #591, #232, #592, #228 |
| M05 | FSBL pre-freeze bundle: fail-closed admission, encoded slot word, poisoned branch target, tail scan, stack limit, #591 sweep as acceptance | firmware | M | P1 | parity | #46, #130, #189, #226, #301, #366, #374, #401, #489, #540, #542, #591, #633, #642, #704, #705, #742, #758, #777, #805, #832, #834, #835 |
| M04 | Zeroize-then-reset in the glitch halt, written no-charge rule, hardened first-boot gates, scrambler fail-closed, SE fault diagnostics | mixed | M | P2 | parity | #47, #82, #109, #200, #208, #366, #484, #485, #692, #707, #715, #719, #802, #805, #834, #835 |
| M06 | Land the fixed delay source on master, gate-adjacent jitter, then a measurement-gated RDI | firmware | M | P2 | parity | #46, #80, #228, #241, #269, #301, #401, #642, #643, #780, #783, #802, #805, #831, #832, #833, #834, #835 |

**FI-01. On-silicon campaign.**
- **Threat.** RDP-2 glitch resistance is the highest-leverage unverified premise. [Bozzato et al.](https://tches.iacr.org/index.php/TCHES/article/download/7390/6562/2561) downgraded RDP-2 on an STM32F373 with one glitch; [µ-Glitch](https://www.usenix.org/system/files/usenixsecurity23-sass.pdf) defeated TrustZone-M on the L5 with four coordinated faults.
- **What to do.** (1) Sweep the RDP-2 option-byte fetch on sacrificial iota2 kits, not pq1 units. (2) Glitch the FSBL admission gates, slot word and `pick_slot`, after adding a trigger toggle. (3) Glitch `gated_unlock` with a wrong PIN, using a fenced bench feature that re-arms the three counters. (4) Glitch the `ct_eq` branch at `secure/src/crypto.rs:366` with double-compute on and off; this needs a never-ship feature and a C10-specific grafting oracle. (5) Leakage test at 10k traces or more. Bind each receipt to the reproducible-build hash.
- **Dropped parts and why.** Clock glitching: pq1 has no external clock. The F4-style VCAP crowbar: `docs/security/red-teaming.md` §13.2 refutes it for the U5. 1k traces: too few. [SPHINCSplus-FA](https://github.com/AymericGenet/SPHINCSplus-FA) as-is: it does not run against C10.
- **Evidence pq1 lacks it.** `tools/bench/` holds connectivity probes only.
- **Precedent.** Donjon runs such campaigns on competitors' parts; no vendor publishes one on its own.
- **Hardware asks.** None for the product; rework on sacrificial boards.
- **Residual after it lands.** A null result holds only for the swept windows; a single-fault null on the TrustZone window proves little. Secure-image results are per release.
- **Not yet tracked.** One umbrella release gate with the publication criterion; on-silicon legs (3) and (4); wiring `sca-trigger`.

**M05. FSBL pre-freeze bundle.**
- **Threat.** Faults against the one stage that becomes unpatchable at write protection plus RDP-2 (invariant #10). [Wagner et al.](https://eprint.iacr.org/2023/1572) and the [BSI-commissioned study](https://eprint.iacr.org/2025/2096) establish the verifier fault class.
- **What to do.** Run the widened #591 sweep first on the pq1 release ELF to get a failing baseline. Then fold per-stage verdict words with distinct constants into the branch address through a non-cancelling accumulator; this fold goes beyond Trezor. Carry the slot as a Hamming-distant word plus complement, re-compare it before the branch, bind the fingerprint digest to it, and make `into_slot` reject anything else. Default to a halt stub. Add the stack limit and a 0xFF tail scan bounded by the geometry registry. Stage B, a second target-sum computation in the Winternitz one-time signature (WOTS) verifier, only if the widened sweep shows a single-fault forge.
- **Merger versus skeptic.** The skeptic corrects the budget to the pq1 ELF: 22,236 B, with 2,340 B before a fourth protected page, against an UNMEASURED 0.9 to 1.4 KB estimate. It splits the merger's FSBL TRNG out as a separate owner decision: a permanent no-boot mode in unpatchable code, for jitter that a side-channel trigger defeats.
- **Dropped parts and why.** Checksum recompute, root `ct_eq`, FORS sentinel, wipe escalation, full RNG driver (see below).
- **Evidence pq1 lacks it. Precedent.** The FSBL defect rows; the Trezor boot lines above.
- **Hardware asks.** None; bench glitch rig only (#301).
- **Residual after it lands.** Side-channel-triggered and multi-fault attackers; a deterministic fault in the single HASH peripheral; `pick_slot` until a rollback floor exists.
- **Not yet tracked.** Every FSBL row above; Stage B; the stale 28,704 B figure in `CLAUDE.md` invariant #10.

**M04. Fault response without attempt-charging.**
- **Threat.** The glitch-detected path is the one park that leaves secrets resident.
- **What to do.** (A) Pass a diverging `on_glitch` action into `wait_random_loop`: mask interrupts, zeroize, system reset. Close stack residue with the SRAM_RST=0 option byte (#82), staged before the RDP-2 burn. (B) Record "detected faults do not consume PIN attempts outside the PIN gate" with a source test. (C) Route the first-boot `done` gates through `check_true_into_sentinel`. (D) Scrambler: one bounded retry, then refuse. Owner confirmation needed: `secure/src/ui/pin_entry.rs:73-78` records the opposite rationale. (E) Reason codes and per-session SE retry counters, diagnostics only.
- **Merger versus skeptic.** Merger P1, final P2: the merger's stack scrub cleared dead stack only, and #82 is the real fix.
- **Dropped parts and why.** Charge-on-fault, second-trip wipe, backup-key erase, park after zeroize (see below).
- **Evidence pq1 lacks it.** `pqsigner-fi/src/lib.rs:273-285`; no SRAM_RST reference in `secure/src/first_boot/`.
- **Precedent.** Trezor clears RAM on halt and does not charge on generic faults (`core/embed/rtl/inc/rtl/error_handling.h:144-149`).
- **Residual after it lands.** Glitch trials stay free in attempt terms; a PIN-holding attacker is unbounded.
- **Not yet tracked.** Items A to E; the single-read wipe question; correcting #835's "H4 closed" wording.

**M06. Delay desynchronisation.**
- **Threat.** Faults timed from an observable anchor: veneer entry, LCD or I2C activity.
- **What to do.** Stage 0 (effectively P1, owner-decided): land the `perf/flash-opt-level-z` delay-source commits on master and close #835. Stage 1: one `wait_random` immediately before the first gate of each of the 17 production veneers, after any `ui::show_status`, with a source-grep gate. Stage 2: an always-on RDI on the existing secure SysTick, with a handler-only generator and a bounded reseed, shipped only after timing, USB and SE soak tests.
- **Merger versus skeptic.** The merger's "36 veneers" with a "shared entry" is wrong; no shared entry exists. The skeptic rates Stage 2 P2 at most, arguably P3 until measured. #833 in the tracked list resolves to an unrelated PR.
- **Dropped parts and why.** Timing canary, PWM-timer host, masking windows, FSBL RDI (see below).
- **Evidence pq1 lacks it.** `fi_delay_pool.rs` is absent from master.
- **Precedent.** Trezor only.
- **Residual after it lands.** An attacker who re-arms on an LCD, I2C or power edge within about 1 ms of the target is unaffected.
- **Not yet tracked.** The merge to master; gate-adjacent jitter; an answer in #805 to the 2026-05-28 "do NOT build" verdict.

### Covered in other sections

- M20, glitch environment sensing: P0, section 11.
- M02, option-byte posture: P1, section 6.
- M19, assurance gates in CI: P1, section 11.
- M21, memory fault resilience: P1, section 11.
- M01, measurement-bound secret release: dropped, section 6.

### Considered and rejected

- **Charge a PIN attempt on a detected fault outside the PIN gate.** `pin_attempts_bump` charges MCU page 124 only; after unlock the next correct PIN resets it; before unlock the gate already precharges. [Tangem's](https://donjon.ledger.com/blog/bypassing-tangem-card-security-with-laser-attack/) post-detection counter fell to power tearing.
- **Second trip means dual-SE wipe.** `wait_random` is reachable from SysTick and preempted veneers, so re-entry is a scheduling event and gives the non-secure world a wipe primitive.
- **Option-byte mismatch arms a wipe.** After RDP-2 the bytes are frozen, so a mismatch is a read glitch and a wipe is denial of service.
- **Erasing the backup-register key (BHK) at halt.** It is reloaded from page 126 every boot, so nothing is cryptographically erased (#707).
- **Zeroize, then park.** A masked park only ends at the watchdog reset; reset directly.
- **"Recompute the WOTS checksum".** C10 is WOTS+C and has no checksum chains; the single point is the target-sum compare.
- **"Verify twice" and `ct_eq` of two roots in the FSBL.** The gate already evaluates twice; the values are public and a new API moves the Lean extraction surface.
- **FORS forced-zero check through a sentinel.** It is a grinding constraint; skipping it alone does not forge.
- **Copying `secure/src/hw/rng.rs` or a bounded fallback into the FSBL.** 36 KB of source for a jitter-only consumer; a fallback contradicts #834.
- **Disassembly-counting CI gate.** #777 shows outlining makes call-site counts unsound.
- **0x00 tail fill; address 0 as fail target.** Slots are erased to 0xFF; address 0 under TrustZone is a SecureFault, not a reset.
- **Core-clocked timing canary.** Frequency-invariant, blind to data faults, and the cycle counter is non-secure-writable (`secure/src/main.rs:4263-4273`).
- **RDI on TIM2/TIM3, masking windows, USB-packet refresh, RDI in the FSBL.** The timers drive the consumption mask; a mask flag is a fault target; USB is non-secure-owned; the FSBL has no TRNG.
- **RDI fed from the delay pool or raw TRNG.** Recreates the #802 drain and driver-lock contention.
- **`wait_random` before the SAU and clock writes.** No TRNG exists yet.
- **Timing envelopes around the SE verdict.** I2C latency varies by orders of magnitude.

### Open questions and unmeasured claims

- Does RDP-2 on the U585 resist a boot-time glitch? UNMEASURED; no board in the project has been at RDP-2.
- Silicon feasibility of every FSBL defect: UNMEASURED; emulation has not run on that glue either.
- M05 flash cost and whether the protected range stays at pages 0 to 2: estimate only.
- Does SRAM_RST cover SRAM1 on watchdog and software resets? Not checked against the reference manual.
- RDI benefit, its flash cost, and the true `mode-production` image size: UNMEASURED.
- Owner decisions pending: FSBL TRNG failure policy, scrambler fail-closed, the single-read wipe, and whether #805 moves from research to build.

---

## 4. Side-channel analysis on signing, key derivation, PIN and secure-element tunnels

### What pq1 does today

**Evidence level.** No power or electromagnetic (EM) trace has ever been captured from pq1 silicon. Every leakage result in the repo is an emulation of the Hamming weight of memory addresses; register values and the HASH and SAES coprocessors are invisible to it (`tools/sca/README.md:456-512`, #228, #236). Every leakage property below is UNMEASURED on silicon.

**Implemented, confirmed by code reading, not on silicon.**

- Signing: the F-16 per-signature shuffle of WOTS chain order and FORS tree order, with independent seeds per double-compute pass (`sphincs-c10/src/shuffle.rs:97-200`, `secure/src/crypto.rs:238-310`); a hedged secret-keyed R-grind (`sphincs-c10/src/fors.rs:64-123`); fresh three-source OptRand (`secure/src/crypto.rs:182-237`); the F-17 limiter of 250 signs per unlock (`secure/src/sign_rate.rs:42-48`).
- Constant-time (CT) code: BIP-39 lookups are 2048-entry mask-OR scans (`bip39/src/full.rs:108-130`, `:489-530`). cargo-checkct proves five drivers free of secret-dependent branches and addresses (`tools/sca/DONJON-RUST-TOOLING.md` §1).
- Keys: the Tier-1 KDF is SAES-CMAC under the device-unique hardware key (DHUK), which never enters CPU registers (`secure/src/hw/saes_cmac.rs:38-46`). PIN comparison stays in secure-element (SE) silicon.

**Partial.**

- The consumption mask is forced on for shipping builds and drives no load on either board (see M15).
- F-16 leaves FORS leaves in natural order (`sphincs-c10/src/fors.rs:148-150`). One sign runs 70,754 `sk_seed`-absorbing SHA-256 calls through a HASH peripheral with no DPA resistance (`sphincs-c10/tests/hash_counts.rs:32-76`).
- The F-17 flash-persistent daily quota is not implemented (`secure/src/sign_rate.rs:35-39`).
- cargo-checkct is not a CI gate (`nightly.yml:147-223`, #312), and no leakage harness runs in CI.

**Fenced off.** The `sca-trigger` GPIO is production-fenced (`secure/src/nsc/mod.rs:134-142`). Masked SHA-2 and SHAKE are closed owner decisions. Invariant #6 blocks the v2 PRF restructure (#229).

**Docs claim what code does not show.** `tools/sca/README.md:600-640` says `grind_r` "NEVER reads sk_seed"; `sphincs-c10/src/fors.rs:110` hashes it on every iteration, and those roughly 2048 iterations are missing from the 70,754 census. The F-17 1 s minimum interval is a no-op against a measured 6.4 to 7.2 s sign (#699).

**Where pq1 is ahead.** Trezor has no masking, shuffling or share representation in its hash, MAC or KDF code (`crypto/sha2.c`, `crypto/hmac.c`, `crypto/pbkdf2.c`); pq1 has the F-16 shuffle. pq1 shipped CT BIP-39 lookups before Trezor's fix for [CVE-2025-69893](https://trezor.io/vulnerability/fix-side-channel-in-bip-39-mnemonic-processing-when-unlocked). pq1 checks in leakage tooling and CT proofs; a grep of trezor-firmware for TVLA or leakage tooling returns nothing. The [Trezor One PIN attack](https://www.ledger.com/blog/Breaking-Trezor-One-with-SCA) does not apply: pq1 has no MCU-side PIN compare.

### What Trezor, Ledger and others do that pq1 does not

- **Always-on random delay interrupt (RDI).** A 1 ms secure timer inserts floating-mean random stalls, refreshed on every USB data event (`core/embed/sec/random_delays/stm32/random_delays.c:139-144`, `:168-181`). pq1 randomises only at annotated `fi::wait_random()` sites (#805), and its delay source had three defects in one month (#643, #832, #835). See M06.
- **DMA-fed mask.** 119 TRNG samples streamed by a secure GPDMA linked list (`core/embed/sec/consumption_mask/stm32u5/consumption_mask.c:26-27`, `:34-37`). pq1 steps an xorshift32 from SysTick.
- **Die-bound PIN material.** PBKDF2 times 20000, then SAES whitening under DHUK xor BHK (`storage/storage.c:114`, `:665-671`), and a digest-before-send pattern so the SE and bus never see the stretched PIN (`docs/core/misc/optiga.md:58-66`). pq1 sends the raw 8-byte PIN inside the tunnels. See M16.
- **Smaller items.** Exponential PIN back-off (`storage/storage.c:1158-1161`, see M12); random delays before every host-visible USB reply (`core/embed/io/usb/stm32/usb.c:617-716`, see M06); the crypto-peripheral fault tamper ITAMP9 (`core/embed/sec/tamper/stm32u5/tamper.c:140-151`, see M20).
- **Ledger.** Its answer to the OLED power channel ([LSB-006](https://donjon.ledger.com/lsb/006/)) was randomised screen-update parameters, not a PWM mask.

**What Trezor does not do.** It enables the mask only on the two monochrome OLED models (`core/embed/models/T2B1/model.toml:5`, `T3B1/model.toml:5`) and re-randomises it only on display refresh (`core/embed/io/display/vg-2864/display_driver.c:417`). It uses the HASH accelerator only for firmware image hashing (`core/embed/sec/image/inc/sec/image_hash_conf.h:31-36`); this is the observed posture, with no documented rationale in the tree. It runs its OPTIGA Shielded AES in software (`core/embed/sec/optiga/optiga_transport.c:773-777`), as pq1 does. Neither Trezor nor Ledger publishes leakage measurements for its own devices.

**Literature.** [Saarinen 2024/367](https://eprint.iacr.org/2024/367) reached t=24.5 within 1,000 traces on an SLH-DSA PRF with CPU hashing. [Belenky et al.](https://tches.iacr.org/index.php/TCHES/article/view/10955) forge HMAC-SHA-2 from a pure hardware core at 30K to 275K traces. The [2025 SoK](https://eprint.iacr.org/2025/1222) finds one published SCA on hash-based schemes relevant to SLH-DSA, so prior art gives no assurance either way. Ledger's [boot-time CPA on Jade](https://www.ledger.com/blog/firmware-extraction-evil-maid-attacks-on-blockstream-jade-hardware-wallet) is the precedent for the pre-PIN tunnel target in SCA-01.

### Live defects confirmed on this surface

| Defect | Evidence | Reachable in the shipping feature set? | Severity | Tracked |
|---|---|---|---|---|
| The production-mandatory mask drives no load on pq1; the fence comment still says the signature "stays uncorrelated" | `secure/src/board/pq1.rs:301-316`, `secure/src/nsc/mod.rs:694-705`, `Makefile:2718` | Yes. Over-claim, not an exploit; the no-op is argued from physics, not measured | Low (merger: low-medium; skeptic lowered it, since `secure/src/nsc/mod.rs:717-722` already says "unmeasured") | #646 partly |
| Mask reseed fails open with no counter; a skipped window waits about 1 s | `secure/src/hw/consumption_mask.rs:181-189`, `secure/src/consumption_mask_prng.rs:85-93` | Yes. Zero skips at non-signing load; signing load UNMEASURED | Low | #831, #646 |
| At HEAD the tested PRNG module has no production caller; the driver keeps an inline copy and the fix is uncommitted | `git show HEAD:secure/src/hw/consumption_mask.rs` :138, :145, :196-198; `secure/src/consumption_mask_prng.rs:22-43` | Yes at HEAD (test-coverage gap) | Low | Untracked |
| The pad self-test runs only under `debug-log` | `secure/src/hw/consumption_mask.rs:99-116` | Yes; production forbids `debug-log` | Low | Untracked |
| Mask docs are wrong: "seeded from rng_strong", "TIM2 CH1 on PA5" for all boards, "masking is the only SCA mitigation" | `docs/security/red-teaming.md:694`, `:306`; `README.md:88`, `261`, `417`; `secure/src/main.rs:1408` | n/a (documentation) | Low | Untracked |
| The `sca_trigger` module doc lists three firing sites; no call site exists, so the pin never toggles | `secure/src/hw/sca_trigger.rs:25-33` | No; production-fenced | Low | #228 checkbox only |

### Recommendations

| ID | Recommendation | Kind | Cost | Priority | Novelty | Tracked issues |
|---|---|---|---|---|---|---|
| M15 | Consumption mask: fix the over-claim, measure, then keep or demote | mixed | M | P3 | parity | #6, #53, #228, #229, #236, #237, #261, #298, #312, #646, #786, #792, #802, #805, #831, #832, #834, #835 |
| SCA-01 | First on-silicon TVLA/CPA campaign, aimed at `fors_secret` and pre-PIN tunnel crypto | mixed | L | P2 | beyond | #228, #229, #236, #241, #298, #299, #301, #312 |
| SCA-02 | Move SE-tunnel AES onto SAES; add `shield.rs` to the leakage harness | firmware | M | P2 | beyond | #55, #202, #228, #236, #246, #299, #648 |
| SCA-03 | WOTS PRF midstate-resume (redesign needed; refuted as written) | firmware | M | P3 | beyond | #228, #229, #299 |

**M15, consumption mask.**
- Threat. A bench attacker with a shunt or EM probe on an unlocked device targets the secret PRF calls.
- What to do. Split it, as the skeptic requires. Now: reword `secure/src/nsc/mod.rs:694-705`, `README.md:233` and `docs/security/red-teaming.md:306` to "unvalidated noise source; efficacy pending #228/#646", without waiting for a measurement; commit the PRNG refactor and delete the STATUS block at `secure/src/consumption_mask_prng.rs:22-43` with it; add a skip counter and a capped reseed retry; label `selftest_pin_toggles()` bench-only; fix the stale docs. Parked: add mask-off, unloaded and loaded arms to the #228 capture on iota2, reporting max|t| raw and after a >100 kHz high-pass. A positive iota2 result does not by itself justify a pq1 spin.
- Dropped parts and why. See "Considered and rejected".
- Evidence pq1 lacks it. First defect row.
- Precedent. Trezor, OLED models only, no published load or measurement.
- Hardware asks. None for pq1 now: a respin for an unmeasured, physically doubtful effect is not justified. Bench: a resistor on iota2 PA5, a shunt and a differential amplifier. Conditional on a positive result: PA6 to a do-not-populate load on the MCU VDD domain, not the SE rail. Regardless: a shunt footprint and trigger pad on a pq1 bench variant.
- Residual after it lands. The channel is characterised, not closed. Even loaded, the mask does nothing against a local EM probe or single-trace attacks, and both reviewers expect a high-pass filter to remove most of it.
- Not yet tracked. The three-arm comparison; the fence over-claim and whether the fence stays (owner decision); the capped-retry constraint; the uncommitted refactor; further stale sites (`CLAUDE.md:221`, `:318`; `docs/hardware/evt-silicon-validation.md:175`, `:758-764`).

**SCA-01, first silicon campaign.**
- Threat. #228 aims at the wrong PRF: WOTS block 1 is a per-layer constant with no varying known input (`sphincs-c10/src/hash.rs:376-392`), while `fors_secret` is one compression mixing `sk_seed` with varying known words (`sphincs-c10/src/hash.rs:408-416`).
- What to do. Now: amend #228 to name `fors_secret` and WOTS block 2, add a `grind_r` hash-counter bucket, correct the `sca_trigger` doc. Then wire per-call triggers and build a harness image that calls the PRFs with chosen inputs on the `hw-sha256` path. Order: tunnel crypto first (the only half fixable in v1), then FORS and WOTS, then SAES-CMAC(DHUK) as single-trace characterisation only. Publish max|t| against trace count with the noise floor.
- Dropped parts and why. "Hardware already on the bench": false for the analog front end. "Ideal vertical-DPA shape": only W[9..11] vary, with 11 to 18 bit values. SAES-CMAC(DHUK) as CPA: no varying known input. P0: a PRF leak can only be documented in v1.
- Evidence pq1 lacks it. `docs/STATUS.md:428`; the dead trigger (last defect row).
- Precedent. None; neither vendor publishes receipts.
- Hardware asks. A shunt or current-probe insertion point on a pq1 bench unit, or an H-field probe with amplifier. iota2 is the cleaner tunnel target, because the pq1 bench SE050 handshake dies on a cryptogram mismatch.
- Residual after it lands. It removes no leakage. A clean result at the scope's noise floor is not proof of absence.
- Reviewer disagreement. One lens says P2, the other P1; both say cost L. Final: P2, L.
- Not yet tracked. Everything in "Now", the pre-PIN threat ordering, the pq1 analog front end.

**SCA-02, tunnel AES on SAES.**
- Threat. `scp03::establish` CMACs the static SCP03 keys in software over a bus-supplied card challenge, before the card is authenticated, on every SE050 init (`secure/src/se050/scp03.rs:251-284`, `secure/src/scp03_logic.rs:124-175`). A recovered key plus a bus tap on a legitimate unlock yields `half_E`.
- What to do. Add AES-128 key size to `secure/src/hw/saes.rs` (`:487` hard-codes 256) and a load-once multi-block API; run SCP03 KDF, CMAC and CBC and the Shielded CCM over SAES ECB behind the `cmac_generic` closure seam (`secure/src/cmac.rs:61`); switch all five establish sites, including first-boot rotation, together; keep the software path for QEMU and host tests. Gate landing on the SCA-01 tunnel measurement.
- Dropped parts and why. Running the TLS-PRF once per power-on buys nothing against a power-cycling attacker. "Shortest CPU residency" is contradicted by the driver, which rewrites all key registers on every block (`secure/src/hw/saes.rs:493-524`). The emulated `shield_target` cannot measure the value channel.
- Evidence pq1 lacks it. The only `KeySel::Software` caller outside `saes.rs` is a known-answer test (`secure/src/hw/bhk.rs:397`).
- Precedent. None; Trezor never runs SAES with a firmware-loaded key. Hardware asks: none.
- Residual after it lands. The OPTIGA leg stays open: the session keys are a software HMAC-SHA256 of the platform binding secret and a chip-supplied `random_S` with no host nonce (`secure/src/optiga/shield.rs:381-397`), so a bus interposer can replay it. The benefit rests on ST's SAES DPA claim, UNMEASURED. The static key is still loaded from CPU memory.
- Reviewer disagreement. One lens says P2 and L, the other P1 and M. Final: P2, M.
- Not yet tracked. All of it, including the flash delta against an over-budget slot.

**SCA-03, WOTS midstate-resume (redesign needed).**
- Threat. Fixed-offset absorption of `sk_seed` in 44,118 `wots_secret` calls per sign.
- What to do. Do not build it. Keep the residue: correct #229 and `docs/archive/work-todo-retired-2026-07-19.md:1920`, which say no cacheable midstate exists, and split the hash census into raw-`sk_seed` and secret-chaining-value buckets. Revisit only after #228.
- Dropped parts and why. See "Considered and rejected".
- Evidence pq1 lacks it. No midstate or HASH context-swap code exists.
- Precedent. None as an SCA measure. Residual: leakage unchanged.
- Reviewer disagreement. One lens refuted it (P3); the other did not (P2). Final: P3.
- Not yet tracked. The #229 correction and the census split.

### Covered in other sections

- M03, secret-frame display hardening (SCA-10): P2, section 2.
- M06, FI-delay source, dispatcher jitter, measurement-gated RDI (SCA-05): P2, section 3.
- M12, PIN inter-attempt back-off (SCA-08): P3, section 8.
- M16, die-bound and salted PIN credentials, DHUK-masked XOR halves (SCA-06): P1, section 7.
- M20, NS clock/power/tamper levers, PVD, ADC4 watchdogs (SCA-04): P0, section 11.

### Considered and rejected

- **SCA-09, additive-masked compares (rejected).** The operands at `secure/src/dual_se.rs:468-470` are equal on every honest unlock, so the masked difference is constant zero, and both operands are still loaded unmasked. The same secrets pass through an unmasked SHA-256 on the preceding line. Trezor's `secequal32` (`storage/storage.c:220-243`) guards a normally-unequal compare against an attacker-chosen guess, which pq1 does not have.
- **SCA-03 as written.** `fors_secret` and `grind_r` still absorb `sk_seed` about 28.7k times per sign, so the gain is at most about 1.6x in signal-to-noise. Resuming loads a secret midstate about 22k times per layer at a fixed offset, and the layer-1 midstate is forgery-equivalent. The software option moves a secret compression onto the CPU.
- **D-06, mask as a display-emanation defence (dropped in M15).** A 10 kHz PWM cannot touch 20 MHz SPI content.
- **Mask on the backlight enable (dropped in M15).** It would modulate trusted-display brightness and load the wrong rail.
- **GPDMA table port now, and "refill per display refresh" (dropped in M15).** With no refresh during a 7 s sign, Trezor's table is a fixed 11.9 ms pattern that averages out. Continuous TRNG refill at 10 kHz is infeasible as specified (#802 measured about 356 us per 1 ms tick). Edge-aligned PWM leaves a fixed rising-edge grid, so the period must be randomised too.
- **Per-tick reseed retry (dropped in M15).** Uncapped retry under a persistent TRNG error recreates #802.

### Open questions and unmeasured claims

- Does the HASH peripheral leak `sk_seed` on this silicon, and does a loaded mask change traces-to-detect? Both UNMEASURED (#228).
- Can an attacker collect unlimited pre-PIN SCP03 handshakes? Not verified: the boot order in `main.rs` and any failed-handshake accounting were not traced.
- Does the Rigol plus shunt chain have TVLA sensitivity, or is a ChipWhisperer-Husky required? `docs/security/red-teaming.md:99-104` and `docs/hardware/evt-silicon-validation.md:921-923` disagree.
- If the mask is demoted, the retained SCA layers shrink to F-13, F-16, F-17 and OptRand. That goes to the owner, without reopening SHAKE or masked SHA-2.
- Open with no issue: the F-17 daily quota, and SCA characterisation of the single SHA-256 over the 8-digit PIN (`secure/src/optiga/mod.rs:916-918`).

---

## 5. Blind-signing elimination and clear-signing coverage

Evidence level for this section: code reading at HEAD c75b0d9c plus host and QEMU transcripts, not silicon. The pq1 bench board has no LCD and the physical what-you-see-is-what-you-sign (WYSIWYS) campaign has never run (#375, #700).

### What pq1 does today

**Implemented.** A priority-ladder dispatcher routes every UserOp through native CoW, Safe, ERC-7730, a known-call omission filter, value transfer, ERC-20, typed-call and finally loud blind sign (`secure/src/tx/display/dispatch.rs:551-566`); any ladder error is a refusal (`secure/src/nsc/cmd_sign_userop.rs:1559-1561`). Safe multiSend is decoded per record against three pinned addresses, at most 6 records, refuse-not-truncate (`secure/src/tx/eip712/safe/multi_send.rs:1-80`). ERC-7730 proofs are Merkle-verified against a firmware-pinned root of 365 leaves (`secure/src/tx/erc7730.rs:53-77`). A 16 KiB Bloom filter of 4,615 registry-known tuples hard-refuses a known call that arrives without its descriptor (`secure/src/tx/display/dispatch.rs:1023-1103`). Off-chain typed data requires a verified, bound descriptor and refuses otherwise (`secure/src/nsc/cmd_sign_offchain.rs:421-560`).

**Partial.** The catalogue is dev-unattested: 0 of 365 descriptors carry an ERC-8176 attestation, so a production-shaped image has no catalogue it can ship (#377). The pixel UI (`ui-px`) is out of `make release`, 76,949 B over the secure slot; its chrome mask sits outside every transcript proof (#762) and its interactive presenter has no automated coverage (#779).

**Fenced off.** Forced-blind is default-off and production-forbidden (`Makefile:2675`); v1 is rejected, v2 awaits an owner decision (#329).

**Claim-versus-code drift.** CLAUDE.md names `fsbl-tests/tests/paired_constants.rs` as the scroll-to-end pin; the pin is at `fsbl-tests/tests/source_invariants.rs:878-890`, and `paired_constants.rs:168-172` still says the constant is `false`. The CoW "exact intent" claim holds only for database-known tokens (`secure/src/tx/eip712/cowswap/verify.rs:196-214`). `docs/STATUS.md:468` calls Kani "CI-wired"; the nightly has not completed since about 2026-09-06 (#776).

**Where pq1 is ahead.** A registry-known shape either clear-signs or refuses, where Trezor and Ledger fall back to blind signing ([Ledger wallet docs](https://developers.ledger.com/docs/clear-signing/for-wallets)). pq1 decodes SafeTx on-device, where the industry procedure is manual hash comparison ([SEAL framework](https://frameworks.securityalliance.org/wallet-security/signing-and-verification/secure-multisig-safe-verification)). The literature search found no Ledger or Trezor UserOp decoding ([eth_signUserOperation thread](https://ethereum-magicians.org/t/eip-idea-eth-signuseroperation-rpc/16184)).

### What Trezor, Ledger and others do that pq1 does not

Trezor paths are relative to trezor-firmware at 6ab39e95.

- **Generic EIP-712 walker** with empty-domain warning and nested-domain rejection (`core/src/apps/ethereum/sign_typed_data.py:69-140`, `:293-296`, `:407-426`). pq1 refuses typed data without a curated descriptor. Trezor lets the user skip struct and array contents, and its empty domain is a warning, not a refusal.
- **Signed external definitions**: Merkle proof, CoSi-signed root, type-domain byte, firmware-baked minimum data version (`core/embed/rust/src/definitions/blob.rs:34-89`). The floor is a build-time constant; nothing is persisted on the device.
- **Unknown-contract danger screen** (`core/src/apps/ethereum/layout.py:132-142,415-418`). pq1 has loud banners and pixel pulse cues but no shared danger class.
- **Address chunking** with an isolated `0x` (`core/src/apps/ethereum/layout.py:588-594`) and a seed-derived **address MAC** (`core/src/apps/common/address_mac.py:14-44`).

Trezor does not have: a blind typed-hash handler in core (legacy T1 only, `legacy/firmware/ethereum.c:1210-1228`), built-in `setApprovalForAll`, `increaseAllowance` or `permit` handlers, a custody-change danger class, a spending policy, or paymaster code. Its documented choice on clear-sign failure is blind fallback (`core/src/apps/ethereum/README.md:146-154`).

Coldcard ships a device-enforced spending policy ([SSSP](https://coldcard.com/docs/sssp/)). Ledger's 2026 bulletins define the regression classes for this surface: an 8-bit array count that reviewed 257 elements as one ([LSB-024](https://donjon.ledger.com/lsb/024/)), a host overwriting parameters between display and signature ([LSB-023](https://donjon.ledger.com/lsb/023/)), and an `approve` accepted as a payment ([LSB-025](https://donjon.ledger.com/lsb/025/)).

### Live defects confirmed on this surface

| Defect | Evidence | Reachable in the shipping feature set? | Severity | Tracked |
|---|---|---|---|---|
| RAW32 (kind 0) is accepted with only a length check and no switch removes it, so a hostile companion can downgrade supported typed data to a 32-byte hash | `secure/src/nsc/cmd_sign_offchain.rs:212-218`; `Makefile:2672-2675` | Yes in principle. No production image can be built today (`OPTIGA_S2_PRODUCTION_BLOCKED`). | Medium. One lens calls it a defect, the other a documented policy residual; the facts are agreed. | #381 |
| `approve(addr, 0)` on a contract without authenticated ERC-20 metadata renders "Revoke approval". ERC-721 `approve(to, tokenId)` shares the selector, so on an NFT contract this grants token 0. | `secure/src/tx/display/erc20_unknown.rs:90-97`; `secure/src/tx/display/erc20_screens.rs:45,193-194`; `pqsigner-erc7730/src/display/primitives.rs:1236-1238` | Yes by code path. Not exercised on device or in a host test. | Low-medium. The screen still shows "! Unknown token". | Untracked (#343 adjacent) |

### Recommendations

| ID | Recommendation | Kind | Cost | Priority | Novelty | Tracked issues |
|---|---|---|---|---|---|---|
| CS-01 | Fence RAW32 behind a default-off, production-forbidden feature | firmware | S | P1 | parity | #338 #381 #692 #700 |
| CS-02 | Shared custody-change danger class; same-(Safe, nonce) re-sign detection | firmware | M | P2 | beyond | #329 #377 #474 #600 #603 #700 #714 #762 #770 |
| CS-03 | Secure-world spending-policy guard on every release route | mixed | L | P2 | parity | #280 #343 #474 #636 #758 |
| CS-05 | Structural EIP-712 tier with omission filter, design-first | firmware | L | P2 | parity | #329 #374 #381 #493 #494 #534 #602 #693 |
| CS-04 | Paymaster semantics; refuse non-empty paymaster in production meanwhile | firmware | L | P3 | beyond | #324 #328 #337 #353 |
| CS-07 | Fix the revoke mislabel; native `setApprovalForAll` and allowance decoders | firmware | M | P3 | parity | #78 #329 #343 #403 #409 #410 #411 #420 #425 #474 |
| CS-09 | Secure-world "THIS WALLET" self-tag; pixel-UI address chunking | firmware | M | P3 | parity | #348 #349 #366 #472 #603 |
| CS-10 | C10-signed catalogue refresh as one atomic versioned unit | mixed | XL | P3 | parity | #224 #225 #329 #345 #377 #379 #403 #486 #535 #540 |

**CS-01 (P1, proposed P0).**
- Threat. A hostile companion submits the hash of a Permit, SafeTx or CoW order as RAW32. Permit-class signatures were 3 of the 11 drains over $1M in 2025 ([Scam Sniffer](https://drops.scamsniffer.io/scam-sniffer-2025-crypto-phishing-losses-fall-83-to-84-million/)).
- What to do. Add an `offchain-raw32` feature, default off, in `PROD_FORBIDDEN`, with a `mode-production` fence modelled on forced-blind (`secure/src/nsc/mod.rs:271-285`). Gate kind 0 before any UI so the render code is dead-stripped. Put the kind-admission decision in a workspace crate so the feature-off test executes; `secure/src/nsc` is excluded from host tests. This selects the "disable" branch of #381 and needs the owner's sign-off.
- Dropped parts and why. The fresh-PIN, session-cap and counter ceremony: it is friction, not semantics; one signature suffices for a drain; the hostile companion reports the counter; fresh PIN inherits the #692 attempt-burn class.
- Evidence pq1 lacks it. See the defects table. The reviewer did not trace the absent-descriptor path of the remaining kinds line by line.
- Precedent. Trezor core has no blind typed-hash path. Ledger requires blind signing disabled by default ([requirements](https://developers.ledger.com/docs/device-app/develop/requirements/security)); not independently checked.
- Residual. On-chain loud blind tiers remain. Typed data without a pinned descriptor becomes unsignable.
- Not yet tracked. The mechanism, e2e wiring, and the phishing UX tests #381 requires for the acceptance branch.

**CS-02 (P2, proposed P1; cost S corrected to M).**
- Threat. The Radiant and Bybit pattern: custody changes resemble routine pages and attackers harvest signatures with "retry" prompts ([NCC Group](https://www.nccgroup.com/research/in-depth-technical-analysis-of-the-bybit-hack/), [Hacken](https://hacken.io/insights/radiant-hack-review/)).
- What to do. (a) One `Danger` classification for both painters using the existing orange pulse. Close the real gaps: owner add, remove, swap, `changeThreshold` and `disableModule` have plain heads, and a Safe-wrapped unlimited approve renders with `pulse=false` (`secure/src/tx/display/safe_screens.rs:503`) while the direct path pulses. (b) Extend #600 with a non-secret SRAM ring of `(safe, nonce, safeTxHash)` that survives lock, clears on power loss and records at release.
- Dropped parts and why. UserOp `(sender, nonce)` warnings: same-nonce re-signs are routine fee bumps and would habituate users. The premise that "! MULTISIG OFF" is the only banner is false (`secure/src/tx/display/safe_mgmt.rs`).
- Precedent. Trezor's danger screen covers unknown contracts only. No vendor ships nonce re-sign detection.
- Residual. A malicious-first request signs cleanly. Replug clears the ring. An interstitial with the same next-press gesture is a salience cue only.
- Not yet tracked. The shared class, the Safe-route cue inconsistency, the nonce-keyed ring.

**CS-03 (P2, proposed P1; cost M corrected to L).** The lenses split on kind; the item map records mixed.
- Threat. A compromised companion or hurried user. It delays a coercer but does not defeat one who extracts the Policy PIN or the seed words.
- What to do. A per-edit policy record with recipient and chain allowlists, per-operation caps, forbid toggles and a lockdown bit, evaluated on the decoded representation the renderer shows, on every route including batch and all off-chain kinds. With a policy active, blind tiers hard-refuse. Use a count quota on the page-123 tally. The Policy PIN must be enforced in secure-element silicon, following the duress-PIN pattern.
- Dropped parts and why. Wall-clock velocity: pq1 has no battery and `timeout::now()` counts from boot (`secure/src/timeout.rs:29,253`); an on-chain time bound would change the initCode hash and break invariant #6. An MCU-only Policy PIN violates "no software PIN compare".
- Precedent. Coldcard SSSP.
- Residual. Caps fall to splitting without the quota. A downgrade to a pre-policy signed image removes the guard, because no rollback floor is live (`cmd_fw_commit.rs:5-16`).
- Not yet tracked. The entire mechanism.

**CS-05 (P2, proposed P1; cost M corrected to L).** The lenses split on kind; the item map records firmware.
- Threat. With RAW32 off, long-tail typed data is unsignable. The reviewer is explicit that the walker is a usability feature with a new phishing tier, not a defence.
- What to do. File a design-first issue for the owner decision "curated-only versus structure-only tier". If approved: a new off-chain kind carrying the domain preimage, type string and member witnesses; a typeHash-only deny set for wildcard-contract shapes (Permit, Permit2, SafeTx, SafeMessage, GPv2Order, Seaport) consulted before the walker; an exact-set omission filter keyed on `(chain_id, domain_separator)`.
- Dropped parts and why. The proposal is unbuildable as written: kinds 2 and 3 carry only hashes (`secure/src/nsc/cmd_sign_offchain.rs:468-472`). The Bloom twin alone has no security effect today.
- Precedent. Trezor's walker is skippable; render-every-leaf is stricter.
- Residual. Attacker-chosen field names and undecoded amounts. A route around the Safe DELEGATECALL rule was flagged as an unconfirmed lead.
- Not yet tracked. All of it.

**CS-04 (P3, proposed P1).** One lens says P2 and mixed, the other P3 and firmware; the item map records P3, firmware, L.
- Threat. The device signs `sha256(paymasterAndData)` without seeing the bytes. Exploitation needs an existing or co-signed token allowance to the hostile paymaster.
- What to do. Now, at cost S: hard-refuse a non-empty paymaster hash in `mode-production`, because the 2026-06-27/28 owner decision is that pq1 ships no paymaster-using companion (`secure/src/tx/display/value_page.rs:465-470`). If that reverses: append raw bytes as a trailer, hash in the secure world, show the paymaster address with a Merkle-verified name, flag `approve(spender == paymaster)`.
- Dropped parts and why. "A hole the docs do not state" is false (`docs/security/security-review-2026-05.md:367-368`, `docs/security/red-teaming.md:750-758`). A pinned "max cost" is only as true as the firmware's copy of the debit formula.
- Precedent. None shipped.
- Residual. The approve cross-check misses Permit2, `increaseAllowance`, nested and earlier allowances.
- Not yet tracked. Review finding H-6, the production refusal, and the doc fix at `docs/companion/companion-batch-sign-integration.md:297`.

**CS-07 (P3, proposed P2; cost S corrected to M).**
- Threat. Approval-class calls outside the catalogue fall to the typed-call "GUESS:" tier or loud blind.
- What to do. First fix the live defect: restrict revoke wording to Merkle-authenticated ERC-20 metadata. After #343 is decided, add `setApprovalForAll(address,bool)`, `increaseAllowance` and `decreaseAllowance` under the unknown-contract banner, below the known-call refusal gate.
- Dropped parts and why. Revoke framing, spender naming, the unlimited label and native-value surfacing already ship (#474; `secure/src/tx/display/dispatch.rs:691-726`). On-chain `permit()` defends nothing: the wallet has no ECDSA key and cannot be a permit owner.
- Precedent. Trezor covers approve only (`core/src/apps/ethereum/clear_signing.py:1411-1482`); the new selectors exceed it despite the parity label.
- Residual. Selector-only identification on unauthenticated contracts.
- Not yet tracked. The mislabel and both decoders.

**CS-09 (P3, proposed P2; cost S corrected to M).**
- Threat. A user who expects a destination to be their own account cannot confirm that on-device. This does not address address-poisoning in general.
- What to do. Always tag the current account on fund-destination fields, never the call target. Tag siblings only from a companion `account_index` hint verified by recompute. Chunk addresses on the pixel UI only, and rewrite `check_words_unbroken` (`pqsigner-ui-px/src/check.rs:122-151`), which would otherwise go vacuous.
- Dropped parts and why. EIP-55 already ships (`pqsigner-erc7730/src/display/primitives.rs:375`); the lenses cite different landing dates. A DHUK-keyed address MAC is unsound: DHUK is per-die and survives re-seed, so a previous seed's tags would still validate.
- Precedent. Trezor chunking and seed-derived MAC.
- Residual. Sibling keygen time is UNMEASURED on pq1.
- Not yet tracked. The self-tag; chunking beyond #366 td-1.

**CS-10 (P3, proposed P2; cost L corrected to XL).** One lens kept P2; the item map records P3.
- Threat. Catalogue freshness equals firmware cadence. Under the fail-closed policy a stale catalogue is inconvenient, not unsafe.
- What to do. Treat this as the deferred PQDESC_V1 channel (`docs/erc7730-root-rotation-and-update-policy.md:103-122`) and amend that document. Version root, leaf count, Bloom, refused-known set and provenance class as one unit. Start with additive-only ERC-20 and names roots. Enforce provenance at runtime, show the installed version on a trusted screen, and use a two-copy commit.
- Dropped parts and why. A separate catalogue key contradicts the decision record ("never introduce a second signer"). A flash-page floor is erasable; the record requires a one-time-programmable (OTP) anchor. No free flash page exists (`geometry/src/lib.rs:121-138`).
- Precedent. Mislabelled as parity: Trezor is stateless and persists nothing.
- Residual. The catalogue signer gains clear-to-blind downgrade authority that today needs a reviewed firmware release. A stored root is outside the boot fingerprint (invariant #10). Blocked behind #377.
- Not yet tracked. No issue covers the channel.

### Covered in other sections

- M19, make existing assurance execute and block in CI (includes CS-08, the attack-vector regression corpus): P1, section 11.

### Considered and rejected

- **CS-06, on-chain intent commitment (proposed P1; cost XL).** One lens kept it as a P2 design spike, the other refuted it; the item map records "drop". The contract would recompute the digest from the calldata the firmware built, so the check proves "digest matches calldata", not "the device showed X". It gives no defence against a compromised image, a renderer bug or a skipped confirm, and Safe, CoW and ERC-7730 routes all commit as `BLIND‖calldataDigest`. The wallet has no upgrade path and the implementation address is inside the CREATE2 init-code hash, so the change means a new wallet address on every chain. Salvage: a Kani harness for rendered-versus-signed operands.
- **Constraining facts from parts dropped inside items:** no trusted time on pq1; PIN compare only in secure-element silicon; DHUK survives re-seed; the wallet cannot own an ECDSA permit; one signing key for catalogue and firmware.

### Open questions and unmeasured claims

- Owner decisions pending: RAW32 policy (#381); structure-only typed-data tier; native ERC-20 scope (#343); paymaster product scope; catalogue key reuse against the signature cap (#225).
- UNMEASURED: sibling keygen time on pq1; pixel-UI frame time in the shipping configuration (#781); worst-case secure stack for the renderers (#374).
- Not verified: the Ledger "disabled by default" requirement; whether a walker could bypass the Safe DELEGATECALL rule.
- Trezor-derived checks not yet confirmed in pq1: non-zero ABI padding rejection, trailing-calldata refusal outside multiSend, and no gateway call serviced while a confirm dialog is pending (the LSB-023 class).

---

## 6. Measured boot, RDP-2, option bytes and the verify-before-first-power chain

Abbreviations: RDP = readout protection, WRP = write protection, FSBL = first-stage bootloader, HDP = hide protection (flash that code can close until reset by setting ACCDIS), BOR = brown-out reset, SWD = serial wire debug, DHUK and BHK = the STM32U5 hardware unique key and boot hardware key, SE = secure element, FI = fault injection.

### What pq1 does today

Evidence level for this whole subsection: confirmed by code reading, not on silicon, unless stated. No unit has ever been at RDP-2 and WRP is set on no board. Invariant #10 is not claimable today.

**Implemented (bench only).**
- The FSBL verifies both slots through a full manifest chain (structure, CRC, digest, vendor fingerprint, SPHINCS+C10 signature, rollback floor), each verdict behind an FI sentinel (`fsbl/src/main.rs:255-290`, `fw-manifest/src/lib.rs:450-569`). It re-hashes both images from flash through a double-evaluated gate (`fsbl/src/verify.rs:38-110`).
- It renders the 8-word fingerprint before branching and halts if any SPI transfer or the backlight enable fails read-back (`fsbl/src/main.rs:198-223`). The verdict proves no observable step failed, not that the user saw words; the backlight receipt came from a board with no LCD. The 4 s hold and ~6.93 s total boot are EXPECTED; only 2.930 s of work is measured.
- tz-1, a read-only option-byte tripwire, runs before every branch and halts on a persistent two-pass mismatch (`fsbl/src/optbytes.rs:66-85`). It covers TZEN, RDP, the secure watermarks, SECBOOTADD0 and SWAP_BANK only.
- A host-tested comparator library covers the full profile (`shared/src/lockdown.rs:28-97`).

**Partial or fenced off.**
- The crate cannot build a shipping FSBL: `mode-production` is a `compile_error!` (`fsbl/src/main.rs:73-80`).
- First-boot Phase A (verify ship profile, blank-check pages 123..127, both-buttons confirm, burn RDP-2) and Phase B (journalled BHK write and SE credential rotation) exist only under `rdp2-self-lock`, which needs `mode-production`, which `secure/build.rs:37-40` panics on. Host-tested only.
- The RDP-2 burn routine is inert. It writes OPTSTRT and OBL_LAUNCH to a register that implements neither and returns `Ok(())` (`secure/src/hw/flash.rs:384-397`, #268). It is deliberately unfixed pending an owner decision.
- The pin switches are off: `WRP1A_MASK_PINNED=false`, `OEM_LOCK_MASK_PINNED=false`, `require_boot_lock=false`. Every genuine first boot would therefore halt at E0809 before any burn. The gate fails closed.
- The secure-world fingerprint row is compiled out of `mode-production` (owner decision 2026-09-28, `secure/src/main.rs:256-276`). A shipping image has one row and no two-row divergence signal.
- No software fence stops the runtime flash API from writing FSBL pages 0..4 (`secure/src/flash_policy.rs:32-49`). That rule rests on WRP alone.
- The external verifier checks only the bench profile; the ship profile is a template with PENDING fields (`tools/verify_ship_state.py:1-177`).

**Docs that claim more than the code shows.**
- CLAUDE.md invariant #10 says the geometry registry is "CI-pinned". No workflow runs those tests (#720, #721).
- `docs/firmware/reproducible-builds.md:241` says CI runs `verify-repro` on every PR. No workflow does.
- `docs/security/HARDENING.md:178-189` describes boot-time SE attestation in the present tense. No such code exists.
- `docs/provisioning/first-boot-provisioning.md:48` tells the factory to protect pages 0-3; the verifier requires 0..=4.

**Where pq1 is ahead.** Three points, all by design, none by shipped unit. Neither Trezor nor Ledger offers a verify-before-first-power step; Trezor ships blank and relies on seals ([Trezor](https://trezor.io/support/troubleshooting/device-issues/is-my-device-safe-to-use)). Trezor shows no boot-time fingerprint for official firmware. pq1's post-quantum verification covers the whole chain with one primitive; Trezor's covers only boardloader to bootloader and is hybrid. Ledger publishes no MCU option-byte posture.

### What Trezor, Ledger and others do that pq1 does not

- **Full option-byte compare every boot, with repair and erase.** Trezor's boardloader compares live OPTR, SECBOOTADD0R, WRP and SECWM registers to constants, rewrites them on mismatch, then regenerates the BHK (`core/embed/sec/option_bytes/stm32u5/option_bytes.c:124-170`, `core/embed/projects/boardloader/main.c:325-340`). pq1 compares a subset and halts.
- **OEM key lockout.** Trezor writes all four OEM key registers to 0xFFFFFFFF and asserts the lock bits are clear (`option_bytes.c:213-222`, `:247-250`), repeated in the kernel (`core/embed/projects/kernel/main.c:180-181`). pq1's equivalent check is unpinned and points at the wrong bits.
- **BOOT_LOCK in the pinned SECBOOTADD0 value** (`option_bytes.c:86-87`) and **HDP over a secret sector**, closed before handoff (`option_bytes.c:66-95`, `core/embed/sec/secret/stm32u5/secret.c:598-651`). pq1 has neither.
- **Padding check to the end of the image area** (`core/embed/sec/image/image.c:469-500`). pq1 hashes declared lengths only.
- **TRNG-driven delays in the immutable stage** (`core/embed/projects/boardloader/main.c:111-129`). The pq1 FSBL has no TRNG (section 3).
- **Challenge-keyed whole-area firmware hash and a per-device MCU attestation key** (`core/embed/sec/fwutils/fwutils.c:45-105`, `core/embed/sec/mcu_attestation/mcu_attestation.c:63-97`). See section 1.
- **Krux** hashes the full flash region and fills free blocks ([Krux](https://selfcustody.github.io/krux/getting-started/features/tamper-detection/)). **Ledger** added an SE-driven whole-MCU integrity check at each boot after LSB-013 ([Ledger](https://donjon.ledger.com/lsb/013/)).

What Trezor does not do, as recorded: it does not seal secrets to a firmware measurement (gating is by signature class, `fw_check.c:233-241`); its secure monitor does not re-verify the kernel; its boardloader does not run the full random-delay module; and its power-on-only reset rule `reset_flags_check` (`core/embed/sys/startup/stm32u5/reset_flags.c:26-38`) has zero callers. The Trezor data file lists that gate as called at `boardloader/main.c:323`; a grep run for this section shows that line calls `reset_flags_reset` only.

Literature that bounds every on-device check: one glitch during option-byte load downgraded RDP-2 to RDP-1 on STM32F373 ([Bozzato et al.](https://tches.iacr.org/index.php/TCHES/article/download/7390/6562/2561)); Keylabs reports the class across the family ([Keylabs](https://www.cypherock.com/keylabs.pdf)); Donjon used it on Trezor Safe 3 ([Trezor](https://trezor.io/vulnerability/donjon-s-trezor-safe-3-evaluation)). The data found no public equivalent on STM32U5.

### Live defects confirmed on this surface

| Defect | Evidence | Reachable in the shipping feature set? | Severity | Tracked |
|---|---|---|---|---|
| OEM1LOCK and OEM2LOCK masks sit on reserved bits 26/27 of FLASH_NSSR; the real bits are 18/19. Flipping the pin flag without fixing them would let a planted regression key pass vacuously. | `shared/src/lockdown.rs:279-280` against `STM32U585.svd:6409-6420` | No. The gate fails closed while `OEM_LOCK_MASK_PINNED=false`. | Latent-high if pinned wrong; none today | Untracked (#46 covers pinning, not this fact) |
| The secure-world SECBOOTADD0 mismatch branch contains only `secure_log!`, which is a no-op without `debug-log`. | `secure/src/main.rs:1276-1290`, `:62-64` | Compiled in by cfg reading; not link-verified because the production image is unbuildable. | Merger: low-medium. Skeptic: low, because SECBOOTADD0 is frozen at RDP-2 and Phase A halts pre-lock. | Untracked |
| After lock, nothing checks WRP, OEM locks, BOOT_LOCK or BOR level. | `fsbl/src/optbytes.rs:24-30`, `secure/src/first_boot/mod.rs:174-176` | Yes, once any unit is locked. | Merger: medium. Skeptic: low; the fields are immutable at RDP-2, so the gap is only a fault-skipped Phase A. | #46, #270 |
| "No measurement-bound secrets, in any form" rests on a premise that HDP breaks. The sentence is literally true; the "in any form" reasoning is not. | `docs/security/vendor-signing-key-compromise.md:459-462` | n/a (documentation) | Low | #486 |
| #39 does not say where the code that runs after the ACCDIS write lives, and calls the FSBL contents "code+secrets" although the FSBL holds no secret. | #39 body; `geometry/src/lib.rs:123-125` | Not in code. Live when #39 is implemented. | Merger: medium. Skeptic: low to medium, a spec gap. | #39 |
| Three records disagree on HDP: "chosen deliberately 0" in a rejected draft, open ship-blockers that require it, and "deferred". | `draft-v2.md:72`; #39, #43; `docs/security/production-security.md:521-528` | n/a (decision record) | Low | #752 |

Refuted, so not listed: the claim that all RDP verdicts are silent in production. The post-lock RDP regression halts (`secure/src/main.rs:1251-1259`).

### Recommendations

| ID | Recommendation | Kind | Cost | Priority | Novelty | Tracked issues |
|---|---|---|---|---|---|---|
| M02 | Fix the OEM-lock bits, publish the SWD checklist and factory record, pin the option-byte masks on silicon, then widen the FSBL compare and add a slot-tail check before the geometry freeze. Halt, never wipe. | mixed | M | P1 | parity | #35, #37, #38, #39, #42, #43, #44, #45, #46, #82, #141, #192, #193, #214, #248, #268, #270, #366, #387, #400, #540, #595, #695, #707, #712, #753, #835 |

**M02. Option-byte posture.**

*Threat.* A transit or factory attacker with an RDP-0 unit plants an OEM2 regression key, clears WRP on the FSBL pages, leaves BOOT_LOCK clear, lowers the BOR level, or stages a payload in an unmeasured slot tail. The first-boot lock then freezes that state.

*What to do.* The skeptic reordered the merged package; the item map keeps P1 and cost M overall.
1. P1, no silicon needed: correct the masks to bits 18/19 with a host test bound to the SVD values.
2. P1, docs and tooling: add FLASH_NSSR bits 18/19, WRP1AR/WRP2AR, BOOT_LOCK and BOR level to `docs/security/user-device-verification.md` and to the per-unit factory record (#595). The skeptic calls this the load-bearing control, because every on-device check runs in flash the same attacker can rewrite.
3. P1, silicon ceremony with #45/#268: provision an OEM2 key (not only OEM1) and confirm the predicate trips; confirm that writing all four 64-bit key registers to 0xFFFFFFFF and reloading option bytes clears the lock; pin WRP, BOOT_LOCK and BOR level; then flip the pin flags. Flip `require_boot_lock` after #753 fixes the factory order.
4. P2, before #540: move tz-1 to the full profile and require `[len, capacity)` of the selected slot to read 0xFF. This needs a ship/bench profile split, or every bench board halts.
5. P3: gate a SECBOOTADD0 halt on RDP-2 with a visible code; resolve #192; add a host test that fails on any production verdict whose only effect is `secure_log!`.

*Dropped parts and why.* See "Considered and rejected".

*Evidence pq1 lacks it.* `shared/src/lockdown.rs:258-292`, `:334-356`, `:445`; `fsbl/src/verify.rs:38-65`.

*Precedent.* Trezor, as cited above. The log-only-verdict test has no vendor precedent.

*Hardware asks.* One sacrificial STM32U585CIU6, shared with #45. A factory line step for the OEM key clear and per-unit register record. No board change.

*Residual after it lands.* A glitch at option-byte load still opens debug before any instruction runs. An OEM2 key holder regresses RDP under reset, so no post-lock firmware check stops that attack; only the Phase A gate and the user's SWD read do. Halt leaves a weakened stolen unit intact for repeated attempts, bounded by the SE counters. The inactive slot and manifest pages stay unmeasured.

*Not yet tracked.* The 26/27 fact and the stale `lockdown.rs` comment that SECBOOTADD0 is mutable at RDP-2 (RM0456 Rev 7 §7.6.2 freezes it); the silent SECBOOTADD0 verdict and its test; the FSBL slot-tail check; the ship/bench split for #270; the checklist lines; the OEM2 positive test and two-register clear. The exact OPTR compare is #141, closed while `shared/src/lockdown.rs:373-379` is still a partial mask: reopen it.

### Covered in other sections

- M05, FSBL pre-freeze FI bundle (fail-closed polarity, TRNG for delays, tail scan, #591 sweep): P1, section 3.
- M07, one FSBL freeze-review package (vendor-key policy, minimum epoch, Merkle-leaf signing): P2, section 9.
- M08, erased-tail check on the selected slot, optional wider fingerprint: P3, section 9.
- M09, verify-before-first-power tool plus host-verified birth record: P0, section 1.
- M10, display and button-net RC-decay self-check against a factory baseline: P3, section 1.
- M17, per-boot refuse-only SE configuration audit: P2, section 7.

### Considered and rejected

**M01, measurement-bound secret release (status rejected; five member proposals).**
- Any seal of the form CMAC under DHUK over the image hash is forgeable. DHUK has no per-stage lock on the U5, any secure image can select it (`secure/src/hw/secret_keys.rs:176-200`), and the hash is public. Computing it in the FSBL and passing it through a mailbox changes nothing.
- A sound variant needs an FSBL-only secret behind HDP and a directional transfer key for updates. It was not built. Staging a secure slot requires the PIN (`secure/src/nsc/cmd_fw_chunk.rs:39`), so the gain is narrow: a non-genuine image could not turn a known PIN into both entropy halves. Against that sit a frozen-registry change, irreversible option bytes, an unpatchable FSBL, a single-fault provisioning step and a new update brick class on top of #712/#707.
- Geometry facts that constrain any future design: HDP1 must start at page 0; pages 5 and 6 are runtime-written manifests. The merger said the secret page must be page 5. The skeptic corrected this: page 4 could serve, still with a registry change. The shipping FSBL has no TRNG and no flash-program path (the bench `stage-marker` feature has one).
- Per-update SE credential re-provisioning lands in the irreversible OPTIGA lifecycle class. A third XOR share rewrites seed material on every update.
- Hiding pages 126/127 with HDP is infeasible in place, and any secure code can still use the BHK through the AES engine.
- What survives is S-cost process work: comments on #39 (exit-stub location, no secret in the FSBL, what hiding public code buys), a reasoning fix in `vendor-signing-key-compromise.md`, an owner ratification of one HDP posture, and a note that #591's "bare `!=`" text is stale.
- Tillitis TKey ships a measured key derivation, with no persistent storage and so no update migration ([Tillitis](https://dev.tillitis.se/intro/)). No vendor found does it with persistent state and updates.

**Parts dropped inside M02.**
- Wipe or BHK erase on mismatch: against the owner decision of 2026-07-23 and the June 2026 critical-port adjudication, and it is an FI brick lever. In the FSBL it is a no-op, because the FSBL cannot write flash.
- Phase A writing the OEM keys: the only permitted on-device option-byte write is the RDP burn. Moved to the factory.
- FSBL refusing to branch on reset flags: the legitimate first-boot reload sets OBLRSTF, and a glitched load sets no flag.
- Reset cause as an input to the RDP burn (kept by the merger, dropped by the skeptic): a voltage glitch presents as BOR, which is classified Cold and allowed (`secure/src/reset_cause.rs:182-184`), and a pin-only reset after the documented SWD check would be refused.
- Tail check at firmware commit (kept by the merger, dropped by the skeptic): commit refuses fail-closed today and the slot is erased whole at begin.
- Secure-world every-boot re-check (merger kept; skeptic: optional P3): the fields are immutable at RDP-2. Trezor repeats it because Trezor repairs option bytes.
- Fatal die-identity check: an attacker who controls the part can present any ID code.
- Krux-style random fill and a wider measured hash range: incompatible with a vendor-signed hash, identical words across units, and the deliberate FSBL and secure-world range identity.

### Open questions and unmeasured claims

- Whether an RDP-2 to RDP-1 glitch works on STM32U585: UNMEASURED; no public result found (#401).
- Whether 0xFFFFFFFF clears a planted OEM lock at RDP-0: read from RM0456 Rev 7, not confirmed on silicon.
- Whether SWD is dead under reset at RDP-2 when no OEM2 key exists, which would give users an external post-lock observable: an untested lead from the skeptic.
- ACCDIS semantics (does it deny instruction fetch) and HDP1EN polarity: not confirmed on silicon (#214).
- The DHUK value across the RDP-1 to RDP-2 transition: UNMEASURED.
- FSBL growth for the full compare and the tail-compare time (about 0.1 s): estimates, UNMEASURED.
- Whether the user can see the FSBL fingerprint on a sealed pq1: #705 is open. The inventory reads it as possibly addressed; the skeptic treats the fingerprint as not visible. Until it closes, a pre-sale implant is caught only by the RDP-0 SWD check.
- The production feature set cannot be linked, so every reachability entry above is a cfg reading. The independent-model cross-check of M01 did not run.

---

## 7. Secure-element usage

Evidence level throughout, unless a line says otherwise: confirmed by code reading, not on silicon. A `mode-production` + `optiga-trust-m` image does not compile today (`secure/src/nsc/mod.rs:313-321`), so "reachable" below means present under `PROD_SHIP_FEATURES` (`Makefile:2718`) once it links, and running in bench dual-SE images now.

### What pq1 does today

**Implemented.** The seed entropy is XOR-split across an Infineon OPTIGA Trust M V3 and an NXP SE050 (`secure/src/dual_se.rs:145-227`), validated on silicon. Both tunnels are mandatory on secret paths: OPTIGA Shielded Connection (`secure/src/optiga/shield.rs:679-760`) and SE050 SCP03 (Secure Channel Protocol 03) with response protection (`secure/src/se050/scp03.rs:324-335`), on per-device keys with no runtime fallback to published keys (`secure/src/se050/scp03.rs:190-224`). PIN attempts are charged three ways: MCU flash page 124 before either chip is called (`secure/src/nsc/mod.rs:1394-1490`), the OPTIGA E120 counter, and the SE050 UserID. Rotation probes separate "bus fault" from "chip refused" (`secure/src/se050/mod.rs:431-452`).

**Partial.** Boot reconciliation compares page 124 with E120 only; SE050 attempt reads are policy-denied (`secure/src/se050/mod.rs:891-926`), and the cold-reboot receipt is open (#200). OPTIGA secret objects are readable after a PIN verify without the tunnel at the access-condition level (#116).

**Fenced off or bench-only.** The first-boot flow (RDP-2 self-lock, then transport-to-final rotation of SCP03, admin PIN and OPTIGA pairing secret) exists (`secure/src/first_boot/mod.rs:188-277`, `:296-441`) but is in no flashable image. OPTIGA lifecycle lockdown (ship-blockers S-1/S-2/S-3) is deliberately unwired (`secure/src/optiga/mod.rs:2031-2063`). In every buildable image the pairing secret is the unsalted DHUK (device hardware unique key) derivation (`secure/src/hw/secret_keys.rs:484-507`).

**Docs claim, code does not show.** `docs/security/threat-model.md:233` claims a freshness nonce on both tunnels; the OPTIGA handshake has none (`secure/src/optiga/shield.rs:698-700`). CLAUDE.md calls E120 a "32-lifetime-attempt" backstop; code resets it after every correct PIN (`secure/src/optiga/mod.rs:1621-1628`). CLAUDE.md gives the SE050 object range as `0x7B0C_*`; code uses `0x7B10_xxxx` (`secure/src/se050/mod.rs:23-62`). More drift is in the defect table.

**Where pq1 is ahead.** Two secure elements from two vendors each hold a share, which is what Ledger Donjon recommends after its DS28C36 laser attack ("splitting secrets into shares between different circuits", [FDTC 2023](https://fdtc.deib.polimi.it/FDTC23/slides/FDTC2023-slides-3-3.pdf)). A failed OPTIGA tunnel is a hard refusal on pq1; Trezor resets the chip and continues unpaired (`core/embed/sec/optiga/optiga_init.c:47-64`). The candidate flow rotates tunnel credentials per device; Trezor never rotates its pairing secret. The M16 defects show the split's real floor is lower than documented.

### What Trezor, Ledger and others do that pq1 does not

- **One-way transform before the bus, plus an MCU floor.** Trezor sends only `HMAC(stretched_pin, "")` to the OPTIGA and keeps MCU stretching with a hardware and storage salt so a compromised SE cannot lower security below the MCU-only design (`storage/storage.c:628-678`, `core/embed/sec/optiga/optiga.c:972-979`, `docs/core/misc/optiga.md:58-66`). pq1 sends the raw PIN to the SE050.
- **Lifetime operation cap.** `PIN_TOTAL_CTR` at 600,000 with Change=Never gates the stretching keys (`core/embed/sec/optiga/optiga.c:482-522`).
- **Metadata write, read back, compare, and a lock audit** (`core/embed/sec/optiga/optiga.c:311-353`, `core/embed/projects/prodtest/cmd/prodtest_optiga.c:252-304`).
- **Handshake first, write the pairing secret only on failure, handshake again** (`core/embed/projects/prodtest/cmd/prodtest_optiga.c:109-162`).
- **Host-verified attestation** per chip (`core/src/apps/management/authenticate_device.py:9-79`). Ledger's Genuine Check is the same shape and, by Ledger's own statement, cannot detect implants ([Donjon threat model](https://donjon.ledger.com/threat-model/device-genuineness/)).
- **Security Event Counter (E0C5) handling** (`core/embed/sec/optiga/optiga_init.c:101-139`).
- **Coldcard Mk4** needs the MCU and both SEs to decrypt the seed (vendor claim, [Coinkite](https://blog.coinkite.com/understanding-mk4-security-model/)).

Trezor explicitly does not: verify OPTIGA identity or metadata at boot, close the missing host nonce in the Shielded Connection (`core/embed/sec/optiga/optiga_transport.c:747-838`), rotate the pairing secret, or use any post-quantum element in either SE channel.

### Live defects confirmed on this surface

| Defect | Evidence | Reachable in the shipping feature set? | Severity | Tracked |
|---|---|---|---|---|
| SE050 user credential is the raw 8-digit PIN, stored and sent on every attempt | `secure/src/se050/apdu.rs:794-809`, `secure/src/se050/mod.rs:2938-2943` | Yes | Medium | Untracked |
| OPTIGA F1D0 secret is one unsalted SHA-256 of the PIN | `secure/src/optiga/mod.rs:916-918`, `domain/src/lib.rs:97-103` | Yes | Medium | #124 (partial) |
| One extracted SE yields the PIN, hence the wallet; docs say otherwise. Reasoned from code | `docs/security/threat-model.md:121`, `:222-226`, `:600` vs `secure/src/dual_se.rs:455` | Yes (design level) | Medium-high as claim drift; decap-class attacker | Untracked |
| HARDENING.md describes an AESKey, a credential stretched with PBKDF2, and a boot-time SE attestation, that do not exist | `docs/security/HARDENING.md:158-163`, `:258-270`, `:32`, `:176`, `:178-189` | Documentation | Low | Untracked |
| Boot resume resets page 124 even when the SE wipe failed | `secure/src/main.rs:1946-1951` | Yes | Low today, high once M16 P1 lands without P2 | Untracked |
| Forged bare `0x6986` on SE050 CreateSession triggers a dual-SE wipe on the next correct-PIN unlock over USB | `secure/src/se050/scp03.rs:614-634`, `secure/src/nsc/cmd_request_unlock.rs:159-163` | Yes | Medium to high (two reviewers differ); needs a bus interposer | #104, #105 |
| Recorded OPTIGA session replays; the MCU then re-encrypts under a reused key and nonce | `secure/src/optiga/shield.rs:698-701`, `:757-759` | Yes | Medium-high, no bench proof | #117 |
| SE050 provisioned probe fails open; with a forced OPTIGA "unprovisioned" reading the seed wizard runs on a used device | `secure/src/se050/mod.rs:1788-1796`, `secure/src/dual_se.rs:141-143`, `secure/src/optiga/mod.rs:981-983` | Yes | Medium-high | #111, #121, #169 |
| Final pairing secret can be written in plaintext before the wizard if the tunnel is forced down | `secure/src/optiga/mod.rs:603-618`, `secure/src/optiga/apdu.rs:523-533` | Only under `rdp2-self-lock` after rotation | Medium-high | #118, #126 |
| Provisioning writes a secret into an already-Operational object without comparing its metadata | `secure/src/optiga/mod.rs:1265-1287` | Yes | High per #87, owner-deferred | #87 |
| Silent plaintext fallback in `send_command` | `secure/src/optiga/apdu.rs:523-533` | Present; no ship-path secret read found reaching it | Low to medium | #126 (trigger stale) |
| `get_version_ext` goes on the wire without Le | `secure/src/se050/apdu.rs:944-950` | Not on a boot path | Medium, latent | #444 |

### Recommendations

| ID | Recommendation | Kind | Cost | Priority | Novelty | Tracked issues |
|---|---|---|---|---|---|---|
| M16 | Die-bind and salt the PIN credentials sent to both SEs; mask each half | firmware | L | P1 | parity | #5, #12, #124, #200, #202, #203, #247, #268, #400, #485, #540, #626, #637, #692, #707, #712, #743 |
| SE-03 | Stop a bare SE status word from driving a wipe (redesign needed) | firmware | M | P1 | parity | #7, #104, #105, #106, #120, #125, #126, #127, #168, #385, #692, #715 |
| SE-05 | Shielded-Connection liveness probe with a host challenge | firmware | M | P1 | beyond | #1, #4, #117, #123, #126, #145, #200, #307, #396 |
| SE-06 | Provisioning ordering guards and a fail-safe provisioned check | firmware | M | P1 | parity | #11, #36, #76, #87, #111, #118, #121, #123, #126, #169, #268, #276, #366, #385, #445, #712 |
| M17 | Per-boot refuse-only SE configuration audit; SE identity proven host-side | mixed | L | P2 | parity | #6, #14, #27, #61, #63, #67, #68, #76, #87, #116, #117, #120, #121, #126, #206, #207, #209, #210, #215, #244, #245, #249, #263, #268, #272, #444, #697 |
| SE-08 | Lifetime OPTIGA budget and Security Event Counter awareness (redesign needed) | mixed | M | P2 | parity | #116, #119, #170, #251, #254, #275, #443, #485 |
| M18 | User-supplied entropy hashed into the new-wallet seed | firmware | M | P3 | parity | #237, #238, #369, #370, #371, #400, #470, #594, #636, #641, #700, #704, #778, #779, #783, #784 |

**M16. Die-bound, salted PIN credentials.**
- Threat. A lab attacker who reads one SE's non-volatile memory recovers the PIN offline, emulates the destroyed chip with tunnel keys from the same dump, and unlocks.
- What to do. Replace both presentations with `SAES-CMAC(DHUK, label_per_SE || salt || PIN)`. Add a 32-byte per-provisioning salt erased first in every wipe entry point, and make the page-124 reset conditional on wipe success. Mask each half with a PIN-keyed DHUK value. Mint credentials only at RDP-2. Correct both docs.
- Dropped parts and why. The DHUK xor BHK fold (open BHK strand defects #707, #712). PBKDF2 stretching (under 15 bits against a die oracle, and a long software hash over the PIN). The non-PIN-keyed mask: the skeptic showed two emulators plus the unmodified die open the wallet. The DHUK known-answer gate moves to #692/#400.
- Evidence pq1 lacks it. Defect rows 1 to 5.
- Hardware asks. None.
- Precedent. Trezor `storage/storage.c:628-677`; Coldcard Mk4 (vendor claim).
- Disagreement. Merger cost M, skeptic L (about 40 call sites, not 14). Final: L, P1.
- Residual after it lands. A malicious secure-world image can still select DHUK. One extracted SE plus an emulator gets 10 guesses in total.
- Not yet tracked. All of it. Every bank-1 page is owned (`geometry/src/lib.rs:127-137`), so the salt needs a registry change (#540) or page-125 co-tenancy.

**SE-03. Unauthenticated wipe verdicts.**
- Threat. An interposer on the SE050 bus replaces one response with bare `69 86`. SCP03 never authenticates error status words.
- What to do. Make page 124 the only wipe authority. Map an SE-reported lockout to a non-wiping fault state, as the boot and PendSV arms already do (`secure/src/main.rs:4198-4205`), and offer the wipe only behind a trusted-UI confirmation. Keep the charge and extend the #715 verdictless cap to `CMD_REQUEST_UNLOCK`.
- Dropped parts and why. The confirmation probe is refuted: the interposer forwards the command, so both counters stay in sync, a later authenticated probe passes, and a genuinely locked card produces the identical transcript. "Do not charge page 124" needs a refund, which is a free PIN-probe oracle.
- Evidence pq1 lacks it. Defect row 6.
- Precedent. Weak. Trezor's Tropic retry list is transport-error retry only (`core/embed/sec/tropic/tropic.c:183-216`); the Ledger LSB-016 citation was not checked.
- Residual after it lands. Ten induced faults still exhaust page 124. An authenticated lockout verdict needs a different SE050 policy.
- Not yet tracked. A typed unauthenticated result, a durable cap, the fault state, an invariant #2 text update. Proposed P0; final P1.

**SE-05. Liveness probe.**
- Threat. Whole-session replay of a recorded OPTIGA session.
- What to do. After every handshake, before any counter-bound command, send 32 bytes from the MCU TRNG alone to OPTIGA CalcHash inside the tunnel and compare with a local SHA-256. Do not draw from `rng_strong` (it re-enters `ensure_shield`, `secure/src/rng_strong.rs:185`). A mismatch must be inconclusive, never `Shield`, or `rotate_pbs_to_salted` falls through to the E140 rewrite (`secure/src/optiga/mod.rs:700-707`).
- Dropped parts and why. "No page-124 charge" (precharge precedes SE traffic). #117's "fresh GetRandom" fix (a recorded response is accepted).
- Evidence pq1 lacks it. No CalcHash wrapper in `secure/src/optiga/apdu.rs:105-117`.
- Precedent. None; Trezor has the same gap.
- Residual after it lands. A pairing-secret holder and a live relay still pass.
- Not yet tracked. The mechanism, the ProVerif model update, a record-and-replay bench test, the `docs/security/threat-model.md:233` fix.

**SE-06. Ordering guards.**
- Threat and evidence pq1 lacks it. Defect rows 8 and 9.
- What to do. Skip the E140 write once the journal says Rotated. Make the SE050 probe tri-state. Add an MCU sentinel as the wizard discriminator, cleared before the SE wipe on every wipe path.
- Dropped parts and why. "Refuse provisioning once RDP-2 or rotation is done" would disable the field wizard, which runs after both. A three-leg AND that parks on disagreement strands a power cut between the two `provision` calls (`secure/src/dual_se.rs:203-217`) with no exit at RDP-2. Handshake-first does not stop an active interposer.
- Precedent. Trezor's factory sequence cited above; its write is itself plaintext, so "no plaintext rewrite" goes beyond Trezor.
- Residual after it lands. "Error means provisioned" sends a glitching SE050 to the unlock path, which burns page 124 (#692).
- Not yet tracked. The sentinel and its home (not an erasable record on page 127), and the uniform factory-entry guard.

**M17. Configuration audit and identity.**
- Threat. A chip with looser access conditions than designed, a substituted chip before first boot, an interposer.
- What to do. L0: allowlist the pre-tunnel commands and require SE-05 freshness before any verdict. L1: after rotation and tunnel load, compare OPTIGA metadata and the SE050 applet configuration against a pinned per-object allowlist; refuse and park on mismatch, never wipe or self-heal; add the provisioning-time check (#87). L2: a factory per-unit record with an OTP anchor, and a host verifier where each SE signs a nonce against its own vendor root.
- Dropped parts and why. On-device vendor-chain verification (invariant #5). A DHUK-derived C10 attestation key (see the rejected list). Wipe on mismatch (one forged frame becomes a wipe lever). First-boot self-pinning (it enshrines whichever chip is present). The page-127 table-version journal (no consumer).
- Evidence pq1 lacks it. No E0C2 or E0E0 read exists in `secure/src`.
- Precedent. Trezor per-boot Tropic configuration check (`core/embed/projects/secmon/main.c:136,139`, write-to-fix); the per-element binding rule comes from [Trezor's August 2026 fix](https://trezor.io/vulnerability/authenticity-proofs-not-bounded-to-their-secure-element). No vendor was found shipping a refuse-only OPTIGA/SE050 audit.
- Hardware asks. No board change. Confirm the production SE050 variant (#697) and a production certificate at OPTIGA E0E0 (#27). The factory OTP burn must include the identity anchor and record three identifiers per unit.
- Disagreement. Merger P1; skeptic P2, because the factory-owned rows do not exist until S-1/S-2/S-3 close and #87 carries an owner deferral. Final: P2.
- Residual after it lands. Malicious firmware on genuine chips passes. An attacker reading OTP before first boot derives the transport keys.
- Not yet tracked. The per-boot audit, an SE050 LockState reader, blank and reset table rows, a user-confirm gate on the relay, retargeting #210, #244, #245 and #249.

**SE-08. Lifetime budget.**
- Threat. A counter-reset bug makes the OPTIGA an unbounded PIN oracle. No code references E122 or E0C5.
- What to do. Put the counter on the guess path (`Luc(E120) AND Luc(E122)` on F1D0 Execute, or a chip-side stretching key), mirrored on the duress twin, inside the frozen S-3 profile. Split out the E0C5 read and throttle classification as a small firmware item.
- Dropped parts and why. The counter on the Read condition of the half: reads happen only after a successful verify (`secure/src/optiga/mod.rs:2582-2626`), so wrong guesses cost nothing. Keep-powered decay of the event counter: pq1 has no battery.
- Precedent. Trezor binds it via Execute, never Read (`core/embed/sec/optiga/optiga.c:504-522`).
- Residual after it lands. Change=Never is irreversible only at LcsO=Operational, which is an open ship-blocker.
- Not yet tracked. The attach-point decision; #485 points at closed #443.

**M18. User entropy.**
- Threat. A semantic bug in the seed-draw path that the existing gate (`scripts/rng_consumer_audit.py:17-20`) cannot see. The seed is one `rng_strong::fill` with no user term (`secure/src/main.rs:964-974`).
- What to do. On the new-wallet path only, collect coin flips as short presses and compute `SHA-256(tag || rng_strong_32 || len || user_bytes)` in a workspace crate with a known-answer test. Document "generate offline from dice, then Restore" as the zero-code auditable path.
- Dropped parts and why. Check words and the "first word changes" demo (a rigged image fakes both). Host-commitment randomizer (`docs/security/vendor-signing-key-compromise.md:666-676`: "do not fund"). Dice-only mode (removes `rng_strong`). Host entropy check (the wizard runs before USB exists, `secure/src/main.rs:4001` vs `:4233`).
- Precedent. Trezor hashes host entropy with internal entropy (`core/src/apps/management/reset_device/__init__.py:543-551`). The Coldcard incident was a software-fallback bug ([Block](https://engineering.block.xyz/blog/predictable-rng-fallback-and-32-bit-reseed-in-coldcard-firmware)), a class pq1 already fences.
- Disagreement. Merger P2 and S; skeptic P3 and M. Final: P3, M.
- Residual after it lands. No defence against malicious firmware.
- Not yet tracked. The design; record two separate decisions on #371.

### Covered in other sections

- M01, measurement-bound secret release (member SE-09): dropped, section 6.
- M14, wipe as a verified, resumable transaction with a designed recovery path (member SE-07): P1, section 8.

### Considered and rejected

No item written here is rejected outright. Facts that killed parts and constrain future designs:

- SCP03 never authenticates error status words, so no later command can authenticate a negative SE050 verdict.
- A counter in a Read access condition never counts wrong guesses.
- Any secure-world image can select DHUK, so a DHUK-derived key proves "some secure image on this die".
- The factory never runs at RDP-2, so it cannot certify a DHUK-derived key.
- OPTIGA access conditions are expression encodings, not bitmasks; compare against allowlisted encodings.
- The Infineon handshake has no host-nonce slot.
- No PIN-change flow exists in `secure/src`, `proto` or `shared`.
- Page 127 erased means `RotatedSaltMissing`, a pairing brick (`secure/src/first_boot/mod.rs:66-72`).

### Open questions and unmeasured claims

- UNMEASURED: CalcHash latency and availability on the V3 part; boot-time cost (estimated 100 to 300 ms) and flash cost (estimated 3 to 8 KB) of the M17 audit; single-trace leakage of SAES-CMAC with the PIN as message.
- Unconfirmed on silicon: a 16-byte user UserID at `max_attempts=10`; an all-zero reprogram of a programmed flash quad-word (page-125 salt option); two counters in one Execute expression; E0C2, E0E0 and E0F0 access at the shipping lifecycle state.
- No bench replay of #117 and no silicon demonstration of the forged-`0x6986` wipe exist.
- #104, #105, #120 and #126 are "candidate, pre-adjudication" issues; the cited triggers of #120 and #126 no longer match current code.
- Production SE050 variant, E2 or C2 (#697).
- Owner decisions needed: the M16 salt page, the SE-06 sentinel home, the #87 brick tradeoff, whether firmware may relay an SE-produced ECDSA attestation signature, and #371.

---

## 8. PIN, wipe and duress

Evidence level for this section: confirmed by code reading, not on silicon, unless a line says otherwise. The round-2 reviews of M12 and M14 ran without a second reviewer.

### What pq1 does today

**Implemented.**
- One choke point, `gated_unlock`, serves all three unlock arms: USB, boot prompt, and the idle re-unlock in the PendSV (deferred-service) handler. It charges MCU flash page 124 before any secure element (SE) call, with a double read, a sentinel gate and an exact +1 readback (`secure/src/nsc/mod.rs:1429-1495`). Its fault-injection (FI) jitter is about 0 to 19 µs and by its own comment defeats only uncalibrated single shots (`secure/src/nsc/mod.rs:1404-1413`).
- Each attempt is also consumed on OPTIGA (E120 counter, limit 32) and the SE050 UserID (limit 10) (`secure/src/dual_se.rs:356-378`). The PIN compare never runs in the MCU.
- PIN entry is a two-button, 8-digit secure-world dialog with a random start digit per position. The active digit is shown in clear, as the file states (`secure/src/ui/pin_entry.rs:25-31`).
- A page-125 wipe-in-progress flag is armed before destructive work and resumed at boot (`secure/src/main.rs:1903-1953`).

**Partial.**
- Boot reconciliation is directional (wipe when E120 used > page 124). The SE050 is not an input. No cold-reboot silicon receipt exists (#200).
- Tamper escalation is forced into shipping images but has never run on silicon (#391).
- Host tests are mostly source-text assertions. The 19-test lockout-wipe FI matrix is untracked in git and not compiled (`secure/src/main.rs:411-421`). No Kani harness covers the attempt counter.
- Button PIN entry has never run on pq1 silicon (#700).

**Fenced off.** The duress and decoy wallet (`duress-pin`) is complete and silicon-validated per #280, but absent from `PROD_SHIP_FEATURES` (`Makefile:2718`). A shipping image has no duress path (#636).

**Docs that code does not support.** `docs/security/threat-model.md:431` (progressive delay, "button entry without echo"), `docs/security/threat-model.md:432` (duress "not implemented"), `docs/security/HARDENING.md:258-275` (PIN collected in the non-secure world, PBKDF2 stretching; neither exists), `README.md:20` ("validated end-to-end on silicon"; the reboot legs have no receipt).

**Where pq1 is ahead.** The SE-silicon compare removes the firmware digit-compare side-channel class that [Ledger Donjon used against Trezor One](https://www.ledger.com/blog/Breaking-Trezor-One-with-SCA). With the XOR split, faulting one SE's PIN check releases only one half, which matters after the [TROPIC01](https://donjon.ledger.com/blog/tropic01-laser-fault-injection/) and [Tangem](https://donjon.ledger.com/blog/bypassing-tangem-card-security-with-laser-attack/) laser results. The non-secure world cannot reset the 120 s idle timer; Trezor's auto-lock is host-resettable. An independent-entropy decoy exceeds Trezor's offer only if it ships, and today it does not.

### What Trezor, Ledger and others do that pq1 does not

- **Trezor unlock path**: exponential back-off of 2^fails - 1 s, uncapped (`storage/storage.c:1158-1161`); an FI-hardened counter encoding on U5 flash (`storage/pinlogs_blockwise.h:8-73`); an inline wipe at `ctr + 1 >= PIN_MAX_TRIES` for every caller (`storage/storage.c:1223-1230`).
- **A resettable OPTIGA design**: "resettable under all circumstances", and any reset must first overwrite PIN_SECRET (`docs/core/misc/optiga.md:105-111`). Wipe erases the active sector first, then re-initialises (`storage/norcow.c:284-299`).
- **Fault handler burns an attempt**; a second fault during handling wipes (`storage/storage.c:1815-1848`). See M04.
- **PIN-derived key** (PBKDF2, 20000 iterations, then the secure AES peripheral under a die key, `storage/storage.c:628-680`) and a 600000-use lifetime OPTIGA counter. Partial fit: pq1 must not add a software compare; the counter analogue is #485.
- **Coldcard**: anti-phishing words after a PIN prefix, and Trick PINs ([PIN docs](https://coldcard.com/docs/pins/), [Mk4 security model](https://blog.coinkite.com/understanding-mk4-security-model/)). Foundation Passport ships "Security Words" ([docs](https://docs.foundation.xyz/passport/advanced)); mechanism unverified from code.
- **Ledger**: 3 attempts then wipe, keypad randomised ([Donjon PIN threat model](https://donjon.ledger.com/threat-model/os-pin-security-mechanism/)); "wipe verified at startup" in firmware 1.4 ([LSB-003](https://donjon.ledger.com/lsb/003/), member citation, not re-fetched).

Trezor explicitly does not ship a decoy PIN (deniability is left to passphrase wallets, `core/src/apps/evolu/get_node.py:50`), does not use its full guard-key counter on U5 because an SE counter is primary and flash has ECC, has no anti-phishing words (zero grep hits at 6ab39e95cf), and does not rate-limit host-raised unlock dialogs (`core/src/apps/common/lock_manager.py:261-268`).

### Live defects confirmed on this surface

"Ship set" means `PROD_SHIP_FEATURES`. It does not link today (S-2 fence, `secure/src/nsc/mod.rs:315`) and nothing has shipped.

| Defect | Evidence | Reachable in the shipping feature set? | Severity | Tracked |
|---|---|---|---|---|
| E120 is never reset after a lockout wipe, so every later boot sees E120 > page 124 and wipes again | `secure/src/optiga/mod.rs:2795-2801`, `secure/src/nsc/mod.rs:1661-1716` | Yes by code read; conditional on the OPTIGA shield being up at reconcile (#127 doubts it) | High, availability | #123 |
| Post-wipe provisioning refuses and panics because the SE050 USERID_OBJ survives | `secure/src/se050/mod.rs:1976-2001`, `secure/src/crypto.rs:472-496` | Yes | High, availability | #168 |
| F1D0 cannot be rewritten after a wipe on the locked profile, so OPTIGA provisioning fails at its first write | `secure/src/optiga/mod.rs:1123-1131`, `secure/src/optiga/mod.rs:2832-2840` | Yes | High, availability | No |
| Wipe verdict discarded; "WALLET WIPED" shown and page 124 reset unconditionally | `secure/src/nsc/cmd_request_unlock.rs:190-211`, `secure/src/main.rs:1946-1952` | Yes, feature-independent | Medium | #123 in part |
| SE050 wipe returns `Ok(())` when admin-PIN derivation fails, leaving user objects | `secure/src/se050/mod.rs:3193-3205` | Yes | Medium | No |
| `admin_exists()` is false on a transport error, clearing the resume flag when the SE050 is unreachable; the admin object self-deletes even when data deletes failed | `secure/src/se050/mod.rs:678-686`, `secure/src/se050/mod.rs:2329-2377` | Yes | Medium | #106 in part |
| SE050 duress objects missing from the wipe lists; header comment claims otherwise | `secure/src/se050/mod.rs:2266-2288`, `secure/src/se050/mod.rs:64-71` | No (`duress-pin` not shipped) | Low now, medium if duress ships | #107 |
| Page-123 state has no wallet discriminator: under a decoy unlock `CMD_OFFCHAIN_STATUS` returns the real wallet's counters | `secure/src/offchain_state.rs:23-33`, `secure/src/nsc/cmd_offchain_status.rs:75-79` | No (`duress-pin` not shipped) | Medium, deniability | No |
| Boot and PendSV arms never wipe on `PinLocked` or check the post-bump count; the 10th wrong PIN defers the wipe to the next boot or USB unlock | `secure/src/main.rs:4198-4207`, `secure/src/main.rs:4587-4598` | Yes | Low to medium | No |
| A locked device paints the PIN dialog on every host unlock request with no rate bound; host LOCK then UNLOCK sidesteps #148 | `nonsecure/src/usb/commands.rs:286-287`, `secure/src/nsc/cmd_request_unlock.rs:51-54` | Yes | Low | No |
| PIN dialog holds no `TrustedUiWaitGuard` while the watchdog is in the ship set: about 30 s budget on USB, 4 s stall budget in PendSV | `secure/src/hw/iwdg.rs:126`, `secure/src/hw/iwdg.rs:137` | Yes by source read; not built or run with `iwdg` on | Medium, availability | No |
| Doc drift listed in the inventory | see inventory | n/a | Low | #637, #636 in part |

### Recommendations

| ID | Recommendation | Kind | Cost | Priority | Novelty | Tracked issues |
|---|---|---|---|---|---|---|
| M14 | Wipe as a verified, resumable transaction, plus a designed post-wipe recovery rule in the S-1 ceremony | mixed | L | P1 | parity | #5 #8 #12 #22 #75 #104 #106 #107 #120 #123 #127 #129 #168 #170 #200 #204 #254 #256 #320 #692 #712 #715 |
| pin-04 | Fix duress docs now; enable `duress-pin` only behind per-wallet page-123 state and #107 | mixed | L | P2 | parity | #10 #107 #123 #171 #258 #280 #370 #446 #626 #636 #700 #772 |
| pin-05 | One lockout response on all three unlock arms | firmware | S | P2 | parity | #75 #104 #120 #125 #127 #168 #200 #692 #715 |
| M12 | Capped, reboot-surviving PIN back-off inside `gated_unlock` | firmware | M | P3 | parity | #119 #148 #175 #329 #600 #637 #692 #700 #713 #715 #728 #729 #802 |
| M13 | Pre-PIN "device words" from a salted die-key MAC over the PIN prefix | firmware | M | P3 | parity | #206 #249 #268 #280 #601 #636 #700 #705 #772 #784 |
| pin-03 | FI-hardened page-124 record codec | firmware | L | P3 | parity | #200 #216 #392 #397 #692 #715 #835 |

Disagreements (the table holds the final values): M12 merger S, skeptic M. M13 merger P2/S, skeptic P3/M. pin-03 proposed P1, lenses P3 and P2. pin-04 lenses P1/M and P2/L. pin-05 lenses M and S. No item has a hardware ask except M14.

**M14. Verified wipe and lockout recovery**
- Threat. A power cut, bus fault or glitch mid-wipe leaves a device that claims a wipe that did not happen. On the ship profile a wiped device cannot be provisioned again, so ten PIN attempts brick the hardware.
- What to do. Tier A, firmware now: consume the `factory_reset_admin` result through a sentinel at every call site; clear the flag, reset page 124 and print "WALLET WIPED" only on a verified result. Make SE050 existence checks and `admin_exists` tri-state, unknown meaning not wiped. Delete the admin object only after data objects are verified absent. Return `Err` on admin-PIN derivation failure. Let only the dual-SE layer clear the flag. Add a boot-time assertion: when the flag is clear and the wizard is about to run, re-check SE050 existence and the F1E1 sentinel, and re-arm on any survivor. Complete the sweep lists (#107, #129). A bounded-resume terminal screen is mandatory, or a persistent SE fault wipes on every boot forever. Stop promising "restore from seed". Put the decision logic in a workspace crate so its tests run, and add a cold reboot to `pin-gate-wipe-e2e`. Tier B, paper plus a sacrificial part: adopt the rule "every counter reset destroys a secret the unlock needs, and every wipe can reset or retire the counter", then choose Trezor's PIN_SECRET indirection or per-generation object sets.
- Dropped parts and why. OPTIGA readback (`secure/src/optiga/apdu.rs:1174-1199`); the verdict becomes blank-write status plus F1E1, which argues for writing the sentinel last. Regenerating the boot hardware key (BHK) first. Both: see Considered and rejected. Gating reconcile on `is_provisioned()` alone: it swaps a re-wipe for a wizard that cannot provision.
- Evidence pq1 lacks it. Defect rows 1 to 7.
- Precedent. Trezor (paths above). Ledger 1.4 and BitBox02 Nova ([datasheet](https://bitbox.swiss/bitbox02/nova/BitBox02_Nova_BTC_Datasheet.pdf)) are member citations, not re-fetched.
- Hardware asks. No board change. One sacrificial OPTIGA Trust M V3 and one sacrificial SE050E; assertions over log or USB because the bench pq1 has no LCD.
- Residual after it lands. Tier A alone leaves the device unrecoverable. Generations are bounded by OPTIGA's counters (about 2 to 3 lifetime wipes). The resume counter is new durable state on page 125.
- Not yet tracked. The F1D0 brick; the `Ok(())` path; the `admin_exists` coercion and admin self-delete; the unconditional reset and screen text; the runtime object-identifier (OID) range bump that three comments rely on and nothing implements; the boot assertion; the S-1 rule; the FI suite's dependency on an uncommitted `WipeFault`; `pin-gate-wipe-e2e` proves recovery only on a non-locked bench build.

**pin-04. Duress**
- Threat. Coercion. The shipping image has no decoy, and the absence is implicit.
- What to do. (a) Now, cost S: correct the doc lines and record explicitly that the ship image has no duress path. (b) Enable only after: a per-wallet discriminator in the page-123 key, #107 fixed, a ship-shaped flash measurement, a logic-analyser capture of both unlock sequences, and #280 on a unit with a panel. Add the forcing or forbidding fence either way.
- Dropped parts and why. #370 is already fixed (`secure/src/crypto.rs:545-569`); close it. "Decoy by default" is not a recorded owner decision (#636). PIN-change coupling is moot; no PIN-change flow exists.
- Evidence pq1 lacks it. `Makefile:2718`; no CI job compiles `duress-pin`.
- Precedent. Coldcard Trick PINs. Trezor's wipe code refuses a PIN equal to it at `storage/storage.c:1724-1725`.
- Residual after it lands. The I2C operation order differs between real and duress unlocks, UNMEASURED. An attacker who extracts the OPTIGA platform binding secret (PBS) distinguishes the wallets by OID (#10). The decoy has no mnemonic backup. Wipe-on-duress is terminal for the hardware until M14 Tier B.
- Not yet tracked. The page-123 leak, the bus-order difference, the unrecoverable decoy, the fence.

**pin-05. One lockout response**
- Threat. A deferred wipe on two of three arms: after the 10th wrong PIN at the device prompt both halves stay on the SEs until the next boot or USB unlock. No arm grants an extra guess, so this is not a counter bypass.
- What to do. Move `trigger_lockout_wipe` into `nsc/mod.rs` with its fail-in caller pattern. Port the post-bump count check to the boot and PendSV wrong-PIN arms. On an SE-originated `PinLocked`, arm the page-125 flag, which the existing boot check already honours. Corroborating with a fresh session before that wipe is the #104 design and is unverified on silicon.
- Dropped parts and why. "E120 exhaustion is not wiped at next boot" is false; reconcile catches it. Gating on an authenticated status word (`secure/src/se050/scp03.rs:551-558`, see Considered and rejected). Immediate wipe on an SE050 lockout: it only surfaces after OPTIGA accepted the PIN (`secure/src/dual_se.rs:370-404`), so it would hit a correct-PIN user.
- Evidence pq1 lacks it. Defect row 9.
- Precedent. `storage/storage.c:1223-1230`.
- Residual after it lands. It must follow #104 and #120; more eager wipes mean more bricks until M14 lands. Wipe duration inside PendSV against the watchdog is untested.
- Not yet tracked. All of it, plus the attempt log labelling every `PinLocked` as AlreadyAtMax (`secure/src/nsc/mod.rs:1628`).

**M12. PIN back-off**
- Threat. Glitch campaigns on the gate and a fast fault-driven walk to the wipe (#715, #119). Attempts are already human-paced (about 4 to 5 s) and capped at 10; the skeptic removed "trace harvesting" as a motive. Net value is true docs plus parity.
- What to do. First put `TrustedUiWaitGuard` around PIN entry (watchdog defect). Then wait `min(2^n - 1, 60)` s from the page-124 count before the precharge, on the secure tick, gated to `stm32u585`, with a fixed countdown screen and a cancel that needs a new `UnlockError` variant. If declined, correct the docs, which is what #637 asks.
- Dropped parts and why. The host-prompt cooldown: the prompt would still be up about two-thirds of the time, and returning `UserRejected` for an unpainted prompt misleads the companion; file the prompt storm as an issue only. The uncapped schedule: 511 s on attempt 10. "USB-speed attempts": refuted.
- Evidence pq1 lacks it. `secure/src/nsc/mod.rs:1394-1493` has no failure-scaled delay.
- Precedent. Trezor. A Ledger back-off is unverified.
- Residual after it lands. Whoever resets page 124 resets the delay.
- Not yet tracked. The watchdog interaction, the prompt storm, the constraints above.

**M13. Device words**
- Threat. Post-setup swap of the whole unit for a lookalike that harvests the PIN. Malicious code on the user's own die and interception before setup are out of scope.
- What to do. After digit 4, show two BIP-39 words from `CMAC(DHUK, DOMAIN || page-127 salt || prefix)`, where DHUK is the derived hardware unique key. The salt is required because `secure/src/hw/secret_keys.rs:493-499` forbids a bare die-key ladder. Cap derivations since the last successful unlock and exempt wizard entries. Label the words "not device-unique" from the runtime readout-protection (RDP) level plus journal state. Test label collisions against every die-key label including the two ML-KEM ones. Render on the forced secret frame.
- Dropped parts and why. SE-held MAC key: neither driver has a MAC-generate command. SE-enforced rate limit: see Considered and rejected. Per-boot cap of 3: the wizard alone calls `enter_pin` four times. Opt-in toggle: needs a persistent bit (#601 blocker).
- Evidence pq1 lacks it. `secure/src/ui/pin_entry.rs:54-146` has no mid-entry hook; the secure-world fingerprint is compiled out of `mode-production` (`secure/src/main.rs:1750-1751`).
- Precedent. Coldcard since 2018; Passport. Trezor and Ledger have none.
- Residual after it lands. Live relay through the genuine unit; pre-enumeration of 10^4 prefixes with no attempt consumed; filmed words replayed; words survive a wipe.
- Not yet tracked. The whole mechanism; only #601 covers the threat.

**pin-03. Page-124 codec**
- Threat. A sustained fault that reads the whole page as 0xFF decodes as zero attempts. It yields no extra guesses, because SE050 and E120 still count; an earlier triage accepted it (`tools/sca/README.md:428-450`).
- What to do. Page 124 only: a bit-expanded, replicated record in a workspace crate with Kani harnesses (#397). A reset-atomicity design is blocking: erase-then-write turns a power cut into a wipe via `secure/src/main.rs:1935-1951`.
- Dropped parts and why. Page 123: its 16-byte record is full and a blank page is legal there. Trezor replicates over 6 halfwords, not 8.
- Evidence pq1 lacks it. `secure/src/hw/flash.rs:764-768` (erased means 0 attempts), `secure/src/hw/flash.rs:955` (reset is erase-only).
- Precedent. `storage/pinlogs_blockwise.h:8-73`.
- Residual after it lands. Suffix truncation still decodes to a well-formed lower count.
- Not yet tracked. The codec, the reset protocol, a 0xFF read-fault model in `tools/sca/fi_target`.

### Covered in other sections

- M04, fault response without attempt-charging, P2, section 3.
- M06, random-delay desynchronisation, P2, section 3.
- M20, glitch-environment sensing and closing non-secure clock, power and tamper levers, P0, section 11.

### Considered and rejected

No item written here was rejected outright. Dropped parts whose killing facts constrain future designs:
- Error status words from the SE050 carry no response MAC, so no verdict can be "authenticated locked".
- OPTIGA data objects cannot be read without the PIN, so OPTIGA wipe verification by readback is impossible.
- The SE050 credentials derive from the BHK, so regenerating it at wipe destroys the only credentials that can reach the SE050.
- Neither SE has a time base. Any rate limit is MCU-side.
- OPTIGA has four counters; one is taken by duress.

### Open questions and unmeasured claims

- Owner decision: is a post-lockout device a designed single-use brick (`secure/src/se050/mod.rs:2011-2021`) or recoverable? Tier B has no mandate until this is ruled.
- Owner decision: ship duress or record that it does not ship (#636); expose the attempt log unauthenticated (#719).
- Sentinel-first versus sentinel-last in the OPTIGA wipe: in-code rationale and #123 disagree.
- Does the OPTIGA leg of boot reconcile run at all (#127)? Does E120 ratchet on a successful verify (#170, #254)?
- UNMEASURED: watchdog behaviour during real PIN entry; I2C trace distinguishability of real and duress unlocks; flash cost of `duress-pin` in ship shape; any FI campaign against the PIN gate; whether DHUK at RDP-1 equals DHUK at RDP-2.
- Not traced: how `pin-gate-wipe-e2e` re-provisions past the USERID guard; whether commands other than unlock raise a prompt while locked.

---

## 9. Firmware update and rollback

Evidence level: confirmed by code reading at HEAD c75b0d9c, not on silicon, unless stated. The one silicon receipt is FSBL verify, render and branch on pq1 (dev key, RDP-0; `docs/firmware/firmware-update.md:443-463`). A slot flip has never run on hardware.

### What pq1 does today

**Implemented (verify and staging half).** `CMD_FW_BEGIN` runs one chain: structure, CRC, digest, vendor-key fingerprint, SPHINCS+C10 signature, rollback floor. Every step runs on every input, and the verdicts pass through fault-injection (FI) sentinels (`secure/src/fw_update/mod.rs:468-555`). A trusted-display authorization precedes the verifier and an install confirm precedes any flash operation (`secure/src/nsc/cmd_fw_begin.rs:32-228`). `CMD_FW_COMMIT` re-hashes flash against the signed hashes inside a sentinel gate (`secure/src/fw_update/verify.rs:41-115`). The first-stage bootloader (FSBL) repeats the chain per slot, has no flash write path in normal builds (`fsbl/src/marker.rs:36-41`), and renders the 8-word fingerprint before branching.

**Partial or absent.** No update can be activated on any build: COMMIT stages, then returns an error unconditionally with no floor write and no reset (`secure/src/nsc/cmd_fw_commit.rs:332-375`). There is no valid anti-rollback backend: the unary one-time-programmable (OTP) tally is physically invalid on STM32U585 error-correcting quad-words, and `otp::bump_to` has zero call sites (#31). A/B try-once recovery is nonfunctional (#271, #138). FSBL immutability is not implemented: write protection (WRP) is programmed nowhere in the tree, and no software guard excludes FSBL pages from the erase primitives (`secure/src/flash_policy.rs:124-170`). The signed bundle does not bind the FSBL; a different FSBL booted the unchanged bundle on silicon (#742). The manifest-v6 core (`fw-manifest/src/v6.rs:1-132`) has no consumer.

**Fenced off.** Production, real-key and factory builds fail to compile (`secure/build.rs:14-55`, `fsbl/src/main.rs:67-74`). `make release` is a hard error (`Makefile:2913-2917`). The production vendor key does not exist (#69).

**Docs that claim more than the code shows.** `docs/firmware/firmware-update.md:214-219` says COMMIT bumps OTP and resets; both were removed. `docs/firmware/firmware-update.md:484-491` says the new manifest is checked against the running slot's key fingerprint; the code uses the compiled-in key (`secure/src/fw_update/mod.rs:516-517`). `README.md:430` says the update path runs end to end. CLAUDE.md invariant #10 calls the geometry crate "CI-pinned"; #720 records that its tests run in no workflow.

**Where pq1 is ahead.** The chain is post-quantum only, end to end. Trezor's T3W1 firmware headers remain Ed25519; only its bootloader header is hybrid (`core/embed/sec/image/boot_header.c:33-109`). pq1 never arms a wipe on malformed manifests and requires a physical authorization per verifier run. These are bench-level advantages: recovery is nonfunctional, WRP is absent, and a sealed pq1 cannot light the panel from the FSBL (#705).

### What Trezor, Ledger and others do that pq1 does not

- **Movable rollback floor.** Trezor keeps unary 16-byte cells in a hidden flash page, enforced at boot and at upload (`core/embed/sec/monoctr/stm32u5/monoctr.c:79-135`), and hides the page before the jump (`core/embed/sec/secret/stm32u5/secret.c:170-184`). BitBox02 Nova's datasheet claims bootloader anti-downgrade ([datasheet](https://bitbox.swiss/bitbox02/nova/BitBox02_Nova_BTC_Datasheet.pdf)).
- **Multi-key roots.** Trezor requires 2 SLH-DSA signatures from up to 3 keys (`core/embed/sec/image/inc/sec/boot_header.h:25-35`). Foundation documents 2-of-4 release keys ([docs](https://docs.foundation.xyz/firmware-updates/passport-prime/)); vendor claim, not re-verified.
- **Merkle batch signing.** One ceremony covers many images (`core/embed/sec/image/boot_header.c:226-261`).
- **Erased-remainder check** at every boot (`core/embed/sec/image/image.c:437-523`), plus erase read-back in the flash driver (`core/embed/sys/flash/stm32u5/flash.c:211-250`).
- **Signed hardware model and revision** (`core/embed/sec/image/image.c:140-166`, `core/embed/sec/image/boot_header.c:183-186`).
- **Fingerprint over the whole signed header** (`core/embed/sec/image/image.c:168-176`).
- **No update surface at all.** Tangem ships non-updatable firmware ([vendor claim](https://tangem.com/en/learning-hub/post/is-tangem-safe/)).

Ledger LSB-021 shows the brick class: an unvalidated host-supplied reset address during update ([Donjon](https://donjon.ledger.com/lsb/021/)). Checksum faults on hash-based signatures also hit the verifier ([ePrint 2023/1572](https://eprint.iacr.org/2023/1572)); see section 3.

Trezor explicitly does not: enforce image expiry (`core/embed/sec/image/image.c:125-131`; the low bit is reused as a compatibility flag), allow-list bootloader hashes (`core/embed/sec/image/stm32/boot_image.c:78-80`), run A/B firmware slots, offer SD recovery on U5 models (`core/embed/projects/boardloader/sd_update.c:24-26`), or sign firmware PQ-only.

### Live defects confirmed on this surface

| Defect | Evidence | Reachable in the shipping feature set? | Severity | Tracked |
|---|---|---|---|---|
| Rollback floor can never rise; every vendor-signed image stays installable | `fsbl/src/otp.rs:1-41`; `secure/src/nsc/cmd_fw_commit.rs:332-375`; `secure/src/nsc/cmd_fw_begin.rs:112` | No. Production is compile-blocked (`fsbl/src/main.rs:67-70`, `Makefile:2508-2509`) | Ship-blocker, not new | #31, #543, #546 |
| Threat model presents an FSBL self-check of its key against an OTP hash as the defence against a replaced FSBL; a replaced FSBL omits the check | `docs/security/threat-model.md:517-518`; #220 body | Documentation only | Low | #220 (scope wrong) |
| Fingerprint covers the secure image only; releases differing in the non-secure (NS) image or version show identical words | `fsbl/src/verify.rs:109`; `fsbl/src/main.rs:286`; `secure/src/fw_update/mod.rs:135` (skeptic cites `:139`; the call sits at line 138 in the tree) | Yes | Merger low-medium; skeptic low (NS is untrusted by design) | None |
| Slot tail beyond the declared length is never verified erased; BEGIN's erase is judged by status flags only, no blank read-back | `fsbl/src/verify.rs:52-68`; `secure/src/fw_update/verify.rs:57-58`; `secure/src/hw/flash.rs:1307-1352` | Yes; needs prior secure-world write or a faulted erase | Low | None |
| FSBL comments say software SHA-256 while `hw-sha256` is the default | `fsbl/src/verify.rs:5-24`; `fsbl/Cargo.toml:16,79` | Documentation only | Info | None |
| Cross-board image under the shared dev key is accepted by updater and FSBL | `fsbl/src/main.rs:321-353`; `secure/src/fw_update/mod.rs:468-520`; `fsbl/build.rs:94-159` | No today; yes if the vendor signs a wrong-board build | Low (bench, availability) | #487 |

The single baked vendor key was proposed as a defect. The skeptic reclassified it as a design residual (single key is the documented default), so it is not listed.

### Recommendations

| ID | Recommendation | Kind | Cost | Priority | Novelty | Tracked issues |
|---|---|---|---|---|---|---|
| M07 | One recorded FSBL freeze review: key policy, minimum-version constant, Merkle signing, sealed profile, hidden flash counter as review input | mixed | M | P2 | parity | #31 #35 #39 #43 #67 #69 #212 #220 #225 #226 #266 #486 #540 #541 #543 #544 #545 #546 #696 #742 #752 #753 #758 |
| M08 | Erased-tail check at COMMIT and in the FSBL; optionally derive the 8 words from the signed manifest digest | mixed | M | P3 | parity | #226 #268 #486 #540 #591 #696 #705 #742 #758 |
| FWU-3 | Bind board model and revision into what is signed; check in updater and FSBL | firmware | M | P2 | parity | #487 #540 #543 #545 |
| FWU-7 | Redesign: reviewer cross-check note mapping Trezor's update-control-block rules to Draft 1.1, plus a producer-side route-around rule | process | S | P3 | parity | #138 #271 #480 #486 #540 #542 #543 #545 #546 #696 #758 |

**M07. FSBL freeze review.** The merger rated P1; the skeptic corrected to P2 overall and wanted the key-count decision alone at P1. Final: P2.
- Threat. After WRP and readout protection level 2 (RDP-2) the FSBL cannot change. It embeds one vendor key (`fsbl/src/vendor_pubkey.rs:20-23`), so a stolen key signs firmware every device accepts forever.
- What to do. Hold one review and record every outcome, including declines, in `docs/security/vendor-signing-key-compromise.md` (boxes at `:84-97` are unticked). (A) Decide single key versus primary plus recovery key, either accepted. The second key must also go into every secure image with an either-key BEGIN verifier, and fwsign's FSBL-equals-secure gate must change (`fwsign/src/artifact_key.rs:596-598`), because `CMD_FW_*` is the only install path at RDP-2 (#696). Decide before #541 freezes its measurement profile. (B) Minimum-version constant in the FSBL. (C) Merkle-leaf signing: default "declined with record". (D) Trezor's hidden flash counter: a note into #543 only. (E) Put the FSBL digest in release receipts (#742); freeze the per-key signature cap (#225). (F) Cost the sealed profile and record the outcome.
- Dropped parts and why. Quorum, OTP self-check, "select the backend now"; see "Considered and rejected".
- Evidence pq1 lacks it. One key, one verify (`fsbl/src/main.rs:335-346`); no hide-protection code (grep for `SECHDPCR`, `SECWM1R2`, `ACCDIS` returns nothing).
- Precedent. Trezor, lines cited above.
- Hardware asks. None for the board. For D only: sacrificial STM32U585CIU6 parts (#544).
- Residual after it lands. A primary-key thief still wins on every device. The design note's recovery flow (`:58-63`) is incoherent: a "new primary" absent from the FSBL can never sign a bootable manifest, so the recovery key becomes the only key and has no successor. The FSBL picks the highest version (`fsbl/src/main.rs:377-382`), so an attacker signing at the top of the version space cannot be outranked. Items B and C conflict with the frozen Draft 1.1 (`docs/security/a-b-firmware-rollback-architecture.md:160-161`; 121-byte preimage at `fw-manifest/src/v6.rs:55`) and need an owner reopen, as does D (`:3896-3897`). A valid signature stays authentic, not benign.
- Not yet tracked. Option B's secure-world and tooling consequences; the ordering before #541; the max-version residual; the minimum-version constant; Merkle manifest signing; sealed-profile costing; correcting #220 and threat-model §9.8.

**M08. Erased-tail check and fingerprint coverage.** The merger rated P2, cost S, firmware; the skeptic corrected to P3, M, mixed. Final: P3, M, mixed.
- Threat. A dormant payload or stale bytes in a slot tail after a secure-world exploit or a skipped erase. The transit case is already covered by the full-flash debug-port diff (`docs/security/user-device-verification.md:85`).
- What to do. Part 1: word-walk each tail and require erased flash, a check and not a hash. Land the COMMIT half now. Land the FSBL half inside the #540 geometry cutover, with capacity taken from `pqsigner-geometry`. Add erase read-back at BEGIN. Add both walks to #591. Part 2 (owner decision, with manifest-v6): derive the words from the signed manifest digest in all three renderers and `fwmeasure`; have `make release` emit expected words per slot.
- Dropped parts and why. Whole-window hash, random fill, signed lengths; see below.
- Evidence pq1 lacks it. Defect rows 3 and 4.
- Precedent. Trezor's `check_image_contents`; Krux fills and hashes empty flash ([Krux](https://selfcustody.github.io/krux/getting-started/features/tamper-detection/)).
- Residual after it lands. The merger's "no brick lever" is false. A shipped unit has one valid slot; a dirty tail there is a permanent halt at RDP-2 (`fsbl/src/main.rs:220-222`). With two slots the check forces a downgrade to the previous image. Unchecked space remains in manifest-page slack, boot-state page 6 and pages 123-127. Part 2 as merged turns the secure-world row into a copy and removes the divergence signal; it must recompute or the loss must be an explicit owner trade. Its value is release identification, not attack detection.
- Not yet tracked. All of Part 1 and Part 2; the missing FSBL fault handler; bench flash recipes must erase whole slots.

**FWU-3. Board binding.** Original P0; one verifier gave P2, the other P1. Final: P2.
- Threat. A vendor-signed iota2 image installed on pq1. It leaves PA8, the secure-element rail enable, as an input (`secure/src/hw/buttons.rs:108-116`) and hands SE reset and enable pins to the non-secure world. The result is a brick at RDP-2; no secret is disclosed. It requires a release-process error.
- What to do. Owner chooses the mechanism: signed model and revision fields (121 to 127 bytes, new digest), a per-board key or domain (Draft 1.1 §6.4, `:2430-2441`), or a board tag inside the secure image, covered by the signed hash. Fold the check into the all-steps-run chain and the FI sentinels. Make fwsign require a board identity and cross-check the binary's board feature. Fix the release default of `BOARD=iota2` (`Makefile:43`, `Makefile:2662`). The FSBL-side check must exist before the freeze.
- Dropped parts and why. "Reject before the C10 verify" (contradicts timing normalization); the unsigned interim tag.
- Evidence pq1 lacks it. No board field in either format (`fw-manifest/src/lib.rs:59-80`, `fw-manifest/src/v6.rs:54-55`).
- Precedent. Trezor `core/embed/sec/image/image.c:140-166`, `core/embed/projects/boardloader/main.c:131-134`, `core/embed/projects/bootloader/workflow/wf_firmware_update.c:105,150,170`. The Trezor data file's `main.c:119-130` and `wf_firmware_update.c:131-135` cites are wrong. Trezor matches revision exactly; a range rule has no precedent.
- Residual after it lands. An in-image tag rejects only after write and hash.
- Not yet tracked. That #487's trigger has fired; the three-way mechanism decision; the placement constraints; the freeze deadline; the `BOARD` default.

**FWU-7. Update-control-block cross-check.** One verifier refuted it as written (confidence 0.8).
- Threat. A decoder bug in a frozen FSBL is permanent.
- What to do. Do not amend Draft 1.1. Attach a non-normative note to #546: a mapping table showing rows (a), (c), (d), (f) are already normative; a rule that route-around is producer-side input avoidance only; a pre-freeze differential fuzz of FSBL decoders against the host core.
- Dropped parts and why. Rows (b) and (e); see below.
- Evidence pq1 lacks it. No document mentions `boot_ucb.c`.
- Precedent. Trezor `core/embed/sec/image/stm32/boot_ucb.c:56-171`. `BOARDLOADER_UCB_ZERO_ADDR_BUG` (`core/embed/models/T3W1/model_T3W1.h:56-68`) has no consumer in the tree; only a comment supports "the fix lives in the mutable bootloader".
- Residual after it lands. Documentation only.
- Not yet tracked. The note and the rule.

### Covered in other sections

- M02, option-byte posture (pin masks, halt on mismatch): P1, section 6.
- M05, FSBL pre-freeze FI bundle: P1, section 3.
- M19, make existing assurance execute and block in CI: P1, section 11.

### Considered and rejected

- **2-of-3 signature quorum in the FSBL.** A second 4008-byte signature does not fit the one-page manifest (3,995 B free in the legacy layout, 3,916 B in v6). m-of-n is a recorded decline (#486).
- **FSBL self-check of its key against OTP.** A replaced FSBL omits the check. The external verifier already diffs the whole FSBL, so the surviving form adds nothing.
- **Selecting the hidden flash counter now.** Draft 1.1 says authoritative records "MUST remain in OTP". The counter page cannot share page 5, which is the runtime-written Manifest A. A skipped hide-write lets runtime erase the floor.
- **`mode-sealed` build profile now.** Decoders live in the secure image, so sealing is a re-architecture.
- **Whole-window hash into the fingerprint.** About +1.8 s at the only measured rate, and it changes signed-hash semantics.
- **Random fill plus pinned hash (Krux style).** Incompatible with a vendor-signed hash and the byte-exact diff.
- **"Sign the lengths" as a tail defence.** An under-declared length changes the hashed range, so the hash no longer matches.
- **"The compressible-firmware bypass applies."** Refuted: it defeats a self-attested hash ([LSB-002](https://donjon.ledger.com/lsb/002/)); pq1's FSBL row is not self-attested.
- **FWU-7 row (b), erase the record first.** Trezor copy semantics; Draft 1.1 journals are program-only.
- **FWU-7 row (e), a route-around flag byte.** A frozen FSBL honours only flags coded before the freeze. A flag it does honour is a downgrade knob for hostile runtime.
- **FWU-7's premise.** The "Route-1 journal" (pages 64/122) is the OTP launch journal, not the activation record.

### Open questions and unmeasured claims

- FSBL free space is inconsistent across the data: 10,532 B free (M08), about 4 KiB (M07 skeptic), 52 B on a Draft 0.9 proxy. #541 owns the measured link.
- The 2.93 s FSBL work figure is the software-SHA path. The default `hw-sha256` FSBL has not run on silicon. UNMEASURED.
- Tail-walk cost: estimated 0.2 to 0.5 s, on both slots, three evaluations each. UNMEASURED. The stage-marker harness measures only the one-slot case.
- The FSBL has no fault handler. Whether an interrupted erase raises a double-ECC fault that halts every boot is UNMEASURED and untracked.
- Whether the ui-px atlas lies inside the declared NS length is inferred from linker scripts, not from a built binary.
- Will the owner reopen Draft 1.1 for items B, C or D?

---

## 10. USB, companion attack surface and TrustZone isolation

Threat model for this section: a malicious host drives the non-secure (NS) world over USB. NS holds no secret by design, so the load-bearing boundary is the non-secure-callable (NSC) gateway plus the Security Attribution Unit (SAU) and the Global TrustZone Controller (GTZC). Unless a line says otherwise, every pq1 fact below is confirmed by code reading, not on silicon. Trezor paths are relative to the `trezor-firmware` checkout.

### What pq1 does today

**Implemented.**
- Host-facing framing. HID frame reassembly, the APDU header parser and the chained-APDU state machine live in the dependency-free `shared` crate, so the production code is the fuzzed code (`shared/src/apdu_framing.rs:349-498`, `:64-82`, `:209-243`). It enforces a 4096-byte APDU cap, a per-command chain bound (`nonsecure/src/usb/commands.rs:99-112`), chain, drain and reassembly timeouts, and a single-session router lease (`nonsecure/src/usb/commands.rs:226-242`). Four Kani harnesses, proptests and two libFuzzer targets cover it.
- Pointer validation. The NS pointer window arithmetic is Kani-proven and Miri-checked host-side (`shared/src/ns_ptr_validate.rs:109-164`); firmware adds the ARMv8-M TT (test target) instruction per 32-byte stride (`secure/src/nsc/ptr_validate.rs:60-175`).
- Time-of-check/time-of-use discipline. NS payloads are copied byte-wise into secure SRAM and only the copy is parsed (`secure/src/nsc/cmd_sign_userop.rs:160-189`). Companion fields are assertions: EntryPoint is compared twice and `sender` must equal the device-derived CREATE2 address (`secure/src/nsc/cmd_sign_userop.rs:190-226`).
- Isolation. Default-secure GTZC allowlist with compile-time image pins and fail-closed readback (`secure/src/sau.rs:503-590`), SRAM1 secure and SRAM2 NS, configuration lock (`secure/src/sau.rs:631-745`), illegal-access interrupt that wipes under `tzic-wipe` (`secure/src/hw/tzic.rs:228-276`). Enforcement was silicon-validated 2026-05-20, but only on the non-shipping `mock-se,ui-semihosting,debug-log,e2e-test` combination; SPI1 and IWDG have no receipt (#390, #79).
- Liveness. Secure-owned watchdog, secure-only 120 s inactivity timer that NS cannot reset (`secure/src/timeout.rs:315-327`), signing rate limiter.

**Partial.**
- The `NsPtr<T>` typestate has one production consumer (`secure/src/nsc/mod.rs:2011`); all `cmd_*` handlers use free functions behind a fault-injection (FI) sentinel (#84).
- `make check-fi-ir` and `tools/check-gateway-abi.sh` exist but no CI workflow calls them (#130, #690, #701).
- A locked device shows a PIN dialog on every host UNLOCK request, with no rate bound (M12).

**Absent, by decision or not yet built.** No host transport authentication or encryption (deferred by owner). No memory protection unit (MPU) in either world; NS runs privileged (#277). GTZC2 (TAMP, backup SRAM) is unconfigured. RCC and PWR are not secure-attributed (#80). Device identity over USB is placeholder: `device_uid` is 16 zero bytes (`nonsecure/src/usb/commands.rs:420-421`).

**Docs that claim more than the code shows.**
- `docs/security/threat-model.md:263` presents `NsPtr<T>` as the mechanism that validates gateway pointers.
- `docs/security/HARDENING.md:212` and `docs/security/threat-model.md:242` claim MPU regions in both worlds; none exist.
- `docs/security/threat-model.md:267` cites a `clippy::indexing_slicing` deny lint that is not in the repo.
- The inventory credits `HandlerGuard` with non-reentrancy. Verification refuted this (USB-01).
- Issues #70, #239, #136 and #130 are open although their fixes are in the tree. #70 carries the ship-blocker label.

**Where pq1 is ahead.** PIN entry, the trusted display and all transaction parsing run in the secure world. Trezor's architecture document states that its NS `coreapp` "can ask for access to raw secrets and will just get them" (`docs/core/embed-arch/embed-arch.md:24,92,106,325-326,360-362,383`). The host cannot extend pq1's autolock; Trezor's is host-pingable. pq1's first-stage bootloader has no USB. A host cannot trigger a wipe; Trezor allows WipeDevice while locked. Pointer arithmetic is machine-proven.

### What Trezor, Ledger and others do that pq1 does not

- **One gateway chokepoint.** Trezor's NS kernel enters through a single `smcall_invoke` path with numbered dispatch and a fatal default (`core/embed/sys/smcall/stm32/smcall_dispatch.c:61-63,475-488`), and every call has a `__verified` probe wrapper (`core/embed/sys/smcall/stm32/smcall_verifiers.c:36-686`). pq1 has about 35 independent veneers. Trezor does **not** refuse nested entry; a search of its smcall directory for reentrancy terms is empty. It has no equivalent window because its secure monitor never blocks in UI.
- **Clock, power and stack attribution.** Trezor secures RCC, PWR, SYSCFG and RAMCFG (`core/embed/sec/trustzone/stm32u5/tz_init.c:249-298,304-337,339-406`), sets hardware stack limits (`core/embed/sys/task/stm32/systask.c:161-180,575-632,632-720,793-813`) and arms a voltage detector (`core/embed/sys/pvd/stm32/pvd.c:28-52`). See M20 and M21.
- **Time-domain jitter on the USB path.** `wait_random()` on every control-request branch (`core/embed/sec/random_delays/inc/sec/random_delays.h:26-43`). See M06.
- **Authenticated host channel.** Trezor Host Protocol (THP): a Noise XX handshake, code-entry pairing with a password-authenticated key exchange, revocable credentials (`docs/common/thp/specification.md:3,459-470,541,618-636,879-882`; `core/src/apps/thp/pairing.py:99-137,231-260,294-322,393-420`). Firmware 2.12.2 fixed a pairing bypass via low-order points ([advisory](https://trezor.io/vulnerability/thp-pairing-could-be-completed-without-the-pairing-code)). X25519 conflicts with pq1's PQ-only stance, so this is an owner decision, not a port. Older Trezor models keep the unencrypted codec.
- **Host-compiled message decoder.** Bounded protobuf decoding with a nesting cap (`core/embed/rust/src/protobuf/decode.rs:14-27,59-75,99-157,199-278`). pq1's 1274-line NS router is host-uncompilable.
- **USB class back-pressure.** No re-arm until the report is consumed (`core/embed/io/usb/stm32/usb_class_hid.c:93-174,202-227,333-347,404-444`).
- **Ledger** treats its transport MCU as untrusted ([Donjon threat model](https://donjon.ledger.com/threat-model/os-transport-security/)) and, after LSB-023, rejects interleaved commands centrally in the SDK before application code ([LSB-023](https://donjon.ledger.com/lsb/023/)).
- **BitBox** disclosed a memory-corruption bug exploitable by a hostile host before wallet setup ([BitBox](https://blog.bitbox.swiss/en/bitbox-08-2026-dixence-update/)).

Trezor's recorded non-goals: the secure monitor does not re-verify the kernel, the memory-block controller raises no exception on illegal access, `drbg_random8` returns the constant 128 under lock contention, and the THP queue drops the oldest element when full.

### Live defects confirmed on this surface

| Defect | Evidence | Reachable in the shipping feature set? | Severity | Tracked |
|---|---|---|---|---|
| The gateway is not reentrant-safe. `HandlerGuard::enter()` only counts depth and no veneer refuses. A nested `nsc_sign_userop` refills the shared `SIGN_SNAP_BUF`; the outer handler re-reads it after confirm and signs it. The device displays one calldata and signs another, at the same `to`, `value` and `data_len`. Off-chain signing is not swap-vulnerable. **Corrected 2026-10-12:** batch signing does not have the same shape; the batch handler re-binds the signed calldata to the confirmed commitment and would refuse (see the update note in the live-defects section). | `secure/src/nsc/mod.rs:1277-1280`, `:1923-1990`, `:1026`; `secure/src/nsc/cmd_sign_userop.rs:175-189`, `:204-208`, `:388`, `:1933`, `:2133-2137`; `secure/src/nsc/cmd_sign_userop_batch.rs:2098`, `:2264` | Yes. The path is gated only on `stm32u585` and is compiled by the production feature set, which does not link today because of the S-2 fence. CMSE silicon only; QEMU's mailbox is non-reentrant by construction. Trigger is a banked NS SysTick or PendSV exception. Source-traced, no proof of concept, nested stack depth UNMEASURED. | One lens: high. The other: high to critical within the threat model. Both require a compromised NS image, which is FSBL-measured and vendor-signed. | Partly: #152, #835. The defect itself is untracked. |
| `cmd_pin_attempt_log::run` is a production, PIN-less handler whose pointer check is a single bare branch with no FI sentinel. One instruction skip writes 36 bytes of non-secret log data to an NS-chosen secure address. | `secure/src/nsc/cmd_pin_attempt_log.rs:23-33`; `secure/src/nsc/mod.rs:2052-2060`; `secure/src/pin_attempt_log.rs:98,106` | Yes by construction; the veneer has no feature gate. Needs NS code execution plus one glitch. Not demonstrated. | Low (one lens), low-medium (the other) | No. #140 covers prodtest only; #719 covers disclosure only. |

About 40 `SAFETY` comments rely on the guarantee the first defect shows is absent (`secure/src/nsc/mod.rs:1001-1003`, `:1024`, `:1915`), and `secure/src/sau.rs:716` wrongly implies AIRCR.PRIS stops an NS exception preempting a secure veneer.

### Recommendations

| ID | Recommendation | Kind | Cost | Priority | Novelty | Tracked issues |
|---|---|---|---|---|---|---|
| USB-01 | Atomic try-enter at every veneer, `Busy` refusal, post-confirm re-binding of the signed bytes | firmware | M | P0 | parity | #132, #140, #152, #418, #468, #600, #729, #835 |
| USB-06 | Redesign: fix the pin-attempt-log gate, finish `NsPtr` adoption, optional per-veneer locked-policy gate | firmware | M | P2 | parity | #84, #140, #152, #418, #600, #715, #719 |
| USB-08 | Signing-ceremony anomaly layer: semantic intent ring, retry-mutation classification, UI as a separate owner decision | firmware | L | P2 | beyond | #329, #600, #616, #714, #779 |
| USB-09 | Host-compilable NS router with composed fuzzing; USB-face rig; re-cite the ES0499 row | mixed | M | P3 | parity | #130, #136, #313, #428, #476, #588, #590, #596, #626 |

**USB-01. Make the gateway non-reentrant.**
- Threat. A hostile NS image arms a banked NS system exception and calls a second veneer while the secure thread is parked in `confirm()` or `enter_pin()` for up to 120 s. This is the Ledger LSB-023 class.
- What to do. Add `compare_exchange(0,1)` at the top of every `cmse-nonsecure-entry` veneer, before any argument is read, through the `fi::check_true_into_sentinel` idiom. Return a new `NscStatus::Busy` (value 9 is free in `proto/src/lib.rs:2102`) with a USB status-word mapping. Keep per-handler `enter()` for the idle-wipe depth semantics. Fix the root cause as well: commit a SHA-256 of the snapshot or reconstructed calldata before confirm and re-check it after, or build the calldata before confirm (the batch handler already does this and is the pattern to copy); scrub `SIGN_SNAP_BUF` on every early return. Define how the PendSV idle re-unlock takes the same token. Optionally add BASEPRI_S=0x80 inside veneers. Correct the false comments and add a threat-model row. Evidence: a source-invariant test over all veneers, a host model of the guard in a workspace crate, and a silicon test.
- Dropped parts and why. The proposed QEMU test is vacuous: `poll_gateway` runs to completion (`secure/src/nsc/mod.rs:1770-1799`). The NS USB interrupt vector does not exist: no code writes `NVIC_ITNS` and NS USB is polled. The Trezor reentrancy precedent is false. Cost rose from S to M: existing source-pin tests assert the literal `fetch_add` and must be rewritten.
- Evidence pq1 lacks it. See the defect table; `NscStatus` has no `Busy` variant.
- Precedent. Ledger's central rejection after [LSB-023](https://donjon.ledger.com/lsb/023/); Trezor's single chokepoint, as architecture only.
- Hardware asks. None.
- Residual after it lands. A single fault that skips the guard reopens nested entry; the re-binding hash covers that case. Impact differs by display: under `ui-lcd` the pages are a stack value so the dialog keeps the original transaction; under `ui-px` the nested zeroing wipes the pixel transcript and is likely to break or refuse the dialog.
- Not yet tracked. Nested NS entry as a threat; the post-confirm re-read; unscrubbed early returns; the refusal mechanism; the invariant test; the comment and threat-model corrections; `cmd_pin_attempt_log` and `nsc_register_heartbeat` as unguarded veneers.

**USB-06. Gateway policy (redesign needed).**
- Threat. PIN gating and pointer validation are enforced by per-handler discipline, so a new command can land without the uniform FI shape. One already did.
- What to do. (a) Convert `cmd_pin_attempt_log` to the sentinel gate, cost S. (b) Finish #84 and add a semgrep ban on `validate_ns_*_ptr(` outside the validation modules. (c) Correct `docs/security/threat-model.md:259-263` until #84 lands. (d) Optionally add a per-veneer `gate(CMD_ID)` helper with a build-time check that every veneer calls it, after #719 is decided.
- Dropped parts and why. The central table "in dispatch" is refuted: `dispatch` is `#[cfg(not(feature = "stm32u585"))]`, QEMU only (`secure/src/nsc/mod.rs:1812-1813`). The unknown-command anomaly counter is dropped; see the rejected list.
- Evidence pq1 lacks it. `secure/src/nsc/cmd_pin_attempt_log.rs:23-25`; 20 PIN-gate sites across 15 of 20 handler files.
- Precedent. Trezor `core/src/trezor/workflow.py:20-41`. The verifier corrected the claim: Trezor's filter is prompt-then-allow in Python with no FI hardening, not deny-first.
- Hardware asks. None.
- Residual after it lands. Policy stays per-entry discipline, now machine-checked.
- Not yet tracked. Items (a) and (c), and the semgrep rule. The lenses priced this at S (part a alone) and M (full residue); the final value is M.

**USB-08. Signing-ceremony anomaly layer.**
- Threat. The companion reports "failed, sign again" and resubmits a mutated payload until the user stops reading. `docs/security/threat-model.md:282` records "NONE TODAY".
- What to do. Treat this as the implementation spec for #600 and split it as #600 does. Core first: a pure-logic workspace crate holding a bounded secure-SRAM ring keyed on semantic fields (kind, chain, sender, to, value, token and amount, selector or calldata digest, slot), excluding nonce and fee, returning Normal, RepeatBurst or MutatedRetry. Keep the ring across LOCK and idle-lock, because both are host-inducible; it holds only public fields. Count prompts, not released signatures. Restrict the diff trigger to a real retry signal. The friction UI is a separate owner decision.
- Dropped parts and why. The page-byte fingerprint never matches a fee-bumped retry. Clear-on-lock lets the host empty the ring. "Scroll to end after three repeats" is already unconditional (`secure/src/ui/px/confirm_px.rs:57`). The 2 s hold contradicts the 2026-09-22 gesture decision. Reusing the F-17 counter would break its FI read-back (`secure/src/crypto.rs:94-96`).
- Evidence pq1 lacks it. No ceremony module or design document exists.
- Precedent. None. The cited Trezor `ContinueOnErrors` is used only in backup flows.
- Hardware asks. None.
- Residual after it lands. Habituation. A companion that uses a different nonce key evades the nonce heuristic. A "repeat" banner can reassure wrongly if the first presentation was the malicious one.
- Not yet tracked. The parameters, the field-level diff page, the fee-only rule, and PIN re-entry as the escalation. #600 is labelled priority:high; P2 applies to the delta. The lenses priced cost at M and L; the final value is L.

**USB-09. Router fuzzing, USB rig, ES0499 row.**
- Threat. The NS router is the largest host-reachable parser and has no host tests. NS bugs are denial-of-service class by design.
- What to do. Refactor the router's `static mut` and raw-pointer state into an owned struct behind an NSC trait (#313), then fuzz the composed path with a mock gateway (#588). Oracle: the router still answers a fresh GET_VERSION after any frame sequence, and `ensure_trailer_skeleton` never exceeds `per_cmd_chain_bound`. Build the Cynthion or Facedancer rig (#590). Re-cite `docs/security/threat-model.md:373` to the `synopsys-usb-otg` 0.4.0 dependency and add a check that fails on an unreviewed version or checksum change.
- Dropped parts and why. "Implement ES0499 or fork the crate" rests on a false premise for one lens: single-packet transfers and flush-on-reset exist in the dependency (`endpoint.rs:125,138`, `bus.rs:89`; spot-checked for this report). The other lens and the inventory read the row as a claim with no code, because they searched only `nonsecure/`. "A wedge that survives power-cycle" is dropped: router state is RAM only (`nonsecure/src/usb/commands.rs:116-172`).
- Evidence pq1 lacks it. The NS crate has no `[lib]` target and no tests; 13 fuzz targets stop at `shared`.
- Precedent. Trezor's host-compiled decoder and HID class, cited above.
- Hardware asks. Bench equipment only; the proposal estimated about USD 300. No board change.
- Residual after it lands. A mock-gateway fuzz cannot find a signing or disclosure bug. Rig results must not reopen the descoped HID rate limiter without profiling evidence.
- Not yet tracked. The row correction and pin check; the stronger oracle; the crate shape with its follow-on gateway-ABI join and NS-slot re-measurement. The lenses gave P2 and P3; the final value is P3.

### Covered in other sections

- M06, random-delay desynchronisation and dispatcher-entry jitter, P2, section 3.
- M09, verify-before-first-power tool and host-verified birth record, P0, section 1.
- M12, PIN back-off and cooldown on dismissed host unlock prompts, P3, section 8.
- M19, make existing assurance gates execute and block in CI, P1, section 11.
- M20, close the NS clock, power and tamper levers; voltage detection, P0, section 11.
- M21, fail-stop memory integrity (stack limit, ECC, SRAM option bits), P1, section 11.

### Considered and rejected

No item on this surface has status rejected. These parts were dropped, and the facts behind them constrain future designs:

- **Central policy in `dispatch`** (USB-06 part 1). There is no dispatcher on silicon; no command number crosses into the secure world.
- **Unknown-command anomaly counter with lock** (USB-06 part 4). Unknown INS bytes are rejected in NS (`nonsecure/src/usb/commands.rs:346-361,398`), so a counter there is attacker-held. It would add a host-triggerable lock while #715 is open and would write host-triggerable entries into a ring that is readable unauthenticated (#719).
- **QEMU test for reentrancy** (USB-01). The mailbox cannot be preempted, and tests inside `secure/src/nsc` never run because the module is `#[cfg(not(test))]`.
- **Clear-on-lock ring, page-hash fingerprint, hold-to-sign** (USB-08). Host-inducible reset, fee pages break matching, and the gesture decision forbids a hold.
- **Standing owner decisions.** The HID OUT token bucket was descoped 2026-05-28 because it false-trips chained transfers. USB stays in NS on OTG_FS with no DMA. A Trezor-style split that trusts NS is declined. Host transport encryption is deferred.

### Open questions and unmeasured claims

- The USB-01 swap has no proof of concept on silicon. Nested stack depth is UNMEASURED; an overflow would fault closed. Whether the STM32U585 implements both banked SysTicks was not checked against the datasheet. Lead note added after this section was written: Trezor runs a SysTick in both its secure monitor and its non-secure kernel on the same STM32U5 family (trezor-firmware `core/embed/sys/task/stm32/system.c:70`, `docs/core/embed-arch/embed-arch.md:57`), so the non-secure timer the attack needs exists on this silicon family.
- Whether the deref-site re-validation noted in #84 covers `cmd_pin_attempt_log` was not checked.
- The two USB-09 verifier lenses disagree on whether `docs/security/threat-model.md:373` describes existing code. The post-transfer `XFRSIZ` assert claimed at `docs/security/threat-model.md:376` and the ES0499 sub-section numbers were not checked. `endpoint.rs:106` carries a "TODO: flushing FIFO".
- GTZC enforcement has no silicon receipt on the shipping feature combination or after the configuration lock (#390).
- The PendSV re-unlock runaway guard has never been exercised on silicon (#692, #700).
- Owner decisions pending: #719 (unauthenticated PIN-attempt log), the USB-08 friction UI, and whether batch, off-chain and forced-blind signs count as ceremony attempts.
- The `ui-px` image is 76,949 B over its slot, which bounds any USB-08 UI. Whether pq1's HID transport re-arms only after consume is unchecked.

---

## 11. Systemic defences: environment sensing, memory integrity, assurance gates

Evidence level throughout: confirmed by code reading, not on silicon, unless stated. No true `mode-production` image builds today (OPTIGA S-2 fence), so "reachable" refers to the ship feature set (`Makefile:2718`).

### What pq1 does today

**Implemented.** A fail-closed three-source random number generator (`secure/src/rng_strong.rs:1-51`) with a per-PR consumer allowlist (`scripts/rng_consumer_audit.py:1-50`). A secure-owned independent watchdog, IWDG (`secure/src/hw/iwdg.rs:156-240`). Reset-cause classification (`secure/src/reset_cause.rs:1-70`). HardFault and non-maskable interrupt (NMI) handlers that zeroize and reset (`secure/src/main.rs:4637-4691`). An illegal-access controller wired to the intrusion wipe (`secure/src/hw/tzic.rs:227-260`). Fault-injection (FI) primitives (`secure/src/fi.rs:86-330`). About 40 `compile_error!` never-ship fences (`secure/src/nsc/mod.rs:95-945`).

**Partial.** Internal tampers (TAMP) force a dual-SE wipe in shipping builds, but TAMP has never run on silicon (#391), shipping polls at 1 ms (no `tamp-irq` in `Makefile:2662`), the LSE clock tamper is vacuous on an LSI-clocked RTC (`secure/src/hw/tamp.rs:238-258`), and three analog-watchdog tampers have no ADC4 driver. The PIN-attempt reason ring is RAM-only (`secure/src/pin_attempt_log.rs:19-27`).

**Absent.** Programmable voltage detector (PVD), a pinned brown-out reset (BOR) level, a stack limit register (MSPLIM), SRAM error-correcting code (ECC), flash double-ECC handling, secure attribution of the clock, power and system-config blocks (RCC, PWR, SYSCFG), any persistent fault record.

**Exists but does not run.** About 30 of 68 enrolled gates are `local_documented`, several more run in no workflow (defect table), and `master` has no branch protection.

**Docs claim, code does not show.** CLAUDE.md invariant #10 calls geometry "CI-pinned" (#720). CLAUDE.md calls the idle timer an "S-only TIM"; it is the secure SysTick on the core clock (`secure/src/timeout.rs:3`). `docs/security/brownout-hardening.md:321` says SRAM ECC is "always active". `docs/security/HARDENING.md` §4.4-4.7 states BOR, PVD and temperature sensing as requirements with no status; none exists. Drift also runs pessimistic: `docs/security/threat-model.md:508-509` and `brownout-hardening.md:314` call TAMP log-only and IWDG absent; both are stale.

**Where pq1 is ahead.** The Trezor data records no equivalent of the gate-enforcement meta-gate (`scripts/check_gate_enforcement.py:1-40`), the hardware-assumption ledger, the locked Kani census or the Lean on-chain proofs. pq1's tamper response destroys the SE shares; Trezor only reboots (`core/embed/sec/tamper/stm32u5/tamper.c:268-275`).

### What Trezor, Ledger and others do that pq1 does not

Trezor, on the same STM32U5:

- Secures RCC, PWR, SYSCFG (`core/embed/sec/trustzone/stm32u5/tz_init.c:296-326`) and RAMCFG, ICACHE (`tz_init.c:271-281`).
- Arms PVD level 5 in all three boot stages (`core/embed/sys/pvd/stm32/pvd.c:28-56`); pins BOR level 4 (`core/embed/sec/option_bytes/stm32u5/option_bytes.c:41-45`).
- Sets MSPLIM at reset (`core/embed/sys/startup/stm32u5/startup_init.c:336`), re-bases the stack pointer on overflow (`core/embed/sys/task/stm32/systask.c:823-840`), clears unused stack (`startup_init.c:349`).
- Decodes flash double-ECC errors in NMI, region-scoped in the loaders (`systask.c:877-900`).
- Keeps secret RAM in SRAM2 with ECC and reset-erase on (`core/embed/models/T3T1/memory.ld:42`, `option_bytes.c:78-84`; polarity taken from #48, likely, not certain).
- Checks every option register for exact equality at each boot (`option_bytes.c:60-83`).
- Shows a RAM postmortem on its fatal screen (`systask.c:509-560`).
- Runs a two-sided mock-RNG marker scan (`.github/workflows/core.yml:112-121`, `:180`) and nightly hardware-in-the-loop tests (`.github/workflows/core-hw.yml:52-116`).

Trezor does not: configure ADC4 analog watchdogs, so its tampers 7/12/13 are inert too (`tamper.c:138-140`); set TAMPSEC (`core/embed/sec/secret/stm32u5/secret.c:178`); persist any fault or tamper counter (`core/embed/sec/telemetry/stm32u5/telemetry.c:27-105` holds battery data only); erase storage on tamper.

Ledger runs emulated instruction-skip and stuck-at sweeps in CI with [rainbow](https://www.ledger.com/blog/fault-injection-simulation); its secure-element sensors are closed. [LSB-024](https://donjon.ledger.com/lsb/024/) shows a merged fix missing from a tagged build. The [Coldcard RNG failure](https://engineering.block.xyz/blog/predictable-rng-fallback-and-32-bit-reseed-in-coldcard-firmware) was a build macro that no binary gate caught. Nordic nRF54L and TI CC27xx ship on-die glitch detectors (vendor claim).

### Live defects confirmed on this surface

| Defect | Evidence | Reachable in the shipping feature set? | Severity | Tracked |
|---|---|---|---|---|
| RCC, PWR, SYSCFG non-secure: NS can reprogram PLL and prescalers | No SECCFGR write in any image; `secure/src/hw/rcc.rs:10` | Yes, given NS code execution; use against signing not demonstrated | Medium-high | #269, #80 (whose body gives a wrong SECCFGR address, the HSI trim register) |
| NS can stretch the 120 s idle wipe by slowing the core clock | `secure/src/timeout.rs:3,27`; `secure/src/main.rs:852-866` (desk-derived) | Same | Low-medium (skeptic; merger: medium) | none |
| TAMP unsecured: NS can disable or clear tampers | `secure/src/hw/bhk.rs:420-421`; RM0456 §64.4.5 | Yes by code and manual | Medium | #81, #50 |
| Tampers 7/12/13 enabled, can never fire | `secure/src/hw/tamp.rs:290-307` | Yes | Low | none |
| PVD off; BOR level absent from ship profile | `shared/src/lockdown.rs:338-345`, `:517-522` | Yes; frozen per die at RDP-2 | Medium | #49 |
| `tamp`+`tamp-wipe`+`bhk` co-enabled with tampers 6/9 in erase mode | `Makefile:2662`, `:2718` versus #208 | Ship set only; never run | High if it fires; probability UNMEASURED | #208 |
| FLASH_ACR NS-writable by design: wait-state lever survives (skeptic) | RM0456 §7.9.1; `secure/src/hw/rcc.rs:181-183` | Yes, given NS code execution | Medium | none |
| BOR reset classified Cold, no scrub (skeptic) | `secure/src/reset_cause.rs:182-185` | Yes | Low-medium | none |
| NMI handler ignores FLASH_ECCR and its comment says no NMI source is armed (`:4643`); FSBL has no exception handlers | `secure/src/main.rs:4636-4656` | Conditional on double-ECC raising NMI (#94) | Medium (availability) | #94 |
| Option-byte verifier ignores SRAM erase and ECC bits; the only bench recipe sets the NS bank's bit (`Makefile:364-380`) | `shared/src/lockdown.rs:295-312` | Not yet (`rdp2-self-lock` quarantined) | High, irreversible once shipped | partly #82, #46 |
| Stack residue never cleared (the "scrub skipped on Cold" half is denied) | `secure/src/nsc/mod.rs:1729-1744` | Yes; needs physical readout | Low | none |
| `fi_min` recompute guard compiled away; gate script never committed | `pqsigner-fi/src/lib.rs:238-249` (master); `Makefile:4480-4485` | Yes; NS USB length clamps only | Medium-low | #130, #777 |
| 165 rollback and geometry tests and the FSBL geometry gate run nowhere | `.github/workflows/ci.yml:219-227`, `:268-277` | Process | Medium | #720, #721, #725 |
| Nightly Kani red 40 runs, since at least 2026-09-01 | run 38045775090 | Process | Medium | #776 |
| FI harness does not build; sign target differs from production | `tools/sca/fi_target/src/main.rs:33-38`; `tools/sca/c10_sign_target/src/main.rs:97,99` | Tooling | Medium | none |
| Never-ship audit and ABI check unenrolled; no branch protection | `tools/build-evt-image.sh:83` is the sole caller | Process | Medium | #456, #690 |
| PIN digit and seed letters drawn via an uncovered secret-indexed glyph path | `secure/src/ui/px/status_map.rs:288-289`, `:303-309` | `ui-px` only | Medium | #784 |
| `tamp::init` clears sticky tamper status unread | `secure/src/hw/tamp.rs:272` | Yes | Low | none |

### Recommendations

| ID | Recommendation | Kind | Cost | Priority | Novelty | Tracked issues |
|---|---|---|---|---|---|---|
| M20 | Deny NS the clock, power and tamper levers; PVD-5 over BOR-3 with SRAM-only zeroize; ADC4 watchdogs log-only | firmware | L | P0 | parity | #47 #48 #49 #50 #70 #75 #79 #80 #81 #82 #150 #208 #227 #248 #256 #269 #366 #391 |
| M21 | Fail-stop memory integrity: MSPLIM, decoded ECC NMI, ECC secret bank, SRAM option bits in the ship profile | mixed | L | P1 | parity | #21 #46 #48 #82 #92 #93 #94 #124 #150 #178 #230 #248 #268 #366 #374 #397 #484 #540 #542 #543 #544 #545 #705 |
| M19 | Make existing assurance execute and block | process | L | P1 | parity | #10 #70 #81 #130 #136 #186 #189 #211 #232 #237 #239 #258 #260 #296 #312 #335 #389 #450 #451 #456 #558 #591 #592 #593 #604 #633 #635 #664 #680 #690 #701 #720 #721 #722 #723 #724 #725 #735 #771 #776 #777 #784 |
| SYS-06 | Bounded, reboot-surviving fault and tamper forensics | firmware | L | P2 | parity | #47 #50 #75 #208 #248 #366 #484 #540 #634 #705 #715 #719 #723 #758 |

**M20. Environment sensing.** P0 covers stages A and B; stage C is P2. Merger said kind mixed, skeptic firmware; final firmware.

- **Threat.** NS code can re-clock the core under secure crypto and disable tampers. A USB-fed rail can sag unseen above the 1.71 V default BOR.
- **What to do.** Stage A: write RCC, PWR, SYSCFG SECCFGR and RCC_PRIVCFGR, TAMPSEC (preserving BHKLOCK), RTC_SECCFGR, plus RAMCFG and ICACHE (#150), then lock. Move `rcc.rs` and `reset_cause.rs:19` to the secure alias, because later NS-alias access reads as zero. Re-assert FLASH_ACR latency at every gateway entry. Compile out the NS RCC read (`nonsecure/src/main.rs:190`), which would otherwise trigger a wipe. Add `tamp-irq` at `Makefile:2662` and `:2718`. Stage B: BOR level 3 with PVD level 5; the handler zeroizes SRAM and resets, with no flash write and no SE traffic. Put BOR_LEV and SRAM_RST=0 in the ship profile, first-boot Phase A and the FSBL tripwire. Mask PVD during the RDP-2 write. Stage C: ADC4 watchdogs on internal channels as a slow supply and temperature tamper, log-only until #391.
- **Dropped parts and why.** Wipe on supply events, BOR4+PVD5, ADC4 as glitch detector, clock security, FSBL PVD; facts under "Considered and rejected".
- **Evidence pq1 lacks it.** Defect rows 1 to 8.
- **Precedent.** Trezor for RCC, PWR, SYSCFG, PVD, BOR. TAMPSEC, SLEEPDEEPS and ADC4 exceed Trezor, so "parity" holds for stages A and B only.
- **Hardware asks.** Optional rail divider to an ADC4 pad (only PA6 qualifies; it carries the consumption mask). Confirm the VBAT tie and FLAGB polarity (PB10). EVT sweeps: rail, host, cable, thermal.
- **Residual after it lands.** Nanosecond crowbar, EM, laser and split-pulse faults ([mu-Glitch](https://www.usenix.org/system/files/usenixsecurity23-sass.pdf)) pass under PVD and BOR. Nothing detects VCORE or HSI injection. An attacker can cut power after a trip and retry. A mis-set BOR level is permanent.
- **Not yet tracked.** ADC4 watchdogs; BOR_LEV as a hard gate; the BOR3+PVD5 choice; the SRAM-only handler rule; FLASH_ACR re-assert; BOR-reset scrub; PVD priority (it ties with SysTick, `secure/src/main.rs:886`); NS erase of the BHK through BKERASE (lead); the alias move.

**M21. Memory integrity.** Merger said cost M, skeptic L; final L.

- **Threat.** The secure stack grows into `.bss`, where `STATE` holds the master secret (`secure/src/nsc/state.rs:542`); its worst case is unproven (#374). SRAM1 has no ECC, and [SLasH-DSA](https://arxiv.org/abs/2509.13048) forges SLH-DSA from bit flips in signing state.
- **What to do.** Phase 0, before any die self-locks: add SRAM_RST=0, SRAM2_RST=0 and the chosen ECC bit to the option-byte field list, ship profile, Phase A verifier and RDP-0 check. Phase 1 (cost S, first): set MSPLIM_S from cortex-m-rt's `_stack_end`; make fault entry safe on an exhausted stack (UsageFault with re-base, or a naked HardFault trampoline); set MSPLIM_NS at handover; test on QEMU. Phase 2: log FLASH_ECCR in NMI before reset; define a fail-safe for a persistent double error in pages 123-127; region-scope in the replacement FSBL (#542). Phase 3, redesigned by the skeptic: put all secure RAM including the stack in an ECC bank, by relinking into SRAM3 or by a Trezor-style SRAM2 swap. Phase 4: enable `zero-init-ram`; clear unused stack on lock, idle wipe and fault.
- **Dropped parts and why.** SRAM2 as first written, Cold-reset scrub, page-123 tag; facts below.
- **Evidence pq1 lacks it.** MSPLIM appears only in two comments (`fsbl/src/main.rs:172`, `fsbl/src/manifest.rs:30`); defect rows 9 to 11.
- **Precedent.** Trezor ships MSPLIM, the re-base, the ECC decode and an ECC secret bank.
- **Hardware asks.** No board change. One sacrificial pq1 die for option-bit polarity and the torn-quadword test (#544). A debug-access bench board (no LCD, so evidence comes from UART).
- **Residual after it lands.** Faults on registers, instructions and peripherals; the same fault in both signing passes; invasive probing; reset as denial of service. A lockup is bounded by the 2 s watchdog, not indefinite as the merger implied.
- **Not yet tracked.** MSPLIM in any world; safe fault entry; SRAM bits in the verifier; ECCR decode; stack inside the ECC bank; `zero-init-ram`.

**M19. Assurance gates.**

- **Threat.** Vacuous green: a refactor reopens an FI fold, a dev-feature leak or a geometry regression, and merges.
- **What to do.** Step 0: owner enables required checks, which under direct-to-master forces pull requests or a merge queue. Step 1, rewritten by the skeptic: do not commit the worktree `black_box` patch as-is, because on thumbv8m the recompute folds back to the pre-barrier value and the host-only gate passes it. Recompute from `black_box(a)` and `black_box(b)`; make the gate compile for thumbv8m at `opt-level=s`. Step 2: enrol the never-run oracle, the never-ship audit (two-sided, on its own dual-SE build; the `make build-hw` image fails its positive controls) and the ABI check, each declared in `scripts/gate_enforcement.json`. Step 3: run the rollback, geometry and sphincs-c10 feature suites and `make fsbl`. Step 4: per-harness Kani timeout and memory limit, and a defined consequence for a red nightly. Step 5: repair the FI harness; sweep small gates exhaustively, signing as a sparse sample with stated coverage. Step 6: glyph-path leakage gate, address model only.
- **Dropped parts and why.** Exhaustive signing sweep and its pass rule; closing #130 (refuted: the fix was never committed).
- **Evidence pq1 lacks it.** Defect rows 12 to 17.
- **Precedent.** Trezor's marker scan; Ledger's rainbow CI. The [TF-M FIH design](https://nrfconnectdocs.nordicsemi.com/ncs/latest/tfm/design_docs/tfm_physical_attack_mitigation.html) warns that optimisation removes redundant checks. No vendor publishes a leakage gate on its glyph path; that sub-item is beyond parity.
- **Hardware asks.** None. One self-hosted runner, scheduled triggers only (public repository).
- **Residual after it lands.** No on-device defence is added. Emulation does not model the HASH peripheral. The true production image stays unauditable until S-2 closes.
- **Not yet tracked.** The defeated `fi_min` fix and its thumbv8m gate; a blocking mechanism for scheduled jobs; per-harness Kani limits; two-sided audit enrolment; the ELF-structural FI gate.

**SYS-06. Forensics.** Proposed P1 and M; both verifiers say P2 and L. Kind: one verifier said mixed, final firmware. "Parity" is overstated: Trezor persists no fault or tamper record.

- **Threat.** A returned unit cannot explain a lockout (#715); every diagnostic dies in the security reset. This is a diagnostic, not a defence.
- **What to do.** Cheap slice for #715: fold the sticky tamper status before `tamp.rs:272` clears it; capture fault-status registers after zeroize into backup registers 8-31 or a no-init SRAM mailbox with magic and CRC; expose through the existing PIN-less command (`proto/src/lib.rs:123`). Capture the program counter only for secure-origin frames. Bound every counter, because NS can trigger faults at will. Render reasons in the secure world.
- **Dropped parts and why.** Page 127, "non-erased" backup registers, FSBL reason line; facts below.
- **Evidence pq1 lacks it.** `secure/src/main.rs:4682-4691` discards the exception frame; `secure/src/hw/tzic.rs:83,88` are SRAM statics.
- **Residual after it lands.** With no battery, cutting power after a glitch destroys the record.
- **Not yet tracked.** All of it, plus two owner decisions: a page for any wipe-surviving record, and PIN-less readability of a persistent record. #719 rests on RAM residency (`secure/src/pin_attempt_log.rs:47-50`) and must be re-taken.

### Covered in other sections

- M04, fault response without attempt-charging: P2, section 3.
- M05, FSBL pre-freeze FI bundle: P1, section 3.
- M06, random-delay desynchronisation: P2, section 3.
- M08, erased-tail check on the selected slot: P3, section 9.
- M18, user-supplied entropy: P3, section 7.

### Considered and rejected

No item written here is rejected outright. Parts dropped inside them:

- **Supply or analog events feeding the intrusion wipe.** That path writes flash during the sag and factory-resets both SEs (`secure/src/hw/tzic.rs:204-258`); a marginal cable would wipe wallets.
- **BOR level 4 with PVD level 5 (Trezor's pair).** The thresholds coincide, so the handler races the reset. Numbers come from a round-1 datasheet extract, not re-read.
- **ADC4 as a glitch detector.** Sampling floor is at least 12.65 µs; glitches last 100 to 400 ns.
- **Clock security system.** pq1 uses no HSE or LSE.
- **PVD or a reason line in the FSBL.** The FSBL holds no secrets, is size-bounded, and freezes at RDP-2.
- **Any new record on bank-1 page 127.** It is the append-only first-boot journal holding the OPTIGA salt (`secure/src/flash_policy.rs:3-7`). The wipe erases pages 124 and 125. Bank-2 page 127 is const-asserted erased (`geometry/src/lib.rs:291-295`).
- **Backup registers "outside the erased set".** No such set exists: CR3=0 erases all, and 0-7 hold the BHK.
- **Secrets in SRAM2 as first written.** SRAM2 is the NS bank (`secure/src/sau.rs:436-440`). The skeptic reopens it as a full bank swap.
- **Boot scrub on Cold resets.** A no-op: startup zeroes `.bss` on every reset.
- **A DHUK tag over page 123.** Dropping the newest record with its tag leaves a valid pair. Moved to #93 and #230; the page-124 marker moved to #397 at P3, not refuted.
- **Exhaustive signing sweep.** About 2.6k years in emulation. The pass rule "the compare catches a fault iff the seeds differ" is also wrong: the shuffle permutes only chain and tree order.

### Open questions and unmeasured claims

- Does a flash double-ECC error raise NMI unconditionally on the STM32U585? Not re-read in the reference manual, not measured (#94).
- Option-bit polarity for SRAM_RST and ECC, ECC RAM initialisation, and NS write access to TAMP and PWR: not verified on silicon.
- False-trip rate of the crypto-fault tamper with the BHK loaded: UNMEASURED. PVD and BOR false positives across USB hosts and cables: UNMEASURED.
- Worst-case secure stack depth, and whether the secure world fits in 64 K: unknown (#374).
- The `fi_min` findings come from standalone probes, not the linked NS image. Glyph-path leakage: UNMEASURED.
- Owner decisions outstanding: binding checks versus direct-to-master; BOR level (`docs/hardware/evt-silicon-validation.md:792` asks for 4 or above); the secret RAM bank, which gates the ship option-byte profile; a persistent PIN-less record.

---

## 12. Completeness pass: additional items and corrections

A completeness critic reviewed the consolidated recommendations and named 12 missing topics, 9 priority corrections and 12 unverified claims. Follow-up finders turned 10 of the 12 topics into 19 proposals (X1a to X10b; topic 3 produced one). An independent skeptic reviewed each one against the code.

Result: no proposal was refuted. All 19 survive, 16 of them with a different priority, cost or kind than proposed. Two critic topics produced no proposal. Several sub-parts of surviving proposals were struck and are listed under "Rejected in the completeness pass".

Evidence level throughout: confirmed by code reading, not on silicon, unless stated. Most skeptic verdicts are single-reviewer. The finders and several skeptics record that the advisor tool was rate-limited, and two skeptics (X2a, X10b) record that the codex MCP server was down.

Where the proposer and the skeptic disagree, the table carries the skeptic's corrected value and the item paragraph shows the change as "proposed, then final".

### Surviving extra items

| ID | Surface | Recommendation | Kind | Cost | Priority | Novelty | Tracked issues |
|---|---|---|---|---|---|---|---|
| X1a | display / implant / se | Masked blind binary restore of an existing 24-word phrase: 264 button bits under a per-bit on-screen mask, no echo. Defeats an unadapted, display-only bus tap | firmware | M | P3 | beyond (mechanism only) | #250 #784 #237 #371 #700 #772 #258 #370 |
| X1b | display / implant / se | Owner decision on a two-share create mode (panel shows only the device share, user share entered blind), and a recorded decline of the USB-pad shape | mixed | M | P3 | beyond | #371 #250 #237 #772 #700 |
| X2a | fwupdate | `fwsign`: redundant compute in a second process, stored-signature equality, and a same-top-leaf archive sweep, as an acceptance criterion of the production signer | process | M | P2 | beyond | #69 #225 #486 #266 #592 #611 #368 |
| X2b | systemic | Vendor-key custody decision record in #69, plus a `fwsign` `digest` / `assemble` split. Appliance firmware is a later, owner-gated item | mixed | M | P2 | beyond | #69 #225 #486 #67 #266 #541 #263 |
| X3a | usb / systemic | Pin the set of prompt-free key-derived gateway outputs to exactly CMD 15, and amend the acceptance record. The WON'T-FIX is not reopened | process | S | P3 | parity | #181 #89 #724 |
| X4a | systemic | State the R-incarnation few-time caveat beside P14 and correct the claim sites that call the slot cap a true per-key cap. Fold into #89 | process | S | P2 | parity | #89 #179 #180 #182 #131 |
| X4b | pin | Bind the page-123 journal key to a public wallet tag before launch. Keep the page on wipe. Decommission erase is a later, gated part | firmware | M | P3 | beyond | #182 #180 #634 #123 #168 #106 #107 |
| X5a | display / clearsign | Paint pixel dialogs only from glyph bytes that went through the hasher, and attribute and lock the GPDMA channels | firmware | M | P2 | beyond | none for the atlas window; adjacent #53 #79 #152 #835 #261 #792 #760 |
| X5b | usb / display | BASEPRI_S mask across every verify-paint-proof bracket and the PendSV re-unlock dialog, comment fixes, silicon test with a negative control | firmware | M | P2 | parity | #152 #835 #700 #692; closed #132 #468 #729 |
| X6a | systemic / clearsign | Document pq1 as a required owner of a k-of-n Safe on the shipped on-chain `approveHash` route, with a threat-model row and a real-Safe test | process | M | P2 | parity | none for the topology; adjacent #332 #636 #384 #486 #680 #603 |
| X6b | systemic / clearsign | Defer the off-chain EIP-1271 Safe co-sign route, add no gap carve-out, add a dbgen refusal of the SafeTx typed format, correct the adapter claim | process | S | P2 | parity | #179 #381 #89 #691; closed #693 |
| X7a | clearsign | Injective `personal_sign` rendering: labelled hex mode, visible line breaks, byte-length row, fallible renderer | firmware | M | P2 | parity-plus (skeptic) | #154 |
| X7b | clearsign | Structured Sign-In with Ethereum (SIWE, EIP-4361) pages with address and chain consistency checks, shown before the raw message | firmware | L | P3 | beyond | #154 (dependency); no SIWE issue |
| X8a | fi | Secure memory protection unit (MPU) execute-never on secure SRAM, plus a stack-guard region, split out of #277 | firmware | S | P2 | parity | #277 #374 #54 #540; new issue needed |
| X8b | fi | Decide FSBL-side execute protection before the freeze, as a default-deny MPU table, folded into M05 / #542 | firmware | S | P3 | parity | #540 #542 #54 #277 #374 #591 |
| X9a | fwupdate | Make FSBL C10 verifier correctness a freeze-gate line in M07: gate-specific near-miss negatives first, then the 246-vector corpus replay, mutation testing, a written proof scope | process | S | P2 | beyond | #304 #722 #290 #581 #541 #486 #367 #540 |
| X9b | fwupdate | Add an unticked owner box to the M07 note: FSBL signature-algorithm agility accepted or declined at freeze review, with its consequence | process | S | P3 | parity | #486 #696 #541 #540 #581 |
| X10a | systemic | FSBL pre-freeze claims ledger, report-only in the geometry gate, with an authority column; the #541 combined link stays the verdict | process | S | P2 | beyond | #541 #540 #758 #752 #591 #705 #366 #226 #542 |
| X10b | systemic | Secure-slot and secure-stack admission ledger, re-based on the shipping profile and folded into #752 and #374 | process | S | P2 | parity plus a small process delta (skeptic) | #374 #752 #540 #758 #382 #785 #781 #482 |

### Item notes

**X1a. Masked blind binary restore.** Priority P2 proposed, P3 final; cost M; skeptic confidence 0.7.
Threat: a passive logic-level tap on the NV3007 display SPI bus, the one implant class the study records as confirmed in the wild. Every seed-bearing wizard screen puts seed glyphs on the bus today: `secure/src/main.rs:979` and `:988` (create), `secure/src/main.rs:998-1000` (restore is `enter_mnemonic` only), and `secure/src/ui/seed_wizard.rs:129-170` shows `choose_setup_mode` has two options. No issue tracks a bus-free restore.
What to do: add an opt-in restore option. The user enters the 264 BIP-39 index bits one press at a time. Before each bit the device draws a fresh mask bit and shows only the mapping. The secret bit is the press XOR the mask, and nothing derived from it is rendered. The skeptic's corrections change the item in these ways:
- Scope it to restoring an existing valid 24-word phrase whose wallet address the user already knows. The offline dice or coin claim is struck: a hand-generated 256-bit seed has no valid 24th word until SHA-256 is computed, and `from_indices` rejects a bad checksum (`bip39/src/full.rs:200-206`).
- State the claim as "defeats an unadapted, display-only tap". On the pq1 package the two button pins are 10 and 11 and the display pins are 14 to 20 on the same edge (`secure/src/board/pq1.rs:97-112`, `216-220`), so an adapted implant needs two more wires.
- Replace whole-phrase retry with per-word double entry under independent masks (528 presses). At a 1% slip rate, 264 blind presses succeed about 7% of the time.
- Show both labels symmetrically and repaint on a fixed cadence, because press timing is visible on the display bus alone.
- Fix the button model: a hold over 500 ms becomes Long (`secure/src/hw/buttons.rs:183-189`), so Long-left as undo silently deletes a bit on a slow press.
- Ship on the legacy 16x4 path first. Add a scoped row beside `docs/security/user-device-verification.md:163-168`; do not replace the residual sentence.
Precedent: Trezor Model One [advanced recovery](https://trezor.io/learn/a/advanced-recovery-on-trezor-model-one) splits a secret between a trusted device screen and an untrusted host. The skeptic calls that an analogy across trust domains, not parity.
Residual: a tap on the display bus plus both button nets recovers everything. PIN entry still renders digits on the same bus. M10 and M11 stay necessary. The skeptic did not trace the button routing in the schematic or PCB layers and states that the core fails if the buttons share the display flex. That check comes before filing.

**X1b. Two-share create mode, and decline of the USB-pad shape.** Kind firmware proposed, mixed final; cost M; priority P3; skeptic confidence 0.72.
Threat: the same display-bus tap on the create path, where the device generates the seed. `secure/src/main.rs:962-990` always displays the full seed.
What to do: put an owner ruling on the record under #371 (ceremony changes need one, #772). The candidate mode: the user enters a 256-bit coin-flip share U through the X1a dialog first, the device draws its share D with the unchanged `rng_strong::fill(&mut entropy)`, the panel shows D only, and the seed is D XOR U. The skeptic's corrections:
- The "combine on paper" claim is wrong for the last word, which carries 8 checksum bits. The on-device two-share restore is therefore mandatory scope, not optional.
- U has no checksum, so a wrong U yields a different valid wallet silently on restore as well as on create.
- Chunked double entry is required; unchunked 256 bits entered twice will mismatch often.
- Keep U across quiz retries (`secure/src/main.rs:977-995`), and zeroize it on all exits.
- The existing `decoy-frames` feature (`secure/src/ui/seed_wizard.rs:300-368`, `:428`; `secure/Cargo.toml:541`) must be cited. It is off by default and does not defeat a digital tap.
- Scope it to the legacy dialogs or require a PQ-UI design first. Standalone cost is L.
Precedent: Coldcard [Seed XOR](https://seedxor.com/) is precedent for the backup format only. Coldcard [dice mode](https://coldcard.com/docs/verifying-dice-roll-math/) is precedent for a user-entered share. Neither withholds the seed from the display.
Residual: the second tap is two passive wires. A display tapper who holds D can test guesses of U offline against the public address, so U needs full real-coin entropy. Losing either sheet loses the wallet. The mode protects the seed only. The skeptic assessed the masked dialog only as described, did not re-fetch seedxor.com, and states the main value is the recorded decision.

**X2a. `fwsign` redundant compute and stored-signature equality.** Priority P1 proposed, P2 final; cost S proposed, M final; skeptic confidence 0.8.
Threat: a memory fault on the signing host during the one-shot vendor sign can yield a signature that still verifies but whose top-layer one-time (WOTS) key has signed a wrong bottom-tree root. C10 has one top tree of 512 WOTS keys (`sphincs-c10/src/params.rs:22-31`; `sphincs-c10/src/hypertree.rs:266-270`). A later valid signature in the same top leaf gives two messages under one WOTS key, which is the grafting precondition, under a key the frozen FSBL trusts with no rotation path (#486).
Evidence pq1 lacks it: `fwsign/src/subcommands/sign.rs:261-273` signs once and only self-verifies; `fwsign/src/keystore.rs:129-132` uses the deterministic `None` path; the ledger at `sign.rs:355-381` stores neither digest nor signature and is never read back; `docs/security/threat-model.md:211` and `:317` scope double-compute to Type 1 / Type 2 only.
What to do, with corrections folded in: re-open the key blob and sign in a second process, require byte equality of the two 4008-byte signatures, then verify. Key the ledger on (vendor fingerprint, digest), make it fail closed for a production key (`record_signing` silently skips when the directory is missing, `sign.rs:358-361`), and record the top-leaf index. The archive sweep must check that any two published signatures sharing a top leaf carry identical layer-1 WOTS bytes; that is checkable from public data. Bind all of this to the production signer spec (#225 and the Draft 1.1 V6 signer) as a named acceptance criterion, because the target today is the legacy bench signer. The two-machine mode becomes an owner decision under #69 / #266, since it copies the non-rotatable key to a second host. The doc fix at `threat-model.md:211`, `:317` is independent and should land now.
Precedent: [RFC 9814](https://www.rfc-editor.org/rfc/rfc9814.html), [Genet, TCHES 2023](https://eprint.iacr.org/2023/042), and [SLasH-DSA](https://arxiv.org/abs/2509.13048).
Residual: the skeptic rates this as cheap hygiene on an unrecoverable key, not a live exposure. Rowhammer needs attacker code on the signing host, where key theft is more direct. Only a fraction of faulted signatures still verify. The forgery cost from two WOTS+C signatures is UNMEASURED; the skeptic's rough figure of about 2^18 grinding tries is explicitly unverified.

**X2b. Vendor-key custody decision.** Cost L proposed, M final for the near-term scope; priority P2; skeptic confidence 0.8.
Threat: the vendor key is a passphrase-encrypted file opened on a general-purpose PC (`fwsign/src/subcommands/sign.rs:207-212`; `fwsign/src/keystore.rs:103-116`). No hardware security module (HSM) implements bespoke SPHINCS+C10. `docs/firmware/how_to_make_update.md:15-41` gives only "an offline / air-gapped laptop".
What to do now (P2, S to M): write the custody decision record into #69 before any production key exists, and split `fwsign` into a keyless `digest` step and an `assemble` step that inserts an externally produced signature. `fwsign` has `extract-sig` but no insert path today.
The appliance options must be rewritten before they are costed, because three claims fail against the code:
- `c10_sign_verified` has no deterministic path (`secure/src/crypto.rs:206-269`), so "signs through `c10_sign_verified`" and "uses the deterministic `None` path" cannot both hold.
- Two appliances with identical keys are dual-witness consistency, not dual control. The FSBL accepts one signature (`fsbl/src/main.rs:336`), so either custodian can sign alone.
- An on-device tally is per unit, not per physical key, so it cannot be the #225 cap.
The record must also state: the at-rest trade (an 8-digit PIN on chips whose lifecycle lockdown is open, against Argon2id plus a passphrase), key format and import, bootstrap circularity, and that a production-mode dual-SE appliance image cannot be built today (`OPTIGA_S2_PRODUCTION_BLOCKED`, `secure/src/nsc/mod.rs:315`). The appliance firmware is a later owner-gated item at P3, cost L to XL.
Precedent: Trezor separates digest production from signing (`core/tools/trezor_core_tools/headertool.py:78-84`, `:179-190`). The proposer makes no claim about how Trezor holds its production keys.
Residual: the appliance wins against remote malware and loses margin against physical theft.

**X3a. Pin the prompt-free signer set to CMD 15.** Process, S, P3, parity; skeptic confidence 0.8.
The critic asked for a confirm, a page-123 tally or deterministic randomness on `CMD_GET_INIT_CODE`. That ask is not proposed; see "Rejected". What remains open: the owner acceptance covers one handler and nothing stops the set from growing.
Evidence: callers of a C10 signer in `secure/src/nsc` are `cmd_sign_userop.rs:2292/2418/2542`, `cmd_sign_userop_batch.rs:2448/2539/2656`, `cmd_sign_offchain.rs:1319` and `:1481`, `cmd_sign_userop_forced.rs:1387`, and `cmd_get_init_code.rs:266`. Only the last file has no confirm call. No test asserts this.
What to do: a host source-text test in `secure/src/nsc_small_cmds_pure_tests.rs` asserting set equality, plus a prompt column in `docs/audits/gateway-parsing-20260623-220401.md`, plus an additive dated note in the VULN doc. Skeptic corrections: enumerate every file under `secure/src/nsc/` (the `cmd_*.rs` glob misses `prodtest::*` and helpers); match raw `SigningKey::sign` too and allowlist `secure/src/fw_rollback_e2e.rs:80`; pin the count of signer call sites per file (3/3/2/1/1), because a file-level check passes a new silent branch inside a file that already confirms; run the negative control through the same classifier; add a set-equality check on the dispatcher arms (`secure/src/nsc/mod.rs:1815-1878`). The audit rows must add CMD 18, FW 20-24, CMD 1/11/12 and the prodtest set. The timing figure of about 12 to 17 signatures per 120 s window is the skeptic's estimate and must be marked EXPECTED. Correct the `lit_all.json` LSB-025 relevance text ("pq1 has no silent-sign flows"), which CMD 15 falsifies.
Precedent: Ledger [LSB-025](https://donjon.ledger.com/lsb/025/) and [LSB-022](https://donjon.ledger.com/lsb/022/), as an analogy for the audit practice only.
Residual: the test pins text, not behaviour.

**X4a. R-incarnation few-time caveat.** Process, S, P2, parity; skeptic confidence 0.82.
Threat: a claim-versus-code gap. The slot cap is enforced on device-local page-123 tallies (`aa/src/offchain_gate.rs:165-167`; `secure/src/nsc/cmd_sign_userop.rs:2061-2092`). Total per-key signatures are bounded by R x 65,536 for R page-123 states that started at zero, and the generic floor degrades as 96 - 2*log2(R). `Quantitative.lean:153-165`, the CLAUDE.md status sentence and `docs/security/threat-model.md:359` (residual "None") say otherwise. Only `secure/src/hw/flash.rs:1451-1461` carries the "per device incarnation" qualifier.
What to do, with corrections: fold into #89, whose open checkbox is this quantification. Define R by its real triggers: a distinct unit holding the seed, a torn page-123 compaction, or an external page erase before RDP-2. A wipe and restore on the same unit is not one of them, because no wipe path erases the page. Narrow the escape set to off-chain EIP-1271 signatures plus Type-2 signatures that were withheld or never passed validation; execution-reverted UserOps are counted (`PQSmartWallet.sol:505-515`). The Lean theorem must bound the generic `(q + q²)` term at `q ≤ R · MaxSlotUses` with R an explicit unenforced premise, not mirror the bootstrap theorem's linear-term shape. Add a new threat-model row, a companion retire-or-wipe step in section 11.6, and CMD 18 to the CLAUDE.md gateway table. The optional `userop_sigs` floor sync is split out as a separate firmware item (P3, S to M): it is a wire change and helps only with an honest companion.
Precedent: none in Trezor or Ledger. [NIST SP 800-208](https://csrc.nist.gov/pubs/sp/800/208/final) is a pointer only; the finder read the abstract and did not verify its cloning clauses.
Residual: nothing bounds R. The real limiter is one PIN unlock and one physical confirm per signature.

**X4b. Wallet-tagged page-123 key.** Firmware, M, P3, beyond; skeptic confidence 0.78.
Threat: `slot_key_compute` hashes account, chain and slot only (`secure/src/offchain_state.rs:23-33`), and `erase_offchain_page` has two callers (`secure/src/hw/flash.rs:1736`, `:2023`), neither a wipe. A device set up with a different seed inherits the previous wallet's registered flags, counts and the 128-slot budget.
The skeptic states the threat is not reachable on the ship profile today: a wiped production device cannot be re-provisioned (#168 plus the F1D0 lock) and no user wipe command exists in `proto/src/lib.rs`. The item is a pre-launch format decision. After launch a key change needs a migration of live few-time counters.
What to do: (a) now, cost S: add a tag derived from account-0 `masterPkSeed` (no keygen needed, already public), computed once at unlock and cached; switch all six key call sites together (`cmd_sign_userop.rs:2017`, `cmd_sign_userop_batch.rs:2173`, `cmd_sign_userop_forced.rs`, `cmd_sign_offchain.rs:263`, `cmd_offchain_sync.rs:110`, `cmd_offchain_status.rs:76`); keep the page on lockout and duress wipe; keep the distinct-slot cap global only, because a per-tag cap re-opens the page-123 exhaustion brick. (b) later: the decommission erase, gated on #634, #168 and #123, reachable only with a verified dual-SE wipe.
Precedent: none claimed.
Residual: does nothing for a same-seed clone on a second device (X4a). Under `duress-pin` the tag fixes a per-tuple deniability tell; the shared global cap remains a weaker one.

**X5a. Hashed-copy glyph painting and GPDMA lock.** Priority P1 proposed, P2 final; firmware, M, beyond; skeptic confidence 0.72.
Threat: a hostile non-secure (NS) image rewrites a glyph page after `verify_atlas` hashes it and restores it before `atlas_root_proof`. Both hashes pass and the user confirmed a frame with swapped characters. `window()` is a `'static` slice into NS flash (`secure/src/ui/px/assets.rs:54-65`), `verify_atlas_inner` re-reads NS flash after the hash (`assets.rs:129-142`), and nothing constrains NS inside the bracket (`secure/src/nsc/mod.rs:1086-1108`, `1126-1150`). Several paints have no after-proof (`screens.rs:108-116`, `lcd.rs:418-430`, `lcd.rs:574`, `lcd.rs:620-632`, `assets.rs:168-181`). The attack presupposes a compromised NS image, which is FSBL-measured and vendor-signed, and is unproven on silicon.
What to do, re-ordered by the skeptic: first (S, P1 for the ui-px gate), mask NS exceptions for the dialog (X5b) and set and lock the general-purpose DMA (GPDMA) channel attribution at boot, after checking the reset default and lock semantics in RM0456 and considering LPDMA1 and DMA2D. Second (P2), the capture as defence in depth. Evaluate a whole-container copy (75,128 B) before the per-transcript subset: it keeps `'static` lifetimes and covers every paint site, but needs a measured stack high-water under the double C10 sign, which does not exist. SRAM3 as a home for the copy and runtime block-based attribution of the atlas pages are both recorded as unverified options. Fix the stale claims at `assets.rs:13-18` and `sau.rs:716`. Open an issue; none covers the atlas window.
Precedent: no direct precedent. Ledger [LSB-023](https://donjon.ledger.com/lsb/023/) is a loose analogy, cited in the data and not re-fetched.
Residual: the GPDMA-writes-flash path is a hypothesis neither the finder nor the skeptic confirmed against RM0456 or on silicon. `ui-px` is outside `make release`, so this gates the pixel-UI port. The X5a skeptic judged X5b only from its description inside X5a; X5b is a sibling item in this pass.

**X5b. BASEPRI_S mask across the atlas bracket.** Cost S proposed, M final; firmware, P2, parity; skeptic confidence 0.77.
Threat: the CPU half of X5a. A banked NS SysTick or PendSV handler preempts secure thread mode parked in the dialog. No base-priority mask (BASEPRI), PRIMASK or FAULTMASK is used anywhere in `secure/src`, `nonsecure/src` or `fsbl/src`. The comment at `sau.rs:712-716` credits the `AIRCR.PRIS` bit with stopping NS preemption of a veneer, which is wrong.
What to do, with corrections: an RAII guard setting BASEPRI_S = 0x80 at the atlas call sites, not only at the veneers, because the idle re-unlock runs PIN entry from secure PendSV (`secure/src/main.rs:4490`) outside any veneer and paints through the atlas (`secure/src/ui/pin_entry.rs:183-184`). The source test must cover `screens.rs:111/142/167`, `lcd.rs:422/526/574/627` and the PendSV path. The silicon test as proposed is vacuous: `e2e-test` short-circuits the pixel confirm (`secure/src/ui/px/confirm_px.rs:90-109`), so it needs a fixture that holds the bracket open, a secure-side snapshot of the NS counter, and a negative control with the guard compiled out. Assert BASEPRI_S is 0 at veneer return. Pin secure interrupt priorities with a test. Land it as a sub-item of USB-01.
Precedent: none direct. The [QEMU patch note](https://lists.nongnu.org/archive/html/qemu-arm/2017-09/msg00248.html) is the only fetched source on the semantics.
Residual: the PRIS / BASEPRI_S semantics are unverified by both the finder and the skeptic; checking ARM DDI 0553 is a hard precondition. The mask does nothing against NS DMA or a fault on the flash read, so it must not be presented as closing the atlas swap without X5a.

**X6a. Safe custody topology on the shipped route.** Priority P1 proposed, P2 final; kind mixed proposed, process final; cost M; skeptic confidence 0.8.
Threat: every other item hardens one device. `docs/security/threat-model.md:530` says multi-party approval is the only architectural fix for coercion and that pq1 does not ship it.
Finding: the critic's premise that a firmware decision gates this does not hold. The on-chain route is shipped: `secure/src/nsc/cmd_sign_userop.rs:896-909` and `:1207-1216` bind an `approveHash` call to a SafeTx, `:2614` commits `last_userop_count` at sign time so `MAX_OFFCHAIN_GAP` never applies, and the wallet is `msg.sender` to the Safe (`contracts/smart-wallet/src/PQSmartWallet.sol:239-261`), so no adapter is needed. No doc, test or issue states it as a custody topology.
What to do, with corrections: amend `docs/companion/safe-multisig-clear-sign.md`, `threat-model.md` (`:530`, `:254`, `:430`, and the stale duress line at `:432`), `docs/STATUS.md` and `HARDENING.md:518`. Recommend `approveHash` as the supported route; the `execTransaction`-sender route shows no nonce and has an open red-line in #332. State the per-version matrix: `multi_send.rs:12-13` allowlists only the v1.3.0 and v1.4.1 MultiSendCallOnly deployments, so a 1.5.0 batch is refused. The threat-model row must carry the conditions: pq1 required in every quorum, a second signer that also decodes, funds held in the Safe, `approveHash` irrevocable until the nonce is consumed, and that the device cannot see the Safe's threshold, owners, modules or guard. The Foundry test should `vm.etch` canonical runtime fixtures and go through the existing EntryPoint harness. The Safe Transaction Service client is split out as a separate M to L deliverable; the skeptic flags a likely blocker there (proposals are authenticated by an owner or delegate signature) that was not verified.
Precedent: Safe's [signature documentation](https://docs.safe.global/advanced/smart-account-signatures) and [Ledger Enterprise Multisig](https://www.ledger.com/blog-enterprise-multisig-new-era). The skeptic did not re-fetch the Ledger source. Neither the finder nor the skeptic ran a Foundry test.
Residual: not covered by pq1 plus pq1: vendor firmware-key compromise, a common decoder bug, a shared companion. A different-vendor second signer is classical. A 2-of-2 has no redundancy.

**X6b. Fence the off-chain Safe co-sign route.** Kind mixed proposed, process final; S, P2, parity; skeptic confidence 0.8.
Threat as corrected: a real SafeTx sent as `EIP712_TYPED` is refused today, not rendered generically, because the vendored descriptors bind singleton addresses and the firmware demands exact domain-separator equality (`secure/src/tx/erc7730.rs:163-183`; `cmd_sign_offchain.rs:504-536`). The live off-chain route for a SafeTx hash is blind RAW32 only. The Safe verifier is not on the off-chain path (`cmd_sign_offchain.rs:480`, `:504`, `:612-626`).
What to do: record that the supported route is X6a. Add no "EIP-1271-only signer" carve-out to `MAX_OFFCHAIN_GAP`; settle #179 first. The only code that ships now is a dbgen permanent refusal of the SafeTx typed format plus a negative test, because `common-eip712-Safe.json` defines a generic SafeTx format with no MultiSendCallOnly allowlist and no DELEGATECALL refusal. Amend `docs/companion/companion-safe-tx-integration.md:384-391`, which endorses RAW32 for Safe `signMessage`, and cover both SafeTx and SafeMessage. State that the real fence is #381: a "MUST NOT" binds only honest companions. Correct the adapter claim: Safe 1.5.0 calls `isValidSignature(bytes32,bytes)` with magic `0x1626ba7e` ([Safe.sol v1.5.0](https://raw.githubusercontent.com/safe-global/safe-smart-account/v1.5.0/contracts/Safe.sol)); 1.3.0 and 1.4.1 pass `bytes data` with `0x20c13b0b` ([Safe.sol v1.4.1](https://raw.githubusercontent.com/safe-global/safe-smart-account/v1.4.1/contracts/Safe.sol)), and an adapter for them must hash the data before forwarding. Fix `docs/feature-roadmap-research-2026-06.md:154`, `:155`, `:238`.
Residual: P2 is justified only because the residual sits under ship-blocker #381; standalone it would be P3. Not verified: whether the `eip712-Safe-*` leaves are admitted into `ERC7730_DESCRIPTORS_ROOT`, the Ledger precedent, and which Safe versions run on pq1's target chains.

**X7a. Injective `personal_sign` rendering.** Priority P1 proposed, P2 final; firmware, M; novelty parity proposed, "parity-plus" per the skeptic; skeptic confidence 0.82.
Threat: two different payloads paint identical pages. `secure/src/tx/display/eip1271.rs:503-513` maps every byte outside 0x20..0x7E to `?`, including line feed, `eip1271.rs:404-417` space-pads rows, and there is no length row. `secure/src/tx/display/offchain_screens.rs:99-107` is a second copy on the pixel path. Open issue #154 carries a PoC and maps to no consolidated item.
What to do, with corrections: classify the payload once; printable ASCII plus line feed renders as text, anything else as a loudly labelled hex mode. Use one line-feed marker glyph outside the payload alphabet (0x7F is the one free slot in the legacy font, `secure/build.rs:414-416`), and send any line or message ending in a space to hex mode or refuse it, as `render_const` does (`pqsigner-erc7730/src/display/render/formatters.rs:1629-1640`). Add a "Len: N bytes" row. The renderer must become fallible and refuse before allocating, because `Pages::with_len(total)` asserts (`eip1271.rs:355-358`) and an LF-heavy payload would be a secure-world panic. Fixed overhead is 7 pages, leaving 24 message pages of 31, so the hex cap is about 568 B. Replace the infeasible 2-safety Kani gate with a host-side inverse and a round-trip property, with the #154 pairs as fixed vectors. Put the encoder in `aa` or a small new crate. Correct `docs/companion/usb-protocol-v2.md:332`.
Precedent: Trezor's hex fallback fires only when UTF-8 decoding fails (`core/src/apps/common/signverify.py:31-35`), so Trezor does not separate the #154 pairs. Only the hex fallback is parity.
Residual: the sweep's own caveat says the attack needs a verifier that normalises bytes and is unproven against any concrete verifier. The pixel word-wrap collision is inferred, not executed. Non-ASCII messages become unreadable hex. This is not SIWE clear-signing.

**X7b. Structured SIWE pages.** Priority P2 proposed, P3 final; cost M proposed, L final; firmware, beyond; skeptic confidence 0.72.
Threat as corrected: field legibility, and a warning on malformed look-alikes. The skeptic strikes "cross-chain session confusion" as a security claim: the signed value is already bound to this wallet and the request chain (`aa/src/eip1271.rs:183-198`), so the address and chain checks are fail-early consistency checks, not a new barrier. No SIWE parser exists; a grep finds only comments (`proto/src/lib.rs:1257-1263`).
What to do: a strict no-heap [EIP-4361](https://eips.ethereum.org/EIPS/eip-4361) parser in a workspace crate; structured pages prepended, raw pages still mandatory. Refuse on address mismatch; warn on chain mismatch by default. Structured pages need a mark that raw message pages cannot reproduce, with the `context_page_exact` uniqueness check (`eip1271.rs:300-322`) extended to them. Scope both renderers. Gate on a flash measurement. Hard dependency on X7a (#154).
Precedent: spec-mandated. Trezor has no SIWE parser.
Residual: the device cannot check the browser origin, so the primary phishing case is not mitigated by enforcement, and nothing may market this as phishing protection. Flash cost is UNMEASURED; the skeptic's 3 to 6 KB is a plausibility estimate. No SIWE flow ships yet.

**X8a. Secure-MPU execute-never on secure SRAM.** Priority P1 proposed, P2 final; firmware, S, parity; skeptic confidence 0.8.
Threat as corrected: an attacker-supplied odd word loaded into the program counter by a fault. A load of an even data pointer already takes an INVSTATE UsageFault and ends in the zeroize-and-reset HardFault handler (`secure/src/main.rs:4682-4690`). No MPU is programmed in any image, and `SIGN_SNAP_BUF` is a companion-filled static at a fixed address in executable SRAM (`secure/src/nsc/mod.rs:1026`). The recorded deferral (#277) covers only the privilege split, and `docs/architecture/trezor-comparison.md:433` says the write-xor-execute recommendation "stands".
What to do, with corrections: one execute-never (XN) region over secure SRAM derived from linker symbols per platform (the QEMU build links RAM at 0x3800_0000, 128K, `secure/memory.x:24`), with PRIVDEFENA and HFNMIENA, read back and const-asserted. Add a no-access stack-guard region in the same change; `nsc/mod.rs:1007-1012` documents a real stack overflow into `SLOT_CACHE`, and the skeptic rates the guard as arguably worth more than XN here. Drop the peripheral region. Replace the "no link_section" grep with a map-file gate, since `secure/src` has several static `link_section` uses. The acceptance test needs a target with bit 0 set and a negative control showing the sled executes with the MPU off. The QEMU leg needs its own fault path, because the handler at `main.rs:4682` is gated to `stm32u585`. Open a dedicated issue and record it in #54.
Precedent: Trezor maps SRAM execute-never on the STM32U5 ([mpu.c](https://raw.githubusercontent.com/trezor/trezor-firmware/main/core/embed/sys/mpu/stm32u5/mpu.c), local lines `mpu.c:56-60`, `mpu.c:230-232`). The skeptic checked the local checkout and did not fetch upstream.
Residual: XN removes injected code and leaves code reuse. The same fault can target flash at addresses known from the reproducible build, so a jump past the confirm gate is unaffected. The secure MPU has no lock. This is defence in depth, not an isolation boundary.

**X8b. FSBL-side execute protection before the freeze.** Priority P2 proposed, P3 final; firmware, S, parity; skeptic confidence 0.8.
Threat as corrected: the stated threat is factually wrong. The FSBL never copies manifest or signature bytes into SRAM (`fsbl/src/manifest.rs:41-48`). The only directly attacker-chosen bytes in FSBL SRAM are the 256 B hash chunk (`fsbl/src/verify.rs:119-137`) plus verify scratch. The larger executable attacker surface is about 930 KB of attacker-writable secure bank-1 flash at fixed addresses. The FSBL programs no MPU today (`fsbl/src/sau.rs:32-35`, `57-68`), and after write protection (WRP) plus readout protection level 2 (RDP-2) it can never gain one.
What to do: change the control from one SRAM region to a default-deny table: read-execute over the FSBL's own pages only, execute-never over the rest of the flash it reads, over its SRAM window and over peripherals. Disable the MPU before the handoff in `fsbl/src/branch.rs:76-92`. Fold it as one checkbox into M05 / #542 with a "land or explicitly decline" record, and into #54. Acceptance is bench-only on pq1 with a positive control; there is no QEMU FSBL path.
Precedent: Trezor's boardloader enables the MPU without the default map (`mpu.c:233`) and marks later-stage flash as data (`mpu.c:245-252`). The skeptic states the proposal copied half the precedent.
Residual: the handoff branch runs after the MPU is disabled, and a single skip on the admit gates reaches "boot unverified slot" more cheaply. The FSBL holds no secrets. The skeptic assumed, without checking, that a secure-state fetch from the NS alias faults.

**X9a. FSBL verifier correctness as a freeze gate.** Priority P1 proposed, P2 final; process, S, beyond; skeptic confidence 0.8.
Threat: after the freeze the FSBL's C10 verifier cannot be patched. C10 has no applicable official known-answer tests and one active user. The verifier the FSBL links (`fw-manifest/src/lib.rs:519-534`, sole call site `fsbl/src/main.rs:344-346`) is never replayed against the committed 246-entry corpus; no Rust file references `c10_mutant_corpus.json`.
What to do, re-ordered by the skeptic: (a) lead with gate-specific negatives. All 242 rejects in the corpus mutate one signature under one key and break a hash chain, so a verifier with the forced-zero gate (`sphincs-c10/src/hypertree.rs:380-382`) or the WOTS target-sum gate (`sphincs-c10/src/wots.rs:178`) deleted still agrees on all 246. The test that covers those gates, `sphincs-c10/tests/near_miss_validate.rs`, runs in no CI suite (#722). Enrol it, make it a freeze criterion, and export its vectors to forge and Lean. (b) Add the Rust corpus replay as a default-feature test asserting exactly 246 total and 242 rejects, and tighten `SPHINCsC10AsmMutantCorpus.t.sol:58` from `>= 240` to equality. (c) Run `make mutants` scoped to the verify path and require zero surviving mutants in gate checks. (d) Drop the silicon corpus run and write the scope line instead. (e) Record the `sphincs-c10` and `fw-manifest` tree hashes of the frozen build beside the green run, before #541 freezes. Attach it to M07 as a checklist line.
Precedent: Trezor Safe 7's boardloader requires Ed25519 alongside SLH-DSA (`core/embed/sec/image/boot_header.c:49-100`; [Trezor's rationale](https://trezor.io/guides/trezor-devices/trezor-safe-7/going-quantum-our-choices-for-trezor-safe-7-s-quantum-readiness)). pq1 declined that hedge.
Residual: a green corpus is corpus-tier evidence, not a proof. A differential over one spec cannot see a scheme or parameter flaw and does not replace the declined hybrid. The boot hash self-test is single-block only. Nobody executed the corpus through the Rust verifier, so whether the replay is green today is unknown.

**X9b. Algorithm-agility row in the M07 note.** Priority P2 proposed, P3 final; process, S, parity; skeptic confidence 0.8.
Threat as corrected: the live contract already forbids a second FSBL algorithm (the CLAUDE.md "one in the FSBL" rule; `docs/feature-roadmap-research-2026-06.md:200`). The gap is narrower: no statement of permanence and consequence in the freeze package, and the archive line at `docs/archive/work-todo-retired-2026-07-19.md:2226` still reads "KEPT". `docs/security/vendor-signing-key-compromise.md` has no hit for agility, hybrid or ML-DSA.
What to do: add an unticked owner box next to `vendor-signing-key-compromise.md:94`: "FSBL signature-algorithm agility accepted or declined at freeze review (recommended: declined)". Do not write "DECLINED" as fact. State the consequence: boot-time acceptance is C10 under SHA-256 for the life of the die, and a break or a wrong-accept bug has no field remedy other than return. Fix the manifest reason: 3,916 B cannot hold a second C10 signature (4,008 B) but does hold ML-DSA-44 (2,420 B) or ML-DSA-65 (3,309 B); the real blockers are the exact-schema byte, the erased-reserved check, the FSBL envelope and invariant #5. Label v6 as a candidate; the running stages verify legacy v2. Describe the compensating control by content, not by reference to X9a. Record the install-time lever in the updatable secure world with its limits, adding the skeptic's five: secure-slot flash, void where #696 fails, no help against key theft, shared `fw-manifest` logic, and that an independent FSBL verifier also expires at freeze. Fix the stale claims at `docs/architecture/trezor-comparison.md` `:476` and `:485`. Fold into M07 (#486) as item G.
Residual: recording the decision is the owner's act at the freeze review. The #696 premise is not proven on pq1 silicon.

**X10a. FSBL pre-freeze claims ledger.** Priority P1 proposed, P2 final; process, S, beyond; skeptic confidence 0.8.
Threat: several study items each claim FSBL bytes and nobody sums them. The only joint-fit gate (#541) reserves bytes for the rollback family and the option-byte tripwire only, and #540's "Cumulative resource envelope" row is an unfilled placeholder. An item that misses the freeze cannot be retried.
Measured baseline, reproduced read-only by the skeptic on the 2026-09-28 pq1 ELF: span 22,236 B, pages 0..2, 2,340 B to the page boundary, 10,532 B free in the legacy region, frame total 9,056 of 16,376 B, largest frame 6,096 B. The backlight stage (#705) is already linked, so it is spent. The per-claimant figures (roughly 1.3 to 2.8 KB in total) are estimates, none measured, and the Merkle-proof figure is the finder's own guess. Link-time optimisation (LTO) deltas do not add linearly (`docs/security/fw-rollback-fsbl-resource-map-2026-07.md:150`).
What to do, with corrections: a checked-in machine-readable ledger (id, flash low and high, stack delta and largest new frame, status, source, authority). The ledger sum is report-only in `scripts/check_fsbl_geometry.py`; the pass or fail verdict stays with the #541 combined link. Drop the "derived WRP page count changes" criterion, because WRP covers the declared range. Only owner-approved rows count toward #541's bound. FWU-3 (preimage amendment) and M07 Option B are frozen-interface changes, not byte claims. Add the missing claimants: #591, #752, M05 A4 re-basing, and any FSBL part of SYS-06. Pin the measured span and frame total in the ledger and fail on drift without a ledger update. The geometry gate is not in CI and `make fsbl` defaults to `BOARD=iota2`, so either add a pq1 step (`ci.yml:449`) or call the ledger a manual gate. Update the stale 28,704 B figure in `fsbl/memory-stm32u585.x:13` and CLAUDE.md invariant #10. Treat the "about 8.5 KB free" figure as non-decisional.
Precedent: Trezor tracks linked size against caps (`core/embed/models/T3W1/memory.h:39`; `core/tools/size/`). A forward reservation ledger goes beyond it.
Residual: the ledger gives a range, not a fit proof. #758 still blocks the cutover.

**X10b. Secure-slot and secure-stack admission ledger.** Priority P1 proposed, P2 final; process, S; novelty beyond proposed, "parity plus a small process delta" per the skeptic; skeptic confidence 0.78.
Threat: study items claim secure-slot bytes one at a time and no artifact sums them. The secure stack has no measurement: `-Z emit-stack-sizes` is passed only to the FSBL build (`Makefile:2461-2466`), there is no stack limit register use under `secure/`, and #374 is an open ship-blocker.
The skeptic's corrections change the headline:
- The estimated claims total 25 to 38 KB against 34,071 B free without `ui-px`. Only the upper bound exceeds the headroom. Without CS-05's 16 KiB table (`pqsigner-erc7730/src/known_calls.rs:21`) the estimated rows total 6 to 16 KB. Four rows have no estimate. All figures are UNMEASURED estimates from reviewer verdicts.
- Profile conflict, reported as found and not resolved here. The skeptic cites an owner decision of 2026-09-24 to ship the pixel UI as the trusted display, with a decided layout that is unratified (`docs/security/adversarial-review/findings/flash-geometry-v7-2026-09-24.md:33-40`; #752), and concludes the non-px headroom is a bench reference only. CLAUDE.md states `ui-px` stays out of `make release` and calls the flash lever an open owner decision; the skeptic calls that line stale.
- `make size-report` is the wrong hook: in CI it measures a smoke image against the legacy cap (`.github/workflows/ci.yml:479-493`). The ledger belongs on `size-report-px` plus a new non-px ship-shaped variant.
- Do not promise an FSBL-style frame-sum bound for the secure image. Record stack sizes as input to a call-graph tool plus the on-target high-water that #374 specifies.
What to do: one checked-in ledger (id, priority, estimated flash, estimated stack, measured delta once landed) with the slot span as a parameter, the measuring half folded into #752 item 2 and the stack half into #374 and M21. Block stack-growing rows on #374.
Precedent: Trezor's size tooling, for the measurement half only.
Residual: unmeasured, non-additive estimates can give false comfort or false alarm. The production image cannot be compiled at all today. The skeptic could not find X10a in the research data; it is the sibling item in this pass.

### Rejected in the completeness pass

**Refuted proposals.** None. Every one of the 19 skeptic verdicts is `refuted: false`.

**Critic topics that produced no proposal.** The inputs record no reason for either.
- **Release transparency against a targeted signed update** (critic topic 11: public append-only log of release bundles, companion inclusion-proof check; #308, #67, #68). No proposal was produced in this pass. It stays an open critic suggestion.
- **Independent evaluation before mass production** (critic topic 12: external lab pass on fault injection, side channel and board tamper, third-party code audit, disclosure channel with bounty; #607, #612, #613, #614). No proposal was produced in this pass. It stays an open critic suggestion.

**Parts of surviving items that were struck or declined.**
- **Confirm, page-123 tally or deterministic randomness on `CMD_GET_INIT_CODE`** (critic topic 3). Not proposed. It is the finding in `docs/VULN-getinitcode-bootstrap-fewtime-oracle.md:8-15`, accepted by the owner as WON'T-FIX on 2026-06-30 with "do not re-raise" and re-confirmed on 2026-07-10. The device-side tally was separately rejected in `docs/RESIDUAL-bootstrap-crosschain-fewtime-budget.md:56`. The critic's statement that no item covers it is wrong, and its rate is overstated: the bound is the 120 s idle lock, not 250 per session. Only X3a's tripwire remains.
- **Split-channel backup with a pad leaving over USB** (critic topic 1, shape a). Declined in X1b: the wizard runs at `secure/src/main.rs:4001`, before USB init at `:4233` and NS boot at `:4280`; USB is NS-owned, so a share over USB conflicts with invariant #4; and it needs a new host protocol. The skeptic verified those three reasons; a fourth (the same two-tap bound, with a share on a general-purpose computer) is argument, not code.
- **Offline dice or coin seed restored through X1a**, and the claim that this is a zero-change answer to M18. Struck: no valid checksum word exists without SHA-256.
- **Forced Type-1 rotation after restore for UserOps** (critic topic 4). Rejected in X4a: the re-derived slot key equals the on-chain key and `_addOwnerAtIndex` reverts `AlreadyOwner` (`PQMultiOwnable.sol:243`); remove-then-re-add reopens #131.
- **Per-tag distinct-slot cap** (X4b step 4). Struck: it re-opens the page-123 exhaustion brick.
- **The premise that a firmware gap decision gates the Safe co-signer** (critic topic 6). Rejected in X6a: the on-chain route never reaches the gap gate. The "EIP-1271-only signer" carve-out to `MAX_OFFCHAIN_GAP` is rejected in X6b.
- **Two-machine signing as a default** (X2a step 3). Demoted to an owner decision: it doubles the custody surface of a non-rotatable key.
- **X2b options (b) and (c) as written.** Refuted as written on three claims (see the item note) and to be rewritten before costing.
- **Trailing-space marker glyph** (X7a). Dropped: one free glyph slot cannot serve two markers.
- **"Cross-chain session confusion" as a security claim** (X7b). Struck: the hash binding already closes most of it.
- **Peripheral execute-never region** (X8a region C). Dropped as redundant.
- **Corpus run on pq1 silicon** (X9a leg 3). Dropped in favour of a written scope line.
- **A second FSBL verifier or hybrid.** Not proposed anywhere. X9b records the decision only.
- **Hard-failing geometry gate on summed estimates** (X10a). Rejected: Draft 1.1 section 5 forbids relying on additive estimates.
- **Moving the second Bloom table to the NS slot** (X10b). Contradicts #752, which names the Bloom as something that cannot move because it gates blind-sign downgrade (`secure/src/tx/erc7730.rs:232`). The non-px admission order is also dropped as a shipping plan.

### Priority corrections suggested by the critic

These are the critic's suggestions. No skeptic reviewed them and none is a decision.

1. **M11** (P1, L, 10 hardware asks). It is the only item that addresses a logic-level display-bus tap at its root, and that tap is the single confirmed in-the-wild attack. It needs a mass-production board respin, the longest lead time of any item. The critic suggests scheduling the spec freeze as P0, and notes M03 says no encoding stops this tap.
2. **M03** (P2). Parts A and B are S-cost fixes for defects on the shipping legacy path (typed seed letters and the active PIN digit go through `public_glyph_cols`). The critic suggests splitting A and B out at P1. The original D-01 was P0 S, and the skeptic lowered the whole cluster from the merger's P1.
3. **M06** (P2) versus **FI-01** (P0). On master the FI-delay source reuses the last good random byte, and the side-channel inventory records 31 of 32 identical delays measured on silicon (#832), with the fix only on `perf/flash-opt-level-z`. The critic states step 1 of M06 is a prerequisite of FI-01, not a P2.
4. **M04** (P2). It carries #835, labelled `priority:critical` in the tracker, and the zeroize-then-reset fix for a halt sink that leaves `master_secret` live after a detected glitch. The skeptic lowered the merger's P1 to P2, so the study and the tracker disagree with no stated reason.
5. **M07** (P2) and **FWU-3** (P2). Every FSBL-consumed check is now-or-never before WRP plus RDP-2. The critic suggests marking them "must land before the #540 cutover". For FWU-3 the two verify lenses split P1 / P2 and the master list took the lower. The concrete hazard: a validly signed iota2 image on a pq1 releases PA15, PB5 and PB15 to NS (`secure/src/board/iota2.rs:150-151`), which on pq1 are `SE_RST`, `SE1_EN` and `LCM_EN`.
6. **Systematic rule artifact.** Wherever the two verify lenses disagreed, the master list took the lower priority and the higher cost (FWU-3, SCA-01, SCA-02, pin-03, pin-04, CS-04, CS-10, USB-09). The critic calls SCA-01 the clearest loss: the feasibility lens calls it "the only route to a real leakage number", and M15, SCA-02 and SCA-03 all wait on it, so P1 is the defensible level.
7. **CS-01** (P1) versus **CS-05** (P2). CS-05's own threat text says the two must land together. Fencing RAW32 off before a generic EIP-712 path exists leaves long-tail typed data unsignable and creates pressure to turn RAW32 back on. The critic suggests aligning them, or recording that RAW32-off ships with a known coverage hole.
8. **M02** (P1) versus **M09** (P0). The `pq1-verify` tool in M09 leg 1 is unsound until the OEM-lock and WRP masks are silicon-pinned (M02 part A). An OEM2 password planted during RDP-0 transit is undetectable today and permits later RDP regression. The critic suggests M02 part A inherit M09's P0.
9. **M16** (P1, L). It defends against extraction of both secure-element memories, the highest attacker tier in the study, yet sits above P2 items that stop cheaper attackers (M04, M06, SCA-02). The critic states its real justification is the pre-launch at-rest format freeze, not risk, and suggests labelling it deadline-driven and noting its dependence on the open DHUK RDP-1 versus RDP-2 equality receipt (#400).

### Claims that remain unverified

From the critic:

- **Item count.** `final/master.json` holds 51 items (21 clusters, 30 singles), and the per-surface files also sum to 51. No original proposal is orphaned. IMP-06 is double-homed in M02 and M08. D-07, FI-01 and IMP-09 have empty tracked lists in the master list, although the inventories track FI-01 under #301 #401 #236 #376 and the IMP-09 topic under #238.
- **The "Simonik thesis, 76% PIN-glitch bypass on STM32U5A9" figure** is load-bearing in FI-01, SCA-04 and two inventories but has no entry in `lit_all.json`. `lit_all` #92 quotes Donjon (2025) and a Trezor spokesperson (June 2026) saying no fault-injection attack on STM32U5 has been demonstrated. `docs/security/production-security.md` calls it "plausible but unverified" at `:456-458` and "REAL ... PDF not directly retrieved" at `:711`. It needs a primary source.
- **NS SysTick preemption of secure thread-mode code on the STM32U585**, the basis of USB-01's P0 and of X5a / X5b, is an architecture argument. Neither verify lens confirmed that the U585 implements both SysTicks, and nothing was shown on silicon. Lead note added after this pass: Trezor runs a SysTick in both its secure monitor and its non-secure kernel on the same STM32U5 family (trezor-firmware `core/embed/sys/task/stm32/system.c:70`, `docs/core/embed-arch/embed-arch.md:57`), so the non-secure timer the attack needs exists on this silicon family. The swap remains unreproduced.
- **Display-pin attribution.** `inv_display` says the pq1 trusted-display pins "stay NS-attributable". The code releases only PA11 / PA12 to NS on pq1 (`secure/src/board/pq1.rs:289-290`, `secure/src/hw/usb_hw.rs:157-174`), and #83 is written about iota2's GPIOE. This needs a GPIOA / GPIOB_SECCFGR readback on pq1. If the inventory is right it is a fake-display hole far above its "medium" label; if wrong the gap row should be removed.
- **M10 has no verified basis.** The on-chip runtime power-network sensing claims (eprint 2022/946) failed verification, and PDNPulse is an unpowered bench method. Nothing shows that a GPIO RC-decay measurement on this MCU can resolve a high-impedance tap inside fleet tolerance.
- **The "October 2026" and "CryptoBilis" labels.** `deep_research` caveat 1 says no verified source supports them, while `lit_all` #50 cites a Ledger statement dated 2026-10-09/10 about that reseller. The two are not reconciled.
- **Vendor parity on display-bus implants** is absence of evidence. Nothing was verified about what Trezor Safe 3/5, Coldcard, Keystone, Cypherock, NGRAVE or BitBox ship. M11's "published comparables" inherit that.
- **Physical extraction of the two SE families.** `lit_all` has no entry on OPTIGA Trust M or SE050 attacks, so what the XOR split buys is unquantified and M16 rests on an absence. One web search by the critic found: [EUCLEAK](https://ninjalab.io/EUCLEAK/) ([paper](https://eprint.iacr.org/2024/1380.pdf)) names Optiga Trust M as likely affected but untested, ECDSA only, which bears on M17's challenge-signature identity leg; no SE050-specific published attack; and the SE050 FIPS 140-2 [certificate #3840](https://sec-certs.org/fips/id/3840) lists a sunset date in early 2026. All three need a proper sourced pass.
- **The M09 skeptic correction** that the seed wizard must delete and recreate, never adopt, pre-existing SE state was never checked against code.
- **The critic's own unrun reads.** "No wipe path erases page 123" came from a grep of `erase_offchain_page` callers (the X4a and X4b skeptics later confirmed the two callers by code reading). The CMD 15 yield per session is bounded from published timings, not measured. The atlas swap-and-restore timing is reasoned, not demonstrated.
- **Unimplemented daily sign quota.** README F-17 and `secure/src/sign_rate.rs:35-39` still promise a flash-persistent 500-per-day quota that is not implemented and has no issue.
- **Coverage note.** The critic checked and judged these covered, not missing: one-word-per-page reveal; BIP-39 passphrase and SLIP-39 (recorded declines, not reopened); random-number health tests; BOOT0 and DFU after RDP-2; supply-chain process; companion trust; chain-id display; flash remanence. Those judgements were not independently reviewed.

From the skeptic verdicts in this pass:

- **X1a.** Button routing in the schematic and PCB layers was not traced.
- **X2a.** Forgery cost from two WOTS+C signatures: UNMEASURED.
- **X3a.** Signatures per idle window: estimated, not measured on CMD 15. Whether an in-flight handler guard can extend the idle window was not checked.
- **X4b.** Whether master keygen is cached at each page-123 call site was not traced by the finder; the skeptic's answer is to use `masterPkSeed`.
- **X5a.** NS GPDMA writing the flash control registers: hypothesis. GPDMA reset defaults, SRAM3 availability and block-based attribution of the atlas pages: unverified. Secure stack high-water with a 75 KB copy: UNMEASURED.
- **X5b.** BASEPRI_S and PRIS semantics against ARM DDI 0553: unverified. Tamper and illegal-access interrupt priorities: not opened.
- **X6a.** No Foundry test was run. The Safe Transaction Service authentication blocker is unconfirmed.
- **X6b.** Admission of the Safe typed-data leaves into the descriptor root, and Safe version share on target chains: not verified.
- **X7a.** The pixel word-wrap collision was not executed.
- **X7b.** Flash cost: UNMEASURED. Whether batch off-chain signing carries `PERSONAL_SIGN` was not confirmed.
- **X8a.** The flash slot layout for a candidate execute-never region was not checked against `pqsigner-geometry`.
- **X8b.** That a secure-state fetch from the NS alias faults was assumed.
- **X9a.** The corpus was not executed through the Rust verifier.
- **X9b.** Trezor's published rationale quote was not re-fetched by the skeptic; #696 is unproven on pq1 silicon.
- **X10a, X10b.** Every per-claimant byte figure is an estimate. The secure image was not rebuilt. The shipping-profile conflict in X10b is unresolved.
- **Review depth.** The skeptic verdicts for X1b, X2a, X4b, X7b, X9a and X10b state that no second-model review was available. The X1a and X1b proposals state the same about the finder's side.

---

## 13. On-chain policy layer (focused pass, 2026-10-12)

The eleven surfaces of the main study were all on the device. The smart-contract wallet was not one of them. This pass asks what an on-chain rule can do when the device, its display path or the seed is compromised, and whether that has to be decided before launch.

Evidence: reading of the three wallet contracts; a prior-art survey with primary sources (`focused/onchain_prior_art_report.txt` in the data folder); two facts I re-fetched myself (marked below); and an adversarial review of the first draft of this section by an independent model, GPT through the codex CLI (`focused/onchain_design_review_gpt.md`). The second reviewer named in the project instructions, Kimi, refused to run with a subscription error. No contract was written or tested. The design here is a proposal for review, not a specification.

### Correction to what I told the owner

I said the on-chain policy decision is "now or never, because the contract code is baked into the wallet address". That is true only for rules that live inside the wallet contract. Two things weaken it.

1. **Savings can be protected without changing the wallet.** A separate vault contract that the wallet controls can hold them and enforce a delay. It can be deployed at any time, including after launch.
2. **Changing the wallet is not free today.** `vendor-signing-key-compromise.md:401-413` calls an in-wallet timelock "free now". The wallet implementation, factory and verifier are already deployed on Base mainnet, audited, and bound to formal proofs by code hash (`contracts/verification/docs/PINNED_CODEHASHES.md`), and the factory address is compiled into the firmware (`proto/src/lib.rs:1480`). A change means a new implementation and factory, a firmware constant change, a new audit and a re-run of the proofs. No user wallet exists yet, so it is possible, but it has a real price.

What stays launch-bound is narrower: anything meant to protect funds at the wallet's own address, its approvals, its off-chain signatures and its fee payments. One already-recorded contract question is launch-bound for a different reason and should be decided in the same sitting (see "Decide together with #131" below).

### What the wallet does today

- No upgrade path of any kind (`contracts/smart-wallet/src/PQSmartWallet.sol`; a search for upgrade functions finds none).
- The bootstrap key can only register a slot key. Slot keys can call anything, in one call or a batch (`PQSmartWallet.sol:239-290`, `:449-482`).
- `validateUserOp` returns only "valid" or "invalid" (`:74-75`, `:520`). The time-window fields that EntryPoint v0.6 offers are unused.
- Any slot key can produce an off-chain signature that the wallet accepts for any message, with no limit and no event (`:599-648`; the check is view-only).
- Every key comes from the same 24 words. Whoever has the seed has every key.

### Four attack cases

| Case | What the attacker has | A Ledger or Trezor account | What an on-chain rule could do |
|---|---|---|---|
| T1 | The seed (display implant, backup theft) | Drained at once | Delay the drain and let the owner move the funds to safety first |
| T2 | One signature on something the user did not see (malicious firmware, the gateway defect #846, a blind-sign trick) | That transaction executes | Delay it, show it on-chain, let the owner stop it |
| T3 | The device and the PIN, by force or theft | Drained at once | The attacker must hold the victim for the whole delay, or settle for a small balance |
| T4 | A signed operation that was never broadcast | Usable later | Little. See trap 9 |

### Nine traps

Each of these has broken or weakened a shipped design.

1. **Owner and thief hold the same key (T1).** A "cancel" button helps the thief as much as the owner. The Bitcoin vault work solved this ([BIP-345](https://github.com/bitcoin/bips/blob/master/bip-0345.mediawiki)): withdrawals are slow, and one fast action exists that can only send the funds to an address fixed in advance. The thief gains nothing by using it. Rhinestone's `ColdStorageHook` is the same shape on Ethereum ([source](https://github.com/rhinestonewtf/core-modules/blob/main/src/ColdStorageHook/ColdStorageHook.sol)).
2. **Fees are an uncapped outflow.** In EntryPoint v0.6 the wallet prepays `requiredGas * maxFeePerGas`; unused prefund returns to its deposit, and the charged fee goes to a beneficiary named by whoever submits the bundle (I re-read `_getRequiredPrefund`, `_validateAccountPrepayment` and `_compensate` in the v0.6.0 source). A key holder who colludes with the submitter, or is the submitter, can sign inflated fee fields and extract the wallet's ETH. A limit on `execute` does not see it.
3. **Off-chain signatures bypass an on-chain limit.** A signed message can move tokens with no transaction from the wallet. USDC's permit accepts contract signatures ([source](https://github.com/circlefin/stablecoin-evm/blob/master/contracts/v2/EIP2612.sol)); Permit2 does too, once the wallet has given it a token allowance ([source](https://github.com/Uniswap/permit2/blob/main/src/libraries/SignatureVerification.sol)). The survey found no shipped design that delays or caps the owner's own signatures.
4. **Old approvals.** One unlimited approval to a router, and every later drain needs only that router.
5. **The policy code is itself a target.** On 1 June 2026 Gnosis Pay lost about 1.5 million dollars through the Zodiac Delay and Roles modules. Their signature check "did not check whether the call had succeeded", which "let the attacker(s) queue withdrawals from accounts they did not own" ([post-mortem](https://www.gnosis.io/blog/post-mortem-gnosis-pay-vulnerability-exploit), re-fetched by me). The safety layer was the hole.
6. **Almost every shipped limit binds a helper, not the owner.** Safe's allowance module, Zodiac Roles, Coinbase spend permissions and MetaMask's enforcers all cap a delegate. The owner key stays free. The one owner-binding cross-token limit that shipped (Argent) needed a price oracle and was removed for gas cost ([release 2.5.0](https://github.com/argentlabs/argent-contracts/releases/tag/2.5.0)).
7. **A delay is useless if nobody is told.** Safe's recovery has a 28-day window and "no form of notification". The owner must learn of a queued withdrawal through something that depends on neither the device nor the companion app.
8. **Loosening must be as slow as spending.** Zodiac's cooldown can be set by its owner with no floor.
9. **Time windows on signatures buy little here.** The device has no clock, so a hostile companion chooses the window. A freshness check against a recent block hash is banned in the validation phase ([ERC-7562](https://github.com/ethereum/ERCs/blob/master/ERCS/erc-7562.md)) and possible only in the execution phase, at the cost of a wire-format change. Low value for T1 to T3.

One more, specific to this problem: **the safe address must be held somewhere else.** A second seed generated and shown on the same device is captured by the same implant.

### Three options

| | A. Separate vault contract | B. Small hook in the wallet | C. Vault mode built into the wallet |
|---|---|---|---|
| Wallet contract changes | None | Yes | Yes, large |
| Must be decided before the first user wallet | No | Yes | Yes |
| Protects savings moved into the vault | Yes | Depends on the policy plugged in | Yes |
| Protects funds, approvals and signatures at the wallet's own address | No | Yes | Yes |
| Fee drain (trap 2) | Limited to the small balance left in the wallet | Needs a fee limit in the wallet | Needs a fee limit in the wallet |
| New audit and proof work | One small new contract | Wallet, factory, firmware constant, proofs | The same, much larger |

**Option A in outline.** A vault contract holds ETH and tokens. It has no signature checks, no price oracle, no upgrade and no setters. Everything is fixed when it is created: the wallet that controls it, the delay, the safe address, and the hash of a recovery code.

- **Withdraw:** the wallet announces a withdrawal of a fixed asset, recipient and amount (one signature on the device). After the delay anyone may execute it. The announcement is a public event.
- **Recover:** at any time, either the wallet or anyone who presents the recovery code switches the vault into a terminal state in which it pays only the safe address.
- **Cancel:** the wallet may cancel its own announcement. A convenience; security does not rest on it.

Why this shape answers the traps: the thief with the seed can only announce and wait, and cannot change the delay or the safe address because nothing can. A wrong withdrawal from a mis-signing device sits in public for the whole delay. The vault is out of reach of fees and of off-chain signatures.

### What the independent review changed

The reviewer's verdict was "revise before adopting". I checked its repository citations and agree with all seven points.

1. **Deposit-time substitution is critical, not a footnote.** A hostile companion presents a vault whose safe address is the attacker's; the owner deposits; the attacker presents the recovery code and sweeps at once. The device must verify, before any deposit, a pinned vault factory and code identity, the exact creation parameters, the chain, the controlling wallet, a non-zero delay, and that the safe address is not the wallet, the vault or zero. It cannot verify that the safe address is in safe hands or that the user really holds the code; the user must check the safe address against an independent source. This is firmware work and is undesigned.
2. **"Recover sends everything" can fail forever** if one token reverts or blocklists the safe address and the sweep is atomic. Recovery must be a constant-cost state change with no external calls, followed by separate, permissionless sweeps per asset. A safe address that a token issuer blocklists remains unfixable.
3. **Announcements must be bounded.** An attacker could announce "everything" while the vault is empty, wait out the delay, and drain a later deposit at once. Announcements need a fixed asset, recipient and amount, a reservation against the balance that exists when they are made, an expiry, and recovery that does not depend on the size of the queue. Outflows must be plain transfers; arbitrary calls or approvals reopen traps 3 and 4.
4. **The wallet can be made unusable, so recovery cannot depend on it.** One mis-signed operation can exhaust a slot key's budget (`PQMultiOwnable.sol:220-240`: the off-chain count is supplied by the caller and only has to rise), and a seed holder can burn the bootstrap budget (at most 65,536 operations, so expensive) and remove every slot key. The recovery-code path must work with no call from the wallet and with gas paid from elsewhere, and it must be tested that way.
5. **The recovery code is a bearer secret.** Once revealed in a transaction anyone can replay it. That is harmless for one vault, because it only ever pays the safe address, but a code reused across vaults or chains makes all of them forcibly recoverable. One independent code per vault per chain. It is a hash preimage, not a signature, so invariant 5 is untouched, and a 256-bit code keeps about 128 bits against a quantum search.
6. **Equal keys give no priority.** If the owner reacts close to the end of the delay, the thief's execution can land first, or a chain reorganisation can remove the recovery. The guarantee needs an independent watcher, early action and a margin for finality. Coercion (T3) still succeeds if the attacker can also reach the safe address.
7. **A safe address held by an ordinary wallet ends the post-quantum protection for whatever is swept there.**

### Decide together with #131

The review also pointed at a wallet-contract question that is already recorded and is launch-bound regardless of policy. Removing a slot key and registering the same key again installs it at a new index with fresh counters (`PQMultiOwnable.sol:175-193`, `:242-258`; I re-read both). The per-index caps cannot be reset, but the per-key budget can, which is what invariant 7 is meant to protect. It is recorded as SOL9 in `docs/security/adversarial-review/onchain-contracts-adversarial-review.md:25` and tracked as #131. Every fix listed there changes the frozen contract.

This matters for the option choice. If #131 leads to a redeploy, the audit and proof re-run are being paid anyway, and Option B's extra cost becomes small. If #131 is accepted as a residual and nothing is redeployed, Option B has to carry the whole cost alone.

**Option B in outline.** The wallet gains one optional address, a guard, that is asked before every call and before every off-chain signature is accepted, and that can only refuse. Changing the guard goes through a short built-in delay. Policies are then written later as guard contracts. This protects the wallet's own address, which Option A cannot. It also adds a way to freeze a wallet: a mis-signed "set guard" (T2) blocks everything until the built-in delay lets the owner replace it.

**Why not Safe plus the Zodiac Delay module.** The firmware already clear-signs Safe transactions, so it is the obvious off-the-shelf route. Three reasons against: the June 2026 exploit was in exactly these modules; the Delay module has one all-powerful owner role and no cancel-only role ([source](https://github.com/gnosisguild/zodiac-modifier-delay/blob/main/contracts/Delay.sol)); and it binds module callers, not the owner key.

### What I recommend

1. **Do not record "decline in-wallet policy" yet.** Take one wallet-contract decision before the first user wallet, covering #131 and Option B together, and write it where the unchecked box is (`docs/security/vendor-signing-key-compromise.md:136-139`). The decision is tracked as #867. My expectation is: fix #131 if the owner judges it must be fixed, add the guard hook in the same redeploy if there is one, and decline Option C in either case.
2. **Keep Option A as the candidate for protecting savings**, and write its specification before any code: the recovery state machine, the announcement rules, and the deposit check on the device. The seven review points are its acceptance criteria.
3. **Ship a default alert path with it.** One indexed event per announcement, and a documented recipe for an independent watcher ([Tenderly alerts](https://docs.tenderly.co/alerts/intro-to-alerts) or the self-hosted [OpenZeppelin Monitor](https://github.com/OpenZeppelin/openzeppelin-monitor)). The wallet emits events for on-chain key use, not for off-chain signatures.
4. **Do not adopt Safe plus Zodiac Delay** as the vault.

### Against Ledger and Trezor

A plain account cannot do any of this. The survey found no consumer product that pairs a hardware signer with an on-chain delay that binds that signer. The nearest are Gnosis Pay (on-chain delay, any signer), Coldcard's co-sign feature (on-chain multi-signature, policy enforced on the device) and Liana (a timelock on the recovery path only). Absence is not proven: Trezor, Keystone, BitBox and Passport documentation was not read in full.

On-device spending rules such as Coldcard's do not bind someone who holds the seed; that is the difference. The on-device guard already proposed as CS-03 covers the thief of the device. The vault covers the thief of the seed. One more point for CS-03: its time-based part (a velocity limit) was dropped in the main study because the device has no battery and no clock. On-chain time does not have that problem.

### Owner decisions

1. The wallet-contract decision above: #131, and Option B with it or not.
2. Vault product: yes or no. If yes: the default delay (shipped designs run from 24 hours to 28 days), and what the product tells users about where the safe address should live.
3. Whether an automated watcher may hold a recovery code and act on any unexpected announcement.

### Not verified

- No vault code exists. Gas costs and the deposit check are undesigned.
- How vault calls would clear-sign was not checked in the firmware. The descriptor root is compiled into the image, so a new descriptor needs a firmware release or the catalogue-refresh item CS-10.
- USDC's transfer-by-signature function was not re-read; only its permit path was.
- Whether the firmware can ever be made to sign the remove-and-re-add sequence of #131 was not traced.
- "No shipped product does this" and "no limit was ever bypassed through a wallet's own signatures" are absences after search.
- The fee-drain trap was read from source, not demonstrated.
- Only one independent model reviewed this section.

---

## 14. Next-revision board (focused pass, 2026-10-12)

Every hardware idea in the main study was judged against the current board: a 48-pin STM32U585, an SPI panel with no read-back, two buttons on the only tamper-capable pads, and no battery. This pass asks what changes if the board itself can change. Evidence: the datasheet (DS13086 Rev 10) and reference manual (RM0456 Rev 7), read locally; a survey of what shipped wallets do and of the academic work on unpowered tamper detection, with primary sources (saved in the data folder as `focused/tamper_prior_art_report.txt`). Nothing was measured. The battery decision is not reopened.

### The answer first

> **Correction 2026-10-12 (second pass).** This section was written believing nothing on the current board keeps the backup supply alive. The V10 schematic shows an 11 mF backup capacitor on VBAT and both crystals (section 16, #869). For the hours that capacitor holds, the internal temperature and over-voltage tampers work on an unplugged unit. The conclusions below about transit stand, because hours do not cover weeks; option 7 should be read as "a larger capacitor than the board already has".

A new board does not make an implant detectable. Three findings set the ceiling:

1. **No published method lets a microcontroller detect a passive tap on its own bus** with timers, ADC or comparators. The published detectors use a network analyser or an FPGA ([PDNPulse](https://arxiv.org/abs/2204.02482), [ImpedanceVerif](https://tches.iacr.org/index.php/TCHES/article/view/9954)).
2. **Every shipped wallet that responds to tampering carries a battery**: Keystone 3 Pro (a button cell runs the erase, [firmware](https://github.com/KeystoneHQ/keystone3-firmware)), Passport Prime (two tamper switches, [Keylabs audit](https://foundation.xyz/security/passport-prime-keylabs-audit-2025.pdf)), GridPlus Lattice1 (a mesh with a battery rated "around 5 years when unplugged", [vendor page](https://docs.gridplus.io/lattice1/security-features)). The battery-free ones (Trezor Safe 3 and 5, Coldcard Mk4, BitBox02) use passive measures only: epoxy, a clear case, a welded shell.
3. **"The secure chip drives the screen" does not stop a tap.** That is exactly the architecture the Nano X implant read ([Grand](https://grandideastudio.com/media/ledger_hardware_implant_slides.pdf)).

So the realistic gains on a new board are, in order: make a tap destructive to install, check the enclosure at power-on, and (an owner question) keep the seed off the tappable lines.

One thing the no-battery decision buys that the main study did not credit: the Nano X implant sat in space made by fitting a smaller host battery (the slides do not say what powered it). pq1 has no host battery to shrink or to borrow from. A radio implant must draw from USB power while plugged in, or carry its own cell, which is a visible part.

### What each package offers

From DS13086 Rev 10, Table 2 (versions without the internal switching regulator, which is what pq1 uses):

| Package | Size | GPIOs | Tamper pins | Active tamper loops (one shared output) |
|---|---|---|---|---|
| UFQFPN48 (today) | 7 x 7 mm | 37 | 3 (PC13, PA0, PA1) | 2 |
| LQFP64 | 10 x 10 mm | 51 | 4 (adds PC5) | 3 |
| LQFP100 | 14 x 14 mm | 82 | 8 | 7 |
| UFBGA132 | 7 x 7 mm | 110 | 8 | 7 |

The ball-grid package has the same footprint as today's part. It has no perimeter lands to solder to, eight tamper pins, and spare ADC and touch-sensing pins.

### Options

| # | Option | What it buys | What defeats it | Works unpowered | Cost | Who ships it |
|---|---|---|---|---|---|---|
| 1 | Display and button nets on inner layers, no test pads, connector, flex tail and button region potted in opaque epoxy | Installing a tap means milling epoxy | Patient milling; a tap at the panel glass | Yes | Layout and process | BitBox02 (epoxy) |
| 2 | Same package, buttons moved to the free pads PA10 and PB4 | Frees all three tamper pins: one output, two loops (shell seam, display flex) | Bridge the loop, then cut it; any open while the device is unplugged that is closed again | Only a break still present at the next power-on | Layout only | None battery-free |
| 3 | UFBGA132 with via-in-pad | No solderable copper at the microcontroller; eight tamper pins; spare analog pins | The net still surfaces at the connector, flex and buttons. No source quantifies the gain | Yes (the routing) | Part change, finer board rules, X-ray inspection | Passport Prime hides pads under the display |
| 4 | Loops with trimmed resistance across the shell seam, values written once at the factory, read by the ADC at boot | Detects an opened shell at the next power-on, not only a broken wire | Measure, bridge, then cut | Yes | Layout, one ADC pin per loop, mechanical | None found |
| 5 | A fingerprinted mesh over the display and button region, read at boot | Detected a scope probe and micro-soldering on the mesh in the one paper ([TCHES 2026](https://eprint.iacr.org/2025/1962)) | Unknown. One paper. Needs a high-resolution timer the STM32U585 does not have, so a second small microcontroller | Yes | Research project, about 10 EUR of parts | None |
| 6 | Capacitive enclosure fingerprint used as key material ([TCHES 2019](https://tches.iacr.org/index.php/TCHES/article/view/7334)) | Opening destroys the key. Detected a 0.3 mm drill hole | Drill and repair partly succeeded. A later analysis asks for about 459 cells; the prototype had 128 | Yes | Research project with a discrete analog chain and a bonded flex cover | None. Prototypes only |
| 7 | Supercapacitor on the backup supply, so the mesh stays armed unplugged | Coverage for hours to days after unplugging | Waiting. Leakage sets the hold time: about 13 hours for 0.1 F, 2 to 12 days for 1 F | For that long | One part plus a clamp | None found |
| 8 | Current sense on USB power, compared with an enrolled profile | A radio implant that draws from USB power | An implant with its own cell, a tap upstream of the sensor, a draw below the noise | Not needed | One part. Unproven | None found |
| 9 | Backup and restore that never cross the display or the buttons (an encrypted card) | Removes the seed from the tap | The PIN and addresses still cross those lines. Changes the recovery experience | Yes | Part plus firmware plus a product decision | Tangem, BitBox02 (not confirmed from a primary source) |

Three firmware items decide whether options 2 to 7 are worth anything, and none needs a new board:

- The boot code clears the tamper status before reading it (comment on #75). Until that is fixed no external loop works.
- The secure world's RAM is SRAM1, which a hardware tamper does not erase. Moving secrets to SRAM2, as Trezor does, is what makes "erase on tamper" real (item M21).
- A tripped loop must lead to a persistent "this unit was opened" state, not to "restore from seed", which would have the owner type the seed into a unit that was just opened (owner decision 8 in the summary).

### What I recommend for the next revision

1. **Adopt option 1 as layout and assembly rules.** These are already asks G1-3 to G1-5 in the hardware section. A respin is when they are free.
2. **Take option 2.** It is layout only and uses the same part. The main study excluded moving a button but recorded no reason. The cost is that PA10 and PB4 have no wake-up function, which matters only if a button must wake the device from a deep sleep mode. The three tamper pins are the scarcest resource on the package. Route two loops and leave them unpopulated until the false-trip behaviour is measured.
3. **Decide option 3 on cost alone.** It is the only way to get more tamper pins in the same footprint, and it removes the easiest solder points. Its security gain is real but nobody has measured it.
4. **Fund at most one bench study from options 4 and 5** before committing board area. Option 4 is cheap and weak. Option 5 is the only published unpowered detector built from stock parts, and it rests on one paper that I read only in abstract.
5. **Do not buy transit protection with option 7.** A supercapacitor holds for days and transit takes weeks. A discharged capacitor also looks the same as an attack.
6. **Treat option 9 as an owner question.** It is the only option that removes the target and not just the access. Section 12 discusses backup shapes that avoid the display.
7. **Drop option 6 and touch sensing on the display lines** for now. Both are research with no shipped precedent.

### Against the other wallets

With options 1 and 2 pq1 would be at or above every battery-free wallet surveyed. It would still do less than the three battery-backed designs, which can erase and latch while unplugged. That gap follows from the battery decision and cannot be closed by firmware or by a larger package. What pq1 has that none of them does is the verify-before-first-power check, once issue #850 makes it usable.

### Not verified

- Table 2's column order (which column is which package variant) was inferred from the pin table.
- The mesh paper was read in abstract, artifact notes and the author's blog only.
- Vendor claims for Stax, Flex, Safe 7, NGRAVE and Lattice1 have no independent teardown behind them.
- "No shipped battery-free wallet has active sensing" and "no microcontroller-only tap detector is published" are absences after search.
- The main report cites a source it calls "PACTOR" for a 0.5 pF figure (item M10). The survey could not find a work under that name. Treat that figure as unsupported until the citation is traced.
- Supercapacitor hold times are computed from one part's rated leakage, not measured.

---

## 15. STM32U585 feature cross-check (owner's Gemini conversation, 2026-10-12)

The owner pasted a conversation with Gemini about what the STM32U585 can do to detect foreign hardware, and asked whether pq1 is missing anything from it. Each claim was checked against the firmware at `c75b0d9c`, the pq1 pin table (`docs/hardware/STM32U585CIU6TR Pin Functions.xls`), the datasheet (DS13086 Rev 10) and the reference manual (RM0456 Rev 7). Nothing here was measured on silicon.

**Result.** Most of the list is already in this report or does not apply to the 48-pin package. Nothing in it changes the central conclusion of section 1: the microcontroller cannot see a passive tap on the display bus, and nothing is armed while the device is unplugged. Three small additions came out of the check (N1 to N3 below).

### Claim by claim

| Gemini claim | Verdict for pq1 | Where it stands |
|---|---|---|
| Read the supply voltage with no pin, through the internal reference (VREFINT) | True and unused. | New, small. See N1. The report only considered an external divider on PA6 (M20 Stage C). |
| Measure the backup battery through the VBAT/4 channel | Not applicable. No battery; what V10 fits on VBAT is unrecorded. | G1-8. |
| Measure the device's own current with a shunt and a differential ADC pair | Needs a shunt and two free ADC1 pins. Every ADC1 pair on the 48-pin part is in use. As a detector it fails anyway: the backlight swamps an implant and a competent implant sleeps. | Rejected in Group 3. A bench shunt for side-channel work is G2-3. A VBUS current monitor is the owner question G2-6. |
| Detect a debugger by reading `DHCSR.C_DEBUGEN` | The firmware reads the bit only to decide whether a debug print is safe (`secure/src/main.rs:28`). As a defence it adds nothing: at RDP-2 the debug port is dead, and at RDP-0 a debugger can rewrite the check. The hardware version, internal tamper 6 (debug access while RDP is above 0), is enabled (`secure/src/hw/tamp.rs:287-299`) but covers RDP 0.5 and 1 only, which the ship lifecycle never visits. | Not worth adding. |
| Interrupt on the SWD pins (PA13/PA14) to notice a probe | After RDP-2 the pins could be a tripwire. Low value: the FSBL already checks the RDP byte on every boot (`fsbl/src/optbytes.rs`), and if G1-1 routes SWD to the USB-C sideband pins, any cable or host would trip it. | Log counter at most. Never a wipe. |
| Ping the I2C bus for unexpected devices | A passive tap never answers. Both secure elements are already authenticated by their encrypted tunnels, which is stronger than a ping. What is missing is identity attestation of the chips. | E6, M17, #210, #249. |
| Active tamper mesh (TAMP_OUT to TAMP_IN) | Correct in principle, blocked on this package. DS13086 Table 2 gives the 48-pin part 3 tamper pins and 2 active tampers. The pins are PC13, PA0 and PA1, and PA0/PA1 are the buttons. With no battery nothing is armed while unplugged. | Rejected as IMP-04 and M11. Reopened for a new board in section 14. |
| The tamper block erases keys in hardware before an attacker can read them | Partly wrong for pq1. A hardware tamper erases the backup registers, SRAM2 and the crypto peripherals. The secure world's RAM is SRAM1 (`secure/memory-stm32u585.x:31`), which is not erased. The boot hardware key is reloaded from flash page 126 on every boot, so only the software wipe is durable. The tamper stack has never run on silicon and is not secure-attributed. | M11, M20, M21 (which proposes moving secrets to SRAM2, as Trezor does), A12, #81, #391. |
| Assign passive tamper inputs to any unused GPIO | Wrong. Tamper inputs are fixed pins. Only PC13 is free. The boot code also clears the tamper status before reading it (A16), which blocks any external input until fixed. | G2-1 (case-open footprint, P3), #75. |
| Profile the bus lines with the ADC to notice added capacitance | Not blocked by pins: the display nets do have ADC inputs (PA4, PA5, PA7, PB0, PB1 per DS13086). It is blocked by physics. The ADC samples every 400 ns and cannot see nanosecond edges, so the method is RC decay against a baseline. A buffered tap adds about 1 pF or less, and no peer-reviewed runtime detector exists. Gemini's "medium effort, zero risk" is optimistic: a false positive means the wallet refuses to work. | M10 (bench study first, P3). |
| Poll unused pins for a level change | Free pads are PA10, PB4 and PC13. An implant has no reason to touch them. | No value. |
| Voltage and temperature supervisors | Internal tampers 1 and 2 are enabled with their monitor switched on (`secure/src/hw/tamp.rs:124`, `:192`, `:287-299`), but they watch the backup domain. On the main supply the brown-out level is unpinned and the voltage detector is off. None of these sees a 100 to 400 ns glitch. | C5, M20, #49. |
| Clock security system against a tampered crystal | Firmware runs from internal oscillators only. The pin table lists an 8 MHz and a 32 kHz crystal net (pins 3 to 6), but nothing enables them. | Group 3. See N3. |
| Set RDP level 2 | Planned as the first-boot self-lock. Two caveats Gemini does not give: the burn routine is inert today (B1), and RDP-2 does not stop fault injection or side-channel attacks. | B1, FI-01, #268. |
| Challenge-response handshake with attached modules, using the public-key accelerator | The panel has no cryptography and no read-back line. An elliptic-curve authority would also violate invariant #5. | Not applicable. |
| Tight brown-out thresholds | Right direction, but a tight level on a USB-powered device with a marginal cable causes resets. It needs the rail measurement first. | G1-9, M20 Stage B. |
| Metrology features (LPBAM, CORDIC, FMAC, oversampling) | Not security features for this device. | None. |
| "SESIP level 3 / PSA level 3 physical security" | A certificate of that kind covers the vendor's certified configuration (ST's note TN1545, quoted in #387, describes it), not this firmware. Do not carry the claim over. | #387. |

### New items from this check

- **N1. Make the three ADC4 watchdog tampers real, with no pin (P3).** Internal tampers 7, 12 and 13 are the three ADC4 analog watchdogs (RM0456 Rev 7, TAMP internal signals table). The firmware enables them, but no ADC4 driver exists in the secure world, so nothing useful drives them (row A34, corrected in #861). ADC4 has internal channels that need no pad: the internal reference (VIN[0], which gives the supply voltage), the core voltage (VIN[12]) and the temperature sensor (VIN[13]). A small secure-world ADC4 driver with window thresholds on those channels would give a programmable supply, core-voltage and temperature monitor that runs without the CPU. It also sees over-voltage, which the brown-out and voltage detectors do not. Limits: 2.5 Msps at best, so it sees slow excursions and long glitches only. ADC4 must be made a secure peripheral first. Today it is non-secure, because the second TrustZone controller block is never configured (`secure/src/sau.rs:672-675`; ADC4 is bit 8 of `GTZC2_TZSC_SECCFGR1`, the same block as the tamper attribution in #81). Without that, non-secure code can disarm the monitor or trip it on purpose. Start log-only, because a false trip in confirmed mode erases the hardware key that roots the SE050 credentials (#712). This replaces the PA6 divider of M20 Stage C and leaves PA6 free.
- **N2. Internal tamper 3 is also dead.** It is the LSE clock monitor. It is enabled in `TAMP_CR1` (`secure/src/hw/tamp.rs:290`), but it needs `LSECSSON` and a running 32 kHz crystal, and the firmware uses neither. Add it to the A34 list: either remove the enable or document it as inert.
- **N3. Confirm whether the two crystals are fitted.** The pin table shows crystal nets on pins 3 to 6. Firmware uses neither. If they are populated they are unused parts. A later revision that wants an accurate real-time clock would use the 32 kHz one. This is a question for the board vendor, not a defect. **Correction 2026-10-12:** the V10 schematic shows both (`X101` 8 MHz, `X102` 32.768 kHz) and a backup capacitor on VBAT; whether they are fitted on built units is the remaining question (section 16, #869).

---

## 16. Second pass (2026-10-12): recommendations filed, and what this report had wrong

After the defects were filed (#846 to #867), the owner asked for everything else that had not been filed and that can be done on the current board. This section records what was filed, what was not and why, and the errors in this report that the pass turned up. Sections 1 to 15 are left as written, apart from short dated pointers to this section.

### How the pass was run

- Every recommendation item (the 51 of the master table, the 19 of section 12, N1 to N3 of section 15 and the hardware asks) was checked against all 788 issues in the tracker, bodies included, and against master `c2fab970` (159 commits after the study commit). Seven reviewers did this in parallel, one per group of surfaces, each told that a duplicate issue and a stale premise were the two failures to avoid. The author did the hardware asks and section 15, and read every draft before filing.
- A recommendation got a new issue only where an untracked remainder existed that needs no board change. Where an existing issue already owned the subject, the remainder went there as a comment.
- 971 `path:line` citations went out. 920 were checked by script against a reviewer-supplied snippet of the cited master line. The other 51 are the author's and were read by hand.
- Result: **26 new issues (#869 to #894) and 50 comments**, one per target issue. The new issues carry the label `source:frontier-research-2026-10`. The comments sit on older issues that mostly do not carry it, so the table below is the only complete list of where they are. One bullet of #849 was corrected in place. Drafts, the brief given to the reviewers, their dispositions and the filing log are in `issues-filed/round2/` in the data folder.

### What this report had wrong

Found during this pass. None was run on silicon.

1. **The current board already has a backup capacitor and both crystals** (#869). The hardware section said the VBAT population "is not recorded in the repository", owner decision 2 and ask G1-8 treated it as open, section 14 said nothing is armed while the unit is unplugged, and section 15 (N3) called the crystals a question for the board vendor, although `docs/hardware/evt-silicon-validation.md:729-730` already names pq1's 8 MHz crystal. The V10 schematic in `docs/hardware/schematics/` answers all of it: MCU pin 1 (VBAT) goes to `J102`, a Seiko CPH3225A chip capacitor (11 mF, 3.3 V by distributor listings), charged from `VDD3V3` through a Schottky diode and 4.7 kΩ, and the MCU has an 8 MHz crystal (`X101`) and a 32.768 kHz crystal (`X102`). Whether the parts are fitted on built units is not established. From RM0456 Rev 7: internal tampers 1, 2 and 3 are "functional in VBAT mode" (Table 17); tamper 1 fires on over-voltage only, and an under-voltage ends in a brownout reset that erases the backup domain (section 10.6.4). So for as long as that capacitor holds, which is hours at most by arithmetic and unmeasured, the temperature and over-voltage tampers are live on an unplugged unit and the backup registers keep the hardware key. Section 14's conclusions about transit do not change: hours do not cover weeks. Its option 7 (a supercapacitor) should be read as "a larger one than the board already has". Two documents (`docs/security/user-device-verification.md:91`, `:190-191`) state the opposite of the schematic.
2. **Safe v1.5.0 batches are not refused.** Master allowlists four `MultiSendCallOnly` deployments (`proto/src/lib.rs:1804`). Section 12 (X6a) said three and that 1.5.0 batches are refused.
3. **The delay-source branch is not "0 behind".** `perf/flash-opt-level-z` is 24 commits ahead of and 55 behind master.
4. **`tools/bench/` is not in git on master.** The instrument scripts the study read exist only as untracked files in one checkout.
5. **Half of D-07 had already landed.** Master zeroizes the pixel band buffers after every frame and has deleted the per-band digest table (`ea95a1fe`). Only the 16x4 half remained (#878).
6. **The comment posted on #784 on 2026-10-12 was stale at the commit it cited.** It said the frame is not forced and that a strip digest outlives the frame. Both were removed by `ea95a1fe`. A correction is posted there; the routing point (the live PIN digit is drawn through the non-constant-time path) stands.
7. **X9a:** the Yul and Lean sides do have near-miss vectors for the two bespoke checks. What is missing is the Rust leg of the mutant corpus.
8. **FWU-7:** "differential fuzz against the host core" is vacuous, because the bootloader links the same `fw-manifest` crate.
9. **USB-06:** a "central deny-first policy table in the gateway dispatcher" is the refuted form, since `dispatch` is compiled only for the emulator. What survives is a pinned list of entries callable while locked (one checkbox of #893).
10. **M16:** masking each seed share at rest was already a fix direction of #855, not an untracked addition.
11. **SE-06:** the wizard misfire needs one wrong probe, not two (`secure/src/dual_se.rs:142` ANDs them).
12. **M09 and #249:** the OPTIGA object that holds the Infineon certificate is unconfirmed (`0xE0E3` on the bench chip, `0xE0E0` assumed).
13. **The claim that the pq1 bench SE050 cannot complete its handshake** is stale; #697 records the fix.
14. **CS-02:** "! MULTISIG OFF" is not the only custody banner; enable-module, guard and fallback changes are already loud.
15. **CS-04:** the paymaster gap is stated in the code and in review finding H-6; it is not an unstated hole.
16. **X8b:** the bootloader does not copy the manifest into RAM (`fsbl/src/manifest.rs:41` borrows it from flash). The executable surface that matters is unchecked flash.
17. **M20:** securing the clock controller would not break clock bring-up, which runs before the attribution code. It would break every later access through the non-secure alias.
18. **M16 design note:** RM0456 Rev 7 section 7.3.7 allows programming all zeros over an already programmed flash word, which the review had listed as unknown.
19. **#849:** its fourth fix bullet said to overwrite the OEM keys "in the same ceremony". The first-boot flow may program no option byte other than RDP (requirement R2.1), so the key write is a factory step. The issue body is corrected.
20. **Unmeasured-claims list:** an emulated harness for the OPTIGA PIN derivation does exist (`tools/sca/kdf_target/src/main.rs:435`). What is missing is a capture on silicon.

Three things the reviewers found that the study had not recorded are folded into the issues: the restore dialog returns on the idle timeout without wiping the typed word indices (in #878), the attempt log labels a lockout raised by a secure element as "already at maximum" (comment on #853), and the mask's generator is a 32-bit xorshift where the contract asks for at least 246 bits of state (comment on #831).

### Where each item is tracked now

| Item | Outcome | Where |
|---|---|---|
| USB-01 | Covered | #846 carries every part |
| FI-01 | New issue | #872 (the three gate legs, bench firmware, receipt rule); the rest is #401, #301, #402 |
| M20 | Comments | #49 (brown-out level and detector handler), #269 (secure alias move); the pin-less monitor (N1) on #861 |
| M09 | Comment | #249 (verify on the host, per-proof binding); the tool and the burn are #850 and #849 |
| D-07 | New issue | #878 (16x4 half; the pixel half had landed on master) |
| CS-01 | Comment | #381 (the gate mechanism and what it breaks) |
| M05 | Comment | #864; the rest is #847, #854, #865 |
| M02 | Comments | #46, #270, #856 |
| SE-03 | Comments | #853 and #104 (surviving form only) |
| SE-05 | Comment | #117 |
| SE-06 | New issue | #871; comment on #385 (looks fixed) |
| M11 | New issue | #874 (desk review, requirement fixes, reference material; the rest needs a new board) |
| M16 | Comment | #855 |
| M14 | New issue | #870; comment on #123 |
| M19 | New issue | #873; comment on #776 |
| M21 | Comments | #48, #854 |
| pin-05 | Covered | #853, plus one comment on the attempt-log label |
| IMP-09 | New issue | #885 (host-side check only) |
| M03 | Comment | #237; the firmware defects are #858 and #784 |
| M04 | Comment | #715; the rest is #851, #848, #862 |
| M06 | Comments | #805, #861; the delay source is #865 |
| SCA-02 | New issue | #881 |
| CS-02 | New issue | #882; the nonce ring is in the #600 comment |
| SE-08 | Comments | #485, #275 |
| M07 | Comments | #486 (also carries X9b), #220 |
| FWU-3 | Comment | #487 |
| USB-06 | Folded | one checkbox of #893; the rest is #859, #84, #866 |
| SCA-01 | Comments | #228, #236 |
| CS-03 | New issue | #883 (design first, owner box first) |
| CS-05 | Not filed | owner decision only; one line in the #381 comment |
| M17 | New issue | #880 (device side only) |
| pin-04 | Comment | #636 |
| USB-08 | Comment | #600 |
| SYS-06 | New issue | #879 (warm-reset record only) |
| FWU-7 | Comment | #546 (review note) |
| M15 | Comments | #866, #831, #228; loading the pin needs a new board |
| SCA-03 | Comment | #229 (correction; do not build) |
| CS-07 | Comment | #343; the mislabel is #857 |
| CS-09 | New issue | #891 (self tag only) |
| M18 | Comment | #371 |
| M12 | Comments | #637, #860 |
| M13 | New issue | #887 |
| M08 | Comment | #864 |
| USB-09 | Comments | #588, #866 |
| M10 | New issue | #890 (bench study only) |
| CS-04 | New issue | #886 (owner decision first) |
| pin-03 | New issue | #888 (decide or decline first) |
| CS-10 | Not filed | owner decision only; conflicts with invariant 10 as written |
| SCA-09, M01, CS-06 | Not filed | rejected by the study |
| X1a | New issue | #889 (design first) |
| X1b | Comment | #371 |
| X2a | New issue | #875 |
| X2b | Comment | #69 |
| X3a | New issue | #893 |
| X4a | Comment | #89 |
| X4b | Comment | #182 |
| X5a | New issue | #876 |
| X5b | Comment | #846 |
| X6a | New issue | #884 |
| X6b | Comment | #534; doc parts ride in #884 |
| X7a | Comment | #154 |
| X7b | New issue | #892 |
| X8a | New issue | #877 |
| X8b | Comment | #542 |
| X9a | Comment | #304 |
| X9b | Folded | in the #486 comment |
| X10a | Comment | #541 |
| X10b | Comment | #752 |
| N1, N2 | Comment | #861 |
| N3, G1-8 | New issue | #869 |
| Stale requirement rows | Comment | #866 |
| Open checks with no owner | New issue | #894 |

### Not filed, and why

**Needs a new board, package or enclosure** (sections 14 and the hardware section keep these):

- Hardware asks G1-1 (debug access on a sealed unit; the decision itself is in #850), G1-2, G1-3, G1-4, G1-5, G1-6, G2-1, G2-2, G2-5 and G2-6.
- Every option of section 14: moving the buttons to free the tamper pins, the ball-grid package, trimmed seam loops, a fingerprinted mesh, an enclosure fingerprint, a larger backup capacitor, input-current sensing, a card-based backup.
- Loading the consumption-mask pin (M15), a reference capacitor or divider on PA6 (M10, M20), a case-open switch on PC13 and the "this unit was opened" state that goes with it (M11, owner decision 8).

**Owner decision with no work until it is taken:**

- CS-05: whether typed data without a pinned descriptor gets a lower "structure only" tier. It follows the RAW32 decision in #381.
- CS-10: a signed catalogue channel separate from firmware. As written it conflicts with invariant 10, because it changes what the device clear-signs without changing the boot fingerprint.
- M14, second part: whether a device that locked out is meant to be single-use or recoverable (stated in #870 and #168).
- M15: keep the consumption mask as a production requirement or demote it, after the measurement in #228.
- OEM2 key: #40 asks to provision one, the code and #387 require none (flagged in the #46 comment).
- The hide-protection posture (owner decision 5): #39 and #43 require it and no document configures it. Untouched by this pass.
- A fault record that survives power loss (SYS-06): needs a flash page and a new answer to #719.
- Not reopened: the minimum-version constant, Merkle-leaf signing, a hidden flash counter, signing-appliance firmware (each has a recorded verdict or needs an owner reopen).

**Already covered:** USB-01 (#846), pin-05 (#853), and most of M05, M04, M02, M08 and M16 through the issues filed on 2026-10-12.

### Limits of this pass

- Code reading and document reading only. Nothing was built, run or measured.
- "Untracked" means a search of issue titles and bodies as of 2026-10-12 found no owner. Comments on issues were read only for the comment targets.
- Each reviewer's judgement on whether an existing issue already covers a point was not re-derived by a second reviewer.
- No model from another family reviewed the drafts in this pass.
