TITLE: First on-silicon fault-injection campaign on the firmware's own gates (PIN gate, signature compare, bootloader admission): untracked legs and a receipt rule
LABELS: enhancement,priority:high,surface:sca-fi,surface:hardware,source:frontier-research-2026-10
---
## Summary

No physical glitch has ever been applied to this firmware. A bench plan exists in `docs/security/red-teaming.md` (sections 4.4, 9 and 11), and four issues cover parts of it: #401 (the attempt to downgrade readout protection level 2, RDP-2), #301 (buying and standing up the rig), #402 (host tooling) and #228 (leakage). Nothing tracks the legs that aim at the firmware's own gates on silicon: the PIN gate with a wrong PIN, the double-compute compare in the C10 signer (C10 is the SPHINCS+ variant this wallet signs with), and the admission gates of the first-stage bootloader (FSBL). Nothing tracks the bench-only firmware those legs need, and nothing says what a result must contain to count as evidence. This issue covers those three things only. It is a measurement, not a countermeasure, and most of the firmware part can be written before the rig works.

## What the code does today

- `docs/hardware/evt-silicon-validation.md:12`: fault-injection resistance "has *never* been exercised on any hardware at all".
- `docs/security/red-teaming.md:852`, `:854`, `:855`: the plan's coverage map names the `gated_unlock` verdict, signature verify-before-release and firmware signature verify as glitch targets. None of the three has an on-silicon issue.
- `secure/src/hw/sca_trigger.rs:26` and `:31`: the scope-trigger module says it fires around the hardened C10 sign function and around `gated_unlock`. A search of `secure/src` at master finds no call to `Trigger::raise` or `trig_high` outside that module and its source-text tests. The pin never toggles. (#228 asks to wire it around the signing pseudo-random function only.)
- `secure/Cargo.toml:679` and `secure/src/nsc/mod.rs:135`: the `sca-trigger` feature exists and is listed in the release-build `compile_error!` fence, so every campaign image is a non-shipping image.
- `secure/src/board/pq1.rs:338` and `:317`: on pq1 the trigger is PB3, the debug trace (SWO) pin, which the comment says "is already on the 10-pin" debug header. The open bench board can expose it. An enclosed unit cannot.
- `fsbl/src/main.rs:344` is the bootloader signature gate. The bootloader has a `stage-marker` bench feature (`fsbl/Cargo.toml:72`) and no trigger feature, so a glitch on its gates cannot be timed from a pin.
- `secure/src/nsc/mod.rs:1415` and `:1494`: `gated_unlock` charges flash page 124 before the secure elements see the PIN. A wrong-PIN shot then also consumes an attempt on the OPTIGA counter (limit 32, `secure/src/optiga/mod.rs:1368`) and on the SE050 UserID object.
- `secure/src/nsc/mod.rs:53` and `:54`: the one wrong-PIN driver that needs no buttons, `cmd_test_pin_lockout`, is compiled only under `e2e-test`. That feature cannot be used for this campaign: `secure/src/fi.rs:87` to `secure/src/fi.rs:89` make `wait_random` return at once under `e2e-test`, so an `e2e-test` image has no random delay in any gate and is a weaker binary than the one that ships.
- A correct PIN resets all three counters: page 124 (`secure/src/nsc/mod.rs:1614`), the OPTIGA counter (`secure/src/optiga/mod.rs:2650`) and the SE050 counter on the chip (per the driver comment at `secure/src/se050/mod.rs:152`).
- `secure/src/crypto.rs:350`, `:358` and `:373`: the signer computes the signature twice and compares. The comment at `:366` says this compare "is itself a single-instruction" skip point backed by the verify gate. No feature turns the second computation off, so the countermeasure cannot be measured on and off.
- `secure/src/hw/rcc.rs:3`: the system clock comes from the internal HSI16 oscillator through PLL1. There is no external clock to glitch.
- `docs/security/red-teaming.md:125` refers to the host tooling as "`tools/bench/` once stood up". At master that directory is not in git at all (`git ls-files tools/bench` prints nothing). The instrument probe scripts that the research read exist only as untracked files in one working checkout.

## What is already tracked elsewhere

- #401 covers the RDP-2 downgrade campaign on sacrificial parts. It is not repeated here.
- #301 covers the rig. #402 covers the host orchestration in `tools/bench/`.
- #591, #847 and #865 cover the emulated (host-only) sweeps of the bootloader and the C10 verifier, and the bootloader code defects.
- #232, #592 and #296 cover the emulated sweeps of the C10 signer.
- #228 and #236 cover the on-silicon leakage measurements.
- #376 covers the on-silicon fault campaign for the ERC-7730 descriptor checks. #544 covers the sacrificial-silicon campaign for the rollback backend.
- So this issue is only about the three gate legs on silicon, the bench images for them, and the receipt rule.

## Proposed work

Bench firmware (no rig needed to write it):

- [ ] Wire the trigger per target, not around whole operations: immediately before the secure-element verdict is consumed in `gated_unlock`, and immediately before the `ct_eq` compare in the hardened sign function (`secure/src/crypto.rs:373`). Correct the module doc so that it lists only call sites that exist.
- [ ] Add a trigger toggle to the bootloader as a bench-only feature that cannot be combined with `mode-production`: around the signature gate, the image-hash gate, the slot choice and the branch.
- [ ] Add a fenced bench feature that supplies PINs without buttons and bypasses the confirm dialog, and that leaves `wait_random` live. It must not be `e2e-test`.
- [ ] In the same feature, re-arm the three PIN counters between shots (a correct-PIN unlock after every shot does it), so that a run is not limited to ten shots per provisioning.
- [ ] Show by diffing the disassembly that the code under test is byte-identical with and without the bench feature. The diff must cover `gated_unlock` and what it calls: `wait_random`, `wait_random_loop` and `check_true_into_sentinel`. Those are never inlined, so the caller alone can match while a callee is gutted.
- [ ] Add a never-ship feature that disables the second signature computation, so that the countermeasure can be measured on and off. Put it in the release `compile_error!` fence in `secure/src/nsc/mod.rs`.
- [ ] Write an oracle that classifies a faulted C10 signature as rejected, harmless, or usable for a grafting forgery. The public SPHINCS+ fault tooling targets the reference parameter sets and does not run against C10.

Campaign legs:

- [ ] PIN gate: wrong PIN, glitch the verdict window. Pass means no unlock, and no shot that leaves all three counters unchanged.
- [ ] Signature compare: glitch the compare with double-compute on and off, then the verify gate behind it. Report the two-fault case from the plan (`docs/security/red-teaming.md:854`) separately.
- [ ] Bootloader admission: glitch the signature gate, the slot word and the slot choice on the bench bootloader (the code defects are #847). Run it after #591, so the emulated sweep says where to aim.

Receipt rule (what makes a result count):

- [ ] Each result names the image by its reproducible-build hash, the board, the die revision, the rig, the swept ranges of delay, width and intensity, and the number of shots.
- [ ] Scripts and raw outcome logs are committed under `tools/bench/`, which first has to be committed itself (#402).
- [ ] A null result is written as "nothing in the swept window", never as "resistant". A single-fault null on a target that needs coordinated faults is labelled as that.
- [ ] Results for the secure image are per release. Only the frozen bootloader binary and the die-level RDP-2 answer (#401) are one-off.

## What it needs

A bench campaign on existing units. Nothing in the product changes.

- The open bench board: it has a debug port and the trigger pin. It has no display, so the PIN must come from the new bench feature above, not from buttons and not from `e2e-test`.
- A fault-injection rig. The plan lists a Scaffold, a FaultyCat and a Rigol MHO934 as on hand. How to couple the voltage glitcher to the U585 supply is not settled: the plan says the injection rail has to be identified on a sacrificial part first, and that removing decoupling capacitors sharpens the glitch. Both are rework on that part.
- Sacrificial units for the PIN leg (see Limits).

The bench-firmware checkboxes are firmware only.

## Limits

- The PIN leg can cost a unit its secure elements. If the re-arm fails, ten wrong-PIN shots lock the SE050 UserID object and page 124, and the only way back is the wipe path. #865 (item 4) reports, by source read, that the wipe-and-reprovision path cannot pass on a current build. So the re-arm feature has to be shown to work first, and the leg needs units that can be lost, or a mock secure-element build that tests only the MCU half of the gate.
- A campaign can falsify, it cannot prove. A result holds for the swept window, on these parts, at these conditions.
- Fault behaviour belongs to one binary. A result on the bench bootloader does not transfer to a later frozen bootloader, and a result on one secure image does not transfer to the next release. This is a recurring cost.
- An electromagnetic pulse near the secure elements can damage them. The plan (section 13.3) says to check that both still answer between shots.
- Not checked by me: the state of the rig, the die revision of any bench part, and whether PB3 is free on the bench board in practice. The research rated this item P0. Nothing was run, and nobody has shown an attack on these gates on silicon.

## Related

#401, #301, #402, #228, #236, #591, #847, #865, #232, #592, #296, #376, #544.

Public sources: [Bozzato et al., TCHES 2019](https://tches.iacr.org/index.php/TCHES/article/download/7390/6562/2561) (RDP-2 downgrade on an STM32F3 with one glitch), [μ-Glitch, USENIX Security 2023](https://www.usenix.org/system/files/usenixsecurity23-sass.pdf) (TrustZone-M on the STM32L5 with four coordinated faults), [Genêt, TCHES 2023](https://eprint.iacr.org/2023/042) and [RFC 9814](https://www.rfc-editor.org/rfc/rfc9814.html) (grafting faults on hash-based signatures).

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item FI-01, section 3). Report priority P0 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
