COMMENT_ON: 636
---
**What the 2026-10-11 security frontier research adds to this decision (report item pin-04). Line numbers are at master `c2fab970`.**

The premise still holds at master: `duress-pin` is in none of the three production feature lists (`Makefile:2662`, `Makefile:2703`, `Makefile:2719`), the only duress fences forbid the two test features (`secure/src/nsc/mod.rs:388`, `secure/src/nsc/mod.rs:389`), and no workflow under `.github/workflows` builds it.

**The residual list in the body has changed.**

- #370 looks fixed in the tree (see the comment there). It is no longer a prerequisite.
- #107 is still open and is a hard prerequisite: the SE050 decoy objects are in no wipe list.
- #863 is new and is a hard prerequisite: after a decoy unlock the device reports the real wallet's page-123 counters.
- #280 cannot be run on the open bench board, which has no display panel (#700). It needs an enclosed unit or the dev kit.

**Work that is needed whichever way the decision goes.**

- [ ] Add a compile-time fence that states the decision. Either `mode-production` with `dual-se` requires `duress-pin` (the shape of the tamper fence at `secure/src/nsc/mod.rs:754`), or it forbids it. Today neither holds, so a production image builds the same way with or without the feature and nothing records which was meant.
- [ ] Correct the two document lines that say the feature does not exist: `docs/security/threat-model.md:432` ("Not currently implemented") and `docs/security/HARDENING.md:279` ("worth deciding on"). The code exists; say what ships.

**Work only if the decision is to ship it.**

- [ ] Close #863 and #107 first.
- [ ] Measure the flash cost of `duress-pin` in a ship-shaped build. Not measured anywhere.
- [ ] Capture both unlock sequences on the two I2C buses with a logic analyser. By code read the two cases run the same number of operations in a different order. With the real PIN, the two decoy verifies fail first (`secure/src/dual_se.rs:291`, `secure/src/dual_se.rs:292`) and the real verify and reads follow (`secure/src/nsc/mod.rs:1571`). With the duress PIN, the decoy verifies and reads come first and two padding verifies with no reads follow (`secure/src/dual_se.rs:352`, `secure/src/dual_se.rs:353`). The traffic is encrypted, but frame lengths and order are visible on the bus. Whether that is distinguishable is unmeasured. #10 (item 3) currently says the timing twin holds against a passive bus sniffer.
- [ ] Run #280 on a unit with a panel, on the UI that will ship.
- [ ] The decoy objects on the OPTIGA are never locked (`secure/src/optiga/mod.rs:1332`). When the deferred OPTIGA lifecycle work is done it has to say what happens to them. Nothing to do before then.

**Residuals to write down with the decision.**

- The decoy wallet has no backup. Its entropy is fresh random data (`secure/src/crypto.rs:553`) and is never shown as a mnemonic, so funds put there to make it look real are lost on a wipe or a lost device.
- "Open the decoy by default, wipe only if chosen at setup" is how the code behaves. It is not a recorded owner decision.
- Wipe-on-duress ends the life of the hardware on the locked profile, for the reasons in #168. It also discards the wipe result (`secure/src/nsc/mod.rs:1567`, already in #863).
- An attacker who extracts the OPTIGA pairing secret tells the two wallets apart by object id (#10 item 3).

Not checked: I did not trace the per-command sequence inside each chip driver, and no bus capture exists. Nothing was run on silicon.

<sub>**Provenance.** Security frontier research, 2026-10-11 (report item pin-04, section 8). Report priority P2 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
