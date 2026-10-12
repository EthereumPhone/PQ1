COMMENT_ON: 855
---
**Design constraints for the fix directions in this issue, from the 2026-10-11 security frontier research (item M16) and its independent review. Line numbers are at master `c2fab970`.**

The five fix directions in the body match the reviewed recommendation, including the PIN-keyed mask on each seed half. The review added the points below. None of them is in the body, and three of them change the cost or the order of work.

**1. The salt has no free flash page. This is an owner decision.**

- Every page at the top of flash bank 1 already has an owner in the geometry registry: page 123 (`geometry/src/lib.rs:129`), page 125 (`geometry/src/lib.rs:131`), page 127 (`geometry/src/lib.rs:133`), and the two between them.
- Page 124 cannot hold it: the page is erased after every successful unlock (`secure/src/nsc/mod.rs:1614`).
- Page 125 is the likeliest co-tenant. But it is cleared only by the whole-page erase that ends a wipe (`secure/src/hw/flash.rs:633`), and the wipe-in-progress flag on the same page has to stay armed while the wipe runs. Erasing the salt first would therefore mean programming its quad-word to all zeros. The reference manual allows that one case (RM0456 Rev 7, section 7.3.7: "Programming in a previously programmed address is not allowed except if the data to write is full zero"). It has not been tried on silicon.
- The alternative is a registry change under #540.
- The same page decision comes up for a microcontroller-side "wallet provisioned" record that the research proposes as a seed-wizard gate. Decide the two together.

**2. Why the salt and the order of its erase carry the fix.**

With the die-bound digest but no salt, the device itself becomes a PIN test oracle for someone who has read one chip. The reasoned chain: emulate the extracted OPTIGA (its tunnel key is in the dump). For each guess typed on the device, the emulator receives a keyed hash made from the device's digest for that guess and checks it against the digest it extracted. It then answers with a transport error, so the SE050 is never called (`secure/src/dual_se.rs:376`) and its counter is not spent. After ten guesses the device wipes; the attacker interrupts the SE050 leg of the wipe, and page 124 is reset anyway (the unconditional reset sites are listed in the 2026-10-12 comment on #106). Ten more guesses follow, without limit. A salt that is erased at the very start of every wipe makes the extracted digest useless after the first cycle, so the attacker gets ten guesses in total.

- [ ] Erase the salt inside each wipe entry point, before any secure-element command and before the combined result of the two chip wipes is evaluated.
- [ ] Treat the conditional page-124 reset in #106 as a prerequisite of this issue, not a neighbour.

This chain is reasoned from the code. It was not run.

**3. Scope facts (the review raised the cost from medium to large).**

- OPTIGA: `derive_pin_secret` (`secure/src/optiga/mod.rs:916`) has 11 call sites, some of them for the duress credential. The duress set has to change in the same commit or it stops being a timing twin.
- SE050: the user credential is written at `secure/src/se050/mod.rs:2022` and presented at `secure/src/se050/mod.rs:2776`. The same commands also carry the admin and transport credentials (for example `secure/src/se050/mod.rs:570`), and those must not change. About 26 lines in that file call `verify_session` and about 15 call `write_userid` or its unlimited variant, many of them in bench self-tests, so each one has to be classified.
- The key-derivation helper takes a label capped at 64 bytes (`secure/src/hw/secret_keys.rs:186`). A 22-byte label, a 32-byte salt and the 8-byte PIN come to 62. The helper was written for public labels, so it needs a review for a secret input.
- Under `otp-hardcoded-master-key` (`secure/src/hw/secret_keys.rs:146`) the digest is derived from a constant, so it is not die-bound. That is a bench-only build; say so in the code.
- The domain tag at `secure/src/optiga/mod.rs:70` is pinned by a source-text test (`secure/src/optiga_under_test/pure_tests.rs:1568`). Change it deliberately.
- The mock and QEMU backends and the fixed-PIN test path need the same change.
- No OPTIGA reset is needed for this: the new secret is still 32 bytes, written by the same command under the access conditions in force today. It does have to land before the F1D0 access condition is frozen (#12) and before the first-boot ceremony is approved (#268). I searched `secure/src`, `proto/src` and `shared/src` for a PIN-change flow and found none, so there is no re-wrap problem for the PIN-keyed mask.

**4. Parts the review dropped. Please do not add them back without new evidence.**

- PBKDF2 stretching of the PIN: under 15 bits against an attacker who already holds a die oracle, and a long software hash over the PIN is the side-channel exposure this change removes.
- Folding in the second hardware key (BHK): that key has open lifecycle defects (#707, #712).
- A half mask that is not keyed by the PIN: two chip emulators plus the unmodified microcontroller would open the wallet.
- A device-key known-answer check before PIN attempts: it belongs with #692 and #400.

**5. Not measured, and what each check needs.**

- Whether the SE050 accepts a 16-byte user UserID value with `max_attempts = 10`. A 16-byte value is in use only for the admin credential (`secure/src/hw/secret_keys.rs:407`). Needs a bench unit; the pq1 bench board carries the E2 variant.
- Single-trace leakage of the hardware AES-CMAC with the PIN as the message. Needs an oscilloscope and a shunt on a bench unit.
- The all-zero quad-word reprogram in point 1, which the manual allows but nobody has run here. Needs a bench unit with a debug port, on a scratch page.

**6. What remains after it lands.** A malicious secure-world image can select the device key and recompute everything. One extracted chip plus an emulator gets ten guesses in total. Both chips extracted, plus the unmodified microcontroller and two emulators, also gets ten guesses, provided the mask is PIN-keyed.

**7. One more sentence to check.** The review flagged `docs/security/threat-model.md:121` ("cannot READ `half_E`") as resting on the same assumption as the sentences already listed in the body. I did not work that chain through.

<sub>**Provenance.** Security frontier research, 2026-10-11 (report item M16, section 7). Report priority P1 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
