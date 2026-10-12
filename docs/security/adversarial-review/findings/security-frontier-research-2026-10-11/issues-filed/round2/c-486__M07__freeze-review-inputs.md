COMMENT_ON: 486
---
**Corrections and additions to the design note before the dual-key decision is taken (2026-10-11 security frontier research, items M07 and X9b).**

The note already carries the open boxes: Option B accepted or declined (`docs/security/vendor-signing-key-compromise.md:94`), B plus a minimum-version floor as one decision (`docs/security/vendor-signing-key-compromise.md:134`), the secure-update freeze costed (`docs/security/vendor-signing-key-compromise.md:140`). Its own round-3 correction already records that the frozen Draft 1.1 rejects a compiled-in floor (`docs/security/vendor-signing-key-compromise.md:576`) and that a second key needs an amendment row. #544 and #545 name #226 as the owner of the bootloader freeze review. So the decision needs no new issue. What follows is what the research's independent reviewer found wrong or missing in the text the decision will be taken from. I re-read each code line at master.

**1. Option B is not only a bootloader change.** The secure image carries its own copy of the key (`secure/src/fw_update/vendor_pubkey.rs:32`), and `FW_BEGIN` verifies against that copy (`secure/src/fw_update/mod.rs:519`). `fwsign` refuses any bundle whose bootloader key and secure-image key differ (`fwsign/src/artifact_key.rs:596`). On a locked unit the update commands are the only install path (#696). A shipped secure image that knows only the primary key therefore refuses a recovery-signed image at `FW_BEGIN`, before the bootloader ever sees it. B needs the recovery key in every shipped secure image, an either-key `FW_BEGIN`, and a changed `fwsign` gate and key-policy file.

**2. The recovery flow in the note cannot work as written.** The note says the recovery key signs a firmware "whose embedded secure-world pubkey is the *new* primary" (`docs/security/vendor-signing-key-compromise.md:63`) and that later updates are signed by that new primary. The bootloader re-verifies the manifest signature on every boot against its own baked key (`fsbl/src/main.rs:345`). A new primary that is not in the frozen bootloader can never sign a manifest that boots. After a recovery, the recovery key is the only usable signing key. It is no longer cold and it has no successor. The note should say so, or cost a third baked key.

**3. The stated boot cost is too high.** The note counts one extra signature verification at boot (`docs/security/vendor-signing-key-compromise.md:71`, `docs/security/vendor-signing-key-compromise.md:397`). The bootloader checks the manifest's key fingerprint before the signature (`fsbl/src/main.rs:338`), so the fingerprint can select which key to verify with. It is one signature verification either way. The cost is the 32-byte key plus a second fingerprint compare behind a fault-injection sentinel. Not measured.

**4. A residual the note lacks.** With two valid slots the bootloader boots the higher version (`fsbl/src/main.rs:378`), and no working rollback floor exists (#31). A holder of the leaked primary can sign at the top of the 32-bit version space. On a unit that installs that image first, no recovery image can outrank it. The sentence "the recovery key provides a path above it" (`docs/security/vendor-signing-key-compromise.md:396`) does not hold for those units.

**5. The decision has an earlier deadline than the write-protection freeze.** #541 fixes a measurement profile with "a real-size 32-byte vendor key" and blocks #543, #546 and #544. One key or two has to be decided before that profile is frozen, or the warning build measures the wrong bootloader.

**6. The concrete reason against a two-signature quorum is not recorded.** The note declines m-of-n because there is no aggregation and N keys mean N verifications (`docs/security/vendor-signing-key-compromise.md:47`). The harder reason is size: a second 4,008-byte signature does not fit the one-page manifest. The legacy layout has 3,995 reserved bytes (`fw-manifest/src/lib.rs:78`). The v6 candidate has 3,916 (trailing reserved starts at byte 4,272, `fw-manifest/src/v6.rs:90`, and the CRC sits at 8,188).

**7. Two rows the note does not have.**

- *Merkle-leaf signing* (one signature over a root that covers several images, with a short proof per image). The research's default is "declined, with a record". It would change what is signed, so it falls under the rollback-manifest rule in `CLAUDE.md` (approved specification digest, dual review, owner stage decision). It is listed here only so the freeze record shows it was considered.
- *Signature-algorithm agility in the bootloader.* `CLAUDE.md:358` already rules out a second algorithm ("One algorithm in the wallet, one in the FSBL"), and `docs/feature-roadmap-research-2026-06.md:200` lists the hybrid as excluded. But `docs/archive/work-todo-retired-2026-07-19.md:2226` still reads "KEPT as LOW PRIORITY / future consideration", and the note is silent. After the freeze there is no future in which the bootloader gains a second algorithm. The record should state the consequence in plain words: boot-time acceptance is this one scheme over SHA-256 for the life of the die, and a break of the scheme or a wrong-accept bug in the frozen verifier has no field remedy other than return. **This does not ask to reopen invariant 5.** If the manifest is ever cited as the reason, the correct statement is that 3,916 bytes cannot hold a second signature of the same scheme; the real blockers are the exact schema byte, the erased-reserved check, the bootloader budget and invariant 5.

The compensating control for the second row is to complete the cross-implementation check of the verifier before the freeze. A comment posted on #304 the same day lists the missing Rust leg.

Suggested boxes for the note's "Decision points":

- [ ] Option B text corrected (points 1 to 4) before B is accepted or declined.
- [ ] Key count decided before #541's profile is frozen.
- [ ] Two-signature quorum: add the page-size reason.
- [ ] Merkle-leaf signing: declined, or reopened by the owner through the candidate review.
- [ ] Bootloader signature-algorithm agility: accepted or declined at the freeze review (research recommendation: declined), with the consequence sentence.
- [ ] Fix the archive line or add a supersession note beside it.

Deliberately not in this comment: the hidden flash-page counter that Trezor uses. The frozen draft requires authoritative rollback records to remain in OTP (`docs/security/a-b-firmware-rollback-architecture.md:3896`), and `docs/architecture/trezor-comparison.md:413` already records the verdict "RE-EVALUATE AFTER DRAFT-1.1 CANDIDATE GATES". Raising it again is an owner reopen, not a review tick.

**All of these are bootloader decisions. None can be changed after the first unit is locked.** No board change is involved.

Not checked: nothing was built or measured. Point 3's cost and the "M" size of point 1 are the reviewer's estimates.

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report items M07, section 9, and X9b, section 12). Report priority P2 (M07) and P3 (X9b) are research ratings, not owner decisions; the reviewer put the key-count decision alone at P1 because of point 5. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
