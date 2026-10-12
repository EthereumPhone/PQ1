COMMENT_ON: 220
---
**The bootloader self-check in this issue does not defend against the threat it is filed for (2026-10-11 security frontier research, item M07).**

`docs/security/threat-model.md:518` states the threat: "A re-flashed FSBL today could substitute a different vendor key and the device would not refuse", and names the OTP hash as the defence. The third checklist item here has the bootloader compare its own embedded key with the OTP hash and halt on a mismatch.

A re-flashed bootloader is the attacker's code. It simply leaves the check out. A check that only the genuine bootloader runs cannot detect that the bootloader was replaced.

What does defend against a replaced bootloader sits outside the device: comparing the whole bootloader image with the reproducible build over the debug port before first power (invariant 10, part (a)), and then write protection plus RDP-2. That comparison already covers the embedded key, because the key is part of the image. Today the tool for it compares no flash at all; that is #850.

Suggested disposition (owner's call):

- [ ] Drop the third checklist item (bootloader-side boot verify), or close this issue as declined with the reason above. The research's merger and its independent reviewer both reached this.
- [ ] If an OTP key hash is still wanted, scope it as one more value the external check reads (#850), and note that it adds nothing the full image comparison does not already give.
- [ ] Reword `docs/security/threat-model.md:518` to name the pre-first-power comparison and the lock as the defence.

Dropping it also keeps one claim out of the still-open OTP allocation (#543).

Evidence: document and issue text read at master. Nothing was run.

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item M07, section 9, "considered and rejected": bootloader self-check of its key against OTP). Report priority P2 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
