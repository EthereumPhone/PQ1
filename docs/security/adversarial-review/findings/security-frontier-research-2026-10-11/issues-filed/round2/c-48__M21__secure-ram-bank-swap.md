COMMENT_ON: 48
---
**What "put secrets in SRAM2" takes on the current tree, and one point this issue does not make: the stack has to move too (2026-10-11 security frontier research, item M21). Lines re-read at master `c2fab970`.**

This issue already names the right bank and the reason ("SRAM2 is uniquely ECC-capable AND hardware-erased on tamper"), and #46 records "DECISION: secret buffers in SRAM2". The research adds four facts for whoever implements it.

**1. SRAM2 is the non-secure world's RAM today, so this is a bank swap, not a new section.**

- The secure world links all of its RAM into SRAM1: `secure/memory-stm32u585.x:31`.
- The non-secure (NS) world links into SRAM2: `nonsecure/memory-stm32u585.x:9`.
- The block-based protection for SRAM2 is set to all non-secure: `secure/src/sau.rs:440`.
- The NS RAM window is fixed in three places that are tied together by compile-time checks: the attribution region (`secure/src/sau.rs:49`), the pointer-validation window (`proto/src/lib.rs:59`) and the assertion that binds them (`secure/src/sau.rs:64`). Moving NS out of SRAM2 changes all three, and with them the gateway's pointer-validation surface, so the swap needs its own review.

**2. Moving only the named secret buffers protects the wrong object.** `master_secret` and the slot cache sit in a static (`secure/src/nsc/state.rs:564`), but the signing computation runs on the stack: the reconstructed entropy, the C10 secret seeds, the hash-chain scratch and the two signature buffers of the double-compute check. The stack is at the top of the same SRAM1 region (`secure/memory-stm32u585.x:35`). A design that relocates the statics and leaves the stack in SRAM1 leaves most of the bit-flip exposure, and leaves the stack outside the hardware tamper erase. The whole secure RAM region (data, zero-initialised data and stack) has to sit in the protected bank.

**3. Two candidate layouts, with different properties.**

- Swap banks, as Trezor does on the same chip family: secure RAM in SRAM2 (64 KB), NS RAM in SRAM1 or SRAM3. This gets error correction, the reset erase bit for SRAM2, and the hardware erase on a tamper event. That last property is why it matters here: `tamp` and `tamp-wipe` are forced on for shipping images, but as #47 notes the hardware erase covers the backup registers, SRAM2 and caches, and today no secret lives in any of those except the loaded hardware key. **It requires the secure world's RAM use, including the worst-case stack, to fit in 64 KB. That number does not exist until #374 produces it.**
- Relink secure RAM into the error-corrected part of SRAM3 and protect it with that bank's block controller. This is a smaller change and covers the stack, but SRAM3 is not erased by a tamper event.

**4. The choice gates #848.** The SRAM erase and error-correction option bits are frozen at RDP-2. Which bits to pin depends on which bank holds the secrets, so this decision has to be made before the ship option-byte profile in #848 can be completed.

Suggested additions:

- [ ] Decide the bank (swap into SRAM2, or SRAM3) after #374 gives the secure RAM size, and before #848 freezes the profile.
- [ ] Scope the move to all secure RAM including the stack.
- [ ] Secure the RAM configuration block first (#150). Until then non-secure code can reach the error-correction controls.
- [ ] Check in the reference manual whether error-corrected RAM must be initialised before the first read or partial-word write. If it must, zero the region at startup.
- [ ] Correct the status table row at `docs/security/brownout-hardening.md:321`, which says single-bit correction on SRAM1, SRAM2 and SRAM3 is "always active" with no configuration needed. The same document's own correction further up says it is off by default and set per bank by option bytes, and SRAM1 has no error correction at all according to #848. (#866 already assigns this row to this issue.)

**Limits.** The research did not re-read the reference manual for the option-bit polarity, the tamper-erase scope or the RAM initialisation rule; those statements come from this issue, #47 and the Trezor sources. Error correction turns a bit flip into a fault. It does not help against the same fault landing in both signing passes, against faults on registers or the instruction stream, or against probing a powered, unlocked unit. Bit positions and polarity need a sacrificial die (#544).

<sub>**Provenance.** Security frontier research, 2026-10-11 (report item M21, section 11). Report priority P1 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
