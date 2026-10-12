COMMENT_ON: 542
---
One decision to add to the FA-2.0 guard and fault policy freeze, from the 2026-10 security research (item X8b). **It has to be taken before the first unit is locked**: the bootloader pages become permanent once write protection and readout protection level 2 (RDP-2) are set (invariant 10), and a bootloader frozen without a memory protection unit (MPU) setup can never gain one.

**State today** (lines at master `c2fab970`)

- The bootloader programs the security attribution unit (SAU) and nothing else: `fsbl/src/sau.rs:35` and `fsbl/src/sau.rs:36` are the only region registers in `fsbl/src`. There is no MPU write and no stack limit (the stack limit half is #854).
- So while it verifies images, everything it can read is also executable: its own RAM (`fsbl/memory-stm32u585.x:34`, 16K) and all of secure bank-1 flash, including both manifests and both slots at fixed addresses (`fsbl/memory-stm32u585.x:19` to `fsbl/memory-stm32u585.x:23`). Those flash areas hold bytes the bootloader has not yet checked.
- The research first described the risk as "manifest and signature bytes copied into RAM". That is wrong for the current code: `fsbl/src/manifest.rs:41` borrows the manifest straight from flash. The only attacker-chosen bytes in bootloader RAM are the 256-byte hash chunk (`fsbl/src/verify.rs:119`) and verifier scratch. The larger executable surface is the unchecked flash.

**The decision**

Either land a small default-deny MPU table in the bootloader, or record in the freeze review that it is declined, with the reason. What must not happen is that RDP-2 makes the omission permanent without anyone having decided it.

If it lands, the reviewed shape is:

- [ ] Read and execute over the bootloader's own pages only, taken from the same load span that `scripts/check_fsbl_geometry.py` reports.
- [ ] Read and write, execute-never, over the rest of the flash it reads (manifests, boot state, both slots), over its RAM window and over peripherals. One region over RAM alone, with the default map kept, would leave the flash executable and miss most of the surface.
- [ ] Active inside the HardFault and non-maskable interrupt handlers.
- [ ] Disabled again before the handoff in `fsbl/src/branch.rs:76`, next to where a stack-limit clear would go. The secure image programs no MPU today, so leaving a default-deny table enabled would fault the slot on entry.
- [ ] A constant assertion that ties the region bounds to the geometry crate, because the bench feature used for the test below cannot be in a production build.
- [ ] Acceptance on the open bench board with the `stage-marker` feature and a positive control: with the table compiled out, a small stub copied to RAM and one placed in slot flash both run and record a marker; with the table on, neither does. A silent halt is not evidence, since the bootloader halts silently on many paths. The bootloader is not run under QEMU (`fsbl/src/manifest.rs:32` notes that QEMU loads the secure world directly).
- [ ] Record the outcome in #54, which lists the MPU as a decision to record.

**Limits, so the decision is not oversold**

- The handoff branch itself runs after the MPU is switched off.
- The bootloader holds no secrets. A single skipped branch on the admission gates (#847) reaches "boot an unchecked slot" more cheaply than a redirected program counter. This item ranks below those; the research reviewer rated it P3.
- It stops execution of injected bytes, not reuse of the bootloader's own code.
- It spends bytes in the frozen range. The size was estimated by the research (a few hundred bytes), not measured.
- Not checked: that a secure-state instruction fetch from the non-secure flash alias faults on this part (the reviewer assumed it does).

Needs: bootloader firmware, and the open bench board for the acceptance run (it has a debug port and no display, so the evidence is the stage markers).

Related: #854 (stack limit and NMI handler in the bootloader), #847, #540, #226, #54.

<sub>**Provenance.** Security frontier research, 2026-10-11 (report item X8b, section 12). Report priority P3 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
