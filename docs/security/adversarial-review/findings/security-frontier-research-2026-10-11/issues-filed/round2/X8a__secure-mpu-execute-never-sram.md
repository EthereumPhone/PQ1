TITLE: Mark secure RAM execute-never with the secure memory protection unit, so a fault that redirects the program counter cannot run bytes the companion supplied
LABELS: enhancement,priority:medium,surface:trustzone,surface:runtime,surface:sca-fi,source:frontier-research-2026-10
---
## Summary

No image programs a memory protection unit (MPU). On a Cortex-M33 that leaves all of secure RAM executable. The secure world copies up to several kilobytes of companion-supplied bytes into a static buffer at a fixed, build-determined address, and it runs at one privilege level with the keys. If a fault ever loads an attacker-supplied word with bit 0 set into the program counter, the device executes those bytes. One MPU region that marks secure RAM execute-never (XN) turns that into a fault, and the existing HardFault handler already zeroizes and resets. The repository's own Trezor comparison says this recommendation "stands", but the only MPU issue (#277) is about a much larger change, a privilege split for parsers, which is deferred. This issue tracks the small execute-never part by itself. It is defence in depth, not an isolation boundary.

## What the code does today

- A search for `MPU`, `PRIVDEFENA`, `HFNMIENA` and `MemManage` over `secure/src`, `fsbl/src`, `nonsecure/src`, `shared/src`, `hw/src` and `pqsigner-fi/src` at master finds nothing. The only region registers in the tree are those of the security attribution unit (SAU) (`secure/src/sau.rs:80`).
- `secure/memory-stm32u585.x:31` and `secure/memory-stm32u585-slot-a.x:52`: one RAM region at `0x30000000`, 192K, holding statics and the stack. `secure/memory.x:24`: the QEMU build links RAM at `0x38000000`, 128K.
- `secure/src/nsc/mod.rs:1042`: `SIGN_SNAP_BUF` is a `static mut` byte array that every sign handler fills with the non-secure caller's payload. Its address is fixed by the link, and the build is reproducible, so the address is public.
- `secure/src/main.rs:4751` and `:4756`: the HardFault handler zeroizes the secret caches and resets. Its doc comment says escalated memory, bus, usage and secure faults all funnel into it. `:4749`: the handler is compiled only for `stm32u585`, so the QEMU build has no equivalent.
- `secure/src/main.rs:1354`: `sau::init()` is the point after which an MPU setup would go.
- Docs: `docs/architecture/trezor-comparison.md:429` says "PQSigner currently uses only SAU; MPU is unused. Adding MPU is the standard DEP defense and costs ~150 LOC", and `:433` says the write-xor-execute recommendation "stands". `docs/STATUS.md:626` tracks only "MPU privilege-banking".
- Sections placed by attribute: `secure/src/rng.rs:20`, `secure/src/db_roots.rs:151` and `secure/src/fw_update/vendor_pubkey.rs:31` use `link_section`. The ones I opened are data markers, not code, and I found no `ramfunc`. I did not inspect a linker map.

## What is already tracked elsewhere

- #277 covers the privilege split for attacker-data parsers (supervisor calls plus MPU, ranked L to XL, deferred). It does not itemise execute-never.
- #54 lists the MPU among the unused-feature decisions to record, and expects the answer "unused". The outcome of this issue belongs there.
- #854 asks for the stack limit register (MSPLIM) in the secure reset path. That is the stack-overflow control. An MPU guard page below the stack would duplicate it, so it is not part of this issue.
- #374 covers the worst-case stack bound.
- The bootloader half (the first-stage bootloader has no MPU either, and can never gain one after the freeze) is a separate decision for the bootloader guard policy in #542.
- So this issue is only about one execute-never region over secure RAM in the updatable secure image.

## Proposed work

- [ ] Add a small MPU module using the existing typed register helper (`hw/src/mmio.rs:37`), programmed right after `sau::init()` and before any non-secure data is copied.
- [ ] One region over all of secure RAM: privileged read and write, execute-never. Take the bounds from linker symbols per platform, not from literals (the QEMU RAM base differs).
- [ ] Enable with the default map kept for everything else (`PRIVDEFENA`) and with the MPU active inside the HardFault and non-maskable interrupt handlers (`HFNMIENA`). Read the registers back and halt on mismatch, as the SAU setup does.
- [ ] Leave the memory-management fault disabled so a violation escalates to the existing HardFault handler. Do not route it to the secure-element wipe.
- [ ] Add a build gate on the linker map: no executable input section may land in RAM. A source search is not enough.
- [ ] Decide whether a second execute-never region over the inactive firmware slot and the per-device data pages is worth a region. During an update the inactive slot holds bytes that were streamed in before the commit step checks the signature. Check the layout against the `pqsigner-geometry` crate first.
- [ ] Acceptance test under a test-only feature that the production fence rejects: fill `SIGN_SNAP_BUF` with a small instruction sled, force the program counter to it with bit 0 set, and show the fault path runs. Negative control: with the MPU write compiled out, the sled must execute. Without bit 0 set the test passes for the wrong reason (an invalid-state fault), so the control must use an odd target.
- [ ] Give the QEMU build an observable fault path so the test can also run in `make e2e`.
- [ ] Record the result in #54 and add a row next to `docs/STATUS.md:626`.

## What it needs

Firmware only, in the updatable secure image. The silicon acceptance run needs the open bench board with its debug port; that board has no display, so the evidence must be UART or debug-port output. No board change.

## Limits

- Execute-never stops injected code. It does not stop code reuse. The same fault can load a flash address, and all flash addresses are public through the reproducible build, so a jump past a confirm gate is unaffected. Control-flow integrity stays the job of the existing sentinel, counter and double-compute gates.
- A fault that loads an ordinary (even) data pointer into the program counter already ends in the HardFault handler today, because the Thumb bit is clear. This control only matters when the loaded word is odd and attacker-chosen.
- The secure MPU has no lock. Any secure privileged code can rewrite it. This is not a substitute for #277.
- A wrong region bound faults at boot, so the change needs both the QEMU run and a silicon run before it is trusted.
- Not checked by me: that QEMU's board model implements the secure MPU, and the exact reset state of the MPU registers on this part. No attack through this path has been demonstrated.
- The research reviewer lowered the proposed priority from P1 to P2 for the reasons in the first two bullets.

## Related

#277, #54, #854, #374, #542, #846 (the handler that fills `SIGN_SNAP_BUF`).

Public source: Trezor maps RAM execute-never on its STM32U5 devices, in [`core/embed/sys/mpu/stm32u5/mpu.c`](https://raw.githubusercontent.com/trezor/trezor-firmware/main/core/embed/sys/mpu/stm32u5/mpu.c) (read by the research in a local checkout; I did not re-open it).

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item X8a, section 12). Report priority P2 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
