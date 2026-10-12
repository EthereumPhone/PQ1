Re-check of 18 rows against c75b0d9c: 12 confirmed, 5 partly, 1 refuted. Nothing in the repo was modified, built or flashed.

Conventions: `R` = `/home/nicola/repos/PQSigner_OS`. `git status --short` shows 28 modified files; of the files these rows cite, only `pqsigner-fi/src/lib.rs` is modified, and I read it with `git show c75b0d9c:`. Manual = RM0456 Rev 7 (March 2026), extracted to `/tmp/claude-1000/-home-nicola-repos-PQSigner-OS/7844318a-f4f1-49a2-b794-31ae48f548cc/scratchpad/rm/rm0456.txt`. Section numbers are Rev 7's; the repo's own comments cite older revisions (TAMP is §64 here, not §45/§50). Ship set = `R/Makefile:2662` and `:2718`, which are identical strings.

ROW A13: CONFIRMED
- Corrected citations: RM0456 Rev 7 §7.9.1 (p. 329) and Table 72 in §7.5.7; `R/secure/src/hw/rcc.rs:180-183` (the only FLASH_ACR write, once at boot, never re-read); no `FLASH_PRIVCFGR` write anywhere in `secure/`, `fsbl/`, `shared/`, `nonsecure/`.
- Decisive text (§7.9.1): "This register is nonsecure. It can be read and written by both secure and nonsecure access. This register can be protected against unprivileged access when NSPRIV = 1 in FLASH_PRIVCFGR register."
- Imprecise:
  - "Even after RCC is secured" is counterfactual; RCC is not secured today (row A7).
  - NSPRIV only stops unprivileged non-secure code.
  - The lever is wider than wait states: the same register holds PDREQ1/2, LPM and SLEEP_PD, and `FLASH_PDKEYxR` is also non-secure (§7.9.5).
- Doubt: nobody has shown that lowering LATENCY produces a usable fault in secure code; the secure HardFault handler zeroizes and resets, so it may only be a denial of service.

ROW A16: PARTLY (the core defect is confirmed)
- Corrected citations: `R/secure/src/hw/tamp.rs:270-272` (clear), `:86` (first `TAMP_SR` read, in `poll`), `:287-299` (CR1 enables); `R/secure/src/main.rs:1400` (`tamp::init`), `:1529` (BHK load), `:1644` (`setup_systick`), `:4327` (`poll`). `tamp.rs:364-396` and `:372` are `tamp-irq` only, which is not in the ship set.
- Decisive code: `// Clear any pending tamper flags from a prior power cycle (backup` / `// domain survives reset, so we may see stale flags at first boot).` / `REG.tamp_scr.write(0x0007_FFFF);`. Manual §64.7.12, TAMP_SR: "System reset: not affected".
- Order in the init path:
  1. PWREN, RTCAPBEN, DBP, LSION, wait for LSIRDY, RTCSEL/RTCEN, MONEN (`tamp.rs:231-263`).
  2. `TAMP_SCR` write at `:272`. This is the first TAMP register access of the boot; no `TAMP_SR` read precedes it.
  3. FLTCR, CR1, CR3 = 0, IER.
- Mask: `0x0007_FFFF` clears the eight external flags plus ITAMP1, ITAMP2 and ITAMP3. ITAMP3 needs LSECSSON, which is never set (a grep finds only a comment), so the live sources inside the mask are exactly ITAMP1 and ITAMP2, as claimed. Outside the mask: ITAMP5, 6, 7, 8, 9, 11, 12, 13.
- Imprecise or wrong:
  - There is a second, much larger window the claim omits. `TAMP_CR1` and `PWR_BDCR1.MONEN` are both "System reset: not affected", so ITAMP1/2 stay armed across a reset. Any event during reset hold, the FSBL (about 6.9 s on pq1) or secure boot up to `main.rs:1400` is erased the same way. The 1 ms figure is right only for an event while SysTick is running.
  - "ITAMP5 to ITAMP13 … still wipe" is unproven for the ship set. After `ALL_DONE`, the BHK load at `:1529` runs before SysTick starts at `:1644`. The manual says "the device secrets access is not possible as long as a tamper flag is set" (§64.4), so the likely outcome is the `panic!` at `main.rs:1545` and a WFI park, not a wipe.
- Doubt: TAMP has never run on silicon, so the panic-before-poll path is my reading of the manual and is unmeasured.

ROW A18: CONFIRMED
- Corrected citations: `R/fsbl/src/main.rs:172`, `R/fsbl/src/manifest.rs:30` (comments only). A grep for `msplim|psplim` over `fsbl/`, `secure/`, `nonsecure/`, `shared/`, `geometry/`, `pqsigner-fi/`, `hal/` finds nothing else.
- Decisive code: `// peaked main's frame at ~24.7 KB against a 16 KB RAM budget with no` / `// MSPLIM — a silent stack overflow / HardFault of the legacy bench`.
- Nothing wrong. Three additions that close the alternatives:
  - cortex-m-rt 0.7.5 (the locked version) has no MSPLIM feature.
  - There is no `flip-link`.
  - There is no MPU setup in `secure/src` or `fsbl/src`.
  Statics sit below the stack, so an overflow hits `.bss`/`.data` first.
- Doubt: whether any input can reach the bound is still unproven (#374).

ROW A19 (brown-out part only): REFUTED as a defect
- Corrected citations: `R/secure/src/reset_cause.rs:182-185` (BOR maps to Cold), `:108-110` (`requires_secret_scrub` excludes Cold); `R/secure/src/main.rs:1330-1333` (the only consumer besides a log line at `:1308`); `R/secure/src/nsc/mod.rs:1729-1744` (what the scrub wipes); `R/secure/src/nsc/state.rs:542`, `:552`; `R/secure/src/main.rs:610`.
- Decisive code: `if csr & BORRSTF != 0 {` / `// BOR + PIN with nothing else = clean power-on.` / `return ResetCause::Cold;`
- What is wrong: the classification is as stated, but the scrub it skips changes nothing. `zeroize_sensitive_state` wipes ordinary statics (`STATE`, `SLOT_CACHE`, `SE`). The cortex-m-rt reset handler has already zeroed `.bss` and re-copied `.data` before `main` on every reset cause. `zero-init-ram` is off, and `secure/src` has no `.uninit`, `noinit` or `MaybeUninit` static. Treating a brown-out as scrub-worthy would add no protection.
- What does survive a brown-out is the stack and unused SRAM1, and the whole of SRAM1 while the FSBL runs. That is true for every reset cause; it is the stack-residue half of A19 plus the missing `SRAM_RST` bit in C4.
- Doubt: I read the runtime's reset code and the statics' declarations, not the linked map, so a static placed outside `.bss`/`.data` by a linker script would escape this.

ROW A27: CONFIRMED
- Corrected citations: `R/secure/src/nsc/cmd_pin_attempt_log.rs:23-25` (check), `:29-33` (36 volatile writes); `R/secure/src/nsc/mod.rs:2051-2062` (veneer, no `cfg`, so in every image); `R/proto/src/lib.rs:127` (`PIN_ATTEMPT_LOG_LEN = 36`).
- Decisive code: `if !validate_ns_write_ptr(args.arg1, OUT_LEN) {` / `return NscStatus::InvalidPointer as u32;`. The sibling `R/secure/src/nsc/cmd_fw_status.rs:41-42` says: `// HIGH-1 (audit fault-injection 20260611): sentinel-gate the NS write` / `// pointer (bare if !validate is single-fault FAIL-OUT → OOB write).`
- Imprecise: only the bare branch is a defect.
  - "No PIN gate" is a recorded owner decision (`R/secure/src/pin_attempt_log.rs:33-37`, #719).
  - "No HandlerGuard" is harmless here, because the handler touches no state that the idle wipe zeroizes.
  - The payload is `[0x01, count ≤ 16, dropped_be16, (reason, pre_count)…]`, so the first byte is fixed.
- Doubt: I did not disassemble it, so "one instruction" is a source-level reading.

ROW A32: PARTLY
- Corrected citations: (a) `R/secure/src/nsc/cmd_sign_userop.rs:116`; `pqsigner-fi/src/lib.rs` `check_true_into_sentinel` at c75b0d9c. (b) `R/secure/src/fi.rs:58-59`, `:72`; `R/secure/src/rng.rs:115-121`; `R/secure/src/hw/rng.rs:620` (the driver guard). (c) `R/secure/src/main.rs:4270-4273`.
- Decisive code: `let v1 = cond();` / `wait();` / `let v2 = cond();`
- (a) Confirmed. The first evaluation runs with no jitter after veneer entry and a deterministic LCD status paint. `ns_ptr.rs:84-90` has one production caller, `nsc_register_heartbeat` (`R/secure/src/nsc/mod.rs:2011`), which is not a signing path.
- (b) The `0x5A` fallback exists, but I found no `wait_random` call that runs before `hw::rng::init()` at `main.rs:1384`. The only consumers are the RNG driver's own delays during init, which fall back because the driver guard is held. `first_boot::run_pre_lock_and_maybe_lock` is at `main.rs:1630`, after RNG init. As written, (b) describes a mechanism with no victim.
- (c) Confirmed and unconditional. The code never writes DSCSR, although its own comment says CDS is needed.
- Doubt: whether the cycle counter still counts in Secure state at RDP-2 could not be settled from the local manuals (PM0264 does not cover DWT).

ROW A34: PARTLY (three sub-claims)
- (1) Device info: CONFIRMED.
  - Citations: `R/nonsecure/src/usb/commands.rs:182`, `:416`; `R/nonsecure/src/usb/mod.rs:200` (not `:199`).
  - Code: `const FW_VERSION: [u8; 3] = [0x03, 0x00, 0x00];`. The comment at `:178-181` already calls it a "Hardcoded placeholder, NOT the running image's identity", so this is a known placeholder, not a discovery.
  - `usb` is in the secure ship set. No release recipe pins the non-secure features, because `make release` hard-errors.
- (2) ITAMP7/12/13: PARTLY.
  - Citations: enabled at `R/secure/src/hw/tamp.rs:293`, `:297`, `:298`, and in IER at `:318`, `:322`, `:323`. There is no ADC4 code in `secure/`, `fsbl/`, `nonsecure/` or `shared/`.
  - "Can never fire" is wrong in principle. ADC4 is a non-secure peripheral here: its security bit is bit 8 of `GTZC2_TZSC_SECCFGR1`, and GTZC2 is never configured (`R/secure/src/sau.rs:672-675`). Non-secure code could arm an analog watchdog and raise these tampers.
  - This is not a new forced-wipe finding. `tzic-wipe` in the ship set already lets non-secure code trigger the same wipe by touching any secure peripheral.
- (3) Erase read-back: CONFIRMED.
  - Citations: `R/secure/src/hw/flash.rs:1307-1352`, `:1366-1386` (`erase_slot`).
  - Erase success is judged from the status register only. Later programming is read-back verified (`:1285-1296`), so a missed erase matters only for bytes that are never written, which is the C10 tail.
- Doubt (for (2)): whether an ADC4 watchdog event really reaches the tamper logic on a U585 is from the manual's source table and is unmeasured.

ROW B5: CONFIRMED (and stronger than written)
- Corrected citations: `R/secure/src/first_boot/state.rs:306`, `:323`, `:333`, `:345`, `:375-378`; `R/secure/src/first_boot/journal.rs:102-104`; `R/secure/src/first_boot/mod.rs:419-421`.
- Decisive code: `if done & DONE_ALL == 0 {` / `hw.commit_step(STEP_ALL_DONE)`, and `pub fn all_done(&self) -> bool { self.has(DONE_ALL) }`.
- Imprecise:
  - Step 6 commits `ALL_DONE` without requiring the earlier bits, and `all_done()` tests only that one bit. A step skipped by one fault is never re-run, because later boots return early.
  - `rdp2-self-lock` is in both ship strings, so by your definition this is ship-set code, not class B.
- Consequence, as far as I traced it:
  - Step 5 skipped: `FinalPbsSaltMissing` (`R/secure/src/hw/secret_keys.rs:533`), fail closed.
  - Step 3 skipped: fail closed. Transport keys are used only in first-boot functions (`R/secure/src/se050/mod.rs:421`, `:538`), so runtime SCP03 fails.
  - Step 2 skipped: the anti-pre-plant erase is skipped and the next boot likely panics at `main.rs:1516`.
  - Step 4 skipped (admin re-key): not traced. It may leave a device that works but whose lockout wipe cannot authenticate.
- Doubt: the step-4 outcome is the one that could raise severity, and I did not follow it.

ROW C4: PARTLY
- Corrected citations: `R/shared/src/lockdown.rs:295-312` (`ObField`, no SRAM variant), `:533-582` (`verify_ship_profile`; the cited `:517-521` is the advisory `bor_lev`); `R/Makefile:374-380`; `R/secure/src/reset_cause.rs:95-98`; `R/secure/memory-stm32u585.x:31`; `R/nonsecure/memory-stm32u585.x:9`.
- Decisive manual text (§7.9.13, FLASH_OPTR): "Bit 15 SRAM_RST: All SRAMs (except SRAM2 and BKPSRAM) erase upon system reset / 0: … erased when a system reset occurs / 1: … not erased". Also "ST production value: 0x1FEF F8AA".
- Names, bits and polarity, all active-low:
  - `SRAM_RST`: bit 15.
  - `SRAM2_RST`: bit 25.
  - `SRAM2_ECC`: bit 24.
  - `SRAM3_ECC`: bit 23.
  The production value decodes to all four = 1: no erase on reset, ECC off, and `BOR_LEV` = 0.
- `lockdown.rs` has no field for any of them. Neither does `R/fsbl/src/optbytes.rs`, `first_boot/mod.rs`, or either profile in `R/tools/ship-profiles/`.
- The recipe claim holds: it sets `BOR_LEV=3 SRAM2_RST=0`, and SRAM2 is the non-secure RAM.
- Imprecise: the ECC half is moot for the secure world. Secure RAM is SRAM1 only, and Table 46 (§6.3) gives SRAM1 no ECC. `SRAM2_ECC` would cover non-secure RAM and SRAM3 is unused. `SRAM_RST` is the bit that matters.
- Doubt: the production value is from the manual, not read from a pq1 die.

ROW C7: CONFIRMED
- Corrected citations: `R/fsbl/src/fi.rs:31-33`, `:36-38`. Every FSBL delay goes through this; there is no other entropy source in `fsbl/src`.
- Decisive code: `fn rng_byte() -> u8 {` / `0x42` / `}`
- Nothing wrong. The file header (`:5-16`) already admits it.
- Doubt: I did not re-check the `movs r0,#66` disassembly, since that needs a build.

ROW C10: CONFIRMED (one wording correction)
- Corrected citations: `R/fsbl/src/verify.rs:52-57` (capacity checks), `:62`, `:68` (hash exactly the declared lengths); `R/secure/src/fw_update/verify.rs:42-58`; `R/fw-manifest/src/lib.rs:177`, `:180`, `:204`.
- Decisive code: `let actual_secure = hash_flash_region(secure_base, secure_len);` and `pub const SIGNED_PREIMAGE_LEN: usize = DOMAIN_TAG.len() + 4 + 32 + 32;`
- Imprecise: the lengths are not signed. In the only implemented manifest (v0x02) the signed preimage is tag, version and the two hashes, 75 bytes; lengths are unsigned metadata bound only through the hashes. Say "manifest-declared lengths".
- No blank check on the tail exists in `fsbl/src` or `secure/src/fw_update`. The tail is erased at `FW_BEGIN` but never read back (A34(3)).
- Doubt: reaching the tail needs a second, control-flow fault, which nobody has demonstrated.

ROW C11: CONFIRMED
- Corrected citations: `R/fsbl/src/verify.rs:109`; `R/fsbl/src/main.rs:220`, `:286`; `R/secure/src/fw_update/mod.rs:133-139`; `R/bip39/src/lib.rs:222-225`.
- Decisive code: `let display_verdict = render::render_fingerprint(&secure_digest);`
- Nothing wrong. The non-secure hash is verified against the signed manifest at boot but is not in the 8 words; nor is `fw_version`.
- Doubt: this may be intended design, since the non-secure world is untrusted by invariant #4. It is an owner call, not clearly a defect.

ROW C12: CONFIRMED
- Corrected citations: `R/fsbl/src/main.rs:76-78`, `:172`, `:197-198` (both manifests are read before a slot is picked); `R/fsbl/Cargo.toml:131`. There is no `#[exception]` anywhere in `fsbl/src`, so NMI and HardFault use cortex-m-rt's default infinite loops.
- Decisive manual text (§7.3.2): "When two errors are detected, the ECCD flag (ECC detection) is set in FLASH_ECCR. In this case, an NMI is generated."
- Imprecise: the stated condition is the wrong one. The manual documents the NMI with no enable bit. What is unmeasured is whether a torn program or erase leaves a word that reads as a two-bit error. The same section notes that an erased line supports no two-error detection.
- Doubt: that torn-write behaviour (#94).

ROW D1: CONFIRMED (and stronger than written)
- Corrected citations: `R/tools/verify_ship_state.py:34-38` (docstring says "allow-list"), `:53-75` (code is a deny-list), `:84-104`, `:119-126` (refuses the template), `:133-155`; `R/Makefile:2441-2442`; `R/tools/ship-profiles/bench-rdp0-tzen.json`; `R/tools/ship-profiles/ship-option-b.template.json`; `R/docs/hardware/evt-silicon-validation.md:661-663`.
- Decisive text: `Every programmer invocation is built here and checked against an allow-list of` / `read verbs before it runs` against `WRITE_VERBS = {`.
- Imprecise:
  - The only runnable profile has no `flash` key and the template has `"flash": []`. Today the tool compares 16 option-byte fields and hashes zero bytes of flash.
  - The missing OTP, UID and per-device pages are a profile gap. The tool's `--read` can hash any address a profile names.
  - Neither profile lists `BOR_LEV`, any SRAM bit, WRP2A/2B or the OEM locks.
- "No buyer can run it on a sealed unit" is supported: "No SWD — the enclosed unit's 10-pin connector is removed and the pads are inside the case."
- The deny-list also omits verbs such as `-w32`/`-w8` and `-tzenreg`. That list is from my memory of the ST CLI, not checked against the installed tool.
- Doubt: whether the production enclosure will expose SWD is a hardware decision I cannot read from code.

ROW E14: CONFIRMED
- Corrected citations: `R/docs/hardware/hardware_requirements.md:100-103`; `R/secure/src/main.rs:1393-1397`. More stale sites not in the row: `main.rs:1402-1404` (log strings say "log-only"), `:4317-4319`; `R/secure/src/hw/tamp.rs:78-81`.
- Decisive text: "`secure/src/hw/tamp.rs` (TAMP driver, currently log-only and not yet wired into `main()`)", against `hw::tamp::init();` at `main.rs:1400` and `trigger_intrusion_wipe()` under `tamp-wipe` at `tamp.rs:103-109`.
- Nothing wrong. The "runtime copy only" point holds: the wrapped key persists on page 126 and reloads each boot (`R/secure/src/hw/bhk.rs:5-11`).
- Doubt: none of substance.

ROW E17: PARTLY
- Corrected citations: `R/docs/security/user-device-verification.md:184-186`, and the fuller statement at `:72-76`; the doc's own answer at `:77-80`; status line at `:3`.
- Decisive text: "No NRST needed (vector catch)." and "It does not matter that VBUS briefly ran whatever firmware was resident before the probe attached: the dump reads persistent state *after* the halt".
- What is wrong: the doc does not overlook the pre-attach window; it argues the window is harmless. The contradiction is with two other places:
  - CLAUDE.md invariant #10(a), which says "connect-under-reset before first power".
  - `R/tools/verify_ship_state.py:112-115`, which defaults to `--mode UR` ("do not change this"). That mode needs NRST, which the two-pin SBU design does not route.
  The whole doc is marked "DESIGN … Nothing here is implemented".
- Doubt: whether the argument at `:77-80` survives firmware that acts on the secure elements before the halt is a design question I did not analyse.

ROW E19: CONFIRMED (low)
- Corrected citations: `R/docs/security/vendor-signing-key-compromise.md:459-463`; the same doc at `:298`; RM0456 §7.5.3.
- Decisive text: "There is no hardware measurement latch on STM32U585 — no PCR, no DICE CDI engine, no SAES measurement register." Manual: "HDPx_ACCDIS can be only cleared by a system reset."
- Imprecise: the sentence is literally true; there is no measurement register. The weak part is the reason given, "the binding is computed by the measured code itself". That does not cover an immutable first stage that derives a value and then closes HDP. Line `:298` rejects HDP only as a callable enclave. This row also does not fit class E: the doc denies a capability; it does not claim a missing control.
- Doubt: none on the facts; the severity is editorial.

ROW E20: CONFIRMED
- Corrected citations: `R/fsbl/src/verify.rs:5-24`; `R/fsbl/src/main.rs:40-47`; `R/fsbl/Cargo.toml:16`; `R/fsbl/memory-stm32u585.x:14`; `R/CLAUDE.md:31`; `R/scripts/check_fsbl_geometry.py:9`; `R/fsbl/src/marker.rs:83`; `R/docs/security/measured-boot.md:296`.
- Decisive text: `default = ["hw-sha256"]` against "**This is also why the HASH-peripheral port is no longer worth its cost.**"
- Size:
  - Commit c6a97080 (2026-09-28, an ancestor of HEAD) is titled "SHA-256 on the HASH peripheral — 30,720 -> 22,236 B".
  - The existing pq1 ELF `R/target/fsbl-hw/…/pqsigner-fsbl` (built 2026-09-28) has a LOAD size of 0x56dc = 22,236 B.
  - The iota2 ELF under `R/target/fsbl/` is 0x51ec = 20,972 B.
- Imprecise: 22,236 B is "as of the 2026-09-28 ELF", not HEAD. `fsbl/` is unchanged since c6a97080, but `sphincs-c10/src` gained 79 lines in five files, and I did not rebuild.
- Timing: the 2.930 s figure was taken at the 10 s hold, before the HASH port, so it is the software-path number.
- Doubt: the current size at HEAD.

Summary
- Fully confirmed: 12 (A13, A18, A27, B5, C7, C10, C11, C12, D1, E14, E19, E20).
- Partly: 5 (A16, A32, A34, C4, E17). Refuted: 1 (the brown-out part of A19).
- I trust A16 least: its core is solid, but my correction about ITAMP5–13 rests on manual text for a peripheral that has never run on silicon.

The advisor timed out on my first call and answered on the second. The codex MCP server failed to connect, so no external-model cross-check was run.