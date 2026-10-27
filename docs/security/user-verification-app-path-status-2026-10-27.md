# PQ1 user-side firmware verification — status note (2026-10-27)

> **UPDATE 2026-10-27 (later the same day): NO-GO SUPERSEDED. The prover is ST's ROM bootloader.**
> The design now in force ships the device with **empty flash** and option bytes that boot
> ST's mask-ROM USB bootloader (DFU). The app fills all 2 MB of flash with random data
> through that ROM, the user unplugs and replugs, and the app reads it all back. No PQ1
> code runs on the device before the release is installed. Read
> [`user-device-verification.md` § USB path](user-device-verification.md#usb-path-proof-of-secure-erasure-with-a-power-cycle)
> first. Why the NO-GO below no longer holds:
>
> - **"PoSE needs a ROM."** It has one: ST's bootloader in system memory. It writes and
>   reads memory over USB, and reading all of `R` back is equivalent to the MAC.
> - **Rejected option 1, "with TrustZone on, ST's bootloader runs non-secure, so secure
>   flash reads back as zeros".** The shipping profile leaves SECWM1/SECWM2 empty, so
>   every page is non-secure while the ROM fills and reads it. A page malware hides as
>   secure reads back wrong and fails the profile check (EVT control C3). The release
>   install switches bank 1 back to secure.
> - **"Firmware that ignores the boot pin can imitate the bootloader."** Imitation does
>   not help. After the unplug, anything other than the ROM must live in non-volatile
>   storage, and flash must read back as 2 MB of random data. So an impostor and the data
>   it displaced must both fit in the small storage the fill cannot cover (OTP, spare
>   option-byte bits, the backup domain while the J102 supercap holds VBAT). The open
>   soundness question is now only whether that storage is small enough, not the prover's
>   own bytes.
> - **"Production sets BOOT_LOCK and straps BOOT0 to ground."** The ROM is entered
>   through the option bytes (`nSWBOOT0=0 nBOOT0=0`) with no pin. BOOT_LOCK is set by the
>   release's first boot.
> - **SE storage** is excluded by provisioning the SEs at the factory with final keys
>   derived from the per-die DHUK (RDP-1), then regressing to RDP-0. One caveat is still
>   open: firmware can raise RDP to 1 itself in transit.
> - **Power-cut recovery** is no longer a trust question. Until the release is installed,
>   the device always boots ST's ROM.
>
> An intermediate version (also 2026-10-27) put a PQ1 prover in flash. Its own code left
> ~4.4 KB of compressible slack, which is why the prover moved to the ROM.
>
> The body below is kept unchanged as the record of the first review.

**Status: STOPPED — ARCHITECTURE NO-GO. No firmware, SDK, or companion code was implemented.** The
requested app-only proof is unsound on the current RDP-0 hardware. Only this status note was changed.
This note records the goal, the completed design review, the blocker, and the viable alternatives.

## Goal

PQ1 ships at RDP-0 and locks itself to RDP-2 on its first field boot (invariant #10). Before that lock,
every buyer should be able to confirm their device runs the published firmware, using only the Vault app,
a USB-C cable and a laptop: no extra chip on the board, no adapter, no probe.

## How we got here

1. **ST USB DFU (BOOT0 over the SBU pins).** Rejected. With TrustZone on, ST's bootloader runs
   non-secure, so the secure firmware reads back as zeros (seen on EVT #1, 2026-09-21). Production also
   sets BOOT_LOCK and straps BOOT0 to ground. And firmware that ignores the boot pin can imitate the
   bootloader.
2. **SWD on the USB-C SBU pins plus a commodity probe.** Already designed in
   `docs/security/user-device-verification.md` (2026-07-17). It gives a real guarantee but needs a probe:
   a Raspberry Pi Debug Probe (~$12) and a passive USB-C breakout. No ready-made cable exists. Rejected by
   the founder as not easy enough.
3. **"Firmware enters DFU, the app reads it back" / "app asks the device for its hash".** Rejected. The
   code being checked is the code answering, so this only catches mistakes, not attacks.
4. **Wipe-and-reinstall with proof (what the founder wanted built).** The app would fill every writable
   memory location with verifier-selected random bytes, disclose a final key, and verify a keyed MAC over
   the whole contents before installing the signed release. This is Perito & Tsudik's Proof of Secure
   Erasure (PoSE), not a device-reported hash and not primarily a timing measurement. The paper is
   [ePrint 2010/217](https://eprint.iacr.org/2010/217).

## Resolution: the PoSE precondition is absent

The completed plan had a mandatory architecture gate before implementation. It failed:

- PoSE explicitly requires a small **genuinely immutable ROM** containing the receive/write, read/send,
  final-key MAC, and recovery routines. The FSBL is flash at `0x0C00_0000`
  (`fsbl/memory-stm32u585.x:33`). Its WRP is reversible at RDP-0
  (`docs/provisioning/first-boot-requirements.md`: the factory stages reversible WRP; only RDP-2 makes it
  permanent). Resident malware can therefore replace the supposed ROM, simulate the proof, and survive
  the reinstall. A RAM-resident routine has the same missing trust root and introduces code-compression
  attacks; it is not a substitute.
- Power-cut recovery has the same blocker. A flash recovery stub is writable state excluded from the
  erase and can carry malware forward; a RAM recovery routine dies on the power cut.
- ST's mask ROM does not rescue the design. It provides a fixed DFU protocol, not the required PoSE
  routine; with TZEN=1 it cannot read the secure contents (the observed zeros), and a firmware-requested
  DFU entry can be imitated by the resident firmware. The 512-byte user OTP area has only 336 bytes free
  and cannot hold the USB + erase + MAC + recovery stack (`secure/src/hw/otp.rs`).
- The exact release-input problem also remains: `make release` refuses, the production FSBL is
  compile-fenced (`fsbl/src/main.rs:67`), and the live/frozen geometry migration is open. These are
  secondary blockers, not the reason for the NO-GO.

A green result from any of these mutable-code variants would be a false security claim. Consequently no
production-shared or EVT prototype was written, and no hardware state was changed. The attached headless
EVT was detected over USB-C (`1209:7051`) and ST-LINK (`0483:374f`), but testing cannot repair a missing
security precondition.

**Review receipt:** target `2483414ebfcd40758052b0f92e6f2c81dc29f6fc`; the coordinator reproduced the
mutable-ROM attack from the sources above. Kimi K3 independently returned `FIX` with the same blocker
(session `session_1995d778-05ba-4d05-8da9-6f74b4fac4e4`). Claude Opus 5 independently identified the
same blocker and returned `GAP` only because it had not read ST's primary manuals; its stated hardware
limits match the repo's EVT evidence. The GPT-5.6 SOL CLI was unavailable after the required two launch
attempts. The conditional implementation plan stopped at UV-0 as designed; no weaker consistency check
was substituted.

## Exploration findings (useful for any path)

**Device boot / lock**
- First-boot lock flow: `secure/src/first_boot/{mod,state,journal}.rs`. The lock confirm screen
  (`state.rs:193`) and the decline path exist.
- The self-lock can't run yet:
  - `rdp2-self-lock` needs `mode-production`, which the S-2 and FW-rollback fences block.
  - Phase A always halts at E0809, because the WRP/OEM masks are unpinned (`shared/src/lockdown.rs`).
  - Known defect #268: the RDP burn writes the wrong register and silently does nothing
    (`hw/flash.rs:432`).
- The written requirements forbid USB before the lock: `docs/provisioning/first-boot-requirements.md`
  R1.2, R2.4, §6.

**FSBL / flash**
- The FSBL has no USB and no flash write path. It uses about 19.7 KB of its 38,912-B maximum span; its
  production build is fenced off.
- Bank 1 has zero spare pages. The only secure-flash headroom is inside the FSBL region.
- The live flash layout still differs from the frozen geometry registry (#540).
- OTP layout (`hw/otp.rs`):
  - 0..128: legacy tally
  - 128..160: device master key
  - 160..176: sentinel
  - 176..512: free

**USB / app**
- Production USB is non-secure only and starts after the wallet is unlocked (`secure/src/main.rs:5093`,
  5154).
- It is HID only, at about 20–40 KB/s measured, with no bulk or WebUSB interface.
- Firmware-update commands 20–24 need an unlocked wallet, and COMMIT refuses on non-devunit builds.
- The companion app (`~/Documents/PQ1/pq1-companion`) forwards each 64-byte report through a Tauri IPC
  call. It has no onboarding flow and no firmware fetching.

**Clocks / memory**
- The clock comes from the HSI16 RC oscillator (no crystal) through PLL1: 160 MHz, 4 wait states,
  ICACHE on.
- SRAM3, SRAM4 and the backup SRAM are unused.
- The display controller holds 161 KB of GRAM. Whether it can be read back on pq1 is unverified (no MISO;
  the SDA line may be bidirectional).
- Silicon timing evidence: `sign_timing.rs` gave cycle-identical minimum timings across runs and fresh
  boots (DVT rows 16.4/16.6).

**Release artifacts**
- No full-flash release image or FSBL artifact is published, and `make release` refuses.
- The user-verification design assumes such an image exists.

## Options I can deliver here

- **A. SWD verifier:**
  - an open-source verifier tool (probe-rs CLI and/or WebUSB page);
  - the board change spec (SWDIO/SWCLK on SBU1/SBU2, remove the SBU→BOOT0 circuit, remove the VBAT
    supercap);
  - a published full-flash release image.
- **B. In-app consistency check:** before the lock, the Vault app compares the firmware hash and the
  8 boot words with the published release. It catches mistakes only, and the wording must say so.
- **C. Both:** B for everyone, A for full assurance.

## Manufacturer request (already drafted, independent of the above)

- Route SWDIO (PA13) to SBU1 (A8) and SWCLK (PA14) to SBU2 (B8), untied, with series resistors and
  low-capacitance ESD protection.
- Remove U111/R131/R132 (the SBU→BOOT0 circuit). Keep BOOT0 strapped low.
- Remove the VBAT supercap unless it is needed. Keep J210.
