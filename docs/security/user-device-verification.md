# End-User Device Verification — byte-exact firmware proof at unboxing

**Status: DESIGN (2026-07-17). Nothing here is implemented; work breakdown at
the end.** Companion pieces that already exist: reproducible builds
(`docs/firmware/reproducible-builds.md`), RDP-0 shipping + first-boot RDP-2
self-lock (work-todo #36, `docs/provisioning/first-boot-provisioning.md`),
measured-boot 8-word fingerprint (`docs/security/measured-boot.md`).

> **UPDATE 2026-10-27: owner direction, the consumer path becomes USB, not
> SWD.** The owner chose a probe-free procedure that runs in the Vault desktop
> app over the ordinary USB-C cable: a **proof of secure erasure with a power
> cycle, done by ST's own ROM bootloader**.
> - The device ships with **empty flash**, booting ST's mask-ROM USB DFU.
> - The app fills all 2 MB of flash with fresh random data through it.
> - The user unplugs and replugs.
> - The app reads everything back.
>
> No PQ1 code runs on the device until the release is installed. This also
> changes the factory flow: the SEs get their **final, DHUK-derived keys at
> the factory at RDP-1**.
>
> **Soundness is still open.** It needs the non-volatile storage the fill
> cannot cover to be tiny. Today it is not: the J102 supercap keeps ~2.2 KB of
> backup domain alive, the OTP is blank, and the other chips on the board are
> unaudited.
>
> Full design, argument, residuals, prerequisites and EVT results:
> [§ USB path: proof of secure erasure with a power cycle](#usb-path-proof-of-secure-erasure-with-a-power-cycle)
> at the end of this file. The SWD procedure below stays as the expert,
> ground-truth option. Nothing in either path is production-approved.

## The claim this design delivers

> A user who receives a PQ1 in the mail can **fully verify, byte-for-byte,
> that the device contains exactly the published open-source firmware build**
> — before any secret exists on the device, using ~$5 of commodity hardware
> from an independent supply chain, in under two minutes, with no soldering
> or disassembly.

The core claim is **unconditional on factory honesty** for the firmware bytes:
it does not rest on attestation, certificates, or trusting anyone. It rests on
physics: at RDP-0 the SWD debug port, with the CPU halted at the reset vector,
returns the true contents of every persistent bit on the MCU, and **no
firmware executes while it is read** — so there is nothing that can lie.

## Why this is the only possible shape

Fake firmware flashed in transit has byte-identical *capabilities* to the
genuine build: same flash, same OTP (including SE transport keys), same SEs,
same DHUK once it self-locks. No challenge/response, CA, SE attestation, or
companion protocol can distinguish them **from inside**, because every answer
the genuine firmware can compute, the fake can too. Exactly two asymmetries
exist:

1. **External readout of the persistent state, with the CPU not running**
   (SWD at RDP-0, connect-under-reset). Ground truth; nothing to trust.
2. Code made immutable **before** the adversary's window (factory RDP-2 burn)
   — which moves the trust to the factory ceremony and was rejected as the
   primary mechanism (owner decision 2026-07-14: ship RDP-0, user-verifiable).

PQ1 ships RDP-0, so (1) is available to every user. This document's job is to
make (1) an actual consumer procedure instead of an expert escape hatch.

## User procedure (what the quickstart card says)

1. **Get a verifier probe — NOT from the PQ1 box.** Any CMSIS-DAP/ST-LINK
   compatible SWD probe works: a $4 Raspberry Pi Pico flashed with the
   open-source `debugprobe` UF2 (drag-and-drop, no tools), a CH347 board, an
   ST-LINK clone, or the optional open-hardware PQ1 Verify Cable. The point of
   supply-chain independence: an interdictor of the device parcel does not
   control the probe.
2. **Before powering the device from anything else**, connect the probe to the
   PQ1's USB-C port (SWD is routed on the SBU pins — see hardware section) and
   run the open-source verifier: `pq1-verify` (probe-rs CLI) or the WebUSB
   page. One click.
3. The tool halts the core at the reset vector, dumps **all persistent MCU
   state**, and diffs it against the published reproducible release. Result:
   **green + 8 BIP-39 fingerprint words**, or red with the exact differing
   region.
4. **Unplug (full power removal), then power on normally, keeping the device
   in hand.** The boot screen renders its 8-word measured-boot fingerprint.
   **Compare: screen words == tool words == words published for the release.**
5. Confirm the on-screen "lock device" prompt; the verified firmware then
   performs the RDP-2 self-lock + SE credential rotation (work-todo #36) and
   enters the seed wizard. From this point the verified code is immutable and
   is its own guardian.

A user who skips this gets the weaker companion-app SE genuine-check only
(board-level, does **not** prove firmware) and the quickstart must say so
plainly. Deterrence still generalizes: an interdictor cannot know which units
will be verified, so tampering at scale is detectable at scale.

## Ground-truth dump mechanics

- **Reset-halt without NRST:** attach SWD, set `DHCSR.C_DEBUGEN` +
  `DEMCR.VC_CORERESET`, issue `AIRCR.SYSRESETREQ` → the core halts at the
  reset vector **before executing a single instruction**. (Standard vector
  catch; probe-rs supports it. NRST wiring is therefore not required — two
  SBU pins suffice.)
- It does not matter that VBUS briefly ran whatever firmware was resident
  before the probe attached: the dump reads persistent state *after* the
  halt, and the subsequent power-cycle (step 4) discards all volatile state.
  What the dump shows is exactly what executes after the power-cycle.
- **Coverage — every persistent bit on the U585:**

  | Region | Expected value | Source of truth |
  |---|---|---|
  | Flash, both banks, all pages except 123–127 | byte-exact == published full-flash release image (unused pages erased `0xFF`) | reproducible build artifact |
  | Flash pages 123–127 (per-device state) | blank/erased at ship | ship profile (Phase A re-checks the same) |
  | Option bytes (RDP, TZEN, WRP both banks, BOOT_LOCK, SECWM, BOR, …) | exact published ship profile; **RDP must be `0xAA`** | published ship option-byte profile |
  | OTP area (per-device: OTP master → transport keys) | salted hash matches this unit's factory birth certificate | transparency log (see below) |
  | MCU 96-bit UID | matches birth certificate | transparency log |
  | System memory / engineering bytes | mask ROM, not writable | n/a |
  | Backup domain (RTC backup regs) | PQ1 never has a backup battery (owner, 2026-10-27). But the V10 board carries J102 (a Seiko CPH3225A chip supercap on VBAT, charged from VDD3V3 through D104/R114), which held the backup domain through a 10 s unplug on EVT-3D21. Cleared by the step-4 power removal only once J102 is removed; until then, fill and count it (§ USB path) | board requirement (see hardware section) |

  There is no other writable persistent store on the MCU. A device that
  arrives **not** at RDP `0xAA`, or with any flash/option-byte/OTP deviation,
  fails loudly → do not use, return it. (This includes a device an attacker
  — or malicious resident firmware — already locked to RDP-2: the dump is
  simply impossible, which *is* the tamper signal.)
- The tool computes the 8-word fingerprint from the dumped active slot via
  the same `sphincs_tz_bip39::firmware_fingerprint_lines` derivation,
  binding the chip it probed to the screen the user reads in step 4.

## Why in-transit malware cannot survive a green result

Suppose the parcel was interdicted and malicious firmware ran on the device
before the user verified. For the attack to persist past step 5 it must live
in some persistent state. Walk the list:

- **MCU flash / option bytes / OTP** — dumped and diffed; any residue is a
  red result. "Self-cleaning" malware that restores genuine bytes before
  shipment has, by construction, left the device genuinely clean: after the
  power-cycle only the verified bytes execute. Extra burned OTP bits are
  one-way and show up as a birth-certificate hash mismatch.
- **RAM** — dead after the step-4 power removal.
- **SE050 / OPTIGA state** (pre-poisoned objects, known transport keys):
  neutralized by the existing first-boot design — Phase B rotates SCP03/admin
  to the BHK axis and OPTIGA PBS to the DHUK+TRNG-salt axis, and the seed
  wizard provisions user objects from scratch. Transport keys being known to
  a transit attacker is already in the threat model (the factory knows them
  too); they die at step 5 before any seed exists. **Design requirement on
  the wizard:** treat all pre-existing SE user-object state as hostile —
  delete/recreate with verified policies, never adopt.
- **The SEs run no attacker code** (SE050 applets are NXP-signed; OPTIGA has
  no user code), so "malware inside the SE" is not a channel.

Conclusion: a green dump + matching on-screen words + user custody from step
2 onward ⇒ the device that enters the seed wizard is running **exactly** the
published build. That is the full-verification claim.

## Required design delta: confirm-gated Phase A

Today's #36 candidate runs Phase A (RDP=0xCC programming) on first boot
unconditionally. Under this design that is wrong twice over: (a) a curious
user who powers the device before verifying would irreversibly destroy their
own ability to verify; (b) a transit attacker could power genuine devices to
lock them (DoS, and it defeats verification of genuine units). **Phase A must
be gated on an explicit trusted-UI confirmation** — boot at RDP-0 shows
"Confirm to lock device — after that verification over SWD not possible
anymore.", and only a
deliberate button sequence proceeds to the lock. An attacker pressing it in
transit yields a device that arrives locked → fails step 3 → rejected. The
gate converts that attack from compromise into a returned unit.

## Verifier tool + hardware trust

- The tool is open source, reproducibly built, and trivially re-implementable
  (its spec is "dump these ranges, diff against these published artifacts") —
  independent implementations are encouraged and expected. Rebuilding the
  firmware from source locally (`make verify-repro`,
  `docs/firmware/reproducible-builds.md` §Independent verification workflow)
  removes even the release-artifact trust.
- A compromised host PC can lie. Mitigations, layered: run from a live USB or
  a phone (WebUSB); cross-check the 8 published fingerprint words on a second
  device — the step-4 screen comparison is independent of the host that ran
  the dump.
- Probe firmware (e.g. Pico `debugprobe`) is open source and user-flashed;
  the probe never sees secrets (there are none on the device yet).

## What this explicitly does NOT prove (honest boundary)

Firmware verification ≠ device verification. Out of scope, with their
mitigating layers:

1. **Hardware implants around a genuine MCU** (e.g. a logger on the LCD SPI
   bus capturing the seed words during the wizard, or a button injector).
   The firmware is exactly genuine; the board is not. Layer: tamper-evident
   packaging/case, published board photos for visual comparison, and the SE-CA
   genuine-check; targeted per-unit hardware implants remain the residual, as
   they are for every wallet vendor.
2. **A counterfeit board with an SWD-emulating fake "MCU" + the victim unit's
   transplanted genuine SEs**, serving genuine bytes over the debug port while
   running attacker code elsewhere. Cost: custom hardware per unit plus
   destructive transplant. Layers: birth-certificate UID↔SE binding in the
   transparency log, SE-CA check, tamper evidence, case design. Accepted
   residual at this cost tier.
3. **ST silicon itself** (mask ROM, RDP enforcement). Inherited, as by every
   STM32 product.

The previous companion-only "CA in the SEs" idea proves only chip
genuineness — it is kept (it kills clone/counterfeit boards and anchors the
transparency log) but it is **not** the firmware proof; this procedure is.

## Hardware + factory requirements

- **Route SWDIO/SWCLK to USB-C SBU1/SBU2** on the production board (unused by
  USB 2.0; add ESD protection). No NRST needed (vector catch). After the
  step-5 RDP-2 lock the debug port is silicon-dead, so the routing is inert
  for the device's whole life after unboxing — zero attack surface added.
  Fallback if SBU routing fails review: an accessible pogo-pad footprint, at
  the cost of the "one cable" UX.
- **No backup battery, at any point** (owner, 2026-10-27). VBAT retention
  still exists on V10 through J102 (a Seiko CPH3225A chip supercap on VBAT, charged from VDD3V3 through D104/R114). Either J102 is
  removed, so the step-4 power removal clears the backup domain, or the
  backup domain is filled and counted (§ USB path). Open decision.
- **Factory birth certificate + transparency log:** per unit, factory HSM
  signs `(MCU UID, salted OTP-content hash, SE cert public keys, ship
  option-byte profile id, firmware release hash)` into an append-only public
  log. The verifier checks the per-device rows against it; the companion's
  SE-CA activation check cross-references the same entry. Note the dependency
  split: the *firmware* claim needs no log; the log covers per-device OTP,
  clone deterrence, and overbuild accounting (work-todo #22's manifest slots
  in here unchanged).

## Work breakdown

1. `pq1-verify` CLI on probe-rs: reset-halt, full dump, diff vs release
   artifact + ship option-byte profile, fingerprint-word output. (The repo
   already drives probe-rs; this is host tooling, no firmware change.)
2. WebUSB/WebHID browser variant of (1) with guided UX.
3. Confirm-gated Phase A (trusted-UI "verify or lock" screen) in
   `secure/src/first_boot/` — the one firmware change this design requires.
4. Seed-wizard SE-state hostility rule (delete/recreate, never adopt) —
   verify current wizard behavior, close any gap.
5. Production board: SBU↔SWD routing + ESD + no-VBAT requirement into the
   hardware spec.
6. Birth-certificate signing + transparency log service; fold into the #22
   factory-manifest design.
7. Quickstart card + docs: the 5-step procedure, the "skipping this = weaker
   guarantee" statement, supported probe list.
8. Optional open-hardware PQ1 Verify Cable (nice-to-have; commodity probes
   are the security story).

---

<a id="usb-path-proof-of-secure-erasure-with-a-power-cycle"></a>
## USB path: proof of secure erasure with a power cycle

**Status: OWNER DIRECTION 2026-10-27 — design + EVT experiment only. Not
implemented in shipping firmware, not production-approved, and it changes the
factory flow (§ Prerequisites). Read this whole section before touching
first-boot provisioning, factory provisioning, SE key derivation, WRP
staging, option-byte handling, the FSBL, or the Vault desktop app's
onboarding flow.**

It supersedes the NO-GO in
[`user-verification-app-path-status-2026-10-27.md`](user-verification-app-path-status-2026-10-27.md),
whose premise ("Proof of Secure Erasure needs an immutable ROM") is answered
below. The immutable ROM it asks for already exists: ST's USB bootloader in
the STM32U585's system memory.

> **UPDATE 2026-10-27 (later the same day): the prover is now ST's ROM, not
> PQ1 code.** The first version of this section put a small PQ1 prover in
> flash. Its own code left ~4.4 KB of compressible slack, enough for malware
> that reuses it (§ Test status, first experiment). The owner moved the
> prover into ST's mask-ROM bootloader. The device now ships with **empty
> flash**, and no PQ1 code runs on it until the release is installed.

### The procedure (what the user does)

The device arrives at RDP-0 with **empty flash**. Its option bytes make it
boot ST's mask-ROM USB bootloader (DFU) and leave every flash page
non-secure and unprotected; this is the **shipping profile**, defined below.
The user runs the Vault desktop app (no phone app is planned yet) over the
normal USB-C cable:

1. **Check and fill.** Through the ROM, the app:
   - reads the option bytes and the OTP;
   - mass-erases flash;
   - writes fresh random data `R` to **all 2 MB** of flash (`R` is
     generated and kept on the host);
   - writes a random canary to SRAM2.
2. **Unplug.** The user unplugs the device, waits at least the minimum off
   time, and plugs it back in. The app measures how long the device was gone.
3. **Read back.** The device boots ST's ROM again. The app reads **all** of
   flash, plus the option bytes, the OTP and the SRAM2 canary, and requires:
   - flash equals `R` byte for byte;
   - the shipping profile;
   - OTP equals the factory record;
   - the canary is gone;
   - the off time is at least the minimum.
4. **Install.** Only on a full match, the app:
   - mass-erases;
   - writes the published release through the ROM and reads it back;
   - switches the option bytes to the release layout (bank 1 secure, boot
     from flash).

   The device then reboots into the release.
5. **Lock.** The release's first boot does the rest:
   - stages WRP on the FSBL range and BOOT_LOCK;
   - checks the OEM-key locks;
   - clears the backup domain;
   - locks to RDP-2 after the trusted-UI confirmation
     (`docs/provisioning/first-boot-requirements.md`).

**The shipping profile** (`tools/pose/pose.py` `ship_profile_problems`):
- RDP 0xAA, TZEN 1.
- nSWBOOT0 0 and nBOOT0 0, so the chip boots ST's bootloader whatever the
  BOOT0 pin says.
- BOOT_LOCK 0, SWAP_BANK 0, DUALBANK 1.
- SECWM1 and SECWM2 empty. With TZEN=1 the ROM runs non-secure and can reach
  only non-secure flash.
- No WRP, no HDP.

**Recovery is trivial.** Until step 4 switches the option bytes, the device
boots ST's ROM on every power-up. An interrupted run is simply started again.
There is no PQ1 code on the device for a power cut to damage.

### Why ST's ROM bootloader is the prover

Perito & Tsudik's PoSE ([ePrint 2010/217](https://eprint.iacr.org/2010/217))
puts the prover in ROM so its own bytes cannot be a hiding place. The
STM32U585 has one: ST's bootloader in system memory, mask ROM nobody can
change. It already does what PoSE needs, writing memory and reading it back
over USB. Reading all of `R` back is equivalent to the paper's MAC over it,
only slower.

The argument:

- **The power cycle is the trusted reset.** Unplugging is a physical event
  no firmware can fake or prevent. PQ1 has no battery; for the J102
  supercap, see below. It clears SRAM, caches, and CPU and peripheral state.
  Afterwards the hardware boots whatever the option bytes select, and nothing
  volatile survives.
- **Counting.** After the power cycle, the readback is answered by one of two
  things:
  - ST's ROM, which reads the real flash honestly;
  - code that the option bytes boot instead.

  Random data does not compress, so if the answers equal `R`, the device's
  non-volatile storage holds all ~2 MB of `R`. Flash is exactly 2 MB. Anything
  other than the ROM that answers must therefore live, together with every
  byte of `R` it displaced from flash, in **non-volatile storage outside flash
  that the fill cannot cover**. If that storage is too small to hold such
  code, the answer came from ST's ROM, and flash really is `R`: nothing else
  is on the device.

Compared with the first design (a PQ1 prover in flash), this removes two
problems:
- **Prover slack.** There is no PQ1 code on the device, so no compressible
  prover bytes, and no "reuse the genuine prover" attack.
- **Something else running.** After a pass, the only code that runs is ST's
  ROM (until the option-byte switch) and then the installed release. Leftover
  data in OTP, the option bytes or the backup domain is inert unless the
  release reads it. That is what the OTP and option-byte comparison and the
  first-boot clean-up are for.

**What the uncovered storage must be smaller than.** The cheapest impostor
we can think of does not write a USB stack of its own:
1. It boots from a flash page it kept.
2. It starts ST's own ROM bootloader in the non-secure world.
3. It marks its own page secure, so every ROM access to that page traps into
   a secure fault handler. The handler returns the matching bytes of `R` from
   the uncovered storage.

This is trap-and-emulate. The same trick can fake the option-byte and OTP
reads and hijack the install.

**Its size:** the boot stub, the fault handler and the payload, plus an equal
amount of displaced `R`. That is plausibly a few hundred bytes to about 1 KB;
nobody has built one. The uncovered storage must stay well below that. The
target is tens of bytes. This bar is an engineering estimate, not a proof
(Prerequisite 15).

| Store the fill cannot cover | Size | Status and treatment |
|---|---|---|
| OTP, unprogrammed quad-words | 512 B on EVT-3D21 (all blank) | Write-once, so the fill cannot use it. **The factory burns every quad-word** with recorded random data. The exception is a minimal rollback-floor region, which counts. The ROM reads all 512 B, and the app compares them with the factory record, so dormant data there is caught. |
| Option-byte fields free to hold data | roughly 10–20 B (NSBOOTADD0/1 are unused with TZEN=1; spare bits) | Counted. The ROM reads all 64 B, and the app requires the shipping profile and the factory values in every other field. The OEM1/OEM2 keys are write-only and read as zero, so they are useless as storage; see the first-boot checks below. |
| Backup domain (backup SRAM 2 KB, TAMP 32×4 B, RTC registers) | about 2.2 KB | **Too large, and the ROM cannot reach it.** The probe was refused with `errVENDOR`. On the EVT it survives an unplug because of J102, a Seiko CPH3225A chip supercap on VBAT, charged from VDD3V3 through D104/R114. PQ1 never has a backup battery (owner, 2026-10-27). **Hard prerequisite: remove J102.** Then measure how long the bare VBAT node keeps the backup domain, and set the app's minimum off time above that. |
| SE050 / OPTIGA storage | tens of KB | Must be **unreachable** from MCU code during transit. That is the factory change below, plus the open RDP-0→1 caveat. |
| Non-volatile memory in other chips on the board | unknown | **Not yet audited.** Each of these must be checked against its datasheet for non-volatile memory the MCU can write: the NV3007 LCD controller (possible MTP/OTP for panel settings), the AW21036 LED driver, the AW99703 backlight driver, and the power path (AW32901, AW35602, ET83101H). Writable non-volatile memory in the display controller would also be a WYSIWYS concern. |
| SRAM, caches, peripherals, LCD GRAM | — | Volatile, so gone after a long enough unplug. This is a physical assumption, not counted. If SRAM survived (an unplug that is too short, or a rail that never fully collapses), malware could boot from it with SECBOOTADD0 pointing at SRAM. The app enforces a minimum measured off time. The SRAM2 canary catches honest runs that skipped the unplug, because a reset alone keeps SRAM2 (SRAM2_RST=1, measured). |
| ST system memory (bootloader, RSS) | — | Mask ROM, trusted, as in every path. |
| Undocumented on-die storage | — | Assumed none. This is a silicon assumption, like the ROM. |

**Checks the release's first boot must make, because the ROM cannot see
them:**
- **OEM1LOCK/OEM2LOCK.** A planted OEM2 key would allow a later RDP-2 →
  RDP-1 regression. The lock bits are in `FLASH_NSSR`, which the ROM does not
  expose. First boot must refuse to lock if either is set. The bit positions
  are still unpinned (`shared/src/lockdown.rs` `OEM_LOCK_MASK_PINNED`).
- **Nothing inherited.** First boot must not trust anything left in the
  backup domain, and must set its own VTOR/SAU/MPU before trusting any
  register read. This matters only if the counting failed; it is cheap
  defence in depth.

### Why the factory must provision the SEs with final per-die keys

If MCU code can authenticate to an SE during transit, malware can park part
of `R` (or itself) in SE storage and the count fails. Today it can: the
factory leaves the SEs on **transport** keys (HKDF of the OTP master,
public-by-assumption and readable by any code at RDP-0) and first boot
rotates them (`first-boot-provisioning.md`). The new factory flow:

1. Flash the factory provisioning image; raise RDP to **1** (the DHUK is a
   shared ST constant at RDP-0 and per-die only from RDP-1).
2. Derive the **final** SE050 SCP03/admin credentials and the OPTIGA PBS
   on-die **from the DHUK alone** and install them. They never leave the die;
   the factory holds no copy.
3. Lock the SE policies so nothing answers without those credentials (SE050
   `SCP_REQUIRED`; no OPTIGA object writable outside the shield).
4. **Regress RDP 1→0.** The hardware mass-erases flash and keeps OTP.
5. **Burn the OTP** (Prerequisite 6), set the **shipping profile**, and write
   nothing: flash stays empty. Ship at RDP-0.

At RDP-0 the DHUK reverts to the shared constant, so no MCU code — genuine
or malicious — can talk to either SE until the device is at RDP ≥ 1 again.

**Open caveat (found 2026-10-27, not yet closed): RDP 0→1 in transit.** Any
firmware at RDP-0 can raise RDP to 1 itself. At RDP-1 the per-die DHUK
returns, so malware would know (from the public source) how to derive the SE
keys and could stash itself in SE storage, keeping only a small loader in
flash or another uncovered store. Candidate closures:

- the factory **pre-creates every SE object the wallet needs, at fixed size,
  and fills all remaining SE NVM** with objects the per-die credentials cannot
  delete or grow, so writable SE capacity is a few bytes (it then joins the
  uncovered-storage table);
- or an SE policy under which the per-die credentials cannot create objects;
- or a way for the user procedure to detect RDP-1. (The regression back to
  RDP-0 that malware would need erases flash, so this is about the SEs only.)

Which of these the SE050 (applet 7.2) and OPTIGA policy models support is
unverified. Until one is closed, the SEs are **not** excluded from the count.

### Prerequisites (all open; tracked in #1082)

1. **`DHUK-RDP12` must pass** (`docs/security/red-teaming.md` §6.5, issues
   #388/#400). The DHUK must be identical at RDP-1 (factory) and at RDP-2
   (after the first-boot lock), or every unit loses its SEs at the lock. The
   test is one-shot and needs a sacrificial part.
2. **The factory ceremony: RDP-1 → SE provisioning → RDP 1→0 regression →
   OTP burn → shipping profile.** It reverses `first-boot-requirements.md`
   F2 / "Factory MUST NOT program RDP" and "no factory-held final pairing
   secret" (CLAUDE.md shipping model). It needs §11 authorization, like any
   RDP or SE-credential action.
3. **Final SE keys derived from the DHUK alone.** Today:
   - the SE050 final keys hang off the BHK on flash page 126;
   - the OPTIGA PBS hangs off a TRNG salt on page 127
     (`secure/src/hw/secret_keys.rs`).

   The fill destroys both pages. The first-boot transport→final rotation
   (`secure/src/first_boot/`, `rdp2-self-lock`) goes away, or shrinks to a
   verification step.
4. **Close the RDP-1-in-transit caveat** above.
5. **Remove J102.** PQ1 never has a backup battery, and the ROM cannot fill
   the backup domain. Then measure:
   - how long the bare VBAT node keeps the backup domain;
   - how long SRAM keeps data after the unplug.

   Set the app's minimum off time above both. The EVT values in § Test
   status are with J102 fitted.
6. **The factory burns all OTP** except a minimal rollback-floor region, and
   records the image per device so the app can compare it. This needs a
   decision on the floor region's size budget.
7. **Audit the other chips on the board for writable non-volatile memory**
   (see the table).
8. **WRP staging moves from the factory to first boot.** The device ships with
   empty flash, so there is nothing to protect at the factory. Invariant #10's
   WRP-before-RDP-2 ordering still holds, done on-device.
9. **First-boot changes:**
   - stage WRP and BOOT_LOCK, and optionally `nSWBOOT0=0 nBOOT0=1` so the
     BOOT0 pin no longer matters;
   - the OEM-lock check;
   - clear the backup domain;
   - set VTOR/SAU/MPU before trusting register reads;
   - fix the RDP-burn register defect (#268).

   The installer mass-erases before writing, so pages 123–127 start blank, as
   Phase A (R2.2) requires.
10. **A native option-byte writer in the Vault desktop app,** with a hard
    guard: refuse any write whose RDP byte is not 0xAA, or that changes TZEN
    or any field other than the release fields. `pose.py` deliberately has
    no option-byte writer; on the EVT, option bytes were changed with
    `STM32_Programmer_CLI`.
11. **The Vault desktop app flow:** fill, the unplug prompt with a measured
    off time, verify, install, the option-byte switch, the fingerprint
    display. It also needs the release artifact it verifies against. At the
    ROM's pace a run takes about 2 minutes; see the measured times in § Test
    status.
12. **USB before the lock.** No PQ1 code runs before the release, so
    `R1.2`/`R2.4`/§6 (USB before the lock) apply unchanged to the release's
    first boot.
13. **SE exclusion must also cover the OPTIGA protected-update path.** No
    object may be updatable through a trust anchor (`Int`/`0xF0` metadata).
    This ties to S-2.
14. **Optional board change:** consumers no longer need the SBU→BOOT0 circuit
    (U111/R131/R132). First boot can make the pin irrelevant (item 9).
15. **Pin the uncovered-storage budget:**
    - a written, reviewed estimate of the smallest impostor;
    - the measured total of uncovered storage after items 5–7.

### What it does NOT prove

Same honest boundary as the SWD path above (hardware implants, counterfeit
boards, ST silicon), plus:

- **ST's bootloader** is trusted to do what it says. That is the same trust
  every STM32 user already places in mask ROM; it was never user-verifiable.
- **SE firmware** is NXP's and Infineon's, and was never user-verifiable
  either.
- **The factory's SE provisioning** cannot be checked by the user. A factory
  that left an extra SE credential behind still cannot read the seed: under
  #855 each stored half is masked with a DHUK-keyed, PIN-keyed value, so
  reading out a chip gives only masked halves.
- **A compromised host** can lie about the comparison. The mitigations are
  the same as for the SWD path.

### Docs that still describe the old (transport-key) model

Update these when the factory change is implemented, not before:
- CLAUDE.md: the shipping model, invariants #3/#10, the `rdp2-self-lock`
  bullet. Each carries an UPDATE pointer here.
- `docs/provisioning/first-boot-provisioning.md`
- `first-boot-requirements.md`
- `factory-provisioning.md`
- `docs/factory-mass-production-model.md`
- `docs/security/HARDENING.md`
- `docs/security/threat-model.md`
- `docs/security/production-security.md`
- `docs/security/research-bundles/E-supply-chain.md`

### Test status (EVT-3D21)

Board: EVT-3D21 (UID `003D0021 30465002 2033314C`, USB serial
`2070316D3046`), RDP 0xAA, TZEN 1, J102 fitted.

#### ST ROM bootloader (current design)

Tool: `tools/pose/pose.py`, a native DfuSe client (Linux usbfs, standard
library only). Procedure: `tools/pose/README.md`.

Pre-state: a full ST-LINK backup at
`~/Documents/PQ1/evt3d21-backup-2026-10-27-pose-rom/` (two byte-identical
dumps). Setup through ST-LINK:
- `-e all`, so flash is empty, as shipped;
- `-ob nSWBOOT0=0 nBOOT0=0 SECWM1_PSTRT=0x7F SECWM1_PEND=0x0`. SECWM2 was
  already empty.

After this the chip enumerated as `0483:df11` with no pin and no button.

What the ROM exposes (bootloader `bcdDevice` 2.00, transfer size 1024):
- alt 0 `@Internal Flash /0x08000000/256*08Kg`: all 2 MB;
- alt 1 `@Option Bytes /0x40022040/01*64 e`;
- alt 2 `@OTP Memory /0x0BFA0000/01*512 e`.

`pose.py`'s option-byte decode matched `STM32_Programmer_CLI -ob displ`
field for field. Probe results:
- SRAM2 at `0x20030000`: writes accepted and read back;
- backup SRAM at `0x40036400`: refused (`errVENDOR`).

| Run | What | Unplug | Result |
|---|---|---|---|
| M2 | fill only | — | An ST-LINK dump of `0x08000000`/2 MiB matched `R` byte for byte. |
| C1 | After a fill, page 77 rewritten over SWD (a page "malware kept"), then a reset. | no | **FAIL**: mismatched pages `[77]`. The SRAM2 canary survived the reset (SRAM2_RST=1), so a reset alone does not pass the canary check. |
| C3 | Page 255 made secure (`SECWM2` 0x7F..0x7F), which hides it from the non-secure ROM. | no | **FAIL**: page 255 reads back wrong, and the profile check reports `SECWM2 covers pages 127..127`. |
| 1 | honest `run` | yes; 3 s by the kernel log | Flash, profile, OTP and canary all good, and the canary was gone, so power was lost. **FAIL on the off-time gate**: 2.9 s measured, against a 10 s minimum. |
| 2 | honest `run` | yes: out at 19:12:19, back for good at :30, with a 4 s reconnect at :23 (the plug bounced on re-insertion) | Two tool bugs: it measured only the first gap, and then a udev permission race crashed its verify. A manual `verify` of the same session: **PASS**. Flash byte-exact; canary 14/4096 bytes equal, about chance. Both bugs are fixed (bounce-aware timing, udev retry). |
| 3 | honest `run` | yes; 17 s by the kernel log (19:36:10 → :27) | The tool's 600 s wait expired before the unplug. Fixed: it now waits 3600 s and never verifies on a timeout. A manual `verify` after the unplug: **PASS**. Flash byte-exact, profile and OTP correct, canary 16/4096, about chance. |
| C2 | After a fill, `nSWBOOT0=1 nBOOT0=1` over SWD, so the chip boots flash, which holds `R`. | reset by the option-byte reload | **FAIL**: nothing enumerates, and `verify` reports "did not come back as ST's ROM DFU". |
| Install | `pose.py install` of the backup images through the ROM. Then `STM32_Programmer_CLI -c port=USB1` switches bank 1 back to secure and sets boot to flash. | — | The device enumerates as `PQSigner OS`. An ST-LINK dump matches the backup byte for byte, and `-ob displ` is identical to the pre-state. |

**Honest gap:** no single run has both the tool-measured off time and a
PASS. The off-time measurement agrees with the kernel log (2.9 s against 3 s;
4.72 s against the first 4 s gap). The bounce handling and the gate logic are
covered by unit tests (`make pose-test`).

Measured:
- **Throughput.** Mass erase: 0.27–0.44 s. A real erase: the following
  writes over previously filled flash succeeded. Fill of 2 MiB: 93 s
  (22 KiB/s, paced by the ROM's poll timeout per 1 KiB block). Readback of
  2 MiB: 11.9 s.
- **Independent cross-check.** An ST-LINK dump of `0x08000000`/2 MiB right
  after a fill matched `R` byte for byte.

What these runs establish:
- ST's ROM alone can fill and read back every flash byte, the option bytes
  and the OTP, with no PQ1 code on the device.
- A kept page, a page hidden as secure, and boot redirected away from the ROM
  are each detected.

What they do not establish:
- that the uncovered storage is small enough: J102 is still fitted, the OTP
  is blank, and the other chips are unaudited;
- that SE storage is unreachable (this EVT's SEs are still on dev/transport
  keys);
- the factory RDP-1 step and DHUK-RDP12.

#### First experiment: a PQ1 prover in flash (superseded)

Code: commit `68be6b139` (`tools/pose/prover/`, since removed). Backup:
`~/Documents/PQ1/evt3d21-backup-2026-10-27-pose/`.

| Run | Prover | Unplug between fill and readback | Result |
|---|---|---|---|
| 1 | honest | no | flash and prover region match; SRAM canary retained (no power cycle) |
| 2 | honest | **yes** (USB-C + ST-LINK, ~10 s) | **PASS**: flash byte-exact, canary gone, backup SRAM + TAMP retained (J102 supercap on VBAT; not a battery) |
| 3 | `cheat-skip-page` | no | **FAIL** at exactly page 192 (bank 2 page 64) |
| 4 | `cheat-ram-hold` | no | flash comparison **passes**: 64 KB of `R` sat in SRAM, never in flash. A same-session check is fooled. |
| 5 | `cheat-ram-hold` | **yes** | **FAIL** at pages 248–255, exactly the 64 KB held in SRAM |

**Timings:**
- erase of 254 pages: 1.0 s;
- fill of 2,080,768 B over HID: 43 s;
- readback: 72 s.

**Why it was dropped.** The prover was 13.5 KB of code, using the generic
`usb-device` and `synopsys-usb-otg` crates. Under xz -9e its 16 KB of pages
compressed to ~11.9 KB. That left ~4.4 KB of slack where malware could keep
itself while reusing the genuine prover: a decompressor, a hook and a
few-byte release patch. That is an order of magnitude too much, and it
motivated the move to ST's ROM.

**Review status:** the ST-ROM version of this section has **not yet had an
independent adversarial review**. A Kimi K3 review was started on 2026-10-27
and stopped at the owner's request; GPT-5.6 was not available in that session.
The first version (a PQ1 prover in flash) was reviewed by Kimi K3, and its
findings carried over where they still apply:
- OEM keys and BOOT_LOCK;
- whole-OTP accounting;
- the OPTIGA protected-update path;
- SRAM remanence.
