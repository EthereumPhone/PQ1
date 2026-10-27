# End-User Device Verification — byte-exact firmware proof at unboxing

**Status: DESIGN (2026-07-17). Nothing here is implemented; work breakdown at
the end.** Companion pieces that already exist: reproducible builds
(`docs/firmware/reproducible-builds.md`), RDP-0 shipping + first-boot RDP-2
self-lock (work-todo #36, `docs/provisioning/first-boot-provisioning.md`),
measured-boot 8-word fingerprint (`docs/security/measured-boot.md`).

> **UPDATE 2026-10-27 — owner direction: the consumer path becomes USB, not
> SWD.** The owner chose a probe-free procedure that runs in the Vault desktop app
> over the ordinary USB-C cable: a **proof of secure erasure with a power
> cycle** (fill all flash with fresh random data → user unplugs and replugs →
> read everything back). It needs no immutable ROM, but it changes the
> factory flow: the SEs get their **final, DHUK-derived keys at the factory at
> RDP-1**, and the device ships at RDP-0 holding only the prover. **Its
> soundness is still open:** the prover's own bytes leave too much
> compression slack today (§ Test status). Full design,
> argument, residuals, prerequisites and work list:
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
staging, the FSBL, or the companion onboarding flow.**

It supersedes the NO-GO in
[`user-verification-app-path-status-2026-10-27.md`](user-verification-app-path-status-2026-10-27.md),
whose premise ("Proof of Secure Erasure needs an immutable ROM") is answered
below.

### The procedure (what the user does)

The device arrives at RDP-0 with only a small **prover** in flash. In the
Vault desktop app (no phone app is planned), over the normal USB-C cable:

1. **Fill.** The app sends fresh random data `R` (generated on the host, kept
   on the host) and the device writes it to **every flash byte outside the
   prover's own pages** (both banks, ~2 MB). The app also fills the backup
   domain (backup SRAM, TAMP backup registers) while the board keeps VBAT
   alive. V10 does, through the J102 supercap; PQ1 never has a backup battery.
2. **Unplug.** The user unplugs the device, waits a few seconds, and plugs it
   back in.
3. **Read back.** The device boots from flash and streams **all** of flash
   back; the app compares every byte with `R` plus the published prover
   bytes, in a random chunk order the app picks after step 2.
4. **Install + lock.** Only on a full match: the app sends the published
   release, the prover installs it, the device reboots into it, and the
   existing first-boot flow locks to RDP-2 after the trusted-UI confirmation
   (`docs/provisioning/first-boot-requirements.md`).

### Why a ROM may not be needed (and what still has to hold)

Perito & Tsudik's PoSE ([ePrint 2010/217](https://eprint.iacr.org/2010/217))
puts the prover in ROM so its own bytes cannot be a hiding place. We replace
that with two things:

- **Counting.** Random data does not compress. If the device returns the
  correct `R` for ~2 MB of flash, ~2 MB of its non-volatile storage holds
  `R`. Whatever is left — the only place malware can live — is the
  difference between *all* non-volatile storage and what `R` occupies.
- **The power cycle is the trusted reset.** Unplugging is a physical event no
  firmware can fake or prevent. It erases every volatile store: SRAM,
  ICACHE/DCACHE, CPU and peripheral state, the display controller's RAM.
  After it, the CPU executes whatever bytes sit at the secure boot address in
  flash, and nothing else on the MCU survives. So malware cannot keep itself
  in cache or RAM across the check (the earlier "ICACHE residency" worry), and
  SRAM never needs filling.

What is left for malware after a matching readback is the **slack**:

| Store | Size | Treatment |
|---|---|---|
| Prover pages (known bytes, not filled) | `|P|` | Malware can replace the prover with itself plus a *compressed* copy of the genuine prover. Room gained ≈ `|P| − |compress(P)|`. **Main residual; kept small by a minimal prover** (size budget is an open item). The pad after the prover image is true-random (not PRNG output), so it cannot be compressed. |
| OTP, every unprogrammed quad-word | up to 512 B (176..512 free today; 0..176 too if the new design no longer burns the OTP master or sentinel) | Write-once, so the procedure cannot fill it; counts as slack. Malware could burn a loader there. Fix: the factory burns every unused quad-word with recorded random data. |
| Option bytes | tens of spare bits | Counts as slack; the genuine prover reports the full profile after a pass and first boot re-verifies it. |
| Backup domain (backup SRAM 2 KB, TAMP 32×4 B) | ~2.2 KB | **Measured: survives a 10 s unplug on EVT-3D21** by J102 (a Seiko CPH3225A chip supercap on VBAT, charged from VDD3V3 through D104/R114). **There is no backup battery, at any point** (owner, 2026-10-27); the supercap is the only VBAT source. Either J102 is removed (no VBAT retention), or fill it and require it back as part of `R` (`pose.py` does; `--no-vbat` otherwise). Caveat: malware can set `BHKLOCK` (`secure/src/hw/bhk.rs`) so TAMP_BKP0–7 can be neither filled nor read. That fails closed when the backup domain is gated, which is the reason to gate it. Also, `bhk.rs`'s "a power cycle resets the backup domain" is false on a board that keeps VBAT. |
| OEM1/OEM2 regression keys, BOOT_LOCK, the rest of OPTR | 48 B keys + bits | Not usable as code storage, but a planted OEM2 key would allow a later RDP-2 → RDP-1 regression, and BOOT_LOCK=0 leaves the boot address mutable. The genuine prover must report OEM1LOCK/OEM2LOCK clear and the full expected OPTR after a pass. The prover reports raw `FLASH_NSSR`; the bit positions are still unpinned (`shared/src/lockdown.rs` `OEM_LOCK_MASK_PINNED`). |
| SE050 / OPTIGA storage | tens of KB | Must be **unreachable** from MCU code during transit. That is what the factory change below is for, and see the RDP-1 caveat. |
| Volatile stores (SRAM, caches, LCD GRAM, peripherals) | — | Gone after the power cycle. |
| Undocumented on-die storage | — | Assumed none: the die (STM32U585, 2 MB) is the largest of its line. This is a silicon assumption, like ST mask ROM. |

**What the slack must be smaller than (corrected 2026-10-27 after review).**
A first draft said malware must fit a whole working USB/flash stack plus the
compressed prover into the slack. That overstated the bar. Malware can
**reuse the genuine prover's code**. At boot, a small stub unpacks the
compressed genuine prover into SRAM, adds a hook and runs it. The genuine
code then answers every readback correctly, and at the install step the hook
patches the incoming release. A patch of a few bytes is enough to be
catastrophic, for example making the RNG return a constant.

So the real condition is: the exploitable redundancy of every known,
boot-resident byte, plus every other slack store, must be smaller than
**a decompressor + a hook + a few-byte release patch**, plausibly a couple
of hundred bytes.

The first EVT prover leaves about **4.4 KB** (measured, see Test status),
an order of magnitude too much. **The USB path is therefore NOT yet sound.**
It becomes sound only if the slack can be driven below that bar.

Candidate levers, none of them evaluated yet:
- **Store the prover pre-compressed** with a strong compressor and run it
  from SRAM behind a tiny decompressor, so an attacker cannot compress it
  further. The residual slack is then the stub's own redundancy plus the
  gap between our compressor and the best one available.
- **A hand-written minimal USB/flash prover**, instead of the generic crates.
- **Burn every unused OTP quad-word at the factory** with random data,
  recorded per device. This removes the OTP slack; quad-words are
  write-once, so they cannot be reused afterwards.
- **Remove J102** (no VBAT retention), or fill and gate the backup domain,
  as the test does.
- **A per-session encrypted prover** whose key reaches the device only after
  the unplug. This only helps if the key arrives through a path that is
  itself tiny, for example the buttons.

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
4. **Regress RDP 1→0.** Hardware mass-erases flash and keeps OTP.
5. Write the prover; ship at RDP-0.

At RDP-0 the DHUK reverts to the shared constant, so no MCU code — genuine
or malicious — can talk to either SE until the device is at RDP ≥ 1 again.

**Open caveat (found 2026-10-27, not yet closed): RDP 0→1 in transit.** Any
firmware at RDP-0 can raise RDP to 1 itself. At RDP-1 the per-die DHUK
returns, so malware would know (from the public source) how to derive the SE
keys and could stash itself in SE storage, keeping only a small loader in the
prover pages. Candidate closures:

- the factory **pre-creates every SE object the wallet needs, at fixed size,
  and fills all remaining SE NVM** with objects the per-die credentials cannot
  delete or grow, so writable SE capacity is a few hundred bytes (it then
  joins the slack table);
- or an SE policy under which the per-die credentials cannot create objects;
- or a way for the user procedure to detect RDP-1.

Which of these the SE050 (applet 7.2) and OPTIGA policy models support is
unverified. Until one is closed, the SEs are **not** excluded from the count.

### Prerequisites (all open; tracked in #1082)

1. **`DHUK-RDP12` must pass** (`docs/security/red-teaming.md` §6.5, issues
   #388/#400): the DHUK must be identical at RDP-1 (factory) and RDP-2 (after
   the first-boot lock), or every unit loses its SEs at the lock.
   One-shot, sacrificial part.
2. **Factory RDP-1 → SE provisioning → RDP 1→0 regression** ceremony.
   Reverses `first-boot-requirements.md` F2 / "Factory MUST NOT program RDP"
   and "no factory-held final pairing secret" (CLAUDE.md shipping model). It
   needs §11 authorization like any RDP/SE-credential action.
3. **Final SE keys from the DHUK alone.** Today SE050 final keys hang off the
   BHK on flash page 126 and the OPTIGA PBS off a TRNG salt on page 127
   (`secure/src/hw/secret_keys.rs`); the fill destroys both pages. The
   first-boot transport→final rotation (`secure/src/first_boot/`,
   `rdp2-self-lock`) goes away or shrinks to a verification step.
4. **Close the RDP-1-in-transit caveat** above.
5. **Shipped flash = prover only** (no wallet firmware), and a decision on
   how the prover relates to the FSBL (keep separate and overwrite at install,
   or make the FSBL itself the prover so the verified bytes are the ones WRP
   and RDP-2 then freeze).
6. **WRP staging moves from the factory to first boot.** Factory-staged WRP
   would make the FSBL pages unfillable known bytes, i.e. more slack.
   Invariant #10's WRP-before-RDP-2 ordering still holds, done on-device.
7. **Decide J102.** PQ1 never has a backup battery; the J102 supercap is the
   only VBAT source. Either remove it, then measure how long the bare VBAT
   node still holds the backup domain and set the unplug wait above that, or
   keep it and fill and count the backup domain.
8. **Prover size budget** and a minimal prover. The first EVT prover uses the
   generic `usb-device` + `synopsys-usb-otg` stack; a hand-rolled minimal OTG
   driver is the follow-up.
9. **Power-loss UX.** After step 1 the flash is random data; an interrupted
   procedure leaves a device that only boots the prover. Re-running from step
   1 recovers it as long as the prover pages are intact. If they are not,
   recovery needs SWD or RMA.
10. **Vault desktop app flow** (fill, unplug prompt, verify, install,
    fingerprint display) and the release artifact it verifies against.
11. **Supersedes `R1.2`/`R2.4`/§6 USB-before-lock only for the prover**: the
    installed release's first boot keeps those rules.
12. **Drive the slack below the "decompressor + hook + few-byte patch" bar**
    (see above) and measure it. This is the open soundness question of the
    whole path.
13. **The first-boot code needs changes, not just reuse:**
    - the installer must leave pages 123–127 blank, because the fill leaves
      them random and Phase A (R2.2) would halt;
    - Phase A only *verifies* WRP and never stages it (`first_boot/mod.rs`);
    - the RDP-burn register defect (#268) must be fixed.
14. **SE exclusion must also cover the OPTIGA protected-update path**: no
    object may be updatable through a trust anchor (`Int`/`0xF0` metadata).
    This ties to S-2.
15. **SRAM remanence.** The user must leave the device unplugged long enough
    for every rail to collapse. `pose.py` fails a run whose SRAM canary
    survived. Malware can fake the canary, so this guards honest runs only.

### What it does NOT prove

Same honest boundary as the SWD path above (hardware implants, counterfeit
boards, ST silicon), plus:

- **SE firmware** is NXP/Infineon's and was never user-verifiable.
- **The factory's SE provisioning** cannot be checked by the user. A factory
  that left an extra SE credential behind still cannot read the seed: under
  #855 each stored half is masked with a DHUK-keyed, PIN-keyed value, so a
  chip readout gives masked halves only.
- **A compromised host** can lie about the comparison. Same mitigations as
  the SWD path.

### Docs that still describe the old (transport-key) model

Update these when the factory change is implemented, not before: CLAUDE.md
(shipping model, invariants #3/#10, `rdp2-self-lock` bullet — each carries an
UPDATE pointer here), `docs/provisioning/first-boot-provisioning.md`,
`first-boot-requirements.md`, `factory-provisioning.md`,
`docs/factory-mass-production-model.md`, `docs/security/HARDENING.md`,
`docs/security/threat-model.md`, `docs/security/production-security.md`,
`docs/security/research-bundles/E-supply-chain.md`.

### Test status (EVT-3D21)

Experiment code: `tools/pose/` (prover firmware, host verifier, README).
Board: EVT-3D21 (UID `003D0021 30465002 2033314C`), RDP 0xAA, TZEN 1.

Pre-state: full ST-LINK backup at
`~/Documents/PQ1/evt3d21-backup-2026-10-27-pose/` (two byte-identical dumps;
OTP fully blank on this unit). Restore afterwards: verified, the option-byte
`-ob displ` diff is empty, and the unit enumerates as `PQSigner OS` again.

| Run | Prover | Unplug between fill and readback | Result |
|---|---|---|---|
| 1 | honest | no | flash and prover region match; SRAM canary retained (no power cycle) |
| 2 | honest | **yes** (USB-C + ST-LINK, ~10 s) | **PASS**: flash byte-exact, canary gone (263/65536 bytes equal ≈ chance), backup SRAM + TAMP retained (J102 supercap on VBAT; not a battery) |
| 3 | `cheat-skip-page` | no | **FAIL** at exactly page 192 (bank 2 page 64) |
| 4 | `cheat-ram-hold` | no | flash comparison **passes**: 64 KB of `R` sat in SRAM, never in flash. A same-session check is fooled. |
| 5 | `cheat-ram-hold` | **yes** | **FAIL** at pages 248–255, exactly the 64 KB held in SRAM |

Also measured:
- **Independent SWD cross-check.** An ST-LINK dump right after the fill
  matched prover + `R` byte for byte, so the prover wrote what it claimed.
- **Timings.** Erase of 254 pages: 1.0 s. Fill of 2,080,768 B over HID:
  43 s. Readback of 2 MiB: 72 s (round-trip bound; can be pipelined).
- **Prover size and slack.** The prover is 13.5 KB of code (generic
  `usb-device` + `synopsys-usb-otg`) in 16 KB of pages, padded with true
  random. xz -9e compresses the page image to ~11.9 KB, so the slack from the
  prover region alone is ~4.4 KB. That is an order of magnitude above the
  bar above, which is why the path is **not yet sound**.
- **The vector table is the first easy target**: ~2 KB of mostly identical
  handler addresses.

What these runs establish:
- The fill → unplug → readback mechanism works on silicon.
- The unplug defeats RAM-resident cheats (run 4 against run 5).
- On this board the backup domain must be counted.

What they do not establish:
- that SE storage is unreachable (this EVT's SEs are still on dev/transport
  keys);
- the factory RDP-1 step and DHUK-RDP12;
- the slack bound.

Review receipt: Kimi K3 adversarial review of this section, 2026-10-27.
Its findings are folded in above:
- the code-reuse correction;
- BHKLOCK and the VBAT backup domain;
- OEM keys and BOOT_LOCK;
- whole-OTP accounting;
- the OPTIGA protected-update path;
- first-boot incompatibilities;
- SRAM remanence.

GPT-5.6 was not available in this session.
