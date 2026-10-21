# Dev-unit firmware updates (`devunit-ab`)

Signed firmware updates over USB for **pre-production dev units** — DVTs
handed to outside testers (first use: investor units, 2026-10-21). Not the
production update design: production stays blocked on the unapproved Draft 1.1
rollback work and the open geometry decision (#540, #752, #908). Every piece is
behind the `devunit-ab` feature, which `mode-production` refuses at compile
time in the FSBL, the secure world and both build scripts.

## How it works

* **Layout** (`fw-manifest/src/devunit.rs` is the single source of truth):
  FSBL at bank-1 pages 0–3, manifests A/B at pages 4/5, a boot log at page 6,
  secure slot A at bank-1 pages 7–86, secure slot B at **bank-2** pages 48–127
  (made secure with `SECWM2 = 0x30..0x7F`), non-secure slots A/B at bank-2
  pages 0–23 / 24–47. 640 KiB per secure slot, so the pixel-UI image fits
  (it does not fit the frozen 57-page production slot, #908). Bank-1 pages
  123–127 — PIN counter, PIN salt, off-chain counters — never move, so a
  unit keeps its wallet across updates.
* **Two builds per release.** Images are not position independent, so every
  release is linked for slot A and for slot B and both are signed. The updater
  sends the variant for the slot the unit is *not* running from. The device
  refuses an image linked for the wrong slot (vector-table check at COMMIT, and
  again in the FSBL).
* **Update** (`CMD_FW_BEGIN/CHUNK/COMMIT`, unchanged wire protocol): PIN
  unlock required; the device asks "VERIFY FIRMWARE PACKAGE?", checks the
  vendor C10 signature, then shows "UPDATE TO V<x>?" with the version, the
  image fingerprint words and the signer words; only after that does it erase
  the inactive slot. COMMIT re-hashes the written images, writes the new
  manifest as `TRIED`, locks the wallet and resets. The FSBL boots the higher
  valid version.
* **Anti-downgrade without OTP.** A release must be strictly newer than the
  running one (BEGIN refuses otherwise), and the FSBL boots the higher valid
  version. Dev units never read or write OTP.
* **Probation / automatic rollback.** The new release logs `ATTEMPT` in the
  boot log early in every boot and `CONFIRM` once the wallet unlocks. If it
  boots three times without reaching an unlocked wallet (crash, hang + power
  cycle, broken SE path), the FSBL boots the previous slot again. The FSBL
  never writes flash.
* **Versions** are `YY.MM.DD.N` packed into the signed `u32` (`26.10.21.2` =
  `0x1A0A1502`); the device shows them in that form.
* **Boot fingerprint, shown once, in the pixel UI's design.** The dev-unit
  FSBL is built with `px-fingerprint`: it paints the "OS FINGERPRINT" title
  (1.5 s) and then the eight words, whole, on the numbered words grid (4 s),
  pixel for pixel the secure world's screens (`fsbl/src/px_fprint.rs`, pinned
  by `fsbl-tests/tests/px_fingerprint.rs`). The secure world no longer shows
  its own copy on dev units. The FSBL is never written over USB: a unit
  flashed before 2026-10-21 evening keeps the 5x8 text screen until it is
  re-flashed over DFU or SWD (`flash.sh` without `--erase-all` keeps the
  wallet).

## Signing key

A dedicated dev-unit SPHINCS+C10 key, created 2026-10-21 with `fwsign keygen`:

| | |
|---|---|
| private key | `~/Documents/PQ1/devunit-fw-key/devunit-fw.key` (passphrase in `passphrase.txt` next to it, both mode 0600) — **not in git; back it up** |
| public key | `config/devunit-firmware-vendor-pubkey.bin` (committed) |
| fingerprint | `a838b938444c6fa52471868dd0777508ef9ef72f101d8bfb038a4a0c9da4be12` (`config/devunit-firmware-vendor-key.sha256`) |
| words the device shows as SIGNER | **popular shift evoke mass shoulder spoon mushroom cotton** |

Units flashed with this FSBL accept only releases signed by this key. Losing
the key means those units can only be changed by reflashing over DFU/SWD.
It is a dev key held on a laptop: the dev-unit security story is "pre-production".

## Build a release

```bash
tools/devunit/release.sh                 # version = today's YY.MM.DD.N
tools/devunit/release.sh 26.10.22.1      # explicit
PROFILE=bench tools/devunit/release.sh   # headless mock-SE bench image
```

Output: `target/devunit/releases/<profile>-<version>/` with
`pq1-devunit-<version>.pq1fw` (the update package: both slot variants),
`factory/` (first-flash images), `bundle-{a,b}.pqfw`, and `RELEASE.txt`
(version, features, fingerprint words per slot).

Profiles:

* `investor` (default): `dual-se,dev-testkey,ui-lcd,ui-px,ui-px-dma,unlock-diag,
  stm32u585,usb,board-pq1` + `devunit-ab`. **No `dev-dfu`**: behind the FSBL
  its both-buttons check runs just before the PIN pad appears, and an early
  "enter" chord would latch the unit into ROM DFU on every boot. Override
  with `FEAT_S=...` for bench units.
* `bench`: `mock-se,e2e-test,ui-noop,...` — never touches the secure elements,
  auto-unlocks and auto-confirms; for the headless EVT bench board.

## First flash of a unit (once, before it ships)

Over USB-C with the ROM bootloader (`0483:df11`): use the SBU-bridged USB-C
adapter (`docs/hardware/evt-dev-loop.md`), or hold both buttons while plugging
in if the unit already runs a `dev-dfu` image. Then:

```bash
tools/devunit/flash.sh target/devunit/releases/investor-<v> --dfu --erase-all
```

`--erase-all` mass-erases (fresh unit, or one with ODM/monolithic firmware).
Without it, only bank-1 pages 0–86 and bank 2 are erased and the wallet pages
survive. With a probe on J210: `--swd` instead of `--dfu`. The script handles
TZEN=0 and TZEN=1 units, opens the watermarks for the non-secure ROM
bootloader, and leaves `TZEN=1, SECWM1=0..0x7F, SECWM2=0x30..0x7F,
SECBOOTADD0=0x180000, nSWBOOT0=1, nBOOT0=1`. RDP stays 0, no WRP, no OTP.

**Acceptance check per unit** (the FSBL has never run on a DVT before
2026-10-21; it refuses to boot if its display bring-up fails):

1. After flashing, the panel shows the FSBL's 8 words — they must equal the
   slot-A words in `RELEASE.txt`.
2. The setup wizard runs; create the wallet, enter the PIN.
3. `tools/devunit/fwupdate.py --info` reports the release on slot A.
4. Build the next release and install it once (below): this exercises the
   on-device dialogs and slot B on that unit before it leaves.

## Update a unit

The unit must be unlocked. Either tool:

* **Browser (any OS):** open `tools/devunit/pq1-fwupdate.html` in Chrome or
  Edge, pick the `.pq1fw` file, Connect, Install. Self-contained, no network.
* **Linux CLI:** `tools/devunit/fwupdate.py <file.pq1fw>`; `--info` shows what
  runs.

On the device, for each question: tap RIGHT through its screens, press BOTH
buttons on the last one to accept, hold LEFT to cancel. ~25 s transfer for the
investor image, then the unit restarts, shows the new words, asks for the PIN.
Cancel, unplug, or an error at any point leaves the running release in place.

**What to send a tester:** the `.pq1fw` file, `pq1-fwupdate.html`, and the
signer words above. The page lists the firmware words for their unit.

## Release discipline

* Test every release on the bench first (at least: install it on a dev unit
  and reach an unlocked wallet). The rollback catches a release that cannot
  unlock; it cannot catch one that unlocks but breaks signing or USB.
* **Never ship an update that changes the wallet's on-flash or on-chip format**
  (PIN-credential/salt scheme, SE key derivations, `dev-testkey` vs real keys,
  KDF tags). There is no migration path: the tester would be locked out of
  their wallet (#855 was such a change).
* Versions must increase; reuse of a version number is refused by the device.

## Tests

```bash
PROFILE=bench tools/devunit/release.sh <v>           # two bench releases v1 < v2
tools/devunit/flash.sh target/devunit/releases/bench-<v1> --swd
tools/devunit/fwupdate.py target/devunit/releases/bench-<v2>/*.pq1fw
tools/devunit/fwupdate-selftest.py <newer.pq1fw> <older-or-same.pq1fw>
node tools/devunit/webhid-harness.mjs <newer.pq1fw>  # the HTML page's code, real device
```

Rollback test: `PROFILE=bench FEAT_S="mock-se,e2e-test,ui-noop,stm32u585,usb,board-pq1,devunit-test-fault"
tools/devunit/release.sh <v>` builds a release that faults on every boot;
installing it must end with the previous release running again (three
`ATTEMPT` records in the boot log at `0x0C00C000`).

### Silicon evidence (EVT-3D21, UID `003D0021 30465002 2033314C`, 2026-10-21)

Bench profile, ST-LINK + USB-C:

* SWD first flash; DFU first flash (TZEN=1 path) with the partial erase
  verified to keep bank-1 pages 87–127 (marker test).
* Updates A→B and B→A, repeatedly (26.10.21.1 → .2 → .3 → .4 → .6 → .7 → .8);
  328 KB secure image in 13.6 s. Boot log after each: `CONFIRM(old)`,
  `ATTEMPT(new)`, `CONFIRM(new)`; staged manifest `try_once = 0xAA`.
* Refusals: downgrade, bad signature, wrong-slot build, tampered image (all
  `0x6A80`), abort → nothing staged; the running release untouched after each.
* Hard reset mid-stream → previous release boots, half-written slot ignored.
* Faulting release (`devunit-test-fault`) → three `ATTEMPT`s, then the FSBL
  booted the previous slot by itself (~30 s); a good update afterwards
  installed normally.
* The browser updater's script (via `webhid-harness.mjs`) installed a release
  end to end (22.5 s).

Investor image (26.10.21.1, real dual-SE + pixel UI) on the same headless board,
buttons emulated over SWD (PA0/PA1 driven low through the secure GPIOA alias):

* SWD first flash with the partial erase kept the board's test wallet; the
  dev-unit FSBL booted the investor slot A with no panel attached (the render
  path does not depend on one).
* PIN entry on the real pixel PIN row (random start digits read from SRAM)
  unlocked the real OPTIGA + SE050 wallet; non-secure world and USB came up;
  `fwupdate.py --info` read the dev-unit trailer (26.10.21.1, slot A).
* `FW_BEGIN` reached the pixel consent flow (`confirm_screens_checked` under
  `nsc_fw_begin`). With no consent, the dialog's 120 s idle timeout ended the
  session: `FW_BEGIN` returned `0x6984`, the updater reported "running
  firmware unchanged", and the unit kept running 26.10.21.1 (then locked).
* Full investor updates with the on-device consents accepted (owner approved
  the emulated presses): 26.10.21.1 (A) → 26.10.21.2 (B) → 26.10.21.3 (A).
  Each time: the updater's UNLOCK brought up the PIN row when locked, the
  verify consent (2 taps + chord) and the install consent ("UPDATE TO
  V26.10.21.x?", 6 taps + chord) were accepted, 503 KB secure + 98 KB
  non-secure streamed in 25.0 s + 4.9 s, COMMIT reset into the FSBL, the new
  slot booted and unlocked the real wallet, and `fwupdate.py` confirmed the
  new release and slot. Boot log after each: `CONFIRM(old)`, `ATTEMPT(new)`,
  `CONFIRM(new)`.
* Gotcha: with OpenOCD attached, the non-secure world's DHCSR-gated semihosting
  prints park the core unless `arm semihosting enable` is set — USB then never
  enumerates. Not an issue without a debugger.

Not yet run on silicon: the FSBL on a DVT panel (it refuses to boot if its
display bring-up fails — the per-unit acceptance check covers it), real button
hardware (the bench emulates the pins), and a torn boot-log record (the
ECC-NMI recovery path).
