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
  dev-dfu,stm32u585,usb,board-pq1` + `devunit-ab`. **`dev-dfu` with a 2 s
  hold** (since 2026-10-21 evening; releases up to 26.10.21.5 had none): the
  FSBL can only be re-flashed over DFU or SWD. To enter DFU, hold BOTH
  buttons while plugging in USB-C and keep holding through the fingerprint
  (~8 s) until the unit enumerates as `0483:df11`. The bench's 50 ms trigger
  would latch a unit into DFU on a stray chord just before the PIN pad.
* `bench`: `mock-se,e2e-test,ui-noop,...` — never touches the secure elements,
  auto-unlocks and auto-confirms; for the headless EVT bench board.

## First flash of a unit (once, before it ships)

Over USB-C with the ROM bootloader (`0483:df11`): use the SBU-bridged USB-C
adapter (`docs/hardware/evt-dev-loop.md`), or hold both buttons while plugging
in if the unit already runs a `dev-dfu` image (dev-unit images: keep holding
~8 s, through the fingerprint). A unit on 26.10.21.1–.5 has no `dev-dfu`:
install a newer release over USB first, then use the buttons. Then:

```bash
tools/devunit/flash.sh target/devunit/releases/investor-<v> --dfu --erase-all
```

`--erase-all` mass-erases (fresh unit, or one with ODM/monolithic firmware).
Without it, only bank-1 pages 0–86 and bank 2 are erased and the wallet pages
survive. With a probe on J210: `--swd` instead of `--dfu`. The script handles
TZEN=0 and TZEN=1 units, opens the watermarks for the non-secure ROM
bootloader, and leaves `TZEN=1, SECWM1=0..0x7F, SECWM2=0x30..0x7F,
SECBOOTADD0=0x180000, nSWBOOT0=1, nBOOT0=1`. RDP stays 0, no WRP, no OTP.

**Acceptance check per unit** (the FSBL first ran on a DVT on
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

On the device (firmware 26.10.21.10 and later): one question, "UPDATE
FIRMWARE?" — tap RIGHT through the new version and its 8 words (3 taps), press
BOTH buttons on the last screen to install, hold LEFT to cancel. The signature
is checked before the question appears, so everything on it is authentic; the
signer words are no longer shown (the device only accepts the dev-unit key).
Then INSTALLING with progress, ~30 s, and the unit restarts, shows the new
words, asks for the PIN. Firmware up to 26.10.21.9 asks twice (a verify
question, then "UPDATE TO V…?" with 6 taps and the signer words).
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

### Silicon evidence (two pq1 DVTs with panel and buttons, 2026-10-21 evening)

Owner at the device, real buttons, USB-C only:

* DVT #1, first flash over ROM DFU (both-buttons entry of its previous
  `dev-dfu` image), `--erase-all`, 26.10.21.1: the FSBL drove the DVT panel
  (5x8 words) and booted slot A; its secure elements still held an earlier
  wallet (PIN screen, not the wizard).
* Signed USB updates on the real panel and buttons: 26.10.21.1 (A) → .8 (B);
  after the DFU re-flash below (.8 on A) → .9 (B) → .10 (A) → .11 (B) → .12
  (A) → .13 (B), each unlocked on the new release. Transfer 30-36 s, 79 s with the per-chunk
  INSTALLING film (0d3a2c1c; smooth, confirmed by the owner).
* 26.10.21.8's 2 s both-buttons hold entered ROM DFU; `flash.sh` WITHOUT
  `--erase-all` put the `px-fingerprint` FSBL on (pixel "OS FINGERPRINT" +
  whole-word grid, no second screen from the secure world) and the existing
  wallet still unlocked.
* The UI changes were each confirmed on the panel one install after they
  landed (the running firmware draws the update dialogs): UPDATE FIRMWARE?
  wording, INSTALLING instead of a frozen confirm, the one-consent flow
  (UPDATE FIRMWARE? → NEW VERSION → 8 words → chord), the smooth film.
* DVT #2 (investor unit): both-buttons DFU from its previous image,
  `--erase-all`, 26.10.21.13.

Not yet run on silicon: a torn boot-log record (the ECC-NMI recovery path),
and the 3-boot rollback on a DVT (silicon-tested on the EVT bench board only).
