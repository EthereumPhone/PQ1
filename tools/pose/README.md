# Proof of secure erasure through ST's ROM bootloader: EVT experiment

Design, argument, residuals and results:
[`docs/security/user-device-verification.md` § USB path](../../docs/security/user-device-verification.md#usb-path-proof-of-secure-erasure-with-a-power-cycle).

**Bench experiment only.** This is not a production-approved procedure. It is
the reference for what the Vault desktop app does.

The device ships with the release flashed and boots it. Its first screen
offers **Set up** (the default, no computer needed) and **Check first**. Only
a user who picks Check first goes through this check:
- the release sets the **check profile**: boot ST's mask-ROM USB bootloader
  (DFU, `0483:df11`) with all flash non-secure;
- it resets, and from then on no PQ1 code runs until the check is over.

That firmware path is not implemented yet. On the EVT, ST-LINK sets the check
profile instead (below). `pose.py` speaks DfuSe to the ROM:
1. it fills all 2 MB of flash with fresh random data `R`;
2. the user unplugs and replugs;
3. it reads all 2 MB back, plus the option bytes and the OTP, and compares.

An earlier version of this experiment put a PQ1 "prover" in flash
(`tools/pose/prover/`, removed; see commit `68be6b139`). Its own code left
~4.4 KB of compressible slack, which is why the design moved to the ROM.

## Pieces

- `pose.py`: DfuSe client and verifier.
  - Standard library only: Linux usbfs (`/dev/bus/usb`) through `ioctl`.
    ST's udev rule `50-usb-conf.rules` gives `0483:df11` mode 0666.
  - Its commands are listed below.
  - **It has no option-byte write path**. Option bytes are changed with
    `STM32_Programmer_CLI`.
- `test_pose.py`: unit tests, including the real DfuSe client against an
  in-memory fake of the ROM (`make pose-test`).

| Command | What it does |
|---|---|
| `info` | DfuSe alt layouts, UID (USB serial), decoded option bytes, check-profile problems, OTP |
| `probe` | what the ROM can reach besides flash: option bytes, OTP, an SRAM2 write, backup SRAM |
| `fill --session D` | mass erase, write `R` (2 MiB from `secrets`) to all flash, write a 4 KiB SRAM2 canary |
| `verify --session D [--otp-expected F]` | read back all flash, the option bytes, the OTP and the canary, write `receipt.json` |
| `run --session D [--min-off 10]` | `fill`, prompt to unplug, measure how long the device was gone, `verify` |
| `install --image ADDR=FILE …` | mass erase, write the images, read them back. It prints the option-byte commands that switch back to the shipping profile, so the device boots the release and shows its first screen again. |

`verify` gives **PASS** only if all of these hold:
- every flash byte equals `R`;
- the option bytes match the check profile:
  - RDP 0xAA, TZEN 1, nSWBOOT0 0, nBOOT0 0, BOOT_LOCK 0, SWAP_BANK 0,
    DUALBANK 1;
  - SECWM1/SECWM2 empty, no WRP, no HDP;
- the OTP equals the expected image (all 0xFF on the EVT);
- under `run`, the device was gone for at least `--min-off` seconds and the
  SRAM2 canary is gone.

With SRAM2_RST=1, a reset alone keeps SRAM2 (measured), so a missing canary
shows that power was lost. Like the off-time measurement, this only catches
honest runs that skipped the unplug. Malware could fake both.

## Procedure on EVT-3D21 (ST-LINK + USB-C)

```bash
B=~/Documents/PQ1/evt3d21-backup-<date>          # back up first, twice, compare
P="STM32_Programmer_CLI -c port=SWD mode=UR"
$P -ob displ > $B/ob-before.txt
$P -u 0x0C000000 0x100000 $B/bank1.bin -u 0x08100000 0x100000 $B/bank2.bin \
   -u 0x0BFA0000 0x200 $B/otp.bin

# check profile, as the release will set it on "Check first": boot ST's ROM,
# every page non-secure. (-e all only stands in for a device whose flash is
# about to be filled anyway.)
$P -e all
$P -ob nSWBOOT0=0 nBOOT0=0 SECWM1_PSTRT=0x7F SECWM1_PEND=0x0   # SECWM2 already empty here
lsusb -d 0483:df11

python3 tools/pose/pose.py info
python3 tools/pose/pose.py run --session $B/sessions/run1 --min-off 10
#   when told: unplug USB-C AND the ST-LINK (SWD can back-power the MCU),
#   wait >10 s, replug USB-C only

# install (here: restore the backup) and switch back to booting it
python3 tools/pose/pose.py install --image 0x08000000=$B/bank1.bin --image 0x08100000=$B/bank2.bin
STM32_Programmer_CLI -c port=USB1 -ob SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F
STM32_Programmer_CLI -c port=USB1 -ob nSWBOOT0=1 nBOOT0=1
```

**Notes:**
- With TZEN=1 the ROM runs non-secure. That is why bank 1 must be non-secure
  (empty SECWM1) while the ROM fills and reads it, and why it is switched back
  before the device boots the release.
- A page left secure reads back wrong and fails the check-profile check.
  That is control C3.
- The design's shipping profile boots flash with the BOOT0 pin ignored
  (`nSWBOOT0=0 nBOOT0=1`). The EVT restore above uses the EVT's own original,
  pin-selected setting.

## DfuSe as the ROM implements it (EVT-3D21, bootloader `bcdDevice` 2.00)

| Alt | Layout string | Use |
|---|---|---|
| 0 | `@Internal Flash /0x08000000/256*08Kg` | all 2 MB, both banks (non-secure alias) |
| 1 | `@Option Bytes /0x40022040/01*64 e` | `FLASH_OPTR` … `OEM2KEYR2`, 16 words |
| 2 | `@OTP Memory /0x0BFA0000/01*512 e` | the 512-B OTP |

The transfer size is 1024. The protocol:
- Commands go as DNLOAD block 0: `0x21` + address sets the pointer; `0x41`
  alone mass-erases.
- Data block `n ≥ 2` goes to `pointer + (n−2)·1024`.
- Every DNLOAD is followed by GETSTATUS polling (DNBUSY → DNLOAD-IDLE).
- UPLOAD needs an ABORT back to dfuIDLE after the set-address.

The ROM accepts SRAM2 (`0x20030000`) on alt 0. It refuses backup SRAM
(`0x40036400`, `errVENDOR`), so the fill cannot cover the backup domain.
