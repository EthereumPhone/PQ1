# Proof of secure erasure: EVT experiment

Design, argument, residuals and results:
[`docs/security/user-device-verification.md` § USB path](../../docs/security/user-device-verification.md#usb-path-proof-of-secure-erasure-with-a-power-cycle).

**Bench experiment only.** This is not the production prover and not a
production-approved procedure.

## Pieces

- `prover/`: standalone `no_std` crate (own `[workspace]`), pq1, secure
  state.
  - It links at bank-1 page 0 (`0x0C00_0000`, the SECBOOTADD0 boot address)
    and owns `PROVER_PAGES` = 2 pages.
  - The page image is the code plus a true-random tail from `prover/pad.bin`.
  - It has no option-byte, OTP or RDP write path, never powers the secure
    elements, and refuses flash writes below its own pages.
  - Cargo features `cheat-skip-page` and `cheat-ram-hold` build dishonest
    provers as negative controls.
- `pose.py`: host verifier, standard library only, raw `/dev/hidraw`.
- `test_pose.py`: unit tests for the pure helpers
  (`python3 -m unittest tools/pose/test_pose.py`).

`make pose-prover [POSE_FEATURES=cheat-…]` builds the ELF, `prover.bin`,
`prover-padded.bin` (the 16 KiB page image), and prints the slack numbers.

## Procedure on EVT-3D21 (ST-LINK + USB-C)

```bash
B=~/Documents/PQ1/evt3d21-backup-<date>          # back up first, twice, compare
STM32_Programmer_CLI -c port=SWD mode=UR -ob displ > $B/ob-before.txt
STM32_Programmer_CLI -c port=SWD mode=UR -u 0x0C000000 0x100000 $B/bank1.bin \
    -u 0x08100000 0x100000 $B/bank2.bin -u 0x0BFA0000 0x200 $B/otp.bin

make pose-prover
STM32_Programmer_CLI -c port=SWD mode=UR -e [0 1] \
    -w tools/pose/prover/prover-padded.bin 0x0C000000 -v -rst
python3 tools/pose/pose.py info
python3 tools/pose/pose.py fill --session /path/to/session
#   unplug USB-C AND the ST-LINK (SWD can back-power the MCU), wait ~10 s,
#   replug USB-C only
python3 tools/pose/pose.py verify --session /path/to/session \
    --image tools/pose/prover/prover-padded.bin

# restore
STM32_Programmer_CLI -c port=SWD mode=UR -e all -w $B/bank1.bin 0x0C000000 \
    -w $B/bank2.bin 0x08100000 -v -rst
```

`verify` passes only if all of these hold:
- every flash byte is the prover image or the session's `R`;
- the backup domain came back (pass `--no-vbat` on a board without VBAT
  retention);
- the SRAM canary is gone, which shows the unplug really happened;
- the prover reports RDP 0xAA, TZEN 1 and blank free OTP.

`receipt.json` in the session directory records everything.

## Wire protocol (64-byte HID reports, VID:PID 1209:7051, product "PQ1 PoSE prover")

| Op | Request | Reply |
|---|---|---|
| `0x01` HELLO | — | `0x81`, version, `PQPOSE01`, prover pages (u32), flash length (u32) |
| `0x03` ERASE | page (u16, 0..255) | `0x83`, ok, SR (u32) |
| `0x04` WRITE | space, offset (u32), length (u8, ×16, ≤48), pad, data at byte 8 | none; the first error is latched |
| `0x05` READ | space, offset (u32), report count (u16) | `count` × [`0x85`, space, offset, 56 data bytes] |
| `0x07` STATUS | — | `0x87`, failed, space, offset, SR, write count |

Spaces:
- 0: flash offset 0..2 MiB; bank 1 via the secure alias, bank 2 via the
  non-secure alias.
- 1: SRAM3 canary, 64 KiB.
- 2: backup SRAM, 2 KiB.
- 3: TAMP_BKP0–31.
- 4: info blob, read-only. It holds the FLASH option registers, UID, flash
  size, PWR_BDCR1, prover pages, cheat flags, FLASH_NSSR, and OTP at
  offset 128.

Any request it cannot serve is answered `0x8F`.
