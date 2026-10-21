#!/usr/bin/env python3
"""Drive a pq1 unit's trusted UI over SWD — for boards with no panel/buttons.

    tools/devunit/headless-ui.py pin 13572468 --elf <secure.elf>
    tools/devunit/headless-ui.py confirm --elf <secure.elf>     # walk + accept a dialog
    tools/devunit/headless-ui.py state --elf <secure.elf>

BENCH ONLY (EVT-3D21: J210 SWD + USB-C, no panel, no buttons). Talks to a
running OpenOCD (`openocd -f interface/stlink.cfg -c "transport select hla_swd"
-f target/stm32u5x.cfg -c "reset_config none" -c init`, TCL port 6666) and
never halts the core:

* Buttons: the firmware reads LEFT = PA0, RIGHT = PA1 as pulled-up, active-low
  inputs. A press is emulated by switching the pin to output-low (MODER=01,
  ODR=0) through the secure GPIOA alias; release switches it back to input.
  The firmware sees exactly what a real button produces (IDR=0 while held).
* PIN entry: each position starts at a random digit (F-20), so the tool finds
  the PIN array in secure SRAM: it snapshots the stack, taps RIGHT once, and
  keeps the 8-byte window whose first byte advanced by one (mod 10) while the
  other seven stayed put. Then it dials each position from its read-back value
  and confirms with the both-buttons chord.
* Dialogs (`confirm --taps N`): tap RIGHT exactly N times to reach the
  returning ask, then the chord, which signs only there. N must be exact: a
  RIGHT tap ON the returning ask re-enters the details, so over-tapping wraps
  onto a detail screen where the chord is ignored. Firmware update: the verify
  consent needs 2, the install consent 6 (pinned in status_map.rs tests).

Symbols (PX_SAMPLING, RING_HEAD) come from the secure ELF the unit runs.
"""
from __future__ import annotations

import argparse
import socket
import struct
import subprocess
import sys
import time

GPIOA = 0x5202_0000          # secure alias
MODER, IDR, BSRR = 0x00, 0x10, 0x18
LEFT, RIGHT = 1, 2
STACK_LO, STACK_HI = 0x3001_8000, 0x3003_0000


class Ocd:
    def __init__(self, port: int = 6666) -> None:
        self.s = socket.create_connection(("127.0.0.1", port))
        self.buf = b""

    def cmd(self, c: str) -> str:
        self.s.sendall(c.encode() + b"\x1a")
        while b"\x1a" not in self.buf:
            chunk = self.s.recv(1 << 20)
            if not chunk:
                raise IOError("OpenOCD closed the connection")
            self.buf += chunk
        out, self.buf = self.buf.split(b"\x1a", 1)
        return out.decode()

    def r32(self, addr: int, n: int = 1) -> list[int]:
        out = self.cmd(f"read_memory {addr:#x} 32 {n}").split()
        if len(out) != n:
            raise IOError(f"read {addr:#x}: {' '.join(out)[:200]}")
        return [int(x, 0) for x in out]

    def w32(self, addr: int, v: int) -> None:
        self.cmd(f"write_memory {addr:#x} 32 {{{v:#x}}}")

    def rbytes(self, addr: int, n: int) -> bytes:
        words = []
        for a in range(addr, addr + n, 4096):
            words += self.r32(a, min(1024, (addr + n - a) // 4))
        return b"".join(struct.pack("<I", w) for w in words)


def symbols(elf: str) -> dict[str, int]:
    out = subprocess.check_output(["arm-none-eabi-nm", "-C", elf], text=True)
    want = {"ui::px::lcd::PX_SAMPLING": "sampling", "ui::px::lcd::RING_HEAD": "ring_head",
            "ui::px::lcd::STABLE_BITS": "stable", "timeout::TICKS": "ticks"}
    syms = {}
    for line in out.splitlines():
        parts = line.split(maxsplit=2)
        if len(parts) == 3:
            for k, v in want.items():
                if parts[2].endswith(k) and parts[2].startswith("sphincs_tz_secure::"):
                    syms[v] = int(parts[0], 16)
    missing = set(want.values()) - set(syms)
    if missing:
        sys.exit(f"symbols not found in {elf}: {missing}")
    return syms


class Ui:
    def __init__(self, ocd: Ocd, syms: dict[str, int]) -> None:
        self.o, self.sy = ocd, syms
        self.o.w32(GPIOA + BSRR, (1 << 16) | (1 << 17))   # ODR0/1 = 0

    def _set(self, mask: int) -> None:
        v = self.o.r32(GPIOA + MODER)[0] & ~0xF
        if mask & LEFT:
            v |= 0b01
        if mask & RIGHT:
            v |= 0b01 << 2
        self.o.w32(GPIOA + MODER, v)

    def u8(self, name: str) -> int:
        a = self.sy[name]
        return (self.o.r32(a & ~3)[0] >> (8 * (a & 3))) & 0xFF

    def u32(self, name: str) -> int:
        return self.o.r32(self.sy[name])[0]

    def wait_live(self, timeout_s: float) -> None:
        end = time.monotonic() + timeout_s
        while time.monotonic() < end:
            if self.u8("sampling"):
                return
            time.sleep(0.2)
        raise TimeoutError("no dialog is waiting for input")

    def press(self, mask: int, hold: float, gap: float = 0.25) -> None:
        h0 = self.u32("ring_head")
        self._set(mask)
        time.sleep(hold)
        self._set(0)
        time.sleep(gap)
        if self.u32("ring_head") == h0:
            raise IOError("the firmware did not register the press")

    def tap(self, mask: int) -> None:
        self.press(mask, 0.12)

    def chord(self) -> None:
        self.press(LEFT | RIGHT, 0.15, 0.4)


def find_pin_array(ui: Ui) -> int:
    """Locate the dial of position 0: tap RIGHT, RIGHT, LEFT, LEFT and keep
    the 8-byte window whose first byte follows +1, +2, +1, 0 (mod 10) while
    the other seven never change. Counters that merely step by one, and copies
    the renderer keeps of the row (which lag a frame), fail that pattern."""
    snap = lambda: ui.o.rbytes(STACK_LO, STACK_HI - STACK_LO)  # noqa: E731
    base = snap()
    cands = [i for i in range(len(base) - 7) if max(base[i:i + 8]) <= 9]
    for btn, d in ((RIGHT, 1), (RIGHT, 2), (LEFT, 1), (LEFT, 0)):
        ui.tap(btn)
        time.sleep(0.3)
        now = snap()
        cands = [i for i in cands
                 if now[i] == (base[i] + d) % 10 and now[i + 1:i + 8] == base[i + 1:i + 8]]
    if not cands:
        raise IOError("PIN array not found")
    if len({base[i:i + 8] for i in cands}) != 1:
        raise IOError(f"PIN array ambiguous ({len(cands)} candidates)")
    if len(cands) > 1:
        print(f"PIN digits found in {len(cands)} places (all agree)")
    return STACK_LO + cands[0]


def enter_pin(ui: Ui, pin: str) -> None:
    ui.wait_live(120)
    time.sleep(1.0)
    addr = find_pin_array(ui)
    print(f"PIN array at {addr:#010x}")
    for pos, ch in enumerate(pin):
        target = int(ch)
        for _ in range(3):
            cur = ui.o.rbytes(addr, 8)[pos]
            delta = (target - cur) % 10
            if delta == 0:
                break
            if delta <= 5:
                for _ in range(delta):
                    ui.tap(RIGHT)
            else:
                for _ in range(10 - delta):
                    ui.tap(LEFT)
        if ui.o.rbytes(addr, 8)[pos] != target:
            raise IOError(f"position {pos}: could not dial {target}")
        ui.chord()
        print(f"  position {pos + 1}/8 entered")


def confirm(ui: Ui, taps: int) -> None:
    ui.wait_live(600)
    time.sleep(2.0)
    for _ in range(taps):
        ui.tap(RIGHT)
        time.sleep(0.6)
    time.sleep(1.0)
    ui.chord()
    print(f"walked {taps} screens and sent the chord")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("action", choices=["pin", "confirm", "state"])
    ap.add_argument("value", nargs="?")
    ap.add_argument("--elf", required=True, help="secure ELF the unit runs (for symbol addresses)")
    ap.add_argument("--taps", type=int, help="exact RIGHT taps to the returning ask (confirm)")
    a = ap.parse_args()
    ui = Ui(Ocd(), symbols(a.elf))
    if a.action == "pin":
        if not a.value or len(a.value) != 8 or not a.value.isdigit():
            sys.exit("pin needs 8 digits")
        enter_pin(ui, a.value)
    elif a.action == "confirm":
        if a.taps is None:
            sys.exit("confirm needs --taps (exact screens to the returning ask)")
        confirm(ui, a.taps)
    else:
        print(f"sampling={ui.u8('sampling')} stable={ui.u32('stable'):#x} ring_head={ui.u32('ring_head')} "
              f"ticks={ui.u32('ticks')} MODER={ui.o.r32(GPIOA + MODER)[0]:#010x} IDR={ui.o.r32(GPIOA + IDR)[0]:#010x}")


if __name__ == "__main__":
    main()
