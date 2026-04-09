#!/usr/bin/env python3
"""
Two-button hardware-wallet front-end for real STM32U585 + OLED.

Same arrow-key mapping as wallet_run.py (the QEMU version), but talks to
real hardware via probe-rs semihosting file I/O instead of QEMU:

    <-           Left button, short tap   (back / prev / scroll)
    ->           Right button, short tap  (next / scroll)
    <- + ->      CONFIRM                  (long-press right; advance / OK)
    Esc          CANCEL                   (long-press left; back out)
    Ctrl-C       Quit

Button input uses semihosting file I/O (not SYS_READC, which probe-rs
doesn't support). The firmware opens "/input" via SYS_OPEN, and probe-rs
maps it to a TCP socket on localhost via --semihosting-file. This script
listens on that socket and sends button characters when you press arrows.

The OLED display shows the actual UI on the physical SSD1306; semihosting
stdout (hprintln) carries debug output to this terminal.
"""

import os
import select
import socket
import subprocess
import sys
import termios
import threading
import time
import tty
from pathlib import Path

CHORD_WINDOW = 0.15  # seconds

REPO_ROOT = Path(__file__).resolve().parent.parent
SECURE_ELF = (
    REPO_ROOT / "target" / "secure" / "thumbv8m.main-none-eabi" / "release" / "sphincs-tz-secure"
)

CHIP = "STM32U585AIIx"

BANNER = """\
================================================================
  SPHINCS+ Wallet  --  STM32U585 + OLED  (probe-rs semihosting)
================================================================
   <-           Left button  (back / prev / scroll down)
   ->           Right button (next / scroll up)
   <- + ->      CONFIRM      (press both arrows together)
   Esc          CANCEL       (back out one step)
   Ctrl-C       Quit

  Booting target... UI renders on the OLED display.
================================================================
"""


def must_have_binary():
    if not SECURE_ELF.exists():
        sys.stderr.write(
            "wallet_run_hw: secure ELF not found.\n"
            "  Run `make play-hw-display` to build + flash first.\n"
        )
        sys.exit(1)


def start_button_server():
    """TCP server that probe-rs connects to when the target opens /input."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', 0))   # OS picks a free port
    server.listen(1)
    return server


def spawn_probe_rs(port):
    return subprocess.Popen(
        [
            "probe-rs", "run",
            "--chip", CHIP,
            "--semihosting-file", f"/input=tcp:127.0.0.1:{port}",
            str(SECURE_ELF),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
        preexec_fn=os.setsid,
    )


def forward_output(stdout, stop_event):
    """Forward probe-rs semihosting output to terminal (CRLF for raw mode)."""
    out = sys.stdout.buffer
    while not stop_event.is_set():
        try:
            b = stdout.read(1)
        except (ValueError, OSError):
            break
        if not b:
            break
        if b == b"\n":
            out.write(b"\r\n")
        else:
            out.write(b)
        try:
            out.flush()
        except BrokenPipeError:
            break


def read_one_event(fd, timeout):
    """Read one logical key event (arrow, Esc, Ctrl-C) with timeout."""
    rlist, _, _ = select.select([fd], [], [], timeout)
    if not rlist:
        return None
    try:
        b = os.read(fd, 1)
    except OSError:
        return ('quit',)
    if not b:
        return ('quit',)
    c = b[0]
    if c == 0x03:  # Ctrl-C
        return ('quit',)
    if c == 0x1b:  # ESC
        rlist, _, _ = select.select([fd], [], [], 0.08)
        if not rlist:
            return ('cancel',)
        try:
            b2 = os.read(fd, 1)
        except OSError:
            return ('cancel',)
        if b2 not in (b"[", b"O"):
            return ('cancel',)
        rlist, _, _ = select.select([fd], [], [], 0.08)
        if not rlist:
            return ('cancel',)
        try:
            b3 = os.read(fd, 1)
        except OSError:
            return ('cancel',)
        if b3 == b"D":
            return ('left',)
        if b3 == b"C":
            return ('right',)
        return None
    return None


def main():
    must_have_binary()

    fd = sys.stdin.fileno()
    if not os.isatty(fd):
        sys.stderr.write("wallet_run_hw: stdin must be a TTY\n")
        sys.exit(1)

    # Start TCP server for button input before spawning probe-rs.
    server = start_button_server()
    port = server.getsockname()[1]

    sys.stdout.write(BANNER)
    sys.stdout.write(f"  Button input server on 127.0.0.1:{port}\n\n")
    sys.stdout.flush()
    time.sleep(0.2)

    old_termios = termios.tcgetattr(fd)
    proc = None
    conn = None
    stop_event = threading.Event()
    forwarder = None

    try:
        tty.setcbreak(fd)
        proc = spawn_probe_rs(port)
        forwarder = threading.Thread(
            target=forward_output,
            args=(proc.stdout, stop_event),
            daemon=True,
        )
        forwarder.start()

        # Wait for the target to SYS_OPEN("/input") — probe-rs connects
        # to our TCP server.  This typically takes a few seconds while
        # probe-rs flashes + boots the target.
        server.settimeout(60)
        try:
            conn, _ = server.accept()
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except socket.timeout:
            sys.stdout.write("\r\n  Timeout waiting for target to connect.\r\n")
            sys.stdout.flush()
            return

        def emit(byte: str):
            try:
                conn.sendall(byte.encode())
            except (BrokenPipeError, OSError):
                pass

        pending = None
        pending_until = 0.0

        while True:
            if proc.poll() is not None:
                break
            if pending is None:
                timeout = 0.2
            else:
                remaining = pending_until - time.monotonic()
                timeout = max(0.0, remaining)

            ev = read_one_event(fd, timeout)

            if ev is None:
                if pending is not None and time.monotonic() >= pending_until:
                    emit('h' if pending == 'left' else 'l')
                    pending = None
                continue

            kind = ev[0]
            if kind == 'quit':
                break
            if kind == 'cancel':
                if pending is not None:
                    emit('h' if pending == 'left' else 'l')
                    pending = None
                emit('H')
                continue
            if kind in ('left', 'right'):
                if pending is None:
                    pending = kind
                    pending_until = time.monotonic() + CHORD_WINDOW
                elif pending != kind:
                    emit('L')  # Both arrows = confirm
                    pending = None
                else:
                    emit('h' if pending == 'left' else 'l')
                    pending = kind
                    pending_until = time.monotonic() + CHORD_WINDOW
    finally:
        stop_event.set()
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        try:
            server.close()
        except Exception:
            pass
        if proc is not None:
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
        if forwarder is not None:
            forwarder.join(timeout=1)
        termios.tcsetattr(fd, termios.TCSADRAIN, old_termios)
        sys.stdout.write("\r\n")
        sys.stdout.flush()


if __name__ == '__main__':
    main()
