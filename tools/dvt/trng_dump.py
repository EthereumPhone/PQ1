#!/usr/bin/env python3
"""Pull TRNG output from a `trng-dump` secure image over SWD (DVT row 4.8).

The firmware (secure/src/trng_dump.rs) fills a 64 KB buffer through
`hw::rng::fill`, bumps TRNG_DUMP_SEQ and waits until TRNG_DUMP_ACK equals it.
This script reads each completed buffer with `probe-rs read`, acknowledges it,
and appends it to the output file. Symbol addresses come from the ELF.

    tools/dvt/trng_dump.py --elf <secure ELF> --out trng.bin --bytes 2097152
"""
import argparse
import hashlib
import subprocess
import sys
import tempfile
import time

CHUNK = 64 * 1024


def symbols(elf):
    out = subprocess.run(["arm-none-eabi-nm", elf], check=True,
                         capture_output=True, text=True).stdout
    syms = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2].startswith("TRNG_DUMP_"):
            syms[parts[2]] = int(parts[0], 16)
    for name in ("TRNG_DUMP_BUF", "TRNG_DUMP_SEQ", "TRNG_DUMP_ACK", "TRNG_DUMP_ERRS"):
        if name not in syms:
            sys.exit(f"{name} not in {elf}")
    return syms


def probe(chip, *args):
    return subprocess.run(["probe-rs", *args, "--chip", chip], check=True,
                          capture_output=True, text=True).stdout


def read_word(chip, addr):
    return int(probe(chip, "read", "b32", hex(addr), "1").split()[0], 16)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--elf", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--bytes", type=int, default=2 * 1024 * 1024)
    ap.add_argument("--chip", default="STM32U585CIUx")
    a = ap.parse_args()

    s = symbols(a.elf)
    seen = set()
    got = 0
    t0 = time.time()
    with open(a.out, "wb") as f, tempfile.TemporaryDirectory() as td:
        while got < a.bytes:
            seq = read_word(a.chip, s["TRNG_DUMP_SEQ"])
            ack = read_word(a.chip, s["TRNG_DUMP_ACK"])
            if seq == ack:
                time.sleep(0.05)
                continue
            path = f"{td}/chunk.bin"
            probe(a.chip, "read", "b32", hex(s["TRNG_DUMP_BUF"]), str(CHUNK // 4),
                  "--output", path, "--format", "binary")
            data = open(path, "rb").read()
            if len(data) != CHUNK:
                sys.exit(f"short read: {len(data)} B")
            # The buffer must not change under us: SEQ is still the same.
            if read_word(a.chip, s["TRNG_DUMP_SEQ"]) != seq:
                sys.exit("SEQ moved during the read")
            h = hashlib.sha256(data).hexdigest()
            if h in seen:
                sys.exit(f"duplicate chunk at seq {seq}")
            seen.add(h)
            f.write(data)
            got += len(data)
            probe(a.chip, "write", "b32", hex(s["TRNG_DUMP_ACK"]), hex(seq))
            errs = read_word(a.chip, s["TRNG_DUMP_ERRS"])
            print(f"seq={seq} got={got} errs={errs} t={time.time() - t0:.1f}s sha={h[:16]}",
                  flush=True)
    print(f"done: {got} B in {time.time() - t0:.1f}s, fill errors {errs}")


if __name__ == "__main__":
    main()
