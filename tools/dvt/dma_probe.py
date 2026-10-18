#!/usr/bin/env python3
"""Read the `dma-probe` NS fixture's results over SWD (DVT row 3.9).

    tools/dvt/dma_probe.py --ns-elf <NS ELF> [--expect-locked] [--out results.json]

Default (a pre-#982 secure image): PASS when both NS->NS controls complete with
the source pattern, every case that touches secure memory ends in a transfer
error or leaves the sentinel / zeros in the destination, and neither write
target holds the source pattern. The OTP/UID cases are reported, not judged.

--expect-locked (#982, a secure image that claims every DMA channel): PASS only
when the GPDMA1/LPDMA1 attribution registers read all-secure, all-privileged
and all-locked to the non-secure world AFTER its RCC reset/clock attempt,
EVERY case in both passes (controls, OTP and UID included) leaves the
destination sentinel untouched with no completion flag, neither write target
holds the source pattern, and the TZIC counted the non-secure channel writes.
"""
import argparse, json, subprocess, sys, time

NAMES = ["control NS->NS", "S-SRAM1 0x30000000", "SRAM1 NS alias 0x20000000", "S stack 0x3002FF00",
         "SRAM3 S alias 0x30040000", "SRAM3 NS alias 0x20040000", "S flash 0x0C000000",
         "flash NS alias 0x08000000", "OTP 0x0BFA0000", "WRITE S-SRAM1 0x3001FF00",
         "WRITE SRAM1 NS alias 0x2001FF10", "control again", "UID 0x0BFA0700", "OTP last QW 0x0BFA01F0"]
OTP_AREA = {8, 12, 13}   # reported, not judged: a non-zero read here means the area is NOT filtered
SRC = [0xA11CE001, 0xA11CE002, 0xA11CE003, 0xA11CE004]
SENT = 0x5EE55EE5
WRITE_TARGETS = {9: 0x3001FF00, 10: 0x3001FF10}   # both cases land in SRAM1 offset 0x1FFxx


def syms(elf):
    out = subprocess.run(["arm-none-eabi-nm", elf], check=True, capture_output=True, text=True).stdout
    return {p[2]: int(p[0], 16) for p in (l.split() for l in out.splitlines()) if len(p) == 3}


def rw(chip, addr, n, tries=5):
    """Read n words over SWD as hex text, retrying. (`--format binary` failed with
    SwdApWdataError on GTZC registers that the hex path reads every time.)"""
    for t in range(tries):
        r = subprocess.run(["probe-rs", "read", "--chip", chip, "b32", hex(addr), str(n)],
                           capture_output=True, text=True)
        words = r.stdout.split()
        if r.returncode == 0 and len(words) == n:
            return [int(w, 16) for w in words]
        time.sleep(1)
    raise SystemExit(f"SWD read of {addr:#x} failed {tries} times")


def flags(csr):
    f = [n for b, n in [(0, "IDLE"), (8, "TC"), (10, "DTE"), (11, "ULE"), (12, "USE"), (14, "TO")] if csr >> b & 1]
    return "|".join(f) or "-"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ns-elf", required=True)
    ap.add_argument("--out")
    ap.add_argument("--expect-locked", action="store_true",
                    help="judge against a #982-fixed secure image (every channel secure+locked)")
    ap.add_argument("--chip", default="STM32U585CIUx")
    a = ap.parse_args()
    s = syms(a.ns_elf)
    for _ in range(120):
        hdr = rw(a.chip, s["DMA_PROBE_HDR"], 14)
        if hdr[0] == 0xD3A90982 and hdr[1] == 2 * len(NAMES):
            break
        time.sleep(1)
    print(f"hdr magic={hdr[0]:#x} done={hdr[1]} RCC_AHB1ENR(NS read)={hdr[2]:#010x} unlocked={hdr[3]} PRIVCFGR={hdr[4]:#x}")
    print(f"NS view after RCC reset/clock attempt: GPDMA1 SEC={hdr[5]:#06x} PRIV={hdr[6]:#06x} LOCK={hdr[7]:#06x}"
          f"  LPDMA1 SEC={hdr[8]:#x} PRIV={hdr[9]:#x} LOCK={hdr[10]:#x}  (GPDMA1 SEC before attempt={hdr[13]:#06x})")
    print(f"TZIC violations: before passes={hdr[11]} after={hdr[12]}")
    res = rw(a.chip, s["DMA_PROBE_RES"], 12 * len(NAMES))
    rows, ok = [], hdr[1] == 2 * len(NAMES)
    if a.expect_locked:
        lock_ok = (hdr[5:8] == [0xFFFF] * 3 and hdr[8:11] == [0xF] * 3 and hdr[13] == 0xFFFF)
        tzic_ok = hdr[12] > hdr[11]
        print(f"attribution locked and survives the NS RCC attempt: {'ok' if lock_ok else 'UNEXPECTED'}")
        print(f"TZIC counted the NS channel writes: {'ok' if tzic_ok else 'UNEXPECTED'}")
        ok &= lock_ok and tzic_ok
    for n in range(2 * len(NAMES)):
        i, name = n % len(NAMES), ("PRIV " if n >= len(NAMES) else "unpr ") + NAMES[n % len(NAMES)]
        if i == 0:
            print("--- pass:", "privileged channel" if n else "unprivileged channel (reset state)")
        csr, d, spins = res[6 * n], res[6 * n + 1:6 * n + 5], res[6 * n + 5]
        err = bool(csr & 0x1C00)
        if a.expect_locked:
            # A secure channel's registers read 0 to NS and its writes are
            # ignored: no case may complete or touch its destination.
            if i in WRITE_TARGETS:
                d = rw(a.chip, WRITE_TARGETS[i], 4)
                good = d != SRC
            else:
                good = not (csr >> 8 & 1) and d == [SENT] * 4
                if i in OTP_AREA:
                    name += "  [" + ("blocked" if good else "READ: NOT BLOCKED") + "]"
        elif i in (0, 11):
            # The unprivileged pass's controls are informational (see the row).
            good = ((csr >> 8 & 1) and not err and d == SRC) or n < len(NAMES)
        elif i in WRITE_TARGETS:
            tgt = rw(a.chip, WRITE_TARGETS[i], 4)
            good = tgt != SRC
            d = tgt
        elif i in OTP_AREA:
            good = True
            name += "  [" + ("RAZ/filtered" if err or all(w in (SENT, 0) for w in d) else "READ: not filtered") + "]"
        else:
            good = err or all(w in (SENT, 0) for w in d)
        ok &= bool(good)
        print(f"{n:2} {name:35} csr={csr:#010x} {flags(csr):14} {'target' if i in WRITE_TARGETS else 'dst'}="
              f"{' '.join(f'{w:08x}' for w in d)} spins={spins} -> {'ok' if good else 'UNEXPECTED'}")
        rows.append(dict(case=n, name=name, csr=csr, words=d, spins=spins, ok=bool(good)))
    print("VERDICT:", "PASS" if ok else "FAIL")
    if a.out:
        json.dump(dict(hdr=hdr, rows=rows, verdict=bool(ok)), open(a.out, "w"), indent=1)
    sys.exit(0 if ok else 1)


main()
