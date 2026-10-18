#!/usr/bin/env python3
"""Read the `ns-ptr-probe` NS fixture's results over SWD (DVT row 3.8).

    tools/dvt/ns_ptr_probe.py --ns-elf <NS ELF> [--out results.json]

Prints one row per gateway call and a verdict: PASS when the fixture finished
(no fault), every out-of-window pointer returned InvalidPointer (4), and the
in-window cases (12 NS flash for reads, 13, 14) did not.
"""
import argparse
import json
import subprocess
import sys
import tempfile
import time

CMDS = {1: "get_wallet_address", 2: "get_pin_attempt_log", 3: "fw_status", 4: "offchain_status",
        5: "get_init_code", 6: "sign_offchain", 7: "offchain_sync", 8: "sign_userop",
        9: "sign_userop_batch", 10: "fw_begin", 11: "fw_chunk"}
CASES = ["null", "straddle-start", "straddle-end", "past-end", "NS-alias-SRAM1", "secure-SRAM1",
         "secure-flash", "NSC-veneer", "NS-alias-flash-b1", "wrap", "NS-periph", "S-periph",
         "NS-flash-b2", "in-window", "valid-buffer"]
LEN_CASES = {0x20: "in_len=0xFFFFFFFF", 0x21: "in_len=0x80000000", 0x22: "manifest_len=0xFFFFFFFF",
             0x23: "in runs past window", 0x24: "total_len=0xFFFFFFFF", 0x25: "secure ptr, len 0",
             0x26: "secure ptr, len 0", 0x27: "4280-B write past window"}
STATUS = {0: "Ok", 1: "PinIncorrect", 2: "PinLocked", 3: "CryptoError", 4: "InvalidPointer",
          5: "NotInitialized", 6: "UserRejected", 7: "IdleWipe", 10: "FwBadState",
          11: "FwBadManifest", 12: "FwBadVersion", 13: "FwBadChunk", 14: "FwBadImage",
          15: "FwFlashError", 17: "OffchainSlotUnregistered", 18: "OffchainGapExceeded",
          19: "OffchainCapExceeded"}
INVALID = 4
IN_WINDOW = {13, 14}          # always inside the NS SRAM window
READ_OK = {12}                # NS flash bank 2: valid for reads only
# (cmd, arg) whose buffer starting at 0x2003F000 runs past the window end.
TOO_BIG_AT_13 = {(5, 1), (6, 1), (8, 1), (10, 0)}


def symbols(elf):
    out = subprocess.run(["arm-none-eabi-nm", elf], check=True, capture_output=True, text=True).stdout
    return {p[2]: int(p[0], 16) for p in (l.split() for l in out.splitlines())
            if len(p) == 3 and p[2].startswith("NS_PTR_PROBE_")}


def read_words(chip, addr, n):
    with tempfile.TemporaryDirectory() as td:
        path = f"{td}/w.bin"
        subprocess.run(["probe-rs", "read", "b32", hex(addr), str(n), "--chip", chip, "--output", path,
                        "--format", "binary"], check=True, capture_output=True)
        b = open(path, "rb").read()
    return [int.from_bytes(b[i:i + 4], "little") for i in range(0, len(b), 4)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ns-elf", required=True)
    ap.add_argument("--out")
    ap.add_argument("--chip", default="STM32U585CIUx")
    ap.add_argument("--timeout", type=float, default=120)
    a = ap.parse_args()
    s = symbols(a.ns_elf)
    t0 = time.time()
    while True:
        done = read_words(a.chip, s["NS_PTR_PROBE_DONE"], 1)[0]
        if done in (1, 2) or time.time() - t0 > a.timeout:
            break
        time.sleep(1)
    n = read_words(a.chip, s["NS_PTR_PROBE_N"], 1)[0]
    res = read_words(a.chip, s["NS_PTR_PROBE_RES"], max(n, 1))[:n]
    addrs = read_words(a.chip, s["NS_PTR_PROBE_CASES"], 16)
    print(f"done={done} calls={n} t={time.time() - t0:.1f}s")
    rows, fails = [], []
    for w in res:
        cmd, arg, case, st = w >> 24, (w >> 16) & 0xFF, (w >> 8) & 0xFF, w & 0xFF
        if case < 0x20:
            name, addr = CASES[case], addrs[case]
            reads = (cmd in (4, 5, 6, 7, 8, 9, 10, 11) and arg == 0)
            inside = case in IN_WINDOW or (case in READ_OK and reads)
            # 0x2003F000 has 4 KB to the window end: larger writes/reads must be refused.
            if case == 13 and (cmd, arg) in TOO_BIG_AT_13:
                inside = False
            # Stricter is fine: an SRAM-only reader may refuse NS flash.
            if case in READ_OK and reads and st == INVALID:
                ok, name = True, name + " (SRAM-only reader)"
            else:
                ok = (st != INVALID) if inside else (st == INVALID)
        else:
            name, addr = LEN_CASES.get(case, hex(case)), None
            ok = st != 0                                   # refused somehow, never Ok
        row = dict(cmd=CMDS.get(cmd, cmd), arg=arg, case=name, addr=addr, status=STATUS.get(st, st), ok=ok)
        rows.append(row)
        if not ok:
            fails.append(row)
        a_s = f"0x{addr:08x}" if addr is not None else "-"
        print(f"  {'ok ' if ok else 'BAD'} {row['cmd']:20s} arg{arg} {name:24s} {a_s:10s} -> {row['status']}")
    verdict = "PASS" if done == 1 and not fails else "FAIL"
    print(f"VERDICT {verdict} ({len(fails)} unexpected)")
    if a.out:
        json.dump(dict(done=done, rows=rows, verdict=verdict), open(a.out, "w"), indent=1)
    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
