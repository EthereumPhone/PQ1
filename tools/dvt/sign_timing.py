#!/usr/bin/env python3
"""Read and analyse a `sign-timing` secure image over SWD (DVT rows 16.4, 16.6).

The firmware (secure/src/sign_timing.rs) first runs a fixed-vs-random Welch
test on five primitives, then times whole C10 signs. This script waits for
phase 1, prints its t-statistics, then collects sign records until --signs
are done (or --minutes pass) and analyses them:

  * R-grind tries are recomputed from each record's inputs (they are not in
    the signature) and checked against the signature's R;
  * WOTS tries are count+1 per layer, read from the signature;
  * cycles are regressed on both, and the residual is tested by key class.

    tools/dvt/sign_timing.py --elf <secure ELF> --signs 400 --out sign_timing.json
"""
import argparse
import hashlib
import json
import math
import subprocess
import sys
import tempfile
import time

PRIM_NAMES = ["fors_secret", "wots_secret", "slot_entropy", "hmac_sha512(master)", "ct_eq 4008 B"]
PRIMS, REC_WORDS, MAX_SIGNS = 5, 40, 512
K, A = 13, 11


def symbols(elf):
    out = subprocess.run(["arm-none-eabi-nm", elf], check=True, capture_output=True, text=True).stdout
    syms = {p[2]: int(p[0], 16) for p in (l.split() for l in out.splitlines())
            if len(p) == 3 and p[2].startswith("SIGN_TIMING_")}
    for n in ("SIGN_TIMING_PRIM", "SIGN_TIMING_REC", "SIGN_TIMING_PHASE", "SIGN_TIMING_SIGNS",
              "SIGN_TIMING_RNG_ERRS"):
        if n not in syms:
            sys.exit(f"{n} not in {elf}")
    return syms


def probe(chip, *args):
    return subprocess.run(["probe-rs", *args, "--chip", chip], check=True,
                          capture_output=True, text=True).stdout


def read_words(chip, addr, n):
    with tempfile.TemporaryDirectory() as td:
        path = f"{td}/w.bin"
        probe(chip, "read", "b32", hex(addr), str(n), "--output", path, "--format", "binary")
        b = open(path, "rb").read()
    return [int.from_bytes(b[i:i + 4], "little") for i in range(0, len(b), 4)]


def welch(n0, s0, q0, n1, s1, q1):
    m0, m1 = s0 / n0, s1 / n1
    v0 = (q0 - n0 * m0 * m0) / (n0 - 1)
    v1 = (q1 - n1 * m1 * m1) / (n1 - 1)
    den = math.sqrt(v0 / n0 + v1 / n1)
    return m0, m1, v0, v1, (m0 - m1) / den if den else 0.0


def r_grind_tries(sk, pk_seed, pk_root, msg, opt):
    pad = lambda x: x + bytes(16)
    for nonce in range(10_000_000):
        r = hashlib.sha256(sk + b"R_grind" + opt + msg + bytes(28) + nonce.to_bytes(4, "big")).digest()[:16]
        d = hashlib.sha256(pad(pk_seed) + pad(pk_root) + pad(r) + msg + b"\xff" * 32).digest()
        if (int.from_bytes(d, "big") >> ((K - 1) * A)) & ((1 << A) - 1) == 0:
            return nonce + 1, r
    raise RuntimeError("no R")


def lstsq(X, y):
    # Normal equations, small dense solve (columns are few).
    k = len(X[0])
    M = [[sum(r[i] * r[j] for r in X) for j in range(k)] for i in range(k)]
    v = [sum(r[i] * t for r, t in zip(X, y)) for i in range(k)]
    for c in range(k):
        p = max(range(c, k), key=lambda r: abs(M[r][c]))
        M[c], M[p], v[c], v[p] = M[p], M[c], v[p], v[c]
        for r in range(k):
            if r != c:
                f = M[r][c] / M[c][c]
                M[r] = [a - f * b for a, b in zip(M[r], M[c])]
                v[r] -= f * v[c]
    return [v[i] / M[i][i] for i in range(k)]


def corr(a, b):
    n = len(a)
    ma, mb = sum(a) / n, sum(b) / n
    sab = sum((x - ma) * (y - mb) for x, y in zip(a, b))
    sa = math.sqrt(sum((x - ma) ** 2 for x in a))
    sb = math.sqrt(sum((y - mb) ** 2 for y in b))
    return sab / (sa * sb) if sa and sb else 0.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--elf", required=True)
    ap.add_argument("--signs", type=int, default=400)
    ap.add_argument("--minutes", type=float, default=600)
    ap.add_argument("--out", required=True)
    ap.add_argument("--chip", default="STM32U585CIUx")
    a = ap.parse_args()
    s = symbols(a.elf)
    t0 = time.time()
    while read_words(a.chip, s["SIGN_TIMING_PHASE"], 1)[0] != 2:
        time.sleep(10)
    print(f"phase 1 done after {time.time() - t0:.0f} s", flush=True)
    raw = read_words(a.chip, s["SIGN_TIMING_PRIM"], PRIMS * 2 * 8)
    prim = []
    for p in range(PRIMS):
        c = [raw[(p * 2 + k) * 8:(p * 2 + k) * 8 + 8] for k in range(2)]
        n0, n1 = c[0][0], c[1][0]
        s0, s1 = c[0][1] | c[0][2] << 32, c[1][1] | c[1][2] << 32
        q0, q1 = c[0][3] | c[0][4] << 32, c[1][3] | c[1][4] << 32
        m0, m1, v0, v1, t = welch(n0, s0, q0, n1, s1, q1)
        row = dict(name=PRIM_NAMES[p], n=[n0, n1], mean=[m0, m1], var=[v0, v1],
                   min=[c[0][5], c[1][5]], max=[c[0][6], c[1][6]], t=t)
        prim.append(row)
        print(f"  {PRIM_NAMES[p]:22s} n={n0}/{n1} mean={m0:.2f}/{m1:.2f} cyc "
              f"min={c[0][5]}/{c[1][5]} max={c[0][6]}/{c[1][6]} sd={math.sqrt(v0):.2f}/{math.sqrt(v1):.2f} "
              f"t={t:+.2f}", flush=True)
    while True:
        n = read_words(a.chip, s["SIGN_TIMING_SIGNS"], 1)[0]
        print(f"signs={n} t={time.time() - t0:.0f}s", flush=True)
        if n >= min(a.signs, MAX_SIGNS) or time.time() - t0 > 60 * a.minutes:
            break
        time.sleep(60)
    n = min(read_words(a.chip, s["SIGN_TIMING_SIGNS"], 1)[0], MAX_SIGNS)
    words = read_words(a.chip, s["SIGN_TIMING_REC"], n * REC_WORDS)
    errs = read_words(a.chip, s["SIGN_TIMING_RNG_ERRS"], 1)[0]
    recs = []
    for i in range(n):
        w = words[i * REC_WORDS:(i + 1) * REC_WORDS]
        b = b"".join(x.to_bytes(4, "little") for x in w[4:36])
        sk, pks, pkr, msg, opt, r_sig = b[:32], b[32:48], b[48:64], b[64:96], b[96:112], b[112:128]
        rt, r = r_grind_tries(sk, pks, pkr, msg, opt)
        recs.append(dict(cls=w[0], cyc=w[1], wc=[w[2], w[3]], r_tries=rt, r_ok=(r == r_sig),
                         sk=sk.hex()))
    bad_r = sum(not x["r_ok"] for x in recs)
    if sum(x["cls"] == 0 for x in recs) < 3 or sum(x["cls"] == 1 for x in recs) < 3:
        json.dump(dict(prim=prim, recs=recs), open(a.out, "w"), indent=1)
        print(f"{n} signs: too few per class for the sign analysis (phase 1 saved)")
        return
    cyc = [x["cyc"] for x in recs]
    rtr = [x["r_tries"] for x in recs]
    wtr = [x["wc"][0] + x["wc"][1] + 2 for x in recs]
    cls = [x["cls"] for x in recs]
    beta = lstsq([[1.0, r, w] for r, w in zip(rtr, wtr)], cyc)
    res = [c - (beta[0] + beta[1] * r + beta[2] * w) for c, r, w in zip(cyc, rtr, wtr)]
    def t_by_class(v):
        g0 = [x for x, c in zip(v, cls) if c == 0]
        g1 = [x for x, c in zip(v, cls) if c == 1]
        return len(g0), len(g1), welch(len(g0), sum(g0), sum(x * x for x in g0),
                                       len(g1), sum(g1), sum(x * x for x in g1))[4]
    n0, n1, t_raw = t_by_class(cyc)
    _, _, t_res = t_by_class(res)
    sd_res = math.sqrt(sum(x * x for x in res) / (len(res) - 3))
    summary = dict(signs=n, n_class=[n0, n1], rng_errs=errs, r_mismatch=bad_r,
                   beta=dict(base=beta[0], per_r_try=beta[1], per_wots_try=beta[2]),
                   corr_cycles_r_tries=corr(cyc, rtr), corr_cycles_wots_tries=corr(cyc, wtr),
                   residual_sd_cycles=sd_res, t_raw_by_key_class=t_raw, t_residual_by_key_class=t_res,
                   cycles_min=min(cyc), cycles_max=max(cyc), mean_s=sum(cyc) / len(cyc) / 160e6)
    print(json.dumps(summary, indent=1))
    json.dump(dict(prim=prim, summary=summary, recs=recs), open(a.out, "w"), indent=1)


if __name__ == "__main__":
    main()
