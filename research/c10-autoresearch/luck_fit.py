#!/usr/bin/env python3
"""luck_fit.py — split a 16-message kit mean into deterministic work and grind luck
(format-options check, 2026-11-13).

A variant that changes keys (prf2, split810) also changes every message's R-grind
nonce and WOTS counts, so its mean sign differs from the baseline's by grind luck
as well as by the change itself. For each configuration this fits, over its 16
messages,

    cycles_i = det + c_w * wots_tries_i + c_r * r_tries_i

with wots_tries = count0 + count1 + 2 and r_tries = nonce + 1 taken exactly from
the host mirror (`c10-ar-host luck16`, same messages, same keys), and per-message
kit cycles from `experiment_avg.sh` (its `per_sign`). `det` is the luck-free
per-sign cost; `det + c_w * E[tries] + c_r * E[nonces]` is the expected mean.

Usage: luck_fit.py LABEL AVG_JSON_LINE_FILE LINE_INDEX LUCK_FILE TARGET_SUM [...repeat 5]
"""
import json
import re
import sys

import numpy as np

W_TRIES = {205: 2 * 30698.4, 200: 2 * 9192.0}   # exact E[tries per sign] (format_options_numerics.py)
R_TRIES = 2048.0                                 # E[nonces + 1] for a 2^-11 event


def load_avg(path, idx):
    rows = [json.loads(l) for l in open(path) if l.startswith("{")]
    return rows[idx]


def load_luck(path):
    out = []
    for l in open(path):
        m = re.match(r"LUCK (\d+) nonce=(\d+) count0=(\d+) count1=(\d+)", l)
        if m:
            i, n, c0, c1 = map(int, m.groups())
            out.append((n + 1, c0 + c1 + 2))
    assert len(out) == 16
    return out


def main(a):
    res = {}
    while a:
        label, f, idx, lf, ts = a[0], a[1], int(a[2]), a[3], int(a[4])
        a = a[5:]
        r = load_avg(f, idx)
        y = np.array(r["per_sign"], dtype=float)
        lk = load_luck(lf)
        X = np.array([[1.0, w, n] for n, w in lk])
        coef, *_ = np.linalg.lstsq(X, y, rcond=None)
        det, cw, cr = coef
        resid = y - X @ coef
        expect = det + cw * W_TRIES[ts] + cr * R_TRIES
        res[label] = dict(det=det, cw=cw, cr=cr, expect=expect, mean=y.mean())
        print(f"{label:22s} mean {y.mean()/1e6:7.3f} M | det {det/1e6:7.3f} M  c_w {cw:6.1f} cyc/try  "
              f"c_r {cr:6.1f} cyc/nonce  resid sd {resid.std()/1e3:6.1f} k | luck-free expected mean {expect/1e6:7.3f} M "
              f"(this run's tries {sum(w for _, w in lk)/16:8.0f}/sign vs E {W_TRIES[ts]:.0f})")
    return res


if __name__ == "__main__":
    main(sys.argv[1:])
