#!/usr/bin/env python3
"""Round 20 (2026-11-14): regenerate a kit golden from the Python reference and compare bytes.

A golden is pk_root (16) || sig(MSG0) || sig(MSG1), signed with OPT_RAND (`inputs.rs`; the shuffle seed
does not change the bytes). The kit benches compare their signatures to the golden byte for byte, so when
the golden equals the Python reference's output, the device path (the hw key loop, FORS subtree and
per-chain PRF) is tied to the position-bound reference at the golden's positions, not just to the host
Rust copy.

Usage: golden_python_check.py <variant,...|draft03> <golden.bin>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import c10v2_ref as r  # noqa: E402

SK_SEED = b"c10-autoresearch fixed sk_seed!!"
PK_SEED = b"c10-ar pk_seed!!"
OPT_RAND = b"c10-ar opt_rand!"
MSGS = (b"c10-autoresearch message zero..!", b"c10-autoresearch message one...!")


def main(variant, path):
    r.configure(() if variant == "draft03" else variant.split(","))
    g = open(path, "rb").read()
    root = r.keygen(SK_SEED, PK_SEED)
    want = root + b"".join(r.sign(SK_SEED, PK_SEED, root, m, OPT_RAND) for m in MSGS)
    same = want == g
    print(f"{os.path.basename(path)} ({r.variant_name()}): {len(g)} B, Python reference "
          f"{'IDENTICAL' if same else 'DIFFERS'}")
    return 0 if same else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
