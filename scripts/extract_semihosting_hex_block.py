#!/usr/bin/env python3
"""Extract a hex block printed over semihosting into a binary file (#896).

`nonsecure/src/nested_gate_test.rs` prints the unified-sign response it got
back under the nested call between `--RESP-BEGIN--` and `--RESP-END--`, 64
bytes per line. The `nested-gate-test*-hw` recipes use this to rebuild the
response so `tools/verify-c10-sig` can check the signature offline.

Lines may carry a prefix from the host tool, so each line between the
markers contributes its last whitespace-separated token, which must be
even-length lowercase hex. Anything else between the markers is an error.

Exit status: 0 = written and the response's off-chain count (first 8 bytes,
big-endian) is 0; 3 = written but the count is non-zero (the verifier
assumes 0, so the caller should skip it); 1 = no block or a malformed one.

`make e2e` reuses it with custom markers (`--ROT-RESP-BEGIN--` /
`--ROT-RESP-END--`) for the #353 slot-rotation response.

Usage: extract_semihosting_hex_block.py <log> <out.bin> [BEGIN END]
"""

import re
import sys

BEGIN, END = "--RESP-BEGIN--", "--RESP-END--"
HEX = re.compile(r"^(?:[0-9a-f]{2})+$")


def main():
    global BEGIN, END
    if len(sys.argv) not in (3, 5):
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 1
    log, out = sys.argv[1], sys.argv[2]
    if len(sys.argv) == 5:
        BEGIN, END = sys.argv[3], sys.argv[4]
    lines = open(log, encoding="utf-8", errors="replace").read().splitlines()
    starts = [i for i, l in enumerate(lines) if BEGIN in l]
    ends = [i for i, l in enumerate(lines) if END in l]
    if len(starts) != 1 or len(ends) != 1 or ends[0] <= starts[0]:
        print(f"ERROR: expected exactly one {BEGIN}..{END} block, "
              f"found {len(starts)} begin / {len(ends)} end markers")
        return 1
    data = bytearray()
    for n, line in enumerate(lines[starts[0] + 1:ends[0]], start=starts[0] + 2):
        tokens = line.split()
        if not tokens or not HEX.match(tokens[-1]):
            print(f"ERROR: line {n} between the markers is not a hex row: {line!r}")
            return 1
        data += bytes.fromhex(tokens[-1])
    if len(data) < 8:
        print(f"ERROR: block holds only {len(data)} bytes")
        return 1
    with open(out, "wb") as f:
        f.write(data)
    count = int.from_bytes(data[:8], "big")
    print(f"  extracted {len(data)} bytes to {out}; offchain_count={count}")
    return 0 if count == 0 else 3


if __name__ == "__main__":
    sys.exit(main())
