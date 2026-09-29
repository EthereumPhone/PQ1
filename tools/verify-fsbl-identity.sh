#!/usr/bin/env bash
# Check an FSBL ELF against a release bundle's vendor fingerprint, and print
# the FSBL's own measurement so it can be compared to a reproducible build.
#
# WHY THIS EXISTS (#742). The signed bundle does not contain or bind the FSBL:
# `signed_preimage(fw_version, secure_hash, nonsecure_hash)` has no FSBL field,
# and `fwsign sign --fsbl` reads the ELF only to check its retained vendor-key
# sections, then discards it. So "we flashed the signed bundle, therefore the
# FSBL is X" is unfounded. Demonstrated 2026-09-28: a freshly built FSBL booted
# and verified against an unchanged three-day-old bundle, 19/19 markers.
#
# Until WRP + RDP-2 close (invariant #10), FSBL identity rests on out-of-band
# measurement plus this vendor-key chain. Both were manual. This makes the
# second one a command instead of operator testimony.
#
# WHAT IT PROVES: the FSBL carries the same vendor public key the bundle was
# signed under.
#
# WHAT IT DOES NOT PROVE: that this is THE FSBL the release was built from. Two
# different FSBLs signed by the same vendor are indistinguishable here — which
# is exactly the gap #742 proposes closing with a release-side FSBL receipt.
# For that, compare the measurement printed below against a reproducible build
# of the published commit.
#
# Read-only: it reads files and hashes them. It never writes, flashes, or
# connects to a probe.
set -euo pipefail

FSBL=${1:?usage: $0 <fsbl.elf> <bundle-dir-or-measurement.txt>}
REF=${2:?usage: $0 <fsbl.elf> <bundle-dir-or-measurement.txt>}

OBJCOPY=${OBJCOPY:-arm-none-eabi-objcopy}
SECTION=.pqsigner.vendor_pubkey

[ -r "$FSBL" ] || { echo "FAIL: cannot read FSBL ELF: $FSBL" >&2; exit 2; }

# measurement.txt may be given directly or as the directory holding it.
if [ -d "$REF" ]; then MEAS="$REF/measurement.txt"; else MEAS="$REF"; fi
[ -r "$MEAS" ] || { echo "FAIL: cannot read measurement.txt: $MEAS" >&2; exit 2; }

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

"$OBJCOPY" -O binary --only-section="$SECTION" "$FSBL" "$tmp/key.bin" 2>/dev/null || true
if [ ! -s "$tmp/key.bin" ]; then
	echo "FAIL: $FSBL carries no '$SECTION' section." >&2
	echo "      Either it is not an FSBL image, or the key was not embedded." >&2
	exit 1
fi

key=$(sha256sum "$tmp/key.bin" | cut -d' ' -f1)
raw=$(xxd -p -c 64 "$tmp/key.bin")

want=$(grep -oE 'vendor fpr:[[:space:]]*[0-9a-f]{64}' "$MEAS" | grep -oE '[0-9a-f]{64}' || true)
if [ -z "$want" ]; then
	echo "FAIL: no 'vendor fpr:' line in $MEAS" >&2
	exit 1
fi

echo "FSBL                : $FSBL"
echo "  embedded key      : $raw"
echo "  sha256(key)       : $key"
echo "bundle measurement  : $MEAS"
echo "  vendor fpr        : $want"

if [ "$key" != "$want" ]; then
	echo
	echo "==> MISMATCH: this FSBL was built against a DIFFERENT vendor key than"
	echo "    the bundle was signed with. It will reject that bundle's manifest."
	exit 1
fi

echo
echo "==> vendor key MATCHES."
echo "    This proves shared vendor provenance ONLY. It does NOT identify which"
echo "    FSBL is installed — two FSBLs under the same key look identical here."
echo "    Compare the measurement below against a reproducible build:"
echo
if command -v cargo >/dev/null 2>&1; then
	cargo run --release -p fwmeasure --quiet -- "$FSBL" 2>/dev/null | head -12 | sed 's/^/    /'
else
	echo "    (cargo unavailable; run: cargo run -p fwmeasure -- $FSBL)"
fi
