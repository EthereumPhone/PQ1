#!/usr/bin/env bash
# release.sh — build and sign one DEV-UNIT firmware release (`devunit-ab`).
#
#   tools/devunit/release.sh                 # version = today's YY.MM.DD.N
#   tools/devunit/release.sh 26.10.21.3      # explicit version
#   PROFILE=bench tools/devunit/release.sh   # headless mock-SE test image
#   BUILD_ONLY=1 tools/devunit/release.sh 0.0.0.1   # compile + link only (CI; no key)
#
# Dev units only (pre-production DVTs handed to testers). Produces, under
# target/devunit/releases/<version>/:
#
#   pq1-devunit-<version>.pq1fw   the USB update package (both slot variants,
#                                 both signed) for tools/devunit/fwupdate.py
#                                 and tools/devunit/pq1-fwupdate.html
#   factory/                      first-flash images for a blank unit:
#                                 fsbl.bin, manifest-a.bin, secure-a.bin,
#                                 nonsecure-a.bin (tools/devunit/flash.sh)
#   bundle-a.pqfw, bundle-b.pqfw  the fwsign bundles (inspect/verify)
#   RELEASE.txt                   version, features, fingerprint words
#
# Every release is built twice — once linked for slot A, once for slot B —
# because the images are not position independent; the updater sends the
# variant for the slot the device is NOT running from. See
# fw-manifest/src/devunit.rs for the layout and the probation protocol.
#
# Signing key: DEVUNIT_KEY (default ~/Documents/PQ1/devunit-fw-key/devunit-fw.key),
# passphrase from DEVUNIT_PASSFILE (default passphrase.txt next to the key).
# The public half is committed as config/devunit-firmware-vendor-pubkey.bin.
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT=$PWD

PROFILE=${PROFILE:-investor}
case $PROFILE in
  investor)
    # The EVT/DVT dev image (real secure elements, pixel UI) plus the dev-unit
    # update layout — WITHOUT `dev-dfu`: behind the FSBL its both-buttons check
    # runs just as the PIN pad is about to appear, where a user pressing the
    # "enter" chord early would latch the unit into ROM DFU on every boot
    # (only CubeProgrammer gets it out). Signed USB updates replace it; add it
    # back with FEAT_S=... for bench units.
    FEAT_S=${FEAT_S:-dual-se,dev-testkey,ui-lcd,ui-px,ui-px-dma,unlock-diag,stm32u585,usb,board-pq1}
    FEAT_N=${FEAT_N:-stm32u585,usb,board-pq1,ui-px-atlas} ;;
  bench)
    # Headless bench image: mock secure elements (the real chips are never
    # touched), auto-unlock and auto-confirm (`e2e-test`), no display.
    FEAT_S=${FEAT_S:-mock-se,e2e-test,ui-noop,stm32u585,usb,board-pq1}
    FEAT_N=${FEAT_N:-stm32u585,usb,board-pq1} ;;
  *) echo "PROFILE must be investor or bench" >&2; exit 2 ;;
esac
FEAT_S="$FEAT_S,devunit-ab"
FEAT_N="$FEAT_N,devunit-ab"

KEY=${DEVUNIT_KEY:-$HOME/Documents/PQ1/devunit-fw-key/devunit-fw.key}
PASSFILE=${DEVUNIT_PASSFILE:-$(dirname "$KEY")/passphrase.txt}
PUBKEY=$ROOT/config/devunit-firmware-vendor-pubkey.bin
POLICY=$ROOT/config/devunit-firmware-vendor-key.sha256
T=thumbv8m.main-none-eabi
W=$ROOT/target/devunit/$PROFILE

# --- version: YY.MM.DD.N packed big-endian into the u32 fw_version ---------
version_u32() { IFS=. read -r a b c d <<<"$1"; echo $(( (a << 24) | (b << 16) | (c << 8) | d )); }
if [ $# -ge 1 ]; then
  VSTR=$1
else
  day=$(date +%y.%m.%d | sed 's/\b0\([0-9]\)/\1/g')
  n=1
  while [ -d "$ROOT/target/devunit/releases/$PROFILE-$day.$n" ]; do n=$((n + 1)); done
  VSTR="$day.$n"
fi
[[ $VSTR =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || { echo "version must be A.B.C.D" >&2; exit 2; }
for f in ${VSTR//./ }; do [ "$f" -le 255 ] || { echo "version fields must be <= 255" >&2; exit 2; }; done
V=$(version_u32 "$VSTR")
[ "$V" -ge 1 ] || { echo "version must be >= 0.0.0.1" >&2; exit 2; }
OUT=$ROOT/target/devunit/releases/$PROFILE-$VSTR
BUILD_ONLY=${BUILD_ONLY:-0}
[ "$(sha256sum "$PUBKEY" | cut -d' ' -f1)" = "$(cat "$POLICY")" ] || { echo "pubkey/policy mismatch" >&2; exit 2; }
if [ "$BUILD_ONLY" != 1 ]; then
  [ ! -e "$OUT" ] || { echo "$OUT exists — pick a new version" >&2; exit 2; }
  [ -f "$KEY" ] || { echo "signing key $KEY not found" >&2; exit 2; }
  [ -f "$PASSFILE" ] || { echo "passphrase file $PASSFILE not found" >&2; exit 2; }
fi

echo "==> dev-unit release $VSTR (fw_version $V = 0x$(printf %08x "$V")), profile $PROFILE"
echo "    secure:     $FEAT_S"
echo "    non-secure: $FEAT_N"

export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
REPRO="--remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=$HOME/.rustup=/rustup --remap-path-prefix=/nix/store=/nix-store --remap-path-prefix=$ROOT=/pqsigner -C link-arg=--build-id=none"
mkdir -p "$W"

echo "==> FSBL"
FSBL_VENDOR_PUBKEY=$PUBKEY CARGO_TARGET_THUMBV8M_MAIN_NONE_EABI_RUSTFLAGS="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x $REPRO" \
  cargo build --locked --release --target $T --target-dir "$W/fsbl" \
    -p pqsigner-fsbl --features legacy-fw-rollback-unsafe,board-pq1,devunit-ab 2>&1 \
  | grep -E '^(error|warning: unused)|^ *--> fsbl' || true
FSBL_ELF=$W/fsbl/$T/release/pqsigner-fsbl
[ -f "$FSBL_ELF" ] || { echo "FSBL build failed" >&2; exit 1; }
python3 scripts/check_fsbl_geometry.py "$FSBL_ELF" --linker fsbl/memory-stm32u585.x | tail -1

for slot in a b; do
  echo "==> secure, slot $slot"
  # The secure link writes this slot's CMSE import library; an up-to-date
  # build does not relink, and then the library from the last link stands.
  VEN=$W/veneers-$slot.o
  if [ ! -f "$VEN" ]; then
    rm -f "$W/secure-$slot/$T/release/sphincs-tz-secure" "$W/secure-$slot/$T/release/deps/sphincs_tz_secure-"*
  fi
  PQSIGNER_SECURE_SLOT=$slot FSBL_VENDOR_PUBKEY=$PUBKEY \
  CARGO_TARGET_THUMBV8M_MAIN_NONE_EABI_RUSTFLAGS="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x $REPRO -C link-arg=--cmse-implib -C link-arg=--out-implib=$VEN" \
    cargo build --locked --release --target $T --target-dir "$W/secure-$slot" \
      -p sphincs-tz-secure --no-default-features --features "$FEAT_S" > "$W/secure-$slot.log" 2>&1 \
    || { grep -n -A12 '^error' "$W/secure-$slot.log" | head -60; exit 1; }
  [ -f "$VEN" ] || { echo "no veneer import library for slot $slot" >&2; exit 1; }
  echo "==> non-secure, slot $slot"
  # The veneer library is a link input cargo does not track: force a relink.
  rm -f "$W/ns-$slot/$T/release/sphincs-tz-nonsecure" "$W/ns-$slot/$T/release/deps/sphincs_tz_nonsecure-"*
  PQSIGNER_NS_SLOT=$slot PQSIGNER_DEVUNIT_FW_VERSION=$V \
  CARGO_TARGET_THUMBV8M_MAIN_NONE_EABI_RUSTFLAGS="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x $REPRO -C link-arg=$VEN" \
    cargo build --locked --release --target $T --target-dir "$W/ns-$slot" \
      -p sphincs-tz-nonsecure --features "$FEAT_N" > "$W/ns-$slot.log" 2>&1 \
    || { grep -n -A12 '^error' "$W/ns-$slot.log" | head -60; exit 1; }
done

if [ "$BUILD_ONLY" = 1 ]; then
  for slot in a b; do
    arm-none-eabi-readelf -l "$W/secure-$slot/$T/release/sphincs-tz-secure" | grep -E 'Entry'
    arm-none-eabi-readelf -l "$W/ns-$slot/$T/release/sphincs-tz-nonsecure" | grep -E 'Entry'
  done
  echo "==> BUILD_ONLY: both slots built and linked (not signed, nothing packaged)"
  exit 0
fi

mkdir -p "$OUT/factory"
cargo build --locked --release -q -p fwsign
FWSIGN=$ROOT/target/release/fwsign
GIT=$(git rev-parse HEAD)
DIRTY=$(git diff --quiet HEAD -- . ':!target' 2>/dev/null && echo "" || echo "-dirty")
for slot in a b; do
  sid=$([ $slot = a ] && echo 0 || echo 1)
  echo "==> signing slot $slot"
  bid=$(printf 'pq1-devunit %s %s%s slot %s %s' "$VSTR" "$GIT" "$DIRTY" "$slot" "$PROFILE" | sha256sum | cut -d' ' -f1)
  # fwsign reads the passphrase from the terminal; give it a pty.
  script -qec "$FWSIGN sign --legacy-bench-unsafe --devunit-ab --key $KEY --fsbl $FSBL_ELF \
      --trusted-fingerprint $POLICY --version $V --slot $sid --build-id $bid \
      --secure $W/secure-$slot/$T/release/sphincs-tz-secure \
      --nonsecure $W/ns-$slot/$T/release/sphincs-tz-nonsecure \
      --out $OUT/bundle-$slot.pqfw" /dev/null < "$PASSFILE" > "$W/sign-$slot.log" 2>&1 \
    || { tail -20 "$W/sign-$slot.log"; exit 1; }
  [ -f "$OUT/bundle-$slot.pqfw" ] || { tail -20 "$W/sign-$slot.log"; exit 1; }
  mkdir -p "$OUT/unpacked-$slot"
  tar -xf "$OUT/bundle-$slot.pqfw" -C "$OUT/unpacked-$slot"
  "$FWSIGN" verify --devunit-ab --bundle "$OUT/bundle-$slot.pqfw" --pubkey "$PUBKEY" > "$W/verify-$slot.log" 2>&1 \
    || { cat "$W/verify-$slot.log"; exit 1; }
done

arm-none-eabi-objcopy -O binary "$FSBL_ELF" "$OUT/factory/fsbl.bin"
cp "$OUT/unpacked-a/manifest.bin" "$OUT/factory/manifest-a.bin"
cp "$OUT/unpacked-a/secure.bin" "$OUT/factory/secure-a.bin"
cp "$OUT/unpacked-a/nonsecure.bin" "$OUT/factory/nonsecure-a.bin"

python3 -I tools/devunit/pq1fw.py pack --out "$OUT/pq1-devunit-$VSTR.pq1fw" \
  --version "$V" --label "$VSTR" --profile "$PROFILE" --git "$GIT$DIRTY" \
  --features "$FEAT_S" --pubkey "$PUBKEY" \
  --slot-a "$OUT/unpacked-a" --slot-b "$OUT/unpacked-b"

{
  echo "PQ1 dev-unit firmware $VSTR ($PROFILE)"
  echo "fw_version: $V (0x$(printf %08x "$V"))"
  echo "git:        $GIT$DIRTY"
  echo "secure:     $FEAT_S"
  echo "non-secure: $FEAT_N"
  echo "signing key fingerprint: $(cat "$POLICY")"
  echo
  echo "The device shows these 8 words at boot (slot it boots from):"
  for slot in a b; do
    echo
    echo "--- slot ${slot^^} build ---"
    sed -n '/Secure image measurement/,/SHA-256/p' "$OUT/unpacked-$slot/measurement.txt"
  done
} > "$OUT/RELEASE.txt"
python3 -I tools/devunit/pq1fw.py inspect "$OUT/pq1-devunit-$VSTR.pq1fw"
echo "==> done: $OUT"
