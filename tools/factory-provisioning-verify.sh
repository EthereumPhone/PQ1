#!/usr/bin/env bash
#
# Host-side factory ceremony verifier.
#
# Reads the OTP factory sentinel at `0x0BFA_00A0` via probe-rs and
# interprets the result per the encoding in
# `secure/src/hw/otp.rs::FACTORY_SENTINEL_OFFSET`:
#
#   0xFFFFFFFF  — chip never started the ceremony
#   0xFFFFFFFE  — started, halted at failure panel (operator should
#                 read the OLED for the step + error code)
#   0xFFFFFFFC  — started + rehearsal completed (NOT RDP2-eligible)
#   0xFFFFFFFA  — started + production completed (RDP2-eligible)
#   0xFFFFFFF8  — started + both modes completed (RDP2-eligible)
#
# Usage:
#   tools/factory-provisioning-verify.sh                # report only
#   tools/factory-provisioning-verify.sh --bump-rdp2    # also bump
#                                                       # RDP=Level-2
#                                                       # if the
#                                                       # sentinel is
#                                                       # production-
#                                                       # complete.
#                                                       # IRREVERSIBLE.
#
# Exit codes:
#   0  — sentinel reads RDP2-eligible (production or both modes)
#   1  — sentinel reads not-yet-complete or rehearsal-only
#   2  — probe-rs read failed (chip not attached, RDP1+, etc.)
#   3  — unexpected sentinel value (high bits cleared — corrupted OTP)
#   4  — --bump-rdp2 was requested but sentinel is not RDP2-eligible
#
# This script does NOT flash any firmware. Use `make
# flash-hw-factory-provisioning` to flash, then this script to verify.

set -euo pipefail

CHIP="${CHIP:-STM32U585AIIx}"
OTP_SENTINEL_ADDR="${OTP_SENTINEL_ADDR:-0x0BFA00A0}"
POLL_TIMEOUT_SECS="${POLL_TIMEOUT_SECS:-60}"
POLL_INTERVAL_SECS="${POLL_INTERVAL_SECS:-2}"

BUMP_RDP2=0
if [[ "${1:-}" == "--bump-rdp2" ]]; then
    BUMP_RDP2=1
fi

read_sentinel() {
    # `probe-rs read 32 ADDR --num-words 1` returns:
    #   <ADDR>: <HEX_VALUE>
    # We parse out the hex value and normalize to 0x-prefixed
    # lowercase 8-digit form.
    local raw
    if ! raw="$(probe-rs read 32 "${OTP_SENTINEL_ADDR}" \
                   --chip "${CHIP}" --num-words 1 2>/dev/null)"; then
        return 1
    fi
    # Extract the value after the ":". probe-rs output formatting
    # varies between versions; this is loose on purpose.
    printf '0x%08x\n' "$(echo "${raw}" | awk -F: 'NR==1{print $NF}' | tr -d ' ')"
}

decode_sentinel() {
    local v="$1"
    case "${v}" in
        0xffffffff)
            echo "DID_NOT_START — chip never reached the ceremony entry point"
            return 1
            ;;
        0xfffffffe)
            echo "STARTED_FAILED — ceremony entered, halted at failure. Read OLED."
            return 1
            ;;
        0xfffffffc)
            echo "REHEARSAL_ONLY — rehearsal completed, NOT RDP2-eligible"
            return 1
            ;;
        0xfffffffa)
            echo "PRODUCTION_OK — production completed (RDP2-eligible)"
            return 0
            ;;
        0xfffffff8)
            echo "BOTH_OK — rehearsal + production both completed (RDP2-eligible)"
            return 0
            ;;
        *)
            echo "CORRUPT — unexpected high bits cleared (raw=${v})"
            return 3
            ;;
    esac
}

echo "==> Polling OTP sentinel at ${OTP_SENTINEL_ADDR} on ${CHIP}"
echo "    Timeout: ${POLL_TIMEOUT_SECS}s, interval: ${POLL_INTERVAL_SECS}s"

deadline=$(( $(date +%s) + POLL_TIMEOUT_SECS ))
last_value=""
stable_count=0

while [[ $(date +%s) -lt ${deadline} ]]; do
    if ! current="$(read_sentinel)"; then
        echo "    [t+0] probe-rs read failed — chip not attached? RDP1+?"
        exit 2
    fi

    elapsed=$(( ${POLL_TIMEOUT_SECS} - (deadline - $(date +%s)) ))
    echo "    [t+${elapsed}s] sentinel = ${current}"

    # If the sentinel has moved past 0xFFFFFFFF AND has any
    # completion bit (1 or 2) cleared, the ceremony is done. We
    # require the value to be stable across 2 successive reads to
    # be sure the chip isn't mid-write.
    case "${current}" in
        0xfffffffc|0xfffffffa|0xfffffff8)
            if [[ "${current}" == "${last_value}" ]]; then
                stable_count=$(( stable_count + 1 ))
                if [[ ${stable_count} -ge 1 ]]; then
                    echo "==> sentinel stable: ${current}"
                    break
                fi
            fi
            last_value="${current}"
            ;;
        *)
            last_value="${current}"
            stable_count=0
            ;;
    esac

    sleep "${POLL_INTERVAL_SECS}"
done

# Final read + decode.
if ! final="$(read_sentinel)"; then
    echo "ERROR: probe-rs read failed on final attempt"
    exit 2
fi

set +e
decoded="$(decode_sentinel "${final}")"
decode_exit=$?
set -e

echo "==> Final state: ${decoded}"

if [[ ${BUMP_RDP2} -eq 1 ]]; then
    if [[ ${decode_exit} -ne 0 ]]; then
        echo ""
        echo "REFUSING --bump-rdp2: sentinel is not RDP2-eligible."
        echo "Re-run the factory firmware (or inspect the failure on the OLED)"
        echo "and try again. The RDP2 bump is IRREVERSIBLE so we fail-closed here."
        exit 4
    fi
    echo ""
    echo "==> IRREVERSIBLE: bumping STM32 RDP option byte to Level 2..."
    echo "    After this completes, the chip will be PERMANENTLY"
    echo "    locked: no SWD, no semihosting, no probe-rs read/write."
    echo "    Only the OLED + USB enumeration will be observable."
    echo ""
    read -p "Type 'BUMP RDP2' to confirm: " confirmation
    if [[ "${confirmation}" != "BUMP RDP2" ]]; then
        echo "Aborted by user."
        exit 4
    fi
    STM32_Programmer_CLI --connect port=SWD \
        --optionbytes RDP=0xCC
    echo "==> RDP=Level 2 set. Power-cycle the device. Pack and ship."
fi

exit ${decode_exit}
