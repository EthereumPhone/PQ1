#!/usr/bin/env bash
#
# Deploy the production contract set (SPHINCsC10Asm verifier, PQSmartWallet
# implementation, PQSmartWalletFactory) through Arachnid's CREATE2 deployer,
# signing with a `cast wallet` keystore account (default "mhaas").
#
#   ./deploy.sh status                       which chains already have the set
#   ./deploy.sh <chain> [-- <forge args>]    simulate, confirm, broadcast, check
#   ./deploy.sh verify <chain>               source-verify on Etherscan/Basescan
#
#   <chain> = base-sepolia | base | eth-mainnet
#
# The keystore password is asked for once and kept in a private temp file
# (deleted on exit) for the duration of the run. The deploy itself is
# `script/DeployImplAndFactory*.s.sol` → `script/ProductionDeploy.sol`, which
# refuses to broadcast unless the predicted factory and proxy init-code hash
# equal the firmware constants, skips any contract already at its address
# (so an interrupted run can simply be run again), and checks the wiring
# afterwards.
#
# Environment:
#   ACCOUNT            cast wallet account          (default: mhaas)
#   RPC_URL            override the chain's RPC     (default: public RPC)
#   ETHERSCAN_API_KEY  Etherscan v2 key; when set, the deploy verifies the
#                      sources right after broadcasting
#
# Extra forge flags go after `--`, e.g. a gas price cap on Ethereum:
#   ./deploy.sh eth-mainnet -- --with-gas-price 2gwei --priority-gas-price 0.1gwei

set -euo pipefail
cd "$(dirname "$0")"

export FOUNDRY_PROFILE=deploy
ACCOUNT="${ACCOUNT:-mhaas}"
ENTRY_POINT_V06="0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"

die() { echo "error: $*" >&2; exit 1; }

chain_config() {
    case "$1" in
        base-sepolia)
            CHAIN_ID=84532; NAME="Base Sepolia"; SOL=DeployImplAndFactoryBaseSepolia
            DEFAULT_RPC="https://sepolia.base.org"; EXPLORER="https://sepolia.basescan.org" ;;
        base)
            CHAIN_ID=8453; NAME="Base Mainnet"; SOL=DeployImplAndFactoryBaseMainnet
            DEFAULT_RPC="https://mainnet.base.org"; EXPLORER="https://basescan.org" ;;
        eth-mainnet)
            CHAIN_ID=1; NAME="Ethereum Mainnet"; SOL=DeployImplAndFactoryEthMainnet
            DEFAULT_RPC="https://ethereum-rpc.publicnode.com"; EXPLORER="https://etherscan.io" ;;
        *) die "unknown chain '$1' (base-sepolia | base | eth-mainnet)" ;;
    esac
}

# The addresses the firmware expects, computed from the sources under the
# deploy profile. Refuses if they don't match the firmware constants.
predict() {
    local out
    out="$(forge script script/PrintProductionAddresses.s.sol 2>&1)" || { echo "$out"; die "address prediction failed"; }
    grep -q "matches firmware constants.*: true" <<<"$out" \
        || { echo "$out"; die "this checkout does not build the addresses the firmware expects"; }
    VERIFIER="$(awk '/SPHINCsC10Asm verifier/ {print $NF}' <<<"$out")"
    IMPL="$(awk '/PQSmartWallet impl/ {print $NF}' <<<"$out")"
    FACTORY="$(awk '/PQSmartWalletFactory/ {print $NF}' <<<"$out")"
    [[ -n "$VERIFIER" && -n "$IMPL" && -n "$FACTORY" ]] || { echo "$out"; die "could not read predicted addresses"; }
}

# "deployed" / "missing" for each of the three addresses on $RPC.
show_status() {
    local name addr size
    for name in VERIFIER IMPL FACTORY; do
        addr="${!name}"
        size="$(cast codesize "$addr" --rpc-url "$RPC")"
        if [[ "$size" -gt 0 ]]; then
            printf '  %-9s %s  deployed (%s bytes)\n' "$name" "$addr" "$size"
        else
            printf '  %-9s %s  missing\n' "$name" "$addr"
        fi
    done
}

all_deployed() {
    [[ "$(cast codesize "$VERIFIER" --rpc-url "$RPC")" -gt 0 \
        && "$(cast codesize "$IMPL" --rpc-url "$RPC")" -gt 0 \
        && "$(cast codesize "$FACTORY" --rpc-url "$RPC")" -gt 0 ]]
}

check_rpc() {
    local got
    got="$(cast chain-id --rpc-url "$RPC")" || die "RPC $RPC is not reachable"
    [[ "$got" == "$CHAIN_ID" ]] || die "RPC $RPC is chain $got, expected $CHAIN_ID ($NAME)"
}

verify_sources() {
    [[ -n "${ETHERSCAN_API_KEY:-}" ]] || die "set ETHERSCAN_API_KEY (an Etherscan v2 key works for every chain)"
    local common=(--chain "$CHAIN_ID" --verifier etherscan --etherscan-api-version v2
                  --etherscan-api-key "$ETHERSCAN_API_KEY" --compiler-version 0.8.28 --watch)
    echo "=== Verifying sources on $EXPLORER ==="
    forge verify-contract "$VERIFIER" src/verifiers/SPHINCsC10Asm.sol:SPHINCsC10Asm "${common[@]}"
    forge verify-contract "$IMPL" src/PQSmartWallet.sol:PQSmartWallet "${common[@]}" \
        --constructor-args "$(cast abi-encode 'f(address,address)' "$ENTRY_POINT_V06" "$VERIFIER")"
    forge verify-contract "$FACTORY" src/PQSmartWalletFactory.sol:PQSmartWalletFactory "${common[@]}" \
        --constructor-args "$(cast abi-encode 'f(address,address)' "$IMPL" "$VERIFIER")"
}

# Transactions of the last broadcast, from forge's run log.
print_broadcast_log() {
    local log="broadcast/$SOL.s.sol/$CHAIN_ID/run-latest.json"
    [[ -f "$log" ]] || return 0
    echo "=== Transactions ($log) ==="
    python3 - "$log" "$EXPLORER" <<'PY'
import json, sys
log, explorer = sys.argv[1], sys.argv[2]
d = json.load(open(log))
for r in d.get("receipts", []):
    block = int(r["blockNumber"], 16)
    status = "ok" if r.get("status") in ("0x1", 1) else "FAILED"
    print(f"  block {block}  {status}  {explorer}/tx/{r['transactionHash']}")
PY
}

cmd_status() {
    predict
    echo "Firmware contract set: verifier $VERIFIER, impl $IMPL, factory $FACTORY"
    local c
    for c in base-sepolia base eth-mainnet; do
        chain_config "$c"; RPC="$DEFAULT_RPC"
        echo
        echo "$NAME ($CHAIN_ID), $RPC"
        check_rpc
        show_status
    done
}

cmd_verify() {
    chain_config "$1"; RPC="${RPC_URL:-$DEFAULT_RPC}"
    check_rpc
    predict
    all_deployed || { show_status; die "the set is not fully deployed on $NAME"; }
    verify_sources
}

cmd_deploy() {
    chain_config "$1"; shift
    RPC="${RPC_URL:-$DEFAULT_RPC}"
    local extra=()
    if [[ "${1:-}" == "--" ]]; then shift; extra=("$@"); fi

    echo "=== $NAME (chain $CHAIN_ID) ==="
    echo "RPC:      $RPC"
    check_rpc
    echo "Building and checking the addresses against the firmware constants..."
    predict
    show_status
    if all_deployed; then
        echo "All three contracts are already deployed on $NAME. Nothing to do."
        return 0
    fi
    echo

    # Password once, kept in a user-only temp file until the script exits.
    local pwdir
    pwdir="$(umask 077; mktemp -d "${XDG_RUNTIME_DIR:-/tmp}/pq1-deploy.XXXXXX")"
    trap "rm -rf '$pwdir'" EXIT
    local pw
    read -r -s -p "Keystore password for '$ACCOUNT': " pw; echo
    (umask 077; printf '%s' "$pw" > "$pwdir/pw")
    unset pw
    local wallet=(--account "$ACCOUNT" --password-file "$pwdir/pw")

    local deployer
    deployer="$(cast wallet address "${wallet[@]}")" || die "could not unlock '$ACCOUNT' (wrong password?)"
    echo "Deployer: $deployer"
    echo "Balance:  $(cast balance --ether "$deployer" --rpc-url "$RPC") ETH"
    if [[ "$(cast codesize "$deployer" --rpc-url "$RPC")" -gt 0 ]]; then
        echo "          (EIP-7702-delegated account; transactions are sent one at a time)"
    fi
    echo

    echo "=== Simulation (nothing is sent) ==="
    forge script "script/$SOL.s.sol" --rpc-url "$RPC" "${wallet[@]}" "${extra[@]}"
    echo

    local answer
    if [[ "$CHAIN_ID" == 84532 ]]; then
        read -r -p "Broadcast to $NAME? [y/N] " answer
        [[ "$answer" == [yY] ]] || { echo "Aborted."; return 1; }
    else
        read -r -p "This spends real ETH on $NAME. Type '$CHAIN_ARG' to broadcast: " answer
        [[ "$answer" == "$CHAIN_ARG" ]] || { echo "Aborted."; return 1; }
    fi
    echo

    echo "=== Broadcast ==="
    # --slow waits for each receipt before sending the next transaction;
    # Base rejects gapped nonces from an EIP-7702-delegated sender.
    forge script "script/$SOL.s.sol" --rpc-url "$RPC" "${wallet[@]}" --broadcast --slow "${extra[@]}"
    echo

    print_broadcast_log
    echo
    echo "=== On-chain state ==="
    show_status
    all_deployed || die "not all contracts are deployed; run './deploy.sh $CHAIN_ARG' again to finish"
    echo
    echo "Factory: $EXPLORER/address/$FACTORY"

    if [[ -n "${ETHERSCAN_API_KEY:-}" ]]; then
        echo
        verify_sources || echo "Verification failed; retry with: ./deploy.sh verify $CHAIN_ARG"
    else
        echo "Source verification skipped (no ETHERSCAN_API_KEY). Later:"
        echo "  ETHERSCAN_API_KEY=... ./deploy.sh verify $CHAIN_ARG"
    fi
    echo
    echo "Next: update deployments/$( [[ $CHAIN_ARG == base ]] && echo base-mainnet || echo "$CHAIN_ARG" ).json and the deployment issue (#1010 Base, #1011 others)."
}

case "${1:-}" in
    status) cmd_status ;;
    verify) [[ -n "${2:-}" ]] || die "usage: ./deploy.sh verify <chain>"; CHAIN_ARG="$2"; cmd_verify "$2" ;;
    base-sepolia|base|eth-mainnet) CHAIN_ARG="$1"; cmd_deploy "$@" ;;
    *) sed -n '3,10p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
