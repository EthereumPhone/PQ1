#!/usr/bin/env bash
#
# Deterministic CREATE2 deploy of PQSmartWallet impl + factory on Base Mainnet,
# using the existing on-chain SPHINCsC10Asm verifier. Signs with the local
# cast-wallet keystore "mhaas" (will prompt for its password).
#
# Bytecode is byte-identical across chains under FOUNDRY_PROFILE=deploy, so
# the predicted addresses here are the same addresses the wallet will land at
# on any other EVM chain with the same (Arachnid factory, salt, initcode).

set -euo pipefail

cd "$(dirname "$0")"

RPC="${RPC_URL:-https://mainnet.base.org}"
ACCOUNT="${ACCOUNT:-mhaas}"
SCRIPT_SOL="script/DeployImplAndFactoryBaseMainnet.s.sol"
ENTRYPOINT="0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"
ARACHNID="0x4e59b44847b379578588920cA78FbF26c0B4956C"

export FOUNDRY_PROFILE=deploy

# ── v0.6 legacy-interface shim ────────────────────────────────────────────
# The PQSmartWallet source imports `account-abstraction/legacy/v06/*`, but
# `lib/account-abstraction` is pinned at v0.7.0 which pre-dates that folder.
# The interfaces were introduced in v0.8.0 and were pulled in locally from
# the v0.9.0 tag (which this submodule has fetched). They are placed at the
# canonical submodule path so solc metadata (and therefore CREATE2 addresses)
# match what the firmware + companion bake in.
V06_DIR="lib/account-abstraction/contracts/legacy/v06"
V06_FILES=(IAccount06.sol IAggregator06.sol IEntryPoint06.sol INonceManager06.sol IPaymaster06.sol IStakeManager06.sol UserOperation06.sol)
need_shim=0
for f in "${V06_FILES[@]}"; do [[ -f "$V06_DIR/$f" ]] || need_shim=1; done
if (( need_shim )); then
  echo "=== Re-materializing v0.6 legacy shim from account-abstraction v0.9.0 ==="
  mkdir -p "$V06_DIR"
  ( cd lib/account-abstraction && for f in "${V06_FILES[@]}"; do
      git show v0.9.0:contracts/legacy/v06/$f > "contracts/legacy/v06/$f"
    done )
  echo "shim restored at $V06_DIR"
  echo
fi

echo "=== Pre-flight ==="
echo "RPC:        $RPC"
echo "Account:    $ACCOUNT (cast wallet, keystore)"
echo "Script:     $SCRIPT_SOL"
echo

echo "EntryPoint v0.6  $ENTRYPOINT  code-len=$(cast code "$ENTRYPOINT"  --rpc-url "$RPC" | wc -c)"
echo "Arachnid CREATE2 $ARACHNID   code-len=$(cast code "$ARACHNID"   --rpc-url "$RPC" | wc -c)"
echo

echo "=== Build (deploy profile) ==="
forge build
echo

echo "=== Simulate (no broadcast, no signer) ==="
forge script "$SCRIPT_SOL" --rpc-url "$RPC"
echo

read -r -p "Broadcast with cast wallet '$ACCOUNT'? [y/N] " yn
case "$yn" in
  [Yy]*) ;;
  *) echo "aborted."; exit 0 ;;
esac

echo
echo "=== Broadcast (will prompt for '$ACCOUNT' keystore password) ==="
forge script "$SCRIPT_SOL" \
  --rpc-url "$RPC" \
  --account "$ACCOUNT" \
  --broadcast \
  --slow

echo
echo "=== Post-deploy on-chain check ==="
BCAST="broadcast/DeployImplAndFactoryBaseMainnet.s.sol/8453/run-latest.json"
if [[ -f "$BCAST" ]]; then
  python3 - "$BCAST" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
for tx in d.get("transactions", []):
    print(f"  {tx.get('transactionType'):<8} {tx.get('contractName'):<22} {tx.get('contractAddress')}")
PY
else
  echo "  (no broadcast artifact found at $BCAST)"
fi

echo
echo "Done. If impl/factory addresses differ from deployments/base-mainnet.json,"
echo "update that file and also update:"
echo "  - src-tauri/resources/chains.json  (factory)"
echo "  - src-tauri/crates/pq1-chain/src/config.rs:182  (hardcoded factory)"
echo "in ../../../pq1-companion."
