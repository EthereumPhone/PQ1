#!/usr/bin/env bash
# forge_check.sh — round 20 (+ round 21: NoPrf2All3.t.sol, the no-prf2 candidate): the UNCHANGED SPHINCsC10v2All3Asm.sol (and, as a negative control, SPHINCsC10v2Asm.sol)
# against the full stack's KATs, in a minimal forge project under target/forge-r20 (gitignored). The verifier files
# are copied byte-for-byte from contracts/smart-wallet/src/verifiers and their hashes are compared first.
set -euo pipefail
D="$(cd "$(dirname "$0")/.." && pwd)"; R="$(cd "$D/../.." && pwd)"; SW="$R/contracts/smart-wallet"; F="$D/target/forge-r20"
rm -rf "$F"; mkdir -p "$F/src/verifiers" "$F/test"
for v in ISPHINCSVerifier SPHINCsC10v2All3Asm SPHINCsC10v2Asm SPHINCsC10v2Split810Asm SPHINCsC10v2Ts200Asm; do cp "$SW/src/verifiers/$v.sol" "$F/src/verifiers/"; cmp "$SW/src/verifiers/$v.sol" "$F/src/verifiers/$v.sol"; done
cp "$SW/test/c10v2_kat_vectors_all3-wprf2b.json" "$SW/test/c10v2_kat_vectors_all3.json" "$F/test/"
# round 21: the no-prf2 candidate, and the refusing verifiers' own formats (positive controls)
cp "$SW/test/c10v2_kat_vectors_ts200-split810-wprf2b.json" "$SW/test/c10v2_kat_vectors.json" \
   "$SW/test/c10v2_kat_vectors_split810.json" "$SW/test/c10v2_kat_vectors_ts200.json" "$F/test/"
ln -s "$SW/lib" "$F/lib"
cat > "$F/foundry.toml" <<'T'
[profile.default]
src = "src"
out = "out"
libs = ["lib"]
test = "test"
solc_version = "0.8.28"
evm_version = "prague"
via_ir = true
optimizer = true
optimizer_runs = 200
bytecode_hash = "none"
gas_limit = "18446744073709551615"
block_gas_limit = "18446744073709551615"
fs_permissions = [{ access = "read", path = "test/" }]
T
echo 'forge-std/=lib/forge-std/src/' > "$F/remappings.txt"
cp "$D/proto_full/FullStackAll3.t.sol" "$D/proto_full/NoPrf2All3.t.sol" "$F/test/"
( cd "$F" && forge test --offline -vv 2>&1 | tail -25 )
