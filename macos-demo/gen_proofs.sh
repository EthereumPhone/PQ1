#!/usr/bin/env bash
# Print the ERC-20 proofs (android-demo/app/src/main/assets/erc20) as the C table pq1-demo.c includes.
set -euo pipefail
cd "$(dirname "$0")"
echo "/* Generated from android-demo/app/src/main/assets/erc20. Do not edit. */"
rows=()
for f in ../android-demo/app/src/main/assets/erc20/*.bin; do
  name=$(basename "$f" .bin) # <chain>_<token>
  echo "static const unsigned char proof_$name[] = {"
  xxd -i <"$f"
  echo "};"
  rows+=("{ ${name%%_*}, \"${name#*_}\", proof_$name, sizeof proof_$name },")
done
echo "static const struct proof PROOFS[] = {"
printf '    %s\n' "${rows[@]}"
echo "};"
