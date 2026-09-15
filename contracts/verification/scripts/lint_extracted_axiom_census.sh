#!/usr/bin/env bash
# Exact source + elaborated declaration inventory; closure checks remain separate.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec /usr/bin/python3 -E -S "$SCRIPT_DIR/check_axiom_inventory.py" extracted
