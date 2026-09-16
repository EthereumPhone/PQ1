#!/usr/bin/env bash
# Shared exact-config / process-result gate (issues #668, F2/F5).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec /usr/bin/python3 -I "$HERE/check_tlc.py" page123
