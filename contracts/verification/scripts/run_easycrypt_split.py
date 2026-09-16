#!/usr/bin/env python3
"""Run the vendored split gate in its immutable tool image on a disposable copy."""
import json
from pathlib import Path
import re
import subprocess
import sys

root = Path(__file__).resolve().parents[1] / 'easycrypt/c10-port'
lock = json.loads((root / 'cert-toolchain-split.json').read_text())
image = lock['image']
if not re.fullmatch(r'ghcr.io/easycrypt/ec-test-box@sha256:[0-9a-f]{64}', image):
    sys.exit('FAIL: EasyCrypt image must be pinned by digest')
if sys.argv[1:] not in ([], ['--controls']):
    sys.exit('usage: run_easycrypt_split.py [--controls]')
command = ('python3 tools/split_contract.py --toolchain && python3 tools/split_proof_controls.py'
           if sys.argv[1:] else 'bash cert_gate_split.sh')
# No host toolchain, mutable tag, network, shared cache, or existing container.
# Docker verifies the content digest on acquisition; no receipt supplied by the
# caller can select another image. The child gate also checks observed identities.
subprocess.run(['docker', 'run', '--rm', '--init', '--network', 'none',
                '--env', f'PQ_EASYCRYPT_IMAGE={image}',
                '--volume', f'{root}:/source:ro', image, 'bash', '-lc',
                'set -e; eval "$(opam env)"; cp -R /source /tmp/proofs; '
                'cd /tmp/proofs; ' + command], check=True)
