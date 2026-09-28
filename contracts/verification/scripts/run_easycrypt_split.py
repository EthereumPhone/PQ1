#!/usr/bin/env python3
"""Run the vendored split gate in its immutable tool image on a disposable copy."""
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1] / 'easycrypt/c10-port'
lock = json.loads((root / 'cert-toolchain-split.json').read_text())
image = lock['image']
if not re.fullmatch(r'ghcr.io/easycrypt/ec-test-box@sha256:[0-9a-f]{64}', image):
    sys.exit('FAIL: EasyCrypt image must be pinned by digest')
if sys.argv[1:] not in ([], ['--controls']):
    sys.exit('usage: run_easycrypt_split.py [--controls]')
subprocess.run([sys.executable, '-B', str(root / 'tools/check_source_binding.py')], check=True)
if not sys.argv[1:]:
    subprocess.run(['cargo', 'test', '--locked', '-p', 'sphincs-c10',
                    '--target', 'x86_64-unknown-linux-gnu', '--features', 'sim-internals',
                    '--test', 'easycrypt_transcript'], cwd=root.parents[3], check=True)
    with tempfile.TemporaryDirectory(prefix='pq-easycrypt-fullsign-') as temporary:
        output = Path(temporary) / 'evidence'
        subprocess.run([sys.executable, '-I', str(root / 'tools/fullsign_model/check.py'),
                        '--out', str(output)], check=True)
        print('FULLSIGN_MODEL_RECEIPT=' + (output / 'result.json').read_text(), flush=True)
command = ('python3 tools/split_contract.py --toolchain && python3 tools/split_proof_controls.py'
           if sys.argv[1:] else 'bash cert_gate_split.sh')
# EasyCrypt uses no host compiler, mutable tag, network, shared cache, or
# existing container. The Rust host test above is separate correspondence evidence.
# Docker verifies the content digest on acquisition; no receipt supplied by the
# caller can select another image. The child gate also checks observed identities.
subprocess.run(['docker', 'run', '--rm', '--init', '--network', 'none',
                '--env', f'PQ_EASYCRYPT_IMAGE={image}',
                '--volume', f'{root}:/source:ro', image, 'bash', '-lc',
                'set -e; eval "$(opam env)"; cp -R /source /tmp/proofs; '
                'cd /tmp/proofs; ' + command], check=True)
