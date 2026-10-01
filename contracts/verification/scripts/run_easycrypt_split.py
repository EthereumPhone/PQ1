#!/usr/bin/env python3
"""Run the vendored split gate in its immutable tool image on a disposable copy."""
import fcntl
import json
import os
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
# ONE GATE PER HOST (2026-10-01, PQ1 #768).  The gate runs its proof jobs concurrently
# and Z3's time limit is wall-clock, so a second gate on the same host would starve both
# into spurious solver timeouts.  The gate's own `ps` guard cannot see it: each run is a
# separate container with its own process namespace.  This host-wide lock can.
host_lock = open('/tmp/pq-easycrypt-split-gate.lock', 'a+')
try:
    fcntl.flock(host_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    sys.exit('FAIL: another EasyCrypt split gate holds /tmp/pq-easycrypt-split-gate.lock '
             'on this host; concurrent gates would starve each other into solver timeouts')
jobs = os.environ.get('PQ_EASYCRYPT_JOBS', 'auto')
if jobs != 'auto' and not re.fullmatch(r'[1-9][0-9]*', jobs):
    sys.exit('FAIL: PQ_EASYCRYPT_JOBS must be a positive integer or auto')
# Per-job wall-clock cap in seconds (tools/proof_jobs.py, default 7200).  A slow host can
# need more: under GNOME power-saver one cli job ran 6,400 s.  0 disables the cap.
job_timeout = os.environ.get('PQ_EASYCRYPT_JOB_TIMEOUT', '7200')
if not re.fullmatch(r'[0-9]+', job_timeout):
    sys.exit('FAIL: PQ_EASYCRYPT_JOB_TIMEOUT must be a whole number of seconds')


def host_setting(path):
    try:
        return Path(path).read_text().strip() or 'empty'
    except OSError:
        return 'n/a'


# HOST POWER STATE IN THE RECEIPT (2026-10-01).  Z3's limit is wall-clock and the cli leg
# runs at EasyCrypt's default 3 s budget, so the CPU clock is part of what a receipt
# measured.  Measured: the same inputs and code went GREEN under `performance` and RED
# (6 cli verdicts, all `cannot prove goal (strict)`) under GNOME `power-saver`, where cores
# ran at 0.6-2.2 GHz.  Recorded and warned about, not refused (owner decision): a RED run
# with `platform_profile` other than `performance` should be re-run before it is diagnosed.
profile = host_setting('/sys/firmware/acpi/platform_profile')
governor = host_setting('/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor')
print(f'### HOST platform_profile={profile} governor={governor} PQ_EASYCRYPT_JOBS={jobs} '
      f'PQ_EASYCRYPT_JOB_TIMEOUT={job_timeout}',
      flush=True)
if profile not in ('n/a', 'performance'):
    print(f'WARN host platform_profile is {profile!r}, not performance: slower clocks can make '
          'budget-marginal cli proofs fail; re-run under performance before diagnosing a RED',
          flush=True)
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
                '--env', f'PQ_EASYCRYPT_IMAGE={image}', '--env', f'PQ_EASYCRYPT_JOBS={jobs}',
                '--env', f'PQ_EASYCRYPT_JOB_TIMEOUT={job_timeout}',
                '--volume', f'{root}:/source:ro', image, 'bash', '-lc',
                'set -e; eval "$(opam env)"; cp -R /source /tmp/proofs; '
                'cd /tmp/proofs; ' + command], check=True)
