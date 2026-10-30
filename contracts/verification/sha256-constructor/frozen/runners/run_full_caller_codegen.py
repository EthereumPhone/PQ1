"""Bounded constructor diagnostic/proof using the previously reviewed runtime."""
from pathlib import Path
from types import SimpleNamespace
import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import time

sys.dont_write_bytecode = True
root = Path(__file__).resolve().parent
n = root.parent
profile = n / 'padding-profile-candidate/contracts/verification/sha256-padding'
sys.path.insert(0, str(profile))
import replay
import prepare

parser = argparse.ArgumentParser()
parser.add_argument('name')
parser.add_argument('--harness', required=True,
                    choices=['actual_corrected_roots'])
parser.add_argument('--prove', action='store_true')
parser.add_argument('--reuse-codegen')
options = parser.parse_args()
assert not options.prove and not options.reuse_codegen, 'This is a code-generation feasibility diagnostic only'
assert Path(options.name).name == options.name
out = root / options.name
out.mkdir()
(out / 'bin').mkdir()
(out / 'tmp').mkdir()
upstream = n / 'generic-array-buffer/padding/isolation/upstream-kani'
args = SimpleNamespace(kani_root=n / 'kani-candidate', rustup_home=upstream / 'rustup',
                       rustup=Path('/home/nicola/.cargo/bin/rustup'),
                       solver_bin=upstream / 'kani-latest/bin',
                       compat_libs=n / 'kani-architecture/runtime-libs')
config = replay.sources()
tc, tools = replay.runtime(args, config)
bindings = replay.tool_bindings(args, tc)
replay.install_tools(out / 'bin', bindings)
source = root / 'full-caller'
prepare.check_prepared(root / 'inputs', profile)

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

env = {key: os.environ[key] for key in ['HOME', 'USER', 'LANG', 'LC_ALL', 'TZ'] if key in os.environ}
env.update(PATH=os.pathsep.join(map(str, [out / 'bin', Path('/usr/bin'), Path('/bin')])),
           RUSTUP_HOME=str(args.rustup_home), RUSTUP_TOOLCHAIN=config['compiler']['rust_toolchain'],
           RUSTUP_AUTO_INSTALL='0', CARGO_HOME='/home/nicola/.cargo', CARGO_NET_OFFLINE='true',
           CARGO_BUILD_JOBS='2', CARGO_PROFILE_DEV_DEBUG='0', CARGO_INCREMENTAL='0',
           CARGO_TARGET_DIR=str(out / 'target'), RUSTFLAGS='--emit=mir',
           LD_LIBRARY_PATH=os.pathsep.join(map(str, [tc / 'lib', args.compat_libs])),
           TMPDIR=str(out / 'tmp'))
resolutions = replay.check_tool_resolution(out / 'bin', bindings, env['PATH'])
if not (source / 'Cargo.lock').exists():
    with (out / 'lock.log').open('xb') as stream:
        subprocess.run([str(tc / 'bin/cargo'), 'generate-lockfile', '--offline'], cwd=source,
                       env=env, stdout=stream, stderr=subprocess.STDOUT, check=True, timeout=30)
pins = {name: sha(source / name) for name in ['Cargo.toml', 'Cargo.lock', 'src/lib.rs']}
reuse_receipt = None
if options.reuse_codegen:
    assert options.prove and Path(options.reuse_codegen).name == options.reuse_codegen
    prior = root / options.reuse_codegen
    accepted_codegen = json.loads((prior / 'result.json').read_text())
    assert accepted_codegen['exit'] == 0 and accepted_codegen['stop'] is None
    assert not accepted_codegen['solver_requested']
    assert accepted_codegen['source_sha256'] == pins and accepted_codegen['tool_sha256'] == tools
    assert (prior / 'target').is_dir()
    env['CARGO_TARGET_DIR'] = str(prior / 'target')
    reuse_receipt = sha(prior / 'result.json')

def authenticate():
    assert pins == {name: sha(source / name) for name in pins}
    assert replay.runtime(args, config)[1] == tools
    prepare.check_prepared(root / 'inputs', profile)
    dependencies = json.loads((n / 'dependency-source-auth.json').read_text())
    for package in dependencies['packages']:
        assert sha(Path(package['archive'])) == package['archive_sha256']
        assert all(sha(Path(package['source']) / rel) == expected for rel, expected in package['source_sha256'].items())
    source_plan = json.loads((root / 'full-caller-plan.json').read_text())
    consumer = n.parent / 'easycrypt-original-byte-profile-20261028/candidate'
    assert all(sha(consumer / name) == expected for name, expected in source_plan['source_pins'].items())

limit = 1800 if options.prove else 180
command = ['prlimit', '--fsize=16777216:16777216', f'--cpu={limit-5}:{limit}', '--',
           str(args.kani_root / 'target/kani/bin/kani-driver'), 'kani', '--manifest-path',
           str(source / 'Cargo.toml'), '--lib', '--harness', options.harness,
           '-Z', 'uninit-checks', '-Z', 'valid-value-checks', '--keep-temps']
if not options.prove:
    command.append('--only-codegen')
cap = 6442450944
allocated = lambda: int(subprocess.check_output(['du', '-s', '-B1', str(n)], text=True).split()[0])
authenticate()
start_bytes = allocated()
assert start_bytes < cap
start = time.monotonic()
stop = None
peak = start_bytes
with (out / 'command.log').open('xb') as log:
    process = subprocess.Popen(command, cwd=source, env=env, stdout=log,
                               stderr=subprocess.STDOUT, start_new_session=True)
    (out / 'running.json').write_text(json.dumps({'pid': process.pid, 'wrapper_pid': os.getpid(),
                                                'command': command}, indent=2) + '\n')
    print(json.dumps({'pid': process.pid, 'log': str(out / 'command.log')}), flush=True)
    try:
        while process.poll() is None:
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
            peak = max(peak, allocated())
            if peak >= cap:
                stop = 'aggregate storage cap'
            elif time.monotonic() - start > limit:
                stop = 'active elapsed cap'
            if stop:
                break
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
        code = process.wait()
result = {'command': command, 'source': str(source), 'environment': env,
          'source_sha256': pins, 'tool_sha256': tools, 'tool_resolutions': resolutions,
          'exit': code, 'stop': stop, 'seconds': time.monotonic() - start,
          'start_bytes': start_bytes, 'peak_bytes': peak, 'final_bytes': allocated(),
          'cap_bytes': cap, 'log_sha256': sha(out / 'command.log'),
          'solver_requested': options.prove, 'proof_accepted': False,
          'reused_codegen_receipt_sha256': reuse_receipt,
          'acceptance_note': 'Separate complete property/cover/unsupported-check audit required.'}
(out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
authenticate()
print(json.dumps({k: result[k] for k in ['exit', 'stop', 'seconds', 'final_bytes', 'proof_accepted']}), flush=True)
