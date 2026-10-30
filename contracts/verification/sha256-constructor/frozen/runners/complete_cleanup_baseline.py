"""Finite panic-prefix compatibility, explicitly separate from symbolic proof."""
from pathlib import Path
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
parser = argparse.ArgumentParser(); parser.add_argument('name'); parser.add_argument('--wrong-prefix', action='store_true'); options = parser.parse_args()
assert Path(options.name).name == options.name
out = root / options.name
assert out.is_dir()
assert (out / 'tmp').is_dir()
assert (out / 'cargo-home').is_dir()
assert (out / 'target').is_dir()
source = root / ('cleanup-wrong-prefix' if options.wrong_prefix else 'cleanup-v2')
upstream = n / 'generic-array-buffer/padding/isolation/upstream-kani'
tc = upstream / 'rustup/toolchains/nightly-2026-10-23-x86_64-unknown-linux-gnu'
receipt = json.loads((n / 'kani-architecture/digest-caller-probe-v2/acceptance.json').read_text())
sysroot = n / 'kani-architecture/miri-current-sysroot'

def sha(p):
    with p.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()

tools = {name: sha(tc / 'bin' / name) for name in ['rustc', 'cargo', 'miri', 'cargo-miri']}
assert tools == receipt['tool_hashes_at_completion']
sysroot_receipt = n / 'kani-architecture/miri-sysroot-digests.json'
assert sha(sysroot_receipt) == receipt['miri_sysroot_receipt_sha256']
sysroot_files = json.loads(sysroot_receipt.read_text())
assert all(sha(sysroot / name) == expected for name, expected in sysroot_files.items())
assert sha(root / 'inputs/generic-array/src/lib.rs') == receipt['corrected_dependency_sha256']
sys.path.insert(0, str(n / 'padding-profile-candidate/contracts/verification/sha256-padding'))
import prepare
import replay
replay.check_cargo_ancestors(source)
prepared_inventory = prepare.check_prepared(root / 'inputs')
selected_crate = root / ('mutants/omit-prefix-drop' if options.wrong_prefix else 'inputs/generic-array')
def authenticate_dependency():
    assert prepare.check_prepared(root / 'inputs') == prepared_inventory
    baseline = root / 'inputs/generic-array'
    expected_files = {str(f.relative_to(baseline)): f.read_bytes() for f in baseline.rglob('*') if f.is_file()}
    if options.wrong_prefix:
        old = b'for i in 0..self.position {'; new = b'for i in 1..self.position {'
        assert expected_files['src/lib.rs'].count(old) == 1
        expected_files['src/lib.rs'] = expected_files['src/lib.rs'].replace(old, new)
    assert {str(f.relative_to(selected_crate)) for f in selected_crate.rglob('*') if f.is_file()} == set(expected_files)
    assert all((selected_crate / name).read_bytes() == data for name, data in expected_files.items())
authenticate_dependency()
source_files = ['Cargo.toml', 'src/main.rs', '.cargo/config.toml']
pins = {name: sha(source / name) for name in source_files}
env = {key: os.environ[key] for key in ['HOME', 'USER', 'LANG', 'LC_ALL', 'TZ'] if key in os.environ}
env.update(PATH=os.pathsep.join(map(str, [tc / 'bin', Path('/usr/bin'), Path('/bin')])),
           RUSTUP_HOME=str(upstream / 'rustup'), RUSTUP_TOOLCHAIN=tc.name,
           RUSTUP_AUTO_INSTALL='0', CARGO_HOME=str(out / 'cargo-home'), CARGO_NET_OFFLINE='true',
           CARGO_BUILD_JOBS='2', CARGO_INCREMENTAL='0', CARGO_TARGET_DIR=str(out / 'target'),
           LD_LIBRARY_PATH=str(tc / 'lib'), MIRI_SYSROOT=str(sysroot), TMPDIR=str(out / 'tmp'))
commands = [
    ('lock', [str(tc / 'bin/cargo'), 'generate-lockfile', '--offline'], {}, 30),
    ('build', [str(tc / 'bin/cargo'), 'build', '--offline', '--locked'], {}, 120),
    ('native', [str(out / 'target/debug/corrected_cleanup_probe')], {}, 120),
    ('recursive-miri', [str(tc / 'bin/cargo-miri'), 'miri', 'run', '--offline', '--locked'],
     {'MIRIFLAGS': '-Zmiri-recursive-validation'}, 180),
]
if options.wrong_prefix:
    commands = commands[:3]
cap = 6442450944
allocated = lambda: int(subprocess.check_output(['du', '-s', '-B1', str(n)], text=True).split()[0])
results = json.loads((out / 'progress.json').read_text())
assert len(results) == len(commands)
for row, (label, args, extra, limit) in zip(results, commands):
    expected_command = ['prlimit', '--fsize=16777216:16777216', f'--cpu={limit-2}:{limit}', '--'] + args
    assert row['step'] == label and row['command'] == expected_command
    assert row['environment_additions'] == extra and row['exit'] == 0 and row['stop'] is None
    assert row['log_sha256'] == sha(out / (label + '.log'))

authenticate_dependency()
assert pins == {name: sha(source / name) for name in pins}
assert tools == {name: sha(tc / 'bin' / name) for name in tools}
assert all(sha(sysroot / name) == expected for name, expected in sysroot_files.items())
expected = '110 complete-or-panic generator cases: order and exact initialized-prefix drops passed'
if options.wrong_prefix:
    accepted = len(results) == 3 and all(r['exit'] == 0 and r['stop'] is None for r in results[:2]) and results[-1]['exit'] == 101 and results[-1]['stop'] is None
    if accepted:
        failure = (out / 'native.log').read_text()
        assert 'initialized-prefix drop mismatch' in failure and 'left: []' in failure and 'right: [0]' in failure
        assert expected not in failure
else:
    accepted = len(results) == 4 and all(r['exit'] == 0 and r['stop'] is None for r in results)
    if accepted:
        assert (out / 'native.log').read_text().strip().endswith(expected)
        assert (out / 'native.log').read_text().count('deliberate generator stop') == 105
        assert expected in (out / 'recursive-miri.log').read_text()
        assert (out / 'recursive-miri.log').read_text().count('deliberate generator stop') == 105
miri_info = None
if accepted and not options.wrong_prefix:
    info_path = out / 'target/miri/x86_64-unknown-linux-gnu/debug/corrected_cleanup_probe'
    info = json.loads(info_path.read_text())
    decode = lambda value: value if isinstance(value, str) else bytes(value['Unix']).decode()
    assert decode(info['current_dir']) == str(source)
    assert 'src/main.rs' in [decode(value) for value in info['args']]
    (out / 'miri-run-info.json').write_bytes(info_path.read_bytes())
    miri_info = {'sha256': sha(info_path), 'current_dir': decode(info['current_dir'])}
selected_inventory = {str(f.relative_to(selected_crate)): sha(f) for f in selected_crate.rglob('*') if f.is_file()}
result = {'collector_completion': 'All four commands passed. Original collector then rejected string-form Miri argv while parsing run-info; this completion authenticates unchanged source/tools and saved command/output identities without rerunning commands.', 'initial_runner_sha256': sha(root / 'run_cleanup_isolated_initial.py'), 'completion_collector_sha256': sha(Path(__file__)), 'output': str(out), 'source': str(source), 'prepared_inventory': prepared_inventory, 'selected_dependency_inventory': selected_inventory, 'fresh_target_directory': True, 'isolated_cargo_home': True, 'miri_run_info': miri_info, 'accepted_finite': accepted and not options.wrong_prefix, 'accepted_negative_control': accepted and options.wrong_prefix, 'results': results, 'source_sha256': pins,
          'lock_sha256': sha(source / 'Cargo.lock'), 'tool_sha256': tools,
          'miri_sysroot_receipt_sha256': sha(sysroot_receipt),
          'selected_dependency_sha256': sha(selected_crate / 'src/lib.rs'),
          'corrected_dependency_sha256': receipt['corrected_dependency_sha256'],
          'environment': env, 'scope': 'Finite native and experimental recursive-Miri panic-prefix behavior at U0/U1/U8/U32/U64. No universal panic/unwind, full dependency equivalence or complete Digest claim.'}
(out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
assert allocated() < cap, 'terminal artifact allocation cap'
print(json.dumps({'accepted': accepted, 'wrong_prefix_control': options.wrong_prefix, 'steps': len(results)}), flush=True)
