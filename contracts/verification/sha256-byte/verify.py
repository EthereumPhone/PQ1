#!/usr/bin/env python3
"""Replay the source-bound, frozen portable SHA-256 extraction in isolation.

This checks a saved extraction, not a fresh Charon/Aeneas translation. Dependency
oleans are an explicit trusted cache; every profile module is freshly compiled.
See README.md for the compiler/model boundary and dependency preparation.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


class Rejected(ValueError):
    pass


def sha(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise Rejected(reason)


def sources(profile: Path = HERE, root: Path = ROOT) -> tuple[dict, dict]:
    config = json.loads((profile / 'profile.json').read_text())
    require(config['format'] == 1, 'unsupported profile version')
    for name, expected in config['source_sha256'].items():
        require(sha(profile / name) == expected, f'profile source changed: {name}')
    modules = config['modules']
    require(len(modules) == len(set(modules)) and modules[-1] == 'AxiomCheck',
            'duplicate modules or missing final census')
    require(all(m.replace('.', '/') + '.lean' in config['source_sha256'] for m in modules),
            'unbound module source')
    require(set(p.relative_to(profile).as_posix() for p in profile.rglob('*.lean')) ==
            {m.replace('.', '/') + '.lean' for m in modules}, 'unlisted Lean source')
    guard = load_module('sha_byte_profile_guard', profile / 'profile_guard.py')
    data = (profile / 'frozen/input.llbc').read_bytes()
    accepted = guard.check(data, (profile / 'profile-manifest.json').read_bytes())
    portable = load_module('sha_byte_portable_source',
                          root / 'contracts/verification/scripts/check_sha256_portable_source.py')
    errors = portable.check(root)
    require(not errors, 'Rust source binding: ' + '; '.join(errors))
    files = guard.load_strict(data)['translated']['files']
    for name in ('src/sha256/soft.rs', 'src/consts.rs'):
        matching = [f for f in files if isinstance(f['name'], dict) and
                    any(str(n).endswith('/sha2-0.10.9/' + name) for n in f['name'].values())]
        require(len(matching) == 1, f'ambiguous embedded Rust source: {name}')
        require(matching[0]['contents'].encode() == (root / portable.VENDOR / name).read_bytes(),
                f'embedded Rust source differs: {name}')
    owner = root / config['spec_owner']
    require(sha(owner) == config['spec_owner_sha256'], 'SHA specification owner changed')
    # The sole difference is a leading provenance comment in the vendored copy.
    require((profile / 'Extracted/Sha256Vendored.lean').read_bytes().endswith(owner.read_bytes()),
            'vendored SHA specification differs')
    return config, accepted


def output(command: list[str], cwd: Path | None = None) -> str:
    return subprocess.check_output(command, cwd=cwd, text=True, stderr=subprocess.STDOUT,
                                   timeout=60).strip()


def dependencies(config: dict, backend: Path, cache: Path, lean: Path) -> tuple[list[Path], dict]:
    pins = config['pins']
    require(sha(lean) == pins['lean_linux_binary_sha256'], 'Lean executable identity changed')
    version = output([str(lean), '--version'])
    require(pins['lean_version'] in version and pins['lean_commit'][:12] in version,
            'Lean version/commit changed')
    inventory = json.loads((HERE / 'backend-sources.json').read_text())
    for name, expected in inventory.items():
        require(sha(backend / name) == expected, f'Aeneas backend source changed: {name}')
    require({p.relative_to(backend).as_posix() for p in backend.rglob('*.lean')
             if '.lake' not in p.relative_to(backend).parts} ==
            {name for name in inventory if name.endswith('.lean')}, 'unlisted Aeneas source')
    manifest = json.loads((HERE / 'backend-manifest.json').read_text())
    paths = [cache]
    for package in manifest['packages']:
        path = backend / '.lake/packages' / package['name']
        require(output(['git', 'rev-parse', 'HEAD'], path) == package['rev'],
                f'dependency revision changed: {package["name"]}')
        require(not output(['git', 'status', '--porcelain', '--untracked-files=no'], path),
                f'dirty dependency source: {package["name"]}')
        built = path / '.lake/build/lib/lean'
        # Manifest-only dependencies (currently Cli) need no compiled modules.
        # An actual missing import still fails during the fresh Lean compile.
        if built.is_dir():
            paths.append(built)
    require((cache / 'Aeneas.olean').is_file() and (cache / 'Aeneas').is_dir(),
            'Aeneas backend cache is not built')
    artifacts = {}
    for index, path in enumerate(paths):
        require(path.is_dir(), f'dependency build directory missing: {path}')
        # Includes public/private/server oleans and interpreter artifacts.
        for file in sorted(path.rglob('*')):
            if file.is_file():
                artifacts[f'{index}/{file.relative_to(path).as_posix()}'] = sha(file)
    require(artifacts, 'empty dependency artifact inventory')
    return paths, {'lean': str(lean), 'lean_sha256': sha(lean), 'lean_version': version,
                   'backend_source_sha256': inventory, 'dependency_roots': list(map(str, paths)),
                   'dependency_artifact_sha256': artifacts,
                   'dependency_build_claim': 'Authenticated sources; reused compiled dependency caches, not fresh dependency replay.'}


def census(text: str, config: dict) -> dict:
    rows = re.findall(r"^'([^']+)' depends on axioms: \[([^\]]*)\]", text, re.MULTILINE)
    rows += [(name, '') for name in re.findall(r"^'([^']+)' does not depend on any axioms", text, re.MULTILINE)]
    names = [name for name, _ in rows]
    expected = config['axiom_theorems']
    require(len(expected) == len(set(expected)) == 98, 'theorem inventory changed')
    require(len(names) == len(set(names)) and set(names) == set(expected),
            'missing, duplicate or unexpected theorem census')
    allowed = {'propext', 'Classical.choice', 'Quot.sound'}
    require(set(config['allowed_axioms']) == allowed, 'axiom allowlist changed')
    result = {}
    for name, axioms in rows:
        actual = [a.strip() for a in axioms.split(',') if a.strip()]
        require(set(actual) <= allowed, f'unexpected axiom in {name}: {actual}')
        result[name] = actual
    return result


def compile_module(module: str, lean: Path, build: Path, paths: list[Path], timeout: int) -> dict:
    relative = Path(module.replace('.', '/'))
    source = HERE / relative.with_suffix('.lean')
    target = build / relative.with_suffix('.olean')
    target.parent.mkdir(parents=True, exist_ok=True)
    log = build / 'logs' / (module + '.log')
    command = [str(lean), '--root=' + str(HERE), '-o', str(target), str(source)]
    env = os.environ.copy()
    for key in list(env):
        if key.startswith('LEAN_'):
            del env[key]
    env['LEAN_PATH'] = os.pathsep.join(map(str, [build, *paths]))
    start = time.monotonic()
    with log.open('xb') as stream:
        process = subprocess.Popen(command, cwd=HERE, env=env, stdout=stream,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise Rejected(f'proof timeout in {module}; see {log}')
    require(code == 0, f'Lean rejected {module}; see {log}')
    require(target.is_file(), f'no proof artifact for {module}')
    text = log.read_text()
    require('declaration uses' not in text or 'sorry' not in text,
            f'admitted declaration in {module}')
    return {'module': module, 'command': command, 'seconds': time.monotonic() - start,
            'source_sha256': sha(source), 'log_sha256': sha(log), 'olean_sha256': sha(target)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-only', action='store_true')
    parser.add_argument('--backend', type=Path, help='pinned upstream backends/lean source and packages')
    parser.add_argument('--backend-cache', type=Path, help='optional separate authenticated backend build cache')
    parser.add_argument('--lean', type=Path, help='exact Linux x86_64 Lean 4.35 executable')
    parser.add_argument('--output', type=Path, help='new, empty replay output directory outside profile')
    parser.add_argument('--timeout', type=int, default=180, help='seconds per Lean module')
    args = parser.parse_args()
    config, accepted = sources()
    if args.source_only:
        print(json.dumps({'source_check': 'pass', 'profile': accepted}))
        return
    require(all((args.backend, args.lean, args.output)), '--backend, --lean and --output are required')
    require(args.timeout > 0, 'timeout must be positive')
    backend, lean, build = args.backend.resolve(), args.lean.resolve(), args.output.resolve()
    require(not build.is_relative_to(HERE), 'build output must be outside source profile')
    require(not build.exists(), 'replay output must not exist; never reuse profile oleans')
    cache = (args.backend_cache or backend / '.lake/build/lib/lean').resolve()
    paths, dependency = dependencies(config, backend, cache, lean)
    build.mkdir(parents=True)
    (build / 'logs').mkdir()
    # Lean resolves submodules at the first matching directory prefix. This
    # read-only alias exposes upstream Aeneas.* beside our root-module overlay.
    # No profile module is named Aeneas.*, so all output remains private.
    require(not any(m.startswith('Aeneas.') for m in config['modules']), 'unsafe module output namespace')
    (build / 'Aeneas').symlink_to(cache / 'Aeneas', target_is_directory=True)
    receipt = {'status': 'running', 'claim': config['claim'], 'profile_sha256': sha(HERE / 'profile.json'),
               'entrypoint_sha256': sha(Path(__file__)),
               'source_check': accepted, 'dependencies': dependency, 'modules': []}
    receipt_path = build / 'result.json'
    try:
        for module in config['modules']:
            row = compile_module(module, lean, build, paths, args.timeout)
            receipt['modules'].append(row)
            print(f'PASS {module} ({row["seconds"]:.2f}s)', flush=True)
        receipt['axioms'] = census((build / 'logs/AxiomCheck.log').read_text(), config)
        # Recheck source identities after replay, before issuing a passing receipt.
        sources()
        require(sha(HERE / 'profile.json') == receipt['profile_sha256'], 'profile changed during replay')
        require(sha(Path(__file__)) == receipt['entrypoint_sha256'], 'entrypoint changed during replay')
        receipt['status'] = 'pass'
    except Exception as exc:
        receipt['status'] = 'fail'
        receipt['reason'] = str(exc)
        raise
    finally:
        receipt_path.write_text(json.dumps(receipt, indent=2) + '\n')
    print(f'PASS: {len(receipt["modules"])} fresh modules, {len(receipt["axioms"])} axiom closures; {receipt_path}')


if __name__ == '__main__':
    try:
        main()
    except (Rejected, ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as exc:
        print(f'FAIL: {exc}', file=sys.stderr)
        sys.exit(1)
