#!/usr/bin/env python3
"""Run one frozen padding case with the exact retained experimental runtime.

No tool is installed or substituted. Rebuilding the compiler requires renewing
its identity and evidence; an arbitrary newly built binary is not accepted here.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import time

sys.dont_write_bytecode = True
from bounded_disk_usage import measure_allocated_bytes
from prepare import check_prepared
from verify import CASES, HERE, Rejected, accept, read_json, require, sha, sources


def check_runtime_files(root, pins):
    actual = {}
    for name, expected in pins.items():
        path = root / name
        require(sha(path) == expected, f'Kani runtime differs: {name}')
        actual[str(path)] = expected
    return actual


def check_rustup_home(home, external):
    canonical = home.resolve()
    require(canonical == Path(external['rustup_home']),
            'Rustup home differs from the retained driver embedded Cargo path')
    return canonical


def check_cargo_ancestors(case):
    for parent in case.resolve().parents:
        require(not any((parent / '.cargo' / name).exists() for name in ('config', 'config.toml')),
                f'ancestor Cargo configuration is outside this profile: {parent}')


def runtime(args, config):
    root = args.kani_root.resolve()
    require((root / 'target/kani/bin/kani-driver').resolve().parent == root / 'target/kani/bin',
            'driver symlink selects a different installation/model-source root')
    external = read_json(HERE / 'frozen/external-runtime.json')
    rustup_home = check_rustup_home(args.rustup_home, external)
    pins = read_json(HERE / 'frozen/kani-runtime.json')
    actual = check_runtime_files(root, pins)
    require(sha(args.rustup) == external['rustup'], 'rustup launcher differs')
    actual[str(args.rustup)] = external['rustup']
    toolchain = rustup_home / 'toolchains' / config['compiler']['rust_toolchain']
    for root, group in [(toolchain, 'rust_toolchain'), (args.solver_bin, 'solver_bin'),
                        (args.compat_libs, 'compat_libs')]:
        for name, expected in external[group].items():
            require(sha(root / name) == expected, f'external runtime differs: {group}/{name}')
            actual[str(root / name)] = expected
    return toolchain, actual


def tool_bindings(args, toolchain):
    solvers = read_json(HERE / 'frozen/external-runtime.json')['solver_bin']
    return {'cargo': args.rustup, 'rustup': args.rustup, 'rustc': toolchain / 'bin/rustc',
            **{name: args.solver_bin / name for name in solvers}}


def install_tools(directory, bindings):
    for name, target in bindings.items():
        (directory / name).symlink_to(target)


def check_tool_resolution(directory, bindings, path):
    for name, target in bindings.items():
        selected = shutil.which(name, path=path)
        require(selected == str(directory / name) and Path(selected).resolve() == target.resolve(),
                f'tool resolution differs: {name}')
    return {name: str(target.resolve()) for name, target in bindings.items()}


def execute(args):
    config = sources()
    prepared = args.prepared.resolve()
    inputs = check_prepared(prepared)
    toolchain, tools = runtime(args, config)
    if args.check_only:
        print(json.dumps({'inputs_checked': len(inputs), 'runtime_files_checked': len(tools),
                          'fresh_solver_execution': False}))
        return
    require(args.output is not None and args.case is not None and args.budget_root is not None,
            '--case, --output and --budget-root are required for execution')
    require(not args.output.exists() and not args.output.is_relative_to(prepared) and
            not args.output.is_relative_to(HERE), 'use a new output directory outside source inputs')
    require(args.output.is_relative_to(args.budget_root), 'output is outside allocation budget')
    cap = 6144 * 1024 * 1024
    require(measure_allocated_bytes(args.budget_root, cap) < cap, 'allocation cap already reached')
    args.output.mkdir(parents=True)
    for name in ('bin', 'cargo-home', 'tmp'):
        (args.output / name).mkdir()
    bindings = tool_bindings(args, toolchain)
    install_tools(args.output / 'bin', bindings)
    case = prepared / args.case
    check_cargo_ancestors(case)
    # Explicit environment: inherited Rust/Cargo/Kani flags cannot weaken a run.
    env = {key: os.environ[key] for key in ('HOME', 'USER', 'LANG', 'LC_ALL', 'TZ') if key in os.environ}
    env.update({
        'PATH': os.pathsep.join(map(str, [args.output / 'bin', Path('/usr/bin'), Path('/bin')])),
        'RUSTUP_HOME': str(args.rustup_home),
        'RUSTUP_TOOLCHAIN': config['compiler']['rust_toolchain'],
        'RUSTUP_AUTO_INSTALL': '0',
        'CARGO_HOME': str(args.output / 'cargo-home'),
        'CARGO_NET_OFFLINE': 'true',
        'CARGO_BUILD_JOBS': '2',
        'CARGO_PROFILE_DEV_DEBUG': '0',
        'CARGO_INCREMENTAL': '0',
        'CARGO_TARGET_DIR': str(args.output / 'target'),
        'RUSTFLAGS': '--emit=mir',
        'LD_LIBRARY_PATH': os.pathsep.join(map(str, [toolchain / 'lib', args.compat_libs])),
        'TMPDIR': str(args.output / 'tmp'),
    })
    resolutions = check_tool_resolution(args.output / 'bin', bindings, env['PATH'])
    command = [str(args.kani_root / 'target/kani/bin/kani-driver'), 'kani',
               '--manifest-path', str(case / 'Cargo.toml'), '--lib', '--harness',
               config['cases'][args.case]['harness'], '-Z', 'uninit-checks',
               '-Z', 'valid-value-checks', '--keep-temps']
    if args.codegen_only:
        command.append('--only-codegen')
    start = time.monotonic()
    stop = None
    log_path = args.output / 'command.log'
    with log_path.open('wb') as log:
        proc = subprocess.Popen(command, cwd=case, env=env, stdout=log,
                                stderr=subprocess.STDOUT, start_new_session=True)
        try:
            while proc.poll() is None:
                if time.monotonic() - start >= 1800:
                    stop = 'active-time limit'
                elif measure_allocated_bytes(args.budget_root, cap) >= cap:
                    stop = 'allocation limit'
                if stop:
                    break
                time.sleep(1)
        except BaseException as error:
            stop = f'monitor interrupted: {type(error).__name__}: {error}'
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
            code = proc.wait()
    result = {'command': command, 'cwd': str(case), 'environment': env,
              'exit': code, 'stop': stop, 'seconds': time.monotonic() - start,
              'profile_sha256': sha(HERE / 'profile.json'), 'inputs': inputs, 'tools': tools,
              'tool_resolutions': resolutions,
              'log_sha256': sha(log_path), 'solver_requested': not args.codegen_only,
              'fresh_solver_execution': False,
              'proof_accepted': False}
    (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    require(check_prepared(prepared) == inputs and runtime(args, config)[1] == tools,
            'input or runtime changed during execution')
    require(check_tool_resolution(args.output / 'bin', bindings, env['PATH']) == resolutions,
            'tool resolution changed during execution')
    if args.codegen_only:
        require(code == 0 and stop is None, 'code generation did not complete')
    else:
        acceptance = accept(config, args.case, log_path.read_text(), code, stop)
        (args.output / 'acceptance.json').write_text(json.dumps(acceptance, indent=2) + '\n')
        result['proof_accepted'] = True
        result['fresh_solver_execution'] = True
        (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'output': str(args.output), 'seconds': result['seconds'],
                      'codegen_only': args.codegen_only, 'proof_accepted': not args.codegen_only}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('prepared', 'kani-root', 'rustup-home', 'rustup', 'solver-bin', 'compat-libs'):
        parser.add_argument('--' + name, type=lambda p: Path(p).expanduser().absolute(), required=True)
    parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--codegen-only', action='store_true')
    parser.add_argument('--case', choices=CASES)
    parser.add_argument('--output', type=lambda p: Path(p).expanduser().resolve())
    parser.add_argument('--budget-root', type=lambda p: Path(p).expanduser().resolve())
    args = parser.parse_args()
    execute(args)


if __name__ == '__main__':
    try:
        main()
    except (Rejected, OSError, ValueError, KeyError, RuntimeError) as error:
        sys.exit(f'REJECTED: {error}')
