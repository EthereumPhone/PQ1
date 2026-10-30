#!/usr/bin/env python3
"""Check recorded constructor evidence; this command does not run a solver."""
import argparse
from collections import Counter
import gzip
import json
from pathlib import Path
import re
import sys
import tempfile
import tomllib

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
PARENT = HERE.parent / 'sha256-padding'
sys.path.insert(0, str(PARENT))
import verify as padding
import prepare as padding_prepare
from verify import Rejected, digest, read_json, require, sha

CASES = ('default', 'generate', 'corrupt-byte', 'reverse-generation',
         'focused-corrected', 'focused-original')
SEMANTICS = {
    'default': {
        'proofs::actual_default_shapes.assertion.2': (28, 26, 'assertion failed: output[i] == 0'),
        'proofs::actual_default_shapes.assertion.4': (29, 26, 'assertion failed: buffer[i] == 0'),
        'proofs::actual_default_shapes.cover.1': (30, 9, 'both default shapes reached'),
    },
    'generate': {
        'proofs::generated_bytes_and_order.assertion.1': (38, 9, 'assertion failed: calls == 64'),
        'proofs::generated_bytes_and_order.assertion.4': (39, 26, 'assertion failed: output[i] == input[i]'),
        'generate64::{closure#0}.assertion.3': (13, 9, 'assertion failed: i == calls'),
        'proofs::generated_bytes_and_order.cover.1': (40, 9, 'distinct edge values reached'),
    },
    'focused': {
        'focused_default.assertion.2': (8, 5, 'assertion failed: output[0] == 0'),
        'focused_default.cover.1': (9, 5, 'one byte default reached'),
    },
}


def census_digest(rows):
    # Dependency/toolchain paths move on reconstruction. Keep every property
    # identity, description and status; harness locations are checked below.
    normalized = {key: {field: row[field] for field in ('Status', 'Description')}
                  for key, row in rows.items()}
    return digest(json.dumps(normalized, sort_keys=True, separators=(',', ':')).encode())


def sources(profile=HERE):
    config = read_json(profile / 'profile.json')
    require(config['format'] == 1 and set(config['cases']) == set(CASES), 'invalid cases/format')
    require({p.relative_to(profile).as_posix() for p in (profile / 'frozen').rglob('*')
             if p.is_file()} == set(config['frozen_sha256']), 'frozen inventory changed')
    for name, expected in config['frozen_sha256'].items():
        require(sha(profile / name) == expected, f'frozen input changed: {name}')
    for name, expected in config['parent_sha256'].items():
        require(sha(PARENT / name) == expected, f'parent input changed: {name}')
    parent = padding.sources()
    require(config['corrected_dependency_sha256'] == parent['generic_array_corrected_lib_sha256'],
            'dependency correction differs from parent')
    require(config['original_dependency_sha256'] == parent['generic_array_original_lib_sha256'],
            'original dependency differs from parent')
    for project in config['projects']:
        directory = profile / 'frozen/projects' / project
        manifest = tomllib.loads((directory / 'Cargo.toml').read_text())
        selected = manifest['patch']['crates-io']['generic-array']['path']
        original_project = Path(config['historical_root']) / project
        require((original_project / selected).resolve() ==
                Path(config['historical_root']) / config['projects'][project]['selected_crate'],
                'project selects a different dependency')
        packages = tomllib.loads((profile / f'frozen/projects/{project}/Cargo.lock').read_text())['package']
        for package in packages:
            if package.get('source', '').startswith('registry+'):
                stem = f'{package["name"]}-{package["version"]}'
                require(stem in parent['crates'] and package['checksum'] == parent['crates'][stem],
                        'project lock differs from archived crates')
    return config


def accept(config, name, text, exit_code, stop=None):
    require(name in CASES, 'unknown case')
    case = config['cases'][name]
    require(exit_code == case['exit'] and stop is None, 'execution failed or incomplete')
    section, rows = padding.properties(text)
    verdict = 'SUCCESSFUL' if exit_code == 0 else 'FAILED'
    require(re.findall(r'VERIFICATION:- (\w+)', section) == [verdict], 'missing/wrong verdict')
    require(census_digest(rows) == case['census_sha256'], 'property census/status/description changed')
    require(len(rows) == case['properties'] and
            dict(Counter(row['Status'] for row in rows.values())) == case['statuses'],
            'declared property/status counts differ')
    failures = {key for key, row in rows.items() if row['Status'] == 'FAILURE'}
    require(failures == set(case['failures']), 'unexpected or missing failure')
    if name in ('default', 'generate', 'focused-corrected'):
        require(not failures and exit_code == 0, 'positive case did not succeed')
        covers = [row for key, row in rows.items() if '.cover.' in key]
        require(len(covers) == 1 and covers[0]['Status'] == 'SATISFIED', 'positive cover not reached')
        require(all(row['Status'] in ('SUCCESS', 'UNREACHABLE') for key, row in rows.items()
                    if '.cover.' not in key), 'positive guard failed')
    elif name == 'corrupt-byte':
        require(failures == {'proofs::actual_default_shapes.assertion.2'}, 'byte control failed elsewhere')
    elif name == 'reverse-generation':
        require(failures == {'generate64::{closure#0}.assertion.3'}, 'order control failed elsewhere')
    else:
        require(exit_code == 1 and len(failures) == 2, 'original diagnostic failed to detect invalid reference')
        require(all('uninitialized' in json.loads(rows[key]['Description']).lower()
                    for key in failures), 'original diagnostic failed for another reason')
        require("core::slice::from_raw_parts_mut::<'_, u8>.safety_check.1" in failures and
                len([key for key in failures if key.startswith("<core::slice::IterMut<'_, u8>")
                     and key.endswith('.safety_check.13')]) == 1,
                'original diagnostic failed at different operations')
    kind = ('default' if name in ('default', 'corrupt-byte') else
            'generate' if name in ('generate', 'reverse-generation') else 'focused')
    for key, (line, column, description) in SEMANTICS[kind].items():
        row = rows[key]
        require(json.loads(row['Description']) == description and
                row['Location'].startswith(f'src/lib.rs:{line}:{column} in function '),
                f'intended assertion/cover changed: {key}')
        if name in ('default', 'generate', 'focused-corrected'):
            require(row['Status'] == ('SATISFIED' if '.cover.' in key else 'SUCCESS'),
                    'intended positive assertion unreachable')
    return {'case': name, 'properties': len(rows), 'statuses': dict(Counter(r['Status'] for r in rows.values()))}


def runtime_receipt(config, result):
    """Bind every recorded tool to the parent's retained runtime, including extras."""
    historical = Path(config['historical_root']).parent
    external = read_json(PARENT / 'frozen/external-runtime.json')
    expected = {str(historical / 'kani-candidate' / name): value
                for name, value in read_json(PARENT / 'frozen/kani-runtime.json').items()}
    expected['/home/nicola/.cargo/bin/rustup'] = external['rustup']
    roots = {
        'rust_toolchain': Path(external['rustup_home']) / 'toolchains' / padding.sources()['compiler']['rust_toolchain'],
        'solver_bin': historical / 'generic-array-buffer/padding/isolation/upstream-kani/kani-latest/bin',
        'compat_libs': historical / 'kani-architecture/runtime-libs',
    }
    for group, root in roots.items():
        expected.update({str(root / name): value for name, value in external[group].items()})
    require(result['tool_sha256'] == expected, 'recorded runtime inventory differs')
    require(result['environment']['RUSTUP_HOME'] == external['rustup_home'], 'embedded Cargo path differs')


def recorded(config, profile=HERE):
    accepted = []
    codegen_path = profile / 'frozen/receipts/constructor-codegen.json'
    codegen = read_json(codegen_path)
    require(codegen['exit'] == 0 and codegen['stop'] is None and
            codegen['solver_requested'] is False, 'shared code-generation run did not complete')
    runtime_receipt(config, codegen)
    baseline = profile / 'frozen/projects/constructor'
    require(codegen['source_sha256'] == {key: sha(baseline / (key + '.in' if key.endswith('.rs') else key))
                                       for key in ('Cargo.toml', 'Cargo.lock', 'src/lib.rs', '.cargo/config.toml')},
            'shared code-generation source differs')
    historical = Path(config['historical_root'])
    driver = str(historical.parent / 'kani-candidate/target/kani/bin/kani-driver')
    require(codegen['command'] == ['prlimit', '--fsize=16777216:16777216', '--cpu=175:180', '--',
            driver, 'kani', '--manifest-path', str(historical / 'constructor/Cargo.toml'),
            '--lib', '--harness', 'actual_default_shapes', '-Z', 'uninit-checks',
            '-Z', 'valid-value-checks', '--keep-temps', '--only-codegen'],
            'shared code-generation command differs')
    raw_codegen = gzip.decompress((profile / 'frozen/logs/constructor-codegen.log.gz').read_bytes())
    require(digest(raw_codegen) == codegen['log_sha256'], 'shared code-generation output differs')
    for name in CASES:
        case = config['cases'][name]
        result = read_json(profile / f'frozen/receipts/{name}.json')
        raw = gzip.decompress((profile / f'frozen/logs/{name}.log.gz').read_bytes())
        require(digest(raw) == result['log_sha256'], 'recorded output differs')
        project = profile / 'frozen/projects' / case['project']
        require(result['source_sha256'] == {key: sha(project / (key + '.in' if key.endswith('.rs') else key)) for key in
                                           ('Cargo.toml', 'Cargo.lock', 'src/lib.rs', '.cargo/config.toml')},
                'recorded harness/manifest/lock/config differs')
        control_case = name not in ('default', 'generate')
        require(('control_source' in result) == control_case, 'missing/extra control source identity')
        if control_case:
            selected = config['projects'][case['project']]['selected_crate']
            expected_lib = (config['original_dependency_sha256'] if name == 'focused-original'
                            else config['mutations'][name]['lib_sha256']
                            if name in ('corrupt-byte', 'reverse-generation')
                            else config['corrected_dependency_sha256'])
            require(result['control_source']['crate'] == str(Path(config['historical_root']) / selected)
                    and result['control_source']['lib_sha256'] == expected_lib,
                    'control dependency differs from recorded source')
        _, rows = padding.properties(raw.decode())
        require(rows == read_json(profile / f'frozen/receipts/{name}-census.json'),
                'full historical property locations/census differs')
        runtime_receipt(config, result)
        reuse_field = 'compile_cache_reference_sha256' if control_case else 'reused_codegen_receipt_sha256'
        require(result[reuse_field] == sha(codegen_path) and result['tool_sha256'] == codegen['tool_sha256'],
                'shared compilation cache source/tool receipt differs')
        if not control_case:
            require(result['source_sha256'] == codegen['source_sha256'],
                    'positive proof differs from reused code-generation source')
        require(result['environment']['CARGO_TARGET_DIR'] == codegen['environment']['CARGO_TARGET_DIR'] ==
                str(historical / 'constructor-codegen-v1/target'), 'shared cache path differs')
        command = result['command']
        cpu = '--cpu=175:180' if name.startswith('focused-') else '--cpu=1795:1800'
        require(command[:5] == ['prlimit', '--fsize=16777216:16777216', cpu, '--', driver],
                'recorded process bounds changed')
        require(command[5:] == ['kani', '--manifest-path',
                str(Path(config['historical_root']) / case['project'] / 'Cargo.toml'),
                '--lib', '--harness', case['harness'], '-Z', 'uninit-checks', '-Z',
                'valid-value-checks', '--keep-temps'], 'recorded proof flags changed')
        require(result['solver_requested'] is True, 'code generation is not a proof')
        accepted.append(accept(config, name, raw.decode(), result['exit'], result['stop']))
    return accepted


def finite(config, profile=HERE):
    expected_line = '110 complete-or-panic generator cases: order and exact initialized-prefix drops passed'
    require(sha(profile / 'frozen/receipts/miri-sysroot-digests.json') ==
            config['miri_sysroot_receipt_sha256'], 'Miri sysroot receipt differs')
    external = read_json(PARENT / 'frozen/external-runtime.json')
    historical = Path(config['historical_root'])
    toolchain = Path(external['rustup_home']) / 'toolchains' / padding.sources()['compiler']['rust_toolchain']
    commands = {
        'lock': ['prlimit', '--fsize=16777216:16777216', '--cpu=28:30', '--',
                 str(toolchain / 'bin/cargo'), 'generate-lockfile', '--offline'],
        'build': ['prlimit', '--fsize=16777216:16777216', '--cpu=118:120', '--',
                  str(toolchain / 'bin/cargo'), 'build', '--offline', '--locked'],
        'recursive-miri': ['prlimit', '--fsize=16777216:16777216', '--cpu=178:180', '--',
                           str(toolchain / 'bin/cargo-miri'), 'miri', 'run', '--offline', '--locked'],
    }
    for tool in ('rustc', 'cargo'):
        require(config['finite_tool_sha256'][tool] == external['rust_toolchain']['bin/' + tool],
                'finite Rust tool differs from retained runtime')
    for name, case in config['finite'].items():
        require(name in ('baseline', 'wrong-prefix'), 'unknown cleanup case')
        result = read_json(profile / f'frozen/receipts/cleanup-{name}.json')
        output = historical / case['run']
        source = historical / case['project']
        require(result['output'] == str(output) and result['source'] == str(source) and
                result['fresh_target_directory'] is True and result['isolated_cargo_home'] is True and
                result['environment']['CARGO_TARGET_DIR'] == str(output / 'target') and
                result['environment']['CARGO_HOME'] == str(output / 'cargo-home'),
                'cleanup does not use its isolated target/Cargo home')
        if name == 'baseline':
            require(result['initial_runner_sha256'] ==
                    sha(profile / 'frozen/runners/run_cleanup_isolated_initial.py') and
                    result['completion_collector_sha256'] ==
                    sha(profile / 'frozen/runners/complete_cleanup_baseline.py'),
                    'cleanup collector-completion identity differs')
        commands['native'] = ['prlimit', '--fsize=16777216:16777216', '--cpu=118:120', '--',
                              str(output / 'target/debug/corrected_cleanup_probe')]
        cleanup_inputs(config, result, name)
        project = profile / 'frozen/projects' / case['project']
        require(result['source_sha256'] == {key: sha(project / (key + '.in' if key.endswith('.rs') else key)) for key in
                                           ('Cargo.toml', 'src/main.rs', '.cargo/config.toml')} and
                result['lock_sha256'] == sha(project / 'Cargo.lock'), 'cleanup source differs')
        require(result['tool_sha256'] == config['finite_tool_sha256'] and
                result['miri_sysroot_receipt_sha256'] == config['miri_sysroot_receipt_sha256'],
                'cleanup tools/sysroot differ')
        require(result['corrected_dependency_sha256'] == config['corrected_dependency_sha256'] and
                result['selected_dependency_sha256'] == (config['corrected_dependency_sha256']
                if name == 'baseline' else config['mutations']['omit-prefix-drop']['lib_sha256']),
                'cleanup selected dependency differs')
        expected_steps = ['lock', 'build', 'native', 'recursive-miri'] if name == 'baseline' else ['lock', 'build', 'native']
        require([row['step'] for row in result['results']] == expected_steps, 'cleanup steps missing/extra')
        for row in result['results']:
            require(row['command'] == commands[row['step']], 'cleanup command differs')
            raw = gzip.decompress((profile / f'frozen/logs/cleanup-{name}-{row["step"]}.log.gz').read_bytes())
            require(digest(raw) == row['log_sha256'], 'cleanup output differs')
            expected_exit = 101 if name == 'wrong-prefix' and row['step'] == 'native' else 0
            require(row['exit'] == expected_exit and row['stop'] is None, 'cleanup command incomplete')
            text = raw.decode()
            if row['step'] == 'recursive-miri':
                require(row['environment_additions'] == {'MIRIFLAGS': '-Zmiri-recursive-validation'},
                        'recursive Miri check missing/changed')
                require('cargo-miri runner' in text, 'Miri runner marker missing')
                require(f'Compiling corrected_cleanup_probe v0.0.0 ({source})' in text and
                        str(output / 'target/miri/x86_64-unknown-linux-gnu/debug/corrected_cleanup_probe') in text,
                        'Miri did not compile/run the isolated source target')
                run_info_path = profile / 'frozen/receipts/cleanup-miri-run-info.json'
                info = read_json(run_info_path)
                require(sha(run_info_path) == result['miri_run_info']['sha256'] and
                        bytes(info['current_dir']['Unix']).decode() == str(source) ==
                        result['miri_run_info']['current_dir'] and 'src/main.rs' in info['args'],
                        'Miri run-info selects a different source')
            if row['step'] in ('native', 'recursive-miri'):
                if name == 'baseline':
                    require(text.count(expected_line) == 1, 'cleanup success count absent')
                    require(text.count('deliberate generator stop') == 105,
                            'cleanup panic-hook count differs from pinned v2 source')
                else:
                    require(expected_line not in text and 'initialized-prefix drop mismatch' in text and
                            'left: []' in text and 'right: [0]' in text, 'wrong cleanup failure')
    require(set(config['finite']) == {'baseline', 'wrong-prefix'}, 'missing cleanup control')
    return {'cases': 110, 'native': True, 'recursive_miri': True, 'wrong_prefix_rejected': True,
            'scope': 'finite; no universal panic or unwind equivalence'}


def cleanup_inputs(config, result, name):
    """Bind both retained inventories to independent crate reconstruction."""
    with tempfile.TemporaryDirectory(prefix='cleanup-evidence-') as temp:
        reference = Path(temp) / 'inputs'
        inventory = padding_prepare.prepare(reference, PARENT)['files']
        historical_inputs = str(Path(config['historical_root']) / 'inputs')
        relocated = {f'{case}/{file}' for case in padding.CASES
                     for file in ('Cargo.toml', '.cargo/config.toml')}
        for file in relocated:
            raw = (reference / file).read_text().replace(
                json.dumps(str(reference))[1:-1], json.dumps(historical_inputs)[1:-1])
            inventory[file] = digest(raw.encode())
        require(result['prepared_inventory'] == inventory, 'cleanup prepared dependency inventory differs')
        generic = reference / 'generic-array'
        files = {f.relative_to(generic).as_posix(): f.read_bytes() for f in generic.rglob('*') if f.is_file()}
        if name == 'wrong-prefix':
            edit = config['mutations']['omit-prefix-drop']
            old, new = bytes.fromhex(edit['old_hex']), bytes.fromhex(edit['new_hex'])
            require(files['src/lib.rs'].count(old) == 1, 'cleanup mutation anchor differs')
            files['src/lib.rs'] = files['src/lib.rs'].replace(old, new)
        require(result['selected_dependency_inventory'] == {key: digest(raw) for key, raw in files.items()},
                'cleanup selected dependency inventory differs')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-only', action='store_true')
    args = parser.parse_args()
    config = sources()
    result = {'source_binding': 'accepted', 'fresh_solver_execution': False}
    if not args.source_only:
        result['recorded_cases'] = recorded(config)
        result['finite_cleanup'] = finite(config)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (Rejected, OSError, KeyError, ValueError) as error:
        sys.exit(f'REJECTED: {error}')
