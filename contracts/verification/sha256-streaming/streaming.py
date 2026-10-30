#!/usr/bin/env python3
"""Check preserved initialized-streaming evidence; this does not run a solver."""
from collections import Counter
import gzip
import json
from pathlib import Path
import re
import sys
import tarfile
import tomllib

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SHARED = HERE.parent / 'sha256-padding'
sys.path.insert(0, str(SHARED))
import verify as common
from verify import Rejected, digest, properties, read_json, require, sha

CASES = ('positive', 'wrong-remainder', 'lost-residual')
HARNESS = 'symbolic::original_initialized_step'
FLAGS = ['--lib', '--harness', 'original_initialized_step', '-Z',
         'uninit-checks', '-Z', 'valid-value-checks', '--keep-temps']
# This host build input was omitted from the historical source inventory.
# Its archived checksum is bound, but no retroactive source-authentication claim
# is made. Fresh replay reconstructs and authenticates it with every other crate.
HISTORICAL_BUILD_INPUT_EXEMPTIONS = {'version_check-0.9.5'}


def archive_files(stem):
    with tarfile.open(SHARED / f'frozen/crates/{stem}.crate', 'r:gz') as tar:
        return {m.name.removeprefix(stem + '/'): tar.extractfile(m).read()
                for m in tar.getmembers() if m.isfile()}


def sources(profile=HERE, root=ROOT):
    config = read_json(profile / 'profile.json')
    require(config['format'] == 1 and set(config['cases']) == set(CASES),
            'unsupported profile or case set')
    require(sha(SHARED / 'profile.json') == config['shared_profile_sha256'],
            'shared compiler/dependency profile changed')
    for name, expected in config['shared_helpers_sha256'].items():
        require(sha(SHARED / name) == expected, f'shared helper changed: {name}')
    shared = common.sources(SHARED, root)
    require({p.relative_to(profile).as_posix() for p in (profile / 'frozen').rglob('*')
             if p.is_file()} == set(config['frozen_sha256']), 'frozen inventory changed')
    for name, expected in config['frozen_sha256'].items():
        require(sha(profile / name) == expected, f'frozen input changed: {name}')
    freeze = read_json(profile / 'frozen/freeze.json')
    audit = read_json(profile / 'frozen/cover-audit.json')
    require(audit['freeze_sha256'] == sha(profile / 'frozen/freeze.json'), 'cover freeze differs')
    mir = gzip.decompress((profile / 'frozen/harness.mir.gz').read_bytes())
    body = (profile / 'frozen/harness-cover-mir.txt').read_bytes()
    require(digest(mir) == freeze['mir_sha256'] == audit['mir_sha256'] and
            digest(body) == audit['harness_body_sha256'] and body in mir,
            'cover audit differs from compiled MIR')
    attrs = freeze['harness']['attributes']
    require(attrs == {'kind': 'Proof', 'should_panic': False, 'solver': None,
                      'unwind_value': 257, 'stubs': [], 'verified_stubs': []} and
            freeze['harness']['contract'] is None and
            freeze['harness']['has_loop_contracts'] is False, 'harness bounds/stubs changed')
    require(len(freeze['semantic_assertions']) == 13 and
            len(audit['compiled_covers']) == 6 and audit['source_cover_cases'] == 5,
            'semantic assertion or cover census changed')
    lines = (profile / 'frozen/lib.rs').read_text().splitlines()
    for item in freeze['semantic_assertions'].values():
        require(lines[int(item['source_location']['line']) - 1].strip() ==
                f"assert!({item['predicate']});", 'semantic assertion source differs')
    for name, expected in freeze['source_sha256'].items():
        path = 'lib.rs' if name == 'src/lib.rs' else f'inputs/positive/{name}'
        require(sha(profile / 'frozen' / path) == expected, 'compiled input differs')
    consumer = read_json(SHARED / 'frozen/consumer-lock-closure.json')
    registry_stems = set()
    for case in CASES:
        packages = tomllib.loads((profile / f'frozen/inputs/{case}/Cargo.lock').read_text())['package']
        require(len(packages) == 5, 'proof dependency census changed')
        for package in packages:
            if package['name'] == 'original_buffer_indexed_probe':
                require(package['version'] == '0.0.0', 'wrong harness package')
                continue
            matches = [p for p in consumer if p['name'] == package['name'] and
                       p['version'] == package['version']]
            require(len(matches) == 1, 'proof dependency missing from consumer')
            if case != 'positive' and package['name'] == 'block-buffer':
                require('source' not in package and 'checksum' not in package,
                        'mutant must select the local block-buffer')
            else:
                registry_stems.add(f"{package['name']}-{package['version']}")
                require(package.get('source') == matches[0].get('source') and
                        package.get('checksum') == matches[0].get('checksum') ==
                        shared['crates'].get(f"{package['name']}-{package['version']}"),
                        'proof registry dependency differs from consumer')
    deps = read_json(profile / 'frozen/receipts/dependency-source-auth.json')
    recorded_stems = [f"{p['name']}-{p['version']}" for p in deps['packages']]
    require(len(set(recorded_stems)) == len(recorded_stems), 'duplicate dependency source receipt')
    require(registry_stems - set(recorded_stems) <= HISTORICAL_BUILD_INPUT_EXEMPTIONS,
            'registry dependency missing its source-authentication receipt')
    for package in deps['packages']:
        stem = f"{package['name']}-{package['version']}"
        if stem not in shared['crates']:
            continue
        require(package['archive_sha256'] == shared['crates'][stem], 'source/archive pin differs')
        files = archive_files(stem)
        for name, expected in package['source_sha256'].items():
            require(digest(files[name]) == expected, 'recorded source differs from archive')
    return config


def accept(config, case, text, exit_code, stop=None, profile=HERE):
    expected = config['cases'][case]
    require(exit_code == expected['expected_exit'] and stop is None, 'execution failed or stopped')
    section, rows = properties(text)
    require(section.splitlines()[0] == f'Checking harness {HARNESS}...', 'wrong harness')
    require(len(rows) == expected['property_count'] and
            digest(('\n'.join(sorted(rows)) + '\n').encode()) == expected['property_names_sha256'],
            'property census/identities changed')
    verdict = 'SUCCESSFUL' if case == 'positive' else 'FAILED'
    require(re.findall(r'VERIFICATION:- (\w+)', section) == [verdict], 'wrong/missing solver verdict')
    failure = expected['expected_failure']
    require({name for name, row in rows.items() if row['Status'] == 'FAILURE'} ==
            ({failure} if failure else set()), 'missing or unintended failure')
    freeze = read_json(profile / 'frozen/freeze.json')
    audit = read_json(profile / 'frozen/cover-audit.json')
    for name, item in freeze['semantic_assertions'].items():
        row = rows[name]
        loc = item['source_location']
        require(row['Status'] == ('FAILURE' if name == failure else 'SUCCESS') and
                json.loads(row['Description']) == item['description'] and
                row['Location'] == f"{loc['file']}:{loc['line']}:{loc['column']} in function {loc['function']}",
                f'semantic assertion differs: {name}')
    covers = {name for name in rows if '.cover.' in name}
    require(covers == set(audit['compiled_covers']), 'cover census differs')
    for name, item in audit['compiled_covers'].items():
        status = item['positive_status']
        if case == 'lost-residual' and name == audit['lost_residual_additional_unsatisfiable']:
            status = 'UNSATISFIABLE'
        loc = item['source_location']
        require(rows[name]['Status'] == status and json.loads(rows[name]['Description']) == item['description'] and
                rows[name]['Location'] == f"{loc['file']}:{loc['line']}:{loc['column']} in function {loc['function']}",
                f'cover differs: {name}')
    require(all(row['Status'] in ('SUCCESS', 'UNREACHABLE') for name, row in rows.items()
                if name not in covers and name != failure), 'safety/unsupported check failed')
    require({name for name, row in rows.items() if row['Status'] == 'UNREACHABLE'} ==
            set(expected['unreachable_properties']), 'per-property reachability changed')
    statuses = dict(Counter(row['Status'] for row in rows.values()))
    require(statuses == expected['statuses'], 'property status census changed')
    return {'case': case, 'accepted': True, 'properties': len(rows), 'statuses': statuses}


def recorded_runtime(result, case='positive'):
    """Check the recorded inventory, without pretending to inspect the old host."""
    external = read_json(SHARED / 'frozen/external-runtime.json')
    config = read_json(SHARED / 'profile.json')
    env = result['environment']
    argv = result['command']
    require(argv[:4] == ['prlimit', '--fsize=16777216:16777216', '--cpu=1785:1800', '--'] and
            argv[5:7] == ['kani', '--manifest-path'] and argv[8:] == FLAGS and
            Path(argv[7]) == Path(result['source']) / 'Cargo.toml' and
            result['solver_requested'] is True, 'recorded proof command differs')
    driver = Path(argv[4])
    require(driver.is_absolute() and driver.parts[-4:] == ('target', 'kani', 'bin', 'kani-driver'),
            'recorded driver path differs')
    expected = {str(driver.parents[3] / name): value for name, value in
                read_json(SHARED / 'frozen/kani-runtime.json').items()}
    resolutions = result['tool_resolutions']
    rustup = resolutions['rustup']
    expected[rustup] = external['rustup']
    tc = Path(external['rustup_home']) / 'toolchains' / config['compiler']['rust_toolchain']
    solver = Path(resolutions['cbmc']).parent
    libs = env['LD_LIBRARY_PATH'].split(':')
    require(len(libs) == 2 and libs[0] == str(tc / 'lib'), 'recorded loader differs')
    for directory, group in [(tc, 'rust_toolchain'), (solver, 'solver_bin'), (Path(libs[1]), 'compat_libs')]:
        expected.update({str(directory / name): value for name, value in external[group].items()})
    require(expected == result['tool_sha256'], 'recorded runtime inventory differs')
    require(resolutions == {'cargo': rustup, 'rustup': rustup, 'rustc': str(tc / 'bin/rustc'),
                            **{name: str(solver / name) for name in external['solver_bin']}},
            'recorded tool resolution differs')
    source = Path(result['source'])
    output = source.with_name(source.name + '-proof')
    target = source.with_name(source.name + '-codegen') / 'target' if case == 'positive' else output / 'target'
    expected_env = {
        'HOME': '/home/nicola', 'USER': 'nicola', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
        'PATH': f'{output}/bin:/usr/bin:/bin',
        'RUSTUP_HOME': external['rustup_home'],
        'RUSTUP_TOOLCHAIN': config['compiler']['rust_toolchain'], 'RUSTUP_AUTO_INSTALL': '0',
        'CARGO_HOME': '/home/nicola/.cargo', 'CARGO_NET_OFFLINE': 'true',
        'CARGO_BUILD_JOBS': '2', 'CARGO_PROFILE_DEV_DEBUG': '0', 'CARGO_INCREMENTAL': '0',
        'CARGO_TARGET_DIR': str(target), 'RUSTFLAGS': '--emit=mir',
        'LD_LIBRARY_PATH': f'{tc}/lib:{driver.parents[3].parent}/kani-architecture/runtime-libs',
        'TMPDIR': str(output / 'tmp'),
    }
    require(env == expected_env, 'recorded compiler environment differs')


def recorded(config, profile=HERE):
    finite = read_json(profile / 'frozen/receipts/finite.json')
    require(finite['accepted'] is True and finite['dependency_source_auth_sha256'] ==
            sha(profile / 'frozen/receipts/dependency-source-auth.json'), 'finite/source identity differs')
    for name, expected in finite['fixture_sha256'].items():
        require(sha(profile / 'frozen' / name.removeprefix('src/')) == expected,
                'finite fixture differs')
    for item in finite['results']:
        log = gzip.decompress((profile / f"frozen/finite-logs/{item['name']}.log.gz").read_bytes())
        require(digest(log) == item['log_sha256'] and item['stop'] is None and
                item['exit'] == (101 if item['name'].endswith('-check') else 0),
                'finite log/exit differs')
    results = []
    for case in CASES:
        result_file = profile / f'frozen/receipts/{case}-result.json'
        result = read_json(result_file)
        accepted = read_json(profile / f'frozen/receipts/{case}-acceptance.json')
        require(accepted['result_sha256'] == sha(result_file) and
                accepted['freeze_sha256'] == result['codegen_freeze_sha256'] ==
                sha(profile / 'frozen/freeze.json') and
                result['finite_receipt_sha256'] == sha(profile / 'frozen/receipts/finite.json'),
                'recorded receipt binding differs')
        for name, expected in result['source_sha256'].items():
            path = 'lib.rs' if name == 'src/lib.rs' else f'inputs/{case}/{name}'
            require(sha(profile / 'frozen' / path) == expected, 'recorded proof input differs')
        require(set(result['source_sha256']) == {'Cargo.toml', 'Cargo.lock', 'src/lib.rs'},
                'recorded source census differs')
        recorded_runtime(result, case)
        if case != 'positive':
            # Only library bytes change. Cargo's installation marker is inert metadata.
            files = archive_files('block-buffer-0.10.4')
            actual = {name: digest(data) for name, data in files.items()}
            actual['src/lib.rs'] = config['cases'][case]['block_buffer_lib_sha256']
            actual['.cargo-ok'] = digest(b'{"v":1}')
            require(result['mutation_files'] == actual and result['mutation_source_sha256'] ==
                    actual['src/lib.rs'], 'recorded mutant has additional source changes')
        log = gzip.decompress((profile / f'frozen/logs/{case}.log.gz').read_bytes())
        require(digest(log) == result['log_sha256'] == config['cases'][case]['raw_log_sha256'],
                'recorded log identity differs')
        results.append(accept(config, case, log.decode(), result['exit'], result['stop'], profile))
    return results


if __name__ == '__main__':
    try:
        config = sources()
        print(json.dumps({'source_binding': 'accepted', 'fresh_solver_execution': False,
                          'recorded_cases': recorded(config)}, indent=2))
    except (Rejected, OSError, ValueError, KeyError) as error:
        sys.exit(f'REJECTED: {error}')
