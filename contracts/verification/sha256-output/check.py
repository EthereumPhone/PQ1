#!/usr/bin/env python3
"""Check the complete recorded output-serialization evidence; never run a solver."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile

sys.dont_write_bytecode = True
from common import CASES, HERE, Evidence, Rejected, input_contract, require, sha
import inputs

HARNESS = 'core_api::output_assembly_probe::arbitrary_final_state_serialization'
ROOTS = [
    ('assertion', 189, 'output is final-state big-endian byte'),
    ('assertion', 190, 'finalization preserves input block counter'),
    ('assertion', 191, 'finalization resets buffer position'),
    ('cover', 193, 'empty buffered suffix reaches final output'),
    ('cover', 194, 'last single-padding-block position reaches final output'),
    ('cover', 195, 'first double-padding-block position reaches final output'),
    ('cover', 196, 'last output byte and last representable length reach final output'),
]
COUNTS = {'positive': 2324, 'little-endian': 2324, 'omitted-word': 2330, 'unreachable': 2324}
TOOLS = {
    'compiler': '32e91c3c4f3b83d89134b29860600d19dd0dae2f7efdcc64c9c3ef87dd8f4083',
    'driver': '03bee8f729ee655fba3fdfb88c3dc0cde27598599e13f3575dd2a2fb75fbb6fe',
    'backend': 'a5d237b4eda1d0193d1fbfc15e02aac7e74ecf7c9a8741c5d296389177a81e6f',
}
FLAGS = ['--no-malloc-may-fail', '--no-undefined-shift-check', '--no-signed-overflow-check',
         '--nan-check', '--no-self-loops-to-assumptions', '--no-pointer-primitive-check',
         '--object-bits', '16', '--sat-solver', 'minisat2', '--slice-formula', '--unwinding-assertions']


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pinned_stage(evidence, pins, expected):
    require(all(pins.get(path) == value for path, value in expected.items()),
            'stage source/tool/artifact pins differ')
    for path, value in pins.items():
        if path in evidence.index:
            require(digest(evidence.raw(path)) == value, 'stage pin differs from archived bytes: ' + path)


def protocol(evidence, research):
    source = research / 'cbmc-negative-group-budget-candidate/scripts/pq1_budget'
    for name in ['pq1_partition.py', 'pq1_partition_anonymous.json',
                 'pq1_promoted_census.py', 'collect_continuation.py']:
        require(sha(evidence.profile / 'frozen/protocol' / name) ==
                evidence.index[str(source / name)]['raw_sha256'], 'protocol source changed')
    sys.path.insert(0, str(evidence.profile / 'frozen/protocol'))
    import collect_continuation
    return collect_continuation


def roots(properties, parser, case):
    groups = parser.groups(properties)
    required, intended = {}, None
    for kind, line, message in ROOTS:
        found = [name for name, row in properties.items()
                 if row['class'] == kind and row['sourceLocation'].get('file') == 'src/core_api.rs'
                 and row['sourceLocation'].get('function') == HARNESS
                 and row['sourceLocation'].get('line') == str(line)
                 and (row['description'] == message or row['description'].endswith('] ' + message))]
        require(len(found) == 1, 'missing or ambiguous semantic root: ' + message)
        name = found[0]
        required[name] = 'SUCCESS'
        group = next(g for g in groups if name in g)
        if kind == 'cover':
            require(len(group) == 2, 'cover pair changed')
            probe = next(n for n in group if n != name)
            require(properties[probe]['class'] == 'reachability_check', 'cover probe changed')
            required[probe] = required[name] = 'FAILURE' if case == 'positive' else 'SUCCESS'
        else:
            require(properties[name]['expression'] == 'FALSE' and group == [name], 'ordinary assertion lowering changed')
            if line == 189:
                intended = name
    require(len(required) == 11 and intended is not None, 'semantic root set changed')
    if case in ('little-endian', 'omitted-word'):
        required[intended] = 'FAILURE'
    return required, intended


def execution(evidence, folder, command, seconds, cpu, file_bytes, environment, case, research, allowed_exits):
    spec = evidence.json(folder / 'spec.json')
    run = folder / 'run'
    process = evidence.json(run / 'process.json')
    worker = evidence.json(run / 'worker.json')
    observer = evidence.json(run / 'observation.json')
    result = evidence.json(run / 'execution.json')
    expected = ['/usr/bin/prlimit', f'--cpu={cpu[0]}:{cpu[1]}',
                '--as=17179869184:17179869184', f'--fsize={file_bytes}:{file_bytes}',
                '--core=0:0', '--', *command]
    require(spec['command'] == expected and spec['active_seconds'] == seconds, 'command or process bounds changed')
    require(spec['environment'] == environment and spec['cwd'] == str(case / 'inputs/sha2-probe')
            and spec['output'] == str(run), 'execution environment/directory changed')
    require(spec['aggregate_cap'] == 106*1024**3 and spec['workspace'] == 4*1024**3
            and spec['host_floor'] == 10*1024**3 and spec['reserve'] == 32*1024**2
            and spec['storage_root'] == str(research), 'storage policy changed')
    require(0 <= spec['allocation_before'] <= worker['peak_bytes'] <
            min(spec['aggregate_cap']-spec['reserve'], spec['allocation_before']+spec['workspace']),
            'recorded storage bound exceeded')
    start, end = process['start_ns'], process['final_ns']
    require(end-start == seconds*10**9 and process['spec'] == str(folder / 'spec.json'), 'supervisor bound changed')
    host_command = ['/usr/bin/python3', '-B', str(research / 'corrected-digest/circular-backend-cadical-v1/execute.py'),
                    '--worker', str(folder / 'spec.json'), str(start), str(end)]
    require(process['command'] == observer['command'] == host_command, 'independent supervisor command changed')
    require(result['execution_complete'] is True and worker['exit'] == result['exit']
            and result['exit'] in allowed_exits and worker['stop'] is None and observer['stop'] is None
            and observer['exit'] == 0 and worker['zero_descendants'] is True
            and worker['cleanup_on_time'] is True and observer['zero_descendants'] is True,
            'incomplete, failed or unclean execution')
    require(worker['start_ns'] == start <= observer['launched_ns'] <= worker['child_exit_ns']
            <= worker['finished_ns'] <= observer['observed_exit_ns']
            <= observer['zero_descendants_ns'] < end, 'execution timing/cleanup order changed')
    require(result['seconds'] == (observer['zero_descendants_ns']-start)/10**9, 'elapsed-time receipt changed')
    require(all(x.get('proof_accepted', x.get('proof_credit', False)) is False
                for x in [worker, result, observer]), 'execution receipt improperly grants semantic credit')
    return result, evidence.raw(run / 'command.log').decode()


def runtime(evidence, root):
    research, parent = root.parent.parent, root.parent
    runtime_root = parent / 'circular-backend-cadical-v1'
    adoption = evidence.json(parent / 'combined-digest-private-adoption-v1.json')
    require(adoption['closure_checklist_complete'] is True and not adoption['mandatory_gaps']
            and not adoption['blocking_findings'], 'runtime adoption incomplete')
    for role, expected in TOOLS.items():
        require(adoption[role]['sha256'] == expected, 'different private runtime: ' + role)
    model = evidence.json(parent / 'promoted-full-runtime-v2.json')
    consumer = evidence.json(runtime_root / 'consumer-selection-runtime-v3.json')
    setup = evidence.json(runtime_root / 'setup-corrected.json')
    require(digest(evidence.raw(parent / 'promoted-full-runtime-v2.json')) == adoption['model_runtime']['sha256']
            and digest(evidence.raw(runtime_root / 'consumer-selection-runtime-v3.json')) ==
            adoption['runtime_environment']['consumer_profile']['sha256'], 'runtime selection differs from adoption')
    pins = {**model['files'], **consumer['pins']}
    for row in model['links']:
        require(row['source'] not in pins or pins[row['source']] == row['sha256'], 'model source binding conflicts')
        pins[row['source']] = pins[row['target']] = row['sha256']
    for role, expected in TOOLS.items():
        require(pins[adoption[role]['path']] == expected, 'selected runtime does not bind ' + role)
    recovery = runtime_root / 'runtime-recovery-v1'
    receipt = evidence.json(recovery / 'validation-v3/assessment.json')
    require(receipt['accepted'] is True and receipt['pinned_host_files'] == 13015
            and receipt['prepared_input_pins'] == 77504 and len(receipt['ownership_controls']) == 4,
            'runtime recovery scope changed')
    for name in ['runtime_binding.py', 'namespace.py', 'namespace_v4.py', 'snapshot.json',
                 'directory-groups.json', 'bindings-v3.args', 'validation-v3/assessment.json']:
        pins[str(recovery / name)] = digest(evidence.raw(recovery / name))
    return research, runtime_root, adoption, consumer, setup, pins


def source_and_translation(evidence, contract, kind, parser, runtime_info):
    root = Path(contract['historical_root'])
    research, runtime_root, adoption, consumer, setup, runtime_pins = runtime_info
    case = root if kind == 'positive' else root / 'controls-v1' / kind
    recorded_inputs = evidence.json(case / 'input-pins.json')
    with tempfile.TemporaryDirectory(prefix='sha256-output-inputs-') as temp:
        fresh = Path(temp) / 'case'
        expected = inputs.prepare(fresh, kind, evidence.profile)
        lock = 'inputs/sha2-probe/Cargo.lock'
        require(set(recorded_inputs) == {str(case / n) for n in expected if n != lock}, 'recorded source inventory changed')
        for name in expected:
            raw = (fresh / name).read_bytes()
            if name == 'inputs/sha2-probe/.cargo/config.toml':
                raw = raw.replace(json.dumps(str(fresh))[1:-1].encode(), json.dumps(str(case))[1:-1].encode())
            if name != lock:
                require(recorded_inputs[str(case / name)] == digest(raw), 'recorded input is not reconstructed source: ' + name)
        lock_sha = expected[lock]
    codegen = evidence.json(case / 'codegen/assessment.json')
    require(codegen['codegen_complete'] is True and codegen['solver_runs'] == 0
            and codegen['inputs_and_runtime_unchanged'] is True, 'translation did not complete')
    pins = evidence.json(case / 'codegen/pins.json')
    pinned_stage(evidence, pins, {**recorded_inputs, **runtime_pins})
    require(evidence.json(case / 'codegen/links.json') ==
            {str(root / 'bin' / name): target for name, target in consumer['bindings'].items()},
            'translation tool-resolution bindings changed')
    metadata_paths = [p for p in codegen['metadata_and_lock_pins'] if p.endswith('.kani-metadata.json')]
    require(len(metadata_paths) == 1 and codegen['metadata_and_lock_pins'][str(case / lock)] == lock_sha,
            'translation metadata/lock binding changed')
    metadata_path = metadata_paths[0]
    require(digest(evidence.raw(metadata_path)) == codegen['metadata_and_lock_pins'][metadata_path], 'metadata bytes differ')
    metadata = evidence.json(metadata_path)
    require(not metadata['unsupported_features'] and not metadata['test_harnesses']
            and not metadata['contracted_functions'] and metadata['autoharness_md'] is None
            and len(metadata['proof_harnesses']) == 1, 'unexpected translation metadata')
    harness = metadata['proof_harnesses'][0]
    require(harness['pretty_name'] == HARNESS and harness['original_file'] == 'src/core_api.rs'
            and (harness['original_start_line'], harness['original_end_line']) == (166, 198)
            and harness['contract'] is None and not harness['has_loop_contracts']
            and not harness['is_automatically_generated'] and not harness['is_bounded']
            and not harness['is_ctor_based'], 'harness identity/contracts changed')
    require(harness['attributes'] == {'kind': 'Proof', 'should_panic': False, 'solver': None,
            'unwind_value': 193, 'stubs': [], 'verified_stubs': []}, 'harness guards/stubs changed')
    environment = {k: setup['environment'][k] for k in ['HOME', 'USER', 'LANG', 'LC_ALL']}
    environment.update(PATH=str(root / 'bin')+':/usr/bin:/bin', RUSTUP_HOME=consumer['rustup_home'],
        RUSTUP_TOOLCHAIN=consumer['toolchain'], RUSTUP_AUTO_INSTALL='0', CARGO_HOME=str(case / 'cargo-home'),
        CARGO_NET_OFFLINE='true', CARGO_BUILD_JOBS='2', CARGO_PROFILE_DEV_DEBUG='0', CARGO_INCREMENTAL='0',
        CARGO_TARGET_DIR=str(case / 'target'), RUSTFLAGS='--emit=mir',
        LD_LIBRARY_PATH=setup['environment']['LD_LIBRARY_PATH'], TMPDIR=str(case / 'tmp'), PYTHONDONTWRITEBYTECODE='1')
    command = [adoption['driver']['path'], 'kani', '--manifest-path', str(case / 'inputs/sha2-probe/Cargo.toml'),
               '--lib', '--no-default-features', '--features', 'force-soft', '--harness', HARNESS,
               '-Z', 'uninit-checks', '-Z', 'valid-value-checks', '--solver', 'minisat', '--keep-temps', '--only-codegen']
    execution(evidence, case / 'codegen', command, 300 if kind == 'positive' else 180,
              (290, 295) if kind == 'positive' else (170, 175), 128*1024**2, environment, case, research, {0})
    symtab = Path(harness['goto_file'])
    linked = symtab.with_name(symtab.name.removesuffix('.symtab.out')+'.out')
    census_selection = evidence.json(case / 'census/selection.json')
    pinned_stage(evidence, census_selection['pins'], {**pins, **codegen['metadata_and_lock_pins']})
    for path in [metadata_path, str(symtab), str(linked)]:
        require(census_selection['pins'][path] == digest(evidence.raw(path)), 'translation-to-census artifact changed')
    program = case / 'census/prepared.out'
    base = [adoption['backend']['path'], *FLAGS, '--unwind', '193']
    bindings = consumer['bindings']
    commands = [
        ('entry', [bindings['goto-cc'], str(program), '--function', harness['mangled_name'], '-o', str(program)]),
        ('library', [bindings['goto-instrument'], '--add-library', '--no-malloc-may-fail', str(program), str(program)]),
        ('undefined', [bindings['goto-instrument'], '--generate-function-body-options', 'assert-false-assume-false',
                       '--generate-function-body', '.*', '--drop-unused-functions', str(program), str(program)]),
        ('backedges', [bindings['goto-instrument'], '--ensure-one-backedge-per-target', str(program), str(program)]),
        ('inventory', base + ['--show-properties', '--json-ui', str(program)]),
    ]
    require(census_selection['phases'] == [[a, b] for a, b in commands], 'preparation pipeline changed')
    before = digest(evidence.raw(linked))
    raw_census = None
    for name, command in commands:
        result, raw = execution(evidence, case / 'census' / name, command, 60, (50, 55),
                                128*1024**2, environment, case, research, {0})
        receipt = evidence.json(case / 'census' / name / 'receipt.json')
        require(receipt['execution'] == result and receipt['host_exit'] == 0
                and receipt['before_sha256'] == before and receipt['raw_log_sha256'] == digest(raw.encode()),
                'preparation receipt chain changed')
        before = receipt['after_sha256']
        if name == 'inventory':
            raw_census = raw
    require(before == digest(evidence.raw(program)), 'prepared program identity changed')
    assessment = evidence.json(case / 'census/assessment.json')
    properties = parser.census(raw_census)
    require(properties == evidence.json(case / 'census/properties.json') and len(properties) == COUNTS[kind]
            and assessment['program_sha256'] == before and assessment['base_command'] == base
            and assessment['preparation_and_census_complete'] is True
            and assessment['source_and_runtime_unchanged'] is True and assessment['solver_queries'] == 0,
            'complete census changed')
    expected_pins = {**pins, **codegen['metadata_and_lock_pins'], str(program): before,
                     str(case / 'census/properties.json'): digest(evidence.raw(case / 'census/properties.json'))}
    return case, environment, program, base, properties, expected_pins


def recorded_case(evidence, contract, kind, collector, runtime_info):
    parser = collector.partition
    root = Path(contract['historical_root'])
    research = runtime_info[0]
    case, environment, program, base, properties, expected_pins = source_and_translation(
        evidence, contract, kind, parser, runtime_info)
    required, intended = roots(properties, parser, kind)
    if kind == 'unreachable':
        pinned_stage(evidence, evidence.json(case / 'verification/pins.json'), expected_pins)
        command = list(base)
        command[-1] = '65'
        result, raw = execution(evidence, case / 'verification', command+['--verbosity', '8', str(program)],
                                180, (170, 175), 16*1024**2, environment, case, research, {0, 10})
        report = parser.parse_report(raw, properties, list(properties), result['exit'])
        parser.semantic_check(properties, report, required)
        positive_required, _ = roots(properties, parser, 'positive')
        try:
            parser.semantic_check(properties, report, positive_required)
        except ValueError as error:
            require(str(error) == 'required root unreachable or wrong', 'unreachable control refused for another reason')
        else:
            raise Rejected('unreachable assertions accepted as positive evidence')
        return {'case': kind, 'static_properties': len(properties), 'expected_nonvacuity_refusal': True}
    if kind == 'positive':
        selection = evidence.json(root / 'root-probe-unwind65/selection.json')
        root_folder, tail_folder = root / 'root-probe-unwind65', root / 'tail-probe-v1'
        refinement = evidence.json(root / 'unwind-refinement-selection-v1.json')
        base = base + ['--verbosity', '8', '--unwindset', refinement['loop_id']+':65']
        tail_manifest = tail_folder / 'groups.json'
        expected_failure = None
        pin_folders = [root_folder, tail_folder]
    else:
        folder = case / 'partitioned-v1'
        selection = evidence.json(folder / 'selection.json')
        root_folder, tail_folder = folder / 'root', folder / 'tail'
        base[-1] = '65'
        base += ['--verbosity', '8']
        tail_manifest = folder / 'groups.json'
        expected_failure = intended
        pin_folders = [folder]
    for pin_folder in pin_folders:
        pinned_stage(evidence, evidence.json(pin_folder / 'pins.json'), expected_pins)
    parts = selection['parts']
    require(selection['required'] == required and len(parts) == 19, 'selected semantic roots/partition count changed')
    parser.validate_partition(properties, parts, list(required))
    require(evidence.json(tail_manifest) == parts[1:], 'tail selection changed')
    command = base + [arg for name in parts[0] for arg in ['--property', name]] + [str(program)]
    result, raw = execution(evidence, root_folder, command, 180, (170, 175), 16*1024**2,
                            environment, case, research, {0, 10})
    root_report = parser.parse_report(raw, properties, parts[0], result['exit'])
    parser.semantic_check(properties, root_report, required, expected_failure)
    command = base + ['--flush', '--pq1-scoped-partitions', str(tail_manifest), '--pq1-scoped-partial', str(program)]
    result, raw = execution(evidence, tail_folder, command, 900, (890, 895), 16*1024**2,
                            environment, case, research, {0, 10})
    tails = collector.parse_partial(raw, properties, parts[1:], result['exit'])
    summary = collector.compose_reports(properties, parts, list(range(19)), root_report, tails, required, expected_failure)
    require(summary['dynamic_count'] == (1 if kind == 'positive' else 0), 'dynamic unwind inventory changed')
    return {'case': kind, **summary}


def check(profile=HERE):
    contract = input_contract(profile)
    evidence = Evidence(profile)
    count = evidence.authenticate_all()
    root = Path(contract['historical_root'])
    runtime_info = runtime(evidence, root)
    collector = protocol(evidence, root.parent.parent)
    cases = [recorded_case(evidence, contract, kind, collector, runtime_info) for kind in CASES]
    return {'recorded_evidence_complete': True, 'archived_artifacts': count, 'cases': cases,
            'solver_replay': False, 'full_Digest_correspondence': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    try:
        print(json.dumps(check(), indent=2))
    except (Rejected, OSError, ValueError, KeyError) as error:
        sys.exit(f'REJECTED: {error}')
