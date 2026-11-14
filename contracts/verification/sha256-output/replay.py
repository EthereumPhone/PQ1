#!/usr/bin/env python3
"""Replay one archived prepared GOTO program on the exact retained runtime.

This reruns the solver, not the Rust compiler. It never overwrites historical
evidence or accepts a timeout as a negative control. Run inside the retained
runtime namespace documented in README.md.
"""
import argparse
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
import check
import inputs
from common import CASES, HERE, Evidence, Rejected, input_contract, read_json, require, sha


def write(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def selected_queries(evidence, contract, kind):
    root = Path(contract['historical_root'])
    case = root if kind == 'positive' else root / 'controls-v1' / kind
    if kind == 'unreachable':
        return case, [case / 'verification'], None
    folder = root / 'root-probe-unwind65' if kind == 'positive' else case / 'partitioned-v1'
    parts = evidence.json(folder / 'selection.json')['parts']
    folders = ([folder, root / 'tail-probe-v1'] if kind == 'positive'
               else [folder / 'root', folder / 'tail'])
    return case, folders, parts


def relocate_spec(original, old_program, old_groups, output, phase, allocation):
    """Only filesystem placement changes; flags, property IDs and caps remain."""
    spec = json.loads(json.dumps(original))
    replacements = {str(old_program): str(output / 'prepared.out')}
    if old_groups is not None:
        replacements[str(old_groups)] = str(output / 'groups.json')
    spec['command'] = [replacements.get(arg, arg) for arg in spec['command']]
    require(spec['command'][-1] == str(output / 'prepared.out'), 'unrecognized prepared-program argument')
    if '--pq1-scoped-partitions' in spec['command']:
        i = spec['command'].index('--pq1-scoped-partitions') + 1
        require(spec['command'][i] == str(output / 'groups.json'), 'unrecognized group-manifest argument')
    spec['cwd'] = str(output / 'inputs/sha2-probe')
    spec['output'] = str(output / phase / 'run')
    spec['allocation_before'] = allocation
    environment = spec['environment']
    environment.update(PATH=str(output / 'bin')+':/usr/bin:/bin',
                       CARGO_HOME=str(output / 'cargo-home'), CARGO_TARGET_DIR=str(output / 'target'),
                       TMPDIR=str(output / 'tmp'))
    return spec


def authenticate(pins, links):
    for path, expected in pins.items():
        require(sha(path) == expected, 'retained runtime or replay input changed: ' + path)
    for path, target in links.items():
        require(os.readlink(path) == target, 'replay tool link changed: ' + path)


class LiveEvidence:
    """Read the new command receipts with the same execution checks as CI."""
    @staticmethod
    def raw(path):
        return Path(path).read_bytes()

    @staticmethod
    def json(path):
        return read_json(path)


def run(output, kind):
    require(sys.flags.optimize == 0, 'optimized Python disables retained runtime assertions')
    contract, evidence = input_contract(), Evidence()
    # Validate the archived source-to-program and semantic evidence before reuse.
    check.check()
    root = Path(contract['historical_root'])
    research, runtime_root, _, consumer, _, pins = check.runtime(evidence, root)
    output = output.resolve()
    repo = HERE.parents[2]
    require(not output.exists() and output.is_relative_to(research)
            and not output.is_relative_to(repo), 'use a new external directory under the retained research root')
    recovery = runtime_root / 'runtime-recovery-v1'
    # Authenticate local helper code before importing or executing it. The
    # namespace checks its full host snapshot and read-only mounts independently.
    for original, entry in evidence.index.items():
        if entry['artifact'].startswith('frozen/runners/supervision/') or original == str(runtime_root / 'execute.py'):
            pins[original] = entry['raw_sha256']
    authenticate(pins, {})
    sys.path.insert(0, str(recovery))
    binding = importlib.import_module('runtime_binding')
    require(Path(binding.__file__).resolve() == recovery / 'runtime_binding.py', 'wrong runtime-binding module')
    require(binding.require_runtime() == {p: pins[p] for p in pins if Path(p).is_relative_to(recovery)},
            'mounted runtime identity differs')
    available = int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines()
                         if line.startswith('MemAvailable:'))) * 1024
    require(available >= 32*1024**3, 'insufficient available memory for selected profile')
    inputs.prepare(output, kind)
    inputs.check_prepared(output, kind)
    case, folders, parts = selected_queries(evidence, contract, kind)
    program = case / 'census/prepared.out'
    (output / 'prepared.out').write_bytes(evidence.raw(program))
    properties = evidence.json(case / 'census/properties.json')
    if parts is not None:
        write(output / 'groups.json', parts[1:])
    for name in ['bin', 'tmp', 'cargo-home']:
        (output / name).mkdir()
    links = {}
    for name, target in consumer['bindings'].items():
        path = output / 'bin' / name
        require(target in pins, 'unbound runtime tool: ' + name)
        path.symlink_to(target)
        links[str(path)] = target
    pins.update({str(path): sha(path) for path in output.rglob('*') if path.is_file() and not path.is_symlink()})
    for path in [HERE / name for name in ['common.py', 'inputs.py', 'check.py', 'replay.py']]:
        pins[str(path)] = sha(path)
    selection = {'case': kind, 'prepared_program_sha256': sha(output / 'prepared.out'),
                 'recorded_source_translation_reused': True, 'fresh_source_translation': False,
                 'queries': [str(folder) for folder in folders], 'chains': 1,
                 'stop': 'Stop on the first identity, resource, execution or semantic failure; no automatic retry.'}
    write(output / 'selection.json', selection)
    pins[str(output / 'selection.json')] = sha(output / 'selection.json')
    write(output / 'pins.json', pins)
    write(output / 'links.json', links)
    collector = check.protocol(evidence, research)
    parser = collector.partition
    required, intended = check.roots(properties, parser, kind)
    reports = []
    for index, folder in enumerate(folders):
        phase = 'whole' if kind == 'unreachable' else ('root' if index == 0 else 'tail')
        original = evidence.json(folder / 'spec.json')
        groups = None if '--pq1-scoped-partitions' not in original['command'] else Path(
            original['command'][original['command'].index('--pq1-scoped-partitions') + 1])
        allocation = int(subprocess.check_output(['/usr/bin/du', '-s', '-B1', '--', str(research)],
                                                timeout=15).split()[0])
        spec = relocate_spec(original, program, groups, output, phase, allocation)
        spec['selection_sha256'] = sha(output / 'selection.json')
        require(all(spec[key] == value for key, value in {
            'aggregate_cap': 106*1024**3, 'workspace': 4*1024**3,
            'host_floor': 10*1024**3, 'reserve': 32*1024**2, 'storage_root': str(research)}.items()),
            'unselected storage policy')
        require(allocation + spec['workspace'] + spec['reserve'] < spec['aggregate_cap']
                and shutil.disk_usage(research).free > spec['host_floor']+spec['workspace']+spec['reserve'],
                'insufficient selected storage headroom')
        authenticate(pins, links)
        binding.require_runtime()
        location = output / phase
        location.mkdir()
        write(location / 'spec.json', spec)
        print(json.dumps({'case': kind, 'phase': phase, 'active_seconds': spec['active_seconds']}), flush=True)
        with (location / 'host.log').open('x') as log:
            host = subprocess.run(['/usr/bin/python3', '-B', str(runtime_root / 'execute.py'),
                                   str(location / 'spec.json')], stdout=log, stderr=subprocess.STDOUT)
        authenticate(pins, links)
        binding.require_runtime()
        require(host.returncode == 0, 'independent execution did not complete')
        inner = spec['command'][spec['command'].index('--') + 1:]
        seconds, cpu = (900, (890, 895)) if phase == 'tail' else (180, (170, 175))
        result, raw = check.execution(LiveEvidence(), location, inner, seconds, cpu, 16*1024**2,
                                      spec['environment'], output, research, {0, 10})
        if phase == 'tail':
            reports.extend(collector.parse_partial(raw, properties, parts[1:], result['exit']))
        else:
            selected = list(properties) if parts is None else parts[0]
            report = parser.parse_report(raw, properties, selected, result['exit'])
            parser.semantic_check(properties, report, required,
                                  intended if kind in ('little-endian', 'omitted-word') else None)
            reports.append(report)
    if kind == 'unreachable':
        positive_required, _ = check.roots(properties, parser, 'positive')
        try:
            parser.semantic_check(properties, reports[0], positive_required)
        except ValueError as error:
            require(str(error) == 'required root unreachable or wrong', 'wrong unreachable-control refusal')
        else:
            raise Rejected('unreachable control received positive credit')
        summary = {'expected_nonvacuity_refusal': True, 'static_count': len(properties)}
    else:
        summary = collector.compose_reports(properties, parts, list(range(19)), reports[0], reports[1:], required,
                                            intended if kind != 'positive' else None)
        require(summary['dynamic_count'] == (1 if kind == 'positive' else 0), 'dynamic inventory changed')
    authenticate(pins, links)
    result = {'case': kind, 'prepared_program_replay_complete': True, 'fresh_source_translation': False,
              'full_Digest_correspondence': False, 'summary': summary}
    write(output / 'assessment.json', result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--case', choices=CASES, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.output, args.case), indent=2))
    except (Rejected, OSError, ValueError, KeyError, AssertionError, subprocess.SubprocessError) as error:
        sys.exit(f'REJECTED: {error}')
