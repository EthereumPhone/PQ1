#!/usr/bin/env python3
"""Validate this frozen research profile and its recorded symbolic evidence.

This command does not execute Kani. See replay.py for fresh solver execution.
"""
from collections import Counter
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
CASES = ('single-block', 'two-blocks', 'wrong-endian', 'wrong-threshold')
ASSERTIONS = {
    1: (39, 9, 'final_pos == 0'),
    12: (58, 13, 'blocks[1][i] == second'),
    13: (52, 13, 'blocks[0][i] == first'),
    14: (38, 9, 'count == if single { 1 } else { 2 }'),
}
COVERS = ('empty partial block', 'last one-block position',
          'first two-block position', 'last two-block position',
          'all length bits set', 'zero encoded length')


class Rejected(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise Rejected(message)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    def unique(pairs):
        out = {}
        for key, value in pairs:
            require(key not in out, f'duplicate JSON key: {key}')
            out[key] = value
        return out
    return json.loads(Path(path).read_text(), object_pairs_hook=unique)


def lock_closure(lock, name='sphincs-c10', version='0.1.0'):
    packages = tomllib.loads(Path(lock).read_text())['package']
    seen = {}

    def select(name, version=None, source=None):
        matches = [p for p in packages if p['name'] == name and
                   (version is None or p['version'] == version) and
                   (source is None or p.get('source') == source)]
        require(len(matches) == 1, f'ambiguous/missing Cargo package: {name} {version}')
        return matches[0]

    def visit(package):
        key = (package['name'], package['version'], package.get('source', ''))
        if key in seen:
            return
        seen[key] = package
        for dep in package.get('dependencies', []):
            parts = dep.split()
            require(1 <= len(parts) <= 3, f'unrecognized Cargo dependency: {dep}')
            visit(select(parts[0], parts[1] if len(parts) > 1 else None,
                         parts[2].strip('()') if len(parts) > 2 else None))

    visit(select(name, version))
    return sorted(seen.values(), key=lambda p: (p['name'], p['version'], p.get('source', '')))


def sources(profile=HERE, root=ROOT):
    config = read_json(profile / 'profile.json')
    require(config['format'] == 1, 'unsupported profile format')
    require(set(config['cases']) == set(CASES), 'missing/extra case')
    require({p.relative_to(profile).as_posix() for p in (profile / 'frozen').rglob('*')
             if p.is_file()} == set(config['frozen_sha256']), 'unlisted/missing frozen file')
    for name, expected in config['frozen_sha256'].items():
        require(sha(profile / name) == expected, f'frozen input changed: {name}')
    for name, expected in config['production_sources'].items():
        require(sha(root / name) == expected, f'consumer source changed: {name}')
    require(lock_closure(root / 'Cargo.lock') ==
            read_json(profile / 'frozen/consumer-lock-closure.json'),
            'selected C10 dependency closure changed')
    lines = (profile / 'frozen/lib.rs').read_text().splitlines()
    for line, _, expr in ASSERTIONS.values():
        require(lines[line - 1].strip() == f'assert!({expr});', 'intended assertion changed')
    return config


def properties(text):
    sections = re.split(r'(?=Checking harness )', text)
    require(len(sections) == 2, 'expected exactly one harness result')
    section = sections[1]
    rows = {}
    for index, block in enumerate(re.split(r'(?=Check \d+:)', section)[1:], 1):
        match = re.fullmatch(r'Check (\d+): (.+)', block.splitlines()[0])
        require(match is not None and int(match[1]) == index, 'invalid check numbering')
        prop = match[2]
        require(prop not in rows, f'duplicate property: {prop}')
        row = {}
        for field in ('Status', 'Description', 'Location'):
            vals = [line.strip().removeprefix(f'- {field}: ') for line in block.splitlines()
                    if line.strip().startswith(f'- {field}: ')]
            require(len(vals) <= 1 if field == 'Location' else len(vals) == 1,
                    f'missing/duplicate {field} for {prop}')
            row[field] = vals[0] if vals else ''
        allowed = ('SATISFIED', 'UNSATISFIABLE', 'UNREACHABLE') if '.cover.' in prop else (
            'SUCCESS', 'FAILURE', 'UNREACHABLE')
        require(row['Status'] in allowed, f'invalid property status: {prop}: {row["Status"]}')
        rows[prop] = row
    require(bool(rows), 'no properties')
    return section, rows


def accept(config, name, text, exit_code, stop=None):
    require(name in CASES, 'unknown case')
    case = config['cases'][name]
    require(exit_code == case['expected_exit'] and stop is None,
            'execution failed, timed out or stopped')
    section, rows = properties(text)
    require(len(rows) == case['property_count'] == 641, 'property census changed')
    require(digest(('\n'.join(sorted(rows)) + '\n').encode()) == case['property_names_sha256'],
            'property identities changed')
    verdict = 'FAILED' if case['expected_exit'] else 'SUCCESSFUL'
    require(re.findall(r'VERIFICATION:- (\w+)', section) == [verdict], 'wrong/missing verdict')
    failed = 13 if name == 'wrong-endian' else 14 if name == 'wrong-threshold' else None
    expected_failures = {f'proofs::check.assertion.{failed}'} if failed else set()
    require({p for p, row in rows.items() if row['Status'] == 'FAILURE'} == expected_failures,
            'unexpected failure or missing intended failure')
    for number, (line, column, expression) in ASSERTIONS.items():
        row = rows[f'proofs::check.assertion.{number}']
        require(row['Status'] == ('FAILURE' if number == failed else 'SUCCESS'),
                'intended assertion missing/unreachable/wrong status')
        require(row['Description'] == json.dumps('assertion failed: ' + expression),
                'wrong assertion description')
        require(row['Location'] == f'src/lib.rs:{line}:{column} in function proofs::check',
                'wrong assertion source location')
    reachable = {3, 4, 5, 6} if name == 'two-blocks' else {1, 2, 5, 6}
    for number, description in enumerate(COVERS, 1):
        row = rows[f'proofs::check.cover.{number}']
        status = 'SATISFIED' if number in reachable else 'UNREACHABLE'
        if name == 'wrong-threshold' and number == 2:
            status = 'UNSATISFIABLE'
        require(row['Status'] == status and row['Description'] == json.dumps(description),
                f'wrong cover result: {description}')
    return {'case': name, 'accepted': True, 'statuses': dict(Counter(r['Status'] for r in rows.values()))}


def recorded(config, profile=HERE):
    results = []
    for name in CASES:
        data = gzip.decompress((profile / f'frozen/logs/{name}.log.gz').read_bytes())
        result = read_json(profile / f'frozen/receipts/{name}-result.json')
        accepted = read_json(profile / f'frozen/receipts/{name}-acceptance.json')
        identity_path = profile / f'frozen/receipts/{name}-identity.json'
        identity = read_json(identity_path)
        require(accepted['accepted'] is True and sha(identity_path) == accepted['identity_sha256'],
                'original acceptance identity differs')
        require(sha(profile / f'frozen/receipts/{name}-result.json') == accepted['result_sha256'],
                'original execution receipt differs')
        require(accepted.get('source_sha256', accepted.get('harness_sha256')) ==
                sha(profile / 'frozen/lib.rs'), 'recorded harness differs')
        runtime = read_json(profile / 'frozen/kani-runtime.json')
        for tool in ('kani-compiler', 'kani-driver'):
            matching = [value for path, value in identity.items()
                        if path.endswith('/target/kani/bin/' + tool)]
            require(matching == [runtime['target/kani/bin/' + tool]], 'recorded compiler differs')
        require(digest(data) == config['cases'][name]['raw_log_sha256'] == result['log_sha256'],
                'recorded raw log identity changed')
        argv = result['command']
        require(argv[1:3] == ['kani', '--manifest-path'] and argv[4:] == [
            '--lib', '--harness', config['cases'][name]['harness'], '-Z', 'uninit-checks',
            '-Z', 'valid-value-checks', '--keep-temps'], 'recorded proof flags changed')
        results.append(accept(config, name, data.decode(), result['exit'], result['stop']))
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-only', action='store_true')
    args = parser.parse_args()
    config = sources()
    result = {'source_binding': 'accepted', 'fresh_solver_execution': False}
    if not args.source_only:
        result['recorded_cases'] = recorded(config)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (Rejected, OSError, KeyError, ValueError) as error:
        sys.exit(f'REJECTED: {error}')
