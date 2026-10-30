#!/usr/bin/env python3
"""Reconstruct the constructor projects and their exact dependency variants."""
import argparse
import json
from pathlib import Path
import shutil
import sys
import tempfile

sys.dont_write_bytecode = True
from check import HERE, PARENT, Rejected, read_json, require, sha, sources
import prepare as padding_prepare


def prepare(output, profile=HERE):
    config = sources(profile)
    output = output.resolve()
    require(not output.exists() and not output.is_relative_to(profile), 'use a new external directory')
    output.mkdir(parents=True)
    padding_prepare.prepare(output / 'inputs', PARENT)
    for name, edit in config['mutations'].items():
        target = output / 'mutants' / name
        shutil.copytree(output / 'inputs/generic-array', target)
        lib = target / 'src/lib.rs'
        old, new = bytes.fromhex(edit['old_hex']), bytes.fromhex(edit['new_hex'])
        raw = lib.read_bytes()
        require(raw.count(old) == 1, 'mutation anchor is not unique')
        lib.write_bytes(raw.replace(old, new))
        require(sha(lib) == edit['lib_sha256'], 'mutation differs')
    for project in config['projects']:
        target = output / project
        shutil.copytree(profile / 'frozen/projects' / project, target)
        for template in target.rglob('*.rs.in'):
            template.rename(template.with_suffix(''))
        for name in ('Cargo.toml', '.cargo/config.toml'):
            path = target / name
            # JSON escaping matches Cargo TOML basic strings used by these inputs.
            old = json.dumps(config['historical_root'])[1:-1]
            new = json.dumps(str(output))[1:-1]
            path.write_text(path.read_text().replace(old, new))
    inventory = {p.relative_to(output).as_posix(): sha(p) for p in output.rglob('*') if p.is_file()}
    (output / 'prepared.json').write_text(json.dumps({'profile_sha256': sha(profile / 'profile.json'),
                                                    'files': inventory}, indent=2) + '\n')
    return inventory


def check_prepared(output, profile=HERE):
    output = output.resolve()
    config = sources(profile)
    with tempfile.TemporaryDirectory(prefix='constructor-check-', dir=output.parent) as temp:
        reference = Path(temp) / 'expected'
        expected = prepare(reference, profile)
        diagnostics = {f'{name}/points-to.dot' for name in config['projects']}
        actual = {p.relative_to(output).as_posix() for p in output.rglob('*') if p.is_file()}
        require(actual - diagnostics - {'prepared.json'} == set(expected), 'prepared inventory changed')
        for name in expected:
            # Parent preparation and project manifests contain absolute paths.
            path = reference / name
            raw = path.read_bytes()
            if name.endswith(('Cargo.toml', 'config.toml', 'prepared.json')):
                raw = raw.replace(json.dumps(str(reference))[1:-1].encode(),
                                  json.dumps(str(output))[1:-1].encode())
            # The nested parent's prepared.json contains hashes of relocated
            # manifests. Its own validator reconstructs and checks them below.
            if name == 'inputs/prepared.json':
                continue
            require((output / name).read_bytes() == raw, f'prepared bytes changed: {name}')
        padding_prepare.check_prepared(output / 'inputs', PARENT)
    return {name: sha(output / name) for name in expected}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps({'prepared_files': len(prepare(args.output))}))
    except (Rejected, OSError, ValueError) as error:
        sys.exit(f'REJECTED: {error}')
