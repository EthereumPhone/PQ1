#!/usr/bin/env python3
"""Reconstruct original dependency bytes and two isolated semantic controls."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from streaming import CASES, HERE, SHARED, Rejected, read_json, require, sha, sources
from prepare import extract


def prepare(output, profile=HERE):
    config = sources(profile)
    output = output.resolve()
    require(not output.exists() and not output.is_relative_to(profile),
            'use a new preparation directory outside the profile')
    output.mkdir(parents=True)
    vendor = output / 'vendor'
    vendor.mkdir()
    for stem, checksum in read_json(SHARED / 'profile.json')['crates'].items():
        extract(SHARED / f'frozen/crates/{stem}.crate', vendor, stem)
        package = vendor / stem
        files = {p.relative_to(package).as_posix(): sha(p) for p in package.rglob('*') if p.is_file()}
        (package / '.cargo-checksum.json').write_text(json.dumps({'files': files, 'package': checksum}))
    for name in CASES:
        case = output / name
        (case / 'src').mkdir(parents=True)
        (case / '.cargo').mkdir()
        for file in ('lib.rs', 'main.rs', 'reference.rs'):
            shutil.copyfile(profile / 'frozen' / file, case / 'src' / file)
        for file in ('Cargo.toml', 'Cargo.lock'):
            shutil.copyfile(profile / f'frozen/inputs/{name}/{file}', case / file)
        block = vendor / 'block-buffer-0.10.4'
        if name != 'positive':
            block = case / 'dependency'
            shutil.copytree(vendor / 'block-buffer-0.10.4', block)
            subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                            str(profile / f'frozen/{name}.patch')], cwd=block, check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            # A path dependency has no registry checksum; remove only Cargo's generated inventory.
            (block / '.cargo-checksum.json').unlink()
        require(sha(block / 'src/lib.rs') == config['cases'][name]['block_buffer_lib_sha256'],
                'reconstructed block-buffer differs from proof input')
        (case / '.cargo/config.toml').write_text(
            '[source.crates-io]\nreplace-with = "frozen"\n[source.frozen]\ndirectory = ' +
            json.dumps(vendor.as_posix()) + '\n')
    inventory = {p.relative_to(output).as_posix(): sha(p) for p in output.rglob('*') if p.is_file()}
    receipt = {'profile_sha256': sha(profile / 'profile.json'), 'files': inventory,
               'scope': 'Reconstruction only; no compiler or solver executed.'}
    (output / 'prepared.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


def check_prepared(output, profile=HERE):
    output = output.resolve()
    require(not any(p.is_symlink() for p in output.rglob('*')), 'prepared input symlink')
    with tempfile.TemporaryDirectory(prefix='streaming-input-check-', dir=output.parent) as temp:
        reference = Path(temp) / 'inputs'
        expected = prepare(reference, profile)['files']
        actual = {p.relative_to(output).as_posix() for p in output.rglob('*') if p.is_file()}
        diagnostics = {f'{name}/points-to.dot' for name in CASES}
        require(actual - diagnostics - {'prepared.json'} == set(expected), 'prepared inventory differs')
        for name, expected_sha in expected.items():
            if name.endswith('/.cargo/config.toml'):
                text = (reference / name).read_text().replace(
                    json.dumps(reference.as_posix())[1:-1], json.dumps(output.as_posix())[1:-1])
                require((output / name).read_text() == text, 'prepared source configuration differs')
            else:
                require(sha(output / name) == expected_sha, f'prepared input differs: {name}')
    return {name: sha(output / name) for name in expected}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    try:
        result = prepare(args.output)
        print(json.dumps({'prepared_files': len(result['files']), 'output': str(args.output)}))
    except (Rejected, OSError, ValueError, subprocess.CalledProcessError) as error:
        sys.exit(f'REJECTED: {error}')
