#!/usr/bin/env python3
"""Reconstruct isolated proof crates from the authenticated archived packages."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile

sys.dont_write_bytecode = True
from verify import CASES, HERE, Rejected, require, sha, sources


def extract(archive, destination, stem):
    with tarfile.open(archive, 'r:gz') as tar:
        for member in tar.getmembers():
            path = Path(member.name)
            require(path.parts and path.parts[0] == stem and '..' not in path.parts and
                    not path.is_absolute() and (member.isfile() or member.isdir()),
                    'unexpected crate member')
        tar.extractall(destination, filter='data')


def prepare(output, profile=HERE):
    config = sources(profile)
    output = output.resolve()
    require(not output.exists() and not output.is_relative_to(profile),
            'preparation requires a new directory outside the profile')
    output.mkdir(parents=True)
    vendor = output / 'vendor'
    vendor.mkdir()
    for stem, checksum in config['crates'].items():
        archive = profile / f'frozen/crates/{stem}.crate'
        require(sha(archive) == checksum, 'crate archive changed')
        extract(archive, vendor, stem)
        root = vendor / stem
        files = {p.relative_to(root).as_posix(): sha(p) for p in sorted(root.rglob('*'))
                 if p.is_file()}
        (root / '.cargo-checksum.json').write_text(json.dumps({'files': files, 'package': checksum}))
    generic = output / 'generic-array'
    shutil.copytree(vendor / 'generic-array-0.14.7', generic)
    require(sha(generic / 'src/lib.rs') == config['generic_array_original_lib_sha256'],
            'original generic-array source changed')
    # Both the published crate and retained correction use CRLF. Apply the LF
    # patch to a normalized buffer, then restore the original line endings.
    lib = generic / 'src/lib.rs'
    lib.write_bytes(lib.read_bytes().replace(b'\r\n', b'\n'))
    subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                    str(profile / 'frozen/generic-array.patch')], cwd=generic, check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    lib.write_bytes(lib.read_bytes().replace(b'\n', b'\r\n'))
    require(sha(generic / 'src/lib.rs') == config['generic_array_corrected_lib_sha256'],
            'corrected generic-array source differs')
    for name in CASES:
        case = output / name
        (case / 'src').mkdir(parents=True)
        (case / '.cargo').mkdir()
        manifest = (profile / 'frozen/Cargo.toml.in').read_text().replace(
            '"@GENERIC_ARRAY@"', json.dumps(generic.as_posix()))
        if name.startswith('wrong-'):
            block = output / f'block-buffer-{name}'
            shutil.copytree(vendor / 'block-buffer-0.10.4', block)
            subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                            str(profile / f'frozen/{name}.patch')], cwd=block, check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            manifest += f'block-buffer = {{ path = {json.dumps(block.as_posix())} }}\n'
        else:
            block = vendor / 'block-buffer-0.10.4'
        require(sha(block / 'src/lib.rs') == config['cases'][name]['block_buffer_lib_sha256'],
                'block-buffer source differs')
        (case / 'Cargo.toml').write_text(manifest)
        shutil.copyfile(profile / 'frozen/lib.rs', case / 'src/lib.rs')
        shutil.copyfile(profile / f'frozen/locks/{name}.lock', case / 'Cargo.lock')
        (case / '.cargo/config.toml').write_text(
            '[source.crates-io]\nreplace-with = "frozen"\n'
            '[source.frozen]\ndirectory = ' + json.dumps(vendor.as_posix()) + '\n')
    inventory = {p.relative_to(output).as_posix(): sha(p) for p in sorted(output.rglob('*'))
                 if p.is_file()}
    receipt = {'profile_sha256': sha(profile / 'profile.json'), 'files': inventory,
               'scope': 'Input reconstruction only; no compiler or solver executed.'}
    (output / 'prepared.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


def check_prepared(output, profile=HERE):
    """Re-derive expected bytes; a self-reported prepared.json is not authority."""
    output = output.resolve()
    with tempfile.TemporaryDirectory(prefix='padding-input-check-', dir=output.parent) as temp:
        reference = Path(temp) / 'inputs'
        expected = prepare(reference, profile)['files']
        actual = {p.relative_to(output).as_posix() for p in output.rglob('*') if p.is_file()}
        diagnostics = {f'{name}/points-to.dot' for name in CASES}
        require(actual - diagnostics - {'prepared.json'} == set(expected),
                'prepared source inventory changed')
        relocated = {f'{name}/{file}' for name in CASES
                     for file in ('Cargo.toml', '.cargo/config.toml')}
        for name, expected_sha in expected.items():
            if name in relocated:
                text = (reference / name).read_text().replace(
                    json.dumps(reference.as_posix())[1:-1], json.dumps(output.as_posix())[1:-1])
                require((output / name).read_text() == text, f'prepared configuration changed: {name}')
            else:
                require(sha(output / name) == expected_sha, f'prepared input changed: {name}')
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
