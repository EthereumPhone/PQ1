#!/usr/bin/env python3
"""Reconstruct one exact proof/control input from the archived crate sources."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile

sys.dont_write_bytecode = True
from common import CASES, HERE, Rejected, input_contract, require, sha


def extract(archive, destination, stem):
    with tarfile.open(archive, 'r:gz') as tar:
        members = tar.getmembers()
        names = set()
        for member in members:
            path = Path(member.name)
            require(path.parts and path.parts[0] == stem and '..' not in path.parts
                    and not path.is_absolute() and (member.isfile() or member.isdir()),
                    'unexpected archive member')
            require(member.name not in names, 'duplicate archive member')
            names.add(member.name)
        tar.extractall(destination, filter='data')


def controlled_source(upstream, harness, case):
    require(case in CASES, 'unknown case')
    source = upstream + harness
    if case in ('little-endian', 'omitted-word'):
        for old, new in [
            ('let initial_state: [u32; 8] = kani::any();', 'let initial_state: [u32; 8] = [0; 8];'),
            ('let initial_buffer: [u8; 64] = kani::any();', 'let initial_buffer: [u8; 64] = [0; 64];'),
            ('let initial_output: [u8; 32] = kani::any();', 'let initial_output: [u8; 32] = [0; 32];'),
            ('let position: usize = kani::any();', 'let position: usize = 0;'),
            ('let block_count: u64 = kani::any();', 'let block_count: u64 = 0;'),
            ('let byte_index: usize = kani::any();', 'let byte_index: usize = 31;'),
        ]:
            require(source.count(old) == 1, 'non-unique concrete-control input')
            source = source.replace(old, new)
        if case == 'little-endian':
            old, new = 'chunk.copy_from_slice(&v.to_be_bytes());', 'chunk.copy_from_slice(&v.to_le_bytes());'
            require(upstream.count(old) == 2, 'SHA-256/SHA-512 serialization anchors changed')
        else:
            old, new = 'out.chunks_exact_mut(4)', 'out[..28].chunks_exact_mut(4)'
            require(upstream.count(old) == 1, 'SHA-256 serialization anchor changed')
        source = source.replace(old, new, 1)
    elif case == 'unreachable':
        old = '        core.finalize_variable_core(&mut buffer, &mut output);'
        new = '        kani::assume(false); core.finalize_variable_core(&mut buffer, &mut output);'
        require(source.count(old) == 1, 'non-unique unreachable-control anchor')
        source = source.replace(old, new)
    return source


def prepare(output, case='positive', profile=HERE):
    contract = input_contract(profile)
    require(case in CASES, 'unknown case')
    output = output.resolve()
    require(not output.exists() and not output.is_relative_to(profile.resolve()),
            'use a new directory outside the profile')
    vendor = output / 'inputs/vendor'
    vendor.mkdir(parents=True)
    for stem, entry in contract['dependency_archives'].items():
        extract(profile / entry['path'], vendor, stem)
        root = vendor / stem
        files = {p.relative_to(root).as_posix(): sha(p) for p in sorted(root.rglob('*')) if p.is_file()}
        (root / '.cargo-checksum.json').write_text(
            json.dumps({'files': files, 'package': entry['sha256']}, sort_keys=True) + '\n')
    generic = output / 'inputs/generic-array-corrected'
    shutil.copytree(vendor / 'generic-array-0.14.7', generic)
    lib = generic / 'src/lib.rs'
    require(sha(lib) == contract['generic_array_original_lib_sha256'], 'original dependency source differs')
    lib.write_bytes(lib.read_bytes().replace(b'\r\n', b'\n'))
    subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                    str((profile / contract['generic_array_patch']['path']).resolve())],
                   cwd=generic, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    lib.write_bytes(lib.read_bytes().replace(b'\n', b'\r\n'))
    require(sha(lib) == contract['generic_array_corrected_lib_sha256'], 'corrected dependency source differs')
    project = output / 'inputs/sha2-probe'
    upstream = vendor / 'sha2-0.10.9'
    shutil.copytree(upstream / 'src', project / 'src')
    for name in ['LICENSE-MIT', 'LICENSE-APACHE']:
        shutil.copyfile(upstream / name, project / name)
    for name in ['Cargo.toml', 'Cargo.lock']:
        shutil.copyfile(profile / 'frozen/inputs' / name, project / name)
    (project / '.cargo').mkdir()
    (project / '.cargo/config.toml').write_text(
        '[source.crates-io]\nreplace-with = "prepared-vendor"\n'
        '[source.prepared-vendor]\ndirectory = ' + json.dumps(str(vendor)) + '\n')
    core = project / 'src/core_api.rs'
    require(sha(core) == contract['upstream_core_api_sha256'], 'upstream SHA-256 core changed')
    core.write_text(controlled_source(core.read_text(), (profile / 'frozen/inputs/harness.rs.in').read_text(), case))
    require(sha(core) == contract['case_source_sha256'][case], 'prepared case source differs')
    inventory = {p.relative_to(output).as_posix(): sha(p) for p in sorted(output.rglob('*')) if p.is_file()}
    receipt = {'case': case, 'input_contract_sha256': sha(profile / 'frozen/input-contract.json'),
               'files': inventory, 'scope': 'Source reconstruction only; no compiler or solver run.'}
    (output / 'prepared.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return inventory


def check_prepared(output, case='positive', profile=HERE):
    """Regenerate the bytes; prepared.json cannot authorize different inputs."""
    output = output.resolve()
    with tempfile.TemporaryDirectory(prefix='output-source-check-', dir=output.parent) as temp:
        reference = Path(temp) / 'expected'
        expected = prepare(reference, case, profile)
        require(not any(p.is_symlink() for p in output.rglob('*')), 'symlink in prepared inputs')
        actual = {p.relative_to(output).as_posix() for p in output.rglob('*') if p.is_file()}
        require(actual == set(expected) | {'prepared.json'}, 'prepared inventory changed')
        for name in expected:
            data = (reference / name).read_bytes()
            if name == 'inputs/sha2-probe/.cargo/config.toml':
                data = data.replace(json.dumps(str(reference))[1:-1].encode(),
                                    json.dumps(str(output))[1:-1].encode())
            require((output / name).read_bytes() == data, 'prepared source changed: ' + name)
    return {name: sha(output / name) for name in expected}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--case', choices=CASES, default='positive')
    args = parser.parse_args()
    try:
        print(json.dumps({'case': args.case, 'prepared_files': len(prepare(args.output, args.case))}))
    except (Rejected, OSError, ValueError, subprocess.CalledProcessError) as error:
        sys.exit(f'REJECTED: {error}')
