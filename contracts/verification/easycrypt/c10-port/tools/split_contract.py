#!/usr/bin/env python3
"""Fast split integrity, complete proof target order, and checked tool identity.

These are evidence checks, not a proof of the model or its refinement to firmware.
The standard library/solver implementation remains a trusted foundation.
"""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import cert_cone
import stmt_coverage
import stmt_digest

cert_cone.INCLUDE_DIRS = ['base-c10-split', 'cdrafts-split']


def rows(path):
    return [s for s in Path(path).read_text().splitlines()
            if s.strip() and not s.startswith('#')]


def targets():
    """Check the exact pinned closure and return dependencies before consumers."""
    pinned = rows('cert-cone-files-split.tsv')
    if not pinned or len(pinned) != len(set(pinned)):
        raise ValueError('empty or duplicate cone file inventory')
    roots = stmt_coverage.roots()
    for p in roots + pinned:
        if not Path(p).is_file():
            raise ValueError(f'missing proof source: {p}')
    files = cert_cone.cone(roots)
    if set(files) != set(pinned):
        raise ValueError('computed cone differs from pinned file inventory')
    ordered, active, done = [], set(), set()

    def visit(p):
        if p in active:
            raise ValueError(f'cyclic require: {p}')
        if p in done:
            return
        active.add(p)
        for name in cert_cone.requires_of(p, files[p]):
            q = cert_cone.resolve(name)
            if q is not None:
                visit(q)
        active.remove(p)
        done.add(p)
        ordered.append(p)

    for p in sorted(files):
        visit(p)
    return ordered


def check_pins():
    pins = [s.split('\t') for s in rows('cert-statements-split.tsv')]
    if any(len(p) != 2 for p in pins):
        raise ValueError('malformed statement pin row')
    keys = [p[0] for p in pins]
    duplicates = [k for k, n in Counter(keys).items() if n != 1]
    if duplicates:
        raise ValueError(f'duplicate statement pin key: {duplicates[0]}')
    expected = re.findall(r'^EXPECT_PINS=(\d+)$', Path('cert_gate_split.sh').read_text(), re.M)
    if len(expected) != 1 or len(keys) != int(expected[0]) or not keys:
        raise ValueError('unique statement pin count differs from committed EXPECT_PINS')
    # Lexically different aliases (./A.ec, dir/../A.ec) must not count as two
    # declaration identities and substitute for a deleted op pin.
    allowed_paths = set(rows('cert-cone-files-split.tsv'))
    for key, want in pins:
        op = key.startswith('op:')
        path, name = (key[3:] if op else key).split('::')
        if path not in allowed_paths:
            raise ValueError(f'noncanonical or out-of-cone statement pin path: {path}')
        got = (stmt_digest.digest_op if op else stmt_digest.digest)(path, name)
        if not re.fullmatch(r'[0-9a-f]{32}', want) or got != want:
            raise ValueError(f'statement pin changed or unresolved: {key}')
    print(f'OK unique statement pins: {len(keys)}')


def check_toolchain(config, lock):
    hashes = re.findall(r'^git-hash: (.+)$', config, re.M)
    inventories = re.findall(r'^known provers: (.+)$', config, re.M)
    if hashes != [lock['easycrypt']] or len(inventories) != 1:
        raise ValueError('missing or unexpected EasyCrypt identity / prover inventory')
    provers = inventories[0].split(', ')
    if sorted(provers) != sorted(lock['provers']) or len(provers) != len(set(provers)):
        raise ValueError('unexpected solver identity inventory')
    if os.environ.get('PQ_EASYCRYPT_IMAGE') != lock['image']:
        raise ValueError('run full certification through the pinned container wrapper')


def run(*args):
    subprocess.run([sys.executable, *args], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--targets', action='store_true')
    parser.add_argument('--pins', action='store_true')
    parser.add_argument('--toolchain', action='store_true')
    args = parser.parse_args()
    if args.targets:
        print('\n'.join(targets()))
    elif args.pins:
        check_pins()
    elif args.toolchain:
        lock = json.loads(Path('cert-toolchain-split.json').read_text())
        cp = subprocess.run(['easycrypt', 'config'], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, check=True)
        check_toolchain(cp.stdout, lock)
        print(f"OK toolchain: {lock['easycrypt']}, {len(lock['provers'])} pinned prover configurations")
        print(f"### IMAGE {lock['image']}")
    else:
        files = targets()
        check_pins()
        current = Counter(tuple(row[:3]) for row in cert_cone.census(cert_cone.cone(stmt_coverage.roots())))
        expected = Counter(tuple(s.split('\t')[:3]) for s in rows('cert-baseline-split.tsv'))
        if not current or current != expected:
            raise ValueError('assumption/declaration census differs from pinned baseline')
        run('tools/stmt_coverage.py')
        run('tools/policy_cap_fence.py')
        run('tools/taint_closure.py', '--check')
        print(f'OK split static contract: {len(files)} files; proof execution not performed')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as exc:
        sys.exit(f'FAIL split contract: {exc}')
