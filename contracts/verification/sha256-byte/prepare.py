#!/usr/bin/env python3
"""Build the pinned upstream Lean backend in a new external directory.

Requires git and the pinned Lean toolchain (lean/lake on PATH). Downloads only
the mathlib modules imported by this backend and their transitive dependencies.
No compiler patch is installed: replay consumes the committed frozen extraction.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess

import verify


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    destination = args.destination.resolve()
    verify.require(not destination.exists(), 'dependency destination must not exist')
    config, _ = verify.sources()
    destination.mkdir(parents=True)
    env = os.environ.copy()
    env['CI'] = 'true'
    for key in list(env):
        if key.startswith('LEAN_'):
            del env[key]

    def run(*command, cwd=destination):
        subprocess.run(command, cwd=cwd, env=env, check=True, timeout=1800)

    run('git', 'init', '--quiet')
    run('git', 'remote', 'add', 'origin', 'https://github.com/AeneasVerif/aeneas.git')
    run('git', 'fetch', '--quiet', '--depth=1', 'origin', config['pins']['aeneas'])
    run('git', 'checkout', '--quiet', '--detach', 'FETCH_HEAD')
    backend = destination / 'backends/lean'
    inventory = json.loads((verify.HERE / 'backend-sources.json').read_text())
    for name, expected in inventory.items():
        verify.require(verify.sha(backend / name) == expected, f'upstream source mismatch: {name}')
    imports = set()
    for name in inventory:
        if name.endswith('.lean'):
            imports.update(re.findall(r'^\s*(?:public\s+)?(?:meta\s+)?import\s+(Mathlib\.\S+)',
                                      (backend / name).read_text(), re.MULTILINE))
    verify.require(imports, 'no backend mathlib import inventory')
    # Lake resolves the checked-in manifest, never `lake update` or a moving ref.
    run('lake', 'exe', 'cache', 'get', *sorted(imports), cwd=backend)
    run('lake', 'build', 'Aeneas', cwd=backend)
    print(f'Prepared pinned backend: {backend}')


if __name__ == '__main__':
    main()
