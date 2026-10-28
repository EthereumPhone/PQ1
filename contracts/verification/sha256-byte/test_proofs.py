#!/usr/bin/env python3
"""The unchanged final proof must reject dropping or reversing input blocks."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time

import verify


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('replay', type=Path)
    args = parser.parse_args()
    replay = args.replay.resolve()
    config, _ = verify.sources()
    receipt = json.loads((replay / 'result.json').read_text())
    verify.require(receipt['status'] == 'pass' and
                   receipt['profile_sha256'] == verify.sha(verify.HERE / 'profile.json'),
                   'controls require a passing replay of this exact profile')
    for row in receipt['modules']:
        verify.require(verify.sha(replay / (row['module'].replace('.', '/') + '.olean')) == row['olean_sha256'],
                       'replayed module changed')
    lean = Path(receipt['dependencies']['lean'])
    verify.require(verify.sha(lean) == config['pins']['lean_linux_binary_sha256'], 'Lean changed')
    directory = replay / 'controls'
    directory.mkdir()
    source = (verify.HERE / 'Extracted/Sha256Portable/ByteCompression.lean').read_text()
    target = 'ok (foldBlocks blocks.val (toWords state)) := by'
    verify.require(source.count(target) == 1, 'consumer control target changed')
    env = os.environ.copy()
    for key in list(env):
        if key.startswith('LEAN_'):
            del env[key]
    env['LEAN_PATH'] = os.pathsep.join([str(replay), *receipt['dependencies']['dependency_roots']])
    rows = []
    for name, replacement in [('positive', target),
                              ('skip-first', target.replace('blocks.val', '(blocks.val.drop 1)')),
                              ('reverse-blocks', target.replace('blocks.val', 'blocks.val.reverse'))]:
        path = directory / (name + '.lean')
        path.write_text(source.replace(target, replacement))
        log = directory / (name + '.log')
        start = time.monotonic()
        with log.open('xb') as stream:
            result = subprocess.run([str(lean), '--root=' + str(directory), str(path)],
                                    cwd=directory, env=env, stdout=stream, stderr=subprocess.STDOUT,
                                    timeout=180)
        text = log.read_text()
        if name == 'positive':
            verify.require(result.returncode == 0, f'positive control failed: {log}')
        else:
            verify.require(result.returncode == 1 and 'Tactic `rfl` failed' in text and
                           'foldBlocks' in text and text.count('error:') == 1,
                           f'control did not reach the intended theorem mismatch: {log}')
        rows.append({'case': name, 'exit': result.returncode, 'seconds': time.monotonic() - start,
                     'source_sha256': verify.sha(path), 'log_sha256': verify.sha(log)})
        print(f'PASS {name}: expected exit {result.returncode}', flush=True)
    (directory / 'result.json').write_text(json.dumps({'status': 'pass', 'cases': rows}, indent=2) + '\n')


if __name__ == '__main__':
    main()
