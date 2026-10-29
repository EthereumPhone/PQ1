"""Measure allocation while tolerating bounded ENOENT races, never other errors."""
import os
import subprocess
import time


def measure_allocated_bytes(path, cap, run=subprocess.run, pause=time.sleep):
    command = ['du', '-s', '-B1', str(path)]
    for attempt in range(5):
        result = run(command, text=True, stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE, env={**os.environ, 'LC_ALL': 'C'})
        fields = result.stdout.split()
        value = int(fields[0]) if fields and fields[0].isdigit() else None
        if result.returncode == 0:
            if value is None:
                raise RuntimeError('du succeeded without a valid allocation count')
            return value
        # A partial measurement already over the cap is sufficient to stop.
        if value is not None and value >= cap:
            return value
        errors = result.stderr.splitlines()
        vanished = (result.returncode == 1 and errors and
                    all(line.startswith('du: ') and
                        line.endswith(': No such file or directory') for line in errors))
        if not vanished or attempt == 4:
            raise RuntimeError(f'du failed ({result.returncode}): {result.stderr[:1000]}')
        pause(0.05)
    raise AssertionError('Unreachable allocation measurement state')
