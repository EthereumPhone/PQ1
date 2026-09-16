"""Session-local launcher adapter: deadlines include Linux suspend time."""
import importlib.util
import sys
import time
import types
from pathlib import Path

source = Path('/home/nicola/.agents/skills/bounded-review-wave/scripts/run_review_wave.py')
spec = importlib.util.spec_from_file_location('bounded_review_boottime', source)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
clock = types.SimpleNamespace(**{name: getattr(time, name) for name in dir(time)})
clock.monotonic = lambda: time.clock_gettime(time.CLOCK_BOOTTIME)
module.time = clock
if __name__ == '__main__':
    raise SystemExit(module.main())
