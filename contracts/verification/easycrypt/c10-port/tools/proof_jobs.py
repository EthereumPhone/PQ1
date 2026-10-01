#!/usr/bin/env python3
"""Execute the split gate's proof jobs on bounded, isolated worker trees (PQ1 #768).

EXECUTION ONLY.  cert_gate_split.sh writes the manifest -- the exact argv of every job,
built from its own variables -- and judges every result with its unchanged serial verdict
code.  This tool decides nothing about any proof.  It guarantees, or refuses to start:

  * every manifest job runs exactly once, with exactly its manifest argv and merged
    stdout+stderr, inside a private copy of the source tree that is verified
    byte-identical to it before any job starts.  No job ever runs in the source tree;
  * jobs that could write the same .eco file run in ONE worker, in manifest order (= the
    serial gate's phase order).  EasyCrypt exits 0 WITHOUT CHECKING when its target's
    .eco is up to date (ec.ml:588-591, r2026.02), so letting such jobs interleave would
    make a verdict depend on scheduling.  Today this pairs cdrafts-split/C10SpecControls.ec
    (a PHASE 1 target) with the identical PHASE 3 MUST-PASS control row;
  * a job is `done` only if its process EXITED NORMALLY.  A timeout, a signal (OOM kill)
    or a launch error is recorded as such, and the gate turns every one of them into FAIL
    -- a killed MUST-FAIL control is not a rejection.  Each result file is written last,
    atomically, after the job's whole process group is gone.

Exit status: 0 iff every manifest job has a `done` result.  A job's OWN nonzero exit is
data for the judge, not a runner failure: MUST-FAIL controls exit 1 by design.

Manifest: one job per line, `key<TAB>stdin<TAB>argv`, where stdin is a tree-relative path
or `-` (no input) and argv is the job's words joined by single spaces (no path in this
tree contains whitespace; an empty word is refused).

Results in OUT: `<n>.out` (raw output) and `<n>.res` = `status rc wall worker`, where n is
the job's 0-based manifest line.

Serial re-check: --recheck KEYFILE re-runs only the listed jobs (one key per line), each
expanded to its whole .eco chain, ONE AT A TIME in manifest order (--workers is forced to 1),
writing results under their ORIGINAL manifest numbers.  cert_gate_split.sh uses it for jobs
whose parallel verdict was FAIL: alone is the serial gate's exact execution condition.

Solo exclusion: --exclude KEYFILE leaves the listed jobs (expanded to whole .eco chains)
out of this run and writes the expanded list to --excluded-out.  The gate uses it for
MUST-FAIL controls whose declared reason a solver budget miss could produce: under load
such a control could be "rejected for the declared reason" when alone it would COMPILE,
so it must never be judged on a parallel run.  Those keys then go to --recheck.

Workers: --workers N, or `auto` = min(8, usable CPUs // 2).  Measured 2026-09-30 on a
12-core/24-thread host: 8 concurrent EasyCrypt processes replayed the full suite with
1,288/1,288 verdicts identical to the serial receipt; 12 flipped one marginal cli proof
(Z3's `-T` limit is wall-clock).  `--workers 1` is the serial reference mode.
"""
import argparse
import collections
import hashlib
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import threading
import time

AUTO_CAP = 8
PROGRESS_EVERY = 300.0


class Refuse(Exception):
    pass


Job = collections.namedtuple('Job', 'idx key stdin argv')


def parse_manifest(path, tree):
    jobs, keys = [], set()
    for n, line in enumerate(Path(path).read_text().splitlines()):
        fields = line.split('\t')
        if len(fields) != 3:
            raise Refuse(f'manifest line {n + 1}: expected key<TAB>stdin<TAB>argv')
        key, stdin, words = fields
        argv = words.split(' ')
        if not key or key in keys:
            raise Refuse(f'manifest line {n + 1}: empty or duplicate job key {key!r}')
        keys.add(key)
        if '' in argv or len(argv) < 2 or argv[0] != 'easycrypt' or argv[1] not in ('compile', 'cli'):
            raise Refuse(f'{key}: argv must be `easycrypt compile|cli ...` with no empty word')
        if (argv[1] == 'cli') == (stdin == '-'):
            raise Refuse(f'{key}: a cli job reads its file on stdin; a compile job reads none')
        for p in ([stdin] if stdin != '-' else []) + ([argv[-1]] if argv[1] == 'compile' else []):
            if os.path.isabs(p) or '..' in Path(p).parts or not (tree / p).is_file():
                raise Refuse(f'{key}: {p!r} is not a file inside the source tree')
        jobs.append(Job(n, key, None if stdin == '-' else stdin, argv))
    if not jobs:
        raise Refuse('empty manifest')
    return jobs


def eco_path(job):
    """The .eco a job may write or short-circuit on; cli jobs have no target."""
    if job.argv[1] != 'compile':
        return None
    return os.path.normpath(os.path.splitext(job.argv[-1])[0]) + '.eco'


def groups_of(jobs, tree):
    """Chain jobs sharing an .eco path; order chains longest-first by input size."""
    chains = collections.OrderedDict()
    for j in jobs:
        chains.setdefault(eco_path(j) or ('job', j.idx), []).append(j)
    def size(j):
        return (tree / (j.stdin or j.argv[-1])).stat().st_size
    return sorted(chains.values(), key=lambda c: (-sum(size(j) for j in c), c[0].idx))


def tree_digest(root):
    h, n = hashlib.sha256(), 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames) + [d for d in dirnames if os.path.islink(os.path.join(dirpath, d))]:
            p = os.path.join(dirpath, name)
            rel = os.path.relpath(p, root)
            if os.path.islink(p):
                h.update(b'L' + rel.encode() + b'\0' + os.readlink(p).encode() + b'\0')
            elif os.path.isfile(p):
                h.update(b'F' + rel.encode() + b'\0')
                with open(p, 'rb') as fh:
                    for block in iter(lambda: fh.read(1 << 20), b''):
                        h.update(block)
                h.update(b'\0')
            n += 1
    return h.hexdigest(), n


class Runner:
    def __init__(self, jobs, groups, trees, out, timeout):
        self.groups, self.trees, self.out, self.timeout = groups, trees, out, timeout
        self.queue = collections.deque(groups)
        self.lock = threading.RLock()   # re-entrant: stop() also runs as a signal handler
        self.live = set()
        self.results = {}
        self.total = len(jobs)
        self.stopping = False

    def kill_group(self, p):
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass

    def run_one(self, job, w):
        tree = self.trees[w]
        out_path = self.out / f'{job.idx}.out'
        status, rc, t0 = 'error', '-', time.monotonic()
        try:
            stdin = open(tree / job.stdin, 'rb') if job.stdin else open(os.devnull, 'rb')
            with stdin, open(out_path, 'wb') as out:
                p = subprocess.Popen(job.argv, cwd=tree, stdin=stdin, stdout=out,
                                     stderr=subprocess.STDOUT, start_new_session=True)
                with self.lock:
                    self.live.add(p)
                try:
                    p.wait(timeout=self.timeout or None)
                    status, rc = (('done', p.returncode) if p.returncode >= 0
                                  else ('signal', -p.returncode))
                except subprocess.TimeoutExpired:
                    status = 'timeout'
                finally:
                    self.kill_group(p)          # solvers outliving their EasyCrypt, or the timeout
                    p.wait()
                    with self.lock:
                        self.live.discard(p)
        except OSError as exc:
            with open(out_path, 'ab') as out:
                out.write(f'\nproof_jobs: launch error: {exc}\n'.encode())
        wall = time.monotonic() - t0
        h = hashlib.sha256()
        with open(out_path, 'rb') as fh:
            for block in iter(lambda: fh.read(1 << 20), b''):
                h.update(block)
        tmp = self.out / f'{job.idx}.res.tmp'
        tmp.write_text(f'{status} {rc} {wall:.2f} w{w}\n')
        os.replace(tmp, self.out / f'{job.idx}.res')
        with self.lock:
            self.results[job.idx] = (status, rc, wall, w, job.key, h.hexdigest())

    def worker(self, w):
        while True:
            with self.lock:
                if self.stopping or not self.queue:
                    return
                chain = self.queue.popleft()
            for job in chain:                       # a chain stays in one tree, in order
                if self.stopping:
                    return
                self.run_one(job, w)

    def stop(self, *_):
        with self.lock:
            self.stopping = True
            live = list(self.live)
        for p in live:
            self.kill_group(p)

    def run(self):
        threads = [threading.Thread(target=self.worker, args=(w,), daemon=True)
                   for w in range(len(self.trees))]
        for t in threads:
            t.start()
        last = time.monotonic()
        while any(t.is_alive() for t in threads):
            for t in threads:
                t.join(timeout=5)
            if time.monotonic() - last >= PROGRESS_EVERY:
                last = time.monotonic()
                with self.lock:
                    print(f'### PROGRESS done={len(self.results)}/{self.total}', flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--manifest', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--workers', default='auto')
    ap.add_argument('--recheck', metavar='KEYFILE')
    ap.add_argument('--exclude', metavar='KEYFILE')
    ap.add_argument('--excluded-out', metavar='FILE')
    ap.add_argument('--job-timeout', type=float,
                    default=float(os.environ.get('PQ_EASYCRYPT_JOB_TIMEOUT', 7200)))
    args = ap.parse_args()
    tree = Path.cwd().resolve()
    out = Path(args.out).resolve()
    cpus = len(os.sched_getaffinity(0)) if hasattr(os, 'sched_getaffinity') else os.cpu_count() or 1
    try:
        if args.workers == 'auto':
            workers = min(AUTO_CAP, max(1, cpus // 2))
        elif args.workers.isdigit() and int(args.workers) >= 1:
            workers = int(args.workers)
        else:
            raise Refuse(f'--workers must be a positive integer or auto, not {args.workers!r}')
        if out == tree or tree in out.parents:
            raise Refuse('the result directory must lie outside the source tree')
        if out.exists():
            raise Refuse(f'result directory {out} already exists')
        jobs = parse_manifest(args.manifest, tree)
        # EasyCrypt consults exactly one .eco per compile: its target's own (require never
        # reads one).  So that set, not "every .eco in the tree", is what must be absent.
        stale = sorted({e for j in jobs if (e := eco_path(j)) and (tree / e).exists()})
        if stale:
            raise Refuse(f'{len(stale)} target .eco file(s) already exist (e.g. {stale[0]}): '
                         'a valid .eco makes EasyCrypt skip its target unchecked')
        groups = groups_of(jobs, tree)
        known = {j.key for j in jobs}
        if args.recheck and args.exclude:
            raise Refuse('--recheck and --exclude are separate runs')
        if bool(args.exclude) != bool(args.excluded_out):
            raise Refuse('--exclude and --excluded-out go together')
        if args.exclude:
            unwanted = {k for k in Path(args.exclude).read_text().splitlines() if k}
            if not unwanted <= known:
                raise Refuse('--exclude keys must all be manifest jobs')
            dropped = sorted((c for c in groups if any(j.key in unwanted for j in c)),
                             key=lambda c: c[0].idx)
            groups = [c for c in groups if not any(j.key in unwanted for j in c)]
            jobs = [j for c in groups for j in c]
            Path(args.excluded_out).write_text(''.join(j.key + '\n' for c in dropped for j in c))
        if args.recheck:
            wanted = [k for k in Path(args.recheck).read_text().splitlines() if k]
            if not wanted or len(set(wanted)) != len(wanted) or not set(wanted) <= known:
                raise Refuse('--recheck keys must be a non-empty, duplicate-free subset of the manifest')
            # Whole chains, so a re-checked job meets the same .eco history as in the serial gate.
            groups = sorted((c for c in groups if any(j.key in wanted for j in c)),
                            key=lambda c: c[0].idx)
            jobs = [j for c in groups for j in c]
            workers = 1
        workers = max(1, min(workers, len(groups)))
        out.mkdir(parents=True)
        root = out.parent / (out.name + '-trees')
        if root == tree or tree in root.parents:
            raise Refuse('worker trees must lie outside the source tree')
        want, nfiles = tree_digest(tree)
        trees = []
        for w in range(workers):
            dst = root / f'w{w}'
            shutil.copytree(tree, dst, symlinks=True)
            got, _ = tree_digest(dst)
            if got != want:
                raise Refuse(f'worker tree w{w} is not byte-identical to the source tree')
            trees.append(dst)
        if tree_digest(tree)[0] != want:
            raise Refuse('the source tree changed while worker trees were being copied')
    except Refuse as exc:
        print(f'FAIL proof job runner refused to start: {exc}', flush=True)
        return 2
    chained = sum(len(c) for c in groups if len(c) > 1)
    print(f'### PROOF_JOBS{"_RECHECK" if args.recheck else ""} planned={len(jobs)} '
          f'chains={len(groups)} shared_eco_jobs={chained} '
          f'workers={workers} cpus={cpus} job_timeout={args.job_timeout:g}', flush=True)
    print(f'OK   {workers} worker tree(s) byte-identical to the source tree '
          f'({nfiles} files, sha256 {want[:16]})', flush=True)
    runner = Runner(jobs, groups, trees, out, args.job_timeout)
    signal.signal(signal.SIGTERM, runner.stop)
    signal.signal(signal.SIGINT, runner.stop)
    t0 = time.monotonic()
    try:
        runner.run()
    finally:
        runner.stop()
    wall = time.monotonic() - t0
    counts = collections.Counter(r[0] for r in runner.results.values())
    missing = len(jobs) - len(runner.results)
    print(f'### PROOF_JOBS{"_RECHECK" if args.recheck else ""} completed={len(runner.results)}/{len(jobs)} done={counts["done"]} '
          f'timeout={counts["timeout"]} signal={counts["signal"]} error={counts["error"]} '
          f'missing={missing} wall={wall:.0f}s', flush=True)
    # Per-job receipt: the raw outputs die with the container, so each line binds the
    # exit status and the sha256 of exactly the output the gate judged.
    print('### JOB_TIMES (wall seconds, worker, status, exit, output sha256, key; slowest first)',
          flush=True)
    for status, rc, secs, w, key, digest in sorted(runner.results.values(), key=lambda r: (-r[2], r[4])):
        print(f'T {secs:9.2f} w{w} {status} {rc} {digest} {key}')
    sys.stdout.flush()
    shutil.rmtree(root, ignore_errors=True)
    return 0 if counts['done'] == len(jobs) else 1


if __name__ == '__main__':
    sys.exit(main())
