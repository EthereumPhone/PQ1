#!/usr/bin/env python3
"""Negative regression controls for the split gate's parallel proof-job execution.

Toolchain-free: a fake `easycrypt` on PATH stands in for the prover.  The gate's own
judging helpers are extracted VERBATIM from cert_gate_split.sh (between their BEGIN/END
markers) and run against doctored result files -- the same idiom as
scratch/taint_count_controls.sh -- so a weakened helper is caught here, not trusted.
"""
from pathlib import Path
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
import unittest

PORT = Path(__file__).resolve().parents[1]
RUNNER = PORT / 'tools/proof_jobs.py'
GATE = PORT / 'cert_gate_split.sh'

# The fake prover.  Directives live in the target file (compile) or on stdin (cli):
#   EXIT n | SLEEP s | SPAWN (leave a grandchild sleeping, pid in ../grandchild.pid)
#   SELFKILL | ECHO_STDIN | ECO (honour/write the target .eco like ec.ml:588-591)
FAKE = r'''#!/usr/bin/env python3
import os, signal, subprocess, sys, time
mode, target = sys.argv[1], sys.argv[-1]
text = open(target).read() if mode == 'compile' else sys.stdin.read()
open('ran-here.marker', 'a').write(target + '\n')
print('argv=' + ' '.join(sys.argv[1:]))
sys.stderr.write('to-stderr\n')
if 'ECHO_STDIN' in text: print('stdin=' + text.strip())
if 'ECO' in text:
    eco = os.path.splitext(target)[0] + '.eco'
    if os.path.exists(eco): print('SKIPPED-BY-ECO'); sys.exit(0)
    print('CHECKED'); open(eco, 'w').write('{}')
if 'SPAWN' in text:
    p = subprocess.Popen(['sleep', '300'])
    open(os.path.join(os.environ['FAKE_SPOOL'], 'grandchild.pid'), 'w').write(str(p.pid))
for word in text.split('\n'):
    if word.startswith('SLEEP '): time.sleep(float(word.split()[1]))
if 'SELFKILL' in text: os.kill(os.getpid(), signal.SIGKILL)
for word in text.split('\n'):
    if word.startswith('EXIT '): sys.exit(int(word.split()[1]))
'''


def block(name):
    """The gate's own lines between `# BEGIN name` and `# END name`."""
    src = GATE.read_text()
    m = re.search(rf'^# BEGIN {re.escape(name)}\b.*?$(.*?)^# END {re.escape(name)}$', src, re.M | re.S)
    if not m:
        raise AssertionError(f'marker block {name!r} missing from cert_gate_split.sh')
    return m.group(1)


class Fixture:
    def __enter__(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.tree, self.bin, self.spool = base / 'tree', base / 'bin', base / 'spool'
        for d in (self.tree, self.bin, self.spool):
            d.mkdir()
        (self.bin / 'easycrypt').write_text(FAKE)
        (self.bin / 'easycrypt').chmod(0o755)
        self.out = base / 'jobs'
        return self

    def __exit__(self, *exc):
        self.tmp.cleanup()

    def file(self, rel, text):
        p = self.tree / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    def run(self, rows, workers='3', timeout=None, extra=()):
        manifest = self.tree.parent / 'jobs.tsv'
        manifest.write_text(''.join('\t'.join(r) + '\n' for r in rows))
        env = dict(os.environ, PATH=f'{self.bin}{os.pathsep}{os.environ["PATH"]}',
                   FAKE_SPOOL=str(self.spool))
        cmd = [sys.executable, str(RUNNER), '--manifest', str(manifest), '--out', str(self.out),
               '--workers', workers, *extra]
        if timeout is not None:
            cmd += ['--job-timeout', str(timeout)]
        return subprocess.run(cmd, cwd=self.tree, env=env, text=True, capture_output=True, timeout=120)

    def res(self, n):
        p = self.out / f'{n}.res'
        return p.read_text().split() if p.exists() else None

    def out_text(self, n):
        return (self.out / f'{n}.out').read_text()


def compile_row(key, path):
    return (key, '-', f'easycrypt compile -timeout 60 -I base -I drafts {path}')


class RunnerTests(unittest.TestCase):
    def test_every_job_runs_once_with_its_argv_in_a_private_tree(self):
        with Fixture() as fx:
            fx.file('d/A.ec', 'EXIT 0\n'); fx.file('d/B.ec', 'EXIT 1\n'); fx.file('d/C.ec', 'ECHO_STDIN\n')
            r = fx.run([compile_row('compile:d/A.ec', 'd/A.ec'), compile_row('control:d/B.ec', 'd/B.ec'),
                        ('cli:d/C.ec', 'd/C.ec', 'easycrypt cli -iterate -pragmas silent -I base -I drafts')])
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertEqual(fx.res(0)[:2], ['done', '0'])
            self.assertEqual(fx.res(1)[:2], ['done', '1'])    # a job's own failure is data
            self.assertEqual(fx.res(2)[:2], ['done', '0'])
            self.assertIn('argv=compile -timeout 60 -I base -I drafts d/A.ec', fx.out_text(0))
            self.assertIn('to-stderr', fx.out_text(0))        # stderr merged, like 2>&1
            self.assertIn('stdin=ECHO_STDIN', fx.out_text(2))  # cli reads its file on stdin
            self.assertIn('argv=cli -iterate -pragmas silent -I base -I drafts', fx.out_text(2))
            self.assertFalse((fx.tree / 'ran-here.marker').exists(), 'a job ran in the source tree')
            self.assertIn('byte-identical to the source tree', r.stdout)
            self.assertIn('### PROOF_JOBS completed=3/3 done=3', r.stdout)
            self.assertEqual(len(re.findall(r'^T +[0-9.]+ w\d+ done ', r.stdout, re.M)), 3)
            # Each per-job receipt line binds the exit status and the sha256 of the judged output.
            import hashlib
            for n, key in ((0, 'compile:d/A.ec'), (1, 'control:d/B.ec')):
                digest = hashlib.sha256((fx.out / f'{n}.out').read_bytes()).hexdigest()
                rc = fx.res(n)[1]
                self.assertRegex(r.stdout, rf'(?m)^T +[0-9.]+ w\d+ done {rc} {digest} {re.escape(key)}$')

    def test_jobs_sharing_an_eco_run_in_one_tree_in_manifest_order(self):
        # The C10SpecControls case: a PHASE 1 target and a PHASE 3 control on one path.
        # Serially, the control finds the target's .eco and short-circuits.  With 8 workers
        # and padding jobs, the outcome must be that, every time -- never two real checks
        # in two trees, never the control first.  X.ec and X.eca also share X.eco.
        for attempt in range(3):
            with self.subTest(attempt=attempt), Fixture() as fx:
                fx.file('d/S.ec', 'ECO\n'); fx.file('d/Y.ec', 'ECO\n'); fx.file('d/Y.eca', 'ECO\n')
                rows = [compile_row('compile:d/S.ec', 'd/S.ec'), compile_row('compile:d/Y.ec', 'd/Y.ec')]
                for i in range(12):
                    fx.file(f'p/P{i}.ec', 'SLEEP 0.05\n'); rows.append(compile_row(f'compile:p/P{i}.ec', f'p/P{i}.ec'))
                rows += [('control:d/S.ec', '-', 'easycrypt compile -I base -I drafts d/S.ec'),
                         compile_row('compile:d/Y.eca', 'd/Y.eca')]
                r = fx.run(rows, workers='8')
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertIn('shared_eco_jobs=4', r.stdout)
                self.assertIn('CHECKED', fx.out_text(0)); self.assertIn('SKIPPED-BY-ECO', fx.out_text(14))
                self.assertIn('CHECKED', fx.out_text(1)); self.assertIn('SKIPPED-BY-ECO', fx.out_text(15))
                self.assertEqual(fx.res(0)[3], fx.res(14)[3]); self.assertEqual(fx.res(1)[3], fx.res(15)[3])

    def test_malformed_or_unsafe_manifests_refuse_before_any_job_runs(self):
        cases = {
            'duplicate key': [compile_row('k', 'd/A.ec'), compile_row('k', 'd/A.ec')],
            'not easycrypt': [('k', '-', 'sh -c true')],
            'bad subcommand': [('k', '-', 'easycrypt runtest d/A.ec')],
            'empty word': [('k', '-', 'easycrypt compile  d/A.ec')],
            'cli without stdin': [('k', '-', 'easycrypt cli -iterate')],
            'compile with stdin': [('k', 'd/A.ec', 'easycrypt compile d/A.ec')],
            'missing file': [compile_row('k', 'd/Missing.ec')],
            'outside the tree': [compile_row('k', '../escape.ec')],
            'absolute path': [compile_row('k', '/etc/hostname')],
            'two fields': [('k', 'easycrypt compile d/A.ec')],
        }
        for name, rows in cases.items():
            with self.subTest(name), Fixture() as fx:
                fx.file('d/A.ec', 'EXIT 0\n'); (fx.tree.parent / 'escape.ec').write_text('EXIT 0\n')
                r = fx.run(rows)
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertIn('FAIL proof job runner refused to start', r.stdout)
                self.assertFalse(fx.out.exists() and any(fx.out.iterdir()), 'a job ran after refusal')

    def test_a_stale_target_eco_refuses_but_an_unrelated_one_does_not(self):
        with Fixture() as fx:
            fx.file('d/A.ec', 'EXIT 0\n'); fx.file('d/A.eco', '{}')
            r = fx.run([compile_row('k', 'd/A.ec')])
            self.assertEqual(r.returncode, 2); self.assertIn('target .eco', r.stdout)
        with Fixture() as fx:
            fx.file('d/A.ec', 'EXIT 0\n'); fx.file('fork/Other.eco', '{}')
            self.assertEqual(fx.run([compile_row('k', 'd/A.ec')]).returncode, 0)

    def test_bad_worker_counts_refuse(self):
        for workers in ('0', '-1', 'x', '2.5'):
            with self.subTest(workers=workers), Fixture() as fx:
                fx.file('d/A.ec', 'EXIT 0\n')
                self.assertEqual(fx.run([compile_row('k', 'd/A.ec')], workers=workers).returncode, 2)

    def test_timeout_kills_the_process_group_and_has_no_verdict(self):
        with Fixture() as fx:
            fx.file('d/A.ec', 'SPAWN\nSLEEP 60\nEXIT 1\n'); fx.file('d/B.ec', 'EXIT 0\n')
            r = fx.run([compile_row('control:d/A.ec', 'd/A.ec'), compile_row('k2', 'd/B.ec')], timeout=2)
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertEqual(fx.res(0)[0], 'timeout')         # NOT `done 1`: no rejection to judge
            self.assertEqual(fx.res(1)[:2], ['done', '0'])
            self.assertIn('timeout=1', r.stdout)
            pid = int((fx.spool / 'grandchild.pid').read_text())
            time.sleep(0.2)
            self.assertFalse(_alive(pid), 'a solver-like grandchild survived the timeout kill')

    def test_a_signalled_job_has_no_verdict(self):
        with Fixture() as fx:
            fx.file('d/A.ec', 'SELFKILL\n')
            r = fx.run([compile_row('k', 'd/A.ec')])
            self.assertEqual(r.returncode, 1)
            self.assertEqual(fx.res(0)[:2], ['signal', str(int(signal.SIGKILL))])

    def test_a_job_that_cannot_launch_has_no_verdict(self):
        with Fixture() as fx:
            fx.file('d/A.ec', 'EXIT 0\n')
            (fx.bin / 'easycrypt').chmod(0o644)               # not executable
            env_path = os.environ['PATH']
            os.environ['PATH'] = f'{fx.bin}{os.pathsep}/nonexistent'
            try:
                r = fx.run([compile_row('k', 'd/A.ec')])
            finally:
                os.environ['PATH'] = env_path
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertEqual(fx.res(0)[0], 'error')

    def test_recheck_reruns_whole_eco_chains_alone_under_original_numbers(self):
        with Fixture() as fx:
            fx.file('d/S.ec', 'ECO\n'); fx.file('d/T.ec', 'EXIT 0\n'); fx.file('d/U.ec', 'EXIT 0\n')
            rows = [compile_row('compile:d/S.ec', 'd/S.ec'), compile_row('compile:d/T.ec', 'd/T.ec'),
                    compile_row('compile:d/U.ec', 'd/U.ec'),
                    ('control:d/S.ec', '-', 'easycrypt compile -I base -I drafts d/S.ec')]
            keys = fx.tree.parent / 'keys'
            keys.write_text('control:d/S.ec\ncompile:d/U.ec\n')
            r = fx.run(rows, workers='8', extra=('--recheck', str(keys)))
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn('### PROOF_JOBS_RECHECK planned=3 ', r.stdout)
            self.assertIn('workers=1', r.stdout)                     # alone, whatever was asked
            self.assertIsNone(fx.res(1))                              # T was not asked for
            self.assertIn('CHECKED', fx.out_text(0))                  # S's chain partner ran first
            self.assertIn('SKIPPED-BY-ECO', fx.out_text(3))           # ... exactly as in serial order
            self.assertEqual(fx.res(2)[:2], ['done', '0'])

    def test_recheck_refuses_unknown_duplicate_or_empty_keys(self):
        for keys in ('compile:d/Nope.ec\n', 'compile:d/A.ec\ncompile:d/A.ec\n', ''):
            with self.subTest(keys=keys), Fixture() as fx:
                fx.file('d/A.ec', 'EXIT 0\n')
                kf = fx.tree.parent / 'keys'; kf.write_text(keys)
                r = fx.run([compile_row('compile:d/A.ec', 'd/A.ec')], extra=('--recheck', str(kf)))
                self.assertEqual(r.returncode, 2, r.stdout)

    def test_exclude_leaves_whole_chains_out_and_reports_them(self):
        with Fixture() as fx:
            fx.file('d/S.ec', 'ECO\n'); fx.file('d/T.ec', 'EXIT 0\n')
            rows = [compile_row('compile:d/S.ec', 'd/S.ec'), compile_row('compile:d/T.ec', 'd/T.ec'),
                    ('control:d/S.ec', '-', 'easycrypt compile -I base -I drafts d/S.ec')]
            ex, got = fx.tree.parent / 'ex', fx.tree.parent / 'got'
            ex.write_text('control:d/S.ec\n')
            r = fx.run(rows, extra=('--exclude', str(ex), '--excluded-out', str(got)))
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertEqual(got.read_text(), 'compile:d/S.ec\ncontrol:d/S.ec\n')   # whole chain, in order
            self.assertIsNone(fx.res(0)); self.assertIsNone(fx.res(2))
            self.assertEqual(fx.res(1)[:2], ['done', '0'])
            self.assertIn('completed=1/1', r.stdout)
            ex.write_text('control:d/Nope.ec\n')
            fx.out = fx.tree.parent / 'jobs2'
            self.assertEqual(fx.run(rows, extra=('--exclude', str(ex), '--excluded-out', str(got))).returncode, 2)

    def test_sigterm_stops_the_run_and_leaves_jobs_unrun(self):
        with Fixture() as fx:
            rows = []
            for i in range(4):
                fx.file(f'd/A{i}.ec', 'SPAWN\nSLEEP 60\n'); rows.append(compile_row(f'k{i}', f'd/A{i}.ec'))
            manifest = fx.tree.parent / 'jobs.tsv'
            manifest.write_text(''.join('\t'.join(r) + '\n' for r in rows))
            env = dict(os.environ, PATH=f'{fx.bin}{os.pathsep}{os.environ["PATH"]}', FAKE_SPOOL=str(fx.spool))
            p = subprocess.Popen([sys.executable, str(RUNNER), '--manifest', str(manifest), '--out',
                                  str(fx.out), '--workers', '1'], cwd=fx.tree, env=env,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            deadline = time.time() + 20
            while not (fx.spool / 'grandchild.pid').exists() and time.time() < deadline:
                time.sleep(0.05)
            p.send_signal(signal.SIGTERM)
            out, _ = p.communicate(timeout=30)
            self.assertEqual(p.returncode, 1, out)
            self.assertIn('missing=3', out)
            self.assertFalse(_alive(int((fx.spool / 'grandchild.pid').read_text())))


def _alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # A zombie still answers kill(0); it is dead for our purposes.
    try:
        return Path(f'/proc/{pid}/stat').read_text().split(')')[-1].split()[0] != 'Z'
    except OSError:
        return False


class GateJudgeTests(unittest.TestCase):
    """The gate's own judging lines, extracted verbatim and fed doctored results."""

    def bash(self, script):
        return subprocess.run(['bash', '-c', 'set -u; set -o pipefail\n' + script],
                              text=True, capture_output=True, timeout=30)

    def test_job_result_only_yields_a_verdict_for_a_completed_job(self):
        with tempfile.TemporaryDirectory() as d:
            j = Path(d)
            states = {0: ('done 0 1.0 w0', True), 1: ('done 1 1.0 w0', True), 2: ('timeout - 9 w1', False),
                      3: ('signal 9 1.0 w1', False), 4: ('error - 0.0 w2', False), 5: ('done x 1 w0', False),
                      6: ('done  1 w0', False), 7: (None, False), 8: ('', False),
                      10: ('done 0 1.0 w0 extra', False), 11: ('done 0 1.0 x0', False),
                      12: ('done 0 abc w0', False), 13: ('done 0 1.0 w', False)}
            for i, (res, _) in states.items():
                (j / f'{i}.out').write_text('raw output\n')
                if res is not None:
                    (j / f'{i}.res').write_text(res + '\n')
            (j / '9.res').write_text('done 0 1.0 w0\n')      # .out missing
            decl = re.search(r'^declare -A JOB_IDX.*$', GATE.read_text(), re.M).group(0)
            keys = ''.join(f'JOB_IDX[k{i}]={i}; ' for i in range(14))
            script = (f'{decl}; {keys}JOBS_DIR={d}; RECHECK_DIR={d}/re\n' + block('job-result') +
                      'for k in k0 k1 k2 k3 k4 k5 k6 k7 k8 k9 k10 k11 k12 k13 never; do\n'
                      '  if job_result "$k"; then echo "$k OK $JR_RC $JR_OUT"; else echo "$k NO $JR_WHY"; fi\n'
                      'done; echo "seen=${#JOB_SEEN[@]}"\n')
            r = self.bash(script)
            self.assertEqual(r.returncode, 0, r.stderr)
            out = r.stdout.strip().splitlines()
            self.assertEqual(out[-1], 'seen=15')            # every lookup is recorded
            lines = dict(l.split(' ', 1) for l in out[:-1])
            self.assertTrue(lines['k0'].startswith('OK 0 ')); self.assertTrue(lines['k1'].startswith('OK 1 '))
            for k, why in (('k2', 'job timeout'), ('k3', 'job signal'), ('k4', 'job error'),
                           ('k5', 'unreadable exit status'), ('k6', 'malformed result record'),
                           ('k7', 'no result'), ('k8', 'unreadable'), ('k9', 'no result'),
                           ('k10', 'malformed'), ('k11', 'malformed'), ('k12', 'malformed'),
                           ('k13', 'malformed'),
                           ('never', 'never queued')):
                self.assertTrue(lines[k].startswith('NO ') and why in lines[k], (k, lines[k]))

    def test_a_rechecked_job_is_judged_on_its_solo_run_only(self):
        with tempfile.TemporaryDirectory() as d:
            j, re_dir = Path(d), Path(d) / 're'
            re_dir.mkdir()
            (j / '0.out').write_text('parallel\n'); (j / '0.res').write_text('done 1 9.0 w3\n')
            (re_dir / '0.out').write_text('alone\n'); (re_dir / '0.res').write_text('done 0 2.0 w0\n')
            decl = re.search(r'^declare -A JOB_IDX.*$', GATE.read_text(), re.M).group(0)
            base = f'{decl}; JOB_IDX[k]=0; JOBS_DIR={d}; RECHECK_DIR={re_dir}\n' + block('job-result')
            r = self.bash(base + 'job_result k; echo "rc=$JR_RC out=$JR_OUT"\n')
            self.assertIn(f'rc=1 out={d}/0.out', r.stdout)
            r = self.bash(base + 'RECHECKED[k]=1; job_result k; echo "rc=$JR_RC out=$JR_OUT"\n')
            self.assertIn(f'rc=0 out={re_dir}/0.out', r.stdout)
            (re_dir / '0.res').unlink()                     # re-check result missing: no verdict
            r = self.bash(base + 'RECHECKED[k]=1; job_result k || echo "NO $JR_WHY"\n')
            self.assertIn('NO no result', r.stdout)

    def test_solo_select_takes_every_control_a_budget_miss_could_fake(self):
        cases = {   # file text, polarity, declared reason -> selected?
            'plain smt reason': ('lemma l : true. proof. smt(). qed.', 'MUST-FAIL', 'cannot prove goal (strict)', True),
            'try smt': ('lemma l : true. proof. by try smt(). qed.', 'MUST-FAIL', '[by]: cannot close goals', True),
            'try /#': ('lemma l : true. proof. move=> x; try (move=> /#). qed.', 'MUST-FAIL', 'nothing to rewrite', True),
            'postfix ?': ('lemma l : true. proof. smt(foo)?. qed.', 'MUST-FAIL', 'the given proof-term proves:', True),
            'do loop': ('lemma l : true. proof. do! smt(). qed.', 'MUST-FAIL', 'cannot save an incomplete proof', True),
            'orelse': ('lemma l : true. proof. (smt() || done). qed.', 'MUST-FAIL', 'x', True),
            'qualified name before try': ('lemma l : true. proof. apply A.b; try smt(). qed.', 'MUST-FAIL', 'x', True),
            'loud smt, static reason': ('lemma l : true. proof. smt(). exact: foo. qed.', 'MUST-FAIL', 'unknown variable', False),
            'try only in a comment': ('(* try smt() *) lemma l : true. proof. exact: foo. qed.', 'MUST-FAIL', 'x', False),
            'try_lemma is a name': ('lemma l : true. proof. exact: A.try_smt. qed.', 'MUST-FAIL', 'x', False),
            'MUST-PASS cannot be faked': ('lemma l : true. proof. by try smt(). qed.', 'MUST-PASS', '-', False),
        }
        with tempfile.TemporaryDirectory() as d:
            rows = []
            for i, (name, (text, pol, reason, _)) in enumerate(cases.items()):
                (Path(d) / f'c{i}.ec').write_text(text + '\n')
                rows.append(f'c{i}.ec\t{pol}\t{reason}\n')
            (Path(d) / 'cert-controls-split.tsv').write_text('# rows\n' + ''.join(rows))
            r = subprocess.run(['bash', '-c', f'set -u; TMPD={d}\n' + block('solo-select')],
                               cwd=d, text=True, capture_output=True, timeout=30)
            self.assertEqual(r.returncode, 0, r.stderr)
            got = set((Path(d) / 'solo.request').read_text().split())
            for i, (name, (*_, want)) in enumerate(cases.items()):
                with self.subTest(name):
                    self.assertEqual(f'control:c{i}.ec' in got, want)

    def test_cli_judge_keeps_the_serial_verdict_rule(self):
        cases = {   # raw cli output, exit status -> expected first word, fragment
            'clean': ('[1|check]>\r[2|check]>\n', 0, 'OK', '(cli, 2 cmds)'),
            'diagnostic': ('[1|check]>\n<tty>: line 3 (0-4): cannot prove goal (strict)\n', 0, 'FAIL', '1 diagnostic'),
            'nonzero exit': ('[1|check]>\n', 1, 'FAIL', '0 diagnostic'),
            'never ran': ('', 0, 'FAIL', 'did not happen'),
        }
        for name, (raw, rc, verdict, frag) in cases.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as d:
                (Path(d) / 'raw').write_text(raw)
                r = self.bash(f'fail=0; cli_bad=0; cli_run=0; TMPD={d}\n' + block('cli-judge') +
                              f'cli_judge lbl {rc} {d}/raw; echo "fail=$fail bad=$cli_bad run=$cli_run"\n')
                self.assertEqual(r.returncode, 0, r.stderr)
                first = r.stdout.splitlines()[0]
                self.assertTrue(first.startswith(verdict) and frag in first, first)
                self.assertIn('run=1', r.stdout)
                self.assertIn('fail=0' if verdict == 'OK' else 'fail=1', r.stdout)

    def test_cli_one_still_executes_and_judges_for_watched_files(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / 'easycrypt').write_text(
                '#!/bin/sh\n[ "$*" = "cli -iterate -pragmas silent -I a" ] || exit 2\n'
                'printf "[1|check]>\\n"\nexit 0\n')
            (Path(d) / 'easycrypt').chmod(0o755)
            r = self.bash(f'PATH={d}:$PATH; fail=0; cli_bad=0; cli_run=0; TMPD={d}\n' + block('cli-judge') +
                          'cli_one "watched X" -I a < /dev/null; echo "fail=$fail run=$cli_run"\n')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn('OK   watched X (cli, 1 cmds)', r.stdout)
            self.assertIn('fail=0 run=1', r.stdout)

    def test_every_queued_job_must_be_judged(self):
        base = 'fail=0; declare -A JOB_IDX=([a]=0 [b]=1) JOB_SEEN=(); JOB_N=2\n'
        for seen, ok in (('[a]=1 [b]=1', True), ('[a]=1', False), ('', False), ('[a]=1 [b]=1 [c]=1', False)):
            with self.subTest(seen=seen):
                r = self.bash(base + f'JOB_SEEN=({seen})\n' + block('jobs-judged') + 'echo "fail=$fail"\n')
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn('fail=0' if ok else 'fail=1', r.stdout)
        decl = re.search(r'^declare -A JOB_IDX.*$', GATE.read_text(), re.M).group(0)
        r = self.bash(f'fail=0; {decl}; JOB_N=0\n' + block('jobs-judged') + 'echo "fail=$fail"\n')
        self.assertEqual(r.stderr, '')                 # no `unbound variable` escape hatch
        self.assertIn('fail=1', r.stdout)              # nothing queued is not a pass

    def test_phases_1_1e_and_3_no_longer_execute_easycrypt_themselves(self):
        src = GATE.read_text()
        def section(start, end):
            a, b = src.index(start), src.index(end)
            self.assertLess(a, b)
            return [l for l in src[a:b].splitlines() if not l.lstrip().startswith('#')]
        for start, end in (('echo "### PHASE 1 — TARGETS"', 'echo "### PHASE 1d'),
                           ('echo "### PHASE 1e', 'echo "### PHASE 1f'),
                           ('echo "### PHASE 3', 'echo "### PHASE 4')):
            body = section(start, end)
            runs = [l for l in body if re.search(r'(^|[;&|(]\s*|\bif\s+!?\s*)easycrypt\s', l.strip())]
            calls = [l for l in body if re.search(r'\bjudge_(target|cli|control)\b', l)]
            with self.subTest(start):
                self.assertEqual(runs, [], 'a judged phase executes EasyCrypt itself')
                self.assertEqual(len(calls), 1, 'the phase must judge through its shared judge_* rule')


# A prover whose failures can be made LOAD-LIKE: FLAKY fails the first time a given
# (driver, file) runs and passes after; BROKEN always fails.  cli files are identified by
# their first line.  CONTROL_FAIL marks a MUST-FAIL control file.
FAKE_E2E = r"""#!/usr/bin/env python3
import atexit, glob, os, sys, time
running = os.path.join(os.environ['FAKE_SPOOL'], 'running')
os.makedirs(running, exist_ok=True)
me = os.path.join(running, str(os.getpid()))
open(me, 'w').close()
atexit.register(lambda: os.path.exists(me) and os.remove(me))
mode = sys.argv[1]
if mode == 'cli' and sys.argv[1:] != ['cli', '-iterate', '-pragmas', 'silent', '-I', 'base', '-I', 'drafts']:
    print('<tty>: unexpected CLI flags')
    sys.exit(2)
target = sys.argv[-1] if mode == 'compile' else None
text = open(target).read() if mode == 'compile' else sys.stdin.read()
name = (target or 'stdin-' + text.split('\n')[0]).replace('/', '_').replace(' ', '_')
seen = os.path.join(os.environ['FAKE_SPOOL'], mode + '-' + name)
first = not os.path.exists(seen)
open(seen, 'a').write('x')
bad = 'BROKEN' in text or ('FLAKY' in text and first)
for line in text.split('\n'):
    if line.startswith('SLEEP '):
        time.sleep(float(line.split()[1]))
if 'MASKABLE' in text:          # a WEAKENED control: provable alone, budget miss under load
    time.sleep(0.5)
    if len(glob.glob(os.path.join(running, '*'))) > 1:
        print('[critical] [x: line 1] cannot prove goal (strict)')
        sys.exit(1)
    sys.exit(0)
if mode == 'cli':
    print('[1|check]>')
    if bad:
        print('<tty>: line 1 (0-4): cannot prove goal (strict)')
    sys.exit(0)
if 'CONTROL_FAIL_STATIC' in text:   # declared reason a budget miss cannot produce
    print('[critical] [x: line 1] ' + ('parse error' if bad else 'the given proof-term proves: x'))
    sys.exit(1)
if 'CONTROL_FAIL' in text:
    print('[critical] [x: line 1] ' + ('parse error' if bad else 'cannot prove goal (strict)'))
    sys.exit(1)
if bad:
    print('[critical] boom')
    sys.exit(1)
"""


class EndToEndTests(unittest.TestCase):
    """The gate's whole ### PROOF JOBS section, verbatim, with the real runner."""

    def run_gate(self, files, targets, controls):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            tree, tmpd, binp, spool = base / 'tree', base / 'tmpd', base / 'bin', base / 'spool'
            for x in (tree / 'tools', tmpd, binp, spool):
                x.mkdir(parents=True)
            (tree / 'tools/proof_jobs.py').write_text(RUNNER.read_text())
            for rel, text in files.items():
                (tree / rel).parent.mkdir(parents=True, exist_ok=True)
                (tree / rel).write_text(text)
            (tmpd / 'targets').write_text(''.join(t + '\n' for t in targets))
            (tree / 'cert-controls-split.tsv').write_text(
                '# controls\n' + ''.join('\t'.join(c) + '\n' for c in controls))
            (binp / 'easycrypt').write_text(FAKE_E2E)
            (binp / 'easycrypt').chmod(0o755)
            script = ('set -u; set -o pipefail\n'
                      f'fail=0; TMPD={tmpd}; ECFLAGS="-timeout 60"; INC="-I base -I drafts"; PQ_EASYCRYPT_JOBS=4\n'
                      + block('proof-jobs') +
                      'while read -r f; do judge_target "$f"; done < "$TMPD/targets"\n'
                      'while read -r f; do judge_cli "$f"; done < "$TMPD/targets"\n'
                      "while IFS=$'\\t' read -r path kind reason; do case \"$path\" in ''|\\#*) continue;; esac;"
                      ' judge_control "$path" "$kind" "$reason"; done < cert-controls-split.tsv\n'
                      + block('jobs-judged') + 'echo "FINALFAIL=$fail"\n')
            env = dict(os.environ, PATH=f'{binp}{os.pathsep}{os.environ["PATH"]}', FAKE_SPOOL=str(spool))
            r = subprocess.run(['bash', '-c', script], cwd=tree, env=env, text=True,
                               capture_output=True, timeout=300)
            self.assertEqual(r.stderr.strip(), '', r.stderr)   # no unbound-variable escapes
            return r.stdout

    def finalfail(self, out):
        return int(re.search(r'^FINALFAIL=(\d+)$', out, re.M).group(1))

    def test_all_green_needs_no_recheck(self):
        out = self.run_gate({'d/A.ec': '(* A *)\n', 'd/B.ec': '(* B *)\n',
                             'c/P.ec': '(* P *)\n', 'c/F.ec': '(* F *)\nCONTROL_FAIL\n'},
                            ['d/A.ec', 'd/B.ec'],
                            [('c/P.ec', 'MUST-PASS', '-'), ('c/F.ec', 'MUST-FAIL', 'cannot prove goal')])
        self.assertIn('### SERIAL_RECHECK candidates=0', out)
        self.assertEqual(self.finalfail(out), 0, out)
        for line in ('OK   target d/A.ec', 'OK   d/B.ec (cli, 1 cmds)', 'OK   control c/P.ec (MUST-PASS)',
                     'OK   control c/F.ec (MUST-FAIL, rejected for the DECLARED reason)'):
            self.assertIn(line, out)
        self.assertIn('### JOBS_QUEUED=6 JOBS_JUDGED=6 UNJUDGED=0', out)

    def test_load_flakes_are_rechecked_alone_named_and_judged_on_the_solo_run(self):
        out = self.run_gate({'d/A.ec': '(* A *)\nFLAKY\n', 'd/B.ec': '(* B *)\n',
                             'c/F.ec': '(* F *)\nCONTROL_FAIL_STATIC\nFLAKY\n'},
                            ['d/A.ec', 'd/B.ec'], [('c/F.ec', 'MUST-FAIL', 'the given proof-term proves')])
        self.assertIn('### SOLO jobs=0 ', out)
        self.assertIn('### SERIAL_RECHECK candidates=3', out)
        self.assertIn('RECHECK compile:d/A.ec: under parallel load -> FAIL target d/A.ec', out)
        self.assertIn('RECHECK cli:d/A.ec: under parallel load -> FAIL d/A.ec (cli): 1 diagnostic', out)
        self.assertIn('RECHECK control:c/F.ec: under parallel load -> FAIL control c/F.ec: failed for the WRONG reason', out)
        self.assertEqual(out.count('LOADFLAKE '), 3, out)
        self.assertIn('### SERIAL_RECHECK rerun=3 load_flakes=3 still_failing=0', out)
        self.assertIn('OK   target d/A.ec', out)
        self.assertIn('OK   control c/F.ec (MUST-FAIL, rejected for the DECLARED reason)', out)
        self.assertEqual(self.finalfail(out), 0, out)

    def test_a_real_failure_survives_the_recheck(self):
        out = self.run_gate({'d/A.ec': '(* A *)\nBROKEN\n', 'd/B.ec': '(* B *)\n'}, ['d/A.ec', 'd/B.ec'], [])
        self.assertIn('### SERIAL_RECHECK rerun=2 load_flakes=0 still_failing=2', out)
        self.assertIn('FAIL target d/A.ec', out)
        self.assertIn('FAIL d/A.ec (cli): 1 diagnostic', out)
        self.assertNotIn('LOADFLAKE', out)
        self.assertEqual(self.finalfail(out), 2, out)

    def test_the_load_oracle_masks_a_weakened_control_when_run_in_parallel(self):
        # The fake must really produce the false OK this design exists to prevent;
        # otherwise the next test proves nothing.  Run it in a plain parallel batch.
        with Fixture() as fx:
            (fx.bin / 'easycrypt').write_text(FAKE_E2E)
            fx.file('c/M.ec', '(* M *)\nMASKABLE\n')
            rows = [('control:c/M.ec', '-', 'easycrypt compile -I base -I drafts c/M.ec')]
            for i in range(3):
                fx.file(f'd/S{i}.ec', f'(* S{i} *)\nSLEEP 2\n' + 'x' * 2000)
                rows.append(compile_row(f'compile:d/S{i}.ec', f'd/S{i}.ec'))
            r = fx.run(rows, workers='4')
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn('cannot prove goal (strict)', fx.out_text(0))   # masked under load
            self.assertEqual(fx.res(0)[:2], ['done', '1'])

    def test_a_weakened_solver_reason_control_is_never_judged_under_load(self):
        files = {'c/M.ec': '(* M *)\nMASKABLE\n'}
        for i in range(3):
            files[f'd/S{i}.ec'] = f'(* S{i} *)\nSLEEP 2\n' + 'x' * 2000
        out = self.run_gate(files, sorted(f for f in files if f.startswith('d/')),
                            [('c/M.ec', 'MUST-FAIL', 'cannot prove goal')])
        self.assertIn('### SOLO jobs=1 ', out)
        self.assertIn('### PROOF_JOBS_RECHECK planned=1 ', out)
        self.assertIn('FAIL control c/M.ec: MUST-FAIL but COMPILED', out)     # the alarm, not a masked OK
        self.assertNotIn('OK   control c/M.ec', out)
        self.assertEqual(self.finalfail(out), 1, out)

    def test_solo_controls_run_alone_even_when_the_recheck_cap_is_exceeded(self):
        files = {f'd/T{i}.ec': f'(* T{i} *)\nBROKEN\n' for i in range(13)}   # 26 would-FAIL jobs
        files['c/G.ec'] = '(* G *)\nCONTROL_FAIL\n'
        out = self.run_gate(files, sorted(f for f in files if f.startswith('d/')),
                            [('c/G.ec', 'MUST-FAIL', 'cannot prove goal')])
        self.assertIn('### SERIAL_RECHECK skipped: 26 would-FAIL jobs', out)
        self.assertIn('### PROOF_JOBS_RECHECK planned=1 ', out)              # the SOLO control only
        self.assertIn('OK   control c/G.ec (MUST-FAIL, rejected for the DECLARED reason)', out)

    def test_a_mass_failure_is_not_rechecked(self):
        files = {f'd/T{i}.ec': f'(* T{i} *)\nBROKEN\n' for i in range(13)}   # 26 would-FAIL jobs
        out = self.run_gate(files, sorted(files), [])
        self.assertIn('### SERIAL_RECHECK skipped: 26 would-FAIL jobs exceed RECHECK_MAX=25', out)
        self.assertNotIn('PROOF_JOBS_RECHECK', out)
        self.assertEqual(self.finalfail(out), 26, out)


if __name__ == '__main__':
    unittest.main()
