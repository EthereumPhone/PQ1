#!/usr/bin/env python3
"""Executable workflow/manifest controls for #663/#664; no CI jobs are run."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import check_gate_enforcement as gate

ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = Path('scripts/gate_enforcement.json')
BASELINE = json.loads((ROOT / MANIFEST_PATH).read_text())
BLOCKING = [row for row in BASELINE['gates'] if row['enforcement'] != 'local_documented']


class GateControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fv-gate-control-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        names = [Path('Makefile'), MANIFEST_PATH, Path('scripts/check_gate_enforcement.py'),
                 Path('scripts/kani_mutations.json'),
                 Path('contracts/verification/extraction_registry.json')]
        names += [p.relative_to(ROOT) for p in (ROOT / '.github/workflows').glob('*.yml')]
        names += [p.relative_to(ROOT) for p in ROOT.glob('*/Cargo.toml')]
        for name in names:
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        self.manifest = copy.deepcopy(BASELINE)

    def run_checker(self, *, accept=False):
        (self.root / MANIFEST_PATH).write_text(json.dumps(self.manifest))
        result = subprocess.run([sys.executable, 'scripts/check_gate_enforcement.py'],
                                cwd=self.root, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=20)
        expected = 0 if accept else 1
        self.assertEqual(result.returncode, expected, result.stdout)
        return result.stdout

    def change_workflow(self, row, change):
        relative = Path('.github/workflows') / row['runs_in']
        wf = gate.load_workflow(ROOT / relative)
        for job in wf['jobs'].values():
            for step in job.get('steps', []):
                if step == row['required_context']['step']:
                    # Preserve GitHub's actual on key when serializing YAML 1.1.
                    if True in wf:
                        wf['on'] = wf.pop(True)
                    change(wf, job, step)
                    (self.root / relative).write_text(gate.yaml.safe_dump(wf))
                    return relative
        self.fail(f"fixture could not find the pinned step for {row['id']}")

    def restore_workflow(self, relative):
        shutil.copyfile(ROOT / relative, self.root / relative)

    def test_live_fixture_and_unrelated_step(self):
        self.run_checker(accept=True)
        row = next(r for r in BLOCKING if r['id'] == 'miri')
        self.change_workflow(row, lambda wf, job, step:
                             job['steps'].append({'run': 'echo unrelated'}))
        self.run_checker(accept=True)

    def test_printed_command_for_every_blocking_gate(self):
        for row in BLOCKING:
            with self.subTest(gate=row['id']):
                relative = self.change_workflow(row, lambda wf, job, step:
                                                step.update(run='echo ' + row['make']))
                self.run_checker()
                self.restore_workflow(relative)

    def test_shell_forms_on_both_blocking_tiers(self):
        for name in ['miri', 'kani']:
            row = next(r for r in BLOCKING if r['id'] == name)
            commands = [f'make {name}-other', f'if false; then make {name}; fi',
                        f'# make {name}', f'true # make {name}', f'make {name} || true',
                        f'make {name} || :', f'false && make {name}',
                        f'set +e\nmake {name}\ntrue', f'exit 0\nmake {name}',
                        f'cat <<EOF\nmake {name}\nEOF']
            for run in commands:
                with self.subTest(gate=name, run=run):
                    relative = self.change_workflow(row, lambda wf, job, step: step.update(run=run))
                    self.run_checker()
                    self.restore_workflow(relative)

    def test_step_job_and_workflow_suppression(self):
        row = next(r for r in BLOCKING if r['id'] == 'miri')
        mutations = [
            lambda wf, job, step: step.update({'if': False}),
            lambda wf, job, step: job.update({'if': False}),
            lambda wf, job, step: step.update({'if': "github.event_name == 'workflow_dispatch'"}),
            lambda wf, job, step: step.update({'continue-on-error': True}),
            lambda wf, job, step: job.update({'continue-on-error': True}),
            lambda wf, job, step: step.update(shell='/bin/true {0}'),
            lambda wf, job, step: job.update(defaults={'run': {'shell': '/bin/true {0}'}}),
            lambda wf, job, step: wf.update(defaults={'run': {'shell': '/bin/true {0}'}}),
            lambda wf, job, step: wf.update(env={'MAKEFLAGS': '-n'}),
            lambda wf, job, step: job.update({'runs-on': 'self-hosted'}),
            lambda wf, job, step: job.update(strategy={'matrix': {'include': []}}),
        ]
        for i, mutation in enumerate(mutations):
            with self.subTest(mutation=i):
                relative = self.change_workflow(row, mutation)
                self.run_checker()
                self.restore_workflow(relative)

    def test_every_registration_is_required(self):
        for row in BASELINE['gates']:
            with self.subTest(gate=row['id']):
                self.manifest['gates'] = [r for r in BASELINE['gates'] if r['id'] != row['id']]
                self.assertIn('POLICY:', self.run_checker())
        self.manifest = copy.deepcopy(BASELINE)

    def test_every_blocking_level_is_pinned(self):
        for row in BLOCKING:
            with self.subTest(gate=row['id']):
                self.manifest = copy.deepcopy(BASELINE)
                changed = next(r for r in self.manifest['gates'] if r['id'] == row['id'])
                changed.update(enforcement='local_documented', why='Reviewed 2026-09-15 #663')
                self.assertIn('POLICY:', self.run_checker())

    def test_context_cannot_be_removed(self):
        for row in BLOCKING:
            with self.subTest(gate=row['id']):
                self.manifest = copy.deepcopy(BASELINE)
                changed = next(r for r in self.manifest['gates'] if r['id'] == row['id'])
                del changed['required_context']
                self.assertIn('requires an exact required_context', self.run_checker())

    def test_duplicate_registration_and_waiver(self):
        self.manifest['gates'].append(copy.deepcopy(BASELINE['gates'][0]))
        self.assertIn('POLICY:', self.run_checker())
        self.manifest = copy.deepcopy(BASELINE)
        self.manifest['_completeness_waived']['verify-gate-enforcement'] = 'not checked'
        self.assertIn('POLICY:', self.run_checker())

    def test_checker_checks_its_own_ci_step(self):
        row = next(r for r in BLOCKING if r['id'] == 'verify-gate-enforcement')
        self.change_workflow(row, lambda wf, job, step: step.update(run='true'))
        self.assertIn('verify-gate-enforcement:', self.run_checker())

    def test_local_workflow_metadata(self):
        row = next(r for r in self.manifest['gates'] if r['id'] == 'checkct')
        for runs_in in ['missing.yml', 'ci.yml']:
            row['runs_in'] = runs_in
            self.assertIn('checkct:', self.run_checker())


    def test_pull_request_trigger_and_activity_coverage(self):
        row = next(r for r in BLOCKING if r['id'] == 'verify-fv-lints')
        mutations = [
            lambda wf, job, step: gate._get_on(wf).pop('pull_request'),
            lambda wf, job, step: gate._get_on(wf)['pull_request'].update(types=['closed']),
            lambda wf, job, step: gate._get_on(wf)['pull_request'].update(types=[]),
            lambda wf, job, step: gate._get_on(wf)['pull_request'].update(types=['opened', 'reopened']),
            lambda wf, job, step: gate._get_on(wf)['pull_request'].update(types='synchronize'),
        ]
        for i, mutation in enumerate(mutations):
            with self.subTest(mutation=i):
                relative = self.change_workflow(row, mutation)
                self.assertIn('pull_request', self.run_checker())
                self.restore_workflow(relative)
        self.change_workflow(row, lambda wf, job, step:
                             gate._get_on(wf)['pull_request'].update(types=['opened', 'synchronize', 'reopened']))
        self.run_checker(accept=True)

    def test_easycrypt_helper_and_control_paths(self):
        names = ['contracts/verification/easycrypt/**',
                 'contracts/verification/scripts/check_easycrypt.sh',
                 'contracts/verification/scripts/ec_sweep.py',
                 'contracts/verification/scripts/ec_axioms.py',
                 'contracts/verification/Makefile', '.github/workflows/lean-fv.yml']
        for name in names:
            with self.subTest(path=name):
                self.manifest = copy.deepcopy(BASELINE)
                row = next(r for r in self.manifest['gates'] if r['id'] == 'verify-easycrypt-pins')
                row['polices_paths'].remove(name)
                self.assertIn('easycrypt-pins-reverse:', self.run_checker())

    def test_current_split_paths_cannot_be_removed_from_either_lane(self):
        for gate_id in ('verify-easycrypt-split-pins', 'verify-easycrypt-split'):
            row = next(r for r in BASELINE['gates'] if r['id'] == gate_id)
            for name in row['polices_paths']:
                with self.subTest(gate=gate_id, path=name):
                    self.manifest = copy.deepcopy(BASELINE)
                    changed = next(r for r in self.manifest['gates'] if r['id'] == gate_id)
                    changed['polices_paths'].remove(name)
                    self.assertIn('easycrypt-split-reverse:', self.run_checker())

    def test_split_job_requires_its_shared_makefile_prerequisite(self):
        row = next(r for r in BLOCKING if r['id'] == 'verify-easycrypt-split')
        def remove_setup(wf, job, step):
            job['steps'] = [s for s in job['steps']
                            if s.get('name') != 'install elan (toolchain pinned by lean-toolchain)']
        self.change_workflow(row, remove_setup)
        self.run_checker()

    def test_per_pr_denylists_are_rejected(self):
        row = next(r for r in BLOCKING if r['id'] == 'miri')
        for event in ['push', 'pull_request']:
            for pattern in ['secure/src/nsc/ns_ptr.rs', 'secure/src/nsc/*.rs',
                            '**/*.rs', 'docs/**']:
                with self.subTest(event=event, pattern=pattern):
                    def deny(wf, job, step):
                        triggers = gate._get_on(wf)
                        if triggers.get(event) is None:
                            triggers[event] = {}
                        triggers[event].pop('paths', None)
                        triggers[event]['paths-ignore'] = [pattern]
                    relative = self.change_workflow(row, deny)
                    self.assertIn('paths-ignore` is unsupported', self.run_checker())
                    self.restore_workflow(relative)

    def test_allowlist_covers_whole_model_surface(self):
        row = next(r for r in BLOCKING if r['id'] == 'verify-easycrypt-pins')
        model = 'contracts/verification/easycrypt'
        for replacement in [model, model + '/*', model + '/axiom_pins.txt',
                            model + '/**/*.ec']:
            with self.subTest(replacement=replacement):
                def narrow(wf, job, step):
                    for event in ['push', 'pull_request']:
                        paths = gate._get_on(wf)[event]['paths']
                        paths[paths.index(model + '/**')] = replacement
                relative = self.change_workflow(row, narrow)
                self.assertIn('does NOT cover', self.run_checker())
                self.restore_workflow(relative)
        # The inclusion proof supports recursive roots and literal suffixes,
        # without treating a single star or literal directory as recursive.
        self.assertTrue(gate._covers(['contracts/**'], model + '/**'))
        self.assertTrue(gate._covers(['**/Cargo.toml'], 'Cargo.toml'))
        self.assertTrue(gate._covers(['**/Cargo.toml'], 'secure/Cargo.toml'))
        self.assertFalse(gate._covers(['*'], 'secure/Cargo.toml'))
        self.assertFalse(gate._covers(['secure/*'], 'secure/src/nsc/ns_ptr.rs'))
        crates = {'pqsigner-domain': 'domain'}
        self.assertTrue(gate.kani_makefile_coverage(['domain/s'], list(crates), crates))
        self.assertEqual(gate.kani_makefile_coverage(['domain/**'], list(crates), crates), [])

    def test_protocol_family_scope_and_local_wrapper(self):
        symbolic = next(r for r in self.manifest['gates'] if r['id'] == 'verify-protocol-models')
        computational = next(r for r in self.manifest['gates'] if r['id'] == 'verify-cryptoverif')
        source = 'contracts/verification/cryptoverif/seed_split_secrecy.cv'
        self.assertFalse(gate._covers(symbolic['polices_paths'], source))
        self.assertTrue(gate._covers(computational['polices_paths'], source))
        self.assertEqual(computational['enforcement'], 'local_documented')
        symbolic['polices_paths'].append('contracts/verification/cryptoverif/**')
        self.assertIn('protocol-family-scope:', self.run_checker())
        command = subprocess.run(['make', '-n', '--no-print-directory', 'verify-cryptoverif'],
                                 cwd=self.root, text=True, capture_output=True, timeout=20)
        self.assertEqual(command.returncode, 0, command.stderr)
        self.assertIn('PROTOCOL_MODELS=cryptoverif python3 scripts/check_protocol_models.py', command.stdout)

    def test_scheduled_tier_cadence_is_pinned(self):
        workflows = {row['runs_in']: row for row in BLOCKING if row['enforcement'] == 'nightly'}
        self.assertEqual(set(workflows), set(gate.SCHEDULE_POLICY))
        for name, row in workflows.items():
            for schedule in [None, [], [{'cron': '0 0 1 1 *'}],
                             [{'cron': '0 0 31 2 *'}]]:
                with self.subTest(workflow=name, schedule=schedule):
                    def change_schedule(wf, job, step):
                        on = gate._get_on(wf)
                        if schedule is None:
                            on.pop('schedule', None)
                        else:
                            on['schedule'] = schedule
                    relative = self.change_workflow(row, change_schedule)
                    self.assertIn('SCHEDULE_POLICY cadence', self.run_checker())
                    self.restore_workflow(relative)

    def test_branch_filter_grammar_is_bounded(self):
        row = next(r for r in BLOCKING if r['id'] == 'miri')
        for field in ['branches', 'branches-ignore']:
            for pattern in ['master+', 'maste?', 'maste[r]', r'maste\r',
                            '{master,other}', '@(master)', '**/master', '**/**']:
                with self.subTest(field=field, pattern=pattern):
                    def change_branch(wf, job, step):
                        on = gate._get_on(wf)
                        if on.get('pull_request') is None:
                            on['pull_request'] = {}
                        on['pull_request'][field] = [pattern]
                    relative = self.change_workflow(row, change_branch)
                    self.assertIn('branch-pattern syntax', self.run_checker())
                    self.restore_workflow(relative)
        def allowed_branch(wf, job, step):
            on = gate._get_on(wf)
            if on.get('pull_request') is None:
                on['pull_request'] = {}
            on['pull_request']['branches'] = ['mast*']
        self.change_workflow(row, allowed_branch)
        self.run_checker(accept=True)

    def test_event_payload_shapes_fail_closed(self):
        row = next(r for r in BLOCKING if r['id'] == 'miri')
        for event in ['push', 'pull_request']:
            for value in [False, True, 0, '', [], ['opened']]:
                with self.subTest(event=event, value=value):
                    relative = self.change_workflow(row, lambda wf, job, step:
                                                    gate._get_on(wf).update({event: value}))
                    self.assertIn(f'on.{event} must be null or a mapping', self.run_checker())
                    self.restore_workflow(relative)
        relative = self.change_workflow(row, lambda wf, job, step:
                                        wf.update({'on': ['pull_request', False]}))
        self.assertIn('event list must contain non-empty strings', self.run_checker())
        self.restore_workflow(relative)


if __name__ == '__main__':
    unittest.main(verbosity=2)
