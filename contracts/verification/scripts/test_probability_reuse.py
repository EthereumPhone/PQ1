#!/usr/bin/env python3
"""Executable admission, archive and cold-fallback boundaries for control reuse."""
import base64
import copy
import io
import json
import os
import re
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
import zipfile
import warnings

import check_probability as gate
import probability_reuse as reuse
from probability_execution import canonical, digest, read_json
from test_probability_execution import AggregateTests


class FakeGitHub:
    def __init__(self):
        self.data, self.blobs = {}, {}
        self.reads = {}
        self.change = lambda path, count, obj: obj

    def get(self, path):
        self.reads[path] = self.reads.get(path, 0) + 1
        return self.change(path, self.reads[path], copy.deepcopy(self.data[path]))

    def binary(self, path):
        return self.blobs[path]


def archive_directory(directory):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        for p in sorted(directory.rglob("*")):
            if p.is_file():
                archive.writestr(p.relative_to(directory).as_posix(), p.read_bytes())
    return stream.getvalue()


class ReuseTests(unittest.TestCase):
    def setUp(self):
        AggregateTests.setUp(self)
        self.env = patch.dict(os.environ, {"GITHUB_REF": "refs/heads/master", "PROBABILITY_FORCE_COLD": "false"})
        self.env.start(); self.addCleanup(self.env.stop)
        self.root = Path(self.tmp.name) / "root"
        (self.root / ".github/workflows").mkdir(parents=True)
        (self.root / reuse.WORKFLOW).write_text("name: trusted cold workflow\n")
        self.api = FakeGitHub()
        repo = {"full_name": reuse.REPOSITORY, "id": reuse.REPOSITORY_ID}
        self.target = {"kind": "github", "commit": "a" * 40, "tree": "b" * 40,
                       "GITHUB_REPOSITORY": reuse.REPOSITORY, "GITHUB_RUN_ID": "99",
                       "GITHUB_RUN_ATTEMPT": "1", "GITHUB_EVENT_NAME": "push",
                       "GITHUB_SHA": "a" * 40, "GITHUB_WORKFLOW_SHA": "a" * 40,
                       "GITHUB_WORKFLOW_REF": f"{reuse.REPOSITORY}/{reuse.WORKFLOW}@refs/heads/master"}
        self.context = self.target | {"commit": "c" * 40, "GITHUB_SHA": "c" * 40,
                                     "GITHUB_WORKFLOW_SHA": "c" * 40, "GITHUB_RUN_ID": "10",
                                     "GITHUB_EVENT_NAME": "pull_request",
                                     "GITHUB_WORKFLOW_REF": f"{reuse.REPOSITORY}/{reuse.WORKFLOW}@refs/pull/77/merge"}
        self.identity["project_libraries_sha256"] = "libraries"
        for i in range(8):
            bundle = self.directory / f"shard-{i}"
            if i >= 2:
                bundle.mkdir()
                for file in (self.directory / "shard-0").iterdir():
                    if file.is_file():
                        (bundle / file.name).write_bytes(file.read_bytes())
            result = read_json(bundle / "result.json")
            result.update(context=self.context, identity=self.identity, shard=[i, 8])
            if i >= 2:
                result["controls"] = []
            (bundle / "result.json").write_bytes(canonical(result))
        coverage = reuse.authenticate_shards(self.directory, 8, self.identity, self.context,
                                              self.cases, self.manifest, gate.check_closures, "success")
        aggregate = self.directory.parent / "aggregate"
        aggregate.mkdir()
        result = read_json(self.directory / "shard-0/result.json")
        result.update(mode="aggregate", shard=None, aggregate=coverage)
        del result["controls"]
        for name in ("build.log", "axioms.log", "closure-canary.log"):
            (aggregate / name).write_bytes((self.directory / "shard-0" / name).read_bytes())
        (aggregate / "result.json").write_bytes(canonical(result))
        pr = {"number": 77, "merged": True, "merge_commit_sha": "a" * 40,
              "base": {"ref": "master", "repo": repo}, "head": {"sha": "a" * 40, "repo": repo}}
        workflow = {"id": 123, "path": reuse.WORKFLOW, "state": "active"}
        run = {"id": 10, "run_attempt": 1, "head_sha": "a" * 40, "event": "pull_request",
               "status": "completed", "conclusion": "success", "workflow_id": 123,
               "path": reuse.WORKFLOW, "referenced_workflows": [], "repository": repo, "head_repository": repo}
        jobs = []
        for i, name in enumerate([reuse.PROBE_JOB, reuse.FINAL_JOB] + [f"PMF controls ({n}/8)" for n in range(8)]):
            names = [reuse.CHECKOUT_STEP, reuse.INSTALL_STEP, reuse.CLEAN_STEP, reuse.FETCH_STEP]
            if name == reuse.PROBE_JOB:
                names += ["select eligible original run"]
            elif name == reuse.FINAL_JOB:
                names += ["require cold or reuse dependency state", "runner regression controls",
                          "verify-probability (fresh kernel build, claims and typed controls)", "preserve aggregate evidence"]
            else:
                names += ["runner regression controls", "fresh proof build and control shard", "preserve shard evidence"]
            steps = [{"name": n, "status": "completed", "conclusion":
                      "skipped" if name == reuse.PROBE_JOB and n in {reuse.INSTALL_STEP, reuse.CLEAN_STEP, reuse.FETCH_STEP}
                      else "success"} for n in names]
            jobs.append(dict(id=100+i, name=name, run_id=10, run_attempt=1, head_sha="a"*40,
                             status="completed", conclusion="success", labels=["ubuntu-latest"], steps=steps))
            self.api.blobs[f"actions/jobs/{100+i}/logs"] = (
                "2026-10-20T00:00:00Z [command]/usr/bin/git log -1 --format=%H\n"
                "2026-10-20T00:00:01Z " + "c"*40 + "\n").encode()
        artifacts = []
        for i in range(9):
            name = f"probability-8-{i}-1" if i < 8 else "probability-aggregate-8-1"
            data = archive_directory(self.directory / f"shard-{i}" if i < 8 else aggregate)
            artifacts.append(dict(id=200+i, name=name, digest="sha256:"+digest(data), size_in_bytes=len(data),
                                  expired=False, expires_at="2099-01-01T00:00:00Z",
                                  workflow_run=dict(id=10, repository_id=reuse.REPOSITORY_ID,
                                                    head_repository_id=reuse.REPOSITORY_ID, head_sha="a"*40)))
            self.api.blobs[f"actions/artifacts/{200+i}/zip"] = data
        self.api.data = {
            "git/commits/"+"a"*40: {"sha": "a"*40, "tree": {"sha": "b"*40}},
            "git/commits/"+"c"*40: {"sha": "c"*40, "tree": {"sha": "b"*40},
                                    "parents": [{"sha": "d"*40}, {"sha": "a"*40}]},
            "commits/"+"a"*40+"/pulls?per_page=100": [{"number": 77}], "pulls/77": pr,
            "actions/workflows/lean-probability.yml": workflow,
            "actions/workflows/123/runs?event=pull_request&head_sha="+"a"*40+"&per_page=100":
                {"total_count": 1, "workflow_runs": [run]},
            "actions/runs/10": run,
            "actions/runs/10/attempts/1/jobs?per_page=100": {"total_count": len(jobs), "jobs": jobs},
            "actions/runs/10/artifacts?per_page=100": {"total_count": len(artifacts), "artifacts": artifacts},
            "compare/"+"d"*40+"..."+"a"*40: {"status": "ahead", "merge_base_commit": {"sha": "d"*40}},
        }
        for ref in ("a"*40, "c"*40):
            self.api.data[f"contents/{reuse.WORKFLOW}?ref={ref}"] = {
                "encoding": "base64", "type": "file", "content": base64.b64encode((self.root/reuse.WORKFLOW).read_bytes()).decode()}
        self.counter = 0

    def authenticate(self, probe=False):
        self.counter += 1
        identity = {k:v for k,v in self.identity.items() if not probe or k != "project_libraries_sha256"}
        return reuse.authenticate_origin(self.api, self.root, self.target, identity, self.cases,
                                          self.manifest, gate.check_closures,
                                          self.root / f"out-{self.counter}", "10", probe)

    def test_complete_authentication_and_probe_are_distinct(self):
        evidence = self.authenticate()
        self.assertFalse(evidence["admission_only"])
        self.assertEqual(evidence["coverage"]["jobs"], 6)
        self.assertNotEqual(evidence["origin_context"], evidence["target_context"])
        probe = self.authenticate(True)
        self.assertTrue(probe["admission_only"])
        self.assertIsNone(probe["coverage"])
        self.assertNotIn("project_libraries_sha256", probe["identity"])

    def test_foreign_failed_rerun_or_ambiguous_run(self):
        original = copy.deepcopy(self.api.data)
        changes = [{"run_attempt": 2}, {"run_attempt": True}, {"event": "push"}, {"status": "in_progress"},
                   {"conclusion": "failure"}, {"head_sha": "f"*40}, {"workflow_id": 777}, {"path": "other.yml"},
                   {"referenced_workflows": [{"path": "foreign"}]}, {"repository": {"id": 1, "full_name": reuse.REPOSITORY}},
                   {"head_repository": {"id": reuse.REPOSITORY_ID, "full_name": "fork/PQ1"}}]
        for change in changes:
            self.api.data = copy.deepcopy(original); self.api.data["actions/runs/10"].update(change)
            with self.subTest(change=change), self.assertRaises((RuntimeError, KeyError)):
                self.authenticate()
        self.api.data = copy.deepcopy(original)
        key = next(k for k in self.api.data if "/runs?" in k)
        self.api.data[key]["workflow_runs"] *= 2; self.api.data[key]["total_count"] = 2
        with self.assertRaisesRegex(RuntimeError, "ambiguous"):
            self.authenticate()

    def test_wrong_pr_target_workflow_and_checkout(self):
        original = copy.deepcopy(self.api.data)
        changes = [lambda: self.api.data['pulls/77'].update(merged=False),
                   lambda: self.api.data['pulls/77']['head']['repo'].update(full_name='fork/PQ1'),
                   lambda: self.api.data['pulls/77']['base'].update(ref='feature'),
                   lambda: self.api.data['git/commits/'+'c'*40]['tree'].update(sha='f'*40),
                   lambda: self.api.data['git/commits/'+'c'*40]['parents'].reverse(),
                   lambda: self.api.data['compare/'+'d'*40+'...'+'a'*40].update(status='diverged'),
                   lambda: self.api.data[f'contents/{reuse.WORKFLOW}?ref='+ 'a'*40].update(content='bm8='),
                   lambda: self.api.data['actions/workflows/lean-probability.yml'].update(state='disabled_manually')]
        for i, change in enumerate(changes):
            self.api.data = copy.deepcopy(original); change()
            with self.subTest(case=i), self.assertRaises(RuntimeError):
                self.authenticate()
        self.api.data = original
        self.api.blobs['actions/jobs/101/logs'] = self.api.blobs['actions/jobs/101/logs'].replace(b'c'*40,b'f'*40)
        with self.assertRaisesRegex(RuntimeError, 'checkout identities'):
            self.authenticate()

    def test_missing_failed_skipped_jobs_or_steps(self):
        key = 'actions/runs/10/attempts/1/jobs?per_page=100'; original = copy.deepcopy(self.api.data[key])
        changes = [lambda x:x['jobs'].pop(), lambda x:x['jobs'].append(copy.deepcopy(x['jobs'][0])),
                   lambda x:x['jobs'][2].update(conclusion='cancelled'),
                   lambda x:x['jobs'][2]['steps'][-1].update(conclusion='skipped'),
                   lambda x:x['jobs'][2]['steps'].pop(),
                   lambda x:x['jobs'][2]['steps'].append(dict(name='cache pinned probability dependencies',status='completed',conclusion='success')),
                   lambda x:x['jobs'][0]['steps'][1].update(conclusion='success')]
        for i, change in enumerate(changes):
            self.api.data[key] = copy.deepcopy(original); change(self.api.data[key])
            with self.subTest(case=i), self.assertRaises(RuntimeError):
                self.authenticate()

    def test_artifact_metadata_and_digest_refusals(self):
        key = 'actions/runs/10/artifacts?per_page=100'; original = copy.deepcopy(self.api.data[key])
        changes = [lambda x:x['artifacts'].pop(), lambda x:x['artifacts'][0].update(expired=True),
                   lambda x:x['artifacts'][0].update(expires_at='2000-01-01T00:00:00Z'),
                   lambda x:x['artifacts'][0].update(digest='sha256:'+'0'*64),
                   lambda x:x['artifacts'][0].update(id=x['artifacts'][1]['id']),
                   lambda x:x['artifacts'][0]['workflow_run'].update(head_repository_id=1),
                   lambda x:x['artifacts'][0].update(size_in_bytes=reuse.MAX_ARCHIVE+1)]
        for i, change in enumerate(changes):
            self.api.data[key] = copy.deepcopy(original); change(self.api.data[key])
            with self.subTest(case=i), self.assertRaises(RuntimeError):
                self.authenticate()

    def test_metadata_replacement_after_download(self):
        def change(path, count, obj):
            if path == 'actions/runs/10/artifacts?per_page=100' and count == 2:
                obj['artifacts'][0]['id'] = 999
            return obj
        self.api.change = change
        with self.assertRaisesRegex(RuntimeError, 'metadata changed'):
            self.authenticate()

    def test_complete_and_partial_identity_mismatch(self):
        for probe, key in ((False, 'project_libraries_sha256'), (True, 'lean_sha256'),
                           (False, 'policy'), (True, 'manifest_file_sha256')):
            previous = self.identity[key]; self.identity[key] = 'changed'
            with self.subTest(probe=probe,key=key), self.assertRaisesRegex(RuntimeError, 'identity differs'):
                self.authenticate(probe)
            self.identity[key] = previous

    def test_raw_controls_required_despite_green_metadata(self):
        # Repackage with a matching uploader digest: green metadata still cannot
        # replace the complete raw consuming-theorem evidence.
        bundle = self.directory / 'shard-0'
        row = read_json(bundle/'result.json'); row['controls'].pop()
        (bundle/'result.json').write_bytes(canonical(row)); data = archive_directory(bundle)
        self.api.blobs['actions/artifacts/200/zip'] = data
        self.api.data['actions/runs/10/artifacts?per_page=100']['artifacts'][0].update(
            digest='sha256:'+digest(data),size_in_bytes=len(data))
        with self.assertRaisesRegex(RuntimeError, 'incomplete shard controls'):
            self.authenticate()

    def test_original_closure_audit_cannot_be_skipped(self):
        bundle = self.directory.parent/'aggregate'; row = read_json(bundle/'result.json')
        row['closures'] = {}; (bundle/'result.json').write_bytes(canonical(row)); data = archive_directory(bundle)
        self.api.blobs['actions/artifacts/208/zip'] = data
        self.api.data['actions/runs/10/artifacts?per_page=100']['artifacts'][8].update(
            digest='sha256:'+digest(data),size_in_bytes=len(data))
        with self.assertRaisesRegex(RuntimeError,'closure records'):
            self.authenticate()


class BoundaryTests(unittest.TestCase):
    def test_probe_and_producer_fetch_cover_proof_imports(self):
        # A missing root gets compiled only by the full project build, making
        # the early probe's package identity differ on every otherwise valid run.
        manifest = json.loads(gate.MANIFEST.read_text())
        roots = {name for source in manifest['sources']
                 for name in re.findall(r'^import (Mathlib\.\S+)\s*$',
                                        (gate.PROJECT/source).read_text(), re.M)}
        commands = re.findall(r'^          lake exe cache get (.*)\n          lake build proofwidgets/widgetJsAll$',
                              (gate.ROOT/reuse.WORKFLOW).read_text(), re.M)
        self.assertEqual(len(commands), 3)
        self.assertEqual(len(set(commands)), 1)
        self.assertTrue(roots <= set(commands[0].split()), roots-set(commands[0].split()))

    def test_dependency_routing_truth_table(self):
        states = ['success','failure','skipped','cancelled','', 'in_progress']
        for probe in states:
            for matrix in states:
                for candidate in ('','10','0','-1','x','10\nforged=true'):
                    expected = matrix == 'success' or (matrix == 'skipped' and probe == 'success' and candidate == '10')
                    with self.subTest(probe=probe,matrix=matrix,candidate=candidate):
                        if expected:
                            self.assertEqual(reuse.final_route(probe,candidate,matrix),
                                             'cold' if matrix == 'success' else 'reuse')
                        else:
                            with self.assertRaises(RuntimeError):reuse.final_route(probe,candidate,matrix)

    def test_fallback_runs_full_census_and_propagates_failure(self):
        for failure in (RuntimeError('expired'), ValueError('malformed'), TimeoutError('network')):
            with patch.object(gate,'authenticate_origin',side_effect=failure), patch.object(gate,'run_controls',return_value=['all']) as run:
                result=gate.reuse_or_cold(None,{}, {},[],{},Path('/unused'),'10','lean',{},4)
                self.assertFalse(result['reuse']['accepted']); self.assertEqual(result['controls'],['all'])
                run.assert_called_once_with(Path('/unused'),'lean',{},4,0,1)
        with patch.object(gate,'authenticate_origin',side_effect=RuntimeError('origin')), patch.object(gate,'run_controls',side_effect=RuntimeError('cold failed')):
            with self.assertRaisesRegex(RuntimeError,'cold failed'):
                gate.reuse_or_cold(None,{}, {},[],{},Path('/unused'),'10','lean',{},4)
        evidence={'coverage':{'jobs':6}}
        with patch.object(gate,'authenticate_origin',return_value=evidence), patch.object(gate,'run_controls') as run:
            self.assertTrue(gate.reuse_or_cold(None,{}, {},[],{},Path('/unused'),'10','lean',{},4)['reuse']['accepted'])
            run.assert_not_called()

    def test_tokens_removed_from_tool_environment(self):
        with patch.dict(os.environ,{'GH_TOKEN':'example','GITHUB_TOKEN':'example','LEAN_PATH':'/foreign'}):
            env=gate.proof_environment()
            self.assertTrue({'GH_TOKEN','GITHUB_TOKEN','LEAN_PATH'}.isdisjoint(env))
            self.assertEqual(os.environ['GH_TOKEN'],'example')

    def test_modes_cannot_drop_controls(self):
        for args in (['--reuse-run','0'],['--reuse-run','1','--aggregate','/x'],
                     ['--reuse-run','1','--shard-index','0'],['--reuse-probe','--shard-index','0']):
            with self.assertRaises(RuntimeError):gate.arguments(args)
        self.assertEqual(gate.arguments(['--reuse-run','10','--shard-count','8']).reuse_run,'10')
        with patch.dict(os.environ,{'PROBABILITY_AGGREGATE':''}):self.assertIsNone(gate.arguments([]).aggregate)
        for value in ('true','','garbage'):
            with patch.dict(os.environ,{'PROBABILITY_FORCE_COLD':value}):self.assertTrue(reuse.forced_cold())

    def test_archive_traversal_duplicates_links_and_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            for i, name in enumerate(('../escape','/absolute','x/../escape','x//escape','./escape','x\\escape')):
                stream=io.BytesIO()
                with zipfile.ZipFile(stream,'w') as archive:archive.writestr(name,'data')
                data=stream.getvalue(); metadata={'size_in_bytes':len(data),'digest':'sha256:'+digest(data)}
                with self.subTest(name=name), self.assertRaises(RuntimeError):
                    reuse.extract_archive(data,metadata,Path(temp)/str(i))
            stream=io.BytesIO()
            with zipfile.ZipFile(stream,'w') as archive:
                member=zipfile.ZipInfo('link');member.external_attr=(stat.S_IFLNK|0o777)<<16;archive.writestr(member,'/outside')
            data=stream.getvalue()
            with self.assertRaisesRegex(RuntimeError,'non-regular'):
                reuse.extract_archive(data,{'size_in_bytes':len(data),'digest':'sha256:'+digest(data)},Path(temp)/'link')
            with self.assertRaisesRegex(RuntimeError,'digest'):
                reuse.extract_archive(data,{'size_in_bytes':len(data),'digest':'sha256:'+'0'*64},Path(temp)/'bad')

    def test_archive_duplicates_and_resource_limits(self):
        with tempfile.TemporaryDirectory() as temp:
            stream = io.BytesIO()
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', UserWarning)
                with zipfile.ZipFile(stream, 'w') as archive:
                    archive.writestr('duplicate', 'one'); archive.writestr('duplicate', 'two')
            data = stream.getvalue(); meta = {'size_in_bytes': len(data), 'digest': 'sha256:'+digest(data)}
            with self.assertRaisesRegex(RuntimeError, 'duplicate'):
                reuse.extract_archive(data, meta, Path(temp)/'duplicate')
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, 'w') as archive: archive.writestr('file', 'four')
            data = stream.getvalue(); meta = {'size_in_bytes': len(data), 'digest': 'sha256:'+digest(data)}
            for bound in ('MAX_MEMBER', 'MAX_EXPANDED', 'MAX_ARCHIVE'):
                with patch.object(reuse, bound, 1), self.subTest(bound=bound), self.assertRaises(RuntimeError):
                    reuse.extract_archive(data, meta, Path(temp)/bound)

    def test_redirect_does_not_forward_token(self):
        api=reuse.GitHub('example-token');calls=[]
        class Response(io.BytesIO):
            headers={}
        def request(req,timeout):
            calls.append(req)
            if len(calls)==1:
                raise urllib.error.HTTPError(req.full_url,302,'redirect',{'Location':'https://example.blob.core.windows.net/signed'},None)
            return Response(b'bytes')
        with patch.object(api.opener,'open',side_effect=request):
            self.assertEqual(api.binary('actions/artifacts/1/zip'),b'bytes')
        self.assertEqual(calls[0].get_header('Authorization'),'Bearer example-token')
        self.assertIsNone(calls[1].get_header('Authorization'))


if __name__ == '__main__':
    unittest.main()
