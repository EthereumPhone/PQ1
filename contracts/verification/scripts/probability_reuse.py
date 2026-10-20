"""Conservative GitHub PR control provenance; downloaded evidence is only data.

The API records a digest supplied by the pinned uploader. GitHub, the hosted
runner and reviewed workflow/actions remain trusted, not proved by that digest.
Failures refuse reuse; the caller must run the complete cold controls instead.
"""
from __future__ import annotations

import base64
import datetime
import io
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from probability_execution import (
    authenticate_shards, canonical, check_file, decode_json, digest, read_json, require,
)

REPOSITORY = "EthereumPhone/PQ1"
REPOSITORY_ID = 1203164307
WORKFLOW = ".github/workflows/lean-probability.yml"
COUNT = 8
PROBE_JOB = "PR control reuse eligibility"
FINAL_JOB = "PMF proofs and semantic controls (8)"
CHECKOUT_STEP = "Run actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5"
INSTALL_STEP = "install elan (toolchain pinned by lean-toolchain)"
FETCH_STEP = "fetch pinned mathlib probability cache"
CLEAN_STEP = "require no dependency cache"
MAX_ARCHIVE = 32 * 1024**2
MAX_EXPANDED = 128 * 1024**2
MAX_MEMBER = 16 * 1024**2
MAX_RESPONSE = 32 * 1024**2
MAX_REQUEST = 128 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _fetch(request: dict) -> dict:
    """One transaction in the trusted transport worker; never follow redirects."""
    try:
        response = urllib.request.build_opener(NoRedirect).open(
            urllib.request.Request(request["url"], headers=request["headers"]),
            timeout=min(30, request["timeout"]))
    except urllib.error.HTTPError as exc:
        with exc:
            return {"status": exc.code, "location": exc.headers.get("Location", "")}
    with response:
        require('rel="next"' not in response.headers.get("Link", ""),
                "GitHub result listing exceeds bounded page")
        data = response.read(MAX_RESPONSE + 1)
        require(len(data) <= MAX_RESPONSE, "GitHub response exceeds limit")
        return {"status": response.status, "data": base64.b64encode(data).decode("ascii")}


def _transport(url: str, headers: dict, remaining: float) -> dict:
    # Socket timeouts bound individual operations, not a progressing response.
    # The parent bounds connection, headers and body together and kills/reaps
    # the worker on expiry. Only this same trusted module runs in the worker;
    # the credential/request travels through stdin, never argv or environment.
    request = canonical({"url": url, "headers": headers, "timeout": remaining})
    require(len(request) <= MAX_REQUEST, "GitHub request exceeds limit")
    env = {k: v for k, v in os.environ.items() if k not in {"GH_TOKEN", "GITHUB_TOKEN"}}
    try:
        result = subprocess.run(
            [sys.executable, "-E", "-S", str(Path(__file__).resolve()), "--fetch"],
            input=request, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=env, timeout=remaining)
    except subprocess.TimeoutExpired:
        raise RuntimeError("GitHub request time budget exhausted") from None
    except OSError:
        raise RuntimeError("GitHub request transport failure") from None
    require(result.returncode == 0, "GitHub request transport failure")
    return decode_json(result.stdout.decode("ascii"))


class GitHub:
    """Bound requests and do not forward an API token to signed blob URLs."""
    def __init__(self, token: str, timeout: int = 300):
        require(bool(token), "missing read-only GitHub token")
        self.token = token
        self.deadline = time.monotonic() + timeout
        self.requests = 0

    def _read(self, url: str, authorized: bool, binary: bool = False) -> bytes:
        self.requests += 1
        require(self.requests <= 100, "GitHub request budget exhausted")
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, "GitHub request time budget exhausted")
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "pq1-probability-reuse",
                   "X-GitHub-Api-Version": "2022-11-28"}
        if authorized:
            require(url.startswith("https://api.github.com/repos/" + REPOSITORY + "/"),
                    "API request outside repository")
            headers["Authorization"] = "Bearer " + self.token
        response = _transport(url, headers, remaining)
        require(isinstance(response, dict) and type(response.get("status")) is int,
                "invalid transport response")
        status = response["status"]
        if authorized and binary and status == 302:
            location = response.get("location", "")
            parsed = urllib.parse.urlsplit(location)
            require(parsed.scheme == "https" and bool(parsed.hostname)
                    and parsed.username is None and parsed.password is None
                    and (parsed.hostname.endswith(".blob.core.windows.net")
                         or parsed.hostname.endswith(".actions.githubusercontent.com")),
                    "unexpected GitHub artifact/log redirect")
            return self._read(location, False, True)
        require(200 <= status < 300, f"GitHub request failed (HTTP {status})")
        data = base64.b64decode(response["data"], validate=True)
        require(len(data) <= MAX_RESPONSE, "GitHub response exceeds limit")
        require(time.monotonic() <= self.deadline, "GitHub request time budget exhausted")
        return data

    def get(self, path: str):
        return decode_json(self._read("https://api.github.com/repos/" + REPOSITORY + "/" + path,
                                      True).decode())

    def binary(self, path: str) -> bytes:
        return self._read("https://api.github.com/repos/" + REPOSITORY + "/" + path, True, True)


def integer(value, label: str) -> int:
    require(type(value) is int and value > 0, f"invalid {label}")
    return value


def sha(value) -> str:
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value) is not None,
            "invalid Git identity")
    return value


def complete_list(data: dict, key: str) -> list:
    require(isinstance(data, dict) and isinstance(data.get(key), list), "invalid GitHub listing")
    rows = data[key]
    require(type(data.get("total_count")) is int and data["total_count"] == len(rows)
            and len(rows) <= 100, "incomplete GitHub listing")
    return rows


def repository(data: dict) -> None:
    require(data.get("full_name") == REPOSITORY and type(data.get("id")) is int
            and data["id"] == REPOSITORY_ID, "foreign repository")


def consumer(context: dict) -> None:
    require(context.get("kind") == "github" and context.get("GITHUB_REPOSITORY") == REPOSITORY
            and context.get("GITHUB_EVENT_NAME") == "push"
            and os.environ.get("GITHUB_REF") == "refs/heads/master", "not an eligible master push")
    require(context.get("commit") == context.get("GITHUB_SHA") == context.get("GITHUB_WORKFLOW_SHA")
            and context.get("GITHUB_WORKFLOW_REF") == REPOSITORY + "/" + WORKFLOW + "@refs/heads/master",
            "consumer workflow/checkout context differs")
    sha(context["commit"]); sha(context["tree"])


def forced_cold() -> bool:
    # An unknown override cannot enable reuse.
    return os.environ.get("PROBABILITY_FORCE_COLD", "false") != "false"


def final_route(probe_result: str, candidate: str, matrix_result: str) -> str:
    """Only a completed cold matrix or the intentional candidate route can run."""
    if matrix_result == "success":
        return "cold"
    require(matrix_result == "skipped" and probe_result == "success"
            and re.fullmatch(r"[1-9][0-9]*", candidate or "") is not None,
            "neither a successful cold matrix nor an intentional reuse candidate")
    return "reuse"


def origin_run(api, target: dict, requested: str | None = None) -> tuple[dict, dict, dict]:
    consumer(target)
    require(not forced_cold(), "forced cold replay")
    target_commit = api.get("git/commits/" + target["commit"])
    require(target_commit.get("sha") == target["commit"]
            and target_commit.get("tree", {}).get("sha") == target["tree"], "target Git tree differs")
    prs = api.get("commits/" + target["commit"] + "/pulls?per_page=100")
    require(isinstance(prs, list) and len(prs) < 100, "incomplete PR listing")
    eligible = []
    for row in prs:
        number = integer(row.get("number"), "PR number")
        pr = api.get(f"pulls/{number}")
        if pr.get("merged") is True and pr.get("merge_commit_sha") == target["commit"]:
            eligible.append(pr)
    require(len(eligible) == 1, "missing or ambiguous landed PR")
    pr = eligible[0]
    require(pr["base"]["ref"] == "master", "PR base is not master")
    repository(pr["base"]["repo"]); repository(pr["head"]["repo"])
    head = sha(pr["head"]["sha"])
    workflow = api.get("actions/workflows/lean-probability.yml")
    wid = integer(workflow.get("id"), "workflow ID")
    require(workflow.get("path") == WORKFLOW and workflow.get("state") == "active",
            "workflow path/state differs")
    runs = complete_list(api.get(f"actions/workflows/{wid}/runs?event=pull_request&head_sha={head}&per_page=100"),
                         "workflow_runs")
    require(len(runs) == 1, "missing or ambiguous PR workflow run")
    run_id = integer(runs[0].get("id"), "run ID")
    require(requested is None or str(run_id) == requested, "candidate run changed")
    run = api.get(f"actions/runs/{run_id}")
    repository(run["repository"]); repository(run["head_repository"])
    require(run.get("id") == run_id and type(run.get("run_attempt")) is int
            and run["run_attempt"] == 1 and run.get("head_sha") == head
            and run.get("event") == "pull_request" and run.get("status") == "completed"
            and run.get("conclusion") == "success" and run.get("workflow_id") == wid
            and run.get("path") == WORKFLOW and run.get("referenced_workflows") == [],
            "ineligible PR run/attempt/workflow")
    return pr, run, workflow


def origin_jobs(api, run: dict) -> list:
    jobs = complete_list(api.get(f'actions/runs/{run["id"]}/attempts/1/jobs?per_page=100'), "jobs")
    expected = {PROBE_JOB, FINAL_JOB} | {f"PMF controls ({i}/{COUNT})" for i in range(COUNT)}
    require(len(jobs) == len(expected) and {j.get("name") for j in jobs} == expected,
            "missing/duplicate/extra producer job")
    require(len({integer(j.get("id"), "job ID") for j in jobs}) == len(jobs), "duplicate job ID")
    for job in jobs:
        require(job.get("run_id") == run["id"] and job.get("run_attempt") == 1
                and job.get("head_sha") == run["head_sha"] and job.get("status") == "completed"
                and job.get("conclusion") == "success" and job.get("labels") == ["ubuntu-latest"],
                "failed/foreign producer job")
        steps = job["steps"]
        names = [s["name"] for s in steps]
        require(len(names) == len(set(names)), "duplicate producer step")
        require(not any("cache pinned probability dependencies" in name for name in names),
                "producer used an Actions dependency cache")
        required = {CHECKOUT_STEP, INSTALL_STEP, FETCH_STEP, CLEAN_STEP}
        if job["name"] == PROBE_JOB:
            required |= {"select eligible original run"}
        elif job["name"] == FINAL_JOB:
            required |= {"require cold or reuse dependency state", "runner regression controls",
                         "verify-probability (fresh kernel build, claims and typed controls)",
                         "preserve aggregate evidence"}
        else:
            required |= {"runner regression controls", "fresh proof build and control shard",
                         "preserve shard evidence"}
        require(required <= set(names), "missing producer execution/upload step")
        for step in steps:
            expected_conclusion = ("skipped" if job["name"] == PROBE_JOB
                                   and step["name"] in {INSTALL_STEP, FETCH_STEP, CLEAN_STEP}
                                   else "success")
            require(step.get("status") == "completed" and step.get("conclusion") == expected_conclusion,
                    "failed/skipped producer step")
    return jobs


def checkout_from_log(text: str) -> str:
    pattern = (r"(?m)^\S+ \[command\]/usr/bin/git log -1 --format=%H\r?\n"
               r"\S+ ([0-9a-f]{40})\r?$")
    matches = re.findall(pattern, text)
    require(len(matches) == 1, "missing/ambiguous GitHub checkout log identity")
    return matches[0]


def origin_context(api, root: Path, target: dict, pr: dict, run: dict, jobs: list) -> dict:
    commits = {checkout_from_log(api.binary(f'actions/jobs/{j["id"]}/logs').decode()) for j in jobs}
    require(len(commits) == 1, "producer checkout identities differ")
    commit = commits.pop()
    obj = api.get("git/commits/" + commit)
    require(obj.get("sha") == commit and obj.get("tree", {}).get("sha") == target["tree"],
            "producer checkout tree differs")
    parents = obj.get("parents", [])
    require(len(parents) == 2 and parents[1].get("sha") == run["head_sha"],
            "PR head-to-checkout relationship differs")
    first = sha(parents[0]["sha"])
    comparison = api.get(f'compare/{first}...{target["commit"]}')
    require(comparison.get("status") in {"ahead", "identical"}
            and comparison.get("merge_base_commit", {}).get("sha") == first,
            "PR base not an ancestor of landed target")
    workflow_bytes = (root / WORKFLOW).read_bytes()
    require(b"actions/cache@" not in workflow_bytes, "Actions dependency cache not permitted")
    for ref in (commit, run["head_sha"]):
        obj = api.get(f"contents/{WORKFLOW}?ref={ref}")
        require(obj.get("encoding") == "base64" and obj.get("type") == "file"
                and base64.b64decode(obj["content"]) == workflow_bytes, "workflow source differs")
    return {"kind": "github", "commit": commit, "tree": target["tree"],
            "GITHUB_REPOSITORY": REPOSITORY, "GITHUB_RUN_ID": str(run["id"]),
            "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": commit, "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_WORKFLOW_REF": f'{REPOSITORY}/{WORKFLOW}@refs/pull/{pr["number"]}/merge',
            "GITHUB_WORKFLOW_SHA": commit}


def origin_artifacts(api, run: dict) -> list:
    rows = complete_list(api.get(f'actions/runs/{run["id"]}/artifacts?per_page=100'), "artifacts")
    expected = {f"probability-8-{i}-1" for i in range(COUNT)} | {"probability-aggregate-8-1"}
    require(len(rows) == len(expected) and {r.get("name") for r in rows} == expected,
            "missing/duplicate/extra producer artifact")
    require(len({integer(r.get("id"), "artifact ID") for r in rows}) == len(rows), "duplicate artifact ID")
    now = datetime.datetime.now(datetime.timezone.utc)
    for row in rows:
        require(row.get("expired") is False and isinstance(row.get("digest"), str)
                and re.fullmatch(r"sha256:[0-9a-f]{64}", row["digest"]) is not None,
                "expired artifact or missing uploader digest")
        require(datetime.datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00")) > now,
                "artifact past expiry")
        require(type(row.get("size_in_bytes")) is int and 0 < row["size_in_bytes"] <= MAX_ARCHIVE,
                "artifact archive size outside limit")
        source = row["workflow_run"]
        require(source.get("id") == run["id"] and source.get("repository_id") == REPOSITORY_ID
                and source.get("head_repository_id") == REPOSITORY_ID
                and source.get("head_sha") == run["head_sha"], "foreign artifact origin")
    return sorted(rows, key=lambda r: r["name"])


def extract_archive(data: bytes, metadata: dict, destination: Path) -> None:
    require(len(data) <= MAX_ARCHIVE and len(data) == metadata["size_in_bytes"], "archive size differs")
    require("sha256:" + digest(data) == metadata["digest"], "artifact digest mismatch")
    require(not destination.exists(), "artifact destination already exists")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = archive.infolist()
        require(0 < len(members) <= 10000, "archive member count outside limit")
        require(sum(m.file_size for m in members) <= MAX_EXPANDED, "expanded archive exceeds limit")
        seen = set()
        for member in members:
            name = member.filename.rstrip("/") if member.is_dir() else member.filename
            path = PurePosixPath(name)
            require(bool(path.parts) and name not in seen and name == path.as_posix() and not path.is_absolute()
                    and all(part not in {".", "..", ""} for part in path.parts)
                    and re.fullmatch(r"[A-Za-z0-9_./-]+", name) is not None,
                    "unsafe/duplicate archive member")
            seen.add(name)
            mode = member.external_attr >> 16
            require(stat.S_IFMT(mode) in {0, stat.S_IFDIR if member.is_dir() else stat.S_IFREG}
                    and not member.flag_bits & 1, "non-regular/encrypted archive member")
            require(member.file_size <= MAX_MEMBER, "archive member exceeds limit")
        destination.mkdir(parents=True)
        for member in members:
            path = destination / member.filename
            if member.is_dir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("xb") as out:
                    out.write(archive.read(member))


def check_origin_proofs(bundle: Path, identity: dict, context: dict, manifest: dict, check_closures) -> dict:
    result = read_json(bundle / "result.json")
    require(result.get("passed") is True and result.get("mode") == "aggregate"
            and result.get("identity") == identity and result.get("context") == context
            and result.get("manifest_sha256") == identity["manifest_file_sha256"]
            and result.get("lean", {}).get("sha256") == identity["lean_sha256"],
            "original aggregate identity/context differs")
    for key, filename in (("build", "build.log"), ("audit", "axioms.log"),
                          ("closure_canary", "closure-canary.log")):
        row = result[key]
        require(type(row.get("exit")) is int and row["exit"] == 0, "original proof check failed")
        text = check_file(bundle, filename, row["log_sha256"])
        if key == "build":
            require("warning:" not in text, "original build warning")
        elif key == "audit":
            require(check_closures(text, set(manifest["theorems"])) == result["closures"],
                    "original closure records differ")
        else:
            try:
                check_closures(text, {"ProbabilityGateCanary.checked"})
            except RuntimeError as exc:
                require(str(exc) == "non-kernel axiom in closure", "wrong original canary rejection")
            else:
                raise RuntimeError("original added-assumption canary accepted")
            require(row.get("rejected_as_expected") is True, "missing original canary rejection")
    require(result.get("missing_closure_control") is True, "original missing-closure control absent")
    return result


def _metadata_identity(pr: dict, run: dict, workflow: dict) -> dict:
    return {"pr": pr["number"], "head": run["head_sha"], "run": run["id"],
            "attempt": run["run_attempt"], "workflow": workflow["id"], "path": workflow["path"]}


def authenticate_origin(api, root: Path, target: dict, identity: dict, selected: list,
                        manifest: dict, check_closures, out: Path, requested: str | None = None,
                        probe: bool = False) -> dict:
    """The probe is only admission; the final call repeats provenance independently."""
    pr, run, workflow = origin_run(api, target, requested)
    jobs = origin_jobs(api, run)
    context = origin_context(api, root, target, pr, run, jobs)
    artifacts = origin_artifacts(api, run)
    out.mkdir()
    selected_artifacts = ([a for a in artifacts if a["name"] == "probability-aggregate-8-1"]
                          if probe else artifacts)
    for row in selected_artifacts:
        destination = (out / "aggregate" if row["name"] == "probability-aggregate-8-1"
                       else out / "shards" / ("shard-" + row["name"].split("-")[2]))
        extract_archive(api.binary(f'actions/artifacts/{row["id"]}/zip'), row, destination)
    original = read_json(out / "aggregate/result.json")
    original_identity = original.get("identity", {})
    if probe:
        require(set(original_identity) == set(identity) | {"project_libraries_sha256"}
                and all(original_identity[k] == value for k, value in identity.items()),
                "nonproject input/toolchain/dependency identity differs")
    else:
        require(original_identity == identity, "complete target input identity differs")
    original = check_origin_proofs(out / "aggregate", original_identity, context, manifest, check_closures)
    coverage = None
    if not probe:
        coverage = authenticate_shards(out / "shards", COUNT, identity, context, selected,
                                       manifest, check_closures, "success")
        require(original.get("aggregate") == coverage, "original aggregate coverage differs")
    pr2, run2, wf2 = origin_run(api, target, str(run["id"]))
    require(_metadata_identity(pr, run, workflow) == _metadata_identity(pr2, run2, wf2)
            and origin_jobs(api, run2) == jobs and origin_artifacts(api, run2) == artifacts,
            "producer metadata changed during authentication")
    return {"origin": _metadata_identity(pr, run, workflow), "origin_context": context,
            "target_context": target, "identity": identity, "admission_only": probe,
            "artifacts": [{k: a[k] for k in ("id", "name", "digest", "size_in_bytes", "expires_at")}
                          for a in artifacts],
            "aggregate_result_sha256": digest((out / "aggregate/result.json").read_bytes()),
            "coverage": coverage}


if __name__ == "__main__":
    try:
        require(sys.argv[1:] == ["--fetch"], "transport worker arguments")
        raw = sys.stdin.buffer.read(MAX_REQUEST + 1)
        require(len(raw) <= MAX_REQUEST, "transport request exceeds limit")
        sys.stdout.buffer.write(canonical(_fetch(decode_json(raw.decode("utf-8")))))
    except Exception:
        # The parent treats every failed worker as an origin refusal. Do not
        # put request headers, signed URLs or credentials in diagnostics.
        sys.exit(1)
