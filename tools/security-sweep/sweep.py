#!/usr/bin/env python3
"""PQ1 weekly security sweep.

Runs one attacker-goal hunter agent per goal (goals.toml) per backend against a
read-only snapshot of a commit, has a second agent try to refute every finding
and de-duplicate it against the GitHub tracker, merges what survives by root
cause, and writes a report plus GitHub issue drafts. Nothing is filed unless
you run the `file` subcommand afterwards.

    tools/security-sweep/sweep.py run                 # full sweep (takes hours)
    tools/security-sweep/sweep.py run --dry-run       # build prompts only, no agents
    tools/security-sweep/sweep.py run --resume DIR    # finish an interrupted run
    tools/security-sweep/sweep.py file DIR            # file the drafts as issues

See README.md next to this file. Python 3.11+, stdlib only.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import dataclasses
import datetime as dt
import json
import os
import re
import shutil
import signal
import string
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import tomllib
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
GH_REPO = "EthereumPhone/PQ1"
DEFAULT_OUT_ROOT = Path.home() / "pq1-security-sweeps"
KIMI_BIN_DIR = Path.home() / ".kimi-code" / "bin"

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEVERITY_SCALE = """\
- CRITICAL: theft of funds, seed or key extraction, or signing without the user's consent, by tier T0-T2.
- HIGH: the same outcomes at T3-T4 with one chip or one fault; or a permanent brick or lockout reachable by T0-T2.
- MEDIUM: an invariant or threat-model claim is false as stated, but exploitation needs further conditions; or a single-fault path that weakens a security gate.
- LOW: defence-in-depth, or documentation that misstates a security property."""
LIVE_VERDICTS = ("CONFIRMED", "PLAUSIBLE")
# How the CLIs report a spent usage window (Kimi: "You've reached your 5-hour
# usage limit"; Claude: "usage limit reached" / "hit your limit").
QUOTA_PATTERN = re.compile(
    r"usage limit|hit your limit|quota|rate.?limit|too many requests|\b429\b|credit balance", re.I)
PRIORITY_LABEL = {
    "CRITICAL": "priority:critical",
    "HIGH": "priority:high",
    "MEDIUM": "priority:medium",
    "LOW": "priority:low",
}

# Claude agents run with --permission-mode dontAsk, so anything not listed here
# is refused. Tools that can execute arbitrary programs (rg --pre, find -exec,
# sed's `e` command, awk system()) are deliberately absent; the Read/Grep/Glob
# tools cover the same ground. The snapshot is also chmod a-w.
CLAUDE_ALLOWED_TOOLS = [
    "Read", "Grep", "Glob",
    "Bash(ls:*)", "Bash(grep:*)", "Bash(wc:*)",
    "Bash(head:*)", "Bash(tail:*)", "Bash(xxd:*)",
]
CLAUDE_DENIED_TOOLS = ["Edit", "Write", "NotebookEdit", "WebFetch", "WebSearch", "Agent", "Task"]

# --------------------------------------------------------------------------
# Output schemas (enforced by `claude --json-schema`, requested from Kimi in
# the prompt, and re-checked locally by `check_schema` for both).

FINDING_PROPS = {
    "title": {"type": "string"},
    "severity": {"type": "string", "enum": SEVERITIES},
    "attacker_tier": {"type": "string", "description": "weakest tier that can do it, e.g. 'T3: one SE dumped, physical access'"},
    "invariants": {"type": "array", "items": {"type": "string"}},
    "preconditions": {"type": "string"},
    "attack_steps": {"type": "array", "items": {"type": "string"}},
    "code_locations": {"type": "array", "items": {"type": "string"}, "description": "path:line for every step that matters"},
    "why_defences_fail": {"type": "string"},
    "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
    "suggested_fix": {"type": "string"},
}
HUNT_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {"type": "object", "properties": FINDING_PROPS, "required": list(FINDING_PROPS)},
        },
        "checked_and_held": {"type": "array", "items": {"type": "string"}},
        "coverage_notes": {"type": "string"},
    },
    "required": ["findings", "checked_and_held", "coverage_notes"],
}
VERDICT_PROPS = {
    "verdict": {"type": "string", "enum": ["CONFIRMED", "PLAUSIBLE", "REFUTED", "DUPLICATE", "ACCEPTED_RISK"]},
    "severity": {"type": "string", "enum": SEVERITIES},
    "duplicate_of": {"type": ["integer", "null"], "description": "GitHub issue number, or null"},
    "silicon_needed": {"type": "boolean"},
    "evidence": {"type": "array", "items": {"type": "string"}},
    "reasoning": {"type": "string"},
}
VERDICT_SCHEMA = {"type": "object", "properties": VERDICT_PROPS, "required": list(VERDICT_PROPS)}
GROUP_PROPS = {
    "title": {"type": "string"},
    "severity": {"type": "string", "enum": SEVERITIES},
    "member_ids": {"type": "array", "items": {"type": "string"}},
    "issue_body": {"type": "string"},
}
CONSOLIDATE_SCHEMA = {
    "type": "object",
    "properties": {
        "groups": {
            "type": "array",
            "items": {"type": "object", "properties": GROUP_PROPS, "required": list(GROUP_PROPS)},
        }
    },
    "required": ["groups"],
}

_JSON_TYPES = {
    "object": dict, "array": list, "string": str,
    "integer": int, "boolean": bool, "null": type(None),
}


def check_schema(value, schema, path="$"):
    """Return a list of schema violations (the subset of JSON Schema used above)."""
    errors = []
    types = schema.get("type")
    if types is not None:
        types = types if isinstance(types, list) else [types]
        ok = any(
            isinstance(value, _JSON_TYPES[t]) and not (t == "integer" and isinstance(value, bool))
            for t in types
        )
        if not ok:
            return [f"{path}: expected {'/'.join(types)}, got {type(value).__name__}"]
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: {value!r} not in {schema['enum']}")
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}: missing {key!r}")
        for key, sub in schema.get("properties", {}).items():
            if key in value:
                errors += check_schema(value[key], sub, f"{path}.{key}")
    if isinstance(value, list) and "items" in schema:
        for i, item in enumerate(value):
            errors += check_schema(item, schema["items"], f"{path}[{i}]")
    return errors


# --------------------------------------------------------------------------
# Small helpers

_print_lock = threading.Lock()
_log_file = None  # the current run's sweep.log, once the run directory exists


def log(msg: str) -> None:
    now = dt.datetime.now()
    with _print_lock:
        print(f"[{now:%H:%M:%S}] {msg}", flush=True)
        if _log_file:
            _log_file.write(f"[{now:%Y-%m-%d %H:%M:%S}] {msg}\n")
            _log_file.flush()


def open_run_log(run_dir: Path) -> None:
    """Append everything logged from here on to <run_dir>/sweep.log (resumes append too)."""
    global _log_file
    _log_file = open(run_dir / "sweep.log", "a", encoding="utf-8")
    _log_file.write(f"\n===== {dt.datetime.now():%Y-%m-%d %H:%M:%S} {' '.join(sys.argv)}\n")
    _log_file.flush()


def append_history(out_root: Path, run_dir: Path, meta: dict, status: str, summary: dict | None) -> None:
    """One row per sweep attempt in <out_root>/history.md: the log across weeks."""
    path = out_root / "history.md"
    if not path.exists():
        path.write_text(
            "# PQ1 security sweep history\n\n"
            "One row per sweep attempt (a resumed run adds a row). Details: `<run>/report.md`, `<run>/sweep.log`.\n\n"
            "| Finished | Run | Commit | Status | New findings | Re-found known | Failed agents | Cost |\n"
            "|---|---|---|---|---|---|---|---|\n"
        )
    if summary:
        sevs = [g["severity"] for g in summary["new_groups"]]
        new = ", ".join(f"{sevs.count(s)} {s}" for s in SEVERITIES if s in sevs) or "0"
        known = ", ".join(sorted({f"#{d['issue']}" for d in summary["duplicates"] if d.get("issue")})) or "-"
        failed = str(len(summary["failed_hunts"]) + len(summary["failed_verifies"]))
        cost = fmt_cost(summary["cost_usd"])
    else:
        new = known = failed = cost = "-"
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(f"| {dt.datetime.now():%Y-%m-%d %H:%M} | [{run_dir.name}]({run_dir.name}/report.md) | "
                 f"`{meta['commit'][:10]}` | {status} | {new} | {known} | {failed} | {cost} |\n")


def git(*args: str, check: bool = True) -> str:
    res = subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, text=True)
    if check and res.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} failed: {res.stderr.strip()}")
    return res.stdout.strip()


def slugify(text: str, limit: int = 50) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:limit].rstrip("-") or "finding"


def fmt_minutes(seconds: float | None) -> str:
    return "-" if seconds is None else f"{seconds / 60:.0f} min"


def fmt_cost(cost: float | None) -> str:
    return "-" if cost is None else f"${cost:.2f}"


def sev_rank(sev: str) -> int:
    return SEVERITIES.index(sev) if sev in SEVERITIES else len(SEVERITIES)


def fill(template_name: str, **values) -> str:
    text = (HERE / "prompts" / template_name).read_text()
    return string.Template(text).safe_substitute(**values)


def read_json(path: Path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.replace(path)


# --------------------------------------------------------------------------
# Agent processes

_live_procs: set[subprocess.Popen] = set()
_live_lock = threading.Lock()


def kill_group(proc: subprocess.Popen) -> None:
    for sig, grace in ((signal.SIGTERM, 20), (signal.SIGKILL, 10)):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            return
        try:
            proc.wait(timeout=grace)
            return
        except subprocess.TimeoutExpired:
            continue


def kill_all_agents() -> None:
    with _live_lock:
        procs = list(_live_procs)
    for proc in procs:
        kill_group(proc)


def run_process(cmd, cwd, env, stdin_text, timeout, out_path: Path, err_path: Path):
    """Run an agent CLI in its own process group. Returns the exit code, or None on timeout."""
    with open(out_path, "wb") as out, open(err_path, "wb") as err:
        proc = subprocess.Popen(
            cmd, cwd=cwd, env=env, stdout=out, stderr=err,
            stdin=subprocess.PIPE if stdin_text is not None else subprocess.DEVNULL,
            start_new_session=True,
        )
        with _live_lock:
            _live_procs.add(proc)
        try:
            if stdin_text is not None:
                try:
                    proc.stdin.write(stdin_text.encode())
                    proc.stdin.close()
                except BrokenPipeError:
                    pass
            try:
                return proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                kill_group(proc)
                return None
        finally:
            with _live_lock:
                _live_procs.discard(proc)


@dataclasses.dataclass
class AgentResult:
    ok: bool
    data: dict | None = None
    error: str | None = None
    cost_usd: float | None = None
    seconds: float | None = None
    backend: str | None = None
    quota_exhausted: bool = False

    def to_json(self):
        return dataclasses.asdict(self)


def agent_env(sandbox_home: Path) -> dict:
    """Environment for agent processes: no GitHub credentials."""
    env = dict(os.environ)
    for var in ("GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN"):
        env.pop(var, None)
    env["GH_CONFIG_DIR"] = str(sandbox_home / "gh")  # empty: `gh` is logged out
    env["PATH"] = f"{KIMI_BIN_DIR}{os.pathsep}{env.get('PATH', '')}"
    return env


class ClaudeBackend:
    name = "claude"

    def __init__(self, model: str | None, effort: str, budget_usd: float | None):
        self.model, self.effort, self.budget_usd = model, effort, budget_usd
        self.binary = shutil.which("claude")

    def problem(self) -> str | None:
        return None if self.binary else "`claude` is not on PATH"

    def output_instructions(self, schema) -> str:
        return "\n## Output\n\nWhen you are done, return your result in the structured format this session requires.\n"

    def run(self, prompt, schema, cwd, raw_stem: Path, timeout, env, extra_dirs=()) -> AgentResult:
        cmd = [
            self.binary, "-p",
            "--output-format", "json",
            "--json-schema", json.dumps(schema),
            "--strict-mcp-config",
            "--no-session-persistence",
            "--permission-mode", "dontAsk",
            "--effort", self.effort,
        ]
        if self.model:
            cmd += ["--model", self.model]
        if self.budget_usd:
            cmd += ["--max-budget-usd", str(self.budget_usd)]
        for d in extra_dirs:
            cmd += ["--add-dir", str(d)]
        cmd += ["--allowedTools", *CLAUDE_ALLOWED_TOOLS, "--disallowedTools", *CLAUDE_DENIED_TOOLS]
        out, err = raw_stem.with_suffix(".out.json"), raw_stem.with_suffix(".err.txt")
        start = time.monotonic()
        rc = run_process(cmd, cwd, env, prompt, timeout, out, err)
        secs = time.monotonic() - start
        if rc is None:
            return AgentResult(False, error=f"timed out after {fmt_minutes(timeout)}", seconds=secs)
        doc = read_json(out)
        if not isinstance(doc, dict):
            tail = err.read_text(errors="replace")[-400:].strip()
            return AgentResult(False, error=f"exit {rc}, no JSON result. stderr: {tail}", seconds=secs,
                               quota_exhausted=bool(QUOTA_PATTERN.search(tail)))
        cost = doc.get("total_cost_usd")
        if doc.get("is_error") or doc.get("subtype") != "success":
            message = str(doc.get("result"))[:400]
            return AgentResult(False, error=f"{doc.get('subtype')}: {message}", cost_usd=cost, seconds=secs,
                               quota_exhausted=bool(QUOTA_PATTERN.search(message)))
        data = doc.get("structured_output")
        if data is None:
            return AgentResult(False, error="no structured_output in result", cost_usd=cost, seconds=secs)
        problems = check_schema(data, schema)
        if problems:
            return AgentResult(False, error="schema: " + "; ".join(problems[:5]), cost_usd=cost, seconds=secs)
        return AgentResult(True, data=data, cost_usd=cost, seconds=secs)


class KimiBackend:
    """Kimi K3 via `kimi -p`.

    In prompt mode Kimi runs every tool call without asking, edits included, so
    it is confined by the environment instead: the snapshot is read-only, has
    no .git, and `gh` has no credentials.
    """

    name = "kimi"
    _block = re.compile(r"^[ \t]*<<<JSON[ \t]*$(.*?)^[ \t]*JSON>>>[ \t]*$", re.M | re.S)

    def __init__(self, model: str | None):
        self.model = model
        self.binary = shutil.which("kimi") or (str(KIMI_BIN_DIR / "kimi") if (KIMI_BIN_DIR / "kimi").exists() else None)

    def problem(self) -> str | None:
        return None if self.binary else f"`kimi` is not on PATH or in {KIMI_BIN_DIR}"

    def output_instructions(self, schema) -> str:
        return (
            "\n## Output\n\n"
            "When you are done, print your result as one JSON object matching the JSON Schema below. "
            "Put it between a line containing only `<<<JSON` and a line containing only `JSON>>>`, "
            "with no code fences inside, and print nothing after it.\n\n"
            f"```json\n{json.dumps(schema, indent=1)}\n```\n"
        )

    def run(self, prompt, schema, cwd, raw_stem: Path, timeout, env, extra_dirs=()) -> AgentResult:
        cmd = [self.binary]
        if self.model:
            cmd += ["-m", self.model]
        for d in extra_dirs:
            cmd += ["--add-dir", str(d)]
        cmd += ["-p", prompt]
        out, err = raw_stem.with_suffix(".out.txt"), raw_stem.with_suffix(".err.txt")
        start = time.monotonic()
        rc = run_process(cmd, cwd, env, None, timeout, out, err)
        secs = time.monotonic() - start
        if rc is None:
            return AgentResult(False, error=f"timed out after {fmt_minutes(timeout)}", seconds=secs)
        text = out.read_text(errors="replace")
        if rc != 0:
            err_tail = err.read_text(errors="replace")[-600:]
            if QUOTA_PATTERN.search(err_tail):
                return AgentResult(False, error=f"usage limit: {err_tail.strip()[-300:]}", seconds=secs,
                                   quota_exhausted=True)
        blocks = self._block.findall(text)
        if not blocks:
            tail = (text[-300:] + err.read_text(errors="replace")[-200:]).strip()
            return AgentResult(False, error=f"exit {rc}, no <<<JSON block. tail: {tail}", seconds=secs)
        body = textwrap.dedent(blocks[-1]).strip()
        body = re.sub(r"^```(?:json)?\s*|\s*```$", "", body)
        try:
            data = json.loads(body)
        except ValueError as exc:
            return AgentResult(False, error=f"invalid JSON in <<<JSON block: {exc}", seconds=secs)
        problems = check_schema(data, schema)
        if problems:
            return AgentResult(False, error="schema: " + "; ".join(problems[:5]), seconds=secs)
        return AgentResult(True, data=data, seconds=secs)


# --------------------------------------------------------------------------
# Run setup


def load_goals(selected: list[str] | None) -> list[dict]:
    with open(HERE / "goals.toml", "rb") as fh:
        goals = tomllib.load(fh)["goal"]
    if selected:
        known = {g["id"] for g in goals}
        unknown = [s for s in selected if s not in known]
        if unknown:
            raise SystemExit(f"unknown goal(s): {', '.join(unknown)}. Known: {', '.join(sorted(known))}")
        goals = [g for g in goals if g["id"] in selected]
    return goals


def fetch_known_issues(dest: Path) -> str | None:
    """Write every issue (open and closed) as TSV for the verifiers. Returns an error or None."""
    if not shutil.which("gh"):
        return "`gh` is not installed"
    res = subprocess.run(
        ["gh", "issue", "list", "--repo", GH_REPO, "--state", "all", "--limit", "10000",
         "--json", "number,state,title,labels"],
        capture_output=True, text=True,
    )
    if res.returncode != 0:
        return f"gh issue list failed: {res.stderr.strip()[:300]}"
    issues = sorted(json.loads(res.stdout), key=lambda i: i["number"])
    lines = ["number\tstate\ttitle\tlabels"]
    for issue in issues:
        labels = ",".join(lbl["name"] for lbl in issue.get("labels", []))
        title = issue["title"].replace("\t", " ")
        lines.append(f"{issue['number']}\t{issue['state']}\t{title}\t{labels}")
    dest.write_text("\n".join(lines) + "\n")
    return None


def changes_since(prev: str | None, commit: str) -> tuple[str, str]:
    """Return (hunter prompt note, changes.txt contents)."""
    if not prev:
        return ("This is the first sweep, so there is no list of recent changes.", "First sweep: no baseline.\n")
    if prev == commit:
        return ("No commits landed since the previous sweep.", "No commits since the previous sweep.\n")
    is_ancestor = subprocess.run(
        ["git", "-C", str(REPO), "merge-base", "--is-ancestor", prev, commit],
        capture_output=True,
    ).returncode == 0
    if not is_ancestor:
        return (
            f"The previous sweep's commit ({prev[:10]}) is not an ancestor of this one, so there is no list of recent changes.",
            f"Previous sweep commit {prev} is unknown or not an ancestor of {commit}.\n",
        )
    commits = git("log", "--no-merges", "--date=short", "--format=%h %ad %s", f"{prev}..{commit}")
    stat = git("diff", "--stat=160", prev, commit)
    stat_lines = stat.splitlines()
    if len(stat_lines) > 400:
        stat = "\n".join(stat_lines[:399] + [f"... ({len(stat_lines) - 400} more files)", stat_lines[-1]])
    text = f"Commits since the previous sweep ({prev[:10]}..{commit[:10]}):\n\n{commits}\n\nFiles changed:\n\n{stat}\n"
    note = (
        f"Commits since the previous sweep ({prev[:10]}) are listed in `.sweep-context/changes.txt`. "
        "Changed code is the most likely place for new bugs."
    )
    return note, text


def make_snapshot(commit: str, dest: Path, changes_text: str) -> None:
    dest.mkdir(parents=True)
    archive = subprocess.Popen(["git", "-C", str(REPO), "archive", "--format=tar", commit], stdout=subprocess.PIPE)
    untar = subprocess.run(["tar", "-x", "-C", str(dest)], stdin=archive.stdout)
    archive.stdout.close()
    if archive.wait() != 0 or untar.returncode != 0:
        raise SystemExit(f"could not export {commit} into {dest}")
    ctx = dest / ".sweep-context"
    ctx.mkdir()
    (ctx / "changes.txt").write_text(changes_text)
    subprocess.run(["chmod", "-R", "a-w", str(dest)], check=True)


def remove_tree(path: Path) -> None:
    if path.exists():
        subprocess.run(["chmod", "-R", "u+w", str(path)], check=False)
        shutil.rmtree(path, ignore_errors=True)


def hold_sleep_inhibitor():
    """Keep the laptop awake while the sweep runs. Best effort."""
    if not shutil.which("systemd-inhibit"):
        return None
    try:
        proc = subprocess.Popen(
            ["systemd-inhibit", "--what=sleep:idle", "--who=pq1-security-sweep",
             "--why=weekly security sweep", "--mode=block", "sleep", "infinity"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
        )
    except OSError:
        return None
    time.sleep(1)
    if proc.poll() is not None:
        log("note: could not take a sleep inhibitor; keep the laptop awake yourself")
        return None
    return proc


def notify(title: str, body: str) -> None:
    if shutil.which("notify-send"):
        subprocess.run(["notify-send", "--app-name=pq1-security-sweep", title, body], check=False)


# --------------------------------------------------------------------------
# Phases


class Sweep:
    def __init__(self, args, run_dir: Path, meta: dict, goals: list[dict], backends: dict):
        self.args, self.run_dir, self.meta, self.goals, self.backends = args, run_dir, meta, goals, backends
        self.snapshot = run_dir / "snapshot"
        self.context = run_dir / "context"
        self.raw = run_dir / "raw"
        self.sandbox_home = Path(tempfile.mkdtemp(prefix="pq1-sweep-"))
        (self.sandbox_home / "gh").mkdir()
        self.env = agent_env(self.sandbox_home)
        self.goal_by_id = {g["id"]: g for g in goals}
        self.exhausted: set[str] = set()  # backends whose usage window ran out this run
        self.exhausted_lock = threading.Lock()

    def call(self, candidates: list, make_prompt, schema, raw_stem: str, timeout_min: int,
             extra_dirs=()) -> AgentResult:
        """Run on the first candidate backend that still has quota.

        A backend that reports a spent usage window is skipped for the rest of
        the run; the task falls through to the next candidate, if any.
        """
        for backend in candidates:
            with self.exhausted_lock:
                if backend.name in self.exhausted:
                    continue
            res = backend.run(make_prompt(backend), schema, self.snapshot,
                              self.raw / f"{raw_stem}__{backend.name}", timeout_min * 60, self.env, extra_dirs)
            res.backend = backend.name
            if not res.quota_exhausted:
                return res
            with self.exhausted_lock:
                first = backend.name not in self.exhausted
                self.exhausted.add(backend.name)
            if first:
                log(f"{backend.name}: usage limit reached; skipping its remaining tasks this run "
                    f"(finish them later with --resume)")
        names = ", ".join(b.name for b in candidates)
        return AgentResult(False, error=f"skipped: usage limit reached for {names}")

    # --- prompts

    def hunter_prompt(self, goal: dict, backend) -> str:
        return fill(
            "hunter.md",
            commit=self.meta["commit"],
            goal_title=goal["title"],
            goal_objective=goal["objective"].strip(),
            goal_success=goal["success"],
            goal_refs=goal["refs"],
            goal_start="\n".join(f"- {s}" for s in goal["start"]),
            changes_note=self.meta["changes_note"],
            severity_scale=SEVERITY_SCALE,
            output_instructions=backend.output_instructions(HUNT_SCHEMA),
        )

    def verifier_prompt(self, finding: dict, backend) -> str:
        public = {k: v for k, v in finding.items() if k in FINDING_PROPS}
        return fill(
            "verifier.md",
            commit=self.meta["commit"],
            finding_id=finding["id"],
            goal_title=self.goal_by_id.get(finding["goal"], {}).get("title", finding["goal"]),
            hunter=finding["backend"],
            finding_json=json.dumps(public, indent=2),
            known_issues=str(self.context / "known-issues.tsv"),
            severity_scale=SEVERITY_SCALE,
            output_instructions=backend.output_instructions(VERDICT_SCHEMA),
        )

    def consolidate_prompt(self, items: list[dict], backend) -> str:
        return fill(
            "consolidate.md",
            commit=self.meta["commit"],
            findings_json=json.dumps(items, indent=2),
            output_instructions=backend.output_instructions(CONSOLIDATE_SCHEMA),
        )

    # --- generic task runner with resume

    def run_tasks(self, label: str, tasks: list[tuple[str, Path, callable]]) -> dict[str, dict]:
        """tasks: (key, result_path, fn -> AgentResult). Skips tasks whose result already succeeded."""
        results, pending = {}, []
        for key, path, fn in tasks:
            prior = read_json(path)
            if prior and prior.get("ok"):
                results[key] = prior
            else:
                pending.append((key, path, fn))
        if len(results):
            log(f"{label}: reusing {len(results)} finished result(s) from an earlier attempt")
        if not pending:
            return results
        log(f"{label}: running {len(pending)} agent(s), {self.args.jobs} at a time")
        pool = cf.ThreadPoolExecutor(max_workers=self.args.jobs)
        try:
            futures = {pool.submit(fn): (key, path) for key, path, fn in pending}
            for fut in cf.as_completed(futures):
                key, path = futures[fut]
                try:
                    res = fut.result()
                except Exception as exc:  # a bug in this script, not the agent
                    res = AgentResult(False, error=f"internal error: {exc!r}")
                write_json(path, res.to_json())
                results[key] = res.to_json()
                if res.ok:
                    extra = ""
                    if res.data and "findings" in res.data:
                        extra = f", {len(res.data['findings'])} finding(s)"
                    elif res.data and "verdict" in res.data:
                        extra = f", {res.data['verdict']} {res.data['severity']}"
                    log(f"{label} {key}: done{extra} ({fmt_minutes(res.seconds)}, {fmt_cost(res.cost_usd)})")
                else:
                    log(f"{label} {key}: FAILED - {res.error}")
        except KeyboardInterrupt:
            # Stop queued agents and kill running ones; otherwise the pool would
            # wait for hour-long agents to finish before the interrupt lands.
            pool.shutdown(wait=False, cancel_futures=True)
            kill_all_agents()
            raise
        pool.shutdown(wait=True)
        return results

    # --- phase 1: hunt

    def hunt(self) -> dict[str, dict]:
        tasks = []
        for goal in self.goals:
            for bname, backend in self.backends.items():
                tasks.append((
                    f"{goal['id']}/{bname}",
                    self.run_dir / "hunt" / f"{goal['id']}__{bname}.json",
                    lambda b=backend, g=goal: self.call(
                        [b], lambda bk: self.hunter_prompt(g, bk), HUNT_SCHEMA,
                        f"hunt__{g['id']}", self.args.hunt_timeout),
                ))
        return self.run_tasks("hunt", tasks)

    def collect_findings(self, hunts: dict[str, dict]) -> list[dict]:
        findings, n = [], 0
        for goal in self.goals:
            for bname in self.backends:
                res = hunts.get(f"{goal['id']}/{bname}")
                if not res or not res.get("ok"):
                    continue
                for f in res["data"]["findings"]:
                    n += 1
                    findings.append({"id": f"F{n:02d}", "goal": goal["id"], "backend": bname, **f})
        write_json(self.run_dir / "findings.json", findings)
        return findings

    # --- phase 2: verify

    def verifier_order(self, hunter: str) -> list:
        """Preferred verifier first (a different model than the hunter when
        cross-verifying), then the rest as fallbacks if a usage limit hits."""
        names = list(self.backends)
        if self.args.cross_verify and len(names) > 1:
            first = sorted((n for n in names if n != hunter), key=lambda n: n != self.args.verifier)[0]
        else:
            first = self.args.verifier if self.args.verifier in names else names[0]
        return [self.backends[first]] + [self.backends[n] for n in names if n != first]

    def verify(self, findings: list[dict]) -> dict[str, dict]:
        limit = sev_rank(self.args.min_verify_severity)
        tasks = []
        for f in findings:
            if sev_rank(f["severity"]) > limit:
                continue
            tasks.append((
                f["id"],
                self.run_dir / "verify" / f"{f['id']}.json",
                lambda f=f: self.call(
                    self.verifier_order(f["backend"]), lambda bk: self.verifier_prompt(f, bk),
                    VERDICT_SCHEMA, f"verify__{f['id']}", self.args.verify_timeout,
                    extra_dirs=[self.context]),
            ))
        return self.run_tasks("verify", tasks)

    # --- phase 3: consolidate

    def consolidate(self, live: list[dict]) -> list[dict]:
        path = self.run_dir / "consolidate.json"
        if not live:
            write_json(path, {"ok": True, "data": {"groups": []}})
            return []
        order = sorted(self.backends.values(), key=lambda b: b.name != "claude")
        result = self.run_tasks("consolidate", [(
            "groups", path,
            lambda: self.call(order, lambda bk: self.consolidate_prompt(live, bk), CONSOLIDATE_SCHEMA,
                              "consolidate", self.args.verify_timeout),
        )])["groups"]
        ids = {f["id"] for f in live}
        if result.get("ok"):
            groups = result["data"]["groups"]
            covered = {m for g in groups for m in g["member_ids"]}
            # Never let a merge drop a verified finding.
            groups += [fallback_group(f) for f in live if f["id"] not in covered]
            for g in groups:
                g["member_ids"] = [m for m in g["member_ids"] if m in ids]
            return [g for g in groups if g["member_ids"]]
        log("consolidate failed; filing each verified finding as its own draft")
        return [fallback_group(f) for f in live]


def fallback_group(f: dict) -> dict:
    v = f["verification"]
    steps = "\n".join(f"{i}. {s}" for i, s in enumerate(f["attack_steps"], 1))
    evidence = "\n".join(f"- `{loc}`" for loc in f["code_locations"] + v.get("evidence", []))
    body = (
        f"## Summary\n\n{f['why_defences_fail']}\n\n"
        f"## Attacker and preconditions\n\n{f['attacker_tier']}. {f['preconditions']}\n\n"
        f"## Attack steps\n\n{steps}\n\n"
        f"## Evidence\n\n{evidence}\n\n"
        f"## Invariants and claims broken\n\n{', '.join(f['invariants']) or '-'}\n\n"
        f"## Verification\n\n{v['verdict']} by {v.get('verifier', '?')}"
        f"{' (needs silicon confirmation)' if v.get('silicon_needed') else ''}. {v['reasoning']}\n\n"
        f"## Suggested fix\n\n{f['suggested_fix']}\n"
    )
    return {"title": f["title"], "severity": v["severity"], "member_ids": [f["id"]], "issue_body": body}


# --------------------------------------------------------------------------
# Report


def write_report(sweep: Sweep, hunts, findings, verdicts, groups, started: float) -> dict:
    run_dir, meta = sweep.run_dir, sweep.meta
    by_id = {f["id"]: f for f in findings}
    for f in findings:
        f["verification"] = verdicts.get(f["id"])

    issues_dir = run_dir / "issues"
    issues_dir.mkdir(exist_ok=True)
    groups = sorted(groups, key=lambda g: sev_rank(g["severity"]))
    for i, g in enumerate(groups, 1):
        g["draft"] = f"issues/{i:02d}-{slugify(g['title'])}.md"
        g["body_with_footer"] = (
            g["issue_body"].rstrip()
            + "\n\n---\nFound by the weekly security sweep (`tools/security-sweep`) at commit "
            + f"`{meta['commit'][:10]}`, run `{run_dir.name}`, finding(s) {', '.join(g['member_ids'])}.\n"
        )
        (run_dir / g["draft"]).write_text(f"# {g['title']}\n\nSeverity: {g['severity']}\n\n{g['body_with_footer']}")

    failed_hunts = [k for k, r in hunts.items() if not r.get("ok")]
    failed_verifies = [f for f in findings if f["verification"] is not None and not f["verification"].get("ok")]
    total_cost = sum(r.get("cost_usd") or 0 for r in list(hunts.values()) + list(verdicts.values()))
    elapsed = time.time() - started

    def verdict_of(f):
        v = f["verification"]
        return v["data"] if v and v.get("ok") else None

    dupes = [f for f in findings if (d := verdict_of(f)) and d["verdict"] == "DUPLICATE"]
    rejected = [f for f in findings if (d := verdict_of(f)) and d["verdict"] in ("REFUTED", "ACCEPTED_RISK")]
    unverified_low = [f for f in findings if f["verification"] is None]

    L = []
    L.append(f"# PQ1 security sweep, {meta['started'][:10]}\n")
    L.append(
        f"Commit `{meta['commit'][:10]}` ({meta['ref']}) · previous sweep "
        f"`{(meta.get('prev_commit') or 'none')[:10]}` · agents: {', '.join(meta['backends'])} · "
        f"this attempt {fmt_minutes(elapsed)} · Claude API-equivalent cost {fmt_cost(total_cost)}\n"
    )
    L.append("## Result\n")
    if groups:
        counts = ", ".join(f"{sum(g['severity'] == s for g in groups)} {s}" for s in SEVERITIES
                           if any(g["severity"] == s for g in groups))
        L.append(f"**{len(groups)} new finding(s) to review ({counts}).** Drafts are in `issues/`. "
                 f"File them with `tools/security-sweep/sweep.py file {run_dir}`.\n")
    else:
        L.append("**No new findings survived verification.**\n")
    n_hunts = len(sweep.goals) * len(sweep.backends)
    if failed_hunts or failed_verifies:
        L.append(f"⚠ Coverage is incomplete: {len(failed_hunts)} of {n_hunts} hunters and "
                 f"{len(failed_verifies)} verifier(s) failed (see Errors). "
                 f"Re-run them with `sweep.py run --resume {run_dir}`.\n")
    else:
        L.append(f"All {n_hunts} hunters and every verifier completed.\n")

    if groups:
        L.append("## New findings\n")
        for i, g in enumerate(groups, 1):
            members = []
            for m in g["member_ids"]:
                f = by_id[m]
                d = verdict_of(f)
                reg = f" regression of #{d['duplicate_of']}" if d and d.get("duplicate_of") else ""
                members.append(f"{m} ({f['goal']}/{f['backend']}, {d['verdict'] if d else '?'} by "
                               f"{f['verification'].get('backend', '?')}{reg})")
            L.append(f"### {i}. [{g['severity']}] {g['title']}\n")
            L.append(f"Findings: {'; '.join(members)} · draft: `{g['draft']}`\n")
            L.append(g["issue_body"].strip() + "\n")

    if dupes:
        L.append("## Re-found known issues\n")
        L.append("Already tracked on GitHub. A known issue being re-found shows the hunters still reach it.\n")
        L.append("| Finding | Severity | Issue | Title |\n|---|---|---|---|")
        for f in dupes:
            d = verdict_of(f)
            L.append(f"| {f['id']} ({f['goal']}/{f['backend']}) | {d['severity']} | #{d['duplicate_of']} | {f['title']} |")
        L.append("")

    if rejected:
        L.append("## Refuted or accepted\n")
        L.append("| Finding | Verdict | Title | Verifier's reason |\n|---|---|---|---|")
        for f in rejected:
            d = verdict_of(f)
            reason = d["reasoning"].replace("\n", " ").replace("|", "\\|")
            reason = reason[:220] + ("…" if len(reason) > 220 else "")
            L.append(f"| {f['id']} | {d['verdict']} | {f['title']} | {reason} |")
        L.append("")

    if unverified_low:
        L.append(f"## Below the verification threshold ({sweep.args.min_verify_severity}), not verified\n")
        for f in unverified_low:
            L.append(f"- {f['id']} [{f['severity']}] {f['title']} ({f['goal']}/{f['backend']}): "
                     f"{', '.join(f['code_locations'][:3])}")
        L.append("")

    L.append("## Hunter coverage\n")
    L.append("| Goal | Agent | Status | Findings | Paths checked and held | Time | Cost |\n|---|---|---|---|---|---|---|")
    for goal in sweep.goals:
        for bname in sweep.backends:
            r = hunts.get(f"{goal['id']}/{bname}", {})
            if r.get("ok"):
                d = r["data"]
                L.append(f"| {goal['id']} | {bname} | ok | {len(d['findings'])} | {len(d['checked_and_held'])} | "
                         f"{fmt_minutes(r.get('seconds'))} | {fmt_cost(r.get('cost_usd'))} |")
            else:
                L.append(f"| {goal['id']} | {bname} | **failed** | - | - | {fmt_minutes(r.get('seconds'))} | "
                         f"{fmt_cost(r.get('cost_usd'))} |")
    L.append("")

    L.append("## What held\n")
    for goal in sweep.goals:
        for bname in sweep.backends:
            r = hunts.get(f"{goal['id']}/{bname}", {})
            if not r.get("ok"):
                continue
            d = r["data"]
            L.append(f"<details><summary>{goal['id']} / {bname}: {len(d['checked_and_held'])} path(s)</summary>\n")
            L += [f"- {line}" for line in d["checked_and_held"]]
            if d["coverage_notes"].strip():
                L.append(f"\nCoverage notes: {d['coverage_notes'].strip()}")
            L.append("\n</details>\n")

    if failed_hunts or failed_verifies:
        L.append("## Errors\n")
        for k in failed_hunts:
            L.append(f"- hunt {k}: {hunts[k].get('error')}")
        for f in failed_verifies:
            L.append(f"- verify {f['id']} ({f['title']}): {f['verification'].get('error')}")
        L.append("\nRaw agent output is in `raw/`.\n")

    (run_dir / "report.md").write_text("\n".join(L) + "\n")

    summary = {
        "commit": meta["commit"],
        "run": run_dir.name,
        "new_groups": [
            {k: g[k] for k in ("title", "severity", "member_ids", "draft", "body_with_footer")} for g in groups
        ],
        "duplicates": [{"id": f["id"], "issue": verdict_of(f)["duplicate_of"]} for f in dupes],
        "failed_hunts": failed_hunts,
        "failed_verifies": [f["id"] for f in failed_verifies],
        "cost_usd": total_cost,
        "seconds": elapsed,
    }
    write_json(run_dir / "summary.json", summary)
    return summary


# --------------------------------------------------------------------------
# Commands


def cmd_run(args) -> int:
    goals = load_goals(args.goals)
    all_backends = {
        "claude": ClaudeBackend(args.claude_model, args.claude_effort, args.budget_usd),
        "kimi": KimiBackend(args.kimi_model),
    }
    backends = {}
    for name in args.backends:
        if name not in all_backends:
            raise SystemExit(f"unknown backend {name!r} (choose from claude, kimi)")
        problem = all_backends[name].problem()
        if problem:
            raise SystemExit(f"backend {name}: {problem}. Drop it with --backends.")
        backends[name] = all_backends[name]

    out_root = args.out_root.expanduser()
    last_run_path = out_root / "last-run.json"

    if args.resume:
        run_dir = args.resume.expanduser().resolve()
        meta = read_json(run_dir / "meta.json")
        if not meta:
            raise SystemExit(f"{run_dir} has no meta.json; not a sweep run")
        if meta["backends"] != list(backends) or meta["goals"] != [g["id"] for g in goals]:
            log("note: --resume uses the goals and agents recorded in meta.json")
            goals = load_goals(meta["goals"])
            backends = {n: all_backends[n] for n in meta["backends"]}
        last_run_path = run_dir.parent / "last-run.json"  # the baseline lives next to the run
        open_run_log(run_dir)
        log(f"resuming {run_dir.name} at commit {meta['commit'][:10]}")
    else:
        commit = git("rev-parse", "--verify", f"{args.ref}^{{commit}}")
        prev = (read_json(last_run_path) or {}).get("commit")
        note, changes_text = changes_since(prev, commit)
        stamp = dt.datetime.now().strftime("%Y-%m-%d")
        run_dir = out_root / f"{stamp}-{commit[:8]}"
        suffix = 2
        while run_dir.exists():
            run_dir = out_root / f"{stamp}-{commit[:8]}-{suffix}"
            suffix += 1
        run_dir.mkdir(parents=True)
        meta = {
            "commit": commit, "ref": args.ref, "prev_commit": prev,
            "started": dt.datetime.now().isoformat(timespec="seconds"),
            "backends": list(backends), "goals": [g["id"] for g in goals],
            "changes_note": note, "changes_text": changes_text,
            "options": {k: str(v) for k, v in vars(args).items() if k != "func"},
        }
        write_json(run_dir / "meta.json", meta)
        open_run_log(run_dir)
        log(f"sweep {run_dir.name}: commit {commit[:10]} ({args.ref}), {len(goals)} goal(s) x "
            f"{len(backends)} agent(s): {', '.join(backends)}")

    for sub in ("hunt", "verify", "raw", "context"):
        (run_dir / sub).mkdir(exist_ok=True)

    sweep = Sweep(args, run_dir, meta, goals, backends)
    inhibitor = None if (args.dry_run or args.no_inhibit) else hold_sleep_inhibitor()
    started = time.time()
    try:
        known = sweep.context / "known-issues.tsv"
        if known.exists():
            known.chmod(0o644)
        err = fetch_known_issues(known)
        if err:
            log(f"warning: {err}. Verifiers can't de-duplicate against GitHub this run.")
            known.write_text("number\tstate\ttitle\tlabels\n(issue list unavailable this run)\n")
        known.chmod(0o444)

        remove_tree(sweep.snapshot)
        log("exporting a read-only snapshot of the commit")
        make_snapshot(meta["commit"], sweep.snapshot, meta["changes_text"])

        if args.dry_run:
            pdir = run_dir / "prompts"
            pdir.mkdir(exist_ok=True)
            for goal in goals:
                for bname, backend in backends.items():
                    (pdir / f"hunt__{goal['id']}__{bname}.md").write_text(sweep.hunter_prompt(goal, backend))
            sample = {"id": "F00", "goal": goals[0]["id"], "backend": list(backends)[0],
                      **{k: ("example" if v["type"] == "string" else []) for k, v in FINDING_PROPS.items()},
                      "severity": "HIGH", "confidence": "high"}
            (pdir / "verify__sample.md").write_text(sweep.verifier_prompt(sample, sweep.verifier_order(sample["backend"])[0]))
            log(f"dry run: prompts written to {pdir}; no agents were started")
            return 0

        hunts = sweep.hunt()
        findings = sweep.collect_findings(hunts)
        log(f"{len(findings)} finding(s) from {sum(r.get('ok', False) for r in hunts.values())} hunter(s)")
        verdicts = sweep.verify(findings)
        # What the consolidator (and fallback_group) sees: each surviving
        # finding with its verdict flattened in.
        live = []
        for f in findings:
            v = verdicts.get(f["id"])
            if v and v.get("ok") and v["data"]["verdict"] in LIVE_VERDICTS:
                live.append({
                    "id": f["id"], "goal": f["goal"], "hunter": f["backend"],
                    **{k: f[k] for k in FINDING_PROPS},
                    "verification": {**v["data"], "verifier": v.get("backend")},
                })
        groups = sweep.consolidate(live)
        summary = write_report(sweep, hunts, findings, verdicts, groups, started)

        write_json(last_run_path, {"commit": meta["commit"], "run": run_dir.name,
                                   "finished": dt.datetime.now().isoformat(timespec="seconds")})
        n_new = len(summary["new_groups"])
        incomplete = bool(summary["failed_hunts"] or summary["failed_verifies"])
        append_history(run_dir.parent, run_dir, meta, "incomplete" if incomplete else "complete", summary)
        log(f"report: {run_dir / 'report.md'}")
        log(f"{n_new} new finding(s), {len(summary['duplicates'])} re-found known issue(s)"
            f"{', coverage INCOMPLETE' if incomplete else ''}")
        notify("PQ1 security sweep finished",
               f"{n_new} new finding(s){' - coverage incomplete' if incomplete else ''}. {run_dir / 'report.md'}")
        return 1 if n_new else (2 if incomplete else 0)
    except KeyboardInterrupt:
        kill_all_agents()
        log(f"interrupted. Finish later with: {sys.argv[0]} run --resume {run_dir}")
        append_history(run_dir.parent, run_dir, meta, "interrupted", None)
        return 130
    except Exception:
        kill_all_agents()
        log("crashed:\n" + traceback.format_exc())
        append_history(run_dir.parent, run_dir, meta, "crashed (see sweep.log)", None)
        raise
    finally:
        if not args.keep_snapshot:
            remove_tree(sweep.snapshot)
        shutil.rmtree(sweep.sandbox_home, ignore_errors=True)
        if inhibitor:
            kill_group(inhibitor)


def cmd_file(args) -> int:
    run_dir = args.run_dir.expanduser().resolve()
    summary = read_json(run_dir / "summary.json")
    if not summary:
        raise SystemExit(f"{run_dir} has no summary.json (did the run finish?)")
    filed_path = run_dir / "filed.json"
    filed = read_json(filed_path) or {}
    limit = sev_rank(args.min_severity)
    todo = [g for g in summary["new_groups"] if sev_rank(g["severity"]) <= limit and g["draft"] not in filed]
    if not todo:
        print("Nothing to file.")
        return 0
    print(f"Will file {len(todo)} issue(s) on {GH_REPO}:")
    for g in todo:
        print(f"  [{g['severity']}] {g['title']}  ({g['draft']})")
    if not args.yes:
        if input("Proceed? [y/N] ").strip().lower() != "y":
            print("Nothing filed.")
            return 0
    open_run_log(run_dir)  # record what was filed alongside the run's own log
    for g in todo:
        body_file = run_dir / g["draft"]
        with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as tmp:
            tmp.write(g["body_with_footer"])
        try:
            res = subprocess.run(
                ["gh", "issue", "create", "--repo", GH_REPO, "--title", f"[sweep] {g['title']}",
                 "--body-file", tmp.name, "--label", "finding", "--label", PRIORITY_LABEL[g["severity"]]],
                capture_output=True, text=True,
            )
        finally:
            os.unlink(tmp.name)
        if res.returncode != 0:
            log(f"filing failed: {g['title']}: {res.stderr.strip()}")
            continue
        url = res.stdout.strip().splitlines()[-1]
        filed[g["draft"]] = url
        write_json(filed_path, filed)
        log(f"filed {url} from {body_file.name}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run a sweep")
    run.add_argument("--ref", default="master", help="commit or branch to sweep (default: master)")
    run.add_argument("--goals", nargs="+", metavar="ID", help="only these goal ids from goals.toml")
    run.add_argument("--backends", nargs="+", default=["claude", "kimi"], metavar="NAME",
                     help="agent CLIs to hunt with (default: claude kimi)")
    run.add_argument("--jobs", type=int, default=4, help="agents running at once (default: 4)")
    run.add_argument("--hunt-timeout", type=int, default=60, metavar="MIN", help="per hunter (default: 60)")
    run.add_argument("--verify-timeout", type=int, default=30, metavar="MIN", help="per verifier (default: 30)")
    run.add_argument("--min-verify-severity", default="MEDIUM", choices=SEVERITIES,
                     help="findings below this are listed but not verified (default: MEDIUM)")
    run.add_argument("--verifier", default="claude", help="verifier when not cross-verifying (default: claude)")
    run.add_argument("--no-cross-verify", dest="cross_verify", action="store_false",
                     help="don't verify each finding with a different agent than the one that found it")
    run.add_argument("--claude-model", help="model for claude agents (default: your claude default)")
    run.add_argument("--claude-effort", default="high", choices=["low", "medium", "high", "xhigh", "max"])
    run.add_argument("--kimi-model", help="model alias for kimi agents (default: your kimi default)")
    run.add_argument("--budget-usd", type=float, help="spending cap per claude agent")
    run.add_argument("--out-root", type=Path, default=DEFAULT_OUT_ROOT,
                     help=f"where runs are stored (default: {DEFAULT_OUT_ROOT})")
    run.add_argument("--resume", type=Path, metavar="RUN_DIR", help="finish an interrupted run")
    run.add_argument("--dry-run", action="store_true", help="write the prompts and stop; starts no agents")
    run.add_argument("--keep-snapshot", action="store_true", help="keep the source snapshot after the run")
    run.add_argument("--no-inhibit", action="store_true", help="don't hold a systemd sleep inhibitor")
    run.set_defaults(func=cmd_run)

    file_ = sub.add_parser("file", help="file a finished run's drafts as GitHub issues")
    file_.add_argument("run_dir", type=Path)
    file_.add_argument("--min-severity", default="MEDIUM", choices=SEVERITIES,
                       help="file drafts at or above this severity (default: MEDIUM)")
    file_.add_argument("--yes", action="store_true", help="don't ask for confirmation")
    file_.set_defaults(func=cmd_file)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
