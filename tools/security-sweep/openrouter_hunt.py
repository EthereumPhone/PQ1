#!/usr/bin/env python3
"""Security scan / bug hunt with any OpenRouter model.

A single-agent, read-only bug hunter: it exports a git ref into a read-only
snapshot, gives the chosen model four read-only tools (list_dir, glob,
read_file, grep) over that snapshot, and asks it to attack one goal from
goals.toml (or a free-text focus). The model ends by calling submit_findings;
the result is written as JSON + Markdown.

It reuses the weekly sweep's goals, hunter prompt, severity scale and finding
schema (sweep.py), but has no verifier or merge step: treat its findings as
leads to check, not facts.

    export OPENROUTER_API_KEY=sk-or-...
    openrouter_hunt.py --list-models gemini          # browse tool-capable models
    openrouter_hunt.py -m openai/gpt-5 -g pin-bypass
    openrouter_hunt.py -m deepseek/deepseek-r1 --all -j 3
    openrouter_hunt.py -m x-ai/grok-4 --focus "Audit secure/src/nsc/cmd_sign_offchain.rs for OOB writes"
    openrouter_hunt.py                               # interactive: asks model + goal

Only files tracked by git at --ref are sent to OpenRouter (and on to the model
provider). Uncommitted changes are not scanned.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import sweep  # noqa: E402  (goals, prompt template, schema, severity scale)

API = "https://openrouter.ai/api/v1"
DEFAULT_OUT = Path.home() / "pq1-security-sweeps" / "openrouter"
MAX_TOOL_CHARS = 30_000
_print_lock = threading.Lock()


class Spend:
    """Running OpenRouter spend for this run, shared by all parallel goals."""
    lock = threading.Lock()
    total = 0.0
    estimated = False   # True once any call lacked usage.cost and was priced from the model list
    pricing: dict = {}  # model pricing from /models, $/token as strings
    max_cost: float | None = None

    @classmethod
    def add(cls, usage: dict) -> float:
        cost = usage.get("cost")
        if cost is None:
            try:
                cost = (int(usage.get("prompt_tokens") or 0) * float(cls.pricing.get("prompt", 0))
                        + int(usage.get("completion_tokens") or 0) * float(cls.pricing.get("completion", 0)))
            except ValueError:
                cost = 0.0
            cls.estimated = True
        with cls.lock:
            cls.total += float(cost)
        return float(cost)

    @classmethod
    def label(cls) -> str:
        return f"{'~' if cls.estimated else ''}${cls.total:.4f}"

    @classmethod
    def over_budget(cls) -> bool:
        return cls.max_cost is not None and cls.total >= cls.max_cost


def say(msg: str) -> None:
    with _print_lock:
        print(f"[{dt.datetime.now():%H:%M:%S}] [spent {Spend.label()}] {msg}", flush=True)


# --------------------------------------------------------------------------
# OpenRouter

def api_key() -> str:
    key = os.environ.get("OPENROUTER_API_KEY", "").strip()
    if not key:
        raise SystemExit("OPENROUTER_API_KEY is not set (get one at https://openrouter.ai/keys)")
    return key


def http_json(method: str, url: str, body: dict | None = None, timeout: int = 900) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    headers = {
        "Authorization": f"Bearer {api_key()}",
        "Content-Type": "application/json",
        "X-Title": "PQ1 security hunt",
    }
    delay = 5
    for attempt in range(6):
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:1000]
            if e.code in (408, 429, 500, 502, 503, 504) and attempt < 5:
                say(f"HTTP {e.code}, retrying in {delay}s: {detail[:200]}")
                time.sleep(delay)
                delay *= 2
                continue
            raise RuntimeError(f"OpenRouter HTTP {e.code}: {detail}") from None
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            if attempt < 5:
                say(f"network error ({e}), retrying in {delay}s")
                time.sleep(delay)
                delay *= 2
                continue
            raise
    raise RuntimeError("unreachable")


def list_models(filt: str | None) -> int:
    models = http_json("GET", f"{API}/models")["data"]
    rows = []
    for m in models:
        if "tools" not in (m.get("supported_parameters") or []):
            continue
        if filt and filt.lower() not in (m["id"] + " " + m.get("name", "")).lower():
            continue
        p = m.get("pricing") or {}
        try:
            pin, pout = float(p.get("prompt", 0)) * 1e6, float(p.get("completion", 0)) * 1e6
        except ValueError:
            pin = pout = float("nan")
        rows.append((m["id"], m.get("context_length") or 0, pin, pout))
    rows.sort()
    print(f"{'model (tool-capable)':<55} {'context':>9} {'$/M in':>8} {'$/M out':>8}")
    for mid, ctx, pin, pout in rows:
        print(f"{mid:<55} {ctx:>9} {pin:>8.2f} {pout:>8.2f}")
    print(f"\n{len(rows)} models")
    return 0


def model_info(model: str) -> dict | None:
    try:
        for m in http_json("GET", f"{API}/models")["data"]:
            if m["id"] == model:
                return m
    except Exception as e:  # informational only
        say(f"could not fetch model list: {e}")
    return None


# --------------------------------------------------------------------------
# Read-only tools over the snapshot

TOOLS = [
    {"type": "function", "function": {
        "name": "list_dir",
        "description": "List one directory of the repository snapshot (non-recursive).",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string", "description": "directory relative to repo root, '.' for root"}},
            "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "glob",
        "description": "Find files by glob pattern, e.g. 'secure/src/nsc/*.rs' or '**/flash.rs'. Max 300 results.",
        "parameters": {"type": "object", "properties": {"pattern": {"type": "string"}}, "required": ["pattern"]}}},
    {"type": "function", "function": {
        "name": "read_file",
        "description": "Read a text file with line numbers. Use offset/limit for large files (default 400 lines).",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"},
            "offset": {"type": "integer", "description": "first line, 1-based"},
            "limit": {"type": "integer", "description": "number of lines (max 1500)"}},
            "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "grep",
        "description": "Regex search (ripgrep syntax) across files; returns path:line:text, max 200 matches.",
        "parameters": {"type": "object", "properties": {
            "pattern": {"type": "string"},
            "path": {"type": "string", "description": "file or directory to search, default '.'"},
            "glob": {"type": "string", "description": "optional file filter, e.g. '*.rs'"},
            "ignore_case": {"type": "boolean"}},
            "required": ["pattern"]}}},
]


def submit_tool() -> dict:
    return {"type": "function", "function": {
        "name": "submit_findings",
        "description": "Submit your final result. Call exactly once, when you are done.",
        "parameters": sweep.HUNT_SCHEMA}}


class Snapshot:
    def __init__(self, root: Path):
        self.root = root.resolve()

    def resolve(self, rel: str) -> Path:
        p = (self.root / (rel or ".").lstrip("/")).resolve()
        if not p.is_relative_to(self.root):
            raise ValueError("path escapes the repository")
        return p

    def rel(self, p: Path) -> str:
        return str(p.relative_to(self.root)) or "."

    def list_dir(self, path: str = ".") -> str:
        d = self.resolve(path)
        if not d.is_dir():
            return f"error: {path} is not a directory"
        out = [e.name + ("/" if e.is_dir() else "") for e in sorted(d.iterdir()) if e.name != ".sweep-context"]
        return "\n".join(out) or "(empty)"

    def glob(self, pattern: str) -> str:
        pattern = pattern.lstrip("/")
        hits = []
        for p in self.root.rglob("*"):
            if p.is_file():
                r = self.rel(p)
                if r.startswith(".sweep-context"):
                    continue
                if fnmatch.fnmatch(r, pattern) or fnmatch.fnmatch(r, pattern.replace("**/", "")) \
                        or fnmatch.fnmatch(p.name, pattern):
                    hits.append(r)
                    if len(hits) >= 300:
                        break
        return "\n".join(sorted(hits)) or "(no matches)"

    def read_file(self, path: str, offset: int = 1, limit: int = 400) -> str:
        p = self.resolve(path)
        if not p.is_file():
            return f"error: {path} is not a file"
        raw = p.read_bytes()
        if b"\0" in raw[:8192]:
            return f"error: {path} is binary ({len(raw)} bytes)"
        lines = raw.decode(errors="replace").splitlines()
        offset = max(1, int(offset or 1))
        limit = max(1, min(int(limit or 400), 1500))
        chunk = lines[offset - 1: offset - 1 + limit]
        body = "\n".join(f"{i:>6}\t{l}" for i, l in enumerate(chunk, offset))
        more = len(lines) - (offset - 1 + len(chunk))
        if more > 0:
            body += f"\n... ({more} more lines; total {len(lines)})"
        return body or "(empty range)"

    def grep(self, pattern: str, path: str = ".", glob: str | None = None, ignore_case: bool = False) -> str:
        target = self.resolve(path)
        rg = shutil.which("rg")
        if rg:
            # --no-config + fixed argv: no --pre or other executing options can sneak in.
            cmd = [rg, "--no-config", "-n", "--no-heading", "--color=never", "-M", "400",
                   "--glob", "!.sweep-context/**"]
            if ignore_case:
                cmd.append("-i")
            if glob:
                cmd += ["--glob", glob]
            cmd += ["-e", pattern, str(target)]
        else:
            cmd = ["grep", "-rnE", "--exclude-dir=.sweep-context"] + (["-i"] if ignore_case else []) \
                + ([f"--include={glob}"] if glob else []) + ["-e", pattern, str(target)]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=120, errors="replace")
        if res.returncode not in (0, 1):
            return f"error: {res.stderr.strip()[:500]}"
        lines = [l.replace(str(self.root) + "/", "", 1) for l in res.stdout.splitlines()]
        out = "\n".join(lines[:200])
        if len(lines) > 200:
            out += f"\n... ({len(lines) - 200} more matches; narrow the search)"
        return out or "(no matches)"

    def call(self, name: str, args: dict) -> str:
        fn = {"list_dir": self.list_dir, "glob": self.glob, "read_file": self.read_file, "grep": self.grep}.get(name)
        if fn is None:
            return f"error: unknown tool {name}"
        try:
            out = fn(**args)
        except TypeError as e:
            return f"error: bad arguments: {e}"
        except Exception as e:
            return f"error: {e}"
        if len(out) > MAX_TOOL_CHARS:
            out = out[:MAX_TOOL_CHARS] + f"\n... (truncated at {MAX_TOOL_CHARS} chars; use offset/limit or narrow)"
        return out


# --------------------------------------------------------------------------
# Agent loop

OUTPUT_INSTRUCTIONS = """
## Tools and output

You have read-only tools: `list_dir`, `glob`, `read_file`, `grep`. There is no shell, build or network. Paths are relative to the repository root. Work through the code with these tools before concluding; do not report from memory or from documentation alone.

When you are done, call `submit_findings` exactly once with your result. Do not put the result in a normal message.
"""


def build_prompt(goal: dict | None, focus: str | None, commit: str) -> str:
    changes_note = "Recent commits are listed in `.sweep-context/changes.txt`."
    if goal is None:
        goal = {"title": "Custom focus", "objective": focus, "success": "a concrete, code-traced attack.",
                "refs": "all invariants", "start": ["CLAUDE.md (invariants, accepted risks)"]}
    elif focus:
        goal = dict(goal, objective=goal["objective"].strip() + "\n\nAdditional focus from the operator: " + focus)
    prompt = sweep.fill(
        "hunter.md",
        commit=commit,
        goal_title=goal["title"],
        goal_objective=goal["objective"].strip(),
        goal_success=goal["success"],
        goal_refs=goal["refs"],
        goal_start="\n".join(f"- {s}" for s in goal["start"]),
        changes_note=changes_note,
        severity_scale=sweep.SEVERITY_SCALE,
        output_instructions=OUTPUT_INSTRUCTIONS,
    )
    # hunter.md was written for CLI agents with a shell; correct that line.
    return prompt.replace("Reading files plus `grep`/`rg`/`find` is enough.",
                          "Your read-only tools are enough.")


def prune(messages: list, budget_chars: int) -> None:
    """Elide the oldest tool outputs once the conversation exceeds the budget."""
    total = sum(len(m.get("content") or "") for m in messages)
    for m in messages:
        if total <= budget_chars:
            return
        if m["role"] == "tool" and not m["content"].startswith("[elided"):
            total -= len(m["content"])
            m["content"] = "[elided to save context; call the tool again if you still need this]"
            total += len(m["content"])


def hunt(model: str, snap: Snapshot, prompt: str, label: str, out_stem: Path, args) -> dict:
    messages = [{"role": "user", "content": prompt}]
    tools = TOOLS + [submit_tool()]
    transcript = out_stem.with_suffix(".transcript.jsonl")
    cost = 0.0
    tokens_in = tokens_out = 0
    result = None
    forced = False

    def log_msg(obj):
        with transcript.open("a") as fh:
            fh.write(json.dumps(obj) + "\n")

    log_msg({"role": "user", "content": prompt})
    for turn in range(1, args.max_turns + 2):
        if (turn > args.max_turns or Spend.over_budget()) and not forced:
            forced = True
            why = "Cost budget reached" if Spend.over_budget() else "Turn budget exhausted"
            if Spend.over_budget():
                say(f"{label}: --max-cost ${Spend.max_cost:.2f} reached, asking for final result")
            messages.append({"role": "user", "content":
                             f"{why}. Call submit_findings now with what you have traced; "
                             "put unfinished leads in coverage_notes."})
        prune(messages, args.context_chars)
        body = {"model": model, "messages": messages, "tools": tools, "usage": {"include": True}}
        if args.max_tokens:
            body["max_tokens"] = args.max_tokens
        if forced:
            body["tool_choice"] = {"type": "function", "function": {"name": "submit_findings"}}
        if args.temperature is not None:
            body["temperature"] = args.temperature
        if args.reasoning:
            body["reasoning"] = {"effort": args.reasoning}
        resp = http_json("POST", f"{API}/chat/completions", body)
        if "error" in resp:
            raise RuntimeError(f"OpenRouter error: {resp['error']}")
        usage = resp.get("usage") or {}
        call_cost = Spend.add(usage)
        cost += call_cost
        tokens_in += int(usage.get("prompt_tokens") or 0)
        tokens_out += int(usage.get("completion_tokens") or 0)
        say(f"{label} t{turn}: call +${call_cost:.4f} ({int(usage.get('prompt_tokens') or 0):,} in / "
            f"{int(usage.get('completion_tokens') or 0):,} out tokens), this goal ${cost:.4f}")
        msg = resp["choices"][0]["message"]
        log_msg(msg)
        calls = msg.get("tool_calls") or []
        messages.append({"role": "assistant", "content": msg.get("content") or "",
                         **({"tool_calls": calls} if calls else {})})
        if not calls:
            if forced:
                break
            messages.append({"role": "user", "content":
                             "Keep investigating with the tools, or call submit_findings if you are done."})
            continue
        for c in calls:
            name = c["function"]["name"]
            try:
                fargs = json.loads(c["function"].get("arguments") or "{}")
            except json.JSONDecodeError as e:
                out = f"error: arguments are not valid JSON: {e}"
            else:
                if name == "submit_findings":
                    errs = sweep.check_schema(fargs, sweep.HUNT_SCHEMA)
                    if errs:
                        out = "rejected, fix and resubmit:\n" + "\n".join(errs[:30])
                    else:
                        result = fargs
                        out = "accepted"
                else:
                    say(f"{label} t{turn}: {name} {json.dumps(fargs)[:120]}")
                    out = snap.call(name, fargs)
            messages.append({"role": "tool", "tool_call_id": c["id"], "content": out})
            log_msg({"role": "tool", "name": name, "content": out[:2000]})
        if result is not None:
            break
        if forced and (turn > args.max_turns + 1 or Spend.over_budget()):
            break
    return {"result": result, "turns": turn, "cost": cost, "tokens_in": tokens_in, "tokens_out": tokens_out}


# --------------------------------------------------------------------------
# Report

def to_markdown(model: str, title: str, commit: str, run: dict) -> str:
    r = run["result"]
    lines = [f"# {title}", "",
             f"- model: `{model}`", f"- commit: `{commit}`",
             f"- turns: {run['turns']}, tokens in/out: {run['tokens_in']:,}/{run['tokens_out']:,}, "
             f"cost: ${run['cost']:.2f}", "",
             "> Unverified single-model output. Check every finding against the code before acting.", ""]
    if r is None:
        lines.append("**The model did not submit a result.** See the transcript.")
        return "\n".join(lines) + "\n"
    findings = sorted(r["findings"], key=lambda f: sweep.sev_rank(f["severity"]))
    lines.append(f"## Findings ({len(findings)})\n")
    for i, f in enumerate(findings, 1):
        lines += [f"### {i}. [{f['severity']}] {f['title']}", "",
                  f"- **Attacker:** {f['attacker_tier']}",
                  f"- **Invariants:** {', '.join(f['invariants']) or '-'}",
                  f"- **Confidence:** {f['confidence']}",
                  f"- **Preconditions:** {f['preconditions']}", "", "**Attack steps**", ""]
        lines += [f"{n}. {s}" for n, s in enumerate(f["attack_steps"], 1)]
        lines += ["", "**Code locations**", ""] + [f"- `{c}`" for c in f["code_locations"]]
        lines += ["", f"**Why defences fail:** {f['why_defences_fail']}", "",
                  f"**Suggested fix:** {f['suggested_fix']}", ""]
    lines += ["## Checked and held", ""] + [f"- {c}" for c in r["checked_and_held"]]
    lines += ["", "## Coverage notes", "", r["coverage_notes"], ""]
    return "\n".join(lines)


# --------------------------------------------------------------------------
# CLI

def pick_interactive(args, goals: list[dict]) -> None:
    if not sys.stdin.isatty():
        raise SystemExit("--model and --goal/--all/--focus are required when not interactive")
    if not args.model:
        dflt = os.environ.get("OPENROUTER_MODEL", "")
        ans = input(f"OpenRouter model slug{f' [{dflt}]' if dflt else ''} (see --list-models): ").strip()
        args.model = ans or dflt
        if not args.model:
            raise SystemExit("no model given")
    if not (args.goal or args.all or args.focus):
        print("\nGoals:")
        for i, g in enumerate(goals, 1):
            print(f"  {i:>2}) {g['id']:<22} {g['title']}")
        print("   a) all goals\n   f) free-text focus")
        ans = input("pick (number(s), a, or f): ").strip().lower()
        if ans == "a":
            args.all = True
        elif ans == "f":
            args.focus = input("focus: ").strip()
        else:
            for tok in re.split(r"[ ,]+", ans):
                if tok.isdigit() and 1 <= int(tok) <= len(goals):
                    args.goal.append(goals[int(tok) - 1]["id"])
            if not args.goal:
                raise SystemExit("nothing picked")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-m", "--model", default=os.environ.get("OPENROUTER_MODEL"),
                    help="OpenRouter model slug, e.g. openai/gpt-5 (env OPENROUTER_MODEL)")
    ap.add_argument("--list-models", nargs="?", const="", metavar="FILTER",
                    help="list tool-capable OpenRouter models (optionally filtered) and exit")
    ap.add_argument("-g", "--goal", action="append", default=[], help="goal id from goals.toml (repeatable)")
    ap.add_argument("--all", action="store_true", help="run every goal")
    ap.add_argument("--focus", help="free-text mission; alone = custom hunt, with -g = extra focus for that goal")
    ap.add_argument("--list-goals", action="store_true", help="list goals and exit")
    ap.add_argument("--ref", default="HEAD", help="git ref to scan (default HEAD; only committed files)")
    ap.add_argument("-j", "--jobs", type=int, default=1, help="goals to run in parallel")
    ap.add_argument("--max-turns", type=int, default=80, help="tool-use turns before forcing a result")
    ap.add_argument("--max-tokens", type=int, help="max output tokens per model call (default: provider's)")
    ap.add_argument("--context-chars", type=int, default=500_000,
                    help="elide old tool outputs above this many chars (~4 chars/token); "
                         "lower it for small-context models")
    ap.add_argument("--reasoning", choices=["minimal", "low", "medium", "high"],
                    help="OpenRouter reasoning effort, for models that support it")
    ap.add_argument("--temperature", type=float)
    ap.add_argument("--max-cost", type=float, metavar="USD",
                    help="stop the run at this OpenRouter spend: running goals are asked to submit, "
                         "goals not yet started are skipped")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT, help=f"output root (default {DEFAULT_OUT})")
    args = ap.parse_args(argv)

    if args.list_models is not None:
        return list_models(args.list_models or None)
    goals = sweep.load_goals(None)
    if args.list_goals:
        for g in goals:
            print(f"{g['id']:<22} {g['title']}")
        return 0
    if not args.model or not (args.goal or args.all or args.focus):
        pick_interactive(args, goals)
    api_key()

    selected = goals if args.all else (sweep.load_goals(args.goal) if args.goal else [None])
    Spend.max_cost = args.max_cost
    info = model_info(args.model)
    if info:
        Spend.pricing = info.get("pricing") or {}
    if info is None:
        say(f"warning: {args.model} not found in the OpenRouter model list; trying anyway")
    elif "tools" not in (info.get("supported_parameters") or []):
        raise SystemExit(f"{args.model} does not support tool calling on OpenRouter; pick another (--list-models)")
    else:
        ctx = info.get("context_length") or 0
        if ctx and args.context_chars > ctx * 3:
            args.context_chars = int(ctx * 2.5)
            say(f"{args.model} has a {ctx:,}-token context; capping --context-chars at {args.context_chars:,}")

    commit = sweep.git("rev-parse", "--short=12", args.ref)
    stamp = dt.datetime.now().strftime("%Y-%m-%d-%H%M")
    run_dir = args.out / f"{stamp}-{commit}-{sweep.slugify(args.model, 40)}"
    run_dir.mkdir(parents=True, exist_ok=True)

    tmp = Path(tempfile.mkdtemp(prefix="pq1-or-hunt-"))
    snap_root = tmp / "repo"
    changes = sweep.git("log", "--oneline", "-40", commit)
    sweep.make_snapshot(commit, snap_root, changes)
    snap = Snapshot(snap_root)
    say(f"model {args.model}, commit {commit}, snapshot {snap_root}")
    say(f"output: {run_dir}")

    def one(goal):
        gid = goal["id"] if goal else "custom"
        title = f"{goal['title'] if goal else 'Custom focus'} ({gid})"
        prompt = build_prompt(goal, args.focus, commit)
        stem = run_dir / gid
        if Spend.over_budget():
            say(f"{gid}: skipped, --max-cost reached")
            return gid, "skipped"
        say(f"{gid}: started")
        try:
            run = hunt(args.model, snap, prompt, gid, stem, args)
        except Exception as e:
            say(f"{gid}: FAILED: {e}")
            (stem.with_suffix(".error.txt")).write_text(str(e))
            return gid, None
        sweep.write_json(stem.with_suffix(".json"), {"model": args.model, "commit": commit, "goal": gid, **run})
        stem.with_suffix(".md").write_text(to_markdown(args.model, title, commit, run))
        n = len(run["result"]["findings"]) if run["result"] else "no result"
        say(f"{gid}: done, findings: {n}, turns {run['turns']}, ${run['cost']:.2f}")
        return gid, run

    try:
        with cf.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as ex:
            runs = list(ex.map(one, selected))
    finally:
        subprocess.run(["chmod", "-R", "u+w", str(tmp)])
        shutil.rmtree(tmp, ignore_errors=True)

    print("\nSummary")
    for gid, r in runs:
        if r == "skipped":
            print(f"  {gid:<22} skipped (--max-cost reached)")
        elif r is None:
            print(f"  {gid:<22} FAILED")
        elif r["result"] is None:
            print(f"  {gid:<22} no result submitted")
        else:
            sevs = [f["severity"] for f in r["result"]["findings"]]
            counts = ", ".join(f"{s}:{sevs.count(s)}" for s in sweep.SEVERITIES if s in sevs) or "none"
            print(f"  {gid:<22} {counts}  -> {run_dir / (gid + '.md')}")
    print(f"  total spent on OpenRouter this run: {Spend.label()}"
          + ("  (~ = some calls priced from list prices; OpenRouter did not report cost)" if Spend.estimated else ""))
    return 0 if all(isinstance(r, dict) and r["result"] for _, r in runs) else 1


if __name__ == "__main__":
    sys.exit(main())
