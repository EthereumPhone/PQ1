"""Build handoff/ from the live code. `python3 -m tools.handoff --help`."""
import copy
import inspect
import json
import os
import pprint
import re
import shutil
import sys
import tempfile
import zipfile

from . import introspect as I
from . import previews, taxonomy, template
from pq1 import layout, status
import flows
import screens

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(I.REPO, "handoff")
SKILL_SRC = os.path.join(I.REPO, ".claude", "skills", "pq1-conformance")
ZIP_NAME = "pq1-handoff.zip"
PREVIEW_BUDGET_MB = 25
PREVIEW_WARN_KB = 2048
SOURCE_DIRS = ["pq1", "flows", "screens", os.path.join("tools", "panel"),
               os.path.join("tools", "handoff"), os.path.join("tools", "check")]
SOURCE_FILES = ["requirements.txt", "README.md"]


class BuildError(Exception):
    pass


def dump(data):
    return json.dumps(I.jsonable(data), indent=1, sort_keys=True, ensure_ascii=False) + "\n"


# ------------------------------------------------------------------ entries --
def library_entries():
    out = []
    for qual, mod in sorted(screens.modules().items()):
        cat, name = qual.split("/")
        doc = (inspect.getdoc(mod) or "").strip()
        first = doc.split("\n\n")[0].replace("\n", " ") if doc else ""
        presets = sorted(getattr(mod, "PRESETS", {}))
        keys, seen = [], []
        for p in [None] + presets:
            sp = screens.spec(qual, preset=p) if p else screens.spec(qual)
            if sp in seen:                        # a preset equal to the default renders once
                continue
            seen.append(sp)
            keys.append(f"{qual}|{p}" if p else qual)
        out.append(dict(section="library", slug=f"{cat}-{name}".replace("_", "-"), title=f"{cat} / {name}",
                        summary=first[:200], port="PORT", owners=[I.rel(mod.__file__)], qual=qual,
                        match=(lambda s, a, i, _n=mod.ANIM: s.get("kind") == "status" and s.get("anim") == _n),
                        preview=None, anim_keys=keys, gestures=("entry —" if name == "pin_entering" else None)))
    return out


def all_entries():
    return taxonomy.CORE + library_entries()


def live_matches(entry):
    """[(flow, index, screen)] of every live flow screen this entry describes"""
    if entry.get("match") is None:
        return []
    hits = []
    for n in flows.names():
        mod = flows.get(n)
        variants = [flows.screens(n)]
        for e in sorted(getattr(mod, "ENDS", {})):
            try:
                variants.append(flows.screens(n, end=e))
            except ValueError:
                pass
        seen = set()
        for scr in variants:
            for i, s in enumerate(scr):
                key = (i, s.get("id"))
                if key in seen:
                    continue
                try:
                    ok = entry["match"](s, scr, i)
                except Exception:                   # noqa: BLE001
                    ok = False
                if ok:
                    seen.add(key)
                    hits.append((n, i, s, scr))
    return hits


# ------------------------------------------------------------------- blocks --
def _pretty(d):
    d = {k: v for k, v in d.items() if k not in ("dwell",)}
    return pprint.pformat(d, width=92, sort_dicts=False, compact=True)


def blocks_for(entry, specs, preview_files):
    hits = live_matches(entry)

    pref = (entry.get("preview") or (None, None))[1]
    if hits and isinstance(pref, str):
        hits = sorted(hits, key=lambda h: h[0] != pref)     # the previewed flow first

    def example(_arg):
        if not hits:
            return "_No live flow uses this yet._"
        n, i, s, _ = hits[0]
        return (f"Screen {i + 1} of flow `{n}`, as the design system normalizes it "
                f"(defaults filled in):\n\n```python\n{_pretty(s)}\n```")

    def used_in(_arg):
        if entry.get("match") is None:
            return ""
        if not hits:
            return "Used in: _no live flow yet._"
        per = {}
        for n, *_ in hits:
            per[n] = per.get(n, 0) + 1
        names = [f"`{n}`" + (f" ×{c}" if c > 1 else "") for n, c in sorted(per.items())]
        more = f" … and {len(names) - 8} more (see the matrix in [INDEX](../INDEX.md))" if len(names) > 8 else ""
        return f"Used in {len(per)} of {len(flows.names())} flows: " + ", ".join(names[:8]) + more

    def geometry(_arg):
        if not hits or hits[0][2].get("kind") == "status":
            return ""
        L = layout.layout_of(hits[0][2])
        rows = ["| part | value |", "|---|---|",
                f"| circle | centre x {template.fmt_num(L['circle']['cx'])}, y {template.fmt_num(L['circle']['cy'])}, "
                f"r {template.fmt_num(L['circle']['r'])} |"]
        for t in L.get("texts", []):
            bits = [f"{k} {template.fmt_num(v) if isinstance(v, (int, float)) else v}"
                    for k, v in t.items() if k in ("x", "y", "size", "anchor", "weight", "alpha")]
            rows.append(f"| text `{str(t.get('str', ''))[:28]}` | {', '.join(bits)} |")
        return "\n".join(rows)

    def preview(_arg):
        files = preview_files.get(entry["slug"], [])
        if not files:
            return "_No preview for this entry._"
        out = []
        for label, gif in files:
            rel_ = os.path.relpath(os.path.join("previews", gif), os.path.join("catalog", entry["section"]))
            out.append(f"**{label}**\n\n![{label}]({rel_})")
        return "\n\n".join(out)

    def variants(_arg):
        keys = entry.get("anim_keys")
        if not keys:
            return ""
        rows = ["| variant | resolves at | total | result hold | can lead | owns the canvas | interactive | loops |",
                "|---|---:|---:|---:|---|---|---|---|"]
        for k in keys:
            a = specs["anims.json"]["anims"][k]
            rows.append(f"| `{k.split('|')[1] if '|' in k else '(default)'}` | {a['t_resolve']} ms "
                        f"({a['frames_14']['t_resolve']} f) | {a['duration']} ms | {a['result_hold']} ms | "
                        f"{'yes' if a['can_lead'] else 'no'} | {'yes' if not a['rests_on_token'] else 'no'} | "
                        f"{'yes' if a['interactive'] else 'no'} | {'yes' if a.get('loops') else 'no'} |")
        return "\n".join(rows)

    def phases(_arg):
        keys = entry.get("anim_keys")
        if not keys:
            return ""
        names = []
        for k in keys:
            for p in specs["anims.json"]["anims"][k]["phases"]:
                if p not in names:
                    names.append(p)
        if not names:
            return "_This screen declares no `T_*` phase attributes; its timeline is in the module constants below._"
        head = "| phase attribute | " + " | ".join(f"`{k.split('|')[1] if '|' in k else '(default)'}`" for k in keys) + " |"
        rows = [head, "|---|" + "---:|" * len(keys)]
        for p in names:
            cells = []
            for k in keys:
                v = specs["anims.json"]["anims"][k]["phases"].get(p)
                cells.append("—" if v is None else f"{template.fmt_num(v)} ms ({template.fmt_frames(v)} f)")
            rows.append(f"| `{p}` | " + " | ".join(cells) + " |")
        return "\n".join(rows)

    def constants(_arg):
        keys = entry.get("anim_keys")
        if not keys:
            return ""
        mc = specs["anims.json"]["anims"][keys[0]].get("module_constants", {})
        if not mc:
            return ""
        rows = ["| module constant | value |", "|---|---|"]
        for k, v in sorted(mc.items()):
            rows.append(f"| `{k}` | `{json.dumps(v)}` |")
        return "\n".join(rows)

    def curves(_arg):
        keys = entry.get("anim_keys")
        if not keys:
            return ""
        cu = specs["anims.json"]["anims"][keys[0]]["curves_used"]
        return ", ".join(f"`motion.{c}`" for c in cu) or "_none_"

    def gestures(arg):
        ctx = arg or entry.get("gestures") or ""
        rows = [r for r in specs["gestures.json"]["truth_table"] if ctx in r["context"]]
        if not rows:
            raise template.PageError(f"{entry['slug']}: no truth-table context matches {ctx!r}")
        out = ["| context | gesture | result | from | to |", "|---|---|---|---|---|"]
        for r in rows:
            out.append(f"| {r['context']} | {r['gesture']} | `{r['result']}` | {r['from']} | {r['to']} |")
        return "\n".join(out)

    def owners(_arg):
        return "\n".join(f"- `{o}`" for o in entry["owners"])

    def spec_block(_arg):
        keys = entry.get("anim_keys")
        if not keys:
            return ""
        sp = specs["anims.json"]["anims"][keys[0]]["spec"]
        return "```python\n" + pprint.pformat(sp, width=92, sort_dicts=False, compact=True) + "\n```"

    return {"example": example, "used-in": used_in, "geometry": geometry, "preview": preview,
            "variants": variants, "phases": phases, "constants": constants, "curves": curves,
            "gestures": gestures, "owners": owners, "spec": spec_block}


LIBRARY_DEFAULT = """{{doc-self}}

## Variants

{{variants}}

## Phases (per variant, from the live instance)

{{phases}}

Curves this module calls: {{curves}}

{{constants}}

## Spec a flow splices in

{{spec}}

{{used-in}}

## Preview

{{preview}}

{{partial:port-notes}}
"""

PORT_BADGE = {"PORT": "**PORT** — the device implements this.",
              "DEMO-ONLY": "**DEMO-ONLY** — exists for the GIF / demo loop. Do not port.",
              "BENCH-ONLY": "**BENCH-ONLY** — exists for the laptop bench player. Do not port.",
              "SPEC-ONLY": "**SPEC-ONLY** — specified in `pq1/DESIGN.md`; the Python does not render it yet. Port from the spec."}


def render_page(entry, specs, preview_files, fields, allow_missing):
    src_path = os.path.join(template.PAGES, entry["section"], entry["slug"] + ".md")
    blocks = blocks_for(entry, specs, preview_files)
    if entry["section"] == "library":
        mod = screens.modules()[entry["qual"]]
        doc = inspect.getdoc(mod) or ""
        blocks["doc-self"] = "\n".join("> " + ln if ln else ">" for ln in doc.splitlines())
    if os.path.exists(src_path):
        body = open(src_path).read()
    elif entry["section"] == "library":
        body = LIBRARY_DEFAULT
    elif allow_missing:
        body = "_Page not written yet._\n\n{{used-in}}\n\n{{preview}}\n"
    else:
        raise BuildError(f"no page for {entry['section']}/{entry['slug']} — write "
                         f"tools/handoff/pages/{entry['section']}/{entry['slug']}.md")
    where = f"pages/{entry['section']}/{entry['slug']}.md"
    text = template.render(body, where, blocks, fields)
    head = (f"<!-- GENERATED by `python3 -m tools.handoff` from tools/handoff/{where} — do not edit here -->\n"
            f"# {entry['title']}\n\n{entry['summary']}\n\n{PORT_BADGE[entry['port']]}\n\n")
    tail = "\n\n## Owning files\n\n" + blocks["owners"]("") + "\n"
    return head + text.strip() + tail


# ----------------------------------------------------------------- previews --
def preview_plan(entry):
    """[(label, filename stem, recipe)]"""
    if entry["section"] == "library":
        return [((k.split("|")[1] if "|" in k else "default"),
                 entry["slug"] + ("--" + k.split("|")[1] if "|" in k else ""), ("anim", k))
                for k in entry["anim_keys"] if k != "pin/pin_entering" or True]
    rc = entry.get("preview")
    if rc is None:
        return []
    if rc[0] == "window":
        hits = live_matches(entry)
        if rc[1]:
            hits = [h for h in hits if h[0] == rc[1]] or hits
        if not hits:
            return []
        n, i, s, scr = hits[0]
        idx = [j for j in (i - 1, i, i + 1) if 0 <= j < len(scr) and scr[j]["kind"] != "status"]
        return [(f"in flow {n}", entry["slug"], ("window", n, idx))]
    if rc[0] == "synthetic":
        return [("synthetic — no live flow uses this screen type yet; built with the family's own helpers",
                 entry["slug"], rc)]
    return [("preview", entry["slug"], rc)]


def build_previews(entries, out_dir, only=None):
    files, total = {}, 0
    for e in entries:
        if only and e["slug"] not in only:
            continue
        for label, stem, rc in preview_plan(e):
            frames, still = previews.record(rc)
            n = previews.save_gif(frames, os.path.join(out_dir, stem + ".gif"))
            previews.save_png(still, os.path.join(out_dir, stem + ".png"))
            total += n
            if n > PREVIEW_WARN_KB * 1024:
                print(f"  warning: {stem}.gif is {n // 1024} KB", file=sys.stderr)
            files.setdefault(e["slug"], []).append((label, stem + ".gif"))
            print(f"  preview {stem}.gif  {len(frames)} frames  {n // 1024} KB", flush=True)
    if total > PREVIEW_BUDGET_MB * 1024 * 1024:
        raise BuildError(f"previews weigh {total // 1024 // 1024} MB — over the {PREVIEW_BUDGET_MB} MB budget")
    return files, total


def existing_previews(entries, out_dir):
    files = {}
    for e in entries:
        for label, stem, _ in preview_plan(e):
            if os.path.exists(os.path.join(out_dir, stem + ".gif")):
                files.setdefault(e["slug"], []).append((label, stem + ".gif"))
    return files


# -------------------------------------------------------------------- index --
def index_md(entries, specs):
    lines = ["<!-- GENERATED by `python3 -m tools.handoff` — do not edit -->", "# Catalog index", "",
             "Every screen type, library screen, component, action and transition of the PQ1 wallet UI. "
             "Tags: **PORT** implement on the device · **DEMO-ONLY** / **BENCH-ONLY** do not port · "
             "**SPEC-ONLY** specified, not rendered by the Python yet.", ""]
    for sec, title, blurb in taxonomy.SECTIONS:
        rows = [e for e in entries if e["section"] == sec]
        lines += [f"## {title}", "", blurb, "", "| page | what it is | port |", "|---|---|---|"]
        for e in rows:
            lines.append(f"| [{e['title']}]({sec}/{e['slug']}.md) | {e['summary']} | {e['port']} |")
        lines.append("")
    core = [e for e in taxonomy.SCREEN_TYPES if e.get("match")]
    lines += ["## Which flow uses which screen type", "",
              "Counts of screens per flow (default ending). Generated from the live flows.", "",
              "| flow | " + " | ".join(e["slug"] for e in core) + " | library screens |",
              "|---|" + "---:|" * len(core) + "---|"]
    for n in flows.names():
        scr = flows.screens(n)
        cells = []
        for e in core:
            c = sum(1 for i, s in enumerate(scr) if _safe(e["match"], s, scr, i))
            cells.append(str(c) if c else "·")
        lib = sorted({s["anim"] for s in scr if s.get("kind") == "status" and s.get("anim")
                      and s["anim"] not in ("qubit", "resolve", "arrive")})
        lines.append(f"| `{n}` | " + " | ".join(cells) + " | " + (", ".join(lib) or "·") + " |")
    return "\n".join(lines) + "\n"


def _safe(fn, s, scr, i):
    try:
        return bool(fn(s, scr, i))
    except Exception:                                       # noqa: BLE001
        return False


# ------------------------------------------------------------------- guards --
def coverage_guards(entries, specs):
    errs = []
    paged = {e.get("qual") for e in entries if e["section"] == "library"}
    for qual in screens.modules():
        if qual not in paged:
            errs.append(f"library screen {qual} has no catalog page")
    documented = set(specs["screens.schema.json"]["fields"])
    ride_along = set()
    for mod in screens.modules().values():
        ride_along |= set(getattr(mod, "SPEC", {}))
        for p in getattr(mod, "PRESETS", {}).values():
            ride_along |= set(p)
    internal = {"lead", "lead_gap", "handoff", "live", "preset"}
    for kind, keys in specs["screens.schema.json"]["keys_seen_in_live_flows"].items():
        for k in keys:
            if k not in documented and k not in ride_along and k not in internal:
                errs.append(f"screen key {k!r} (seen on a {kind} screen in a live flow) is not documented "
                            f"in pq1/layout.py's schema docstring")
    results = {r["result"] for r in specs["gestures.json"]["truth_table"]}
    src = "\n".join(open(os.path.join(template.PAGES, "actions", f)).read()
                    for f in sorted(os.listdir(os.path.join(template.PAGES, "actions")))
                    if f.endswith(".md")) if os.path.isdir(os.path.join(template.PAGES, "actions")) else ""
    for r in sorted(x for x in results if x and x != "fired"):
        if f"`{r}`" not in src and "{{gestures" not in src:
            errs.append(f"driver result {r!r} is not covered by any actions/ page")
    return errs


# --------------------------------------------------------------------- main --
def build_specs(fast_only=False):
    specs = {}
    for name, fn in I.SPECS.items():
        if fast_only and name in ("gestures.json", "traces.json"):
            continue
        specs[name] = I.jsonable(fn())
    return specs


def _diff(a, b, path=""):
    if isinstance(a, dict) and isinstance(b, dict):
        out = []
        for k in sorted(set(a) | set(b)):
            if k not in a:
                out.append(f"{path}/{k}: (new) {json.dumps(b[k])[:80]}")
            elif k not in b:
                out.append(f"{path}/{k}: (gone)")
            else:
                out += _diff(a[k], b[k], f"{path}/{k}")
        return out
    if a != b:
        return [f"{path}: {json.dumps(a)[:60]} -> {json.dumps(b)[:60]}"]
    return []


def check(full=False):
    """is handoff/ still true to the live code? exit 1 naming what moved"""
    spec_dir = os.path.join(OUT, "spec")
    if not os.path.isdir(spec_dir):
        print("handoff/ has not been built — run `python3 -m tools.handoff`")
        return 1
    live = build_specs(fast_only=not full)
    if not full:
        live.pop("build.json", None)     # it hashes tools/handoff itself; --full checks it
    bad = []
    for name, data in live.items():
        p = os.path.join(spec_dir, name)
        disk = json.load(open(p)) if os.path.exists(p) else {}
        bad += [f"{name}{d}" for d in _diff(disk, json.loads(dump(data)))]
    if not bad:
        print(f"handoff/ matches the live code ({len(live)} specs compared"
              f"{'' if full else '; --full adds gestures + traces'}).")
        return 0
    print(f"handoff/ is STALE — {len(bad)} values moved since it was built:")
    for d in bad[:40]:
        print("  " + d)
    names = set(re.findall(r"/([A-Z][A-Z0-9_]{3,})\b", "\n".join(bad)))
    pages = []
    for root, _, files in os.walk(template.PAGES):
        for f in files:
            txt = open(os.path.join(root, f)).read()
            if any(n in txt for n in names):
                pages.append(os.path.relpath(os.path.join(root, f), template.PAGES))
    if pages:
        print("pages that cite a moved token: " + ", ".join(sorted(pages)))
    print("rebuild with `python3 -m tools.handoff`")
    return 1


def _copy_tree(src, dst, skip=("__pycache__", ".DS_Store")):
    for root, dirs, files in os.walk(src):
        dirs[:] = sorted(d for d in dirs if d not in skip and not d.endswith("_frames"))
        for f in sorted(files):
            if f in skip or f.endswith(".pyc"):
                continue
            rel_ = os.path.relpath(os.path.join(root, f), src)
            os.makedirs(os.path.dirname(os.path.join(dst, rel_)) or dst, exist_ok=True)
            shutil.copyfile(os.path.join(root, f), os.path.join(dst, rel_))


def render_pages(slugs, specs_from):
    """draft mode for page authors: render pages/<section>/<slug>.md against specs already on disk
    (fast — no driver runs) and print them, or the error that would fail the build"""
    spec_dir = os.path.join(specs_from, "spec")
    specs = {f: json.load(open(os.path.join(spec_dir, f))) for f in os.listdir(spec_dir) if f.endswith(".json")}
    fields = I.schema_fields()
    entries = {f"{e['section']}/{e['slug']}": e for e in all_entries()}
    rc = 0
    for slug in slugs:
        e = entries.get(slug) or next((v for k, v in entries.items() if k.endswith("/" + slug)), None)
        if e is None:
            print(f"unknown page {slug!r}; one of: {', '.join(sorted(entries))}", file=sys.stderr)
            rc = 1
            continue
        files = existing_previews([e], os.path.join(specs_from, "previews"))
        try:
            print(render_page(e, specs, files, fields, allow_missing=False))
            print(f"\n[ok] {e['section']}/{e['slug']} renders", file=sys.stderr)
        except (template.PageError, BuildError) as ex:
            print(f"[FAIL] {ex}", file=sys.stderr)
            rc = 1
    return rc


def build(out=OUT, with_previews=True, only=None, allow_missing=False):
    entries = all_entries()
    print("specs …", flush=True)
    specs = build_specs()
    fields = specs["screens.schema.json"]["fields"]
    tmp = tempfile.mkdtemp(prefix="handoff-")
    try:
        os.makedirs(os.path.join(tmp, "spec"))
        for name, data in specs.items():
            open(os.path.join(tmp, "spec", name), "w").write(dump(data))
        pv_dir = os.path.join(tmp, "previews")
        if with_previews:
            print("previews (re-rendered at 14 fps from live code) …", flush=True)
            if only and os.path.isdir(os.path.join(out, "previews")):
                _copy_tree(os.path.join(out, "previews"), pv_dir)
            files, total = build_previews(entries, pv_dir, only)
            files = existing_previews(entries, pv_dir)
            print(f"  {sum(len(v) for v in files.values())} previews, "
                  f"{sum(os.path.getsize(os.path.join(pv_dir, f)) for f in os.listdir(pv_dir)) // 1024 // 1024} MB")
        else:
            if os.path.isdir(os.path.join(out, "previews")):
                _copy_tree(os.path.join(out, "previews"), pv_dir)
            files = existing_previews(entries, pv_dir) if os.path.isdir(pv_dir) else {}
        print("pages …", flush=True)
        errs = []
        for e in entries:
            try:
                text = render_page(e, specs, files, fields, allow_missing)
            except (template.PageError, BuildError) as ex:
                errs.append(str(ex))
                continue
            p = os.path.join(tmp, "catalog", e["section"], e["slug"] + ".md")
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "w").write(text)
        guards = coverage_guards(entries, specs)
        if allow_missing:
            for g in guards:
                print('  (draft) ' + g, file=sys.stderr)
        else:
            errs += guards
        open(os.path.join(tmp, "catalog", "INDEX.md"), "w").write(index_md(entries, specs))
        root_blocks = {"counts": lambda _a: (
            f"{len(flows.names())} flows · {len(screens.modules())} library screens · "
            f"{len([e for e in entries if e['section'] == 'screen-types'])} screen types · "
            f"{len([e for e in entries if e['section'] == 'components'])} components · "
            f"{len([e for e in entries if e['section'] == 'actions'])} actions · "
            f"{len([e for e in entries if e['section'] == 'transitions'])} transitions")}
        for name in ("README.md", "CLAUDE.md"):
            src = os.path.join(template.PAGES, "_root", name)
            if os.path.exists(src):
                try:
                    body = template.render(open(src).read(), f"pages/_root/{name}", root_blocks, fields)
                    open(os.path.join(tmp, name), "w").write(
                        f"<!-- GENERATED by `python3 -m tools.handoff` from tools/handoff/pages/_root/{name} -->\n" + body)
                except template.PageError as ex:
                    errs.append(str(ex))
            elif not allow_missing:
                errs.append(f"missing tools/handoff/pages/_root/{name}")
        for name in ("REPORT.md", "RULES.md"):     # hand-off prose generated beside the specs
            src = os.path.join(HERE, name)
            if os.path.exists(src):
                shutil.copyfile(src, os.path.join(tmp, name))
        if os.path.isdir(SKILL_SRC):
            dst = os.path.join(tmp, "skill", "pq1-conformance")
            _copy_tree(SKILL_SRC, dst)
            _copy_tree(os.path.join(tmp, "spec"), os.path.join(dst, "spec"))
        bl = os.path.join(I.REPO, "tools", "check", "baseline.toml")
        if os.path.exists(bl):      # the tolerated debt ships beside the numbers it explains
            shutil.copyfile(bl, os.path.join(tmp, "spec", "exceptions.toml"))
        if errs:
            print(f"\nBUILD FAILED — {len(errs)} problems:", file=sys.stderr)
            for er in errs:
                print("  - " + er, file=sys.stderr)
            return 1
        if os.path.isdir(out):
            shutil.rmtree(out)
        shutil.move(tmp, out)
        tmp = None
        n_pages = sum(len(f) for _, _, f in os.walk(os.path.join(out, "catalog")))
        print(f"built {os.path.relpath(out, I.REPO)}/ — {n_pages} catalog pages, {len(specs) + 1} specs")
        return 0
    finally:
        if tmp and os.path.isdir(tmp):
            shutil.rmtree(tmp)


def make_zip(out=OUT):
    """pq1-handoff.zip: handoff/ at the root + the skill where Claude Code finds it + a
    runnable snapshot of the source — built fresh, never committed"""
    path = os.path.join(I.REPO, ZIP_NAME)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        def add(src, arc):
            zi = zipfile.ZipInfo(arc, date_time=(2026, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o644 << 16
            z.writestr(zi, open(src, "rb").read())
        for root, dirs, files in os.walk(out):
            dirs.sort()
            for f in sorted(files):
                if f != ".DS_Store":
                    add(os.path.join(root, f), os.path.relpath(os.path.join(root, f), out))
        sk = os.path.join(out, "skill", "pq1-conformance")
        for root, dirs, files in os.walk(sk):
            dirs.sort()
            for f in sorted(files):
                add(os.path.join(root, f), os.path.join(".claude", "skills", "pq1-conformance",
                                                        os.path.relpath(os.path.join(root, f), sk)))
        for d in SOURCE_DIRS:
            for root, dirs, files in os.walk(os.path.join(I.REPO, d)):
                dirs[:] = sorted(x for x in dirs if x != "__pycache__" and not x.endswith("_frames"))
                for f in sorted(files):
                    if not f.endswith(".pyc") and f != ".DS_Store":
                        add(os.path.join(root, f), os.path.join("source", os.path.relpath(os.path.join(root, f), I.REPO)))
        for f in SOURCE_FILES:
            if os.path.exists(os.path.join(I.REPO, f)):
                add(os.path.join(I.REPO, f), os.path.join("source", f))
    print(f"zipped -> {ZIP_NAME} ({os.path.getsize(path) // 1024 // 1024} MB)")
    return 0
