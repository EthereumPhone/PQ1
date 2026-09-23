"""python3 -m tools.check              run every rule; exit 1 on a violation that is not in baseline.toml
   python3 -m tools.check --rule V-TIN one rule
   python3 -m tools.check --propose    print baseline.toml blocks for the unbaselined violations
   python3 -m tools.check --strict     also fail on stale baseline rows (a fixed exception still listed)
   python3 -m tools.check --list       the rule table"""
import argparse
import json
import os
import sys
import tomllib

from . import rules

HERE = os.path.dirname(os.path.abspath(__file__))
BASELINE = os.path.join(HERE, "baseline.toml")


def load_baseline():
    if not os.path.exists(BASELINE):
        return []
    return tomllib.load(open(BASELINE, "rb")).get("known", [])


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python3 -m tools.check", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rule", nargs="+", metavar="ID")
    ap.add_argument("--propose", action="store_true")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--golden", nargs="?", const="sample", choices=["sample", "full"],
                    help="also compare rendered frames with golden.json (opt-in)")
    ap.add_argument("--update-golden", action="store_true", help="rewrite golden.json — LOOK at the renders first")
    a = ap.parse_args(argv)

    if a.list:
        for r in rules.RULES:
            print(f"{r['id']:12} {r['severity']:5} {r['method']:8} {r['title']}")
        return 0
    if a.update_golden or a.golden:
        from . import golden
        if a.update_golden:
            return golden.update()
        rules.RULES.append(dict(id="G-GOLDEN", severity="error", method="render",
                                title="rendered frames match golden.json",
                                fn=lambda: golden.compare(a.golden == "full")))

    known = load_baseline()
    kmap = {(k["rule"], k["where"], k["key"]): k for k in known}
    used, new, infos, report = set(), [], [], []
    todo = [r for r in rules.RULES if not a.rule or r["id"] in a.rule]
    for r in todo:
        try:
            vs = r["fn"]()
        except Exception as ex:                              # noqa: BLE001
            vs = [rules.V(f"rule:{r['id']}", "crashed", f"the rule itself raised {type(ex).__name__}: {ex}")]
        n_known = 0
        for v in vs:
            k = (r["id"], v["where"], v["key"])
            if r["severity"] == "info":
                infos.append((r, v))
            elif k in kmap:
                used.add(k); n_known += 1
            else:
                new.append((r, v))
        report.append((r, len(vs), n_known))
    stale = [k for k in kmap if k not in used and (not a.rule or k[0] in a.rule)]

    if a.json:
        print(json.dumps(dict(new=[dict(rule=r["id"], **v) for r, v in new], stale=[list(k) for k in stale],
                              info=[dict(rule=r["id"], **v) for r, v in infos],
                              rules=[dict(id=r["id"], found=n, known=k) for r, n, k in report]), indent=1))
        return 1 if new or (a.strict and stale) else 0

    if a.propose:
        for r, v in new:
            print(f'[[known]]\nrule = "{r["id"]}"\nwhere = {json.dumps(v["where"])}\nkey = {json.dumps(v["key"])}\n'
                  f'audit = ""\nreason = {json.dumps(v["msg"])}\n')
        print(f"# {len(new)} blocks — paste into tools/check/baseline.toml ONLY for debt you accept; "
              f"give each a reason and the audit finding id", file=sys.stderr)
        return 0

    for r, n, k in report:
        mark = "info" if r["severity"] == "info" else ("FAIL" if n > k else "ok")
        extra = f"  ({k} known)" if k else ""
        print(f"  {mark:4} {r['id']:12} {r['title']}{extra}" + (f"  [{n} noted]" if r["severity"] == "info" and n else ""))
    if infos:
        print("\nfor the record (info — never fails):")
        for r, v in infos:
            print(f"  {r['id']:12} {v['where']}  {v['key']}")
    if stale:
        print(f"\n{len(stale)} STALE baseline row(s) — the exception no longer exists; delete the row from "
              f"tools/check/baseline.toml:")
        for k in stale:
            print(f"  {k[0]:12} {k[1]}  {k[2]}")
    if new:
        print(f"\n{len(new)} NEW violation(s):")
        for r, v in new:
            loc = f":{v['line']}" if v.get("line") else ""
            print(f"  {r['id']:12} [{r['severity']}] {v['where']}{loc}\n               {v['key']}\n               -> {v['msg']}")
        print("\nFix the code (preferred), or accept the debt: python3 -m tools.check --propose")
        return 1
    print(f"\n{len(todo)} rules OK · {len(used)} known exceptions (tools/check/baseline.toml)"
          + (f" · {len(stale)} stale" if stale else ""))
    return 1 if (a.strict and stale) else 0


if __name__ == "__main__":
    sys.exit(main())
