"""python3 -m tools.handoff            build handoff/ from the live code
   python3 -m tools.handoff --check    is handoff/ still true to the code? (fast; exit 1 if stale)
   python3 -m tools.handoff --zip      build, then write pq1-handoff.zip (catalog + skill + runnable source)"""
import argparse
import sys

from . import build


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python3 -m tools.handoff", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="compare handoff/spec with the live code, build nothing")
    ap.add_argument("--full", action="store_true", help="with --check: also re-run the driver (gestures, traces) — slow")
    ap.add_argument("--zip", action="store_true", help="after building, write pq1-handoff.zip")
    ap.add_argument("--no-previews", action="store_true", help="keep the previews already in handoff/ (fast rebuild of pages + specs)")
    ap.add_argument("--only", nargs="+", metavar="SLUG", help="re-render the previews of these entries only")
    ap.add_argument("--allow-missing", action="store_true", help="draft mode: a missing page is a stub, not an error")
    ap.add_argument("-o", "--out", default=build.OUT, help="output folder (default: handoff/)")
    ap.add_argument("--page", nargs="+", metavar="SECTION/SLUG", help="page authors: render these pages to stdout (fast)")
    ap.add_argument("--specs-from", default=build.OUT, metavar="DIR", help="with --page: a built handoff folder whose spec/ to reuse")
    a = ap.parse_args(argv)
    if a.page:
        return build.render_pages(a.page, a.specs_from)
    if a.check:
        return build.check(a.full)
    rc = build.build(a.out, with_previews=not a.no_previews, only=a.only, allow_missing=a.allow_missing)
    if rc == 0 and a.zip:
        rc = build.make_zip(a.out)
    return rc


if __name__ == "__main__":
    sys.exit(main())
