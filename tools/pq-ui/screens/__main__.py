"""Render any library screen: python -m screens [<cat>/]<name>|<preset> [flags]

With no arguments, renders the default demo — the unknown-token idle screen
on a randomly picked design-system ramp (idle/unknown_token). --list (or
-h/--help) shows the catalog. Common flags come from pq1.render.run
(-o/--fps/--at/--frames/--scale/--loops); per-screen flags come from the
module (--pin, --severity, --dir, --treatment, --ending, ...); --ready MS
answers a loading film (the explosion, also as a lead) at that ms — the
orbit wraps whole turns until then. Output defaults to
renders/screens/<name>.gif.
"""
import os
import sys

from pq1 import canvas, render, status

import screens


def _list():
    rows = screens.catalog()
    w = max(len(k) for k in rows)
    for qual, r in rows.items():
        extra = f"  presets: {', '.join(r['presets'])}" if r["presets"] else ""
        print(f"{qual:<{w}}  {r['doc']}{extra}")


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        # default demo: the unknown-token idle screen, random ramp
        argv = ["unknown_token"]
    if argv[0] in ("-h", "--help", "--list", "list"):
        _list()
        return 0
    name, rest = argv[0], argv[1:]
    try:
        mod, pover = screens.get(name)
    except ValueError as e:
        print(e)
        return 1

    if hasattr(mod, "build"):
        build = lambda args: mod.build(args, dict(pover))  # noqa: E731
    else:
        def build(args):
            spec = dict(getattr(mod, "SPEC", {}))
            spec.update(pover)
            spec.setdefault("kind", "status")
            spec.setdefault("anim", mod.ANIM)
            spec.setdefault("token", {"variant": "solid"})
            spec.setdefault("result", None)
            if hasattr(mod, "spec_from_args"):
                spec.update(mod.spec_from_args(args))
            if args.ready is not None:      # a film that waits: answered at MS
                spec["ready"] = args.ready
            anim = status.anim_for(spec)

            def frame(t):
                cv = canvas.Canvas()
                anim.draw(cv, t)
                return cv.out()
            return frame, anim.duration

    def add_args(ap):
        ap.add_argument("--ready", type=float, default=None, metavar="MS",
                        help="a loading film (the explosion, also as a lead): "
                             "the work answers at MS — the orbit wraps whole "
                             "turns until then (a screen with no film raises)")
        if hasattr(mod, "add_args"):
            mod.add_args(ap)

    out_name = name.replace("/", "_")
    render.run(out_name, build, description=(mod.__doc__ or "").strip().splitlines()[0],
               add_args=add_args, argv=rest,
               out_dir=os.path.join("renders", "screens"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
