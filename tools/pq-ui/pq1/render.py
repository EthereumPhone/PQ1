"""PQ1 render harness — one frame loop + CLI surface for standalone screens.

Every screen/animation module renders through this instead of hand-rolling
its own argparse + GIF/frames pipeline:

    from pq1 import render

    def build(args):
        anim = ...                      # anything with .draw(cv, t)
        def frame(t):
            cv = canvas.Canvas()
            anim.draw(cv, t)
            return cv.out()
        return frame, anim.duration     # optionally (frame, duration, step_fn)

    render.run("padlock", build, add_args=my_flags)

build(args) -> (frame_fn, duration_ms) or (frame_fn, duration_ms, step_fn).
frame_fn(t_ms) returns a PIL image (Canvas.out()). step_fn(dt_ms), when
given, advances a stateful screen's physics once per frame tick — it is
also called for --at seeks so any frame stays reachable.
"""
import argparse
import os

from PIL import Image

from . import flow


def frames_of(frame_fn, duration_ms, fps=30, step_fn=None, loops=1):
    """render [0, duration_ms * loops) at fps; returns the frame list"""
    step = 1000.0 / fps
    frames = []
    t = 0.0
    total = duration_ms * max(1, loops)
    while t < total:
        if step_fn:
            step_fn(step)
        frames.append(frame_fn(t))
        t += step
    return frames


def _scaled(img, scale):
    if scale and scale > 1:
        img = img.resize((img.width * scale, img.height * scale), Image.NEAREST)
    return img


def run(name, build, description=None, add_args=None, argv=None,
        out_dir="renders"):
    """standard CLI: -o/--out, --fps (30 preview, 14 = panel rate), --at MS
    (single PNG), --frames DIR, --scale N (NEAREST, inspection), --loops N.
    Defaults <out_dir>/<name>.gif (or .png for --at)."""
    ap = argparse.ArgumentParser(description=description or name)
    ap.add_argument("-o", "--out", default=None, help="output path")
    ap.add_argument("--fps", type=int, default=30, help="frame rate (30 preview, 14 = panel rate)")
    ap.add_argument("--at", type=float, default=None, metavar="MS", help="render one frame at t -> PNG")
    ap.add_argument("--frames", default=None, metavar="DIR", help="also dump per-frame PNGs (0000.png ...)")
    ap.add_argument("--scale", type=int, default=1, help="NEAREST upscale for inspection")
    ap.add_argument("--loops", type=int, default=1, help="repeat the sequence")
    if add_args:
        add_args(ap)
    args = ap.parse_args(argv)

    built = build(args)
    frame_fn, duration_ms = built[0], built[1]
    step_fn = built[2] if len(built) > 2 else None

    if args.at is not None:
        step = 1000.0 / args.fps
        if step_fn:  # advance stateful physics up to the seek point
            t = 0.0
            while t < args.at:
                step_fn(min(step, args.at - t))
                t += step
        img = _scaled(frame_fn(args.at), args.scale)
        out = args.out or os.path.join(out_dir, f"{name}.png")
        os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
        img.save(out)
        print(out)
        return

    frames = frames_of(frame_fn, duration_ms, args.fps, step_fn, args.loops)
    if args.scale > 1:
        frames = [_scaled(f, args.scale) for f in frames]
    out = args.out or os.path.join(out_dir, f"{name}.gif")
    flow.save_gif(frames, out, args.fps, frames_dir=args.frames)
