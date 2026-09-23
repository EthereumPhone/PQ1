"""Golden frames (opt-in: `python3 -m tools.check --golden`).

A pixel regression without the pixels: each library screen is rendered at a
few telling moments (its previews, each phase boundary, the rest) and the
frame's sha256 is compared with golden.json. `--golden=full` hashes EVERY
14 fps frame of every screen. The hashes are only comparable on the same
rendering stack (Pillow / FreeType / raqm / the bundled font), so golden.json
records its environment and the rule SKIPS — never fails — on another machine.

Rewrite after an intended visual change, and only after LOOKING at the render:
    python3 -m tools.check --update-golden
"""
import hashlib
import json
import os

import PIL
from PIL import features

from . import rules
from pq1 import canvas, status
import screens

PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "golden.json")
FRAME = 1000.0 / 14
SKIP = {"idle/unknown_token"}          # its default palette is random() by design


def env():
    font = os.path.join(rules.REPO, "pq1", "assets", "Aileron-Regular.otf")
    return dict(pillow=PIL.__version__, freetype=features.version("freetype2"),
                raqm=features.version("raqm"),
                font_sha=hashlib.sha256(open(font, "rb").read()).hexdigest()[:16])


def _instances():
    seen = []
    for qual, mod in sorted(screens.modules().items()):
        if qual in SKIP:
            continue
        for p in [None] + sorted(getattr(mod, "PRESETS", {})):
            sp = screens.spec(qual, preset=p) if p else screens.spec(qual)
            if (qual, sp) in seen:
                continue
            seen.append((qual, sp))
            an = status.anim_for(sp)
            if not an.interactive:
                yield (f"{qual}|{p}" if p else qual), an


def _hash(an, t):
    cv = canvas.Canvas()
    an.draw(cv, t)
    return hashlib.sha256(cv.out().tobytes()).hexdigest()[:16]


def _times(an):
    main = getattr(an, "main", an)
    ts = set(an.previews) | {an.t_resolve, an.duration - FRAME}
    acc = 0
    for k in ("T_HOLD", "T_IN", "T_WAIT", "T_TEXT"):
        if hasattr(main, k):
            acc += getattr(main, k)
            ts |= {acc - FRAME, acc + FRAME}
    return sorted(round(max(0.0, min(t, an.duration - 1)) / FRAME) * FRAME for t in ts)


def snapshot(full=False):
    out = {}
    for key, an in _instances():
        if full:
            h, t = hashlib.sha256(), 0.0
            while t < an.duration:
                h.update(_hash(an, t).encode())
                t += FRAME
            out[f"{key}|all-frames"] = h.hexdigest()[:16]
        for t in sorted(set(_times(an))):
            out[f"{key}|{round(t)}"] = _hash(an, t)
    return out


def update():
    data = dict(env=env(), frames=snapshot(), full=snapshot(full=True))
    json.dump(data, open(PATH, "w"), indent=1, sort_keys=True)
    print(f"golden.json rewritten — {len(data['frames'])} sampled frames, "
          f"{len([k for k in data['full'] if k.endswith('all-frames')])} full films")
    return 0


def compare(full=False):
    if not os.path.exists(PATH):
        return [rules.V("tools/check/golden.json", "missing", "run python3 -m tools.check --update-golden")]
    gold = json.load(open(PATH))
    if gold["env"] != env():
        print(f"  G-GOLDEN skipped: golden.json was made on {gold['env']}, this machine is {env()}")
        return []
    want = gold["full" if full else "frames"]
    got = snapshot(full)
    out = []
    for k in sorted(set(want) | set(got)):
        if want.get(k) != got.get(k):
            out.append(rules.V(f"anim:{k.rsplit('|', 1)[0]}", f"t={k.rsplit('|', 1)[1]}",
                               "the rendered frame changed — if intended, look at it, then --update-golden"))
    return out
