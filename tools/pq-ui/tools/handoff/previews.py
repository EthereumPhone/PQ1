"""Preview recorders — every GIF is RE-RENDERED from the live code at the
panel's 14 fps (never copied from renders/), so a preview cannot show
behaviour the code no longer has.

Three recorders, one per kind of catalog entry:
  anim    a library / status animation over [0, duration)
  flow    a window of a real flow's screens, walked by the demo Sim (KIOSK)
  driver  a scripted two-button session on the input driver (NAV), with a
          BENCH STRIP under the panel showing which button is down — the
          strip is a reading aid, it is not part of the 428 x 142 panel
"""
import copy
import os

from PIL import Image, ImageDraw, ImageFont

from . import introspect as I
from pq1 import canvas, colors, flow, layout, motion, status
import flows
import screens

FPS = I.PANEL_FPS
STEP = I.FRAME_MS
GIF_DELAY = 70            # GIF delays are centiseconds: 1000/14 = 71.4 -> 70 ms
STRIP_H = 22
_FONT = os.path.join(I.REPO, "pq1", "assets", "Aileron-Regular.otf")
L, R = motion.LEFT, motion.RIGHT


def save_gif(frames, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    pal = [f.convert("RGB").quantize(colors=128, method=Image.MEDIANCUT, dither=Image.NONE)
           for f in frames]
    pal[0].save(path, save_all=True, append_images=pal[1:], duration=GIF_DELAY, loop=0,
                optimize=True, disposal=1)
    return os.path.getsize(path)


def save_png(frame, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    frame.convert("RGB").save(path, optimize=True)


# ------------------------------------------------------------------- anim --
def anim_frames(spec, t_end=None):
    """frames of one status animation, and the ms of its resting still"""
    sp = copy.deepcopy(spec)
    if sp.get("anim") == "unknown_token" or (sp.get("token") or {}).get("variant") == "unknown":
        sp.setdefault("token", {})
        sp["token"].setdefault("palette", 3)      # the repo's one random() — pinned
    an = status.anim_for(sp)
    end = an.duration if t_end is None else t_end
    out, t = [], 0.0
    while t < end:
        cv = canvas.Canvas()
        an.draw(cv, t)
        out.append(cv.out())
        t += STEP
    still_at = min(an.t_resolve + 600, end - STEP) if an.t_resolve else end / 2
    return out, out[min(len(out) - 1, int(still_at / STEP))]


# ------------------------------------------------------------------- flow --
def flow_window(flow_name, pick, end=None, dwell=None, loops=1):
    """a mini-flow cut from a real one: pick(i, screen, all) -> bool keeps a screen.
    dwell = {kind: ms} shortens the demo dwell (a demo-only field) to keep clips small."""
    scr = flows.screens(flow_name, end=end)
    keep = [copy.deepcopy(s) for i, s in enumerate(scr) if pick(i, s, scr)]
    if not keep:
        raise ValueError(f"preview: nothing picked from {flow_name}")
    for s in keep:
        s.pop("next", None)
        if dwell and s["kind"] in dwell:
            s["dwell"] = dwell[s["kind"]]
    frames = flow.render_flow(keep, fps=FPS, loops=loops, guard_s=60)
    rest = next((i for i, s in enumerate(keep)), 0)
    return frames, frames[min(len(frames) - 1, int(1500 / STEP))]


# ----------------------------------------------------------------- driver --
def _strip(panel, down, caption):
    im = Image.new("RGB", (panel.width, panel.height + STRIP_H), (0, 0, 0))
    im.paste(panel.convert("RGB"), (0, 0))
    d = ImageDraw.Draw(im)
    y0 = panel.height
    d.rectangle([0, y0, im.width, im.height], fill=(18, 18, 20))
    font = ImageFont.truetype(_FONT, 11)
    for side, x in ((L, 6), (R, im.width - 38)):
        on = down.get(side)
        d.rounded_rectangle([x, y0 + 4, x + 32, y0 + STRIP_H - 4], 3,
                            fill=(235, 235, 235) if on else None, outline=(120, 120, 125))
        d.text((x + 16, y0 + STRIP_H / 2), "L" if side == L else "R", font=font, anchor="mm",
               fill=(0, 0, 0) if on else (150, 150, 155))
    d.text((im.width / 2, y0 + STRIP_H / 2), caption[:64], font=font, anchor="mm", fill=(170, 170, 175))
    return im


def driver_frames(flow_name, script, end=None):
    """script: ("tap", side[, held_ms]) ("hold", side[, ms]) ("chord",) ("double", side)
    ("wait", ms) ("goto", predicate) — returns frames with the bench strip"""
    b = I.Bench(flow_name, end)
    frames, down, cap = [], {L: False, R: False}, [""]

    def run(ms):
        t_end = b.now + ms
        while b.now < t_end:
            frames.append(_strip(b.d.frame(b.now), down, cap[0]))
            b.now += STEP

    def settle(cap_ms=2500):
        t0 = b.now
        while b.now - t0 < cap_ms:
            run(STEP)
            if b.d.sim.settled and b.now - t0 > 3 * STEP:
                break
        run(450)

    b.now = 0.0
    b.d = type(b.d)(b.d.screens, b.d.sign, b.d.decline)     # a fresh driver on a fresh clock
    run(700)
    for st in script:
        op = st[0]
        if op == "wait":
            run(st[1])
        elif op == "skip":                     # walk forward off-camera is not possible; tap quickly
            for _ in range(st[1]):
                b.d.press(R, b.now); run(STEP); b.d.release(R, b.now); settle(1200)
        elif op == "fast":                     # a tap that does NOT wait for the transit to settle
            side = st[1]
            down[side] = True; cap[0] = f"tap {side} (mid-transit)"
            b.d.press(side, b.now); run(STEP)
            down[side] = False
            r = b.d.release(side, b.now); cap[0] = f"tap {side} (mid-transit)  ->  {r}"
            run(st[2] if len(st) > 2 else 215)
        elif op == "tap":
            side, held = st[1], (st[2] if len(st) > 2 else 110)
            down[side] = True; cap[0] = f"tap {side}"
            b.d.press(side, b.now); run(held)
            down[side] = False
            r = b.d.release(side, b.now); cap[0] = f"tap {side}  ->  {r}"
            settle()
        elif op == "hold":
            side, ms = st[1], (st[2] if len(st) > 2 else motion.HOLD_COMMIT_MS + 2 * STEP)
            cur = b.d.sim.cur
            down[side] = True; cap[0] = f"hold {side} …"
            b.d.press(side, b.now); run(ms)
            down[side] = False
            r = b.d.release(side, b.now)
            fired = b.d.sim.cur != cur or b.d.state != "navigating"
            cap[0] = f"hold {side} {round(ms)} ms  ->  {'commit' if fired else r}"
            settle(3500 if fired else 1200)
        elif op == "chord":
            down[L] = True; cap[0] = "both buttons"
            b.d.press(L, b.now); run(45)
            down[R] = True
            r = b.d.press(R, b.now); run(90)
            down[L] = down[R] = False
            b.d.release(L, b.now); b.d.release(R, b.now); cap[0] = f"both buttons  ->  {r}"
            run(650)
        elif op == "double":
            side = st[1]
            down[side] = True; cap[0] = f"double press {side}"
            b.d.press(side, b.now); run(STEP); down[side] = False; b.d.release(side, b.now); run(STEP)
            down[side] = True
            r = b.d.press(side, b.now); run(STEP); down[side] = False; b.d.release(side, b.now)
            cap[0] = f"double press {side}  ->  {r}"
            run(800)
        elif op == "answer":                   # the host's word on a waiting film
            r = b.d.answer(b.now, st[1])
            cap[0] = f"the host answers {'yes' if st[1] else 'no'}  ->  {r}"
            run(400)
        else:
            raise ValueError(f"preview script: unknown op {op!r}")
    run(500)
    return frames, frames[len(frames) // 2]


def _value_paged():
    """no live flow pages a full-width value today (both fingerprint digests fit one
    screen) — so: the fingerprint family's own digest() given a 64-byte value"""
    from flows import fingerprint as fp
    scr = [dict(id="DIGEST", kind="hero", bottom="CONFIRM DIGEST?"),
           dict(id="VALUE", kind="value", **fp.digest("0x" + "9f3ac41d" * 16))]
    scr = layout.normalize_screens(scr, fp.DEFAULTS)
    frames = flow.render_flow(scr, fps=FPS, loops=1, guard_s=60)
    return frames, frames[min(len(frames) - 1, int(7000 / STEP))]


SYNTHETIC = {"value-paged": _value_paged}


def record(recipe):
    """recipe -> (frames, still)"""
    kind = recipe[0]
    if kind == "anim":
        key = recipe[1]
        qual, _, preset = key.partition("|")
        if qual.startswith("core/"):
            sp = layout.normalize_screens([copy.deepcopy(I.CORE_SPECS[qual[5:]])])[0]
        else:
            sp = screens.spec(qual, preset=preset) if preset else screens.spec(qual)
        if len(recipe) > 2:
            sp.update(recipe[2])
        return anim_frames(sp)
    if kind == "spec":
        return anim_frames(layout.normalize_screens([copy.deepcopy(recipe[1])])[0])
    if kind == "end":                          # a flow's own ending, normalized with its DEFAULTS
        mod = flows.get(recipe[1])
        sp = layout.normalize_screens([copy.deepcopy(mod.ENDS[recipe[2]])], getattr(mod, "DEFAULTS", None))[0]
        return anim_frames(sp)
    if kind == "window":                       # the matching screen(s) with neighbours (build.py resolves it)
        flow_name, idxs = recipe[1], set(recipe[2])
        return flow_window(flow_name, lambda i, s, a: i in idxs,
                           dwell=dict(hero=3600, detail=2400, value=2600, confirm=5600))
    if kind == "synthetic":                    # a screen type no live flow uses yet, built from the
        return SYNTHETIC[recipe[1]]()          # family's own helpers — labelled as such on the page
    if kind == "flow":
        return flow_window(*recipe[1:3], **(recipe[3] if len(recipe) > 3 else {}))
    if kind == "driver":
        return driver_frames(recipe[1], recipe[2], *(recipe[3:4]))
    raise ValueError(f"unknown preview recipe {kind!r}")
