"""Flows — each flow is one module in this package; render with the CLI:

    python3 -m flows                      # list the flows
    python3 -m flows send                 # -> renders/flows/send_flow.gif
    python3 -m flows send --end declined  # -> renders/flows/send/cancel/send_full_declined.gif
    python3 -m flows send --end all       # one GIF per ending
    python3 -m flows send --end failed --ready 7000   # the loading film waiting: the
                                          #   orbit wraps whole turns until the work
                                          #   answers at 7 s, then collides into the X
    python3 -m flows send --fps 14 --frames DIR   # panel-rate PNGs
    python3 -m flows --manifest           # regenerate flows/MANIFEST.md

Interactive bench playback (keyboard-driven, per DESIGN.md § Input) builds
its screen list with flows.playable(name) and drives it via pq1.driver —
see tools/panel/play_flow.py for the NV3007 panel harness.

A flow module declares its screen content only — the PQ1 design system
(pq1/) supplies layout, color, type, motion and the status animations:

    SCREENS   the screen-dict list the flow plays (schema: pq1/layout.py)
    ENDS      optional {name: status screen} terminal alternates for --end
    DEFAULTS  optional fields applied to every screen (icon, token, ...)
    SAMPLES   optional example tokens for the renders: a list of kwargs
              dicts (each with a "symbol") for the module's build(**sample)
              -> dict(DEFAULTS, ENDS, SCREENS); the module's own three
              names are build(**SAMPLES[0]). The renders CYCLE the samples:
              variant slot k of the ending matrix (full endings first, then
              the early ones, endings sorted) takes SAMPLES[k % n], so the
              example set shows every popular token — production is
              untouched, every value is filled per transaction on device

A new flow is just a new file — screens plus which status animation.
Long flows get the design system's mid-flow Confirm? screen for free:
7+ detail screens -> layout.insert_confirm places a confirm-kind screen
6th (early exit; VIEW MORE points onward), dressed by the flow's DEFAULTS.
A flow *family* is a subpackage: shared identity (glyph, DEFAULTS,
endings) lives in the package __init__, each flow is a module, and the
CLI name is "family/flow" — a family may nest sub-families to any depth
("blind/typed_call/sign_with_args"):

    # flows/safe/can_not_decode.py
    from flows.safe import DEFAULTS, ends   # glyph + green + endings

    BODY = [
        dict(id="APPROVE", kind="hero", bottom="APPROVE SAFE TX?", hint=True),
        dict(id="TO", kind="detail", side="left", label="TO",
             lines=["0x78D8..."], size=22),
    ]
    ENDS = ends()
    SCREENS = BODY          # status-free: the demo wraps back to the idle
                            # hero; SCREENS + [ENDS["signed"]] pins a linear
                            # pass that ends in the status instead

    # python3 -m flows safe/can_not_decode --end all
    #   -> renders/flows/safe/can_not_decode/{success,cancel}/can_not_decode_full_<end>.gif
"""
import copy
import importlib
import pkgutil

from pq1 import layout, status


def names():
    """the registered flow names: every non-underscore module in flows/,
    plus subpackage families at any depth, named "family/flow"
    (e.g. "safe/can_not_decode", "blind/typed_call/sign_with_args")"""
    def walk(path, prefix):
        out = []
        for m in pkgutil.iter_modules(path):
            if m.name.startswith("_"):
                continue
            if m.ispkg:
                sub = importlib.import_module(
                    f"{__name__}.{(prefix + m.name).replace('/', '.')}")
                out += walk(sub.__path__, f"{prefix}{m.name}/")
            else:
                out.append(prefix + m.name)
        return out
    return sorted(walk(__path__, ""))


def get(name):
    """the flow module for a name ("family/flow" for nested flows)"""
    if name not in names():
        raise ValueError(f"unknown flow {name!r}; "
                         f"expected one of {', '.join(names()) or '(none)'}")
    return importlib.import_module(f"{__name__}.{name.replace('/', '.')}")


def samples(name):
    """a flow's example tokens — the SAMPLES list (see the module
    docstring), [] for a flow with one fixed sample"""
    return list(getattr(get(name), "SAMPLES", None) or [])


def sample_names(name):
    """the samples' symbols, in SAMPLES order"""
    return [str(s["symbol"]) for s in samples(name)]


def sample_slot(name, end=None, early=False):
    """which sample a rendered variant takes: its slot in the flow's ending
    matrix — full endings first, then the early ones, endings sorted —
    modulo the sample count; None for a flow without SAMPLES"""
    n = len(samples(name))
    if not n:
        return None
    ends = sorted(getattr(get(name), "ENDS", {}))
    k = (len(ends) if early else 0) + (ends.index(end) if end in ends else 0)
    return k % n


def _source(mod, sample):
    """the flow's (DEFAULTS, ENDS, SCREENS) for one sample: the module's
    own names, or build(**SAMPLES[sample]) — sample is an index or a symbol"""
    if sample is None:
        return (getattr(mod, "DEFAULTS", None), getattr(mod, "ENDS", {}),
                mod.SCREENS)
    smp = list(getattr(mod, "SAMPLES", None) or [])
    if not smp:
        raise ValueError(f"flow {mod.__name__.split('.', 1)[1]!r} has no SAMPLES")
    if isinstance(sample, str):
        syms = [str(s["symbol"]).upper() for s in smp]
        if sample.upper() not in syms:
            raise ValueError(f"no sample {sample!r}; expected one of "
                             f"{', '.join(str(s['symbol']) for s in smp)}")
        sample = syms.index(sample.upper())
    built = mod.build(**smp[sample % len(smp)])
    return built.get("DEFAULTS"), built.get("ENDS", {}), built["SCREENS"]


def screens(name, end=None, early=False, sample=None, ready=None):
    """A flow's normalized screen list (deep-copied — safe to mutate).

    ready (ms) answers the ending's loading film at that film time: the
    orbit wraps whole turns until then (StatusAnim "ready" — a render of
    the open-ended film; an ending with no film raises).

    sample picks one of the flow's SAMPLES (an index or a symbol) and
    rebuilds the flow from it via build(**sample); None plays the module's
    own SCREENS (its first sample).

    end picks a terminal status screen from the flow's ENDS dict: it swaps
    the flow's last status screen, or — for a flow whose linear pass is
    status-free (SCREENS without a status: the demo wraps back to the idle
    hero after the last detail) — appends the ending after the details.
    None keeps the flow's own SCREENS unchanged. early takes the mid-flow
    Confirm? exit: the confirm screen commits straight to the ending — its
    "next" is pinned to the status screen, so the demo plays confirm ->
    loading -> result (success, or the declined/failed ending via end) and
    the remaining details are never visited; on a status-free flow with no
    end given, early commits to the flow's DEFAULT_END."""
    mod = get(name)
    defaults, ends, src = _source(mod, sample)
    scr = copy.deepcopy(list(src))
    # DESIGN.md § Flow shape: 7+ detail screens -> the mid-flow Confirm?
    # is ALWAYS the 6th screen (inserted when absent, misplacement raises)
    # and CHAIN always directly follows TO or AMOUNT
    layout.insert_confirm(scr)
    if end is None and early and not any(s.get("kind") == "status" for s in scr):
        end = getattr(mod, "DEFAULT_END", None)   # the commit path needs an ending
    if end is not None:
        if end not in ends:
            raise ValueError(f"flow {name!r} has no end {end!r}; expected one "
                             f"of {', '.join(sorted(ends)) or '(none)'}")
        idx = [i for i, s in enumerate(scr) if s.get("kind") == "status"]
        if idx:                                    # linear pass carries a status
            scr[idx[-1]] = copy.deepcopy(ends[end])
        else:                                      # status-free linear pass:
            heroes = [s for s in scr if s.get("kind") == "hero"]
            if heroes:                             # back on the idle ask first,
                scr.append(copy.deepcopy(heroes[0]))
            scr.append(copy.deepcopy(ends[end]))   # then the ending plays
    if early:
        ci = [i for i, s in enumerate(scr) if s.get("kind") == "confirm"]
        if not ci:
            raise ValueError(f"flow {name!r} has no confirm screen to exit "
                             f"early from (needs 7+ detail screens)")
        si = [i for i, s in enumerate(scr) if s.get("kind") == "status"]
        if not si:
            raise ValueError(f"flow {name!r} has no status screen to commit to")
        scr[ci[0]]["next"] = si[-1]
    if ready is not None:
        si = [i for i, s in enumerate(scr) if s.get("kind") == "status"]
        if not si or not status.loops(scr[si[-1]]):
            raise ValueError(f"flow {name!r}: the ending {end or '(default)'} "
                             f"plays no loading film, nothing waits for an "
                             f"answer (ready needs the qubit film or an "
                             f"explosion lead)")
        scr[si[-1]]["ready"] = ready
    return layout.normalize_screens(scr, defaults)


def playable(name, end=None, decline=None):
    """The screen list for the interactive bench player (pq1.driver).

    The full walkthrough resolved to its sign ending (end, default the
    flow's DEFAULT_END), with a decline ending appended as the final screen
    so the driver can branch to either at runtime — hold-right signs, hold-
    left declines. decline defaults to the first ENDS entry whose state is
    not "done" (preferring "declined"); returns (screens, sign_index,
    decline_index), decline_index None when no such ending exists. A flow's
    FILM-FAILURE ending (status.film_failure — send's TRANSACTION FAILED,
    the loading colliding into the X) is appended too, so the driver can
    restyle the running film when the host answers "failed"
    (pq1.driver.FlowDriver.answer); it is never the decline. Raises for a
    flow with no ending or no navigable screens ahead of it."""
    mod = get(name)
    ends = getattr(mod, "ENDS", {})
    sign_end = getattr(mod, "DEFAULT_END", None) if end is None else end
    scr = screens(name, sign_end)
    # an ENTRY (a PIN row — status.is_interactive) is navigable, typed
    # live; its verdicts play inside it, so it is never a sign / decline
    # target: a flow of attempts alone has neither (both None)
    entry = [s.get("kind") == "status" and status.is_interactive(s) for s in scr]
    si = [i for i, s in enumerate(scr)
          if s.get("kind") == "status" and not entry[i]]
    nav = [i for i, s in enumerate(scr)
           if s.get("kind") != "status" or entry[i]]
    if not nav or (si and si[0] < nav[0]):
        raise ValueError(f"flow {name!r} is not playable: it needs navigable "
                         f"screens (a hero, a detail, an entry) ahead of a "
                         f"status ending")
    film_fail = next((n for n, e in sorted(ends.items())
                      if e.get("kind") == "status" and status.film_failure(e)),
                     None)
    if decline is None:
        fails = sorted(n for n, e in ends.items()
                       if e.get("state", "done") != "done" and n != film_fail
                       and not (e.get("kind") == "status"
                                and status.is_interactive(e)))
        decline = ("declined" if "declined" in fails
                   else fails[0] if fails else None)
    di = None
    if decline is not None:
        if decline not in ends:
            raise ValueError(f"flow {name!r} has no end {decline!r}; expected "
                             f"one of {', '.join(sorted(ends)) or '(none)'}")
        d = copy.deepcopy(ends[decline])
        layout.normalize_screens([d], getattr(mod, "DEFAULTS", None))
        di = len(scr)
        scr.append(d)
    if film_fail is not None and film_fail not in (sign_end, decline):
        f = copy.deepcopy(ends[film_fail])       # the look the host's "no" swaps in
        layout.normalize_screens([f], getattr(mod, "DEFAULTS", None))
        scr.append(f)
    return scr, (si[0] if si else None), di
