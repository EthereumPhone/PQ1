"""PQ1 screen library — reusable screens and animations, one module per
screen, grouped by category:

    verdict/  icon verdicts: an icon pops in, the caption names the fact
              (LOCKED, BACKUP OK, WALLET WIPED, RNG FAILED, ...)
    fx/       full-canvas effect films (explosion)
    pin/      PIN entry and PIN errors
    idle/     steady-state ambient screens (batch signing)
    confirm/  hold-to-confirm interactions

Importing this package registers every screen's animation into
pq1.status.ANIMS, so a flow splices any of them as a status-kind screen:

    import screens
    SCREENS = [
        screens.spec("pin_entering", pin="24031958"),
        screens.spec("batch_sign", tx=1, total=5),
        screens.spec("padlock", preset="unlock"),   # green, "UNLOCKED"
    ]

Module protocol (what discovery reads): ANIM (registered anim name ==
module name), SPEC (bare-render spec defaults), PRESETS (old per-variant
names -> spec overrides), add_args(ap) / spec_from_args(args) for CLI
flags, and optionally build(args) to fully own the render (stateful
screens). Adding a screen = one file in a category folder.
"""
import copy
import importlib
import pkgutil

CATEGORIES = ("verdict", "fx", "pin", "idle", "confirm")

_MODULES = None


def modules():
    """{'verdict/padlock': module, ...} — imports register the anims"""
    global _MODULES
    if _MODULES is None:
        _MODULES = {}
        for cat in CATEGORIES:
            pkg = importlib.import_module(f"{__name__}.{cat}")
            for m in pkgutil.iter_modules(pkg.__path__):
                if m.name.startswith("_"):
                    continue
                _MODULES[f"{cat}/{m.name}"] = importlib.import_module(
                    f"{__name__}.{cat}.{m.name}")
    return _MODULES


def _index():
    """name -> ('module'|'preset', qualified, module, overrides)"""
    idx = {}

    def put(key, entry):
        if key in idx:
            raise ValueError(f"ambiguous screen name {key!r} "
                             f"({idx[key][1]} vs {entry[1]})")
        idx[key] = entry

    for qual, mod in modules().items():
        put(qual, ("module", qual, mod, {}))
        put(qual.split("/", 1)[1], ("module", qual, mod, {}))
        for pname, over in getattr(mod, "PRESETS", {}).items():
            if pname != qual.split("/", 1)[1]:
                put(pname, ("preset", qual, mod, over))
    return idx


def names():
    """every addressable name (modules, category-qualified, presets)"""
    return sorted(_index())


def get(name):
    """resolve any addressable name -> (module, preset spec overrides)"""
    idx = _index()
    if name in idx:
        _, _, mod, over = idx[name]
        return mod, copy.deepcopy(over)
    raise ValueError(f"unknown screen {name!r}; expected one of "
                     f"{', '.join(names())}")


def spec(name, **over):
    """A flow-ready screen dict for a library screen.

    kind/anim are filled in, handoff=True crossfades from the flow's token,
    token is pinned solid (the unknown gradient never leaks into a spliced
    screen) and result is explicit so normalize_screens can't default it.
    preset="x" applies the module's named preset; other keywords override
    spec fields directly."""
    mod, pover = get(name)
    d = dict(kind="status", anim=mod.ANIM, handoff=True,
             token={"variant": "solid"})
    d.update(copy.deepcopy(getattr(mod, "SPEC", {})))
    d.update(pover)
    preset = over.pop("preset", None)
    if preset is not None:
        presets = getattr(mod, "PRESETS", {})
        if preset not in presets:
            raise ValueError(f"screen {name!r} has no preset {preset!r}; "
                             f"expected one of {', '.join(sorted(presets))}")
        d.update(copy.deepcopy(presets[preset]))
    d.update(over)
    d.setdefault("result", None)
    return d


def catalog():
    """{'verdict/padlock': {...}} rows for the CLI listing"""
    rows = {}
    for qual, mod in sorted(modules().items()):
        doc = (mod.__doc__ or "").strip().splitlines()
        rows[qual] = dict(anim=mod.ANIM,
                          presets=sorted(getattr(mod, "PRESETS", {})),
                          doc=doc[0] if doc else "")
    return rows


# importing the package IS the registration (the docstring's promise): a
# flow that names a library anim by hand — an ending led by the explosion
# (flows/firmware) — needs it in pq1.status.ANIMS without calling spec()
modules()
