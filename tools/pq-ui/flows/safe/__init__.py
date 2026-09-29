"""SAFE flow family — Safe{Wallet} transaction signing on the PQ1 grid.

Shared identity for every SAFE flow: the Safe logo glyph and the SAFE
brand ramp (colors.SAFE_GRADIENT) — the #13FF7F token disc with a black
stroke inside the disc edge, riding the Safe-green follower trail — plus
the shared SIGNED / DECLINED endings. The brand ramp is pinned by name
(token "palette": "SAFE"), never hashed, so it renders exactly when a
SAFE transaction is on screen. A new SAFE flow is one module
in this package importing DEFAULTS and ends() and declaring its screens;
render with `python -m flows safe/<name> --end all` (and --early
--end all for the commit paths)
-> renders/flows/safe/<name>/{success,cancel}/<name>_<full|early>_<end>.gif.
"""
import copy

from pq1 import colors, components, status

components.register_logo("safe", "safe.png")

# the Safe token: #13FF7F disc (colors.SAFE_GRADIENT fill) with a black
# edge stroke, Safe-green trail; every circle mark renders BLACK
# (icon_color — vector marks like the chain logo; safe.png keeps its art)
DEFAULTS = dict(icon="safe", icon_color=list(colors.BLACK),
                token=dict(palette="SAFE", ring=list(colors.BLACK)))


def ends():
    """fresh copies of the shared SAFE endings, both resting on a branded
    FILLED flush disc (status.branded_resting — brand families fill the
    circle, DESIGN.md § Color): SIGNED plays the qubit film and lands on
    the brand fill (#13FF7F disc, black edge stroke, black check);
    DECLINED plays NO film — the cancel resolve (status.default_anim):
    the token resolves in place onto the red — #FF423D disc, black X in
    the centre — the SIGNED construction with red swapped in"""
    return copy.deepcopy({
        "signed": dict(id="SIGNED", kind="status",
                       bottom="SIGNED SAFE TX",
                       resting=status.branded_resting(
                           colors.BRAND_PALETTES["SAFE"][0])),
        "declined": dict(id="DECLINED", kind="status",
                         result="x", state="failed",
                         bottom="SAFE TX DECLINED",
                         resting=status.branded_resting(colors.RED)),
    })
