"""COWSWAP flow family — CoW Swap order signing on the PQ1 grid.

Shared identity for every CoW Swap flow: the cow-head logo glyph and the
COWSWAP brand ramp (colors.COWSWAP_GRADIENT) — the #65D9FF token disc
wearing the official cow-head art with a #012F7A (colors.COWSWAP_DARK)
stroke flush at the disc edge, riding the CoW-blue follower trail — plus
the shared SIGNED / DECLINED endings. The brand ramp is pinned by name
(token "palette": "COWSWAP"), never hashed, so it renders exactly when a
CoW Swap order is on screen. The logo (pq1/assets/cowswap.png) and the
ramp hexes are the brand's own — swap.cow.fi's touch icon and the
cowswap repo's blue primary palette — not invented. A new CoW Swap flow
is one module in this package importing DEFAULTS and ends() and
declaring its screens; render with `python -m flows cowswap/<name>
--end all` (and --early --end all for the commit paths)
-> renders/flows/cowswap/<name>/{success,cancel}/<name>_<full|early>_<end>.gif.
"""
import copy

from pq1 import colors, components, status

components.register_logo("cowswap", "cowswap.png")

# the CoW Swap token: #65D9FF disc (colors.COWSWAP_GRADIENT fill) under the
# cow-head art, a navy edge stroke, CoW-blue trail; every circle mark
# renders NAVY (icon_color — vector marks like the chain logo; cowswap.png
# keeps its art)
DEFAULTS = dict(icon="cowswap", icon_color=list(colors.COWSWAP_DARK),
                token=dict(palette="COWSWAP", ring=list(colors.COWSWAP_DARK)))


def ends():
    """fresh copies of the shared COWSWAP endings, both resting on a
    branded FILLED flush disc (status.branded_resting — brand families
    fill the circle, DESIGN.md § Color) with the family's navy mark:
    SIGNED plays the qubit film and lands on the brand fill (#65D9FF
    disc, black edge stroke, navy check — the cow-head logo's own two
    colours under the system's black stroke); DECLINED plays NO film —
    the cancel resolve
    (status.default_anim): the token resolves in place onto the ONE
    cancel circle every family shares — #FF423D disc, black edge
    stroke, black X — the SAFE cancel look; the navy mark colours
    SIGNED only"""
    return copy.deepcopy({
        "signed": dict(id="SIGNED", kind="status",
                       bottom="COWSWAP SIGNED",
                       resting=status.branded_resting(
                           colors.BRAND_PALETTES["COWSWAP"][0],
                           colors.COWSWAP_DARK)),
        "declined": dict(id="DECLINED", kind="status",
                         result="x", state="failed",
                         bottom="COWSWAP DECLINED",
                         resting=status.branded_resting(colors.RED)),
    })
