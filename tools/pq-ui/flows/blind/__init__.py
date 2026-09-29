"""BLIND flow family — transactions the device signs WITHOUT decoding.

Shared identity for every blind-signing flow: the blind mark inside the
token — pq1/assets/blind_icon.svg traced as procedural art
(pq1/procedural/blind.py, components.GLYPHS["blind"]) — white on the
contract's placeholder disc. A blind flow signs for a contract the device
has no logo for, so its token takes the placeholder treatment (DESIGN.md
§ Color): a SOLID disc in the fill of the six-stop ramp hashed from the
contract ADDRESS (components.token_ramp, crc32, never fixed — the address
beats a symbol) and the same ramp darkening away on the trail, so one
contract always wears one colour; defaults(contract) pins it. The family
has no brand, so the endings keep the unbranded resting look — black
disc, the state colour on the ring stroke and the glyph — and the hold
fill rises as a black film over the solid disc.

A new blind flow is one module in this package: DEFAULTS =
defaults(<contract>), ENDS = ends(<subject>), then its screens; render
with `python -m flows blind/<name> --end all` (and --early --end all for
the commit paths on a 7+-detail flow)
-> renders/flows/blind/<name>/{success,cancel}/<name>_<full|early>_<end>.gif.
"""
import copy

ICON = "blind"   # components.GLYPHS["blind"] — the traced blind_icon.svg


def defaults(contract):
    """a blind flow's DEFAULTS: the blind mark on the solid placeholder
    disc + trail hashed from the contract address (never a fixed ramp)"""
    return dict(icon=ICON, token=dict(palette=contract))


def ends(subject="CALL"):
    """fresh copies of the shared endings, captioned on the ask's subject
    ("UNKNOWN CALL CONFIRMED" / "UNKNOWN CALL DECLINED"): CONFIRMED plays
    the qubit film resolving to the green check; DECLINED plays NO film —
    the cancel resolve (status.default_anim): the token resolves in place,
    red ring stroke and red X on the unfilled black disc"""
    return copy.deepcopy({
        "confirmed": dict(id="CONFIRMED", kind="status",
                          bottom=f"{subject} CONFIRMED", chev=None),
        "declined": dict(id="DECLINED", kind="status", result="x", state="failed",
                         bottom=f"{subject} DECLINED", chev=None),
    })
