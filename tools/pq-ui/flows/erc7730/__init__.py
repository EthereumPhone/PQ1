"""ERC7730 flow family — transactions the device clear-signs from an
ERC-7730 descriptor (the JSON a contract's developer publishes so a
wallet can show a call in words instead of calldata).

Every ERC-7730 flow opens on the INTRO: the dev mark — pq1/assets/
dev_icon.svg traced as procedural art (pq1/procedural/dev.py,
components.GLYPHS["dev"]) — white on a BLACK disc with the white ring,
over the gold trail (colors.ERC7730_GRADIENT, pinned by name as palette
"ERC7730" — the device's default gold, never hashed). Its caption carries
the confirm band's right-pointing chevron and the corner chevrons hide
(hero "band_chev"): a tap on either side leads on to the ask (the ask is the hub, DESIGN.md § Input). The intro is not an
ask — commit stays off; the transaction is signed on the idle hero that
follows, or on its return after the details.

From the ask on, every screen shows the call's own identity: the ether
mark white on the SOLID disc hashed from the contract ADDRESS
(components.token_ramp, crc32 — never fixed; defaults(contract) pins it)
and the same ramp darkening away on the trail, so one contract always
wears one colour. The family has no brand, so the endings keep the
unbranded resting look — black disc, the state colour on the ring stroke
and the glyph.

A new ERC-7730 flow is one module in this package: DEFAULTS =
defaults(<contract>), a BODY opening [intro(), <the ask>, <details>…],
ENDS = ends(<subject>), and SCREENS = BODY + [dict(BODY[1]), <ending>] —
the walkthrough returns to the ask, never to the intro. Render with
`python -m flows erc7730/<name> --end all`
-> renders/flows/erc7730/<name>/{success,cancel}/<name>_full_<end>.gif.
"""
import copy

INTRO_CAPTION = "ERC-7730 CLEAR SIGNING"


def defaults(contract):
    """an ERC-7730 flow's DEFAULTS: the ether mark on the solid placeholder
    disc + trail hashed from the contract address (never a fixed ramp)"""
    return dict(icon="eth", token=dict(palette=contract))


def intro(caption=INTRO_CAPTION):
    """the intro screen: the dev mark on the black disc over the gold
    trail, the caption pointing on with the band chevron, no corner
    chevrons, no commit — it is not an ask"""
    return dict(id="ERC7730", kind="hero", icon="dev", token=dict(palette="ERC7730"),
                bottom=caption, band_chev=True, commit=False)


def ends(subject="TRANSACTION"):
    """fresh copies of the shared endings, captioned on the ask's subject
    ("SWAP SIGNED" / "SWAP DECLINED"): SIGNED plays the qubit film
    resolving to the green check; DECLINED plays NO film — the cancel
    resolve (status.default_anim): the token resolves in place, red ring
    stroke and red X on the unfilled black disc"""
    return copy.deepcopy({
        "signed": dict(id="SIGNED", kind="status", bottom=f"{subject} SIGNED", chev=None),
        "declined": dict(id="DECLINED", kind="status", result="x", state="failed",
                         bottom=f"{subject} DECLINED", chev=None),
    })
