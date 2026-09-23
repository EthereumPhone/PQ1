"""FIRMWARE flow family — the device acting on its own firmware (an update
to a new version), on the PQ1 grid.

Shared identity for every firmware flow: a firmware action, not a token
— the DOWNLOAD mark (pq1/assets/download_icon.svg traced as procedural
art, pq1/procedural/download.py, components.GLYPHS["download"]: the
arrow into the tray, the image coming onto the device) BLACK on a WHITE
disc under a BLACK edge stroke, over the default grey trail — the
inverted mono look the fingerprint family set, pinned under its own name
(colors.FIRMWARE_GRADIENT, palette "FIRMWARE" — never hashed).

The firmware KEY FINGERPRINT — the vendor signing key the image is
checked against — is shown as WORDS: fingerprint_intro() is a hero
captioned "FIRMWARE KEY FINGERPRINT" that wears the fingerprint mark
(components.GLYPHS["fingerprint"], the fingerprint family's) on the same
white disc, its caption carrying the band chevron and the corner
chevrons hidden ("band_chev" — an intro, not an ask, so commit is off);
words(...) is the VALUE screen after it — the words on the seed-words
grid of the design canvas (reference/device/pq1_seed_words.py: two
columns of four, numbered 1-4 down the left and 5-8 down the right, the
grey number right-aligned at x 88 / 272 and the white word left-aligned
at x 98 / 282, rows at y 32 / 58 / 84 / 110 — words and numbers at the
22 px Default tier, a step up from the design's 16), no token on the panel
(the circle slides off the left edge and back), no caption.

The endings are the device rebooting into the new image: ends(version)
gives UPDATED — the MAJOR explosion film (screens/fx/explosion, the
flow's token handing its mark off into the split) on a LONGER orbit
(revs=LOAD_REVS: a reboot outlasts a signature) with the busy caption
"RECONNECTING…" held past the orbit through the spiral and the trembling
clump, gone as the blast launches (busy_until="boom"); then, on the
emptied canvas, the resting look ARRIVING (status "arrive": the verdict
entrance law) — the disc FILLED WHITE under the black flush ring with
the black check (status.branded_resting: the FIRMWARE VERIFIED look, the
family's own white disc resolved — user request, Sep 2026),
captioned "FIRMWARE UPDATED TO <version>";
and DECLINED — the MINOR explosion (the contained two-ring pop), then the
one cancel circle every family shares: the red disc, black ring, black X,
"UPDATE DECLINED". Both are one status screen each (the film is the
ending's "lead", status.LedAnim), so a flow's --end swaps them whole.

A new firmware flow is one module in this package: DEFAULTS, ENDS =
ends(<version>), then its screens; render with
`python -m flows firmware/<name> --end all`
-> renders/flows/firmware/<name>/{success,cancel}/<name>_full_<end>.gif.
"""
import copy

import screens  # noqa: F401  registers the explosion film into pq1.status.ANIMS
from pq1 import colors, loading, status

ICON = "download"       # the traced download mark
PALETTE = "FIRMWARE"    # the white disc over the mono trail (colors)
BUSY = "RECONNECTING…"  # the loading caption while the device reboots
LOAD_REVS = loading.REVS_LONG   # the reconnect orbit: two turns more than the sources' 3 — the MINIMUM; the loop adds turns while the reboot is outstanding

DEFAULTS = dict(icon=ICON, icon_color=list(colors.BLACK),   # black mark …
                token=dict(palette=PALETTE,                 # … on the white disc …
                           ring=list(colors.BLACK)))        # … under a black edge stroke

FINGERPRINT_CAPTION = "FIRMWARE KEY FINGERPRINT"


def fingerprint_intro(caption=FINGERPRINT_CAPTION):
    """the key-fingerprint intro: the fingerprint mark on the family's white
    disc, the caption pointing on with the band chevron, no corner
    chevrons, no commit — it announces the words that follow"""
    return dict(id="KEY FINGERPRINT", kind="hero", icon="fingerprint",
                bottom=caption, band_chev=True, commit=False)


def words(values, label=None):
    """the fingerprint's words on the numbered seed-words grid — a value
    screen: the words alone, the token off the panel, the corner chevrons
    for tap-nav; an optional caps `label` sits centred on the bottom
    baseline (the update flow shows none)"""
    return dict(id="WORDS", kind="value", words=list(values), label=label, chev="lr")


def _lead(severity, busy=None, **film):
    """the explosion film as an ending's lead, wearing the family identity
    so the token's mark and edge stroke hand off into the split; `film`
    passes the explosion's own knobs (revs, busy_until)"""
    d = dict(DEFAULTS, anim="explosion", severity=severity, **film)
    if busy:
        d["busy"] = busy
    return copy.deepcopy(d)


def ends(version):
    """fresh copies of the shared endings for the version installing:
    UPDATED — the major explosion on the long reconnect orbit
    ("RECONNECTING…" until the blast), then the white disc + black check
    arrives, "FIRMWARE UPDATED TO <version>"; DECLINED — the minor
    explosion, then the red disc + black X, "UPDATE DECLINED" """
    return copy.deepcopy({
        "updated": dict(id="UPDATED", kind="status", anim="arrive",
                        lead=_lead("major", BUSY, revs=LOAD_REVS, busy_until="boom"),
                        resting=status.branded_resting(colors.WHITE),
                        bottom=f"FIRMWARE UPDATED TO {version}", chev=None),
        "declined": dict(id="DECLINED", kind="status", anim="arrive",
                         result="x", state="failed", lead=_lead("minor"),
                         resting=status.branded_resting(colors.RED),
                         bottom="UPDATE DECLINED", chev=None),
    })
