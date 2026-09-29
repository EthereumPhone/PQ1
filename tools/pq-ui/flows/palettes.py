"""Palette browser — every placeholder ramp as its own idle screen.

A bench / design-review flow, not a transaction: one idle hero per entry in
colors.PLACEHOLDER_GRADIENTS, so the whole palette set can be tapped through
on the panel and judged as the device draws it — the solid token disc in the
ramp's fill under the system's white ring, its five followers trailing in the
ramp's darkening stops, on the idle sweep.

Each caption names the ramp and the colour the DISC actually wears
(colors.ramp_palette(i)[0] — ramp 13 fills BLACK, the recognized-logo look,
not its #F4F4F4 top stop), and marks the seven darkened to the >= 4.5:1
floor against white (commit 8a7a473, Sep 2026).

No ENDS: nothing is signed here, so there is no sign or decline ending —
flows.playable returns None for both and the bench player just navigates
(the flows/pin precedent).

    python3 -m flows palettes                     # -> renders/flows/palettes_flow.gif
    python3 -m flows palettes --fps 14 --frames /tmp/pal
    ~/nv3007/.venv/bin/python tools/panel/play_flow.py palettes   # tap through on glass
"""
from pq1 import colors

# the seven darkened so stop 6 clears 4.5:1 against the white ring + mark
DARKENED = {0, 2, 5, 7, 8, 9, 12}

DEFAULTS = dict(icon="eth")


def _hex(rgb):
    return "#%02X%02X%02X" % tuple(rgb)


def _idle(i):
    """one palette as an idle screen: the disc in the ramp's fill, its trail
    behind, the caption naming the ramp and that fill"""
    fill = colors.ramp_palette(i)[0]
    tag = " NEW" if i in DARKENED else ""
    return dict(id=f"RAMP{i}", kind="hero",
                bottom=f"RAMP {i} {_hex(fill)}{tag}",
                token=dict(palette=i), chev="lr", hint=True)


SCREENS = [_idle(i) for i in range(len(colors.PLACEHOLDER_GRADIENTS))]
