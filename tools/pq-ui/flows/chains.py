"""Chain browser — every network in the registry as its own chain screen.

A bench / design-review flow, not a transaction: one chain badge per row of
chains.CHAINS, in registry order, so the whole set can be tapped through on
the panel and judged as the device draws it — the mark, the disc colour, the
trail ramp and the caption all derived from the one id the screen carries
(the chain screen's whole point: one number, one identity).

The last screen is an id the registry does NOT hold, so the bench also shows
the fallback the rule asks for: the first letter of the name on a disc whose
ramp is hashed from the id, never the ether mark.

No ENDS: nothing is signed here, so there is no sign or decline ending —
flows.playable returns None for both and the bench player just navigates
(the flows/palettes and flows/pin precedent). The Confirm? sitting at screen
6 is not part of the tour: a segment of 7+ details always takes one there
(layout.insert_confirm), and a bench of chain badges is still a segment of
details — the one screen to tap past on the way to Mantle.

    python3 -m flows chains                       # -> renders/flows/chains_flow.gif
    python3 -m flows chains --fps 14 --frames /tmp/chains
    ~/nv3007/.venv/bin/python tools/panel/play_flow.py chains   # tap through on glass
"""
from pq1 import chains

# an id no registry row holds — the letter fallback, named so it has a letter
UNKNOWN = (42220, "Celo")


def _badge(cid, name=None):
    return dict(id=chains.label(cid, name) or str(cid), kind="detail",
                side="right", chain=cid, chain_name=name, label=None,
                chev="lr", hint=True)


SCREENS = [_badge(cid) for cid in chains.CHAINS] + [_badge(*UNKNOWN)]
