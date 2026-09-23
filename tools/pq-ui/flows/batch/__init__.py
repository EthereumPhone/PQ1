"""BATCH flow family — several transactions signed in ONE session, the
device naming which one the signer is looking at.

Every batch flow is a run of SEGMENTS, one per transaction: the BATCH
screen, that transaction's details, the batch screen again in its ask
form, and its own ending naming its place in the batch ("SIGNED 1 OF 3").
Because a status screen closes a segment, each transaction earns the
mid-flow Confirm? on its own detail count, never the batch total
(DESIGN.md § Flow shape, layout._segments).

The BATCH screen is a hero carrying the pager "n/m" top centre — the
same 12 px / 80 % white spot a paged detail uses, here a POSITION in a
sequence of asks rather than text pages, so nothing turns (the hero
"pager" field, DESIGN.md § Typography, Paging). It wears two forms:

  announce  "BATCH SIGN TX 1 OF 3"      the caption points on with the
                                        band chevron, corner chevrons
                                        hidden, commit OFF — it is not an
                                        ask, only a marker of where the
                                        signer is (the flows/erc7730
                                        intro idiom)
  ask       "BATCH SIGN TX 1 OF 3 TX?"  the corner chevrons back for
                                        tap-nav and hold-right armed —
                                        the screen each transaction
                                        returns to after its details,
                                        where the hold fill happens

The LAST transaction has nothing to point on to, so it opens on the ask
form and never wears the chevron — the batch's final commit.

A decline anywhere ends the whole batch: every batch flow's cancel
ending is BATCH DECLINED, whichever transaction it was reached from.

A new batch flow is one module in this package: DEFAULTS =
defaults(<symbol>), a BODY of segments built from batch_hero() +
signed(), ENDS = ends(<total>), and SCREENS = BODY + [the ending].
Render with `python -m flows batch/<name> --end all`
-> renders/flows/batch/<name>/{success,cancel}/<name>_full_<end>.gif.
"""
import copy

from pq1 import components


def defaults(symbol):
    """a batch flow's DEFAULTS — the token it signs for, through the ONE
    switch point (components.token_defaults): a popular symbol wears its
    logo art, ETH/WETH the ether mark, anything else the solid
    placeholder disc + trail hashed from the symbol"""
    return components.token_defaults(symbol)


def batch_hero(tx, total, ask=False):
    """the BATCH screen — a hero carrying the pager tx/total.

    ask=False is the announce form: the caption carries the band chevron,
    the corner chevrons hide and commit stays off (it is not an ask).
    ask=True is the ask form: the caption takes the "TX?", the corner
    chevrons come back for tap-nav and hold-right is armed — where the
    transaction is signed. The last transaction wears only this form.
    """
    caption = f"BATCH SIGN TX {tx} OF {total}"
    if ask:
        return dict(id=f"BATCH {tx} ASK", kind="hero", pager=[tx, total],
                    bottom=f"{caption} TX?", chev="lr", hint=True)
    return dict(id=f"BATCH {tx}", kind="hero", pager=[tx, total],
                bottom=caption, band_chev=True, commit=False)


def signed(tx, total):
    """one transaction of the batch resolved, naming its place in it —
    the qubit film to the green check. It lives in the flow's BODY, not
    in ENDS: only the batch's LAST ending is swappable with --end."""
    return dict(id=f"SIGNED {tx}", kind="status",
                bottom=f"SIGNED {tx} OF {total}", chev=None)


def ends(total):
    """fresh copies of the batch's terminal endings: BATCH SIGNED is the
    qubit film resolving to the green check; BATCH DECLINED plays NO film
    (the cancel resolve, status.default_anim) — the token resolves in
    place, red ring stroke and red X on the unfilled black disc. One
    declined transaction declines the whole batch, so the caption names
    the batch and never the transaction it was reached from."""
    return copy.deepcopy({
        "signed": dict(id="BATCH SIGNED", kind="status",
                       bottom=f"BATCH SIGNED {total} OF {total}", chev=None),
        "declined": dict(id="BATCH DECLINED", kind="status", result="x",
                         state="failed", bottom="BATCH DECLINED", chev=None),
    })
