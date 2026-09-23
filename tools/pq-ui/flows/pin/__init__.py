"""PIN flow family — the eight-ring entry typed with the two buttons, and
what the device answers.

One TRY is ONE screen (screens/pin/pin_entering.py): the entry, then the
verdict its digits earned, playing in the same screen after the row fades
out — never the entry and its verdict as two status screens. attempt()
builds it: `miss` is the verdict a wrong PIN gets on that try, `match` the
verdict a right one gets (UNLOCKED unless told otherwise). The ladder is
the flow's screen list — one attempt per try, the device's answers in
order:

    attempt(wrong_pin())        miss 1: the pill is shaken off — WRONG PIN
    attempt(last_attempt(2))    miss 2: the counter reels 2 -> 1 — LAST ATTEMPT
    attempt(locked(), ...)      miss 3: the padlock locks — LOCKED (terminal)

Rendering (python3 -m flows pin/unlock --end all) dials the demo digits:
`typed` is what the demo enters on that try — WRONG (a miss) or PIN (a
match) — so the two endings are the same third try with different digits
typed; the attempt's `state` follows (done / failed) and sorts the GIF
into success/ or cancel/. PIN and WRONG are SAMPLES: the device's PIN is
the user's, never a number fixed into a flow.

On the bench (.venv/bin/python tools/panel/play_flow.py pin/unlock) the
digits are typed live: tap +/-, both buttons ENTER the digit, double
press NEXT / BACK over entered digits, the 8th digit's ENTER checks
the PIN at once (no hold), hold left to cancel (DESIGN.md § Input); the driver plays the
verdict the typed digits earn, moves on to the next attempt after a miss,
and rests on UNLOCKED / LOCKED.

A PIN gate inside another flow is the same attempt() ahead of the ending:
`... , hero, attempt(wrong_pin(), match=None), ENDS[...]` — a match
continues to the next screen (the signing film opens on the token the
transit fades in), a miss retries on the next attempt in the list.
"""
import copy

import screens   # registers the library's anims into pq1.status.ANIMS

PIN = "00000000"        # the demo's PIN — a sample, the device's is the user's
WRONG = "00000001"      # the demo's miss: the last digit off


def wrong_pin():
    """miss 1 — the pill fills, turns red and is shaken off: WRONG PIN"""
    return screens.spec("pin_mismatch", preset="wrong_pin", id="WRONG PIN")


def last_attempt(left=2):
    """miss 2 — the attempt counter reels left -> 1 beside the heart"""
    return screens.spec("last_attempt", attempts=left, id="LAST ATTEMPT")


def locked():
    """the last miss — the padlock locks (terminal)"""
    return screens.spec("padlock", preset="lock", id="LOCKED")


def unlocked():
    """a match — the padlock springs open"""
    return screens.spec("padlock", preset="unlock", id="UNLOCKED")


def attempt(miss, typed=WRONG, match="unlocked", pin=PIN, **over):
    """one try = ONE screen: the entry, then the verdict its digits earn.
    miss / match are verdict screen dicts (screens.spec); match="unlocked"
    is the padlock opening, None lets a match fall through to the next
    screen (a PIN gate before a signing film). typed is what the demo
    dials on this try; the attempt's state follows it, so --end sorts the
    GIF into success/ (a match) or cancel/ (a miss)."""
    if match == "unlocked":
        match = unlocked()
    d = screens.spec("pin_entering", pin=pin, typed=typed, exit="submit",
                     miss=copy.deepcopy(miss), match=copy.deepcopy(match),
                     state="done" if typed == pin else "failed")
    d.update(over)
    return d
