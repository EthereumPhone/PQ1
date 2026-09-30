"""SETUP flow family — the device's first run: the PIN chosen, the duress
PIN chosen, the seed written down and checked (audit HS-09).

Built from the library, nothing drawn by hand:

- the PIN steps are the PIN entry (screens/pin/pin_entering.py) CHOOSING
  a PIN instead of checking one: set_pin() accepts whatever is entered
  (accept="any"), repeat_pin() checks it against the first (a miss is
  PIN MISMATCH and goes back to SET PIN), set_duress() takes anything BUT
  the PIN (forbid=<pin>; a miss is DURESS PIN MUST DIFFER, retried in
  place), repeat_duress() checks it (PIN MISMATCH, back to SET DURESS PIN);
- the seed is the words grid (flows/firmware.words), 24 words paged 8 a
  page under the n/m pager, after an intro whose caption carries the band
  chevron (backup_intro) and before the ask that commits to the check
  (written_ask);
- each check is the check-word entry (screens/pin/check_word.py): the
  right word among eight decoys, both buttons to choose; a wrong choice
  is WRONG SEED PHRASE (screens/verdict/headshake), then the same check
  again (on_miss: its own id);
- the last check's match lands SETUP COMPLETE — the firmware family's
  white disc arriving with the black check (setup_complete).

Every entry ROUTES itself on the bench (pq1.driver, _after_entry):
on_match="next" continues to the following entry, on_miss=<id> returns
to what it repeats. The demo render plays the happy path in list order.

Identity: the firmware family's device-action look (flows.firmware
DEFAULTS — the white disc under a black edge stroke over the mono trail)
wearing the 3 x 3 DOTS mark: a new wallet. The PINs and the words are VARIABLE
— the user's, never fixed into a flow; the module's are samples.
"""
import copy

import screens
from flows.firmware import DEFAULTS as _FIRMWARE, words as _words
from pq1 import colors, status

DEFAULTS = dict(copy.deepcopy(_FIRMWARE), icon="dots")

PIN = "00000000"        # the demo's PIN — a sample
DURESS = "00000011"     # the demo's duress PIN — differs from PIN


def _entry(sid, busy, pin, typed, **over):
    """one PIN step: the entry typed and submitted, routing on the bench"""
    d = screens.spec("pin_entering", id=sid, busy=busy, pin=pin, typed=typed,
                     exit="submit", miss=None, match=None, state="done")
    d.pop("token")      # the family's white disc crossfades out under the row,
    d.update(over)      # not screens.spec's solid black (the black mark on it)
    return d


def set_pin(pin=PIN):
    return _entry("SET PIN", "SET PIN", pin, pin, accept="any", on_match="next")


def repeat_pin(pin=PIN):
    return _entry("REPEAT PIN", "REPEAT PIN", pin, pin, on_match="next",
                  miss=screens.spec("pin_mismatch"), on_miss="SET PIN")


def set_duress(duress=DURESS, pin=PIN):
    return _entry("SET DURESS PIN", "SET DURESS PIN", duress, duress, forbid=pin,
                  on_match="next", miss=screens.spec("duress_differ"),
                  on_miss="SET DURESS PIN")


def repeat_duress(duress=DURESS):
    """the last PIN step: a match continues to the backup (the first
    screen after the entries — the driver's default route)"""
    return _entry("REPEAT DURESS PIN", "REPEAT DURESS PIN", duress, duress,
                  miss=screens.spec("pin_mismatch"), on_miss="SET DURESS PIN")


def backup_intro(count):
    """the backup intro: its caption points on with the band chevron, no
    corner chevrons, no commit — it announces the words that follow"""
    return dict(id="BACKUP", kind="hero", bottom=f"WRITE DOWN {count} WORDS",
                band_chev=True, commit=False)


def words(values):
    """the seed on the words grid — paged 8 a page past 8 words"""
    return _words(values)


def written_ask():
    """the ask that commits to the check (the hold)"""
    return dict(id="WRITTEN", kind="hero", bottom="WORDS WRITTEN DOWN?",
                chev="lr", hint=True)


def setup_complete():
    """the last match's verdict: the white disc arrives with the black
    check (the firmware UPDATED look)"""
    return dict(kind="status", anim="arrive", state="done", result="check",
                resting=status.branded_resting(colors.WHITE),
                bottom="SETUP COMPLETE")


def check(n, seed, typed=None, match=None, **over):
    """one check: word n of the seed among eight decoys; typed is the
    candidate index the demo chooses (None: the right word). A miss is
    WRONG SEED PHRASE, then the same check again"""
    d = screens.spec("check_word", id=f"CHECK {n}", n=n, words=list(seed),
                     typed=typed, exit="submit",
                     miss=screens.spec("headshake", preset="wrong_seed_phrase"),
                     match=copy.deepcopy(match), on_match="next",
                     on_miss=f"CHECK {n}", state="done")
    d.pop("token")      # the family's white disc under the handoff (as _entry)
    d.update(over)
    return d
