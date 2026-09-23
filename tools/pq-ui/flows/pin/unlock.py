"""UNLOCK — the device asks for its PIN; three tries, then it locks.

  try 1  miss -> WRONG PIN        (the pill shaken off)
  try 2  miss -> LAST ATTEMPT     (the counter reels 2 -> 1)
  try 3  match -> UNLOCKED        the default ending (success/)
         miss  -> LOCKED          --end locked (cancel/)

Every try is one screen — the entry, then its verdict — built by
flows.pin.attempt(); the third try is the ending, so --end swaps the
digits the demo types on it, never a screen behind it.

    python3 -m flows pin/unlock                # -> renders/flows/pin/unlock/unlock.gif
    python3 -m flows pin/unlock --end all      # -> success/unlock_full_unlocked.gif
                                               #    cancel/unlock_full_locked.gif
    .venv/bin/python tools/panel/play_flow.py pin/unlock   # type it yourself
"""
from flows.pin import PIN, attempt, last_attempt, locked, wrong_pin

BODY = [
    attempt(wrong_pin(), id="TRY 1"),
    attempt(last_attempt(2), id="TRY 2"),
]

ENDS = {
    "unlocked": attempt(locked(), typed=PIN, id="TRY 3"),
    "locked": attempt(locked(), id="TRY 3"),
}
DEFAULT_END = "unlocked"
SCREENS = BODY + [ENDS[DEFAULT_END]]
