"""FIRMWARE UPDATE flow — screen content only (grid/type/motion come from pq1).

  UPDATE TO 1.0.3? (idle sweep) -> FIRMWARE KEY FINGERPRINT (the intro,
  the fingerprint mark) -> the 8 WORDS (the fingerprint, full width) ->
  CONFIRM UPDATE TO 1.0.3? (idle sweep, the hold) -> status (UPDATED by
  default: the major explosion on the long reconnect orbit,
  "RECONNECTING…", the white disc arrives) — the full walkthrough.

One viewing screen: below the 7-detail threshold there is no mid-flow
Confirm? and no `--early` variant (DESIGN.md § Flow shape). The update
is committed on an ask only — the opening hero or the CONFIRM hero that
closes the walkthrough — never on the words.

Screen 2 is an INTRO hero (flows.firmware.fingerprint_intro): the
fingerprint mark black on the family's white disc, "FIRMWARE KEY
FINGERPRINT" carrying the band chevron, no corner chevrons, no commit.
Screen 3 shows the fingerprint as WORDS (flows.firmware.words): a VALUE
screen — the token slides off the left edge and the eight words take the
seed-words grid of the design canvas (reference/device/pq1_seed_words.py:
two columns of four, numbered 1-4 down the left and 5-8 down the right,
each grey number right-aligned and its white word left-aligned beside it,
at the 22 px Default tier), no caption in the bottom band; the corner
chevrons stay for tap-nav. Screen 4 is the returning ask, captioned "CONFIRM UPDATE TO
1.0.3?" — the idle sweep, the hold performed here.

Every screen wears the family identity (flows.firmware.DEFAULTS): the
download mark BLACK on the WHITE disc, a black edge stroke round it,
over the default grey trail. Endings (flows.firmware.ends): "FIRMWARE
UPDATED TO 1.0.3" — the major explosion film on five orbit turns
(flows.firmware.LOAD_REVS), the busy caption "RECONNECTING…" held until
the blast launches, then the white disc with the black check arriving on
the emptied canvas; "UPDATE DECLINED" — the minor explosion, then the
red disc with the black X (the cancel circle every family shares).

The version and the words are VARIABLE content — filled per update on
device; the flow fixes the screens, their order and the grid, never a
value. Render with `python -m flows firmware/update --end all`.
"""
from flows.firmware import DEFAULTS, ends, fingerprint_intro, words

VERSION = "1.0.3"                         # the version installing — a sample
# the firmware signing key's fingerprint as words — a sample of eight
WORDS = ["close", "agent", "own", "deputy", "grape", "though", "sail", "simple"]

BODY = [
    dict(id="UPDATE", kind="hero", bottom=f"UPDATE TO {VERSION}?", chev="lr", hint=True),
    fingerprint_intro(),
    words(WORDS),
    dict(id="CONFIRM UPDATE", kind="hero", bottom=f"CONFIRM UPDATE TO {VERSION}?",
         chev="lr", hint=True),
]

ENDS = ends(VERSION)
DEFAULT_END = "updated"
# the full walkthrough: the fingerprint seen, the confirm ask, then the ending
SCREENS = BODY + [ENDS[DEFAULT_END]]
