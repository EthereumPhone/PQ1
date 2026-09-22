"""SAFE sign flow, undecodable call data — screen content only.

  APPROVE SAFE TX? (idle sweep) -> SAFE ACCT -> BLIND SIGN (pulse rings)
  -> TO -> CHAIN -> Confirm? (auto-inserted 6th — this flow has 7 detail
  screens, DESIGN.md § Flow shape: hold-right commits from there, the
  band alternates OR VIEW MORE / TO GO BACK) -> TX INFO -> CALL DATA
  -> TX HASH -> back on the idle hero (every detail seen) -> loading ->
  SIGNED (success) — the full walkthrough. `--end declined` swaps the
  cancellation ending; `--early [--end …]` renders the commit path:
  Confirm? jumps straight to the ending, the rest never visited. Ending
  renders land in success/ and cancel/ folders (see flows/__main__).

BLIND SIGN pulses Safe-green rings around the token (components.pulse):
the device cannot decode the call data, so the signature is flagged and
the user is asked to verify on the dapp. Content ported from
archive/legacy/safe_flow/safe_common.py onto the PQ1 grid.
Render with `python -m flows safe/can_not_decode --end all`.
"""
from flows.safe import DEFAULTS, ends  # noqa: F401  (DEFAULTS read by flows.screens)

BODY = [
    dict(id="APPROVE", kind="hero", bottom="APPROVE SAFE TX?", hint=True),
    dict(id="SAFE ACCT", kind="detail", side="left", label="SAFE ACCT",
         lines=["0x1111111111222222222", "3333333333444444444aa"], size=22),
    dict(id="BLIND SIGN", kind="detail", side="right", label="BLIND SIGN",
         lines=["Can not decode data", "Confirm on dapp"], size=22, pulse=True),
    dict(id="TO", kind="detail", side="left", label="TO",
         lines=["0x123456789abcdef1234", "56789abcdef123456789a"], size=22),
    dict(id="CHAIN", kind="detail", side="right", icon="base", label=None,
         lines=["on BASE"], size=36, text_x=175, circle_x=291),
    dict(id="TX INFO", kind="detail", side="left", label="TX INFO",
         lines=["Nonce: 8", "Type: Standard"], size=28),
    dict(id="CALL DATA", kind="detail", side="right", label="CALL DATA",
         lines=["Function: 0x12345678", "Data: 64 B"], size=22),
    dict(id="TX HASH", kind="detail", side="left", label="TX HASH",
         lines=["0x9f86d081884c7d", "...6c15b0f00a08"], size=22),
]

ENDS = ends()
DEFAULT_END = "signed"      # what --early commits to when no --end is given
# the full walkthrough: every detail, back on the idle ask, then the
# ending plays — loading resolving to success (or cancellation via --end)
SCREENS = BODY + [dict(BODY[0]), ENDS[DEFAULT_END]]
