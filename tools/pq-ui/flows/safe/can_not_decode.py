"""SAFE sign flow, undecodable call data — screen content only.

  APPROVE SAFE TX? (idle sweep) -> NETWORK -> SAFE ACCT -> TO
  -> BLIND SIGN (pulse rings) -> Confirm? (auto-inserted 6th — this flow has 7 detail
  screens, DESIGN.md § Flow shape: hold-right commits from there, the
  band alternates OR VIEW MORE / TO GO BACK) -> TX INFO -> CALL DATA
  -> TX HASH (two pages) -> back on the idle hero (every detail seen)
  -> loading -> SIGNED (success) — the full walkthrough. `--end
  declined` swaps the cancellation ending; `--early [--end …]`
  renders the commit path: Confirm? jumps straight to the ending, the
  rest never visited. Ending renders land in success/ and cancel/
  folders (see flows/__main__).

BLIND SIGN pulses WARNING rings around the token (components.pulse): the
device cannot decode the call data, so the signature is flagged and the
user is asked to verify on the dapp. The rings carry the state, not the
brand — orange around the Safe-green disc, never the SIGNED green
(DESIGN.md § Color). Content ported from
archive/legacy/safe_flow/safe_common.py onto the PQ1 grid.

TX HASH is the safeTxHash, the EIP-712 digest the owner signs and a
co-signer matches against the Safe UI. The device has already said it
cannot decode the call data, so this hash is the ONE value binding the
whole transaction — it is read IN FULL, never shortened. Its 66
characters overflow the three 22 px lines one screen holds, and a hash
is ONE value, so the screen turns PAGES rather than splitting into two
screens or shortening (DESIGN.md § Text rules, Pages): two pages of two
byte-aligned lines at 22 (page 1 "0x" + 8 bytes / 8 bytes, page 2
8 bytes / 8 bytes), the pager "1/2" / "2/2" top centre signalling the
second page. On the bench (pq1.driver) a right tap turns the page
before it advances, a left tap turns it back.
Render with `python -m flows safe/can_not_decode --end all`.
"""
from flows.safe import DEFAULTS, ends  # noqa: F401  (DEFAULTS read by flows.screens)

# the Safe transaction hash — variable content, the EIP-712 digest the
# owner signs; shown IN FULL over two pages, never shortened
HASH = "0x3891eebc185e86fb1b32cb344d10b93d2be974b27f759d33c6275096ddca3720"
assert len(HASH) == 66

BODY = [
    dict(id="APPROVE", kind="hero", bottom="APPROVE SAFE TX?", hint=True),
    dict(id="NETWORK", kind="detail", side="right", chain=8453, label=None),
    dict(id="SAFE ACCT", kind="detail", side="left", label="SAFE ACCT",
         lines=["0x1111111111222222222", "3333333333444444444aa"], size=22),
    dict(id="TO", kind="detail", side="right", label="TO",
         lines=["0x123456789abcdef1234", "56789abcdef123456789a"], size=22),
    dict(id="BLIND SIGN", kind="detail", side="left", label="BLIND SIGN",
         lines=["Can not decode data", "Confirm on dapp"], size=22, pulse=True),
    dict(id="TX INFO", kind="detail", side="right", label="TX INFO",
         lines=["Nonce: 8", "Type: Standard"], size=28),
    dict(id="CALL DATA", kind="detail", side="left", label="CALL DATA",
         lines=["Function: 0x12345678", "Data: 64 B"], size=22),
    dict(id="TX HASH", kind="detail", side="right", label="TX HASH",
         pages=[[HASH[:18], HASH[18:34]],        # "0x" + 8 bytes / 8 bytes
                [HASH[34:50], HASH[50:66]]],     # 8 bytes / 8 bytes
         size=22),
]

ENDS = ends()
DEFAULT_END = "signed"      # what --early commits to when no --end is given
# the full walkthrough: every detail, back on the idle ask, then the
# ending plays — loading resolving to success (or cancellation via --end)
SCREENS = BODY + [dict(BODY[0]), ENDS[DEFAULT_END]]
