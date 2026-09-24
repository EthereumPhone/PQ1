"""PERSONAL COUNTERFACTUAL EIP-1271 flow, HASH twin — the device's own
smart account signing a message under EIP-1271 before the account
contract exists on chain, the message shown as its HASH, screen content
only (grid/type/motion come from pq1).

  SIGN EIP–1271? (idle sweep) -> NETWORK -> ACCOUNT -> SLOT -> SIGNER
  -> Confirm? (auto-inserted as screen 6, the early exit) -> HASH (two
  pages) -> DETAILS (the account state) -> DETAILS (the key budget)
  -> back on the idle hero (every detail seen, the ask again) -> status
  (SIGNED by default) — the full walkthrough.

personal_counterfactual's twin: every screen identical except MSG, which
becomes HASH — the 32-byte message hash the account signs, read IN FULL.
66 characters overflow the three 22 px lines one screen holds, and a hash
is ONE value, so the screen turns PAGES rather than splitting into two
screens or shortening (DESIGN.md § Text rules, Pages): `pages` — two
pages of two byte-aligned lines at 22 (page 1 "0x" + 8 bytes / 8 bytes,
page 2 8 bytes / 8 bytes), the pager "1/2" / "2/2" (12 px, 80 % white,
top centre) signalling the second page. The demo turns the page on the
detail dwell — the first half fades away over 300 ms on the ease-out
curve, then the second half fades in over 300 ms on the ease curve
(motion.page_flip, the confirm band's rhythm); on the bench (pq1.driver)
a right tap turns the page before it advances, a left tap turns it back.

Seven detail screens: the design system inserts the mid-flow Confirm? as
screen 6 (DESIGN.md § Flow shape) and `--early` commits there, skipping
the hash and both DETAILS screens. The signature is committed on an ask
only — the opening hero, Confirm?, or the returning hero — never on a
detail. Endings (flows.eip1271.ends): "EIP1271 SIGNED" (the qubit film
to the green check) / "EIP1271 DECLINED" (the film-less cancel resolve).
The chain screen follows the hero, so the id stays NETWORK.

EVERY value line is VARIABLE content — the flow fixes the screens, their
order, labels and sides, and the tier rule, never a value; the samples
describe the same login request as the twin, its message hashed.
Render with `python -m flows eip1271/personal_counterfactual_hash --end all`
and `python -m flows eip1271/personal_counterfactual_hash --early --end all`.
"""
from flows.eip1271 import defaults, ends

# the signing address — variable content, filled per request on device;
# the token's colour is hashed from it (flows.eip1271.defaults)
SIGNER = "0x5Ea1c7D93b04F6a28E7c3D0b9F1e6A4c8B2d7E05"
# the message hash — variable content; shown in full over two pages
HASH = "0x7d2e9a41c6f08b3d5e1a92c4f7b0d8e63a5c1f9e2b4d7a80c3e6f1b5d9a2c4e7"
assert len(HASH) == 66

DEFAULTS = defaults(SIGNER)   # the ether mark on the address-hashed solid disc

BODY = [
    dict(id="SIGN", kind="hero", bottom="SIGN EIP–1271?", chev="lr", hint=True),
    dict(id="NETWORK", kind="detail", side="right", chain=8453, label=None, chev="lr"),
    dict(id="ACCOUNT", kind="detail", side="left", label="ACCOUNT",
         lines=["On Account 1"], size=36, chev="lr"),
    dict(id="SLOT", kind="detail", side="right", label="SLOT",
         lines=["On Slot 3"], size=36, chev="lr"),
    dict(id="SIGNER", kind="detail", side="left", label="SIGNER",
         lines=[SIGNER[:21], SIGNER[21:]], size=22, chev="lr"),
    # Confirm? lands here — screen 6, placed by layout.insert_confirm
    dict(id="HASH", kind="detail", side="right", label="HASH",
         pages=[[HASH[:18], HASH[18:34]],        # "0x" + 8 bytes / 8 bytes
                [HASH[34:50], HASH[50:66]]],     # 8 bytes / 8 bytes
         size=22, chev="lr"),
    dict(id="DETAILS", kind="detail", side="left", label="DETAILS",
         lines=["Account contract", "does not exist", "on chain yet"], size=22, chev="lr"),
    dict(id="KEYS", kind="detail", side="right", label="DETAILS",
         lines=["1/1000 Keys used", "Gap: 1"], size=28, chev="lr"),
]

ENDS = ends()
DEFAULT_END = "signed"      # what --early commits to when no --end is given
# the full walkthrough: every detail, back on the idle ask, then the
# ending plays — loading resolving to success (or cancellation via --end)
SCREENS = BODY + [dict(BODY[0]), ENDS[DEFAULT_END]]
