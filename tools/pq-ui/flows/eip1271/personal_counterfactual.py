"""PERSONAL COUNTERFACTUAL EIP-1271 flow — the device's own smart account
signing a message under EIP-1271 before the account contract exists on
chain, screen content only (grid/type/motion come from pq1).

  SIGN EIP–1271? (idle sweep) -> NETWORK -> ACCOUNT -> SLOT -> SIGNER
  -> Confirm? (auto-inserted as screen 6, the early exit) -> MSG
  -> DETAILS (the account state) -> DETAILS (the key budget) -> back on
  the idle hero (every detail seen, the ask again) -> status (SIGNED by
  default) — the full walkthrough.

Seven detail screens: the design system inserts the mid-flow Confirm? as
screen 6 (DESIGN.md § Flow shape) and `--early` commits there, skipping
the message and both DETAILS screens. The signature is committed on an
ask only — the opening hero, Confirm?, or the returning hero — never on
a detail.

Endings (--end on the CLI, flows.eip1271.ends): SIGNED is the qubit film
resolving to a green check; DECLINED plays no film (the cancel resolve,
status.default_anim) — the token resolves in place, red ring stroke and
red X on the unfilled black disc. Captions "EIP1271 SIGNED" / "EIP1271
DECLINED". The chain screen follows the hero, so the id stays NETWORK:
canonical id CHAIN must directly follow TO or AMOUNT, and this flow has
neither.

EVERY value line is VARIABLE content — the flow fixes the screens, their
order, labels and sides, and the tier rule, never a value. The samples
describe one plausible request — a dapp login signed by a counterfactual
account: ACCOUNT / SLOT which account and key slot sign ("On Account 1",
"On Slot 3" — 36, the one-line tier); SIGNER the signing address alone
(the address treatment, two <= 21-char halves at 22); MSG the message
text as the dapp sent it, broken between its words into <= 21-char lines
at 22 (three lines — the tier that holds the whole message, DESIGN.md
§ Typography); the first DETAILS the account's deployment state ("Account
contract does not exist on chain yet", three lines at 22); the second
DETAILS (id KEYS) the key budget of the slot — keys spent of the slot's
supply and the gap counter ("1/1000 Keys used" / "Gap: 1" at 28).
personal_counterfactual_hash is the twin that shows the message HASH
instead of the message.
Render with `python -m flows eip1271/personal_counterfactual --end all`
and `python -m flows eip1271/personal_counterfactual --early --end all`.
"""
from flows.eip1271 import defaults, ends

# the signing address — variable content, filled per request on device;
# the token's colour is hashed from it (flows.eip1271.defaults)
SIGNER = "0x5Ea1c7D93b04F6a28E7c3D0b9F1e6A4c8B2d7E05"

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
    dict(id="MSG", kind="detail", side="right", label="MSG",
         lines=["Login to", "app.example.com?", "Nonce: 8f3a9c2e1b"], size=22, chev="lr"),
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
