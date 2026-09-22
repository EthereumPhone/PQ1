"""SAFE add-owner flow — owner management on the Safe, screen content only.

  SAFE ADD OWNER? (idle sweep) -> NETWORK -> SAFE ACCT -> NEW
  -> SIGNERS -> TX INFO -> back on the idle hero (every detail seen,
  the ask again — 5 detail screens, so no mid-flow Confirm? and no
  --early variants, DESIGN.md § Flow shape: accept/cancel never exists
  while viewing details) -> loading -> SIGNED (success) — the full
  walkthrough. `--end declined` swaps the cancellation ending.

Adds a new owner to the Safe: the chain context, the Safe account, the
new owner's address, the signer threshold after the change (2 of 3
signers required) and the transaction nonce. The chain screen is
variable content like every label and value line — "on Mainnet" +
icon="mainnet" is a representative sample; another chain swaps the
line and icon (e.g. lines=["on BASE"], size=36, icon="base"). The id
stays NETWORK: canonical id CHAIN must directly follow TO or AMOUNT,
and this flow has neither.
Render with `python -m flows safe/add_owner --end all`.
"""
from flows.safe import DEFAULTS, ends  # noqa: F401  (DEFAULTS read by flows.screens)

BODY = [
    dict(id="ADD OWNER", kind="hero", bottom="SAFE ADD OWNER?", hint=True),
    dict(id="NETWORK", kind="detail", side="right", icon="mainnet", label=None,
         lines=["on Mainnet"], size=32, text_x=175, circle_x=291),
    dict(id="SAFE ACCT", kind="detail", side="left", label="SAFE ACCT",
         lines=["0x1111111111222222222", "3333333333444444444aa"], size=22),
    dict(id="NEW", kind="detail", side="right", label="NEW",
         lines=["0xAAAABBBBCCCCDDDDEEE", "EFFFF0000111122223333"], size=22),
    dict(id="SIGNERS", kind="detail", side="left", label="SIGNERS",
         lines=["2 of 3", "Signers required"], size=28),
    dict(id="TX INFO", kind="detail", side="right", label="TX INFO",
         lines=["Nonce: 12"], size=36),
]

ENDS = ends()
DEFAULT_END = "signed"      # what the walkthrough resolves to when no --end is given
# the full walkthrough: every detail, back on the idle ask, then the
# ending plays — loading resolving to success (or cancellation via --end)
SCREENS = BODY + [dict(BODY[0]), ENDS[DEFAULT_END]]
