"""BATCH TRANSFERS flow — three ERC-20 transfers signed as ONE batch,
screen content only (grid/type/motion come from pq1).

  BATCH SIGN TX 1 OF 3 ▸ (the batch screen, pager 1/3) -> SEND 1,250
  TOSHI? (the idle screen: the transaction's own ask) -> TO -> CHAIN ->
  AMOUNT -> MAX FEE -> WORST CASE -> DETAILS -> BATCH SIGN TX 1 OF 3 TX?
  (the ask again — the hold) -> SIGNED 1 OF 3 -> the same for tx 2 ->
  BATCH SIGN TX 3 OF 3 TX? (the LAST transaction opens on the ask: no
  chevron, nothing left to point on to) -> its idle screen, its details,
  the ask again -> status (BATCH SIGNED by default) — the full
  walkthrough.

Each transaction is a SEGMENT: the batch screen, the idle screen, six
details, the ask again, and its own ending naming its place in the
batch. Six details per transaction is below the 7-detail threshold, so
there is no mid-flow Confirm? and no `--early` variant — the threshold
is counted per segment, never against the batch total (DESIGN.md § Flow
shape). A transaction is signed on an ask only — the batch screen in its
ask form — never on a detail.

The BATCH screen carries the pager "n/3" top centre: a POSITION in the
batch, not text pages, so nothing turns (the hero "pager" field).

Endings (--end on the CLI): BATCH SIGNED is the qubit film resolving to
the green check; BATCH DECLINED plays no film (the cancel resolve,
status.default_anim). One declined transaction declines the whole batch,
so the caption names the batch. --end swaps the LAST status screen, so
the cancel render signs tx 1 and 2 and declines on tx 3; the mid-batch
decline is its twin, flows/batch/transfers_declined.py.

EVERY value line is VARIABLE content — the recipients, amounts, nonces
and fee figures are filled per transaction on device; the flow fixes the
screens, their order, labels and sides, never a value. Render with
`python -m flows batch/transfers --end all`.
"""
from flows.batch import batch_hero, defaults, ends, signed

SYMBOL = "TOSHI"   # a long-tail token: the SOLID placeholder disc + the ramp
                   # trail hashed from it; a popular symbol would render its
                   # logo art and hide the treatment a sample exists to show
TOTAL = 3

DEFAULTS = defaults(SYMBOL)


def transaction(tx, to, amount, nonce):
    """one transaction of the batch: the BATCH screen, the transaction's
    own IDLE screen, its six details, then the batch screen in its ask
    form — the return-to-idle ask, where the hold fill happens.

    The idle screen is the ordinary flow opening (`flows/send_token.py`):
    the token drifting on the sweep under its ask, hint chevrons, commit
    armed, no pager — the batch screen says WHICH transaction, the idle
    screen says WHAT it is. The last transaction opens on the ask form:
    it has nothing to point on to, so it never wears the chevron."""
    assert len(to) == 42, to        # split mid-string into two 21-char halves
    return [
        batch_hero(tx, TOTAL, ask=(tx == TOTAL)),
        dict(id="SEND", kind="hero", bottom=f"SEND {amount}?", chev="lr", hint=True),
        dict(id="TO", kind="detail", side="left", label="TO",
             lines=[to[:21], to[21:]], size=22, chev="lr"),
        dict(id="CHAIN", kind="detail", side="right", chain=8453, label=None, chev="lr"),
        dict(id="AMOUNT", kind="detail", side="left", label="AMOUNT",
             lines=[amount], size=36, chev="lr"),
        dict(id="MAX FEE", kind="detail", side="right", label="MAX FEE",
             lines=["45.5 gwei", "Tip: 2 gwei"], size=28, chev="lr"),
        dict(id="WORST CASE", kind="detail", side="left", label="WORST CASE",
             lines=["Max: 0.0030 ETH", "Gas: 65000"], size=28, chev="lr"),
        dict(id="DETAILS", kind="detail", side="right", label="DETAILS",
             lines=[f"Nonce: {nonce}", "Data: 68B"], size=28, chev="lr"),
        batch_hero(tx, TOTAL, ask=True),
    ]


# the recipients, amounts and nonces — VARIABLE content, one placeholder
# sample per transaction; the nonce increments across the batch, and the
# fee samples are the ERC-20 transfer set (45.5 gwei x 65000 gas =
# 0.0030 ETH, transfer(to, amount) calldata 68B)
TXS = [
    dict(to="0x78D8526282Ac09f1885D0F39B8875a0180Fc081e",
         amount=f"1,250 {SYMBOL}", nonce=42),
    dict(to="0x4B20993Bc481177ec7E8f571ceCaE8A9e22C02db",
         amount=f"840.5 {SYMBOL}", nonce=43),
    dict(to="0x1aE0EA34a72D944a8C7603FfB3eC30a6669E454C",
         amount=f"12,000 {SYMBOL}", nonce=44),
]

BODY = []
for _n, _tx in enumerate(TXS, 1):
    BODY += transaction(_n, **_tx)
    if _n < TOTAL:                      # every transaction but the last
        BODY.append(signed(_n, TOTAL))  # resolves, then the next begins

ENDS = ends(TOTAL)
DEFAULT_END = "signed"
# the last transaction's ask IS the return — the batch ending follows it
SCREENS = BODY + [ENDS[DEFAULT_END]]
