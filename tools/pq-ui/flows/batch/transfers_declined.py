"""BATCH TRANSFERS, DECLINED MID-BATCH — the twin of
flows/batch/transfers.py showing the rule the full walkthrough cannot:
ONE declined transaction declines the WHOLE batch.

  BATCH SIGN TX 1 OF 3 ▸ -> its idle screen (SEND 1,250 TOSHI?) -> its
  details -> the ask -> SIGNED 1 OF 3 -> BATCH SIGN TX 2 OF 3 ▸ -> its
  idle screen -> its details -> BATCH SIGN TX 2 OF 3 TX? -> hold LEFT ->
  BATCH DECLINED.

Transaction 3 is never reached: the batch ends where the decline
happens, and the caption names the batch, not the transaction it was
reached from. The screens are the twin's, built from the same family
helpers and the same samples (flows.batch.transfers.TXS) — only the pass
is cut short, so this module carries the declined ending ALONE and
`--end all` renders the one GIF.

Six details per transaction, so no mid-flow Confirm? and no `--early`
variant (DESIGN.md § Flow shape). Render with
`python -m flows batch/transfers_declined --end all`.
"""
from flows.batch import defaults, ends, signed
from flows.batch.transfers import SYMBOL, TOTAL, TXS, transaction

DEFAULTS = defaults(SYMBOL)

BODY = (transaction(1, **TXS[0]) + [signed(1, TOTAL)]
        + transaction(2, **TXS[1]))

ENDS = {"declined": ends(TOTAL)["declined"]}
DEFAULT_END = "declined"
# the decline lands on tx 2's ask — hold LEFT, and the batch is over
SCREENS = BODY + [ENDS[DEFAULT_END]]
