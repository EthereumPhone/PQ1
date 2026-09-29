"""SAFE TX HASH FINGERPRINT flow — the device showing the Safe transaction
hash (the EIP-712 safeTxHash of a Safe{Wallet} transaction — one of the
Safe-specific signing hashes ERC-8213 asks a wallet to display) it
computed from the transaction it was handed, for the signer to match
against the Safe UI or an independent hash tool before signing, screen
content only (grid/type/motion come from pq1).

  SAFE TX HASH FINGERPRINT? (idle sweep) -> HASH (the hash alone, full
  width) -> back on the idle hero (the hash seen, the ask again) -> status
  (CONFIRMED by default) — the full walkthrough.

erc8213_call_data_digest's twin: the same flow and layout — one VALUE
screen, the hash alone centred on the panel across the full width, no
label, no token on it (the circle slides off the left edge and back), the
corner chevrons on top — only the ask and the subject change. One viewing
screen: below the 7-detail threshold there is no mid-flow Confirm? and no
`--early` variant (DESIGN.md § Flow shape); the hash is confirmed on an
ask only — the opening hero or the returning one — never on the hash
screen.

Read IN FULL: at the 22 tier a full-width line holds up to 13 bytes
(flows.fingerprint.digest), so the 32-byte safeTxHash is three lines —
"0x" + 11 bytes / 11 bytes / 10 bytes — and shows plain, without the
pager; a longer value would turn pages and the pager "n/m" would come
with them (DESIGN.md § Text rules, Pages).

Every screen wears the family identity (flows.fingerprint.DEFAULTS): the
fingerprint mark BLACK on the WHITE disc, a black edge stroke round it,
over the default grey trail — a firmware action, not a token, so the Safe
brand ramp stays off this flow. Endings (flows.fingerprint.ends):
"SAFE TX HASH CONFIRMED" (the qubit film to the green check) / "SAFE TX
HASH DECLINED" (the film-less cancel resolve).

The hash is VARIABLE content — computed per transaction on device; the
flow fixes the screens, their order, and the line rule, never a value.
Render with `python -m flows fingerprint/safe_tx_hash_fingerprint --end all`.
"""
from flows.fingerprint import DEFAULTS, digest, ends

# the safeTxHash — variable content, the device's EIP-712 hash of the Safe
# transaction; a 32-byte sample
HASH = "0xb81d4e7a2c9f0356e8a1d7c4b2f9e60d3a5c8f1b7e4d2a9c6f0b3e8d1a7c5f24"
assert len(HASH) == 66

BODY = [
    dict(id="SAFE TX HASH FINGERPRINT", kind="hero", bottom="SAFE TX HASH FINGERPRINT?",
         chev="lr", hint=True),
    dict(id="HASH", kind="value", chev="lr", **digest(HASH)),
]

ENDS = ends("SAFE TX HASH")
DEFAULT_END = "confirmed"
# the full walkthrough: the hash, back on the idle ask, then the ending
SCREENS = BODY + [dict(BODY[0]), ENDS[DEFAULT_END]]
