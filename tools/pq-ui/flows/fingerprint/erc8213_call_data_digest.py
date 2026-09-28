"""ERC-8213 CALL DATA DIGEST flow — the device showing the calldata
digest (ERC-8213: Wallet Signature and Calldata Digest Display) it
computed from the raw bytes, for the user to match against the dapp
before signing, screen content only (grid/type/motion come from pq1).

  CALL DATA DIGEST? (idle sweep) -> DIGEST (the hash alone, full width)
  -> back on the idle hero (the digest seen, the ask again) -> status
  (CONFIRMED by default) — the full walkthrough.

One viewing screen: below the 7-detail threshold there is no mid-flow
Confirm? and no `--early` variant (DESIGN.md § Flow shape). The digest
is confirmed on an ask only — the opening hero or the returning one —
never on the digest screen.

DIGEST is a VALUE screen, not a detail: the hash alone, centred on the
panel across the full width, no label, no token on the screen — the
circle slides off the left edge as the hash comes in and slides back for
the returning ask — the corner chevrons on top for tap-nav. Read IN
FULL: at the 22 tier a full-width line holds up to 13 bytes
(flows.fingerprint.digest), so a 32-byte digest is three lines — "0x" +
11 bytes / 11 bytes / 10 bytes — and shows plain, without the pager. A
digest that overflows the three lines turns PAGES rather than splitting
into two screens or shortening (DESIGN.md § Text rules, Pages): the
pager "n/m" (12 px, 80 % white, top centre between the chevrons) comes
with them, the demo turns the page on the dwell (motion.page_flip); on
the bench (pq1.driver) a right tap turns the page before it advances.

Every screen wears the family identity (flows.fingerprint.DEFAULTS): the
fingerprint mark BLACK on the WHITE disc, a black edge stroke round it,
over the default grey trail — a firmware action, not a token. Endings
(flows.fingerprint.ends): "DIGEST CONFIRMED" (the qubit film to the
green check) / "DIGEST DECLINED" (the film-less cancel resolve).

The digest is VARIABLE content — computed per transaction on device;
the flow fixes the screens, their order, and the line rule, never a
value. Render with
`python -m flows fingerprint/erc8213_call_data_digest --end all`.
"""
from flows.fingerprint import DEFAULTS, digest, ends

# the calldata digest — variable content, the device's keccak of the raw
# calldata; a 32-byte sample
DIGEST = "0x3f9c2b7e1a8d4c6f05b2e9d1c7a4f8036e5b1d9a2c7f4e8b0d6a3c1f9e2b5d78"
assert len(DIGEST) == 66

BODY = [
    dict(id="CALL DATA DIGEST", kind="hero", bottom="CALL DATA DIGEST?", chev="lr", hint=True),
    dict(id="DIGEST", kind="value", chev="lr", **digest(DIGEST)),
]

ENDS = ends("DIGEST")
DEFAULT_END = "confirmed"
# the full walkthrough: the digest, back on the idle ask, then the ending
SCREENS = BODY + [dict(BODY[0]), ENDS[DEFAULT_END]]
