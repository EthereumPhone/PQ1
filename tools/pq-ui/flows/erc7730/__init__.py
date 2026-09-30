"""ERC7730 flow family — transactions the device clear-signs from an
ERC-7730 descriptor (the JSON a contract's developer publishes so a
wallet can show a call in words instead of calldata).

Every ERC-7730 flow opens on its ask — no intro screen (the ERC-7730
CLEAR SIGNING hero was removed, user decision 2026-09-26). Every screen
shows the call's own identity: the ether mark white on the SOLID disc hashed from the contract ADDRESS
(components.token_ramp, crc32 — never fixed; defaults(contract) pins it)
and the same ramp darkening away on the trail, so one contract always
wears one colour. The family has no brand, so the endings keep the
unbranded resting look — black disc, the state colour on the ring stroke
and the glyph.

A new ERC-7730 flow is one module in this package: DEFAULTS =
defaults(<contract>), a BODY opening [<the ask>, <details>…],
ENDS = ends(<subject>), and SCREENS = BODY + [dict(BODY[0]), <ending>] —
the walkthrough returns to the ask. Render with
`python -m flows erc7730/<name> --end all`
-> renders/flows/erc7730/<name>/{success,cancel}/<name>_full_<end>.gif.
"""
import copy


def defaults(contract):
    """an ERC-7730 flow's DEFAULTS: the ether mark on the solid placeholder
    disc + trail hashed from the contract address (never a fixed ramp)"""
    return dict(icon="eth", token=dict(palette=contract))


def ends(subject="TRANSACTION"):
    """fresh copies of the shared endings, captioned on the ask's subject
    ("SWAP SIGNED" / "SWAP DECLINED"): SIGNED plays the qubit film
    resolving to the green check; DECLINED plays NO film — the cancel
    resolve (status.default_anim): the token resolves in place, red ring
    stroke and red X on the unfilled black disc"""
    return copy.deepcopy({
        "signed": dict(id="SIGNED", kind="status", bottom=f"{subject} SIGNED", chev=None),
        "declined": dict(id="DECLINED", kind="status", result="x", state="failed",
                         bottom=f"{subject} DECLINED", chev=None),
    })
