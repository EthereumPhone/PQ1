"""The chain registry — one row per EVM network the device can name.

A chain screen says `chain=<id>` and nothing else: the mark, the disc
colour, the trail ramp and the caption are all DERIVED from that one
number. Before this, a flow typed `icon="base"` and `lines=["on BASE"]`
separately, so nothing stopped a screen pairing the Base square with "on
Mainnet" — on a signer, where the disc is part of what the user checks,
that divergence is a lie the device tells. One id, one identity.

Adding a chain is one row of CHAINS plus its mark in
`procedural/chains.py` and its colour in `colors.CHAIN_COLORS`.

A chain id the registry does NOT hold is not an error and does not fall
back to the ether mark: the disc shows the FIRST LETTER of the chain's
name and stays exactly where it is (user rule, Sep 2026). The ether
fallback remains the right answer for a token or a mark the device cannot
resolve — but drawing Ethereum's mark for Celo would name the wrong
network, so a chain answers with a letter instead. The disc is never
empty either way (DESIGN.md, Components).

Because the letter comes from the name, an unknown id must be given one:
`chain=12345, chain_name="Celo"`. A known id takes its name from here.
"""
from . import colors

# EIP-155 chain id -> (display name, caption label, glyph, ramp key)
#   name    what the chain is called; the unknown-chain letter comes from it
#   label   the short form the caption uses, so "on <label>" stays one line
#   glyph   components.GLYPHS key (procedural/chains.py, or eth.py for id 1)
#   ramp    colors.CHAIN_COLORS key — namespaced, never a bare ticker
CHAINS = {
    1:      ("Ethereum Mainnet", "Mainnet",   "mainnet",   "CHAIN:MAINNET"),
    10:     ("OP Mainnet",       "Optimism",  "op",        "CHAIN:OP"),
    56:     ("BNB Chain",        "BNB",       "bnb",       "CHAIN:BNB"),
    137:    ("Polygon",          "Polygon",   "polygon",   "CHAIN:POLYGON"),
    324:    ("zkSync Era",       "zkSync",    "zksync",    "CHAIN:ZKSYNC"),
    5000:   ("Mantle",           "Mantle",    "mantle",    "CHAIN:MANTLE"),
    8453:   ("Base",             "Base",      "base",      "CHAIN:BASE"),
    42161:  ("Arbitrum One",     "Arbitrum",  "arbitrum",  "CHAIN:ARBITRUM"),
    43114:  ("Avalanche",        "Avalanche", "avalanche", "CHAIN:AVALANCHE"),
    59144:  ("Linea",            "Linea",     "linea",     "CHAIN:LINEA"),
    534352: ("Scroll",           "Scroll",    "scroll",    "CHAIN:SCROLL"),
}

LETTER_PREFIX = "letter:"   # the glyph namespace an unknown chain resolves to
CAPTION_TIERS = (36, 32, 28)   # the Big tier, stepped down until the group fits


def known(chain_id):
    return chain_id in CHAINS


def name(chain_id, fallback=None):
    """the chain's display name — `fallback` answers for an unknown id"""
    row = CHAINS.get(chain_id)
    return row[0] if row else fallback


def label(chain_id, fallback=None):
    """the short form the caption uses"""
    row = CHAINS.get(chain_id)
    return row[1] if row else fallback


def caption(chain_id, chain_name=None):
    """the chain screen's line: "on Base", "on Mainnet", "on Celo" """
    return "on %s" % (label(chain_id, chain_name) or chain_name)


def letter_glyph(chain_name):
    """the glyph name for an unknown chain: its first letter on the disc"""
    ch = (chain_name or "").strip()[:1].upper()
    return LETTER_PREFIX + ch if ch else None


def style(chain_id, chain_name=None):
    """the derived look of a chain screen: dict(icon, token, icon_color).

    A known chain wears its own brand: the mark on a disc filled with the
    chain's colour, the trail on the chain's ramp. An unknown one wears its
    first letter on a solid disc whose ramp is hashed from the chain ID —
    deterministic, so the same unrecognised network looks the same on every
    device and every run, the way an unknown token's ramp is hashed from its
    address. Solid, never the gradient: the gradient disc is reserved as the
    unknown-TOKEN signal and a flow's token circle is always solid.
    """
    row = CHAINS.get(chain_id)
    if row is None:
        nm = chain_name or ""
        glyph = letter_glyph(nm)
        if glyph is None:
            raise ValueError(
                "chain id %r is not in pq1.chains.CHAINS, so the disc shows the "
                "chain's first letter — give the screen a chain_name (e.g. "
                "chain_name=\"Celo\") or add the chain to the registry" % (chain_id,))
        # hashed from the id, not the name: two forks can share a name, never an id
        return dict(icon=glyph, token=dict(palette=str(chain_id)),
                    icon_color=list(colors.WHITE))
    _nm, _label, glyph, ramp = row
    return dict(icon=glyph, token=dict(palette=ramp),
                icon_color=list(colors.chain_mark_color(ramp)))
