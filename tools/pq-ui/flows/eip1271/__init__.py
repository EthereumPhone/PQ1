"""EIP-1271 flow family — the device's own smart account signing a message
under EIP-1271 (isValidSignature), on the PQ1 grid.

Shared identity for every EIP-1271 flow: the signer is the device's own
(personal) account — an address, not a token with a logo — so its token
takes the placeholder treatment (DESIGN.md § Color): a SOLID disc in the
fill of the six-stop ramp hashed from the SIGNER ADDRESS
(components.token_ramp, crc32, never fixed) and the same ramp darkening
away on the trail, the white ether mark on it — so one account always
wears one colour, the SIGNER screen shows the address the colour comes
from; defaults(signer) pins it. The family has no brand, so the endings
keep the unbranded resting look — black disc, the state colour on the
ring stroke and the glyph — and ends() captions them "EIP1271 SIGNED" /
"EIP1271 DECLINED". A new EIP-1271 flow is one module in this package:
DEFAULTS = defaults(<signer>), ENDS = ends(), then its screens; render with
`python -m flows eip1271/<name> --end all` (and --early --end all for
the commit paths on a 7+-detail flow)
-> renders/flows/eip1271/<name>/{success,cancel}/<name>_<full|early>_<end>.gif.
"""
import copy

ICON = "eth"   # the ether mark, white on the account's disc


def defaults(signer):
    """an EIP-1271 flow's DEFAULTS: the ether mark on the solid placeholder
    disc + trail hashed from the signer address (never a fixed ramp)"""
    return dict(icon=ICON, token=dict(palette=signer))


def ends():
    """fresh copies of the shared endings: SIGNED plays the qubit film
    resolving to the green check; DECLINED plays NO film — the cancel
    resolve (status.default_anim): the token resolves in place, red ring
    stroke and red X on the unfilled black disc"""
    return copy.deepcopy({
        "signed": dict(id="SIGNED", kind="status", bottom="EIP1271 SIGNED", chev=None),
        "declined": dict(id="DECLINED", kind="status", result="x", state="failed",
                         bottom="EIP1271 DECLINED", chev=None),
    })
