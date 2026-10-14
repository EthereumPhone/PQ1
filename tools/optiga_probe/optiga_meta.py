"""OPTIGA Trust M V3 metadata decoding and access-condition evaluation.

Source of truth: the vendored SRM v3.70,
docs/SLS32AIA010MKUSON10XTMA2/OPTIGA_Trust_M_Solution_Reference_Manual.md
  - metadata tags: Table 49 (~line 5252)
  - access-condition identifiers and operators: ~line 4674
  - data-object types: ~line 4964
  - lifecycle values: ~line 4983
  - last-error codes: ~line 2371
"""

from __future__ import annotations

from dataclasses import dataclass, field

TAG_NAMES = {
    0xC0: "LcsO",
    0xC1: "Version",
    0xC4: "MaxSize",
    0xC5: "UsedSize",
    0xD0: "Change",
    0xD1: "Read",
    0xD3: "Execute",
    0xD8: "MetadataUpdate",
    0xE0: "Algorithm",
    0xE1: "KeyUsage",
    0xE8: "DataType",
    0xF0: "ResetType",
}

LCS = {0x01: "creation", 0x03: "initialization", 0x07: "operational", 0x0F: "termination"}

DATA_TYPES = {
    0x00: "BSTR",
    0x01: "UPCTR",
    0x11: "TA",
    0x12: "DEVCERT",
    0x21: "PRESSEC",
    0x22: "PTFBIND",
    0x23: "UPDATSEC",
    0x31: "AUTOREF",
}

ALGORITHMS = {
    0x03: "NIST-P256",
    0x04: "NIST-P384",
    0x05: "NIST-P521",
    0x13: "BrainpoolP256r1",
    0x15: "BrainpoolP384r1",
    0x16: "BrainpoolP512r1",
    0x41: "RSA-1024",
    0x42: "RSA-2048",
    0x81: "AES-128",
    0x82: "AES-192",
    0x83: "AES-256",
    0x1A: "HMAC-SHA256",
    0x1B: "HMAC-SHA384",
    0x1C: "HMAC-SHA512",
}

LAST_ERROR = {
    0x01: "invalid OID",
    0x03: "invalid param",
    0x04: "invalid length",
    0x05: "invalid data",
    0x06: "internal",
    0x07: "access conditions not satisfied",
    0x08: "data object boundary exceeded",
    0x09: "metadata truncation",
    0x0A: "invalid command",
    0x0B: "command out of sequence",
    0x0C: "not available",
    0x0D: "insufficient memory",
    0x0E: "counter threshold reached",
    0x0F: "invalid manifest",
    0x10: "invalid/wrong payload version",
    0x11: "invalid metadata",
    0x24: "unsupported extension/identifier",
    0x25: "unsupported parameters",
    0x29: "invalid certificate format",
    0x2A: "unsupported certificate",
    0x2C: "signature verification failure",
    0x2D: "integrity validation failure",
    0x2E: "decryption failure",
    0x2F: "authorization failure",
}

# Access-condition identifiers: (name, number of argument bytes).
AC_IDS = {
    0x00: ("ALW", 0),
    0x10: ("SecStaG", 1),
    0x20: ("Conf", 2),
    0x21: ("Int", 2),
    0x23: ("Auto", 2),
    0x40: ("Luc", 2),
    0x70: ("LcsG", 2),
    0x90: ("SecStaA", 1),
    0xE0: ("LcsA", 2),
    0xE1: ("LcsO", 2),
    0xFF: ("NEV", 0),
}
AC_OPS = {0xFA: "==", 0xFB: ">", 0xFC: "<", 0xFD: "&&", 0xFE: "||"}


@dataclass
class Term:
    ident: str
    args: bytes = b""

    def text(self) -> str:
        if self.ident in ("ALW", "NEV"):
            return self.ident
        if self.ident in ("Conf", "Int", "Auto", "Luc"):
            return f"{self.ident}({self.args.hex().upper()})"
        if self.ident in ("LcsG", "LcsA", "LcsO"):
            op = AC_OPS.get(self.args[0], f"?{self.args[0]:02x}")
            val = LCS.get(self.args[1], f"{self.args[1]:#04x}")
            return f"{self.ident}{op}{val}"
        return f"{self.ident}({self.args.hex()})"


@dataclass
class Ac:
    """A parsed access condition: terms joined by && / ||."""

    raw: bytes
    terms: list[Term] = field(default_factory=list)
    joins: list[str] = field(default_factory=list)
    error: str | None = None

    def text(self) -> str:
        if self.error:
            return f"<unparsed {self.raw.hex()}: {self.error}>"
        out = self.terms[0].text() if self.terms else "<empty>"
        for j, t in zip(self.joins, self.terms[1:]):
            out += f" {j} {t.text()}"
        return out

    def references(self, ident: str) -> list[int]:
        return [int.from_bytes(t.args, "big") for t in self.terms if t.ident == ident and len(t.args) == 2]


def parse_ac(raw: bytes) -> Ac:
    ac = Ac(raw=raw)
    i = 0
    expect_term = True
    while i < len(raw):
        b = raw[i]
        if expect_term:
            if b not in AC_IDS:
                ac.error = f"unknown identifier {b:#04x} at {i}"
                return ac
            name, nargs = AC_IDS[b]
            if i + 1 + nargs > len(raw):
                ac.error = "truncated"
                return ac
            ac.terms.append(Term(name, raw[i + 1 : i + 1 + nargs]))
            i += 1 + nargs
            expect_term = False
        else:
            if b not in (0xFD, 0xFE):
                ac.error = f"expected && or || at {i}, got {b:#04x}"
                return ac
            ac.joins.append(AC_OPS[b])
            i += 1
            expect_term = True
    if expect_term and raw:
        ac.error = "dangling operator"
    return ac


@dataclass
class Ctx:
    """What the requester has when an access condition is evaluated."""

    shielded: bool = False
    authorized: frozenset[int] = frozenset()  # Auto() OIDs satisfied
    lcso: int | None = None
    lcsa: int | None = None
    lcsg: int | None = None


def _cmp(op: int, a: int, b: int) -> bool:
    return {0xFA: a == b, 0xFB: a > b, 0xFC: a < b}.get(op, False)


def eval_term(t: Term, ctx: Ctx) -> bool | None:
    if t.ident == "ALW":
        return True
    if t.ident == "NEV":
        return False
    if t.ident == "Conf":
        return ctx.shielded
    if t.ident == "Int":
        return False  # only a signed protected update satisfies it
    if t.ident == "Auto":
        return int.from_bytes(t.args, "big") in ctx.authorized
    if t.ident in ("LcsO", "LcsA", "LcsG"):
        cur = {"LcsO": ctx.lcso, "LcsA": ctx.lcsa, "LcsG": ctx.lcsg}[t.ident]
        if cur is None:
            return None
        return _cmp(t.args[0], cur, t.args[1])
    return None  # Luc, SecSta*: state-dependent


def eval_ac(ac: Ac, ctx: Ctx) -> bool | None:
    """Evaluate with && binding tighter than ||. None = cannot tell."""
    if ac.error or not ac.terms:
        return None
    groups: list[list[Term]] = [[ac.terms[0]]]
    for j, t in zip(ac.joins, ac.terms[1:]):
        if j == "&&":
            groups[-1].append(t)
        else:
            groups.append([t])
    any_unknown = False
    for g in groups:
        vals = [eval_term(t, ctx) for t in g]
        if all(v is True for v in vals):
            return True
        if not any(v is False for v in vals):
            any_unknown = True
    return None if any_unknown else False


@dataclass
class Meta:
    raw: bytes
    tags: dict[int, bytes] = field(default_factory=dict)
    order: list[int] = field(default_factory=list)
    error: str | None = None

    @property
    def lcso(self) -> int | None:
        v = self.tags.get(0xC0)
        return v[0] if v and len(v) == 1 else None

    @property
    def data_type(self) -> int | None:
        v = self.tags.get(0xE8)
        return v[0] if v and len(v) == 1 else None

    def ac(self, tag: int) -> Ac | None:
        v = self.tags.get(tag)
        return parse_ac(v) if v is not None else None

    def security_view(self) -> dict[int, bytes]:
        """Tags that define protection (sizes and version excluded)."""
        return {t: v for t, v in self.tags.items() if t not in (0xC1, 0xC4, 0xC5)}

    def describe(self) -> str:
        if self.error:
            return f"<bad metadata {self.raw.hex()}: {self.error}>"
        parts = []
        for t in self.order:
            v = self.tags[t]
            name = TAG_NAMES.get(t, f"tag{t:02X}")
            if t == 0xC0:
                parts.append(f"{name}={LCS.get(v[0], hex(v[0])) if v else '?'}")
            elif t in (0xC4, 0xC5):
                parts.append(f"{name}={int.from_bytes(v, 'big')}")
            elif t in (0xD0, 0xD1, 0xD3):
                parts.append(f"{name}=[{parse_ac(v).text()}]")
            elif t == 0xE8:
                parts.append(f"{name}={DATA_TYPES.get(v[0], hex(v[0])) if v else '?'}")
            elif t == 0xE0:
                parts.append(f"{name}={ALGORITHMS.get(v[0], hex(v[0])) if v else '?'}")
            else:
                parts.append(f"{name}={v.hex()}")
        return " ".join(parts)


def parse_meta(raw: bytes) -> Meta:
    m = Meta(raw=raw)
    if len(raw) < 2 or raw[0] != 0x20:
        m.error = "no 0x20 root"
        return m
    end = 2 + raw[1]
    if end > len(raw):
        m.error = "root length exceeds payload"
        return m
    i = 2
    while i < end:
        if i + 2 > end:
            m.error = "truncated tag"
            return m
        t, ln = raw[i], raw[i + 1]
        if i + 2 + ln > end:
            m.error = f"tag {t:02X} overruns root"
            return m
        m.tags[t] = raw[i + 2 : i + 2 + ln]
        m.order.append(t)
        i += 2 + ln
    if end != len(raw):
        m.error = f"{len(raw) - end} trailing bytes after root"
    return m


def decode_uid(uid: bytes) -> dict[str, str]:
    """Coprocessor UID (E0C2), SRM 'Coprocessor UID OPTIGA Trust Family'."""
    if len(uid) < 27:
        return {"raw": uid.hex()}
    return {
        "cim_id": uid[0:1].hex(),
        "platform_id": uid[1:2].hex(),
        "model_id": uid[2:3].hex(),
        "rom_mask_id": uid[3:5].hex(),
        "chip_type": uid[5:11].hex(),
        "batch": uid[11:17].hex(),
        "wafer_x": uid[17:19].hex(),
        "wafer_y": uid[19:21].hex(),
        "firmware_id": uid[21:25].hex(),
        "esw_build": uid[25:27].hex(),
    }
