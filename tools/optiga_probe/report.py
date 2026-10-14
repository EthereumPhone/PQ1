#!/usr/bin/env python3
"""Analyse an OPTIGA probe log (`make optiga-probe-hw`) and give a verdict.

Usage:
    report.py LOG [--out DIR] [--json]

Reads the semihosting log the probe image printed, decodes every metadata
blob, checks each object against the SRM semantics, the factory reference and
the firmware's own profiles, applies the ship-blocker rules, and writes
<DIR>/<uid>-<timestamp>.{md,json}.

Exit status: 0 = completed, no finding at MEDIUM or above;
             1 = completed with findings;
             2 = inconclusive (probe did not finish, or no data).
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

import expected as exp  # noqa: E402
from optiga_meta import (  # noqa: E402
    DATA_TYPES,
    LAST_ERROR,
    LCS,
    Ctx,
    decode_uid,
    eval_ac,
    parse_ac,
    parse_meta,
)

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
TOKEN = re.compile(r"(\w+)=(\S+)")


@dataclass
class Finding:
    sev: str
    rule: str
    msg: str
    oid: int | None = None

    def as_dict(self) -> dict:
        return {"severity": self.sev, "rule": self.rule, "oid": f"{self.oid:04X}" if self.oid is not None else None, "message": self.msg}


@dataclass
class ReadRes:
    ok: bool
    length: int = 0
    fp: str | None = None
    lec: int | None = None
    link: str | None = None
    cls: str = ""


@dataclass
class Run:
    mode: str = "?"
    board: str = "?"
    done: bool = False
    aborted: str | None = None
    uid: bytes = b""
    meta: dict[str, dict[int, bytes]] = field(default_factory=dict)  # phase -> oid -> raw
    meta_err: dict[str, dict[int, str]] = field(default_factory=dict)
    data: dict[int, dict[int, bytes]] = field(default_factory=dict)  # oid -> off -> bytes (plain, R4)
    reads: dict[tuple[str, int, str], ReadRes] = field(default_factory=dict)  # (phase, oid, ch)
    sec: list[tuple[str, int | None]] = field(default_factory=list)
    pbs: dict[str, str] = field(default_factory=dict)
    shields: list[dict[str, str]] = field(default_factory=list)
    seqs: list[tuple[str, int]] = field(default_factory=list)  # ("slave"/"master", value)
    sweep_hits: list[tuple[int, str]] = field(default_factory=list)
    fw_findings: list[tuple[str, str]] = field(default_factory=list)
    restarts: list[dict[str, str]] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)
    tier_lines: list[str] = field(default_factory=list)
    names: dict[int, str] = field(default_factory=dict)


def _hexb(s: str) -> bytes:
    try:
        return bytes.fromhex(s)
    except ValueError:
        return b""


def parse_log(text: str) -> Run:
    run = Run()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if "=== OPROBE DONE ===" in line:
            run.done = True
            continue
        if "=== OPROBE ABORT" in line or "=== OPROBE REFUSED" in line:
            run.aborted = run.aborted or line
            continue
        m = re.search(r"\[OPTIGA/shield\] (slave|master)_seq=(0x[0-9a-fA-F]+)", line)
        if m:
            run.seqs.append((m.group(1), int(m.group(2), 16)))
            continue
        idx = line.find("[OPROBE] ")
        if idx < 0:
            continue
        body = line[idx + len("[OPROBE] ") :]
        kind, _, rest = body.partition(" ")
        kv = dict(TOKEN.findall(rest))
        if kind == "BEGIN":
            run.mode = kv.get("mode", "?")
            run.board = kv.get("board", "?")
        elif kind == "UID" and "hex" in kv:
            run.uid = _hexb(kv["hex"])
        elif kind == "META":
            phase = kv.get("phase", "?")
            oid = int(kv.get("oid", "0"), 16)
            if "name" in kv:
                run.names[oid] = kv["name"]
            if "hex" in kv:
                run.meta.setdefault(phase, {})[oid] = _hexb(kv["hex"])
            else:
                run.meta_err.setdefault(phase, {})[oid] = rest
        elif kind == "DATA" and "hex" in kv and kv.get("ch") == "plain" and kv.get("phase") == "R4":
            oid = int(kv["oid"], 16)
            run.data.setdefault(oid, {})[int(kv.get("off", "0"))] = _hexb(kv["hex"])
        elif kind == "READ":
            key = (kv.get("phase", "?"), int(kv.get("oid", "0"), 16), kv.get("ch", "?"))
            res = kv.get("res", "?")
            rr = ReadRes(ok=res == "ok", cls=kv.get("class", ""))
            if res == "ok":
                rr.length = int(kv.get("len", "0"))
                rr.fp = kv.get("fp")
            elif res == "deny":
                lec = kv.get("lec", "??")
                rr.lec = int(lec, 16) if lec != "??" else None
            else:
                rr.link = kv.get("kind", "?")
            run.reads[key] = rr
        elif kind == "SEC":
            val = kv.get("val")
            run.sec.append((kv.get("phase", "?"), int(val) if val is not None else None))
        elif kind == "PBS":
            run.pbs = kv
        elif kind == "SHIELD":
            run.shields.append(kv)
        elif kind == "SWEEP" and "oid" in kv:
            run.sweep_hits.append((int(kv["oid"], 16), rest))
        elif kind == "FINDING":
            msg = rest.split("msg=", 1)[1] if "msg=" in rest else rest
            run.fw_findings.append((kv.get("id", "?"), msg))
        elif kind == "RESTART":
            run.restarts.append(kv)
        elif kind == "STEP":
            run.steps.append(rest)
        elif kind == "ABORT":
            run.aborted = body
        elif kind in ("TIER", "CASE", "FUZZ", "TEAR", "LUC", "THROTTLE", "ATTACK", "SETUP", "LOCK", "REFUSED"):
            run.tier_lines.append(body)
    return run


def object_data(run: Run, oid: int) -> bytes:
    chunks = run.data.get(oid, {})
    return b"".join(chunks[k] for k in sorted(chunks))


def classify(oid: int, raw: bytes, factory: dict[int, str]) -> str:
    m = parse_meta(raw)
    if m.error:
        return "MALFORMED"
    view = m.security_view()
    labels = []
    f = factory.get(oid)
    if f is not None:
        fm = parse_meta(bytes.fromhex(f))
        if not fm.error and fm.security_view() == view:
            labels.append("factory")
    for name, prof in exp.FIRMWARE_PROFILES.get(oid, {}).items():
        if all(view.get(t) == bytes.fromhex(v) for t, v in prof.items()):
            labels.append(f"firmware: {name}")
    return "; ".join(labels) if labels else "UNKNOWN"


def analyse(run: Run) -> tuple[list[Finding], dict]:
    F: list[Finding] = []
    add = lambda sev, rule, msg, oid=None: F.append(Finding(sev, rule, msg, oid))  # noqa: E731
    factory = exp.load_factory()
    r3 = run.meta.get("R3", {})
    metas = {oid: parse_meta(raw) for oid, raw in r3.items()}

    if not run.done:
        add("HIGH", "INCOMPLETE", f"probe did not finish ({run.aborted or 'no DONE line'}); conclusions below are partial")
    if not r3:
        add("HIGH", "NO_DATA", "no R3 metadata in the log")

    # Global lifecycle values feed the AC evaluator.
    def first_byte(oid: int) -> int | None:
        d = object_data(run, oid)
        return d[0] if d else None

    lcsg, lcsa = first_byte(0xE0C0), first_byte(0xF1C0)

    # Firmware-side findings are always surfaced.
    fw_sev = {
        "META_CHANGED": "CRITICAL",
        "KEY_DATA_READABLE": "CRITICAL",
        "SEC_RISE": "HIGH",
        "SEC_HIGH": "HIGH",
    }
    for fid, msg in run.fw_findings:
        add(fw_sev.get(fid, "MEDIUM"), f"FW_{fid}", msg)

    # Per-object checks.
    objects = []
    for oid in sorted(set(r3) | set(run.meta_err.get("R3", {}))):
        m = metas.get(oid)
        name = run.names.get(oid, "")
        entry = {"oid": f"{oid:04X}", "name": name}
        if m is None:
            entry["metadata"] = "unreadable: " + run.meta_err.get("R3", {}).get(oid, "?")
            objects.append(entry)
            add("MEDIUM", "META_UNREADABLE", f"{oid:04X} {name}: metadata read failed", oid)
            continue
        entry["metadata_hex"] = m.raw.hex()
        entry["metadata"] = m.describe()
        entry["state"] = classify(oid, m.raw, factory)
        if m.error:
            add("HIGH", "META_MALFORMED", f"{oid:04X}: {m.error}", oid)
        ctx_plain = Ctx(shielded=False, lcso=m.lcso, lcsa=lcsa, lcsg=lcsg)

        # Who can change it right now, in plaintext, without any authorization?
        change = m.ac(0xD0)
        if change is not None:
            entry["change_plain_noauth"] = eval_ac(change, ctx_plain)
            if change.error:
                add("MEDIUM", "AC_UNPARSED", f"{oid:04X} Change {change.text()}", oid)
            if entry["change_plain_noauth"] is True and oid in exp.WALLET_OIDS:
                add("HIGH", "WALLET_OBJECT_WRITABLE",
                    f"{oid:04X} ({exp.WALLET_OIDS[oid]}) can be rewritten by anyone on the I2C bus, no auth "
                    f"(Change=[{change.text()}], LcsO={LCS.get(m.lcso or 0, m.lcso)})", oid)
        read = m.ac(0xD1)
        rr = run.reads.get(("R4", oid, "plain")) or run.reads.get(("R5", oid, "plain"))
        if rr is not None:
            entry["plain_read"] = "ok" if rr.ok else (f"deny lec={rr.lec:02x}" if rr.lec is not None else f"link {rr.link}")
            if rr.ok and rr.fp:
                entry["data_fp"] = rr.fp
                entry["data_len"] = rr.length
            expect = eval_ac(read, ctx_plain) if read is not None else None
            entry["read_ac_expects_plain_noauth"] = expect
            if rr.ok and expect is False:
                add("CRITICAL", "AC_NOT_ENFORCED",
                    f"{oid:04X} returned {rr.length} bytes in plaintext without auth although Read=[{read.text()}]", oid)
            if rr.ok and rr.cls == "secret" and rr.length and oid in exp.WALLET_OIDS:
                sev = "CRITICAL" if oid in exp.SECRET_READ_OIDS or oid == 0xF1D0 else "HIGH"
                add(sev, "SECRET_READABLE_PLAIN",
                    f"{oid:04X} ({exp.WALLET_OIDS[oid]}) readable in plaintext with no auth: {rr.length} bytes (fp {rr.fp})"
                    + (f"; Read=[{read.text()}]" if read else ""), oid)
            if not rr.ok and rr.lec is not None and expect is True and rr.cls not in ("key", "session"):
                add("LOW", "AC_STRICTER",
                    f"{oid:04X} refused a plaintext read (lec {rr.lec:02x} {LAST_ERROR.get(rr.lec, '')}) although "
                    f"Read=[{read.text() if read else '?'}] allows it", oid)
        objects.append(entry)

    # S-1: F1D0 frozen with a non-ALW Change rule.
    m = metas.get(0xF1D0)
    if m is not None:
        ch = m.ac(0xD0)
        if m.lcso != 0x07:
            add("HIGH", "S1_AUTHREF_NOT_LOCKED",
                f"F1D0 LcsO={LCS.get(m.lcso or 0, m.lcso)}: below Operational its metadata (incl. Change) stays rewritable", 0xF1D0)
        if ch is not None and ch.terms and ch.terms[0].ident == "ALW" and len(ch.terms) == 1:
            add("HIGH", "S1_AUTHREF_CHANGE_ALW", "F1D0 Change=ALW: anyone can replace the PIN AuthRef", 0xF1D0)
        # S-3: silicon PIN lockout bound to E120.
        ex = m.ac(0xD3)
        if ex is None or 0xE120 not in ex.references("Luc"):
            add("HIGH", "S3_NO_SILICON_LOCKOUT",
                f"F1D0 Execute=[{ex.text() if ex else 'absent'}]: no LUC(E120) binding, PIN attempts are not limited in silicon", 0xF1D0)
    m = metas.get(0xE120)
    if m is not None and 0xF1D0 not in (m.ac(0xD0).references("Auto") if m.ac(0xD0) else []):
        add("MEDIUM", "S3_COUNTER_CHANGE",
            f"E120 Change=[{m.ac(0xD0).text() if m.ac(0xD0) else 'absent'}]: not Auto(F1D0)", 0xE120)
    ctr = object_data(run, 0xE120)
    if len(ctr) == 8:
        cur, lim = int.from_bytes(ctr[:4], "big"), int.from_bytes(ctr[4:], "big")
        add("INFO", "E120_VALUE", f"E120 counter {cur}/{lim}", 0xE120)

    # #116: secret Read AC must need the shielded connection too.
    for oid in exp.SECRET_READ_OIDS:
        m = metas.get(oid)
        if m is None:
            continue
        rd = m.ac(0xD1)
        if rd is None:
            continue
        has_auto = bool(rd.references("Auto"))
        conf_and = "Conf" in [t.ident for t in rd.terms] and "&&" in rd.joins
        if has_auto and not conf_and:
            add("HIGH", "ISSUE116_WEAK_READ",
                f"{oid:04X} Read=[{rd.text()}]: PIN auth alone releases it in plaintext (pre-#116 shape)", oid)
        elif rd.text() == "ALW":
            used = int.from_bytes(m.tags.get(0xC5, b"\x00"), "big")
            add("MEDIUM" if used else "INFO", "SECRET_SLOT_UNPROTECTED",
                f"{oid:04X} Read=ALW (factory default), used size {used}", oid)

    # S-2: trust-anchor pool and certificate slots.
    for oid in exp.TRUST_ANCHOR_POOL:
        m = metas.get(oid)
        if m is None:
            continue
        ch = m.ac(0xD0)
        writable = eval_ac(ch, Ctx(lcso=m.lcso, lcsa=lcsa, lcsg=lcsg)) if ch else None
        dtype = DATA_TYPES.get(m.data_type, m.data_type)
        if m.data_type == 0x11 and m.lcso != 0x07:
            add("HIGH", "S2_TA_POOL_OPEN",
                f"{oid:04X} is a trust anchor (type {dtype}) at LcsO={LCS.get(m.lcso or 0, m.lcso)}, "
                f"Change=[{ch.text() if ch else '?'}] -> {'writable without auth' if writable else 'not freely writable'}", oid)
        users = [o for o, mm in metas.items() for t in (0xD0, 0xD1, 0xD3, 0xD8) if mm.ac(t) and oid in mm.ac(t).references("Int")]
        if users:
            add("HIGH" if writable else "MEDIUM", "S2_TA_REFERENCED",
                f"{oid:04X} is referenced by Int() in {', '.join(f'{u:04X}' for u in sorted(set(users)))}", oid)
    for oid in exp.CERT_OIDS:
        m = metas.get(oid)
        if m is not None and m.data_type not in (0x12, None):
            add("MEDIUM", "S2_CERT_RETYPED", f"{oid:04X} data type {DATA_TYPES.get(m.data_type, m.data_type)} (expected DEVCERT)", oid)

    # E140.
    m = metas.get(0xE140)
    rr = run.reads.get(("R4", 0xE140, "plain"))
    if rr is not None and rr.ok and rr.length:
        add("HIGH", "PBS_READABLE_PLAIN",
            f"E140 (PBS) readable in plaintext at LcsO={LCS.get((m.lcso if m else 0) or 0, '?')}: "
            "anyone on the bus can read the pairing secret and impersonate the host", 0xE140)
    if run.pbs:
        pm = run.pbs.get("match")
        prefix = run.pbs.get("build_prefix", "")
        known = exp.KNOWN_PBS_PREFIXES.get(prefix, "unknown root")
        if pm == "1":
            add("INFO", "PBS_MATCH", f"E140 holds this build's PBS (prefix {prefix}, {known})", 0xE140)
        elif pm == "0":
            add("INFO", "PBS_OTHER", f"E140 holds a PBS other than this build's ({known}); chip paired by another image", 0xE140)

    # Shielded checks.
    for (phase, oid, ch), rr in run.reads.items():
        if ch == "shield" and rr.ok and rr.length and oid in exp.SECRET_READ_OIDS + (0xF1D0,):
            add("CRITICAL", "SECRET_READABLE_SHIELD_NOAUTH",
                f"{oid:04X} readable over the shielded channel without PIN auth ({rr.length} bytes)", oid)
    slaves = [v for k, v in run.seqs if k == "slave"]
    masters = [v for k, v in run.seqs if k == "master"]
    for i, (s, mm) in enumerate(zip(slaves, masters), 1):
        if s > mm:
            add("MEDIUM", "CCM_SEQ_OVERLAP",
                f"handshake {i}: slave_seq={s:#x} > master_seq={mm:#x}; the host's record counter (master_seq+1) "
                f"reaches the MasterFinished nonce after {s - mm} records (CCM nonce-reuse precondition)")
        else:
            add("INFO", "CCM_SEQ", f"handshake {i}: slave_seq={s:#x} master_seq={mm:#x}")

    # SEC timeline.
    vals = [v for _, v in run.sec if v is not None]
    if vals:
        add("INFO", "SEC", "SEC timeline: " + ", ".join(f"{p}={v}" for p, v in run.sec))

    # Sweep.
    for oid, rest in run.sweep_hits:
        sev = "HIGH" if "meta=" in rest else "MEDIUM"
        add(sev, "UNDOCUMENTED_OID", f"{oid:04X} answers outside the SRM inventory: {rest}", oid)

    # Objects in states the references do not explain.
    for e in objects:
        if e.get("state") == "UNKNOWN":
            add("LOW", "UNEXPLAINED_METADATA", f"{e['oid']} {e['name']}: {e.get('metadata')}", int(e["oid"], 16))

    summary = {
        "mode": run.mode,
        "board": run.board,
        "completed": run.done,
        "uid": run.uid.hex(),
        "uid_decoded": decode_uid(run.uid) if run.uid else {},
        "objects": objects,
        "pbs": run.pbs,
        "shield": run.shields,
        "sec": run.sec,
        "restarts": run.restarts,
        "tier_lines": run.tier_lines,
    }
    F.sort(key=lambda f: SEVERITY_ORDER.index(f.sev))
    return F, summary


def render_md(findings: list[Finding], s: dict) -> str:
    out = [f"# OPTIGA probe report — UID {s['uid'] or '?'}", ""]
    out.append(f"- mode: {s['mode']}, board: {s['board']}, completed: {s['completed']}")
    if s["uid_decoded"]:
        out.append("- UID: " + ", ".join(f"{k}={v}" for k, v in s["uid_decoded"].items()))
    out += ["", "## Findings", ""]
    if not findings:
        out.append("None.")
    for f in findings:
        out.append(f"- **{f.sev}** `{f.rule}` — {f.msg}")
    out += ["", "## Objects", "", "| OID | name | state | plaintext read | metadata |", "|---|---|---|---|---|"]
    for e in s["objects"]:
        out.append(f"| {e['oid']} | {e['name']} | {e.get('state', '')} | {e.get('plain_read', '')} | {e.get('metadata', '')} |")
    if s["tier_lines"]:
        out += ["", "## Destructive tier log", "", "```"] + s["tier_lines"] + ["```"]
    return "\n".join(out) + "\n"


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log", type=Path)
    ap.add_argument("--out", type=Path, default=Path("target/optiga-probe"))
    ap.add_argument("--json", action="store_true", help="print the JSON report to stdout")
    a = ap.parse_args(argv)
    run = parse_log(a.log.read_text(errors="replace"))
    findings, summary = analyse(run)
    a.out.mkdir(parents=True, exist_ok=True)
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    base = a.out / f"{(run.uid.hex()[:16] or 'nouid')}-{run.mode}-{stamp}"
    report = {"summary": summary, "findings": [f.as_dict() for f in findings]}
    base.with_suffix(".json").write_text(json.dumps(report, indent=2, default=str))
    base.with_suffix(".md").write_text(render_md(findings, summary))
    (base.parent / (base.name + ".log")).write_text(a.log.read_text(errors="replace"))
    if a.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        for f in findings:
            print(f"{f.sev:8} {f.rule:32} {f.msg}")
    print(f"\nreport: {base}.md")
    if not run.done or not run.meta.get("R3"):
        print("VERDICT: INCONCLUSIVE")
        return 2
    serious = [f for f in findings if SEVERITY_ORDER.index(f.sev) <= SEVERITY_ORDER.index("MEDIUM")]
    print(f"VERDICT: {'FINDINGS' if serious else 'CLEAN'} ({len(serious)} at MEDIUM or above)")
    return 1 if serious else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
