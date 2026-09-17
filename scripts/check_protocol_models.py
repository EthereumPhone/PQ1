#!/usr/bin/env python3
"""verify-protocol-models — a regression GATE for the design-layer protocol
proofs (ProVerif / Tamarin / CryptoVerif). It is the third sibling of the repo's
anti-vacuity gates (`verify-proof-mutation` for Lean, `verify-kani-mutation` for
the firmware harnesses).

WHY a gate and not just `make proverif`/`tamarin`/`cryptoverif`: those targets
RUN the tools but exit 0 whether a query is true or false — and these models
carry DESIGNED `is false` residuals (positive controls + documented leak-
residuals). So a bare run is NOT a gate: a security query silently flipping
true->false, or a lemma falsifying, would go unnoticed between manual re-runs.
This asserts each model's verdict pattern against a committed per-file baseline;
any drift (a true->false flip, a falsified lemma, a lost proof, or a tool/parse
failure that zeroes the counts) exits non-zero.

SCOPE (upgraded 2026-07-16, FV review finding F7 — reopens PM-2). This is now a
verdict-IDENTITY gate, not just a verdict-COUNT tripwire:

  1. NONZERO PROVER EXIT IS A FAILURE, checked BEFORE any output parsing.
     proverif 2.05 and tamarin 1.12 both exit 0 on success EVEN with designed
     `is false` residuals (verified on every in-tree model 2026-07-16), so a
     nonzero code cleanly means the tool crashed / could not parse — it must not
     be read as "0 queries, all fine". The pre-fix driver discarded the child
     return code entirely, so a prover that died mid-run (or a synthetic process
     that printed the expected banner and exited 42) passed. It no longer does.

  2. PER-QUERY / PER-LEMMA IDENTITY, not just counts. Each ProVerif RESULT line
     is parsed to (normalized query text -> verdict) and each Tamarin lemma to
     (lemma name -> verdict), then compared as an EXACT DICT against the
     committed baseline. A same-count semantic substitution (e.g. changing the
     authenticity query `Install(m) ==> Sign(m)` to the tautology
     `Install(m) ==> Install(m)`) keeps the true/false COUNTS identical but
     changes the query TEXT, so it now fails. Counts + `cannot be proved`==0 are
     retained as belt-and-braces.

  3. TAMARIN FORMULA PINS (2026-08-20, FV red-team #665). A lemma NAME+verdict
     pin is not enough: gutting the quoted formula to `"T"` keeps the lemma
     name AND the `verified` verdict, and that passed the gate (demonstrated
     2026-08-20). The baseline therefore also pins sha256 of each lemma's
     whitespace-normalized formula (quantifier annotation included), parsed
     from the .spthy SOURCE — this fires before tamarin is even run.

  4. RAW RESULT-LINE COUNT + CRYPTOVERIF IDENTITY (2026-08-20, #666). The
     parsed ProVerif dict absorbs a DUPLICATED RESULT line (same normalized
     key, same verdict -> one dict entry), so the raw `^RESULT ` line count
     per file is pinned too. CryptoVerif's gate was a bare substring check
     (`All queries proved`); its RESULT lines are now parsed into a pinned
     per-query identity dict, with the tool version recorded in the baseline
     (CryptoVerif 2.12).

  5. COMPLETE TAMARIN SOURCE IDENTITY (2026-09-17). Tamarin's comment,
     quoting and preprocessing grammar cannot safely be approximated by a
     formula regex. SHA-256 therefore binds every byte of each committed
     model BEFORE formula extraction or prover execution. Any source edit,
     including comments, requires explicit re-baselining after model/formula
     review and prover replay. Formula and verdict pins remain separate checks
     on those exact models; none of the pinned models uses includes.

ProVerif fresh-variable suffixes (`c_2`, `p_6`, `m_1`, ...) are numbered
per-run, so the query text is normalized `_[0-9]+ -> _N` before comparison; the
predicate/structure — the security-relevant part — is exact.

Families (select with the PROTOCOL_MODELS env var, comma-separated; default all):
  * proverif    — 5 .pv (dual-SE unlock, SCP03 handshake+replay, OPTIGA shield,
                  FW-update authenticity)
  * tamarin     — 3 .spthy (PIN-lockstep, SCP03 replay, seed-split XOR)
  * cryptoverif — 1 .cv (seed-split secrecy, computational)
CI runs `PROTOCOL_MODELS=proverif,tamarin` — an EXPLICIT 2-family subset (the 8
symbolic models). CryptoVerif is local-only on purpose: its ONE property
(seed-split secrecy) is already symbolically gated by tamarin/seed_split_xor.spthy
— the .cv is the computational belt-and-braces. This is a stated subset, not a
silent skip.

Baselines were produced by ProVerif 2.05 / Tamarin 1.12.0 / Maude 3.5.1 /
CryptoVerif 2.12 — the CI job pins those exact versions, else the counts can
shift for reasons unrelated to any real regression. Update the baselines below
(and note it) when a model legitimately changes.

Exit: 0 = every in-scope model matches its baseline; 1 = a regression (drifted
count/identity / falsified / lost proof); 2 = harness error (tool missing, file
absent, nonzero prover exit).

Self-test: `check_protocol_models.py --self-test` runs the WIRED-IN NEGATIVE
CONTROL (no tools needed): it feeds each pure checker a corrupted input
(the `Install=>Install` substitution, a verified->falsified flip, a nonzero
exit, a missing lemma, a duplicated RESULT line, a lemma gutted to `"T"`, a
deleted/unproved CryptoVerif query) and asserts each fires, plus clean inputs
that must NOT fire. Proves the gate is not vacuous. CI runs it alongside the
live gate.
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
PV_DIR = REPO_ROOT / "contracts" / "verification" / "proverif"
TAM_DIR = REPO_ROOT / "contracts" / "verification" / "tamarin"

# --------------------------------------------------------------------------- #
# COMMITTED BASELINES — captured from ProVerif 2.05 / Tamarin 1.12.0, 2026-07-16.
# Update (and note) when a model legitimately changes.
# --------------------------------------------------------------------------- #
# ProVerif: {file: {normalized_query: verdict_bool}} — verdict True = "is true".
PROVERIF_IDENTITY: dict[str, dict[str, bool]] = {
    "dual_se_unlock.pv": {
        "not attacker(reconstruct(hoB[],heB[]))": True,
        "not attacker(reconstruct(ho1[],he1[]))": True,
        "not attacker(reconstruct(ho2[],he2[]))": True,
        "not attacker(reconstruct(hoP[],heP[]))": False,
        "event(ReleasedHalfO(h,p_N)) ==> event(PresentedPinO(p_N))": True,
        "event(ReleasedHalfE(h,p_N)) ==> event(PresentedPinE(p_N))": True,
        "not event(ReleasedHalfO(h,p_N))": False,
        "not event(ReleasedHalfE(h,p_N))": False,
    },
    "scp03_handshake.pv": {
        "not attacker(pinB[])": True,
        "event(HostAccepted(h,c_N)) ==> event(CardSent(h,c_N))": True,
        "event(CardAccepted(h,c_N)) ==> event(HostSent(h,c_N))": True,
        "not event(CardSent(h,c_N))": False,
        "not event(HostAccepted(h,c_N))": False,
        "not event(HostSent(h,c_N))": False,
        "not event(CardAccepted(h,c_N))": False,
        "not attacker(pinR[])": False,
    },
    "optiga_shield_handshake.pv": {
        "not attacker(halfOB[])": True,
        "event(HostAccepted(h,c)) ==> event(OptSent(h,c))": True,
        "event(OptAccepted(h,c)) ==> event(HostSent(h,c))": True,
        "not event(HostAccepted(h,c))": False,
        "not event(OptAccepted(h,c))": False,
        "not attacker(halfOR[])": False,
    },
    # M3 (2026-07-17): the handshake RE-DERIVED from Infineon's reference
    # implementation (github.com/Infineon/optiga-trust-m v5.6.0,
    # src/comms/ifx_i2c/ifx_i2c_presentation_layer.c) rather than from our own
    # driver. Note the LAST entry: injective agreement is pinned FALSE, and that
    # is the finding, not a failure. The real handshake has ONE nonce and the
    # host does not supply it (prl.random is memcpy'd out of the received
    # SlaveHello at :497; the PRF seed is that value alone at :302-313), so the
    # host contributes no freshness and cannot make a session distinct. The
    # sibling optiga_shield_handshake.pv, derived from shield.rs, invented a
    # host nonce and answers this SAME query `true`. If this ever flips to true,
    # the model has drifted back toward the driver's fiction.
    "optiga_shield_handshake_vendor.pv": {
        "not attacker(halfOB[])": True,
        "event(HostAcceptedOpt(r)) ==> event(OptSentHello(r))": True,
        "event(OptAcceptedHost(r)) ==> event(HostSentFinished(r))": True,
        "not event(HostAcceptedOpt(r))": False,
        "not event(OptAcceptedHost(r))": False,
        "not attacker(halfOR[])": False,
        "inj-event(HostAcceptedOpt(r)) ==> inj-event(OptSentHello(r))": False,
    },
    "scp03_replay.pv": {
        "event(Accept(ctr_N,cmd_N)) ==> event(Send(ctr_N,cmd_N))": True,
        "not event(Accept(ctr_N,cmd_N))": False,
    },
    "fw_update_authenticity.pv": {
        "event(Install(m_N)) ==> event(Sign(m_N))": True,
        "not event(Install(m_N))": False,
    },
}
# Raw `^RESULT ` line count per ProVerif file (2026-08-20, #666): the parsed
# identity dict absorbs a DUPLICATED RESULT line (same normalized key, same
# verdict collapses to one entry), so a model padding its output with a twin
# would stay green. The raw count closes that hole.
PROVERIF_RESULT_COUNT: dict[str, int] = {
    "dual_se_unlock.pv": 8,
    "scp03_handshake.pv": 8,
    "optiga_shield_handshake.pv": 6,
    "optiga_shield_handshake_vendor.pv": 8,
    "scp03_replay.pv": 2,
    "fw_update_authenticity.pv": 2,
}
# Tamarin: {file: {lemma_name: {"verdict": "verified"|"falsified",
#                               "formula_sha256": <sha256>}}}.
# formula_sha256 (2026-08-20, #665) is sha256 of `<annotation>\n<formula>` where
# <annotation> is `exists-trace`/`all-traces` (absent == all-traces, tamarin's
# default) and <formula> is the lemma's quoted body with whitespace runs
# collapsed. Gutting a lemma to `"T"` (or any semantic weakening that keeps the
# name and verdict) changes this hash and now FAILS.
TAMARIN_IDENTITY: dict[str, dict[str, dict[str, str]]] = {
    "pin_lockstep.spthy": {
        "honest_boot_possible": {
            "verdict": "verified",
            "formula_sha256": "56a63c75d16f03e930809c69c36b078398a7cc3105e3d7d03b64ad90c4cd6751",
        },
        "fresh_synced_means_no_reset": {
            "verdict": "verified",
            "formula_sha256": "682c3d589d30a6582e123e94f55cadbc8fb37095befe4f7b8d30193dc6da5d4a",
        },
        "zero_synced_means_all_reset": {
            "verdict": "verified",
            "formula_sha256": "e1d799472b62ddeda6618e3b93d83139580c51af2e99243f14840d72073e5f72",
        },
        "full_reset_bypass": {
            "verdict": "verified",
            "formula_sha256": "66c35f480d3cac099d028d64db6cb26ef8787b6a60f2ab14db41524e2710aee8",
        },
    },
    "scp03_replay.spthy": {
        "can_accept": {
            "verdict": "verified",
            "formula_sha256": "10943dc12951a6a57f8337cb005a63ae23aa071aa51612543b4ad29b1c9a0d3b",
        },
        "no_replay": {
            "verdict": "verified",
            "formula_sha256": "05c0034e00ed798e8d06ff68b3ada0b5bb7a56959f7d5ab43f96a4b4da97fb49",
        },
    },
    "seed_split_xor.spthy": {
        "seed_secret_under_single_compromise": {
            "verdict": "verified",
            "formula_sha256": "89a79c34645ae8264b9950bdff88fa5763645e1536740c23cf0bb90b666cd170",
        },
        "both_compromised_leaks_seed": {
            "verdict": "verified",
            "formula_sha256": "48785e24ec558121530b21a9dd400ce6c5b4290b37747cb0851c86599db67b80",
        },
    },
}
# Full UTF-8 source bytes, independent of the textual formula extractor.
# These are reviewed input identities, never values to regenerate automatically
# merely because a model changed. Current models have no includes/preprocessing.
TAMARIN_SOURCE_SHA256: dict[str, str] = {
    "pin_lockstep.spthy": "46fd87fef7ab8f6f5af1e8ffdfd233478f6b3317649aa60064c70498f50050d2",
    "scp03_replay.spthy": "ddb4f8fe0d41beedd2b5e4c2b994beea10d20bedb2aab209e81c9164162550c4",
    "seed_split_xor.spthy": "e647ecf4253a154cbb6dd5ea5fc70035abaab805ddff133a1a358f76ed09c68e",
}
# CryptoVerif (2026-08-20, #666): the gate was a bare `All queries proved`
# substring check — a deleted query still prints it. The RESULT lines are now
# parsed into a pinned per-query identity dict {query_text: proved_bool}.
# Baseline produced by CryptoVerif 2.12 (opam `checkct` switch).
CRYPTOVERIF_VERSION = "2.12"
CRYPTOVERIF_IDENTITY: dict[str, dict[str, bool]] = {
    "seed_split_secrecy.cv": {
        "secrecy of seed": True,
    },
}


class HarnessError(Exception):
    pass


# --------------------------------------------------------------------------- #
# pure parsers + comparison (unit-testable without the tools)
# --------------------------------------------------------------------------- #
def _norm_query(q: str) -> str:
    """Normalize ProVerif fresh-variable suffixes `_<digits>` -> `_N` so the
    baseline is stable across runs. The predicate structure is preserved."""
    return re.sub(r"_\d+", "_N", q.strip())


def parse_proverif(output: str) -> tuple[dict[str, bool], int, int]:
    """(normalized query -> verdict_bool, cannot_be_proved_count, raw RESULT
    line count) from a run. A duplicated query text (same normalized key,
    conflicting verdict) is a parse ambiguity and raises, so a model cannot
    hide a flip behind a twin. A duplicate with the SAME verdict collapses
    silently into one dict entry — the caller must therefore also compare the
    raw RESULT-line count against PROVERIF_RESULT_COUNT (#666). The raw count
    covers EVERY `RESULT `-prefixed line (including parenthetical `(but …)`
    sub-results, which carry no new verdict and are excluded from the identity
    dict), so a duplicated line of any kind moves it."""
    identity: dict[str, bool] = {}
    raw = sum(1 for line in output.splitlines() if line.startswith("RESULT "))
    for m in re.finditer(r"^RESULT (.+?) is (true|false)\.?\s*$", output, re.MULTILINE):
        key = _norm_query(m.group(1))
        verdict = m.group(2) == "true"
        if key in identity and identity[key] != verdict:
            raise HarnessError(f"conflicting verdicts for normalized query {key!r} "
                               f"— fresh-var normalization is too aggressive for this model")
        identity[key] = verdict
    cannot = output.count("cannot be proved")
    return identity, cannot, raw


def parse_tamarin(output: str) -> dict[str, str]:
    """{lemma_name: verdict} from a `tamarin-prover --prove` run."""
    identity: dict[str, str] = {}
    for m in re.finditer(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\):\s*(verified|falsified)\b",
                         output, re.MULTILINE):
        identity[m.group(1)] = m.group(2)
    return identity


# A tamarin lemma in .spthy SOURCE: `lemma <name>:` then an optional
# `exists-trace`/`all-traces` annotation, then the quoted formula (multi-line).
_SPTHY_LEMMA_RE = re.compile(
    r'lemma\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?:(exists-trace|all-traces)\s+)?"((?:\\.|[^"\\])*)"',
    re.DOTALL,
)


def formula_hash(annotation: str, formula: str) -> str:
    """sha256 of `<annotation>\n<normalized formula>` (#665). Whitespace runs
    collapse to one space, so re-indenting a lemma is hash-stable but ANY
    semantic edit — including gutting the body to `"T"` — moves it."""
    norm = re.sub(r"\s+", " ", formula).strip()
    return hashlib.sha256(f"{annotation}\n{norm}".encode("utf-8")).hexdigest()


def parse_spthy_formulas(source: str) -> dict[str, str]:
    """Extract formulas from an identity-checked committed model.

    This is not a general Tamarin parser. The live gate MUST first bind the
    complete source in check_tamarin_source; arbitrary quoting, preprocessing,
    or included declarations cannot be certified by this textual extractor.
    Source-pin changes require a fresh model/formula review and prover replay.
    """
    out: dict[str, str] = {}
    for m in _SPTHY_LEMMA_RE.finditer(source):
        name, ann, formula = m.group(1), m.group(2) or "all-traces", m.group(3)
        if name in out:
            raise HarnessError(f"duplicate lemma name {name!r} in .spthy source")
        out[name] = formula_hash(ann, formula)
    return out


def parse_cryptoverif(output: str) -> dict[str, bool]:
    """{query_text: proved_bool} from CryptoVerif `RESULT Proved …` /
    `RESULT Could not prove …` lines (#666). The bare `All queries proved`
    banner stays green when a query is DELETED; the identity dict does not."""
    identity: dict[str, bool] = {}
    for line in output.splitlines():
        if not re.match(r"\s*RESULT\b", line):
            continue
        m = re.fullmatch(r"RESULT (Proved|Could not prove) (\S(?:.*\S)?)\.?", line)
        if m is None:
            raise HarnessError(f"malformed CryptoVerif RESULT line: {line!r}")
        query = m.group(2).removesuffix(".")
        if query in identity:
            raise HarnessError(f"duplicate CryptoVerif RESULT for {query!r}")
        identity[query] = m.group(1) == "Proved"
    return identity


def tamarin_verdicts(ident: dict[str, dict[str, str]]) -> dict[str, str]:
    return {k: v["verdict"] for k, v in ident.items()}


def tamarin_formula_pins(ident: dict[str, dict[str, str]]) -> dict[str, str]:
    return {k: v["formula_sha256"] for k, v in ident.items()}


def check_tamarin_source(fname: str, source: str) -> list[str]:
    """Bind the entire model before using its textual formula inventory.

    A changed model cannot hide a live lemma in syntax that the extractor does
    not understand. Source re-baselining is an explicit reviewed artifact change,
    even when its formula inventory or prover verdicts would stay the same.
    """
    expected_source = TAMARIN_SOURCE_SHA256.get(fname, '')
    if not re.fullmatch(r'[0-9a-f]{64}', expected_source):
        raise HarnessError(f'{fname}: missing or malformed complete source pin')
    actual_source = hashlib.sha256(source.encode('utf-8')).hexdigest()
    if actual_source != expected_source:
        return [f'{fname}: SOURCE_DRIFTED — complete model source changed '
                f'(expected {expected_source}, got {actual_source}); '
                'rebaseline only after model/formula review and prover replay']
    expected = tamarin_formula_pins(TAMARIN_IDENTITY[fname])
    got = parse_spthy_formulas(source)
    fails = []
    for name, eh in expected.items():
        if name not in got:
            fails.append(f"{fname}: lemma `{name}` formula is MISSING from the .spthy source "
                         f"(renamed/deleted lemma, or parser drift)")
        elif got[name] != eh:
            fails.append(f"{fname}: lemma `{name}` formula DRIFTED — the quoted lemma body changed "
                         f"(expected sha256 {eh[:16]}…, got {got[name][:16]}…). A gutted/weakened "
                         f"formula keeps the name+verdict but not the hash (#665)")
    for name in got:
        if name not in expected:
            fails.append(f"{fname}: UNEXPECTED lemma `{name}` in .spthy source "
                         f"(new lemma — if intentional, pin it in the baseline)")
    return fails


def diff_identity(fname: str, expected: dict, got: dict) -> list[str]:
    """Exact-dict comparison. Reports missing keys, unexpected extra keys, and
    verdict mismatches — each is a regression."""
    fails = []
    for key, ev in expected.items():
        if key not in got:
            fails.append(f"{fname}: expected result `{key}` is MISSING "
                         f"(lost/renamed proof, or the tool did not emit it)")
        elif got[key] != ev:
            fails.append(f"{fname}: result `{key}` verdict DRIFTED — "
                         f"expected {ev!r}, got {got[key]!r} (a security property flipped)")
    for key, gv in got.items():
        if key not in expected:
            fails.append(f"{fname}: UNEXPECTED result `{key}` = {gv!r} "
                         f"(new/substituted query — if intentional, update the baseline)")
    return fails


# --------------------------------------------------------------------------- #
# live runners
# --------------------------------------------------------------------------- #
def _run(cmd: list[str], cwd: Path, timeout: int) -> tuple[str, int]:
    try:
        cp = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise HarnessError(f"tool not runnable: {cmd[0]!r} not on PATH")
    except subprocess.TimeoutExpired:
        raise HarnessError(f"{' '.join(cmd)} timed out (>{timeout}s)")
    return cp.stdout + cp.stderr, cp.returncode


def check_proverif() -> list[str]:
    fails = []
    for fname, ident in PROVERIF_IDENTITY.items():
        path = PV_DIR / fname
        if not path.exists():
            raise HarnessError(f"proverif model missing: {path}")
        out, rc = _run(["proverif", fname], PV_DIR, 600)
        if rc != 0:
            # proverif exits 0 even on `is false` residuals; nonzero == tool error.
            raise HarnessError(f"proverif exited {rc} on {fname} (crash/parse error, NOT a verdict)")
        got, cannot, raw = parse_proverif(out)
        et = sum(1 for v in ident.values() if v)
        ef = sum(1 for v in ident.values() if not v)
        t = sum(1 for v in got.values() if v)
        f = sum(1 for v in got.values() if not v)
        id_fails = diff_identity(fname, ident, got)
        if cannot != 0:
            id_fails.append(f"{fname}: {cannot} query(ies) `cannot be proved` (expected 0)")
        exp_raw = PROVERIF_RESULT_COUNT[fname]
        if raw != exp_raw:
            id_fails.append(f"{fname}: raw RESULT-line count {raw} != pinned {exp_raw} "
                            f"(a duplicated/dropped RESULT line hides behind the identity dict)")
        mark = "ok  " if not id_fails else "FAIL"
        print(f"    [{mark}] {fname:28s} true={t}/{et} false={f}/{ef} cannot={cannot}/0 "
              f"results={raw}/{exp_raw} (identity: {len(ident)} queries pinned)")
        fails += id_fails
    return fails


def check_tamarin() -> list[str]:
    if set(TAMARIN_SOURCE_SHA256) != set(TAMARIN_IDENTITY):
        raise HarnessError('Tamarin source and formula model inventories differ')
    fails = []
    for fname, ident in TAMARIN_IDENTITY.items():
        path = TAM_DIR / fname
        if not path.exists():
            raise HarnessError(f"tamarin model missing: {path}")
        # Bind the complete source before extracting formulas or invoking the
        # prover: a changed model cannot retain credit via unchanged verdicts.
        src_fails = check_tamarin_source(fname, path.read_bytes().decode('utf-8'))
        if src_fails:
            print(f"    [FAIL] {fname}: source identity/formula mismatch; prover not run")
            fails += src_fails
            continue
        out, rc = _run(["tamarin-prover", "--prove", fname], TAM_DIR, 900)
        if rc != 0:
            raise HarnessError(f"tamarin exited {rc} on {fname} (crash/parse error, NOT a verdict)")
        got = parse_tamarin(out)
        ev = sum(1 for v in ident.values() if v["verdict"] == "verified")
        v = sum(1 for x in got.values() if x == "verified")
        fl = sum(1 for x in got.values() if x == "falsified")
        id_fails = diff_identity(fname, tamarin_verdicts(ident), got) + src_fails
        mark = "ok  " if not id_fails else "FAIL"
        print(f"    [{mark}] {fname:24s} verified={v}/{ev} falsified={fl}/0 "
              f"(identity: {len(ident)} lemmas + formulas pinned)")
        fails += id_fails
    return fails


def check_cryptoverif() -> list[str]:
    # Reuse `make cryptoverif` — it owns the -lib/layout probe (F7: it now tries
    # both `libexec/default` and `bin/default`, the two documented install
    # layouts, so this works on nix AND opam switches).
    out, rc = _run(["make", "cryptoverif"], REPO_ROOT, 600)
    if rc != 0:
        raise HarnessError(f"`make cryptoverif` exited {rc} (tool missing / lib-path / crash):\n"
                           + "\n".join(out.strip().splitlines()[-5:]))
    fname = "seed_split_secrecy.cv"
    expected = CRYPTOVERIF_IDENTITY[fname]
    got = parse_cryptoverif(out)
    id_fails = diff_identity(fname, expected, got)
    if "All queries proved" not in out:
        id_fails.append(f"cryptoverif {fname}: 'All queries proved' not in output")
    mark = "ok  " if not id_fails else "FAIL"
    print(f"    [{mark}] {fname:24s} queries proved={sum(got.values())}/{len(expected)} "
          f"(identity: {len(expected)} queries pinned; baseline from CryptoVerif "
          f"{CRYPTOVERIF_VERSION})")
    return id_fails


FAMILIES = {"proverif": check_proverif, "tamarin": check_tamarin, "cryptoverif": check_cryptoverif}


# --------------------------------------------------------------------------- #
# WIRED-IN NEGATIVE CONTROL (no tools needed)
# --------------------------------------------------------------------------- #
def self_test() -> int:
    print("=== check_protocol_models --self-test (negative control) ===")
    ok = True

    def expect_fire(label: str, fails: list[str]) -> None:
        nonlocal ok
        if fails:
            print(f"  ok: `{label}` caught ({fails[0][:72]}…)")
        else:
            print(f"  FAIL: corruption `{label}` was NOT caught — gate is vacuous here!")
            ok = False

    def expect_clean(label: str, fails: list[str]) -> None:
        nonlocal ok
        if fails:
            print(f"  FAIL: clean input `{label}` produced a failure (always-fires): {fails}")
            ok = False
        else:
            print(f"  ok: clean `{label}` produced no failure (not always-firing)")

    fw = "fw_update_authenticity.pv"
    base = PROVERIF_IDENTITY[fw]

    # Clean control: the real committed output must NOT fire.
    clean_out = ("RESULT event(Install(m_1)) ==> event(Sign(m_1)) is true.\n"
                 "RESULT not event(Install(m_1)) is false.\n")
    got, _, raw = parse_proverif(clean_out)
    if raw != PROVERIF_RESULT_COUNT[fw]:
        raise HarnessError('self-test: clean ProVerif raw result count differs')
    expect_clean("fw baseline", diff_identity(fw, base, got))

    # PoC 1: Install=>Sign substituted by the tautology Install=>Install (SAME
    # true/false counts) — the count-only gate missed this; identity catches it.
    tauto_out = ("RESULT event(Install(m_1)) ==> event(Install(m_1)) is true.\n"
                 "RESULT not event(Install(m_1)) is false.\n")
    got, _, _ = parse_proverif(tauto_out)
    expect_fire("Install=>Install tautology (same count)", diff_identity(fw, base, got))

    # PoC 2: a security query flips true -> false.
    flip_out = ("RESULT event(Install(m_1)) ==> event(Sign(m_1)) is false.\n"
                "RESULT not event(Install(m_1)) is false.\n")
    got, _, _ = parse_proverif(flip_out)
    expect_fire("authenticity query flipped true->false", diff_identity(fw, base, got))

    # PoC 3: `cannot be proved` residual must fire.
    got, cannot, _ = parse_proverif(clean_out + "Query ... cannot be proved.\n")
    fails = diff_identity(fw, base, got) + (
        [f"{fw}: {cannot} cannot"] if cannot else [])
    expect_fire("cannot-be-proved residual", fails)

    # PoC 3b (#666): a DUPLICATED RESULT line — the identity dict absorbs it
    # (same key, same verdict), only the raw count drift catches it.
    dup_out = clean_out + "RESULT event(Install(m_9)) ==> event(Sign(m_9)) is true.\n"
    got, _, raw = parse_proverif(dup_out)
    fails = diff_identity(fw, base, got) + (
        [f"{fw}: raw RESULT-line count {raw} != pinned {PROVERIF_RESULT_COUNT[fw]}"]
        if raw != PROVERIF_RESULT_COUNT[fw] else [])
    expect_fire("duplicated RESULT line (identity-absorbed)", fails)

    # PoC 4: nonzero prover exit with expected banner text (the exit-42 PoC).
    # The live checker raises HarnessError on rc!=0 BEFORE parsing; simulate that
    # contract directly.
    def rc_gate(rc: int) -> list[str]:
        if rc != 0:
            return [f"proverif exited {rc} (crash/parse error, NOT a verdict)"]
        return []
    expect_fire("nonzero exit 42 with expected banner", rc_gate(42))
    expect_clean("zero exit", rc_gate(0))

    # PoC 5 (tamarin): a verified lemma reported falsified.
    tl = "pin_lockstep.spthy"
    tbase = tamarin_verdicts(TAMARIN_IDENTITY[tl])
    tclean = "\n".join(f"  {k} (all-traces): {v} (3 steps)" for k, v in tbase.items())
    expect_clean("tamarin baseline", diff_identity(tl, tbase, parse_tamarin(tclean)))
    tflip = tclean.replace("honest_boot_possible (all-traces): verified",
                           "honest_boot_possible (all-traces): falsified")
    expect_fire("tamarin lemma falsified", diff_identity(tl, tbase, parse_tamarin(tflip)))
    # PoC 6 (tamarin): a lemma silently dropped.
    tdrop = "\n".join(l for l in tclean.splitlines() if "full_reset_bypass" not in l)
    expect_fire("tamarin lemma dropped", diff_identity(tl, tbase, parse_tamarin(tdrop)))

    # PoC 7 (tamarin formula pins, #665): the REAL committed .spthy source must
    # NOT fire; the same source with seed_secret_under_single_compromise gutted
    # to "T" — name and verdict unchanged, exactly the demonstrated bypass —
    # MUST fire.
    sx = "seed_split_xor.spthy"
    if set(TAMARIN_SOURCE_SHA256) != set(TAMARIN_IDENTITY):
        raise HarnessError('self-test: source and formula model inventories differ')
    for name in TAMARIN_IDENTITY:
        expect_clean(f'real {name} complete source and formulas', check_tamarin_source(
            name, (TAM_DIR / name).read_bytes().decode('utf-8')))
    src = (TAM_DIR / sx).read_bytes().decode('utf-8')
    gutted = _SPTHY_LEMMA_RE.sub(
        lambda m: (f'lemma {m.group(1)}:\n    {m.group(2) or "all-traces"}\n    "T"'
                   if m.group(1) == "seed_secret_under_single_compromise" else m.group(0)),
        src)
    if gutted == src:
        raise HarnessError('self-test setup: gut substitution did not apply')
    fails = check_tamarin_source(sx, gutted)
    if not any("SOURCE_DRIFTED" in f for f in fails):
        raise HarnessError(f'expected a full-source DRIFT, got: {fails}')
    expect_fire('tamarin lemma gutted to "T" (same name+verdict)', fails)

    # Full-source identity rejects these semantic substitutions before either
    # textual extraction or prover invocation can credit an unchanged verdict.
    def formula_failures(source: str) -> list[str]:
        if source == src:
            raise HarnessError('self-test setup: source mutation did not apply')
        failures = check_tamarin_source(sx, source)
        return failures if any('SOURCE_DRIFTED' in f for f in failures) else []

    name = 'seed_secret_under_single_compromise'
    declaration = next(m.group() for m in _SPTHY_LEMMA_RE.finditer(src)
                       if m.group(1) == name)
    single_line = ' '.join(declaration.split())
    constant_decoy = (
        'restriction pad: "All x #i. Provisioned(x) @ i ==> not (x = \'"' +
        single_line + '\')"\nlemma ' + name + ': "T"\n' +
        'restriction pad2: "All x #i. Provisioned(x) @ i ==> not (x = \'"\')"')
    expect_fire('tamarin original lemma hidden in a quoted public constant',
                formula_failures(src.replace(declaration, constant_decoy)))
    expect_fire('tamarin rule edit with identical lemma formulas',
                formula_failures(src.replace('Out(ho)', "Out('public')")))
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / sx).write_bytes((src + '\n').encode('utf-8'))
        module = sys.modules[__name__]
        with patch.object(module, 'TAM_DIR', Path(tmp)), \
             patch.object(module, 'TAMARIN_IDENTITY', {sx: TAMARIN_IDENTITY[sx]}), \
             patch.object(module, 'TAMARIN_SOURCE_SHA256', {sx: TAMARIN_SOURCE_SHA256[sx]}), \
             patch.object(module, '_run', side_effect=HarnessError(
                 'self-test: changed model must not invoke the prover')):
            expect_fire('tamarin changed source rejected before prover execution',
                        check_tamarin())
    for label, decoy in (
        ('block comment', '/* ' + declaration + ' */'),
        ('line comments', '\n'.join('// ' + line for line in declaration.splitlines())),
        ('nested comment', '/* outer /* ' + declaration + ' */ outer */'),
    ):
        for attribute in ('', ' [reuse]'):
            changed = src.replace(declaration, decoy + '\nlemma ' + name + attribute + ': "T"')
            expect_fire(f'tamarin {label} decoy with attribute {attribute!r}',
                        formula_failures(changed))
        expect_fire(f'tamarin declaration only in {label}',
                    formula_failures(src.replace(declaration, decoy)))
        expect_fire(f'tamarin added {label} changes complete source',
                     formula_failures(decoy + '\n' + src))

    for attribute in ('reuse', 'sources', 'hide_lemma=other'):
        expect_fire(f'tamarin unsupported live [{attribute}] declaration',
                    formula_failures(src.replace('lemma ' + name + ':',
                                                 'lemma ' + name + f' [{attribute}]:')))
    expect_fire('tamarin header comment requires source rebaseline', formula_failures(
        src.replace('lemma ' + name + ':', 'lemma /* header */ ' + name + ' // header\n:')))
    for label, changed in (
        ('duplicate live declaration', src + '\n' + declaration),
        ('unparsed live declaration', src + '\nlemma unparsed [reuse]: "T"'),
        ('unterminated comment', src + '\n/*'),
        ('unterminated quote', src + '\n"'),
    ):
        expect_fire(f'tamarin {label}', formula_failures(changed))

    # Tamarin recognizes comments inside formula quotes. The complete source
    # pin rejects this restriction decoy before textual formula extraction.
    quoted_decoy = ('restriction pad: "All s #i. Provisioned(s) @ i '
                    '==> Ex #j. Provisioned(s) @ j /* "\n' + declaration +
                    '\n*/ "\nlemma ' + name + ': "T"\n// "')
    expect_fire('tamarin quoted restriction hides a live tautology',
                formula_failures(src.replace(declaration, quoted_decoy)))
    disabled = '#ifdef NEVER\n' + declaration + '\n#endif'
    for label, changed in (
        ('disabled pinned declaration', src.replace(declaration, disabled)),
        ('included declaration', src + '\n#include "other.spthy"'),
        ('disabled original and included replacement',
         src.replace(declaration, disabled + '\n#include "replacement.spthy"')),
        ('inline preprocessor directive', src.replace(declaration, '  #ifdef NEVER\n' + declaration)),
        ('directive after a comment', src + '\n/* header */ #define SOMETHING'),
    ):
        expect_fire(f'tamarin {label}', formula_failures(changed))
    expect_fire('tamarin commented directive requires source rebaseline',
                 formula_failures('/* #include "ignored.spthy" */\n' + src))
    for mark in ('/*', '*/', '//'):
        for quote in ('"', "'"):
            changed = quote + 'prefix ' + mark + ' suffix' + quote + '\n' + src
            expect_fire(f'tamarin quoted comment delimiter {quote}{mark}',
                        formula_failures(changed))

    # PoC 8 (cryptoverif identity, #666): the clean RESULT line must NOT fire;
    # a DELETED query (banner still printed) and a `Could not prove` flip MUST.
    cv = "seed_split_secrecy.cv"
    cvbase = CRYPTOVERIF_IDENTITY[cv]
    cv_clean = "RESULT Proved secrecy of seed\nAll queries proved.\n"
    expect_clean("cryptoverif baseline", diff_identity(cv, cvbase, parse_cryptoverif(cv_clean)))
    cv_deleted = "All queries proved.\n"
    expect_fire("cryptoverif query deleted (banner still green)",
                diff_identity(cv, cvbase, parse_cryptoverif(cv_deleted)))
    cv_flipped = "RESULT Could not prove secrecy of seed\n"
    expect_fire("cryptoverif query unproved", diff_identity(cv, cvbase, parse_cryptoverif(cv_flipped)))

    for label, corrupt in [
        ("failure then success", cv_flipped + cv_clean),
        ("success then failure", cv_clean + cv_flipped),
        ("duplicate success", cv_clean + cv_clean),
        ("punctuation duplicate", cv_clean + "RESULT Proved secrecy of seed.\n"),
        ("malformed result", cv_clean + "RESULT Unknown secrecy of seed\n"),
        ("empty result", cv_clean + "RESULT Proved \n"),
        ("indented result", cv_clean + " RESULT Proved secrecy of seed\n"),
    ]:
        try:
            parse_cryptoverif(corrupt)
        except HarnessError as exc:
            expect_fire(f"cryptoverif {label}", [str(exc)])
        else:
            expect_fire(f"cryptoverif {label}", [])
    expect_fire("cryptoverif unexpected query", diff_identity(
        cv, cvbase, parse_cryptoverif(cv_clean + "RESULT Proved secrecy of other\n")))

    print("=== self-test PASS ===" if ok else "=== self-test FAILED ===")
    return 0 if ok else 1


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        return self_test()

    sel = os.environ.get("PROTOCOL_MODELS", "proverif,tamarin,cryptoverif")
    families = [f.strip() for f in sel.split(",") if f.strip()]
    unknown = [f for f in families if f not in FAMILIES]
    if unknown:
        print(f"ERROR: unknown family/families {unknown} (valid: {list(FAMILIES)})", file=sys.stderr)
        return 2

    print(f"=== verify-protocol-models (families: {', '.join(families)}) ===")
    print("    Assert each design-layer model's per-query/per-lemma verdict IDENTITY vs the")
    print("    committed baseline; nonzero prover exit is a failure (F7, 2026-07-16).\n")

    all_fails = []
    for fam in families:
        print(f"--> {fam}")
        try:
            all_fails += FAMILIES[fam]()
        except HarnessError as e:
            print(f"    HARNESS ERROR: {e}", file=sys.stderr)
            return 2

    print()
    if all_fails:
        print(f"FAIL: {len(all_fails)} protocol-model regression(s):", file=sys.stderr)
        for m in all_fails:
            print(f"  - {m}", file=sys.stderr)
        print("\nA drifted verdict/identity = a model's proof changed. If INTENTIONAL "
              "(you edited a model), update the baseline in scripts/check_protocol_models.py "
              "and note it. Otherwise a security property regressed — investigate.", file=sys.stderr)
        return 1
    print(f"OK: all in-scope protocol models match their per-query/per-lemma identity baseline "
          f"(for the families run).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
