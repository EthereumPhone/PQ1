#!/usr/bin/env python3
"""POLICY-CAP QUARANTINE fence for cdrafts-split/C10DeployedScope.ec.

WHY THIS EXISTS.  That file names the DEPLOYMENT cap `c10_q_s = 65536`
(= MAX_SLOT_USES).  Two external reviewers ruled on 2026-08-15 that importing
that cap into the cryptographic model would make a reusable theorem depend on
one wallet's on-chain policy.  The file may name it ONLY in NEGATIVE statements
about what it CANNOT be.  Until now that held by INSPECTION plus a header
comment: any future closure member could `require` the file and nothing would
notice.

DESIGN NOTE -- WHY THIS IS AN INVENTORY AND NOT A GREP.  The first design was
three token-greps (no file requires it / the identifier is confined / lemmas
mentioning it carry no `=>`).  A 54-agent adversarial review confirmed 33
bypasses of that design.  The decisive ones, each VERIFIED in this repo:

  * RE-DECLARE THE VALUE UNDER ANOTHER NAME.  `op c10_max_slot_uses : int =
    65536.` in the file that wants it, plus a premise, imports the cap with no
    require edge and no occurrence of the token.  This is the HOUSE IDIOM, not a
    contrived attack: C10DeployedGeometry.ec:66 and C10DeployedInstance.ec:44
    both define `c10_n = 16` and neither requires the other.
  * SPELL IT IN MODEL SYMBOLS.  This file itself proves `l = 4 * c10_q_s`, so
    `l %/ 4` denotes 65536 using only model constants -- defeating a token grep,
    a literal grep, AND human review, since it reads as a structural fraction of
    hypertree capacity.
  * `declare axiom` INSIDE A SECTION carries no `=>`, so an arrow test is blind
    to it.

A grep keys on a NAME; the object of concern is a NUMBER IN A PREMISE POSITION.
No enumeration of forbidden syntax closes that.  So this fence does not try.  It
instead makes the quarantine file IMMUTABLE-BY-DEFAULT in the repo's own
"ADDITIONS ARE FATAL" idiom: the complete declaration inventory is committed, and
any addition, removal or rename is a manifest delta a human must approve.

WHAT THIS DOES NOT CLOSE, STATED PLAINLY.  A NEW policy number introduced
ELSEWHERE under a different name (the re-declare and `l %/ 4` routes above) is
NOT closed by this fence -- those touch other files, which this fence does not
inventory.  Closing that class needs exhaustive statement-pin coverage over all
34 closure members (~623 statements), which is a separate project.  This fence
closes the quarantine file itself and the isolation property around it.
"""
import hashlib, re, sys, os
from pathlib import Path

FENCED = 'cdrafts-split/C10DeployedScope.ec'
MANIFEST = 'cert-quarantine-split.tsv'
# COMMITTED ROW COUNTS -- the manifest's own anti-vacuity guard, same idea as
# EXPECT_PINS in cert_gate_split.sh.  ADDED 2026-08-20 after measuring that the
# first version of this fence printed `OK ... quarantine intact` with rc=0
# against a manifest gutted to comments only: `want_decls`/`want_reqs` both came
# back empty, so Q2 and Q4 SILENTLY SKIPPED and the fence reported green while
# checking nothing.  That is the exact vacuous-pass shape this repo's controls
# exist to catch, reproduced inside the control.  A count that lives in the TOOL
# (hashed, and not in the manifest it guards) cannot be zeroed by editing the
# manifest.
EXPECT_DECLS = 24
EXPECT_REQS = 3
# Constructs that could turn a closed-arithmetic leaf into something that can
# carry an assumption.  `declare`/`section` cover the section-hypothesis route;
# `clone` covers the with-clause operand route (`op p_stcr <- c10_q_s`), which
# emits an `operand` census row, not a ledger row, and so is NOT caught by the
# cone census's additions-fatal rule.
FORBIDDEN = ['section', 'declare', 'module', 'proc', 'Pr[', 'clone', 'axiom']
DECL_RE = re.compile(
    r"^(lemma|theorem|axiom|op|abbrev|const|pred|type|module|section|declare|clone|local)"
    r"\s+([A-Za-z0-9_']+)", re.M)
# Every spelling of the deployment magnitude a value-grep can reasonably cover.
# NOT a closure of the class -- see the module docstring; `l %/ 4` defeats this.
# Q5 IS A TRIPWIRE, NOT A RULE: `2 ^ 16` will match legitimate arithmetic in some
# future certified file; do not treat a Q5 hit as proof of a policy import.
# The sole exception below binds an exact source, not a whole file or directory.
MAGNITUDES = [r'\b65536\b', r'\b0x10000\b', r'2\s*\^\s*16', r'\b4\s*\^\s*8\b']
# RawShuffle's sole 65536 occurrence divides a 16-bit multiply-shift index. It is
# unrelated to wallet usage. Any source edit, duplicate occurrence, different
# spelling or different path falls back to the ordinary tripwire. Reviewing a
# changed shuffle source requires deliberately updating this digest as well.
NONPOLICY_MAGNITUDES = {
    ('cdrafts-split/RawShuffle.ec', r'\b65536\b'):
        '2d8c14b922f4e85c7c2a1a8a4852a7622dbff8a87a3e6faf43ff6b13d5e3e639',
}



def strip_comments(s):
    """Strip (nested) EasyCrypt comments, REPLACING each with a separator.

    The first version spliced the surrounding text together, so `lemma(* x *)foo`
    became `lemmafoo` and the declaration went INVISIBLE to every regex keyed on
    `lemma\\s+name` -- unpinned and uncounted, which is an evasion, not a
    formatting quirk.  Newlines inside comments are preserved so that line-anchored
    scans keep their line structure."""
    out, depth, i = [], 0, 0
    while i < len(s):
        if s.startswith('(*', i):
            if depth == 0:
                out.append(' ')
            depth += 1; i += 2; continue
        if s.startswith('*)', i) and depth:
            depth -= 1
            if depth == 0:
                out.append(' ')
            i += 2; continue
        if not depth:
            out.append(s[i])
        elif s[i] == '\n':
            out.append('\n')
        i += 1
    return ''.join(out)


def certified_files():
    fs = []
    for d in ('base-c10-split', 'cdrafts-split'):
        if not os.path.isdir(d):
            continue
        for n in sorted(os.listdir(d)):
            if n.endswith('.ec') or n.endswith('.eca'):
                fs.append(os.path.join(d, n))
    return fs


def main():
    problems = []
    if not os.path.exists(FENCED):
        print(f'FENCED FILE MISSING: {FENCED}'); return 1
    code = strip_comments(open(FENCED, encoding='utf-8').read())

    # ---- Q1  ISOLATION-IN: nothing certified may depend on the fenced file ----
    inbound = [f for f in certified_files()
               if f != FENCED and re.search(r'require[^.\n]*\bC10DeployedScope\b',
                                            strip_comments(open(f, encoding='utf-8').read()))]
    if inbound:
        problems.append('Q1 inbound require(s) on the fenced file: ' + ', '.join(inbound))

    # ---- Q2  ISOLATION-OUT: its own requires match the committed allowlist ----
    reqs = sorted(set(re.findall(r'^require\s+(?:import\s+)?(.+?)\.\s*$', code, re.M)))
    # ---- Q3  SEALED LEAF ----
    for tok in FORBIDDEN:
        if re.search(re.escape(tok), code):
            problems.append(f'Q3 forbidden construct {tok!r} present in the fenced file')

    # ---- Q4  DECLARATION INVENTORY, ADDITIONS FATAL ----
    decls = sorted(f'{k}\t{n}' for k, n in DECL_RE.findall(code))

    want_decls, want_reqs = [], []
    if os.path.exists(MANIFEST):
        for line in open(MANIFEST, encoding='utf-8'):
            line = line.rstrip('\n')
            if not line.strip() or line.startswith('#'):
                continue
            tag, _, rest = line.partition('\t')
            if tag == 'decl':
                want_decls.append(rest)
            elif tag == 'require':
                want_reqs.append(rest)
    else:
        problems.append(f'Q4 manifest {MANIFEST} missing -- the fence is unpinned')

    # Q0 -- ANTI-VACUITY.  Before comparing anything, assert the manifest actually
    # carries the rows it is supposed to.  Without this, an empty manifest makes
    # Q2 and Q4 no-ops and the fence passes vacuously.
    if len(want_decls) != EXPECT_DECLS:
        problems.append(f'Q0 manifest declaration rows = {len(want_decls)}, expected {EXPECT_DECLS} '
                        f'-- manifest truncated, Q4 would be vacuous')
    if len(want_reqs) != EXPECT_REQS:
        problems.append(f'Q0 manifest require rows = {len(want_reqs)}, expected {EXPECT_REQS} '
                        f'-- manifest truncated, Q2 would be vacuous')

    want_decls, want_reqs = sorted(want_decls), sorted(want_reqs)
    if want_reqs and reqs != want_reqs:
        problems.append(f'Q2 require set changed: have {reqs} want {want_reqs}')
    if want_decls:
        added = [d for d in decls if d not in want_decls]
        removed = [d for d in want_decls if d not in decls]
        for d in added:
            problems.append('Q4 DECLARATION ADDED (fatal): ' + d.replace('\t', ' '))
        for d in removed:
            problems.append('Q4 declaration removed: ' + d.replace('\t', ' '))

    # ---- Q5  VALUE TRIPWIRE (cheap, explicitly NOT a closure of the class) ----
    for f in certified_files():
        if f == FENCED:
            continue
        source = Path(f).read_bytes()
        c = strip_comments(source.decode('utf-8'))
        for pat in MAGNITUDES:
            matches = list(re.finditer(pat, c))
            if matches:
                expected = NONPOLICY_MAGNITUDES.get((f, pat))
                if len(matches) == 1 and hashlib.sha256(source).hexdigest() == expected:
                    continue
                problems.append(f'Q5 deployment magnitude {pat} in code of {f}')

    if problems:
        for p in problems:
            print('FENCE ' + p)
        return 1
    print(f'OK   quarantine intact: {len(decls)} declarations, {len(reqs)} require lines, '
          f'sealed leaf, no inbound requires, no magnitude leakage')
    return 0


if __name__ == '__main__':
    sys.exit(main())
