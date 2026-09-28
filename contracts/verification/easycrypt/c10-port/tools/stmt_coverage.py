#!/usr/bin/env python3
"""STATEMENT COVERAGE -- every top-level statement in the certified roots must be pinned.

WHY THIS EXISTS, AND WHY THE PINS ALONE ARE NOT ENOUGH.  cert_gate_split.sh PHASE 1c
iterates the MANIFEST (`done < cert-statements-split.tsv`), not the source files.  So it
verifies that every PINNED statement still says what it said -- and is structurally
blind to a statement that was never pinned.  Pinning all 896 statements that exist
today does NOT stop someone adding an 897th tomorrow: the new one is simply absent from
the manifest, and absence is invisible to a loop that reads the manifest.

That was the whole point of the exercise (a prior adversarial review found that a new
certified statement carrying an unwanted hypothesis -- e.g. a deployment policy cap --
could be introduced with no manifest delta), so the pins without this check would have
been a large amount of work that did not close the hole it was aimed at.

This module supplies the missing direction: enumerate statements FROM THE FILES and
assert each one has a manifest row.  Together:
  * PHASE 1c  -- pinned statements cannot silently CHANGE   (manifest -> files)
  * PHASE 1h  -- statements cannot silently APPEAR unpinned (files -> manifest)
"""
import re, os, sys, importlib.util

_spec = importlib.util.spec_from_file_location('_pf', os.path.join(os.path.dirname(__file__), 'policy_cap_fence.py'))
_pf = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(_pf)
strip_comments = _pf.strip_comments

B, D = 'base-c10-split', 'cdrafts-split'
BASE_ROOTS = ('WOTS_TW_ES', 'FL_SL_XMSS_MT_ES', 'FORS_ES', 'SPHINCS_PLUS')
MANIFEST = 'cert-statements-split.tsv'
# `pred` is included because a pred BODY is pure logical content that can be used as
# a lemma HYPOTHESIS -- and neither digest() nor (originally) digest_op() accepted
# it, so its content sat outside every gate surface while the statements naming it
# digested only the token.  Appending a conjunct to a pred body silently installed
# that hypothesis in every statement using it, with zero pin/coverage/census delta.
# Found by adversarial review 2026-08-20; FORS_C_TreePort.ec alone declares 9.
KINDS = r"(?:local\s+)?(?:lemma|theorem|equiv|hoare|phoare|declare\s+axiom|axiom|pred)"
# `(?:^|\.)` not `^`: EasyCrypt is whitespace-insensitive, so
# `qed. lemma hidden : 1 = 1. proof. trivial. qed.` on ONE line is a legal, saved,
# requirable result.  A line-anchored scan does not see it -- it is not counted, not
# reported unpinned, and not pinnable.  tools/cert_cone.py:162 already uses this
# idiom for axioms, so a mid-line AXIOM was caught by the census while a mid-line
# LEMMA was caught by nothing.
DECL = re.compile(r"(?:^|\.)\s*(" + KINDS + r")\s+([A-Za-z0-9_']+)", re.M | re.S)


CONE_MANIFEST = 'cert-cone-files-split.tsv'


def roots():
    """The 38 GATE ROOTS: the closure list plus the four base roots."""
    rs = [os.path.join(D, n.strip() + '.ec') for n in open('closure-c10-split.txt')
          if n.strip() and not n.lstrip().startswith('#')]
    rs += [os.path.join(B, n + '.ec') for n in BASE_ROOTS]
    return rs


def computed_cone():
    """The CERTIFIED CONE: every file the roots transitively require.

    Coverage originally enumerated only the 38 roots, but the cone is 45 files -- so
    79 statements in 7 transitively-required files (BinaryTrees, MerkleTrees, the three
    .eca theories, KeyedHashFunctions and cdrafts-split/FORS_C.ec) were pinned by
    NEITHER check: not by PHASE 1c (no manifest row) and not by PHASE 1h (not
    enumerated).  A statement there could change, or appear, with no delta anywhere.
    Computed with the same tool and the same roots the gate already uses for
    INPUTS_SHA256, so the three computations cannot disagree about what is certified.
    """
    import subprocess
    env = dict(os.environ, CERT_CONE_DIRS='base-c10-split,cdrafts-split')
    out = subprocess.run([sys.executable, 'tools/cert_cone.py'] + roots(),
                         capture_output=True, text=True, env=env, check=True).stdout
    return sorted({l[4:].strip() for l in out.splitlines()
                   if l.startswith('#   ') and l[4:].strip()})


def cone():
    """The cone, cross-checked against a COMMITTED file list.

    Committing the list matters independently of coverage: it makes a file ENTERING or
    LEAVING the certified cone a fatal, human-visible delta, instead of something
    coverage would silently absorb by simply enumerating whatever it found today.
    """
    got = computed_cone()
    if not os.path.exists(CONE_MANIFEST):
        return got, [f'cone manifest {CONE_MANIFEST} missing -- the cone file set is unpinned']
    want = sorted(l.strip() for l in open(CONE_MANIFEST, encoding='utf-8')
                  if l.strip() and not l.startswith('#'))
    problems = []
    if not want:
        problems.append(f'cone manifest {CONE_MANIFEST} has no rows -- would be vacuous')
    for f in got:
        if f not in want:
            problems.append(f'FILE ENTERED THE CONE (fatal): {f}')
    for f in want:
        if f not in got:
            problems.append(f'file left the cone: {f}')
    return got, problems


def statements(path):
    code = strip_comments(open(path, encoding='utf-8').read())
    return [(re.sub(r'\s+', ' ', k).strip(), n) for k, n in DECL.findall(code)]


def main():
    keys = set()
    if os.path.exists(MANIFEST):
        for line in open(MANIFEST, encoding='utf-8'):
            line = line.rstrip('\n')
            if not line.strip() or line.startswith('#'):
                continue
            keys.add(line.split('\t', 1)[0])

    cone_files, cone_problems = cone()
    unpinned, total = [], 0
    for r in cone_files:
        if not os.path.exists(r):
            print(f'FAIL coverage: root file missing: {r}'); return 1
        for kind, name in statements(r):
            total += 1
            # axioms AND preds pin through the op: path (digest() matches only
            # lemma/theorem/equiv/hoare/phoare), so accept either spelling
            if f'{r}::{name}' not in keys and f'op:{r}::{name}' not in keys:
                unpinned.append(f'{r}::{name}  ({kind})')

    want = None
    for line in open('cert_gate_split.sh', encoding='utf-8'):
        m = re.match(r'^EXPECT_STMTS=(\d+)', line)
        if m:
            want = int(m.group(1)); break

    rc = 0
    for cp in cone_problems:
        print('FAIL coverage: ' + cp); rc = 1
    if unpinned:
        print(f'FAIL coverage: {len(unpinned)} UNPINNED statement(s) -- a statement can '
              f'appear without a manifest delta:')
        for u in unpinned[:25]:
            print('       ' + u)
        if len(unpinned) > 25:
            print(f'       ... and {len(unpinned)-25} more')
        rc = 1
    if want is None:
        print('FAIL coverage: EXPECT_STMTS not committed in cert_gate_split.sh'); rc = 1
    elif total != want:
        print(f'FAIL coverage: statement TOTAL {total} != committed EXPECT_STMTS {want} '
              f'-- the certified statement set changed'); rc = 1
    if rc == 0:
        print(f'OK   coverage: all {total} top-level statements across {len(cone_files)} '
              f'CONE files are pinned (roots {len(roots())} + transitively required)')
    return rc


if __name__ == '__main__':
    sys.exit(main())
