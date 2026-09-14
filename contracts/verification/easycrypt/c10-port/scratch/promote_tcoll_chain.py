#!/usr/bin/env python3
"""Promote experiments/wots-badenc/{tcoll,red} -> cdrafts-split (2026-09-14).
Comment edits ONLY.  Asserts comment-stripped code identity with the experiment copy,
asserts every anchored edit fires the expected number of times, and writes nothing
unless every assertion holds."""
import importlib.util, os, re, sys
os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
spec = importlib.util.spec_from_file_location('_pf', 'tools/policy_cap_fence.py')
pf = importlib.util.module_from_spec(spec); spec.loader.exec_module(pf)

SRC = {'TCollResEnum':  ('experiments/wots-badenc/tcoll/TCollResEnum.ec',  '2026-08-13', 'tcoll'),
       'BadEncSplit':   ('experiments/wots-badenc/red/BadEncSplit.ec',     '2026-08-14', 'red'),
       'BadEncToTColl': ('experiments/wots-badenc/red/BadEncToTColl.ec',   '2026-08-14', 'red'),
       'BadEncStep4':   ('experiments/wots-badenc/red/BadEncStep4.ec',     '2026-08-14', 'red')}

def sub(s, old, new, n=1, name=''):
    c = s.count(old)
    assert c == n, f'{name}: anchor fired {c} times, expected {n}: {old[:70]!r}'
    return s.replace(old, new)

out = {}
for name, (path, date, d) in SRC.items():
    s = open(path).read()
    dst = f'cdrafts-split/{name}.ec'
    assert not os.path.exists(dst), f'{dst} exists -- refusing to overwrite'
    dump = f'experiments/wots-badenc/{d}/dump.sh'

    # ---- file-specific edits, anchored on the ORIGINAL (experiment-relative) text ----
    if name == 'TCollResEnum':
        s = sub(s, "Building `R` is the next unit of work.\n"
                   "       Until it exists, this game charges nothing: the fork's WOTS-TW bound is\n"
                   "       unchanged, and the BadEnc summand is still unbounded.",
                   "[CORRECTED 2026-09-14 -- this said\n"
                   "       \"Building `R` is the next unit of work.  Until it exists, this game charges\n"
                   "       nothing\".  It was built the next day and is promoted alongside this file:\n"
                   "       `R_TCOLL` is cdrafts-split/BadEncToTColl.ec and the inequality is\n"
                   "       cdrafts-split/BadEncStep4.ec::badenc_le_tcoll.  What stays true: nothing\n"
                   "       in THIS file charges anything, and the BadEnc summand is still UNBOUNDED --\n"
                   "       moving it to this game does not bound it.]", name=name)
        s = sub(s, "   The gap that remains, restated so nobody has to infer it: the reduction\n"
                   "   BadEnc -> T_COLL_RES_ENUM does not exist.  Until it does, this file changes\n"
                   "   no bound anywhere in the development.",
                   "   The gap that remained when this was written: the reduction\n"
                   "   BadEnc -> T_COLL_RES_ENUM did not exist.  [CORRECTED 2026-09-14: it does now --\n"
                   "   cdrafts-split/BadEncStep4.ec::badenc_le_tcoll.  It MOVES the charge to this\n"
                   "   game; it bounds nothing, and this file on its own still changes no bound.]", name=name)
        s = sub(s, "`./run.sh` (inside the `ec-grind` container, `-I ../base -I ../cd\n"
                   "   -I .`); receipt `tcoll.out`, last recorded `__RC=0`.  `./dump.sh <File>`",
                   "a closure member since 2026-09-14, compiled as a target by\n"
                   "   `cert_gate_split.sh`; pre-promotion receipt\n"
                   "   `experiments/wots-badenc/tcoll/tcoll.out`.  `" + dump + " <File>`", name=name)
        s = sub(s, "`./mkctl.sh`, run with `./runctl.sh`, receipts in `controls/Ctl?.out`.",
                   "`scratch/mkctl_tcoll.sh` (CtlA..F = `scratch/tcoll_ctl{A..F}.ec`); the\n"
                   "   gate runs them from `cert-controls-split.tsv` and grades the declared reason.", name=name)
    if name == 'BadEncSplit':
        s = sub(s, "   `encode_msgWOTS_C` is an ABSTRACT op (`../cd/WOTS_C_Real.ec:377`); the\n"
                   "   development supplies its factorisation as the named hypothesis `encb`\n"
                   "   (e.g. `../cd/WOTS_C_Interactive.ec:1900` carries it verbatim as a premise of\n"
                   "   `query_eq_tw`).  It is a PREMISE here too -- not an axiom, not a `hint`.",
                   "   [CORRECTED 2026-09-14.]  When this was written `encode_msgWOTS_C` was an\n"
                   "   ABSTRACT op and the development supplied its factorisation as the named\n"
                   "   hypothesis `encb`.  Since 2026-08-26 (commit 48230de) the op is DEFINED as\n"
                   "   `encode_msgWOTS (ThC p a x cc)` (cdrafts-split/WOTS_C_Real.ec:404) and the\n"
                   "   bridge is the theorem `encode_msgWOTS_C_compat` (:418), so `EncBridge` below\n"
                   "   is now PROVABLE rather than assumed.  It is still stated as a PREMISE of\n"
                   "   `coll_is_encoder_collision`, which is therefore weaker than it needs to be --\n"
                   "   harmless, because nothing in the development consumes that lemma (checked\n"
                   "   2026-09-14).  `query_eq_tw` (cdrafts-split/WOTS_C_Interactive.ec:1863) still\n"
                   "   carries `encb` as a premise (:1910).", name=name)
        s = sub(s, "   BUILD.  `./run.sh BadEncSplit` (container `ec-grind`, `-I ../base -I ../cd\n"
                   "   -I ../tcoll -I .`); receipt `BadEncSplit.out`.\n\n"
                   "   NEGATIVE CONTROLS -- see `mkctl.sh` / `runctl.sh`, receipts in `controls/`.",
                   "   BUILD.  A closure member since 2026-09-14, compiled as a target by\n"
                   "   `cert_gate_split.sh`; pre-promotion receipt\n"
                   "   `experiments/wots-badenc/red/BadEncSplit.out`.\n\n"
                   "   NEGATIVE CONTROLS -- `scratch/mkctl_bered.sh` (CtlA..D =\n"
                   "   `scratch/bered_ctl{A..D}.ec`), run by the gate from `cert-controls-split.tsv`.", name=name)
        s = sub(s, "control CtlA\n", "control CtlA (bered_ctlA)\n", name=name)
        s = sub(s, "(`../cd/WOTS_C_Real.ec:377`), because", "(`../cd/WOTS_C_Real.ec:404`), because", name=name)
        s = sub(s, "`../base/WOTS_TW_ES.ec:3290`", "`../base/WOTS_TW_ES.ec:3375`", name=name)
        s = sub(s, "`../cd/WOTS_C_Interactive.ec:1806`", "`../cd/WOTS_C_Interactive.ec:1813`", name=name)
    if name == 'BadEncToTColl':
        s = sub(s, "IS NOT PROVED HERE.  What is here is the",
                   "IS NOT PROVED HERE (it is BadEncStep4.ec).  What is here is the", name=name)
        s = sub(s, "   BUILD.  `./run.sh BadEncToTColl`; receipt `BadEncToTColl.out`.",
                   "   BUILD.  A closure member since 2026-09-14, compiled as a target by\n"
                   "   `cert_gate_split.sh`; pre-promotion receipt\n"
                   "   `experiments/wots-badenc/red/BadEncToTColl.out`.", name=name)
        s = sub(s, "`../base/WOTS_TW_ES.ec:3206`", "`../base/WOTS_TW_ES.ec:3291`", name=name)
    if name == 'BadEncStep4':
        s = sub(s, "`./run.sh BadEncStep4` -> `__RC=0` + a fresh `BadEncStep4.eco`.",
                   "compiled as a target by `cert_gate_split.sh` (closure member since\n"
                   "   2026-09-14; pre-promotion receipt `experiments/wots-badenc/red/BadEncStep4.out`).", name=name)
        s = sub(s, "`./printstmt.sh` (receipt `printstmt.out`)",
                   "`experiments/wots-badenc/red/printstmt.sh` (receipt `printstmt.out`\n"
                   "   there; RE-PRINTED against the live trees 2026-09-14 before promotion --\n"
                   "   same restriction set, same premise, same two games)", name=name)
        s = sub(s, "`./mkctl4.sh`, run with\n"
                   "   `./runctl.sh S4CtlA S4CtlB S4CtlC S4CtlD S4CtlE S4CtlF S4CtlG`, receipts in\n"
                   "   `controls/S4Ctl?.out`.",
                   "`scratch/mkctl_bes4.sh` (S4CtlA..G =\n"
                   "   `scratch/bes4_ctl{A..G}.ec`); the gate runs them from\n"
                   "   `cert-controls-split.tsv` and grades the declared reason.", name=name)
    if name == 'TCollResEnum':
        s = sub(s, "`../base/WOTS_TW_ES.ec:2525-2526`", "`../base/WOTS_TW_ES.ec:2610-2611`", n=2, name=name)
        s = sub(s, "`../cd/WOTS_C_Real.ec:380`", "`../cd/WOTS_C_Real.ec:423`", name=name)

    # ---- generic rewrites ----
    s = s.replace('`./dump.sh`', '`' + dump + '`')
    s = s.replace('../base/BadEncCountermodel.ec', 'cdrafts-split/BadEncCountermodel.ec')
    s = s.replace('../base/', 'base-c10-split/').replace('../cd/', 'cdrafts-split/')
    s = s.replace('../tcoll/', 'cdrafts-split/').replace('../RESULT.md', 'experiments/wots-badenc/RESULT.md')
    assert '../' not in s, f'{name}: experiment-relative path survives: ' + s[s.index('../')-60:s.index('../')+40]
    assert './run' not in s and './mkctl' not in s and './runctl' not in s and './printstmt' not in s, name
    assert not re.search(r'(?<![/\w])\./dump\.sh', s), name

    banner = (f"(* PROMOTED 2026-09-14 into the certified closure from\n"
              f"   {path} (proved there {date}).\n"
              f"   CODE IS IDENTICAL to that copy once comments are stripped -- asserted by\n"
              f"   scratch/promote_tcoll_chain.py, not claimed.  COMMENT EDITS ONLY: the\n"
              f"   experiment-relative paths (../base, ../cd, ../tcoll) point at the live trees;\n"
              f"   every file:line citation was re-checked against them and the moved ones updated;\n"
              f"   expired claims are corrected at the sentence and marked [CORRECTED 2026-09-14].\n"
              f"   The experiment copy is kept unedited as the historical record. *)\n")
    s = banner + s
    a = pf.strip_comments(open(path).read()); b = pf.strip_comments(s)
    norm = lambda t: '\n'.join(l.rstrip() for l in t.split('\n')).strip()
    # comment edits change the NUMBER of newlines inside comments; compare code tokens
    toks = lambda t: re.findall(r'\S+', t)
    assert toks(a) == toks(b), f'{name}: CODE CHANGED'
    out[dst] = s

for dst, s in out.items():
    open(dst, 'w').write(s)
    print(f'wrote {dst}  ({len(s.splitlines())} lines)')
print('\n=== remaining line-number references (verify each) ===')
for dst, s in out.items():
    for m in re.finditer(r'[A-Za-z_./-]*\.eca?[`)]?[:,]?\s*\(?:\d+(?:-\d+)?|\(:\d+(?:-\d+)?\)|\s:\d+(?:-\d+)?[,)]', s):
        ctx = s[max(0, m.start()-50):m.end()+5].replace('\n', ' ')
        print(f'{dst.split("/")[-1]:18} ...{ctx}')
