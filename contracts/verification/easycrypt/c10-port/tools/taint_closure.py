#!/usr/bin/env python3
"""FORWARD TAINT CLOSURE over the certified cone.

WHAT THIS IS.  Starting from the cone's `admit`ed lemmas, compute every lemma whose
proof BODY names a tainted lemma, to a fixpoint.  A theorem outside that closure does
not reach the admit by any NAMED application.

WHAT THIS IS NOT -- read before trusting it.  This is a NAME-LEVEL approximation of
"uses", and the direction is NOT uniformly safe.  An EXCLUSION claim needs an
OVER-approximation, but every hole below SHRINKS the closure, i.e. UNDER-approximates.
An earlier version of this header called the whole thing an "over-approximation", which
implied a safety margin it does not have (Kimi K3 adversarial review, 2026-08-27).  It does NOT see:
  * a bare `smt()` that picks a lemma out of the ambient context without naming it;
  * reachability through a clone instantiation or a module argument rather than a
    named application.
Neither hole is believed live here, but a check that reads stronger than it is becomes
the next fail-open.

NAME COLLISIONS BETWEEN AN `op` AND A `lemma` ARE REAL IN THIS TREE.  FORS_C_TreePort.ec
declares BOTH `op extract_op` (:1148) and `lemma extract_op` (:1485).  A pure name match
therefore CANNOT tell "applies the admitted lemma" from "uses the operator".  Two
mitigations, both implemented below:
  * POSITIONAL RULE (sound): EasyCrypt processes a file top-to-bottom and has no forward
    lemma references, so a mention at line X inside the SAME file as a lemma declared at
    line Y > X cannot be a use of that lemma.  This is what excludes `op_extract_wins`
    (:1173), which uses the OP at :1148, not the lemma at :1485.
  * AMBIGUOUS EDGES ARE KEPT, NOT DROPPED.  Where the positional rule cannot decide
    (both the op and the lemma precede the mention) the edge is retained and LABELLED
    `ambig`.  Retaining is the conservative direction for an EXCLUSION claim: it can only
    make the closure larger, never let a real taint escape.  So the honest statement is: this phase catches NAMED-APPLICATION DRIFT.  It is NOT a
soundness proof of exclusion.  A name absent from the closure is absent from the true
closure ONLY modulo the two holes above -- and both are unsafe-direction.

[UPDATE 2026-09-15: for the ONE admit left (FORS_C_TreePort.ec::extract_op) neither hole
applies, for a reason this tool does NOT compute: that theory is OUTSIDE every headline
environment.  EasyCrypt reports its symbols unknown after `require GprocTCollNamed.` (whose
cone holds the other five headline files), checked two-sided on every gate run by PHASE 3
controls scratch/_scope_*.ec.  The holes stay stated because they bite for any future admit
in a theory a headline file DOES require.]

[UPDATE 2026-09-15 (later): --check also enforces SCOPE-PROBE LINKAGE.  The files that declare
HEADLINE results must be in EXACT BIJECTION with the scratch/_scope_neg_op_<H>.ec rows of
cert-controls-split.tsv; each row MUST-FAIL, its declared reason naming every admit theory, and
its probe requiring its own headline theory.  A new headline file with no probe, or a probe left
for a file that no longer declares one, is RED here.  Controls T11..T14 in taint_controls.sh.]

Usage:  taint_closure.py            -> print the closure
        taint_closure.py --check    -> compare against cert-taint-closure.tsv, exit 1 on drift
"""
import re, sys, os

CONE_MANIFEST = 'cert-cone-files-split.tsv'
# Read by scope_linkage() only (added 2026-09-15).
CONTROLS_MANIFEST = 'cert-controls-split.tsv'
SCOPE_PROBE = re.compile(r'^scratch/_scope_neg_op_([A-Za-z0-9_]+)\.ec$')
MANIFEST      = 'cert-taint-closure.tsv'

# COMMITTED CONSTANTS -- these live in the TOOL, not only in the manifest.  A guard that
# reads its expectation out of the file it is checking cannot detect that file being gutted.
EXPECT_SEEDS       = 1      # the cone's ONE admit.  WAS 2 UNTIL 2026-08-30: the WOTS
                            # admit (nhchwcoll_hchwpre_msg) was REMOVED, not contained --
                            # its conclusion is now the BadEnc disjunction and the charge
                            # is an explicit named probability.  `extract_op` remains.
                            # This constant is deliberately EXACT, not a floor: the guard
                            # fired on the change and forced this edit to be reviewed.
EXPECT_CLOSURE     = None   # filled from the manifest, but cross-checked against EXPECT_MIN
# Declarations the parser is allowed not to register (duplicate (file,name) pairs collapse).
# Committed, not recomputed: a budget derived from the thing it checks cannot detect drift.
MIN_CLONE_STMTS  = 60  # MEASURED 80; a floor, so a broken clone scanner cannot pass vacuously.
MAX_UNREGISTERED = 2   # MEASURED: 951 declarations, 949 registered; the 2 are
                       # duplicate (file,name) pairs collapsing.  A LOOSE budget hides
                       # exactly the bugs this guard exists to catch -- keep it exact.
EXPECT_MIN_CLOSURE = 2      # was 3; one seed left, and its chain has one consumer.
                            # the closure can never be smaller than seeds+1 while a consumer exists
# Theorems that MUST NOT be in the closure.  This is the property the README asserts.
HEADLINE = [
    'byte_coordinate_replay_hop',
    'role_grind_joint_coverage',
    'signature_digest_bound',
    'role_grind_ht_bound',

    'full_win_has_no_failure',
    'raw_session_exhaustion_explicit',
    'raw_session_total_cost',
    'byte_physical_to_independent',
    'physical_signature_bytes',
    'full_physical_game_cost',
    'full_physical_to_independent',
    'signature_bytes_roundtrip',

    'bounded_hypertree_accepted',
    'EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED',
    'EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED_TIGHT',
    'EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED_TIGHT_AT_DEPLOYED_PARAMS',
    # Added 2026-08-27 with the variant itself.  A headline result that is NOT in this
    # list is NOT checked for taint -- adding a capstone without adding it here is a
    # silent coverage hole, so the two edits belong in the same commit.
    'EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED_TIGHT_AT_PINNED_ENCODER',
    'EUFCMA_SPHINCS_PLUS_C10_GROUNDED',
    'EUFCMA_SPHINCS_PLUS_C10_QWIRED',
    'gproc_Q_bound',
    # Added 2026-09-14.  WOTSNAMED (GprocWotsNamed.ec, 2026-09-01) was landed WITHOUT this
    # edit -- exactly the silent coverage hole the note above warns about; it went 13 days
    # unchecked for taint.  TCOLLNAMED (GprocTCollNamed.ec) is added with the variant itself.
    'EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED_TIGHT_AT_DEPLOYED_PARAMS_WOTSNAMED',
    'EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED_TIGHT_AT_DEPLOYED_PARAMS_TCOLLNAMED',
]

def strip_comments(s):
    out=[]; d=0; i=0; n=len(s)
    while i < n:
        if s.startswith('(*', i): d+=1; i+=2; continue
        if s.startswith('*)', i) and d>0: d-=1; i+=2; continue
        if d==0: out.append(s[i])
        elif s[i]=='\n': out.append('\n')
        i+=1
    return ''.join(out)

DECL = re.compile(r'^\s*(?:local\s+)?(?:lemma|theorem|equiv|hoare|phoare)\s+([A-Za-z0-9_\']+)', re.M)
OPDECL = re.compile(r'^\s*(?:local\s+)?(?:op|abbrev|pred)\s+([A-Za-z0-9_\']+)', re.M)

def cone_files():
    fs=[l.strip() for l in open(CONE_MANIFEST) if l.strip() and not l.startswith('#')]
    if not fs: sys.exit('FAIL cone manifest empty -- would be vacuous')
    return fs

def parse():
    """-> {(file,name): (file, decl_line, body)} and the set of admitted (file,name) keys.

    KEYED BY (FILE, NAME), not by bare name (fixed 2026-08-27, GPT-5.6 adversarial review).
    54 lemma basenames are declared in MORE THAN ONE cone file; a bare-name dict silently
    kept only the LAST, so a taint edge into a shadowed lemma could be lost entirely."""
    lemmas={}; admitted=set(); opdecls={}
    for f in cone_files():
        if not os.path.exists(f): sys.exit(f'FAIL cone file missing: {f}')
        src=strip_comments(open(f).read())
        lines=src.split('\n')
        cur=None; start=None; buf=[]
        for i,l in enumerate(lines,1):
            om=OPDECL.match(l)
            if om: opdecls.setdefault((f, om.group(1)), i)
            m=DECL.match(l)
            if m:
                cur=m.group(1); start=i; buf=[]
                # SAME-LINE `qed.` (fixed 2026-08-27, found by GPT-5.6 adversarial review).
                # This used to `continue` unconditionally, so a one-line
                # `lemma f : X. proof. .... qed.` was NEVER REGISTERED -- and worse, `cur`
                # stayed set and swallowed the following text into that lemma's body until
                # some LATER qed.  12 such declarations exist in the cone.  A one-line lemma
                # applying an admitted result would have been INVISIBLE to the closure.
                if re.search(r'(?:^|[^A-Za-z0-9_\'])qed\.', l):
                    body=l
                    lemmas[(f,cur)]=(f, start, body)
                    if re.search(r'(?:^|[^A-Za-z0-9_\'])admit(?:ted)?\s*\.', body): admitted.add((f,cur))
                    cur=None; buf=[]
                continue
            if cur is not None:
                buf.append(l)
                # TERMINATOR MATCHED ANYWHERE ON THE LINE (fixed 2026-08-27, found by
                # Kimi K3 adversarial review).  This used to be `re.match(r'\s*qed\.')`,
                # i.e. LINE-INITIAL ONLY -- so a proof closed as `proof. by .... qed.`
                # never terminated, and the lemma's body silently swallowed everything up
                # to the next line-initial `qed.`.  314 of the cone's `qed.` lines are of
                # that shape (33% of 951 declarations), so bodies were routinely
                # mis-attributed and edges could be both invented and lost.
                if re.search(r'(?:^|[^A-Za-z0-9_\'])(?:qed|abort)\.', l):
                    body='\n'.join(buf)
                    lemmas[(f,cur)]=(f, start, body)
                    if re.search(r'(?:^|[^A-Za-z0-9_])admit(?:ted)?\s*\.', body): admitted.add((f,cur))
                    cur=None; buf=[]
    # PARSER-COVERAGE GUARD (added 2026-08-27, Kimi K3's recommendation).
    # Three separate parser bugs in this tool were each INVISIBLE because nothing compared
    # what the parser REGISTERED against what is actually declared: one-line proofs (12),
    # bare-basename overwrites (54 duplicated names), and a line-initial-only terminator
    # (314 of 951 `qed.` lines).  Every one silently SHRANK the closure, which is the
    # unsafe direction for an exclusion claim.  So: count declarations independently and
    # require the parser to have registered essentially all of them.
    raw = 0
    for f in cone_files():
        for l in strip_comments(open(f).read()).split('\n'):
            if DECL.match(l): raw += 1
    if raw == 0:
        sys.exit('FAIL anti-vacuity: zero declarations scanned -- the parser is broken')
    missed = raw - len(lemmas)
    if missed > MAX_UNREGISTERED:
        sys.exit(f'FAIL parser coverage: {raw} declarations scanned but only {len(lemmas)} '
                 f'registered ({missed} unregistered, budget {MAX_UNREGISTERED}). '
                 f'An unregistered lemma is INVISIBLE to the closure, which is the unsafe '
                 f'direction for an exclusion claim.')
    # CLONE-ROUTE GUARD (added 2026-08-28).  PHASE 5's SECOND named hole is "reachability
    # through a clone instantiation rather than a named application".  MEASURED: it is NOT
    # LIVE in this tree -- of 80 clone statements across the 45 cone files, ZERO name an
    # admit-containing theory, and both admits sit at FILE TOP LEVEL (not inside any
    # cloneable sub-theory), so cloning the whole file is the only route and nobody does it.
    # This guard keeps it that way.  It derives the forbidden names from the COMPUTED
    # admits, so it tracks the tree rather than a hardcoded list.
    admit_theories = {os.path.splitext(os.path.basename(f))[0] for (f, _n) in admitted}
    clone_stmts = 0
    offenders = []
    CLONE = re.compile(r'\bclone\b[^.]{0,400}?\.', re.S)
    for f in cone_files():
        src = strip_comments(open(f).read())
        for m in CLONE.finditer(src):
            clone_stmts += 1
            blob = m.group(0)
            for t in admit_theories:
                if re.search(r'(?:^|[^A-Za-z0-9_])' + re.escape(t) + r'(?![A-Za-z0-9_])', blob):
                    offenders.append(f'{f}:{src[:m.start()].count(chr(10))+1} clones {t}')
    # ANTI-VACUITY: a scanner that finds no clones at all would pass this guard trivially.
    if clone_stmts < MIN_CLONE_STMTS:
        sys.exit(f'FAIL clone-route guard is vacuous: only {clone_stmts} clone statements '
                 f'scanned (expected >= {MIN_CLONE_STMTS}) -- the scanner is broken')
    if offenders:
        sys.exit('FAIL clone route into an admit-containing theory is now LIVE:\n  ' +
                 '\n  '.join(offenders) +
                 '\n  PHASE 5 is a NAME-level check and cannot follow taint through a clone.')
    return lemmas, admitted, opdecls

def mentions(body, name):
    return re.search(r'(?:^|[^A-Za-z0-9_\'])'+re.escape(name)+r'(?![A-Za-z0-9_\'])', body) is not None

def closure():
    lemmas, admitted, opdecls = parse()
    if len(admitted) != EXPECT_SEEDS:
        sys.exit(f'FAIL anti-vacuity: found {len(admitted)} admitted lemmas, expected {EXPECT_SEEDS} '
                 f'-- the parser or the tree changed: {sorted(admitted)}')
    # HEADLINE is matched on the NAME half of the key; a headline name that is itself
    # duplicated across cone files is refused rather than silently resolved.
    hkeys={}
    for h in HEADLINE:
        ks=[k for k in lemmas if k[1]==h]
        if not ks:
            sys.exit(f'FAIL anti-vacuity: headline name {h} not found as a declaration -- '
                     f'the exclusion check would be vacuous')
        if len(ks)>1:
            sys.exit(f'FAIL headline name {h} is declared in {len(ks)} cone files {sorted(x[0] for x in ks)} '
                     f'-- ambiguous, refusing to guess which one the exclusion is about')
        hkeys[h]=ks[0]
    def edge(user, t):
        """Does `user` plausibly APPLY tainted lemma `t`?  -> None | 'sure' | 'ambig'"""
        uf, uln, ubody = lemmas[user]
        tf, tln, _tb  = lemmas[t]
        tname = t[1]
        if not mentions(ubody, tname): return None
        # POSITIONAL RULE (sound): no forward lemma references within a file.
        if uf == tf and uln < tln: return None
        # An `op` of the same name also in scope makes the edge undecidable by name.
        if (tf, tname) in opdecls and opdecls[(tf, tname)] < uln: return 'ambig'
        return 'sure'

    tainted = {a: 'ADMIT' for a in admitted}
    changed = True
    while changed:
        changed = False
        for nm in lemmas:
            if nm in tainted: continue
            for t in list(tainted):
                e = edge(nm, t)
                if e:
                    tainted[nm] = e; changed = True; break
    return lemmas, admitted, tainted

def scope_linkage(lemmas, admitted):
    """SCOPE-PROBE LINKAGE (added 2026-09-15).  The PHASE 3 scope controls prove, per headline file,
    that the admit's theory is UNKNOWN in that file's environment.  Nothing tied those rows to
    HEADLINE, so a new headline file got no probe and PHASE 5 said nothing.  That is the same class
    as WOTSNAMED going 13 days unregistered for taint.  Enforced here as an EXACT BIJECTION, not a
    subset: a probe left for a file that no longer declares a headline is refused too.
    Deliberately NOT checked, because PHASE 3 already makes it RED: a probe that references another
    symbol, or requires the admit theory itself, COMPILES -- and a MUST-FAIL that compiles fails."""
    probs = []
    hbases = {os.path.splitext(os.path.basename(k[0]))[0] for k in lemmas if k[1] in HEADLINE}
    theories = sorted({os.path.splitext(os.path.basename(f))[0] for (f, _n) in admitted})
    if not os.path.exists(CONTROLS_MANIFEST):
        return [f'{CONTROLS_MANIFEST} missing -- scope-probe linkage cannot be checked'], len(hbases), 0
    rows, scanned = {}, 0
    for l in open(CONTROLS_MANIFEST):
        l = l.rstrip('\n')
        if not l.strip() or l.startswith('#'): continue
        scanned += 1
        parts = l.split('\t')
        m = SCOPE_PROBE.match(parts[0])
        if m:
            if m.group(1) in rows: probs.append(f'scope probe for {m.group(1)} registered twice')
            rows[m.group(1)] = (parts[0], parts[1] if len(parts) > 1 else '', parts[2] if len(parts) > 2 else '')
    if scanned == 0:
        return [f'{CONTROLS_MANIFEST} has no rows -- scope-probe linkage would be vacuous'], len(hbases), 0
    if not rows:
        return ['scope-probe linkage is vacuous: no scratch/_scope_neg_op_<H>.ec rows matched in '
                f'{CONTROLS_MANIFEST} -- the row matcher is broken or the probes were removed'], len(hbases), 0
    for b in sorted(hbases - set(rows)):
        probs.append(f'headline file {b} has no scope probe '
                     f'(expected scratch/_scope_neg_op_{b}.ec as MUST-FAIL in {CONTROLS_MANIFEST})')
    for b in sorted(set(rows) - hbases):
        probs.append(f'scope probe {rows[b][0]} is registered for {b}, which declares no HEADLINE result')
    for b in sorted(set(rows) & hbases):
        path, kind, reason = rows[b]
        if kind != 'MUST-FAIL':
            probs.append(f'scope probe {path} is {kind!r}, not MUST-FAIL')
        for t in theories:
            if f'{t}.' not in reason:
                probs.append(f'scope probe {path}: declared reason does not name admit theory {t}')
        if not os.path.exists(path):
            probs.append(f'scope probe file missing: {path}'); continue
        src = strip_comments(open(path).read())
        reqs = set()
        for rm in re.finditer(r"(?<![A-Za-z0-9_'])require\s+([^.]*)\.", src, re.S):
            body = rm.group(1).replace('import', ' ').replace('export', ' ')
            reqs.update(re.findall(r"[A-Za-z][A-Za-z0-9_']*", body))
        if b not in reqs:
            probs.append(f'scope probe {path} does not require its headline theory {b}')
    return probs, len(hbases), len(rows)

def main():
    lemmas, admitted, tainted = closure()
    rows=sorted((lemmas[k][0], lemmas[k][1], k[1], tainted[k]) for k in tainted)
    if '--check' not in sys.argv:
        for f,ln,n,tag in rows:
            print(f'{f}\t{ln}\t{n}\t{tag}')
        print(f'# closure size = {len(rows)}', file=sys.stderr)
        return 0
    # ---- check mode ----
    problems=[]
    if len(rows) < EXPECT_MIN_CLOSURE:
        problems.append(f'closure size {len(rows)} < EXPECT_MIN_CLOSURE {EXPECT_MIN_CLOSURE} -- suspiciously small')
    for k in tainted:
        if k[1] in HEADLINE:
            problems.append(f'HEADLINE IS TAINTED: {k[1]} ({k[0]}) transitively applies an admitted lemma')
    link_probs, n_hfiles, n_probes = scope_linkage(lemmas, admitted)
    problems += link_probs
    if not os.path.exists(MANIFEST):
        problems.append(f'{MANIFEST} missing -- the closure is unpinned')
    else:
        want=set(); wrows=0
        for l in open(MANIFEST):
            l=l.rstrip('\n')
            if not l.strip() or l.startswith('#'): continue
            wrows+=1
            parts=l.split('\t')
            if len(parts) < 3: problems.append(f'malformed manifest row: {l}'); continue
            want.add((parts[0], int(parts[1]), parts[2], parts[3] if len(parts)>3 else 'taint'))
        if wrows == 0:
            problems.append('manifest has no rows -- would be vacuous')
        got=set(rows)
        # EVERY manifest site must RESOLVE: file exists, line in range, symbol on that line.
        for f,ln,n,_t in sorted(want):
            if not os.path.exists(f): problems.append(f'manifest site file missing: {f}'); continue
            src=strip_comments(open(f).read()).split('\n')
            if not (1 <= ln <= len(src)): problems.append(f'manifest site out of range: {f}:{ln}'); continue
            if not mentions(src[ln-1], n):
                problems.append(f'manifest site does not resolve: {f}:{ln} does not name {n}')
        got4 = set((f,ln,n,t) for f,ln,n,t in rows)
        want4 = want
        for extra in sorted(got4-want4): problems.append(f'TAINT CLOSURE GREW: {extra[0]}:{extra[1]} {extra[2]} [{extra[3]}]')
        for gone in sorted(want4-got4): problems.append(f'taint closure SHRANK: {gone[0]}:{gone[1]} {gone[2]} [{gone[3]}]')
    if problems:
        for p in problems: print(f'FAIL taint: {p}')
        return 1
    print(f'OK   taint containment: closure = {len(rows)} lemmas, none of the {len(HEADLINE)} '
          f'headline results is in it (name-level, NOT a soundness proof -- see the tool header)')
    print(f'OK   scope-probe linkage: {n_hfiles} headline files <-> {n_probes} registered scope probes '
          f'(exact bijection)')
    return 0

sys.exit(main())
