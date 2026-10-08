#!/usr/bin/env python3
"""Digest the STATEMENT of a named lemma, comments and whitespace normalised.

WHY THIS EXISTS.  Adversarial review round 4 (Kimi K3) observed that the gate
pinned NAMES and never STATEMENTS.  `EUFCMA_SPHINCS_PLUS_C10_AT_DEPLOYED_PARAMS`
has no consumer anywhere in the tree, so its conclusion could be weakened to
`true` (proof `trivial`) and every gate phase would still pass: it compiles, the
name is still a lemma, the assumption cone is unchanged, and no control mentions
it.  Three hardening rounds secured everything AROUND the statement and never
hashed the statement itself.

WHAT IT DOES.  Extracts the text from `lemma NAME` / `theorem NAME` up to the
terminating `proof.`, strips (nested) comments, collapses whitespace, and prints
sha256.  A weakened conclusion, a dropped premise, or a relaxed module
restriction all change the digest.

HONEST LIMIT.  This is a TEXTUAL pin, not semantic: a statement could in
principle be rewritten to an equivalent form and trip the gate (a false alarm,
which is the safe direction), and a semantically different statement that
normalises identically would not (no such case is known).  It does NOT verify
the proof -- PHASE 1 does that.
"""
import hashlib, io, re, sys

def strip_comments(s):
    out = []; d = 0; i = 0
    while i < len(s):
        if s.startswith('(*', i): d += 1; i += 2; continue
        if s.startswith('*)', i) and d > 0:
            d -= 1; i += 2
            # Emit a SPACE where a comment was: otherwise `f(* *)x` splices to
            # `fx`, a DIFFERENT parse that digests identically.  Demonstrated by
            # adversarial review, run 5; cert_cone.py already did this correctly.
            out.append(' ')
            continue
        if d == 0: out.append(s[i])
        i += 1
    return ''.join(out)

def digest_op(path, name):
    """Digest an op/const DECLARATION, terminator included.

    Run 5's kill shot: `op emb_in : dgstblock * cntr -> dgst.` can be replaced by
    `op emb_in (x : dgstblock * cntr) : dgst = witness.` -- ThC becomes constant,
    the S-TCR term becomes trivially winnable, and NOTHING in the gate notices:
    no proof unfolds emb_in (its properties are carried as HYPOTHESES), the
    pinned statements mention it only as a token, and abstract-vs-defined ops are
    both non-census categories.  Pinning the DECLARATION closes that.
    """
    body = strip_comments(io.open(path, encoding='utf-8', errors='replace').read())
    # FIRST MATCH IS NOT GOOD ENOUGH (fixed 2026-08-02, run 11, GPT-5.6).
    # This took re.search -- the FIRST textual match, at any indentation, with no
    # scope or kind discipline.  Two consequences, one hypothetical and one LIVE:
    #   * hypothetical: a decoy `abstract theory D. op c10_k : int = 13. end D.`
    #     placed above the real declaration reproduces the committed digest while
    #     the real op says something else.
    #   * LIVE, and in this manifest for several rounds: the pin
    #     `op:base-c10-split/WOTS_TW_ES.ec::P` matched
    #         op P x <- 0 <= x < w          (BaseW Subtype clone, ~line 162)
    #     -- a clone `with`-OPERAND BINDING, not a declaration -- while the real
    #     +C gate predicate
    #         op P (m : msgWOTS) : bool = digitsum (encode_msgWOTS m) = target_sum.
    #     at :654 was pinned by NOTHING.  A `<-` binding is never the declaration
    #     the pin means, so those matches are skipped; genuine ambiguity is
    #     reported instead of silently resolved.
    pat = re.compile(r'(?:^|\.)\s*((?:op|pred|const|abbrev|axiom|declare\s+axiom)\s*(?:\[[^\]]*\]\s*)?' +
                     re.escape(name) + r'(?![A-Za-z0-9_\']))', re.M | re.S)
    cands = []
    for c in pat.finditer(body):
        tail = body[c.start(1):]   # group 1 = keyword onward; c.start() may be the preceding '.'
        t = re.search(r'\.(?=\s|$)', tail)
        decl = tail[:t.end()] if t else tail
        if '<-' in decl.split('=')[0]:      # clone with-operand binding, not a declaration
            continue
        cands.append(c)
    if not cands:
        return None
    if len(cands) > 1:
        # Ambiguity is FATAL, not resolved by position: the manifest names one
        # declaration and the file has several.
        return 'AMBIGUOUS-%d-DECLARATIONS' % len(cands)
    m = cands[0]
    rest = body[m.start(1):]   # SPAN RE-ANCHOR: see the note on `(?:^|\.)` above
    # A DECLARATION TERMINATOR is a period followed by whitespace/EOF.  The naive
    # `rest.find('.')` stopped inside QUALIFIED NAMES: join_dgst's body begins
    # `MDigestBlock.insubd (...)`, so the digest covered only
    # `... = MDigestBlock.` and the entire body was unpinned.  Found by
    # adversarial review, run 7 -- while the claims log said join_dgst was pinned.
    mt = re.search(r'\.(?=\s|$)', rest)
    decl = rest[:mt.end()] if mt else rest
    return hashlib.sha256(' '.join(decl.split()).encode()).hexdigest()[:32]


def digest(path, name):
    body = strip_comments(io.open(path, encoding='utf-8', errors='replace').read())
    # Same discipline as digest_op: a name declared twice means the pin is
    # ambiguous, and picking the first one is how a decoy wins.
    # `equiv` / `hoare` / `phoare` DECLARATIONS ARE STATEMENTS TOO (run 13d).
    # This matched only lemma|theorem, so pinning an `equiv` returned None, the
    # caller printed NOT-FOUND, and a manifest row whose expected value was the
    # literal string NOT-FOUND then COMPARED EQUAL.  A pin that cannot resolve
    # its target must fail, not agree with itself.  Found while pinning
    # GprocKg_sk_eq (Tier 1 brick 2).
    _c = re.findall(r'(?:^|\.)\s*(?:local\s+)?(?:lemma|theorem|equiv|hoare|ehoare|phoare)\s+' + re.escape(name) + r'(?![A-Za-z0-9_\'])',
                    body, re.M)
    if len(_c) > 1:
        return 'AMBIGUOUS-%d-STATEMENTS' % len(_c)
    m = re.search(r'(?:^|\.)\s*((?:local\s+)?(?:lemma|theorem|equiv|hoare|ehoare|phoare)\s+' + re.escape(name) + r'(?![A-Za-z0-9_\']))',
                  body, re.M | re.S)
    if not m:
        return None
    rest = body[m.start(1):]   # SPAN RE-ANCHOR: group 1 starts at the keyword
    # TERMINATOR RE-ANCHOR.  `(?:^|\.)` is needed so a MID-LINE `proof` is found
    # (`qed. lemma h : 1 = 1. proof. trivial. qed.` is legal EasyCrypt), but the
    # slice must stop at the KEYWORD, not at the '.' the alternation consumes --
    # otherwise the statement's own terminating period is dropped and EVERY digest
    # moves.  Measured: without group(1) here, 870 of 923 pins changed.
    p = re.search(r'(?:^|\.)\s*(proof\b)', rest, re.M)
    stmt = rest[:p.start(1)] if p else rest
    norm = ' '.join(stmt.split())
    return hashlib.sha256(norm.encode()).hexdigest()[:32]

if __name__ == '__main__':
    for arg in sys.argv[1:]:
        if arg.startswith('op:'):
            path, name = arg[3:].split('::')
            d = digest_op(path, name)
            print(f'op:{path}::{name}\t{d or "NOT-FOUND"}')
        else:
            path, name = arg.split('::')
            d = digest(path, name)
            print(f'{path}::{name}\t{d or "NOT-FOUND"}')
