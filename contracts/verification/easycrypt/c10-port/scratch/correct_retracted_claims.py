#!/usr/bin/env python3
"""Correct, at the sentence, the RETRACTED claim "C10's WOTS layer never encodes an
adversary-chosen value / key-determined internal nodes" in two CERTIFIED headers.
Retracted 2026-08-14 (vendored README "CORRECTION 2026-08-14 (final)";
scratch/FINDING-both-my-claims-were-wrong.md).  Re-verified at source 2026-09-14:
sphincs-c10/src/hypertree.rs::verify reads FORS secrets (:386) and auth paths (:394)
from the signature, rebuilds roots (:401), forms fors_pk (:416), uses it as the layer-0
WOTS message (:419), and reads the counter from the signature (:433).
DO NOT RUN WHILE A GATE IS RUNNING: both targets are hashed, and the gate re-verifies
INPUTS_SHA256 at the end.  Comment edits only; comment-stripped code identity asserted."""
import importlib.util, os, re
os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
spec = importlib.util.spec_from_file_location('_pf', 'tools/policy_cap_fence.py')
pf = importlib.util.module_from_spec(spec); spec.loader.exec_module(pf)
toks = lambda t: re.findall(r'\S+', pf.strip_comments(t))
EDITS = {
 'cdrafts-split/BadEncCountermodel.ec': [(
"""   *** THE DEPLOYED WALLET IS NOT AFFECTED, AND THIS IS NOT AN ATTACK. ***
   C10's WOTS layer never encodes an adversary-chosen value — it encodes
   key-determined internal nodes (sphincs-c10/src/fors.rs:265-268;
   `compute_fors_pk` takes no message argument).  The adversary below is a
   MODEL-LEVEL object that the deployment gives no one the ability to build.
   Classification is unchanged: proof-technique limitation, not a vulnerability.""",
"""   *** NO ATTACK IS KNOWN AND THIS FILE EXHIBITS NONE -- BUT NOT FOR THE REASON
   THIS HEADER USED TO GIVE. ***   [CORRECTED 2026-09-14]
   It said: "C10's WOTS layer never encodes an adversary-chosen value -- it encodes
   key-determined internal nodes (sphincs-c10/src/fors.rs:265-268; `compute_fors_pk`
   takes no message argument)."  That is true of the honest SIGNER and FALSE at the
   VERIFIER, which is what a forgery game is about: `verify` reads the FORS secrets
   and auth paths out of the signature (sphincs-c10/src/hypertree.rs:386, :394),
   rebuilds the roots from them (:401), forms `fors_pk` (:416) and uses it as the
   layer-0 WOTS message (:419), with the counter also read from the signature (:433).
   The sentence was retracted in the vendored README on 2026-08-14 ("CORRECTION
   2026-08-14 (final)", scratch/FINDING-both-my-claims-were-wrong.md), which named
   THIS header as carrying it; the file was promoted on 2026-08-31 without the fix.
   What survives: the adversary below is handed its colliding pair as a HYPOTHESIS,
   so it is a MODEL-LEVEL object and nothing here is an attack.  What does NOT
   survive is any claim that the deployment makes the WOTS message key-determined.
   The leg rests on an UNBOUNDED assumption at the +C layer
   (cdrafts-split/TCollResEnum.ec), not on message-side structure.""")],
 'cdrafts-split/TCollResEnum.ec': [(
"""   it is not a bound.  The deployed wallet is unaffected for the same reason
   recorded in `cdrafts-split/BadEncCountermodel.ec`'s header: C10's WOTS layer
   encodes key-determined internal nodes, never an adversary-chosen value.""",
"""   it is not a bound.  [CORRECTED 2026-09-14 -- this went on: "The deployed wallet
   is unaffected for the same reason recorded in BadEncCountermodel.ec's header:
   C10's WOTS layer encodes key-determined internal nodes, never an
   adversary-chosen value."  That reason is FALSE at the verifier and was retracted
   on 2026-08-14 -- see the corrected BadEncCountermodel.ec header, which cites
   sphincs-c10/src/hypertree.rs.  No attack is known; the deployed WOTS leg rests on
   THIS game's assumption, which nothing in the tree bounds.]"""),
 ("""   simply hand over a colliding pair.  At the +C layer it cannot: the WOTS
   message is `ThC ps ad m ctr`, a keyed digest it does not control.  This file""",
"""   simply hand over a colliding pair.  At the +C layer it cannot: the WOTS
   message is `ThC ps ad m ctr`, a keyed digest it does not control.
   [CLARIFIED 2026-09-14: "does not control" means the digest VALUE.  The adversary
   still picks the preimage (m', ctr'), receives `ps` at `find`, and can evaluate
   `ThC` itself (`thfc` is an ambient op).  So a win must be FOUND -- a second surface
   preimage of a recorded codeword (`tcoll_win_needs_coll`) -- and cannot be handed
   over.  That is an EVENT-level fact, not a hardness claim.]  This file""")],
 'cdrafts-split/GprocWotsNamed.ec': [(
"""require import GprocQWired.   (* reuse its WitnessF for the anti-vacuity check *)""",
"""require import GprocQWired.   (* CORRECTED 2026-09-14: this said "reuse its WitnessF for
   the anti-vacuity check", copied from GprocChargedQWired.ec, where it is true.  THIS
   file uses WitnessF zero times and has no anti-vacuity check; its controls are
   scratch/gwn_ctl{A,B}.ec. *)""")],
}
out = {}
for path, edits in EDITS.items():
    s0 = open(path).read(); s = s0
    for old, new in edits:
        assert s.count(old) == 1, (path, s.count(old), old[:60])
        s = s.replace(old, new)
    assert toks(s0) == toks(s), path + ': CODE CHANGED'
    out[path] = s
for path, s in out.items():
    open(path, 'w').write(s); print('corrected', path)
