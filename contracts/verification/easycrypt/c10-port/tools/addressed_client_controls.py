"""Controls for the paired/wrapper addressed-node continuation.

Contract twins check exact interface/charge sensitivity, not tightness or
logical necessity. Program twins compare complete oracle state, typecheck
separately and include an unchanged and an equivalent-program control.
"""
from addressed_node_controls import imports, lemma_block
from c10_caller_controls import mutate
from c10_wrapper_security_controls import only_definitions, replace_once

CONTRACTS = [
    ('paired-prefix', 'AddressedPairedSessionBound', 'paired_byte_addressed_node_euf_bound',
     '<= addressed_node_physical_euf_charge qr qs.', '<= addressed_node_independent_euf_charge qr qs.',
     '(paired_byte_addressed_node_euf_bound A qr qs &m)'),
    ('paired-keygen-prefix', 'AddressedPairedKeygenBound', 'paired_keygen_byte_addressed_node_euf_bound',
     '<= addressed_node_physical_euf_charge qr qs.', '<= addressed_node_independent_euf_charge qr qs.',
     '(paired_keygen_byte_addressed_node_euf_bound A qr qs &m)'),
    ('two-signing-passes', 'AddressedWrapperMemoCalls', 'nonordinary_wrapper_valid_count',
     '<=q+775', '<=q+773', '(nonordinary_wrapper_valid_count seed0 q)'),
    ('final-verifier', 'AddressedWrapperMemoSession', 'nonordinary_wrapper_byte_game_count',
     '<=wrapper_exceptional_public_budget qr qs]', '<=wrapper_exceptional_public_budget qr qs-771]',
     '(nonordinary_wrapper_byte_game_count A qr qs)'),
    ('raw-cap', 'AddressedWrapperMemoSession', 'nonordinary_wrapper_byte_game_count',
     'WrapperLimits.raw_cap=qr /\\ WrapperLimits.sign_cap=qs', 'WrapperLimits.sign_cap=qs',
     '(nonordinary_wrapper_byte_game_count A qr qs)'),
    ('actual-game', 'AddressedWrapperByteCollision', 'wrapper_byte_addressed_node_collision',
     'Pr[IndependentGame(WrapperByteContext(A)).run()', 'Pr[RealGame(WrapperByteContext(A)).run()',
     '(wrapper_byte_addressed_node_collision A qr qs &m)'),
    ('collision-charge', 'AddressedWrapperByteCollision', 'wrapper_query_byte_addressed_collision_best',
     '<=best_wrapper_addressed_node_charge qr qs.', '<=0%r.',
     '(wrapper_query_byte_addressed_collision_best A qr qs &m)'),
    ('wrapper-prefix', 'AddressedWrapperNumericalBound', 'wrapper_physical_byte_addressed_node_euf_bound',
     '<= wrapper_addressed_physical_euf_charge qr qs.', '<= wrapper_addressed_independent_euf_charge qr qs.',
     '(wrapper_physical_byte_addressed_node_euf_bound A qr qs &m)'),
]

# Each local charge is checked against the already proved original theorem.
CHARGES = [
    ('node-zero', '(wrapper_total_public_budget qr qs)%r*(1%r/2%r)^128 +', '0%r +'),
    ('encoding', '((wrapper_total_public_budget qr qs)*(wrapper_total_public_budget qr qs-1))%r/2%r*(1%r/2%r)^129 +', '0%r +'),
    ('wots', '632475648%r*', '0%r*'),
    ('fors', '6442450944%r*', '0%r*'),
    ('coverage', 'coverage_charge (qr+3*qs+1).', '0%r.'),
]
PROGRAMS = [
    ('second-call', 'second <@ RawSigner(O).sign(seed,root,random,message,shuffle_b);', 'second <- first;'),
    ('internal-verify', 'valid <@ RawSigner(O).verify(seed,root,message,oget first);', 'valid <- true;'),
]
# Exact-source calibration; parser/resource failures are never credited.
REASONS = {'second-call': '[by]: cannot close goals', 'internal-verify': '[by]: cannot close goals'}


def addressed_client_outputs(port):
    outputs = {}
    def save(name, source):
        outputs[port/'scratch'/('addressed_client_'+name.replace('-', '_')+'.ec')] = source.rstrip()+'\n'
    for name, file, theorem, before, after, application in CONTRACTS:
        source = (port/'cdrafts-split'/(file+'.ec')).read_text()
        statement = lemma_block(source, theorem).split('proof.')[0]
        statement = replace_once(statement, 'lemma '+theorem, 'lemma checked')
        changed = replace_once(statement, before, after)
        for mode, claim in [('positive', statement), ('reject', changed)]:
            save(name+'_'+mode, imports(source)+'require import '+file+'.\n'+claim+
                 'proof. exact '+application+'. qed.\n')
    file = 'AddressedWrapperNumericalBound'
    source = (port/'cdrafts-split'/(file+'.ec')).read_text()
    theorem = 'wrapper_query_byte_addressed_node_euf_bound'
    statement = lemma_block(source, theorem).split('proof.')[0]
    charge_source = ('require import '+file+'.\n'+only_definitions(source)+'\n'+statement+
        'proof. move=> ha hr hs hqr hqs; exact ('+file+'.'+theorem+' A qr qs &m ha hr hs hqr hqs). qed.\n')
    for name, before, after in CHARGES:
        changed = replace_once(charge_source, before, after)
        save(name+'_positive', charge_source)
        save(name+'_typed', only_definitions(changed))
        save(name+'_reject', changed)
    source = (port/'cdrafts-split/RawWrapper.ec').read_text()
    source = replace_once(source, 'module RawWrapper ', 'module ControlWrapper ')
    source = 'require import RawWrapper.\n'+source+'''
lemma wrapper_comparison (O <: PrefixOracle) :
  equiv [ControlWrapper(O).sign ~ RawWrapper(O).sign :
    ={arg,glob O} ==> ={res,glob O}].
proof.
  proc; sp 1 1; if; first by auto.
  + by sim; auto.
  by auto.
qed.
'''
    save('program_positive', source)
    save('program_preserving', mutate(source, 'ControlWrapper', 'sign', 'if (ready)', 'if (!!ready)'))
    for name, before, after in PROGRAMS:
        changed = mutate(source, 'ControlWrapper', 'sign', before, after)
        save(name+'_typed', only_definitions(changed))
        save(name+'_reject', changed)
    # Closed arithmetic witnesses distinguish the budget and retained minimum.
    # They make no claim that the conservative 775 bound is attained.
    header = ('require import AllCore StdOrder.\nrequire import AddressedWrapperMemoSession '
              'AddressedWrapperByteCollision.\nimport RealOrder.\n')
    for name, claim, false_claim, proof in [
        ('budget-arithmetic', 'wrapper_exceptional_public_budget 3 2=2324',
         'wrapper_exceptional_public_budget 3 2=1553', 'by rewrite /wrapper_exceptional_public_budget; smt()'),
        ('minimum', 'best_wrapper_addressed_node_charge 0 0<=retained_wrapper_node_charge 0 0',
         'retained_wrapper_node_charge 0 0<best_wrapper_addressed_node_charge 0 0',
         'rewrite /best_wrapper_addressed_node_charge; smt()')]:
        positive = header+'lemma witness : '+claim+'.\nproof. '+proof+'. qed.\n'
        save(name+'_positive', positive)
        save(name+'_reject', positive+'lemma checked : '+false_claim+'.\nproof. exact witness. qed.\n')
    return outputs


def addressed_client_rows():
    from pathlib import Path
    port = Path(__file__).resolve().parents[1]
    rows = []
    for path in sorted(addressed_client_outputs(port)):
        key = path.stem.removeprefix('addressed_client_').removesuffix('_reject').replace('_', '-')
        reason = REASONS.get(key, 'the given proof-term proves:')
        rows.append(str(path.relative_to(port))+'\t'+('MUST-FAIL\t'+reason if path.stem.endswith('_reject') else 'MUST-PASS\t-'))
    return rows
