"""Controls for actual-wrapper coverage, accepted encodings and FORS charges.

Contract twins test exact theorem sensitivity, not probability lower bounds or
the tightness of conservative budgets. Changed charge definitions typecheck
separately. Closed arithmetic twins have explicit contradictory alternatives.
Existing wrapper program controls remain enrolled and unchanged.
"""
from addressed_node_controls import imports, lemma_block
from c10_wrapper_security_controls import only_definitions, replace_once


CONTRACTS = [
    ('coverage-budget', 'WrapperStirlingCoverage', 'wrapper_byte_stirling_coverage_bound',
     '<=stirling_coverage_charge (qr+3*qs+1).', '<=stirling_coverage_charge (qr+qs+1).',
     '(wrapper_byte_stirling_coverage_bound A qr qs &m)'),
    ('accepted-event', 'WrapperAcceptedEncodingCharge', 'wrapper_query_byte_accepted_encoding_collision',
     'accepted_wots_encoding_collision Independent.rawhistory', 'wots_encoding_collision Independent.rawhistory',
     '(wrapper_query_byte_accepted_encoding_collision A qr qs &m)'),
    ('actual-game', 'WrapperAcceptedEncodingCharge', 'wrapper_byte_accepted_encoding_collision',
     'Pr[IndependentGame(WrapperByteContext(A)).run()', 'Pr[RealGame(WrapperByteContext(A)).run()',
     '(wrapper_byte_accepted_encoding_collision A qr qs &m)'),
    ('two-signing-passes', 'WrapperLeafCandidateCost', 'wrapper_leaf_release_cost',
     '<=q+2*364892+771]', '<=q+364892+771]', '(wrapper_leaf_release_cost q)'),
    ('final-verifier', 'WrapperLeafSessionCost', 'wrapper_leaf_driver_cost',
     '<=q0+qr0+qs0*wrapper_leaf_public_budget+771]', '<=q0+qr0+qs0*wrapper_leaf_public_budget]',
     '(wrapper_leaf_driver_cost A q0 qr0 qs0)'),
    ('raw-cap', 'WrapperLeafSessionCost', 'wrapper_leaf_byte_cost',
     r'WrapperLimits.raw_cap=qr /\ WrapperLimits.sign_cap=qs', 'WrapperLimits.sign_cap=qs',
     '(wrapper_leaf_byte_cost A qr qs)'),
    ('fixed-guesses', 'WrapperSelectedLeafBound', 'wrapper_selected_leaf_candidate_bound',
     'qr qs+2+12', 'qr qs+12', '(wrapper_selected_leaf_candidate_bound A qr qs &m)'),
    ('final-output', 'WrapperSelectedLeafBound', 'wrapper_selected_leaf_candidate_bound',
     'qr qs+2+12', 'qr qs+2', '(wrapper_selected_leaf_candidate_bound A qr qs &m)'),
    ('physical-prefix', 'WrapperRefinedNumericalBound', 'wrapper_physical_byte_refined_euf_bound',
     '<= wrapper_refined_physical_euf_charge qr qs.', '<= wrapper_refined_independent_euf_charge qr qs.',
     '(wrapper_physical_byte_refined_euf_bound A qr qs &m)'),
]

CHARGES = [
    ('encoding', 'accepted_encoding_charge (wrapper_total_public_budget qr qs) +', '0%r +'),
    ('fors', 'best_wrapper_leaf_charge qr qs +', '0%r +'),
    ('coverage', 'stirling_coverage_charge (qr+3*qs+1).', '0%r.'),
]


def wrapper_nonnode_outputs(port):
    outputs = {}

    def save(name, source):
        outputs[port/'scratch'/('wrapper_nonnode_'+name.replace('-', '_')+'.ec')] = source.rstrip()+'\n'

    for name, file, theorem, before, after, application in CONTRACTS:
        source = (port/'cdrafts-split'/(file+'.ec')).read_text()
        statement = lemma_block(source, theorem).split('proof.')[0]
        statement = replace_once(statement, 'lemma '+theorem, 'lemma checked')
        changed = replace_once(statement, before, after)
        for mode, claim in [('positive', statement), ('reject', changed)]:
            extra = 'require import ByteEncodingCharge PrefixGames.\n' if name in ('accepted-event', 'actual-game') else ''
            save(name+'_'+mode, imports(source)+extra+'require import '+file+'.\n'+claim+
                 'proof. exact '+application+'. qed.\n')

    file = 'WrapperRefinedNumericalBound'
    source = (port/'cdrafts-split'/(file+'.ec')).read_text()
    theorem = 'wrapper_query_byte_refined_euf_bound'
    statement = lemma_block(source, theorem).split('proof.')[0]
    charge_source = ('require import '+file+'.\n'+only_definitions(source)+'\n'+statement+
        'proof. move=> ha hr hs hqr hqs; exact ('+file+'.'+theorem+' A qr qs &m ha hr hs hqr hqs). qed.\n')
    for name, before, after in CHARGES:
        changed = replace_once(charge_source, before, after)
        save(name+'_positive', charge_source)
        save(name+'_typed', only_definitions(changed))
        save(name+'_reject', changed)

    header = ('require import AllCore StdOrder.\nrequire import WrapperLeafSessionCost '
              'WrapperLeafOpeningBound.\nimport RealOrder.\n')
    for name, claim, false_claim, proof in [
        ('budget-arithmetic', 'wrapper_leaf_candidate_budget 3 2=1617019',
         'wrapper_leaf_candidate_budget 3 2=886464',
         'rewrite /wrapper_leaf_candidate_budget /wrapper_leaf_public_budget; smt()'),
        ('minimum', 'best_wrapper_leaf_charge 0 0<=retained_wrapper_fors_charge 0 0',
         'retained_wrapper_fors_charge 0 0<best_wrapper_leaf_charge 0 0',
         'rewrite /best_wrapper_leaf_charge; smt()')]:
        positive = header+'lemma witness : '+claim+'.\nproof. '+proof+'. qed.\n'
        save(name+'_positive', positive)
        save(name+'_reject', positive+'lemma checked : '+false_claim+'.\nproof. exact witness. qed.\n')

    # An equivalent regrouping of the per-attempt budget must still prove the
    # exact original arithmetic, without changing either signing contribution.
    save('budget_preserving', header+'''
op regrouped_budget qr qs = 155135+qr+qs*(364892+771+364892)+771.
lemma checked qr qs : regrouped_budget qr qs=wrapper_leaf_candidate_budget qr qs.
proof. rewrite /regrouped_budget /wrapper_leaf_candidate_budget /wrapper_leaf_public_budget; smt(). qed.
''')
    return outputs


def wrapper_nonnode_rows():
    from pathlib import Path
    port = Path(__file__).resolve().parents[1]
    return [str(path.relative_to(port))+'\t'+
            ('MUST-FAIL\tthe given proof-term proves:' if path.stem.endswith('_reject') else 'MUST-PASS\t-')
            for path in sorted(wrapper_nonnode_outputs(port))]
