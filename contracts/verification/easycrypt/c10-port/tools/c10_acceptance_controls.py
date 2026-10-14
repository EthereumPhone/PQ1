"""Typed changes to paired search tests, with unchanged consuming proofs."""
from c10_representation import source

# name, operator, Lean before/after, EasyCrypt before/after, intended lemma
ACCEPTANCE_CHANGES = [
    ('last-digit', 'wots_sum', 'List.range 43', 'List.range 42', ') 43)', ') 42)', 'wots_sum_common'),
    ('sum-origin', 'wots_sum', 'acc)) 0 ', 'acc)) 1 ', 'acc)) 0 ', 'acc)) 1 ', 'wots_sum_common'),
    ('target', 'wots_target', '205', '204', '205', '204', 'wots_accept_common'),
    ('fors-offset', 'fors_zero_field', '132', '131', '132', '131', 'fors_accept_common'),
    ('fors-width', 'fors_zero_field', '11', '10', '11', '10', 'fors_accept_common'),
]

# Calibrated against the pinned prover. A timeout or a type error never counts.
ACCEPTANCE_REASONS = {
    'last-digit': '[by]: cannot close goals',
    'sum-origin': '[by]: cannot close goals',
    'target': '[by]: cannot close goals',
    'fors-offset': 'nothing to rewrite',
    'fors-width': 'nothing to rewrite',
}


def acceptance_outputs(port):
    from c10_representation_controls import changed
    proof = (port / 'cdrafts-split/C10AcceptanceBridge.ec').read_text()
    anchor = 'require import C10Representation.'
    if proof.count(anchor) != 1:
        raise ValueError('acceptance representation import drift')
    generated = source(False)
    outputs = {port / 'scratch/c10_acceptance_positive.ec': proof.replace(anchor, generated)}
    benign = changed(generated, 'wots_target', '205', '(200 + 5)', False)
    benign = changed(benign, 'fors_zero_field', '11', '(5 + 6)', False)
    outputs[port / 'scratch/c10_acceptance_preserving.ec'] = proof.replace(anchor, benign)
    for name, func, _, _, before, after, _ in ACCEPTANCE_CHANGES:
        definitions = changed(generated, func, before, after, False)
        stem = 'c10_acceptance_' + name.replace('-', '_')
        outputs[port / 'scratch' / (stem + '_typed.ec')] = definitions
        outputs[port / 'scratch' / (stem + '_reject.ec')] = proof.replace(anchor, definitions)
    return outputs


def acceptance_rows():
    rows = ['scratch/c10_acceptance_positive.ec\tMUST-PASS\t-',
            'scratch/c10_acceptance_preserving.ec\tMUST-PASS\t-']
    for name, *_ in ACCEPTANCE_CHANGES:
        stem = 'scratch/c10_acceptance_' + name.replace('-', '_')
        rows.extend([stem + '_typed.ec\tMUST-PASS\t-',
                     stem + '_reject.ec\tMUST-FAIL\t' + ACCEPTANCE_REASONS[name]])
    return rows
