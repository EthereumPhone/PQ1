"""Typed changes to functional WOTS values, consumed by unchanged endpoint proofs.

The existing caller/shuffle/backend controls retain their procedural mutations.
This family tests the eight new shared functional operators in both printers.
Definitions must typecheck first. A normal proof rejection demonstrates proof
sensitivity at its recorded consumer, not a proof of a mutated theorem's negation.
"""
import re
from c10_representation import source

MODULES = ('C10FunctionalWotsValue', 'C10FunctionalWotsChain', 'C10FunctionalWotsKeygen',
           'C10FunctionalWotsRecover', 'C10FunctionalWotsShuffle', 'C10FunctionalWotsFill',
           'C10FunctionalWotsSign')
OPERATORS = ('hash_bytes_node', 'wots_secret_value', 'wots_chain_value', 'wots_keygen_nodes',
             'wots_keygen_value', 'wots_sign_values', 'wots_recover_nodes', 'wots_recover_value')

# name, operator, Lean before/after, EasyCrypt before/after, Lean/EC first consumer.
WOTS_CHANGES = [
    ('node-width', 'hash_bytes_node', 'List.take 16', 'List.take 15', 'take 16', 'take 15',
     'hash_step_value', 'interpreted_node'),
    ('backend-input', 'hash_bytes_node', '(hash_fn bs)', '(hash_fn (List.reverse bs))',
     '(hash_fn bs)', '(hash_fn (rev bs))', 'hash_step_value', 'interpreted_node'),
    ('secret-index', 'wots_secret_value', 'layer tree kp ci)', 'layer tree kp (ci+1))',
     'layer tree kp ci)', 'layer tree kp (ci+1))', 'secret_pure_value', 'functional_private_node'),
    ('chain-order', 'wots_chain_value', 'List.reverse', 'id', 'rev ', 'idfun ',
     'chain_succ', 'functional_chain_fold'),
    ('chain-position', 'wots_chain_value', 'start + (Int.ofNat i)', '(start + (Int.ofNat i)) + 1',
     'start + (i)', '(start + (i)) + 1', 'chain_succ', 'functional_chain_fold'),
    ('keygen-count', 'wots_keygen_nodes', 'List.range 43', 'List.range 42', ') 43)', ') 42)',
     'keygen_nodes_value', 'functional_keygen_nodes'),
    ('keygen-steps', 'wots_keygen_nodes', ') 0 7)', ') 0 6)', ') 0 7)', ') 0 6)',
     'keygen_nodes_value', 'functional_keygen_nodes'),
    ('keygen-kind', 'wots_keygen_value', 'layer tree 1 kp', 'layer tree 2 kp',
     'layer tree 1 kp', 'layer tree 2 kp', 'keygen_pure_value', 'functional_keygen_value'),
    ('sign-digit', 'wots_sign_values', 'Int.toNat (wots_field bs i)', 'Int.toNat (7 - (wots_field bs i))',
     'max 0 (wots_field bs i)', 'max 0 (7 - (wots_field bs i))', 'sign_nodes_value', 'functional_sign_nodes'),
    ('recover-steps', 'wots_recover_nodes', '(7 - (wots_field bs i))', '(6 - (wots_field bs i))',
     '(7 - (wots_field bs i))', '(6 - (wots_field bs i))', 'recover_nodes_value', 'functional_recover_nodes'),
    ('recover-target', 'wots_recover_value', '(wots_target )', '((wots_target )+1)',
     '(wots_target )', '((wots_target )+1)', 'extracted_recover_value', 'functional_recover_value'),
    ('recover-rejection', 'wots_recover_value', 'else (List.replicate 16 0)', 'else (List.replicate 16 1)',
     'else (nseq 16 0)', 'else (nseq 16 1)', 'extracted_recover_value', 'functional_recover_value'),
]


def functional_definitions(lean):
    text = source(lean)
    prefix = 'def ' if lean else 'op '
    result = []
    for name in OPERATORS:
        match = re.search(r'(?ms)^' + prefix + name + r'\b.*?(?=\n\n|\Z)', text)
        if not match:
            raise ValueError('functional WOTS operator missing: ' + name)
        result.append(match.group())
    return '\n\n'.join(result) + '\n'


def native_fixture(port, definitions):
    imports, bodies = [], []
    for name in MODULES:
        text = (port / 'cdrafts-split' / (name + '.ec')).read_text()
        def collect(match):
            for theory in match.group(1).split():
                if theory not in MODULES and theory not in imports:
                    imports.append(theory)
            return ''
        bodies.append(re.sub(r'(?m)^require import ([^.]+)\.', collect, text))
    return 'require import ' + ' '.join(imports) + '.\n\n' + definitions + '\n' + '\n'.join(bodies)


# Calibrated in isolated pinned-image workers; no SMT uncertainty is credited.
WOTS_REASONS = {row[0]: '[by]: cannot close goals' for row in WOTS_CHANGES}
WOTS_REASONS.update({
    'node-width': 'the given proof-term proves:',
    'backend-input': 'the given proof-term proves:',
    'chain-order': 'nothing to rewrite',
    'sign-digit': 'nothing to rewrite',
    'recover-steps': 'nothing to rewrite',
    'recover-target': 'nothing to rewrite',
})


def functional_wots_outputs(port):
    from c10_representation_controls import changed
    from c10_functional_wots_fixtures import fixture_source
    original = functional_definitions(False)
    benign = changed(original, 'hash_bytes_node', 'take 16', 'take (8+8)', False)
    results = {port / 'scratch/c10_wots_value_positive.ec': native_fixture(port, original),
               port / 'scratch/c10_wots_value_preserving.ec': native_fixture(port, benign),
               port / 'scratch/c10_wots_value_fixtures.ec': fixture_source(False)}
    for name, operator, _, _, before, after, _, _ in WOTS_CHANGES:
        altered = changed(original, operator, before, after, False)
        stem = 'c10_wots_value_' + name.replace('-', '_')
        results[port / 'scratch' / (stem + '_typed.ec')] = 'require import AllCore List IntDiv C10Representation.\n' + altered
        results[port / 'scratch' / (stem + '_reject.ec')] = native_fixture(port, altered)
    return {path: text.rstrip() + '\n' for path, text in results.items()}


def functional_wots_rows():
    rows = ['scratch/c10_wots_value_positive.ec\tMUST-PASS\t-',
            'scratch/c10_wots_value_preserving.ec\tMUST-PASS\t-',
            'scratch/c10_wots_value_fixtures.ec\tMUST-PASS\t-']
    for name, *_ in WOTS_CHANGES:
        stem = 'scratch/c10_wots_value_' + name.replace('-', '_')
        rows.extend([stem + '_typed.ec\tMUST-PASS\t-',
                     stem + '_reject.ec\tMUST-FAIL\t' + WOTS_REASONS[name]])
    return rows
