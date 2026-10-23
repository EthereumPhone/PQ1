"""Typed forest/layer value changes consumed by the unchanged endpoint proofs."""
import re
from c10_representation import source

MODULES = ('C10FunctionalCallerState', 'C10FunctionalCallerShuffle',
           'C10FunctionalForestRecover', 'C10FunctionalLayerRecover', 'C10FunctionalLayerSign',
           'C10FunctionalForestOne', 'C10FunctionalForestFill', 'C10FunctionalForestValue',
           'C10FunctionalForestSign')
OPERATORS = ('forest_sign_secrets', 'forest_sign_paths', 'forest_recover_roots',
             'forest_compress_value', 'forest_recover_value', 'forest_sign_value',
             'wots_search_digests', 'layer_sign_slot', 'layer_sign_values', 'layer_recover_value')
# Name, operator, Lean before/after, EasyCrypt before/after, first Lean/EC consumer.
CALLER_CHANGES = [
    ('forest-last-tree', 'forest_sign_secrets', 'seed secret ht 12)', 'seed secret ht 11)',
     'seed secret ht 12)', 'seed secret ht 11)', 'signer_secrets_value', 'functional_forest_secrets_value'),
    ('forest-secret-index', 'forest_sign_secrets', 'List.getD forest_indices i 0', 'List.getD forest_indices (i+1) 0',
     'nth 0 forest_indices i', 'nth 0 forest_indices (i+1)', 'signer_secrets_value', 'functional_forest_secrets_value'),
    ('forest-path-index', 'forest_sign_paths', 'List.getD forest_indices i 0', 'List.getD forest_indices (i+1) 0',
     'nth 0 forest_indices i', 'nth 0 forest_indices (i+1)', 'signer_paths_value', 'functional_forest_paths_value'),
    ('forest-last-leaf', 'forest_recover_roots', 'seed ht 12 0', 'seed ht 12 1',
     'seed ht 12 0', 'seed ht 12 1', 'signer_roots_value', 'functional_forest_roots_value'),
    ('forest-compress-domain', 'forest_compress_value', '0 ht 4 0', '0 ht 3 0',
     '0 ht 4 0', '0 ht 3 0', 'forest_compression_value', 'fixed_functional_forest_recover'),
    ('forest-recover-order', 'forest_recover_value', 'forest_indices forest_secrets forest_paths', 'forest_indices (List.reverse forest_secrets) forest_paths',
     'forest_indices forest_secrets forest_paths', 'forest_indices (rev forest_secrets) forest_paths',
     'extracted_forest_sign_value', 'fixed_functional_forest_recover'),
    ('forest-sign-address', 'forest_sign_value', 'forest_recover_value hash_fn seed ht', 'forest_recover_value hash_fn seed (ht+1)',
     'forest_recover_value hash_fn seed ht', 'forest_recover_value hash_fn seed (ht+1)',
     'extracted_forest_sign_value', 'functional_forest_result_value'),
    ('layer-search-bound', 'wots_search_digests', 'List.range 10000000', 'List.range 9999999',
     '10000000).', '9999999).', 'pure_layer_sign_values', 'functional_layer_slot_shared'),
    ('layer-slot-sentinel', 'layer_sign_slot', 'kp message))', 'kp message)) + 1',
     'kp message)).', 'kp message)) + 1.', 'pure_layer_sign_values', 'functional_layer_slot_shared'),
    ('layer-signed-counter', 'layer_sign_values', '))), nonce,', '))), nonce+1,',
     '))), nonce,', '))), nonce+1,', 'pure_layer_sign_values', 'functional_layer_payload'),
    ('layer-signed-path', 'layer_sign_values', 'merkle_auth_values hash_fn seed secret layer tree kp', 'merkle_auth_values hash_fn seed secret layer tree (kp+1)',
     'merkle_auth_values hash_fn seed secret layer tree kp', 'merkle_auth_values hash_fn seed secret layer tree (kp+1)',
     'pure_layer_sign_values', 'functional_layer_payload'),
    ('layer-recover-position', 'layer_recover_value', 'nonce) kp auth', 'nonce) (kp+1) auth',
     'nonce) kp auth', 'nonce) (kp+1) auth', 'layer_recovery_value', 'fixed_functional_layer_recover'),
]
CALLER_REASONS = {row[0]: '[by]: cannot close goals' for row in CALLER_CHANGES}
for _name in ('forest-compress-domain', 'forest-recover-order', 'layer-signed-counter',
              'layer-signed-path', 'layer-recover-position'):
    CALLER_REASONS[_name] = 'cannot prove goal (strict)'

CALLER_REASONS['forest-last-tree'] = 'the given proof-term proves:'
for _name in ('forest-secret-index', 'forest-path-index'):
    CALLER_REASONS[_name] = 'cannot prove goal (strict)'


def functional_definitions(lean):
    text = source(lean)
    prefix = 'def ' if lean else 'op '
    definitions = []
    for name in OPERATORS:
        match = re.search(r'(?ms)^' + prefix + name + r'\b.*?(?=\n\n|\Z)', text)
        if not match:
            raise ValueError('functional caller definition missing: ' + name)
        definitions.append(match.group())
    return '\n\n'.join(definitions) + '\n'


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


def functional_caller_outputs(port):
    from c10_representation_controls import changed
    from c10_functional_caller_fixtures import fixture_source
    original = functional_definitions(False)
    benign = changed(original, 'forest_compress_value', '0 ht 4 0', '0 ht (2+2) 0', False)
    result = {port / 'scratch/c10_caller_value_positive.ec': native_fixture(port, original),
              port / 'scratch/c10_caller_value_preserving.ec': native_fixture(port, benign),
              port / 'scratch/c10_caller_value_fixtures.ec': fixture_source(False)}
    for name, operator, _, _, before, after, _, _ in CALLER_CHANGES:
        altered = changed(original, operator, before, after, False)
        stem = 'c10_caller_value_' + name.replace('-', '_')
        result[port / 'scratch' / (stem + '_typed.ec')] = 'require import AllCore List IntDiv C10Representation.\n' + altered
        result[port / 'scratch' / (stem + '_reject.ec')] = native_fixture(port, altered)
    return {path: text.rstrip() + '\n' for path, text in result.items()}


def functional_caller_rows():
    rows = ['scratch/c10_caller_value_positive.ec\tMUST-PASS\t-',
            'scratch/c10_caller_value_preserving.ec\tMUST-PASS\t-',
            'scratch/c10_caller_value_fixtures.ec\tMUST-PASS\t-']
    for name, *_ in CALLER_CHANGES:
        stem = 'scratch/c10_caller_value_' + name.replace('-', '_')
        rows += [stem + '_typed.ec\tMUST-PASS\t-',
                 stem + '_reject.ec\tMUST-FAIL\t' + CALLER_REASONS[name]]
    return rows
