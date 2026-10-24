"""Typed changes to the complete signer header and byte-expression consumers.

Each changed definition must type-check separately. Its unchanged consuming
proof must then reject at the named theorem, not an import or resource error.
"""
import re
from c10_representation import source
from c10_functional_verifier_controls import definition

GROUPS = {
    'header': ('C10FunctionalSignerHeader',
               ('signer_randomizer', 'signer_digest', 'signer_search_digests', 'signer_nonce_slot')),
    'bytes': ('C10FunctionalSignatureBytes', ('nodes_bytes', 'layer_bytes', 'signature_bytes')),
}
# Name, group, operator, Lean before/after, native before/after, intended consumers.
SIGNER_CHANGES = [
    ('optional-random', 'header', 'signer_randomizer',
     'r_preimage secret random message nonce', 'r_preimage secret [] message nonce',
     'r_preimage secret random message nonce', 'r_preimage secret [] message nonce',
     'randomizer_value', 'functional_randomizer_shared'),
    ('randomizer-order', 'header', 'signer_randomizer',
     'r_preimage secret random message nonce', 'r_preimage message random secret nonce',
     'r_preimage secret random message nonce', 'r_preimage message random secret nonce',
     'randomizer_value', 'functional_randomizer_shared'),
    ('randomizer-nonce', 'header', 'signer_randomizer',
     'r_preimage secret random message nonce', 'r_preimage secret random message (nonce+1)',
     'r_preimage secret random message nonce', 'r_preimage secret random message (nonce+1)',
     'randomizer_value', 'functional_randomizer_shared'),
    ('digest-root', 'header', 'signer_digest',
     'verifier_digest hash_fn seed root', 'verifier_digest hash_fn seed seed',
     'verifier_digest hash_fn seed root', 'verifier_digest hash_fn seed seed',
     'digest_value', 'functional_fors_digest_shared'),
    ('nonce-first-trial', 'header', 'signer_search_digests',
     '(Int.ofNat i)', '(Int.ofNat (i+1))', '(i)', '(i+1)',
     'schedule_value', 'functional_fors_slot_shared'),
    ('nonce-budget', 'header', 'signer_search_digests',
     '10000000', '9999999', '10000000', '9999999',
     'schedule_value', 'functional_fors_slot_shared'),
    ('nonce-sentinel', 'header', 'signer_nonce_slot',
     '(fors_first_slot (signer_search_digests hash_fn seed root secret random message))',
     '(fors_first_slot (signer_search_digests hash_fn seed root secret random message)+1)',
     '(fors_first_slot (signer_search_digests hash_fn seed root secret random message))',
     '(fors_first_slot (signer_search_digests hash_fn seed root secret random message)+1)',
     'extracted_header_result', 'functional_fors_slot_shared'),
    ('node-order', 'bytes', 'nodes_bytes', 'value ++ tail', 'tail ++ value',
     'value ++ tail', 'tail ++ value', 'nodes_bytes_flatten', 'nodes_bytes_flatten'),
    ('counter-high-bytes', 'bytes', 'layer_bytes', 'u32_bytes nonce', 'u32_bytes (nonce % 256)',
     'u32_bytes nonce', 'u32_bytes (nonce %% 256)', 'layer_encoding', 'layer_bytes_encoder'),
    ('forest-path-order', 'bytes', 'signature_bytes',
     '[] forest_paths)', '[] (List.reverse forest_paths))',
     '[] forest_paths)', '[] (rev forest_paths))', 'decoded_bytes', 'signature_bytes_encoder'),
    ('second-layer-fields', 'bytes', 'signature_bytes',
     'layer_bytes values1 nonce1 auth1', 'layer_bytes values0 nonce0 auth0',
     'layer_bytes values1 nonce1 auth1', 'layer_bytes values0 nonce0 auth0',
     'decoded_bytes', 'signature_bytes_encoder'),
    ('randomizer-prefix', 'bytes', 'signature_bytes', 'random ++', '[] ++',
     'random ++', '[] ++', 'decoded_bytes', 'signature_bytes_encoder'),
]
SIGNER_REASONS = {'optional-random': 'cannot save an incomplete proof', 'randomizer-order': 'cannot save an incomplete proof', 'randomizer-nonce': 'cannot save an incomplete proof', 'digest-root': 'cannot save an incomplete proof', 'nonce-first-trial': 'the given proof-term proves:', 'nonce-budget': 'the given proof-term proves:', 'nonce-sentinel': 'not a congruence', 'node-order': '[by]: cannot close goals', 'counter-high-bytes': '[by]: cannot close goals', 'forest-path-order': '[by]: cannot close goals', 'second-layer-fields': 'nothing to rewrite', 'randomizer-prefix': '[by]: cannot close goals'}


def functional_definitions(group, lean):
    return '\n\n'.join(definition(source(lean), name, lean) for name in GROUPS[group][1])+'\n'


def preserving_definitions(group, lean):
    from c10_representation_controls import changed
    original = functional_definitions(group, lean)
    if group == 'header':
        return changed(original, 'signer_search_digests', '10000000', '(9999999+1)', lean)
    return changed(original, 'nodes_bytes', 'fun value tail => (value ++ tail)',
                   'fun item rest => (item ++ rest)', lean)


def lean_fixture(root, group, definitions, typed=False):
    module = GROUPS[group][0]
    text = (root/'Extracted'/(module+'.lean')).read_text()
    imports = [line for line in text.splitlines() if line.startswith('import ')]
    text = '\n'.join(line for line in text.splitlines() if not line.startswith('import '))
    namespace = 'Extracted.'+module+'Probe'
    block = 'namespace '+namespace+'\nopen C10Representation\n'+definitions+'\nend '+namespace+'\n'
    body = '' if typed else text.replace('Extracted.'+module, namespace)
    return '\n'.join(imports)+'\n'+block+'\n'+body+'\n'


def native_fixture(port, group, definitions, typed=False):
    text = (port/'cdrafts-split'/(GROUPS[group][0]+'.ec')).read_text()
    imports = re.findall(r'(?m)^require import [^.]+\.', text)
    body = '' if typed else re.sub(r'(?m)^require import [^.]+\.', '', text)
    return '\n'.join(imports)+'\n\n'+definitions+'\n'+body+'\n'


def functional_signer_outputs(port):
    from c10_representation_controls import changed
    result = {}
    for group in GROUPS:
        for name, definitions in [('positive', functional_definitions(group, False)),
                                  ('preserving', preserving_definitions(group, False))]:
            result[port/'scratch'/('c10_signer_'+group+'_'+name+'.ec')] = native_fixture(port, group, definitions)
    for name, group, operator, _, _, before, after, _, _ in SIGNER_CHANGES:
        definitions = changed(functional_definitions(group, False), operator, before, after, False)
        stem = 'c10_signer_'+name.replace('-', '_')
        result[port/'scratch'/(stem+'_typed.ec')] = native_fixture(port, group, definitions, True)
        result[port/'scratch'/(stem+'_reject.ec')] = native_fixture(port, group, definitions)
    return {path: text.rstrip()+'\n' for path, text in result.items()}


def functional_signer_rows():
    rows = [f'scratch/c10_signer_{group}_{name}.ec\tMUST-PASS\t-'
            for group in GROUPS for name in ('positive', 'preserving')]
    for name, *_ in SIGNER_CHANGES:
        stem = 'scratch/c10_signer_'+name.replace('-', '_')
        rows += [stem+'_typed.ec\tMUST-PASS\t-', stem+'_reject.ec\tMUST-FAIL\t'+SIGNER_REASONS[name]]
    return rows
