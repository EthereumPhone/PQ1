"""Typed complete-verifier changes against unchanged endpoint proofs.

Only the six appended expressions are shadowed; earlier component theorems
remain imported unchanged. The decision mutations alter the actual new Boolean
comparison definition, then recheck its unchanged consuming theorem.
"""
import re
from c10_representation import source

MODULES = ('C10FunctionalVerifierValue', 'C10FunctionalVerifierState', 'C10FunctionalVerifier')
OPERATORS = ('digest_fors_indices', 'verifier_digest', 'digest_forest_value',
             'hypertree_first_value', 'hypertree_recover_value', 'verifier_recover_value')
# Name, operator (decision means the hand-written final Boolean adapter),
# Lean before/after, native before/after, first Lean/native consuming theorem.
VERIFIER_CHANGES = [
    ('digest-indices', 'digest_fors_indices', 'fors_field bs i', 'fors_field bs (i+1)',
     'fors_field bs i', 'fors_field bs (i+1)', 'header_index_words', 'functional_digest_indices'),
    ('digest-root', 'verifier_digest', 'hmsg_preimage seed root', 'hmsg_preimage seed seed',
     'hmsg_preimage seed root', 'hmsg_preimage seed seed', 'digest_value', 'functional_verifier_digest'),
    ('forest-digest', 'digest_forest_value', '(ht_field bs)', '(ht_field (List.reverse bs))',
     '(ht_field bs)', '(ht_field (rev bs))', 'decoded_verifier_result', 'functional_verifier_forest_value'),
    ('first-position', 'hypertree_first_value', '(ht % 512)', '(ht % 511)',
     '(ht %% 512)', '(ht %% 511)', 'extracted_hypertree_value', 'functional_verifier_layer_step'),
    ('top-layer', 'hypertree_recover_value', 'hash_fn seed 1', 'hash_fn seed 0',
     'hash_fn seed 1', 'hash_fn seed 0', 'extracted_hypertree_value', 'functional_verifier_layer_step'),
    ('second-message', 'hypertree_recover_value',
     '(hypertree_first_value hash_fn seed ht message values0 nonce0 auth0)', 'message',
     '(hypertree_first_value hash_fn seed ht message values0 nonce0 auth0)', 'message',
     'extracted_hypertree_value', 'functional_verifier_layer_step'),
    ('forest-order', 'verifier_recover_value', 'bs forest_secrets forest_paths',
     'bs (List.reverse forest_secrets) forest_paths', 'bs forest_secrets forest_paths',
     'bs (rev forest_secrets) forest_paths', 'decoded_verifier_result', 'functional_verifier_layer_step'),
    ('forced-zero', 'decision', 'fors_zero_field digest = 0', 'fors_zero_field digest = 1',
     'fors_zero_field d = 0', 'fors_zero_field d = 1', 'decoded_verifier_result', 'functional_verifier_decision'),
    ('final-root', 'decision', '= root)', '= seed)', '= root.', '= seed.',
     'decoded_verifier_result', 'functional_verifier_decision'),
    ('second-fields', 'decision', 'let second := sig.2.2.2.getD 1', 'let second := sig.2.2.2.getD 0',
     'let second = nth ([],0,[]) sig.`4 1', 'let second = nth ([],0,[]) sig.`4 0',
     'decoded_verifier_result', 'functional_verifier_decision'),
]
VERIFIER_REASONS = {row[0]: 'cannot save an incomplete proof' for row in VERIFIER_CHANGES}
VERIFIER_REASONS['digest-indices'] = 'the given proof-term proves:'
VERIFIER_REASONS['digest-root'] = '[by]: cannot close goals'


def definition(text, name, lean):
    prefix = 'def ' if lean else 'op '
    match = re.search(r'(?ms)^'+prefix+name+r'\b.*?(?=\n\n|\Z)', text)
    if not match:
        raise ValueError('verifier definition missing: '+name)
    return match.group()


def functional_definitions(lean):
    text = source(lean)
    return '\n\n'.join(definition(text,name,lean) for name in OPERATORS)+'\n'


def native_fixture(port, definitions, mutation=None, typed=False):
    from c10_representation_controls import changed
    imports, bodies = [], []
    for name in MODULES:
        text = (port/'cdrafts-split'/(name+'.ec')).read_text()
        def collect(match):
            for theory in match.group(1).split():
                if theory not in MODULES and theory not in imports:
                    imports.append(theory)
            return ''
        text = re.sub(r'(?m)^require import ([^.]+)\.', collect, text)
        if name == 'C10FunctionalVerifier' and mutation:
            text = changed(text, 'paired_verifier_result', *mutation, False)
        bodies.append(text)
    if typed:
        body = definition(bodies[-1], 'paired_verifier_result', False) if mutation else ''
    else:
        body = '\n'.join(bodies)
    return 'require import '+' '.join(imports)+'.\n\n'+definitions+'\n'+body+'\n'


def lean_fixture(root, definitions, mutation=None, typed=False):
    from c10_representation_controls import changed
    text = (root/'Extracted/C10FunctionalVerifier.lean').read_text()
    imports = [line for line in text.splitlines() if line.startswith('import ')]
    text = '\n'.join(line for line in text.splitlines() if not line.startswith('import '))
    if mutation:
        text = changed(text, 'verifierResult', *mutation, True)
    namespace = 'Extracted.C10FunctionalVerifierProbe'
    text = text.replace('Extracted.C10FunctionalVerifier', namespace)
    block = 'namespace '+namespace+'\nopen C10Representation\n'+definitions+'\nend '+namespace+'\n'
    if typed:
        text = ('namespace '+namespace+'\nopen C10Representation Extracted.C10RepresentationBridge\n'+
                definition(text, 'verifierResult', True)+'\nend '+namespace+'\n') if mutation else ''
    return '\n'.join(imports)+'\n'+block+'\n'+text+'\n'


def functional_verifier_outputs(port):
    from c10_representation_controls import changed
    original = functional_definitions(False)
    benign = changed(original,'hypertree_recover_value','hash_fn seed 1','hash_fn seed (2-1)',False)
    result = {port/'scratch/c10_verifier_value_positive.ec':native_fixture(port,original),
              port/'scratch/c10_verifier_value_preserving.ec':native_fixture(port,benign)}
    for name,operator,_,_,before,after,_,_ in VERIFIER_CHANGES:
        altered = original if operator == 'decision' else changed(original,operator,before,after,False)
        mutation = (before,after) if operator == 'decision' else None
        stem = 'c10_verifier_value_'+name.replace('-','_')
        result[port/'scratch'/(stem+'_typed.ec')] = native_fixture(port,altered,mutation,True)
        result[port/'scratch'/(stem+'_reject.ec')] = native_fixture(port,altered,mutation)
    return {path:text.rstrip()+'\n' for path,text in result.items()}


def functional_verifier_rows():
    rows = ['scratch/c10_verifier_value_positive.ec\tMUST-PASS\t-',
            'scratch/c10_verifier_value_preserving.ec\tMUST-PASS\t-']
    for name,*_ in VERIFIER_CHANGES:
        stem = 'scratch/c10_verifier_value_'+name.replace('-','_')
        rows += [stem+'_typed.ec\tMUST-PASS\t-',stem+'_reject.ec\tMUST-FAIL\t'+VERIFIER_REASONS[name]]
    return rows
