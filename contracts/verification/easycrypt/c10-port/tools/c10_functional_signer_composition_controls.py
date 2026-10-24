"""Typed signer-composition changes; native-only rows cover history and cost."""
import re
from c10_functional_verifier_controls import definition

MODULES = ('C10FunctionalSignerValue', 'C10FunctionalSignerState',
           'C10FunctionalSignerFinish', 'C10FunctionalSigner')
# Name, Lean operator/before/after/consumer, native operator/before/after/consumer.
COMPOSITION_CHANGES = [
    ('first-coordinate', 'finishResult', '0 (ht/512) (ht%512)', '0 (ht%512) (ht/512)',
     'finish_result', 'paired_finish_result', '0 (ht %/ 512) (ht %% 512)',
     '0 (ht %% 512) (ht %/ 512)', 'functional_signer_finish_value'),
    ('second-layer', 'finishResult', '1 (ht/512/512)', '0 (ht/512/512)',
     'finish_result', 'paired_finish_result', '1 (ht %/ 512 %/ 512)',
     '0 (ht %/ 512 %/ 512)', 'functional_signer_finish_value'),
    ('second-message', 'finishResult', '(ht/512%512) current', '(ht/512%512) forest.2.2',
     'finish_result', 'paired_finish_result', '(ht %/ 512 %% 512) (oget first).`2',
     '(ht %/ 512 %% 512) forest.`3', 'functional_signer_finish_value'),
    ('second-exhaustion', 'finishResult',
     'layerResult f seed secret 1 (ht/512/512) (ht/512%512) current', '.ok (first,current)',
     'finish_result', 'paired_finish_result',
     'paired_layer_result fn key seed 1 (ht %/ 512 %/ 512) (ht %/ 512 %% 512) (oget first).`2',
     'first', 'functional_signer_finish_value'),
    ('outer-root', 'signerResult', 'headerResult f seed root secret random message',
     'headerResult f seed seed secret random message', 'pure_signer_result',
     'paired_signer_result', 'signer_nonce_slot fn seed root key random message',
     'signer_nonce_slot fn seed seed key random message', 'functional_signer_value'),
]
NATIVE_EFFECT_CHANGES = [
    ('header-call-cost', 'functional_signer_cost', '2 * functional_header_steps',
     '1 * functional_header_steps', 'functional_signer_success'),
    ('exhaustion-history', 'functional_signer_state', 'then final = searched',
     'then final = h', 'functional_signer_exhausted'),
    ('finish-history', 'functional_finish_state',
     'functional_signer_layers_state f forest final key seed d shuffle',
     'functional_signer_layers_state f initial final key seed d shuffle',
     'functional_signer_complete'),
]
COMPOSITION_REASONS = {
    'first-coordinate': 'cannot prove goal (strict)',
    'second-layer': 'cannot prove goal (strict)',
    'second-message': 'cannot prove goal (strict)',
    'second-exhaustion': 'cannot prove goal (strict)',
    'outer-root': '[by]: cannot close goals',
    'header-call-cost': 'cannot save an incomplete proof',
    'exhaustion-history': 'cannot save an incomplete proof',
    'finish-history': 'cannot prove goal (strict)',
}


def lean_fixture(root, mutation=None, typed=False, preserving=False):
    from c10_representation_controls import changed
    values = (root/'Extracted/C10FunctionalSignerValues.lean').read_text()
    definitions = '\n\n'.join(definition(values, n, True) for n in ('finishResult', 'signerResult'))
    if preserving:
        definitions = changed(definitions, 'finishResult', 'let ht := ht_field digest',
                              'let ht := (fun input => ht_field input) digest', True)
    if mutation:
        definitions = changed(definitions, *mutation, True)
    text = (root/'Extracted/C10FunctionalSigner.lean').read_text()
    namespace = 'Extracted.C10FunctionalSignerProbe'
    text = text.replace('Extracted.C10FunctionalSigner\n', namespace+'\n')
    anchor = 'namespace '+namespace+'\n'
    if text.count(anchor) != 1:
        raise ValueError('signer namespace anchor drift')
    if typed:
        return text[:text.index(anchor)]+anchor+definitions+'\nend '+namespace+'\n'
    return text.replace(anchor, anchor+'\n'+definitions+'\n', 1)


def native_fixture(port, mutation=None, typed=False, preserving=False):
    from c10_representation_controls import changed
    imports, bodies = [], []
    for module in MODULES:
        text = (port/'cdrafts-split'/(module+'.ec')).read_text()
        def collect(match):
            for imported in match.group(1).split():
                if imported not in MODULES and imported not in imports:
                    imports.append(imported)
            return ''
        bodies.append(re.sub(r'(?m)^require import ([^.]+)\.', collect, text))
    body = '\n'.join(bodies)
    if preserving:
        body = changed(body, 'paired_finish_result', 'let ht = ht_field d',
                       'let ht = (fun input => ht_field input) d', False)
    if mutation:
        body = changed(body, *mutation, False)
    if typed:
        names = re.findall(r'(?m)^op (\w+) ', body)
        # These hand-written operators are adjacent, unlike generated operators;
        # a blank-line delimiter would duplicate each trailing declaration.
        from cert_cone import _decl_span
        declarations = [_decl_span(body, body.index('op '+name+' ')) for name in names]
        if any('\nlemma ' in text or not text.endswith('.') for text in declarations):
            raise ValueError('composition operator boundary drift')
        body = '\n\n'.join(declarations)
    return 'require import '+' '.join(imports)+'.\n\n'+body+'\n'


def native_changes():
    return [(name, operator, before, after, theorem)
            for name, _, _, _, _, operator, before, after, theorem in COMPOSITION_CHANGES]+NATIVE_EFFECT_CHANGES


def signer_composition_outputs(port):
    result = {port/'scratch/c10_signer_composition_positive.ec': native_fixture(port),
              port/'scratch/c10_signer_composition_preserving.ec': native_fixture(port, preserving=True)}
    for name, operator, before, after, _ in native_changes():
        stem = 'c10_signer_composition_'+name.replace('-', '_')
        result[port/'scratch'/(stem+'_typed.ec')] = native_fixture(port, (operator,before,after), True)
        result[port/'scratch'/(stem+'_reject.ec')] = native_fixture(port, (operator,before,after))
    return {path: text.rstrip()+'\n' for path, text in result.items()}


def signer_composition_rows():
    rows = ['scratch/c10_signer_composition_positive.ec\tMUST-PASS\t-',
            'scratch/c10_signer_composition_preserving.ec\tMUST-PASS\t-']
    for name, *_ in native_changes():
        stem = 'scratch/c10_signer_composition_'+name.replace('-', '_')
        rows += [stem+'_typed.ec\tMUST-PASS\t-',stem+'_reject.ec\tMUST-FAIL\t'+COMPOSITION_REASONS[name]]
    return rows
