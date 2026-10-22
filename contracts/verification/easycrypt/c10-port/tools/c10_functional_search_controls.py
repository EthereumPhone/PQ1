"""Typed functional-search mutations and equivalent edits, with real consumers.

Definitions must compile before a failed proof earns credit. Procedure variants
first check deterministic correspondence, then retain the functional consumers.
Rejection at correspondence does not independently test each later invariant.
"""
import re
from c10_caller_controls import mutate

# name, operator, before, after, consuming theorem (same in both printers).
SELECTOR_CHANGES = [
    ('wots-origin', 'wots_first_slot', 'then 1 else', 'then 2 else', 'wots_first_slot_common'),
    ('wots-exhaustion', 'wots_first_slot', 'slot = 0 then 0', 'slot = 0 then 1', 'wots_first_slot_common'),
    ('wots-step', 'wots_first_slot', 'slot + 1', 'slot + 2', 'wots_first_slot_common'),
    ('wots-signed-zero', 'wots_first_slot', '((wots_sum digest) - (wots_target ))',
     '(max 0 ((wots_sum digest) - (wots_target )))', 'wots_first_slot_common'),
    ('fors-origin', 'fors_first_slot', 'then 1 else', 'then 2 else', 'fors_first_slot_common'),
    ('fors-exhaustion', 'fors_first_slot', 'slot = 0 then 0', 'slot = 0 then 1', 'fors_first_slot_common'),
    ('fors-step', 'fors_first_slot', 'slot + 1', 'slot + 2', 'fors_first_slot_common'),
]

# name, family, module, procedure, before, after, original consumer.
# The deterministic `checked` comparison runs before that consumer.
PROCEDURE_CHANGES = [
    ('backend-cost', 'backend', 'FixedBackend', 'hash',
     'calls <- calls + 1', 'calls <- calls + 2', 'fixed_hash'),
    ('backend-output', 'backend', 'FixedBackend', 'hash',
     'return oget history.[x]', 'return []', 'fixed_hash'),
    ('backend-history', 'backend', 'FixedBackend', 'hash',
     'history.[x] <- fn x', 'history <- empty.[x <- fn x]', 'fixed_hash'),
    ('wots-cap', 'wots', 'PairedAcceptanceWots', 'count',
     'i < signing_budget /\\ result = None', 'i < signing_budget-1 /\\ result = None', 'functional_wots_prefix'),
    ('wots-index', 'wots', 'PairedAcceptanceWots', 'count',
     'result <- Some (i,d)', 'result <- Some (i+1,d)', 'functional_wots_prefix'),
    ('wots-start', 'wots', 'PairedAcceptanceWots', 'count',
     'i <- 0', 'i <- 1', 'functional_wots_prefix'),
    ('fors-cap', 'fors', 'PairedAcceptanceGrind', 'run',
     'i < signing_budget /\\ result = None', 'i < signing_budget-1 /\\ result = None', 'fixed_fors_prefix'),
    ('fors-result', 'fors', 'PairedAcceptanceGrind', 'run',
     'result <- Some (r,hd)', 'result <- Some (r,rd)', 'fixed_fors_prefix'),
    ('fors-start', 'fors', 'PairedAcceptanceGrind', 'run',
     'i <- 0', 'i <- 1', 'fixed_fors_prefix'),
]


def definitions_only(text):
    result, count = re.subn(r'(?ms)^lemma\b.*?\bqed\.', '', text)
    if count != len(re.findall(r'(?m)^lemma\b', text)) or count == 0:
        raise ValueError('functional control lemma boundary drift')
    if re.search(r'(?m)^(lemma|proof|qed)\b', result):
        raise ValueError('functional type fixture retained a proof')
    return result


def correspondence(family):
    if family == 'backend':
        state = ('FixedBackend.fn{1} = C10FixedBackend.FixedBackend.fn{2} /\\ '
                 'FixedBackend.history{1} = C10FixedBackend.FixedBackend.history{2} /\\ '
                 'FixedBackend.calls{1} = C10FixedBackend.FixedBackend.calls{2}')
        return ('require C10FixedBackend.\nlemma checked :\n'
                '  equiv[FixedBackend.hash ~ C10FixedBackend.FixedBackend.hash :\n'
                '    ={x} /\\ ' + state + ' ==> ={res} /\\ ' + state + '].\n'
                'proof. proc; sp 1 1; if; auto => />; try ring. qed.\n')
    if family == 'wots':
        proc = 'PairedAcceptanceWots(PreparationView(FixedPrefix)).count'
    else:
        proc = 'PairedAcceptanceGrind(FixedPrefix).run'
    variables = 'seed,layer,tree,kp,message,i,result' if family == 'wots' else 'random,message,seed,root,i,result'
    calls = 'wp; call (_ : ={arg,glob FixedPrefix} ==> ={res,glob FixedPrefix}); first by sim.\n'
    if family == 'fors':
        calls += '    wp; call (_ : ={arg,glob FixedPrefix} ==> ={res,glob FixedPrefix}); first by sim.\n'
    return ('require C10SearchAcceptance.\nlemma checked :\n'
            f'  equiv[{proc} ~ C10SearchAcceptance.{proc} :\n'
            '    ={arg,glob FixedPrefix} ==> ={res,glob FixedPrefix}].\n'
            f'proof. proc; while (={{{variables},glob FixedPrefix}}).\n'
            '  + ' + calls + '    auto => />; try ring.\n'
            '  auto => />; try ring.\nqed.\n')


def fixture(port, family):
    names = {
        'selector': ['C10Representation', 'C10FirstHit'],
        'backend': ['C10FixedBackend'],
        'wots': ['C10FirstHit', 'C10SearchAcceptance',
                 'C10FixedBackend', 'C10FunctionalWots'],
        'fors': ['C10FirstHit', 'C10SearchAcceptance',
                 'C10FixedBackend', 'C10FunctionalFors'],
    }[family]
    imports, bodies = [], []
    for name in names:
        text = (port / 'cdrafts-split' / (name + '.ec')).read_text()
        if name == 'C10SearchAcceptance':
            text = definitions_only(text)
        def collect(match):
            for theory in match.group(1).split():
                if theory not in names and theory not in imports:
                    imports.append(theory)
            return ''
        bodies.append(re.sub(r'(?m)^require import ([^.]+)\.', collect, text))
    text = 'require import ' + ' '.join(imports) + '.\n\n' + '\n'.join(bodies)
    if family != 'selector':
        proofs = re.findall(r'(?ms)^lemma\b.*?\bqed\.', text)
        text = definitions_only(text) + '\n' + correspondence(family) + '\n' + '\n'.join(proofs) + '\n'
    return text


# Calibrated on the pinned checker; no rejection uses inconclusive SMT attempts.
FUNCTIONAL_REASONS = {name: '[by]: cannot close goals' for name, *_ in SELECTOR_CHANGES}
FUNCTIONAL_REASONS['wots-signed-zero'] = 'nothing to rewrite'
FUNCTIONAL_REASONS.update({name: 'cannot save an incomplete proof' for name, *_ in PROCEDURE_CHANGES})
FUNCTIONAL_REASONS['backend-unchecked-history'] = 'the given proof-term proves:'


def functional_search_outputs(port):
    from c10_representation_controls import changed
    result = {}
    fixtures = {family: fixture(port, family) for family in ('selector', 'backend', 'wots', 'fors')}
    for family, original in fixtures.items():
        preserving = original
        if family == 'selector':
            for name in ('wots_first_slot', 'fors_first_slot'):
                preserving = changed(preserving, name, 'slot + 1', 'slot + (2 - 1)', False)
        elif family == 'backend':
            preserving = mutate(original, 'FixedBackend', 'hash', 'calls + 1', 'calls + (2 - 1)')
        elif family == 'wots':
            preserving = mutate(original, 'PairedAcceptanceWots', 'count', 'i <- i+1', 'i <- i+(2-1)')
        else:
            preserving = mutate(original, 'PairedAcceptanceGrind', 'run', 'i <- i+1', 'i <- i+(2-1)')
        for label, text in [('positive', original), ('preserving', preserving)]:
            result[port / 'scratch' / f'c10_functional_{family}_{label}.ec'] = text
    for name, operator, before, after, _ in SELECTOR_CHANGES:
        altered = changed(fixtures['selector'], operator, before, after, False)
        stem = 'c10_functional_' + name.replace('-', '_')
        result[port / 'scratch' / (stem + '_typed.ec')] = definitions_only(altered)
        result[port / 'scratch' / (stem + '_reject.ec')] = altered
    for name, family, module, procedure, before, after, _ in PROCEDURE_CHANGES:
        altered = mutate(fixtures[family], module, procedure, before, after)
        stem = 'c10_functional_' + name.replace('-', '_')
        result[port / 'scratch' / (stem + '_typed.ec')] = definitions_only(altered)
        result[port / 'scratch' / (stem + '_reject.ec')] = altered
    backend = (port / 'cdrafts-split/C10FixedBackend.ec').read_text()
    statement = re.search(r'(?ms)^lemma fixed_hash\b.*?^proof\.', backend).group().removesuffix('proof.')
    statement = statement.replace('lemma fixed_hash ', 'lemma checked ', 1)
    header = 'require import AllCore List FMap C10RawOracle C10FixedBackend.\n'
    original = header + statement + 'proof. exact (fixed_hash f h x0 c). qed.\n'
    before = 'backend_consistent h f /\\ x = x0 /\\ FixedBackend.calls = c ==>'
    if original.count(before) != 1:
        raise ValueError('functional cache-consistency premise drift')
    altered = original.replace(before, 'x = x0 /\\ FixedBackend.calls = c ==>')
    stem = 'c10_functional_backend_unchecked_history'
    result[port / 'scratch' / (stem + '_positive.ec')] = original
    result[port / 'scratch' / (stem + '_typed.ec')] = definitions_only(altered)
    result[port / 'scratch' / (stem + '_reject.ec')] = altered
    return {path: text.rstrip() + '\n' for path, text in result.items()}


def functional_search_rows():
    rows = []
    for family in ('selector', 'backend', 'wots', 'fors'):
        for label in ('positive', 'preserving'):
            rows.append(f'scratch/c10_functional_{family}_{label}.ec\tMUST-PASS\t-')
    for name, *_ in SELECTOR_CHANGES + PROCEDURE_CHANGES:
        stem = 'scratch/c10_functional_' + name.replace('-', '_')
        rows.extend([stem + '_typed.ec\tMUST-PASS\t-',
                     stem + '_reject.ec\tMUST-FAIL\t' + FUNCTIONAL_REASONS[name]])
    stem = 'scratch/c10_functional_backend_unchecked_history'
    rows.extend([stem + '_positive.ec\tMUST-PASS\t-', stem + '_typed.ec\tMUST-PASS\t-',
                 stem + '_reject.ec\tMUST-FAIL\t' + FUNCTIONAL_REASONS['backend-unchecked-history']])
    return rows
