"""Typed undercount controls for the wrapper and its adaptive cost context.

Budget definitions and their derived identity statements change together; the
consuming cost lemmas and proofs remain byte-identical. Procedural mutations
change definitions only. Benign preservation and over-budget variants must pass.
Proof rejection establishes sensitivity, not that every mutation is false.
"""
from c10_caller_controls import definitions_only, mutate

# name, family, before, after, intended first consuming theorem
WRAPPER_COST_CHANGES = [
    ('physical-second-sign', 'budget',
     'op wrapper_physical_budget : int = 2*(4*signing_budget+435646)+771.',
     'op wrapper_physical_budget : int = 1*(4*signing_budget+435646)+771.',
     'wrapper_physical_cost'),
    ('physical-internal-verify', 'budget',
     'op wrapper_physical_budget : int = 2*(4*signing_budget+435646)+771.',
     'op wrapper_physical_budget : int = 2*(4*signing_budget+435646)+0.',
     'wrapper_physical_cost'),
    ('public-second-sign', 'budget',
     'op wrapper_public_budget : int = 2*(3*signing_budget+364892)+771.',
     'op wrapper_public_budget : int = 1*(3*signing_budget+364892)+771.',
     'wrapper_public_cost'),
    ('public-internal-verify', 'budget',
     'op wrapper_public_budget : int = 2*(3*signing_budget+364892)+771.',
     'op wrapper_public_budget : int = 2*(3*signing_budget+364892)+0.',
     'wrapper_public_cost'),
    ('prior-history-reset', 'history',
     'result <- None;', '(result, Shared.calls) <- (None, 0);',
     'wrapper_physical_cost'),
    ('third-sign', 'history',
     'valid <@ RawSigner(O).verify',
     'first <@ RawSigner(O).sign(seed,root,random,message,shuffle_a);\n          valid <@ RawSigner(O).verify',
     'wrapper_physical_cost'),
    ('refusal-charge', 'session-sign',
     'sign_calls <- sign_calls+1;',
     'if (result <> None) { sign_calls <- sign_calls+1; }',
     'wrapper_ready_refusal_charge'),
    ('sign-cap', 'session-sign',
     'sign_calls < sign_limit', 'true', 'wrapper_sign_full'),
    ('raw-cap', 'session-hash',
     'raw_calls < raw_limit', 'true', 'wrapper_raw_full'),
]

# Calibrated against the pinned toolchain before certificate enrollment.
WRAPPER_COST_REASONS = {'physical-second-sign': '[by]: cannot close goals', 'physical-internal-verify': '[by]: cannot close goals', 'public-second-sign': '[by]: cannot close goals', 'public-internal-verify': '[by]: cannot close goals', 'prior-history-reset': '[by]: cannot close goals', 'third-sign': '[by]: cannot close goals', 'refusal-charge': 'cannot save an incomplete proof', 'sign-cap': '[by]: cannot close goals', 'raw-cap': '[by]: cannot close goals'}
WRAPPER_COST_THEOREMS = {row[0]: row[-1] for row in WRAPPER_COST_CHANGES}


def splice_import(proof, anchor, definitions):
    if proof.count(anchor) != 1:
        raise ValueError('wrapper control import drift: ' + anchor)
    return proof.replace(anchor, definitions)



def change_budget(source, before, after):
    """Keep the derived identity consistent; leave the consuming proof intact."""
    if source.count(before) != 1:
        raise ValueError('wrapper budget definition drift')
    name = before.split()[1]
    old_value = before.split(' = ', 1)[1]
    new_value = after.split(' = ', 1)[1]
    identity = name + ' = ' + old_value
    if source.count(identity) != 1:
        raise ValueError('wrapper budget identity drift')
    result = source.replace(before, after).replace(identity, name + ' = ' + new_value)
    anchor = '\nlemma wrapper_physical_cost'
    if result.split(anchor, 1)[1] != source.split(anchor, 1)[1]:
        raise ValueError('budget control changed a consuming proof')
    return result


def wrapper_cost_outputs(port):
    wrapper = (port/'cdrafts-split/RawWrapperCost.ec').read_text()
    history = splice_import(wrapper, 'require import RawSigner RawSignerCost RawWrapper.',
        'require import RawSigner RawSignerCost.\n' + (port/'cdrafts-split/RawWrapper.ec').read_text())
    session = (port/'cdrafts-split/WrapperSessionCost.ec').read_text()
    session = splice_import(session,
        'require import RawSigner RawSignerCost RawWrapper RawWrapperCost WrapperSession.',
        'require import RawSigner RawSignerCost RawWrapper RawWrapperCost.\n' +
        (port/'cdrafts-split/WrapperSession.ec').read_text())
    outputs = {port/'scratch/c10_wrapper_cost_positive.ec': history,
               port/'scratch/c10_wrapper_session_cost_positive.ec': session}
    outputs[port/'scratch/c10_wrapper_cost_preserve_history_positive.ec'] = mutate(
        history, 'RawWrapper', 'sign', 'result <- None;',
        '(result, Shared.calls) <- (None, Shared.calls);')
    for kind, charge in [('physical', '4*signing_budget+435646'),
                         ('public', '3*signing_budget+364892')]:
        before = 'op wrapper_' + kind + '_budget : int = 2*(' + charge + ')+771.'
        after = before.replace('= 2*', '= 3*')
        outputs[port/'scratch'/('c10_wrapper_cost_' + kind + '_overcount_positive.ec')] = change_budget(wrapper, before, after)

    for name, family, before, after, _ in WRAPPER_COST_CHANGES:
        if family == 'budget':
            changed = change_budget(wrapper, before, after)
        elif family == 'history':
            changed = mutate(history, 'RawWrapper', 'sign', before, after)
        else:
            changed = mutate(session, 'WrapperSession', family.split('-')[1], before, after)
        stem = 'c10_wrapper_cost_' + name.replace('-', '_')
        outputs[port/'scratch'/(stem+'_typed.ec')] = definitions_only(changed)
        outputs[port/'scratch'/(stem+'_reject.ec')] = changed
    return outputs


def wrapper_cost_rows():
    rows = ['scratch/c10_wrapper_cost_positive.ec\tMUST-PASS\t-',
            'scratch/c10_wrapper_session_cost_positive.ec\tMUST-PASS\t-',
            'scratch/c10_wrapper_cost_preserve_history_positive.ec\tMUST-PASS\t-',
            'scratch/c10_wrapper_cost_physical_overcount_positive.ec\tMUST-PASS\t-',
            'scratch/c10_wrapper_cost_public_overcount_positive.ec\tMUST-PASS\t-']
    for name, *_ in WRAPPER_COST_CHANGES:
        stem = 'scratch/c10_wrapper_cost_' + name.replace('-', '_')
        rows.extend([stem+'_typed.ec\tMUST-PASS\t-',
                     stem+'_reject.ec\tMUST-FAIL\t'+WRAPPER_COST_REASONS[name]])
    return rows
