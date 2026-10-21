"""Typed changes to the native complete-signer R observer and its contracts.

Clone only the compared procedure's module, keeping the canonical shared state
and the consuming theorem/proof. Definition-only siblings distinguish a typed
program change from a malformed fixture. Contract rejection is proof-term
sensitivity, not a claim that every altered statement is mathematically false.
"""
import re

from c10_caller_controls import mutate


# Group: definition source/module, consuming source/lemma, equivalent edit.
GROUPS = {
    'event': ('RObservedSigner', 'RObservedSigner', 'RObservedExhaustion',
              'r_observed_failure_exact', 'sign',
              'RFailure.bad \\/ accepted = None;', 'false \\/ (RFailure.bad \\/ accepted = None);'),
    'signer': ('RObservedSigner', 'RObservedSigner', 'RObservedSigner',
               'r_observed_sign_erases', 'sign',
               'RFailure.bad \\/ accepted = None;', '!!(RFailure.bad \\/ accepted = None);'),
    'session': ('FullRSession', 'FullRSession', 'FullRSession',
                'full_r_sign_erases', 'sign',
                'FullSession.sign_calls+1', 'FullSession.sign_calls+(2-1)'),
    'init': ('FullRSession', 'FullRSession', 'RAvailabilityExamples',
             'r_observer_initialization', 'init',
             'RFailure.bad <- false;', 'RFailure.bad <- !!false;'),
    'driver': ('FullRGame', 'FullRDriver', 'FullRGame',
               'full_r_driver_erases', 'run', 'return result;', 'return !!result;'),
    'context': ('FullRGame', 'FullRContext', 'FullRGame',
                'full_r_context_erases', 'run',
                'FullLimits.raw_cap,FullLimits.sign_cap',
                'FullLimits.raw_cap+0,FullLimits.sign_cap+0'),
    'returned': ('FullRGame', 'FullRFailureContext', 'FullRGame',
                 'full_r_failure_context_event', 'run',
                 'return RFailure.bad;', 'return !!RFailure.bad;'),
}

# name, group, exact procedure-local replacement
R_AVAILABILITY_CHANGES = [
    ('flag-dropped', 'event', 'RFailure.bad \\/ accepted = None', 'false'),
    ('flag-inverted', 'event', 'accepted = None;', 'accepted <> None;'),
    ('grind-message', 'signer', '.run(random,message,seed,root)', '.run(random,[],seed,root)'),
    ('finish-seed', 'signer', '.finish(seed,', '.finish([], '),
    ('failed-admission', 'session', '!FullSession.failed /\\', 'true /\\'),
    ('cap-admission', 'session', 'FullSession.sign_calls < FullSession.sign_limit',
     'FullSession.sign_calls <= FullSession.sign_limit'),
    ('message-admission', 'session', 'size message = 32', 'size message = 31'),
    ('admitted-counter', 'session', 'FullSession.sign_calls+1', 'FullSession.sign_calls+0'),
    ('failed-ledger', 'session', 'FullSession.failed <- true;', 'FullSession.failed <- false;'),
    ('message-ledger', 'session', 'rcons FullSession.signed_messages message',
     'FullSession.signed_messages'),
    ('initial-event', 'init', 'RFailure.bad <- false;', 'RFailure.bad <- true;'),
    ('final-failure-guard', 'driver', '!FullSession.failed /\\', 'true /\\'),
    ('final-message-guard', 'driver', '!List.mem FullSession.signed_messages forged.`1', 'true'),
    ('forgery-result', 'driver', 'return result;', 'return !result;'),
    ('keygen-seed', 'context', 'inputs.`3,inputs.`4,', 'inputs.`4,inputs.`4,'),
    ('initialized-cap', 'context', 'FullLimits.raw_cap,FullLimits.sign_cap',
     'FullLimits.raw_cap,FullLimits.raw_cap'),
    ('returned-event', 'returned', 'return RFailure.bad;', 'return !RFailure.bad;'),
]

R_AVAILABILITY_REASONS = {
    name: '[by]: cannot close goals' for name, *_ in R_AVAILABILITY_CHANGES
}
R_AVAILABILITY_REASONS.update({
    name: 'cannot save an incomplete proof'
    for name in ['initial-event', 'keygen-seed', 'initialized-cap', 'returned-event']
})

CONTRACT_CHECKS = [
    ('query-cap', 'RClassifiedExhaustion', 'classified_grind_exhaustion',
     'size Independent.queries <= q /\\', 'true /\\', '(classified_grind_exhaustion q)'),
    ('recorded-history', 'RClassifiedExhaustion', 'classified_grind_exhaustion',
     'history_recorded Independent.rawhistory Independent.queries /\\', 'true /\\',
     '(classified_grind_exhaustion q)'),
    ('classified-history', 'RClassifiedExhaustion', 'classified_grind_exhaustion',
     'classified_history Independent.secrethistory Independent.rawhistory seed root /\\',
     'true /\\', '(classified_grind_exhaustion q)'),
    ('initial-observer', 'RObservedExhaustion', 'r_observed_failure_exact',
     ' /\\ !RFailure.bad{2}', '', '(r_observed_failure_exact O)'),
    ('byte-caps', 'ByteRAvailability', 'byte_r_initialized_exhaustion',
     'FullLimits.sign_cap{m} = qs =>', 'true =>', '(byte_r_initialized_exhaustion A qr qs &m)'),
    ('byte-event', 'ByteRAvailability', 'byte_r_initialized_exhaustion',
     '.run() @ &m : res]', '.run() @ &m : !res]', '(byte_r_initialized_exhaustion A qr qs &m)'),
    ('byte-charge', 'ByteRAvailability', 'byte_r_initialized_exhaustion',
     'byte_r_availability_charge qr qs.', 'byte_r_availability_charge qr qs - 1%r.',
     '(byte_r_initialized_exhaustion A qr qs &m)'),
]


def _lemma(source, name):
    matches = list(re.finditer(r'(?ms)^lemma ' + re.escape(name) + r'\b.*?\bqed\.', source))
    if len(matches) != 1:
        raise ValueError('R availability lemma boundary drift: ' + name)
    return matches[0].group() + '\n'


def _header(source):
    return '\n'.join(re.findall(r'^(?:require import|import) .+$', source, re.M)) + '\n'


def _fixture(port, group):
    definition, module, consumer, theorem, *_ = GROUPS[group]
    source = (port / 'cdrafts-split' / (definition + '.ec')).read_text()
    text = (port / 'cdrafts-split' / (consumer + '.ec')).read_text()
    start = source.index('module ' + module + ' ')
    end = source.index('\n}.', start) + len('\n}.')
    block = source[start:end]
    checked = _lemma(text, theorem).replace('lemma ' + theorem, 'lemma checked', 1)
    # The imported source owns all original globals; only this module is cloned.
    header = _header(source) + _header(text) + 'require import ' + definition + ' ' + consumer + '.\n\n'
    block = re.sub(r'\b' + re.escape(module) + r'\b', 'ControlledRAvailability', block)
    checked = re.sub(r'\b' + re.escape(module) + r'\b', 'ControlledRAvailability', checked)
    return header, block + '\n\n', checked


def r_availability_outputs(port):
    outputs = {}
    for group, (_, _, _, _, proc, before, after) in GROUPS.items():
        header, block, proof = _fixture(port, group)
        stem = 'c10_r_availability_' + group
        outputs[port / 'scratch' / (stem + '_positive.ec')] = header + block + proof
        preserving = mutate(block, 'ControlledRAvailability', proc, before, after)
        outputs[port / 'scratch' / (stem + '_preserving.ec')] = header + preserving + proof
    for name, group, before, after in R_AVAILABILITY_CHANGES:
        header, block, proof = _fixture(port, group)
        changed = mutate(block, 'ControlledRAvailability', GROUPS[group][4], before, after)
        stem = 'c10_r_availability_' + name.replace('-', '_')
        outputs[port / 'scratch' / (stem + '_typed.ec')] = header + changed
        outputs[port / 'scratch' / (stem + '_reject.ec')] = header + changed + proof
    for name, module, theorem, before, after, application in CONTRACT_CHECKS:
        text = (port / 'cdrafts-split' / (module + '.ec')).read_text()
        statement = _lemma(text, theorem).split('proof.', 1)[0]
        statement = statement.replace('lemma ' + theorem, 'lemma checked', 1)
        if statement.count(before) != 1:
            raise ValueError('R availability contract anchor drift: ' + name)
        header = _header(text) + 'require import ' + module + '.\n\n'
        proof = 'proof. exact ' + application + '. qed.\n'
        stem = 'c10_r_availability_' + name.replace('-', '_')
        outputs[port / 'scratch' / (stem + '_positive.ec')] = header + statement + proof
        outputs[port / 'scratch' / (stem + '_reject.ec')] = header + statement.replace(before, after) + proof
    return outputs


def r_availability_rows():
    rows = []
    for group in GROUPS:
        for suffix in ['positive', 'preserving']:
            rows.append('scratch/c10_r_availability_' + group + '_' + suffix + '.ec\tMUST-PASS\t-')
    for name, *_ in R_AVAILABILITY_CHANGES:
        stem = 'scratch/c10_r_availability_' + name.replace('-', '_')
        rows.extend([stem + '_typed.ec\tMUST-PASS\t-',
                     stem + '_reject.ec\tMUST-FAIL\t' + R_AVAILABILITY_REASONS[name]])
    for name, *_ in CONTRACT_CHECKS:
        stem = 'scratch/c10_r_availability_' + name.replace('-', '_')
        rows.extend([stem + '_positive.ec\tMUST-PASS\t-',
                     stem + '_reject.ec\tMUST-FAIL\tthe given proof-term proves:'])
    return rows
