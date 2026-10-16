"""Typed session changes and unchanged consuming equivalences.

Rejection is proof sensitivity, not a claim that every mutant theorem is false.
Definition-only copies must compile before a proof rejection is credited.
"""
from c10_caller_controls import mutate, definitions_only

CONTRACT_CHECKS = [
    ('initial-caps', 'C10PairedInitialization', 'paired_byte_initialized',
     '={glob A,glob FullLimits,glob KeygenInputs}', '={glob A,glob KeygenInputs}',
     '(paired_byte_initialized A)'),
    ('success-event', 'C10PairedInitialization', 'paired_byte_success_probability',
     'RealGame(ByteContext(A)).run() @ &m : res',
     'RealGame(ByteContext(A)).run() @ &m : !res',
     '(paired_byte_success_probability A &m)'),
    ('numerical-charge', 'C10PairedSessionBound', 'paired_byte_wots_candidate_euf_bound',
     '<= wots_candidate_physical_euf_charge qr qs.',
     '<= wots_candidate_physical_euf_charge qr qs - 1%r.',
     '(paired_byte_wots_candidate_euf_bound A qr qs &m)'),
]


PAIRED_SESSION_CHANGES = [
    ('failed-admission', 'PairedSession', 'sign',
     '!FullSession.failed /\\', 'true /\\', 'paired_session_sign'),
    ('sign-cap', 'PairedSession', 'sign',
     'FullSession.sign_calls < FullSession.sign_limit',
     'FullSession.sign_calls <= FullSession.sign_limit', 'paired_session_sign'),
    ('message-width', 'PairedSession', 'sign',
     'size message = 32', 'size message = 31', 'paired_session_sign'),
    ('attempt-charge', 'PairedSession', 'sign',
     'FullSession.sign_calls+1', 'FullSession.sign_calls+0', 'paired_session_sign'),
    ('exhaustion', 'PairedSession', 'sign',
     'FullSession.failed <- true', 'FullSession.failed <- false', 'paired_session_sign'),
    ('returned-ledger', 'PairedSession', 'sign',
     'rcons FullSession.signed_messages message',
     'FullSession.signed_messages', 'paired_session_sign'),
    ('sign-message', 'PairedSession', 'sign',
     'FullSession.root,random,message,shuffle',
     'FullSession.root,random,[],shuffle', 'paired_session_sign'),
    ('prior-query-cost', 'PairedSession', 'sign',
     'FullSession.sign_calls <- FullSession.sign_calls+1;',
     'Shared.calls <- 0; FullSession.sign_calls <- FullSession.sign_calls+1;',
     'paired_session_sign'),
    ('failed-final', 'PairedByteDriver', 'run',
     '!FullSession.failed /\\', 'true /\\', 'paired_byte_driver'),
    ('fresh-message', 'PairedByteDriver', 'run',
     '!List.mem FullSession.signed_messages forged.`1', 'true', 'paired_byte_driver'),
    ('byte-domain', 'PairedByteDriver', 'run',
     'byte_signature forged.`2', 'size forged.`2 = 4008', 'paired_byte_driver'),
    ('verified-output', 'PairedByteDriver', 'run',
     'decode_signature forged.`2', 'decode_signature (nseq 4008 0)', 'paired_byte_driver'),
]

PAIRED_SESSION_REASONS = {
    name: '[by]: cannot close goals' for name, *_ in PAIRED_SESSION_CHANGES
}
PAIRED_SESSION_REASONS['verified-output'] = 'the given proof-term proves:'


def paired_session_outputs(port):
    source = (port / 'cdrafts-split/C10PairedSession.ec').read_text()
    preserving = mutate(source, 'PairedSession', 'sign',
                        'FullSession.sign_calls+1', 'FullSession.sign_calls+(2-1)')
    preserving = mutate(preserving, 'PairedByteDriver', 'run',
                        'size forged.`1 = 32', 'size forged.`1 = 16+16')
    outputs = {
        port / 'scratch/c10_paired_session_positive.ec': source,
        port / 'scratch/c10_paired_session_preserving.ec': preserving,
    }
    for name, module, procedure, before, after, _ in PAIRED_SESSION_CHANGES:
        changed = mutate(source, module, procedure, before, after)
        stem = 'c10_paired_session_' + name.replace('-', '_')
        outputs[port / 'scratch' / (stem + '_typed.ec')] = definitions_only(changed).rstrip() + '\n'
        outputs[port / 'scratch' / (stem + '_reject.ec')] = changed
    for name, module, theorem, before, after, application in CONTRACT_CHECKS:
        text = (port / 'cdrafts-split' / (module + '.ec')).read_text()
        start = text.index('lemma ' + theorem)
        statement = text[start:text.index('proof.', start)].replace('lemma ' + theorem, 'lemma checked', 1)
        if statement.count(before) != 1:
            raise ValueError('paired session contract mutation anchor drift: ' + name)
        header = text[:text.index('lemma ')] + 'require import ' + module + '.\n\n'
        proof = 'proof. exact ' + application + '. qed.\n'
        stem = 'c10_paired_session_' + name.replace('-', '_')
        outputs[port / 'scratch' / (stem + '_positive.ec')] = header + statement + proof
        outputs[port / 'scratch' / (stem + '_reject.ec')] = header + statement.replace(before, after) + proof
    return outputs


def paired_session_rows():
    rows = ['scratch/c10_paired_session_positive.ec\tMUST-PASS\t-',
            'scratch/c10_paired_session_preserving.ec\tMUST-PASS\t-']
    for name, *_ in PAIRED_SESSION_CHANGES:
        stem = 'scratch/c10_paired_session_' + name.replace('-', '_')
        rows.extend([stem + '_typed.ec\tMUST-PASS\t-',
                     stem + '_reject.ec\tMUST-FAIL\t' + PAIRED_SESSION_REASONS[name]])
    for name, *_ in CONTRACT_CHECKS:
        stem = 'scratch/c10_paired_session_' + name.replace('-', '_')
        rows.extend([stem + '_positive.ec\tMUST-PASS\t-',
                     stem + '_reject.ec\tMUST-FAIL\tthe given proof-term proves:'])
    return rows
