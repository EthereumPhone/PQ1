"""Typed key-preparation changes and unchanged consuming equivalences.

Rejection establishes proof sensitivity, not falsity of every changed claim.
Definition-only copies must compile before proof rejection receives credit.
"""
import re

from c10_caller_controls import mutate, definitions_only


CONTRACT_CHECKS = [
    ('initial-caps', 'C10PairedKeygen', 'paired_keygen_byte_initialized',
     '={glob A,glob FullLimits,glob KeygenInputs}', '={glob A,glob KeygenInputs}',
     '(paired_keygen_byte_initialized A)'),
    ('initial-key-input', 'C10PairedKeygen', 'paired_keygen_byte_initialized',
     '={glob A,glob FullLimits,glob KeygenInputs}', '={glob A,glob FullLimits}',
     '(paired_keygen_byte_initialized A)'),
    ('success-event', 'C10PairedKeygen', 'paired_keygen_byte_success_probability',
     'RealGame(ByteContext(A)).run() @ &m : res',
     'RealGame(ByteContext(A)).run() @ &m : !res',
     '(paired_keygen_byte_success_probability A &m)'),
    ('numerical-charge', 'C10PairedKeygenBound', 'paired_keygen_byte_wots_candidate_euf_bound',
     '<= wots_candidate_physical_euf_charge qr qs.',
     '<= wots_candidate_physical_euf_charge qr qs - 1%r.',
     '(paired_keygen_byte_wots_candidate_euf_bound A qr qs &m)'),
]


PAIRED_KEYGEN_CHANGES = [
    ('public-seed', 'PairedKeygenPreparation', 'run',
     'node KeygenInputs.public_seed', 'nseq 16 0', 'paired_keygen_preparation'),
    ('seed-padding', 'PairedKeygenPreparation', 'run',
     'seed <- pad_node (node KeygenInputs.public_seed);',
     'seed <- node KeygenInputs.public_seed;', 'paired_keygen_preparation'),
    ('root-seed', 'PairedKeygenPreparation', 'run',
     'root(seed,1,0)', 'root(nseq 32 0,1,0)', 'paired_keygen_preparation'),
    ('root-layer', 'PairedKeygenPreparation', 'run',
     'root(seed,1,0)', 'root(seed,0,0)', 'paired_keygen_preparation'),
    ('root-tree', 'PairedKeygenPreparation', 'run',
     'root(seed,1,0)', 'root(seed,1,1)', 'paired_keygen_preparation'),
    ('root-padding', 'PairedKeygenPreparation', 'run',
     'seed,pad_node root)', 'seed,root)', 'paired_keygen_preparation'),
    ('returned-random', 'PairedKeygenPreparation', 'run',
     'return (KeygenInputs.random,', 'return ([],', 'paired_keygen_preparation'),
    ('returned-message', 'PairedKeygenPreparation', 'run',
     'KeygenInputs.random,KeygenInputs.message,',
     'KeygenInputs.random,[],', 'paired_keygen_preparation'),
    ('context-seed', 'PairedKeygenByteContext', 'run',
     'inputs.`3,inputs.`4,', 'inputs.`4,inputs.`4,', 'paired_keygen_byte_context'),
    ('context-root', 'PairedKeygenByteContext', 'run',
     'inputs.`3,inputs.`4,', 'inputs.`3,inputs.`3,', 'paired_keygen_byte_context'),
    ('raw-cap', 'PairedKeygenByteContext', 'run',
     'FullLimits.raw_cap,FullLimits.sign_cap',
     'FullLimits.sign_cap,FullLimits.sign_cap', 'paired_keygen_byte_context'),
    ('sign-cap', 'PairedKeygenByteContext', 'run',
     'FullLimits.raw_cap,FullLimits.sign_cap',
     'FullLimits.raw_cap,FullLimits.raw_cap', 'paired_keygen_byte_context'),
    ('prior-query-cost', 'PairedKeygenByteContext', 'run',
     'result <@ PairedByteDriver',
     'Shared.calls <- 0; result <@ PairedByteDriver', 'paired_keygen_byte_context'),
    ('prior-history', 'PairedKeygenByteContext', 'run',
     'result <@ PairedByteDriver',
     'Shared.history <- empty; result <@ PairedByteDriver', 'paired_keygen_byte_context'),
    ('returned-result', 'PairedKeygenByteContext', 'run',
     'return result;', 'return !result;', 'paired_keygen_byte_context'),
]

PAIRED_KEYGEN_REASONS = {
    name: '[by]: cannot close goals' for name, *_ in PAIRED_KEYGEN_CHANGES
}


def paired_keygen_outputs(port):
    source = (port / 'cdrafts-split/C10PairedKeygen.ec').read_text()
    preserving = mutate(source, 'PairedKeygenPreparation', 'run',
                        'root(seed,1,0)', 'root(seed,2-1,1-1)')
    preserving = mutate(preserving, 'PairedKeygenByteContext', 'run',
                        'return result;', 'return !!result;')
    preserving = mutate(preserving, 'PairedKeygenByteContext', 'run',
                        'result <@ PairedByteDriver',
                        'Shared.calls <- Shared.calls+0; Shared.history <- Shared.history; '
                        'result <@ PairedByteDriver')
    outputs = {
        port / 'scratch/c10_paired_keygen_positive.ec': source,
        port / 'scratch/c10_paired_keygen_preserving.ec': preserving,
    }
    for name, module, procedure, before, after, _ in PAIRED_KEYGEN_CHANGES:
        changed = mutate(source, module, procedure, before, after)
        stem = 'c10_paired_keygen_' + name.replace('-', '_')
        outputs[port / 'scratch' / (stem + '_typed.ec')] = definitions_only(changed).rstrip() + '\n'
        outputs[port / 'scratch' / (stem + '_reject.ec')] = changed
    for name, module, theorem, before, after, application in CONTRACT_CHECKS:
        text = (port / 'cdrafts-split' / (module + '.ec')).read_text()
        start = text.index('lemma ' + theorem)
        statement = text[start:text.index('proof.', start)].replace('lemma ' + theorem, 'lemma checked', 1)
        if statement.count(before) != 1:
            raise ValueError('paired keygen contract mutation anchor drift: ' + name)
        header = '\n'.join(re.findall(r'^(?:require import|import) .+$', text, re.M))
        header += '\nrequire import ' + module + '.\n\n'
        proof = 'proof. exact ' + application + '. qed.\n'
        stem = 'c10_paired_keygen_' + name.replace('-', '_')
        outputs[port / 'scratch' / (stem + '_positive.ec')] = header + statement + proof
        outputs[port / 'scratch' / (stem + '_reject.ec')] = header + statement.replace(before, after) + proof
    return outputs


def paired_keygen_rows():
    rows = ['scratch/c10_paired_keygen_positive.ec\tMUST-PASS\t-',
            'scratch/c10_paired_keygen_preserving.ec\tMUST-PASS\t-']
    for name, *_ in PAIRED_KEYGEN_CHANGES:
        stem = 'scratch/c10_paired_keygen_' + name.replace('-', '_')
        rows.extend([stem + '_typed.ec\tMUST-PASS\t-',
                     stem + '_reject.ec\tMUST-FAIL\t' + PAIRED_KEYGEN_REASONS[name]])
    for name, *_ in CONTRACT_CHECKS:
        stem = 'scratch/c10_paired_keygen_' + name.replace('-', '_')
        rows.extend([stem + '_positive.ec\tMUST-PASS\t-',
                     stem + '_reject.ec\tMUST-FAIL\tthe given proof-term proves:'])
    return rows
