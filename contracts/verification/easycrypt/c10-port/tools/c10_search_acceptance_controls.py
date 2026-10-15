"""Typed procedural changes to the paired-acceptance search correspondence."""
from c10_caller_controls import mutate, definitions_only

# name, module, procedure, before, after, intended consuming theorem
SEARCH_ACCEPTANCE_CHANGES = [
    ('count-target', 'PairedAcceptanceWots', 'count',
     '= wots_target', '= wots_target - 1', 'paired_wots_count'),
    ('count-budget', 'PairedAcceptanceWots', 'count',
     'i < signing_budget /\\ result = None',
     'i < signing_budget - 1 /\\ result = None', 'paired_wots_count'),
    ('count-result', 'PairedAcceptanceWots', 'count',
     'result <- Some (i,d)', 'result <- Some (i+1,d)', 'paired_wots_count'),
    ('recover-target', 'PairedAcceptanceWots', 'recover',
     '= wots_target', '= wots_target - 1', 'paired_wots_recover'),
    ('recover-sentinel', 'PairedAcceptanceWots', 'recover',
     'result <- nseq 16 0', 'result <- nseq 16 1', 'paired_wots_recover'),
    ('nonce-accept', 'PairedAcceptanceGrind', 'run',
     'fors_zero_field (bits_to_bytes hd) = 0',
     'fors_zero_field (bits_to_bytes hd) <> 0', 'paired_nonce_grind'),
    ('nonce-digest', 'PairedAcceptanceGrind', 'run',
     'fors_zero_field (bits_to_bytes hd)',
     'fors_zero_field (bits_to_bytes rd)', 'paired_nonce_grind'),
    ('nonce-exhaustion', 'PairedAcceptanceGrind', 'run',
     'return result;', 'return if result = None then Some ([],[]) else result;',
     'paired_nonce_grind'),
]

# Calibrated to the pinned prover; resource/type errors are never evidence.
SEARCH_ACCEPTANCE_REASONS = {
    name: '[by]: cannot close goals' for name, *_ in SEARCH_ACCEPTANCE_CHANGES
}


def search_acceptance_outputs(port):
    source = (port / 'cdrafts-split/C10SearchAcceptance.ec').read_text()
    preserving = mutate(source, 'PairedAcceptanceWots', 'count',
                        '= wots_target', '= wots_target + 0')
    preserving = mutate(preserving, 'PairedAcceptanceGrind', 'run',
                        '= 0)', '= (1 - 1))')
    outputs = {
        port / 'scratch/c10_search_acceptance_positive.ec': source,
        port / 'scratch/c10_search_acceptance_preserving.ec': preserving,
    }
    for name, module, procedure, before, after, _ in SEARCH_ACCEPTANCE_CHANGES:
        changed = mutate(source, module, procedure, before, after)
        stem = 'c10_search_acceptance_' + name.replace('-', '_')
        outputs[port / 'scratch' / (stem + '_typed.ec')] = definitions_only(changed).rstrip() + '\n'
        outputs[port / 'scratch' / (stem + '_reject.ec')] = changed
    return outputs


def search_acceptance_rows():
    rows = ['scratch/c10_search_acceptance_positive.ec\tMUST-PASS\t-',
            'scratch/c10_search_acceptance_preserving.ec\tMUST-PASS\t-']
    for name, *_ in SEARCH_ACCEPTANCE_CHANGES:
        stem = 'scratch/c10_search_acceptance_' + name.replace('-', '_')
        rows.extend([stem + '_typed.ec\tMUST-PASS\t-',
                     stem + '_reject.ec\tMUST-FAIL\t' + SEARCH_ACCEPTANCE_REASONS[name]])
    return rows
