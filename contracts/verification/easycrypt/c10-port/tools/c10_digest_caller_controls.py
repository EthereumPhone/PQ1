"""Typed caller mutations for paired WOTS/FORS/hypertree digest computations."""
from c10_caller_controls import mutate, definitions_only

# name, module, procedure, before, after, first consuming theorem
DIGEST_CALLER_CHANGES = [
    ('fill-digit-index', 'PairedDigestWots', 'fill',
     'wots_field (bits_to_bytes accepted) i',
     'wots_field (bits_to_bytes accepted) ((i+1) %% 43)', 'digest_wots_fill'),
    ('fill-digit-digest', 'PairedDigestWots', 'fill',
     'wots_field (bits_to_bytes accepted) i',
     'wots_field (bits_to_bytes []) i', 'digest_wots_fill'),
    ('recover-digit-index', 'PairedDigestWots', 'recover',
     'wots_field (bits_to_bytes d) i',
     'wots_field (bits_to_bytes d) ((i+1) %% 43)', 'digest_wots_recover'),
    ('forest-sign-index', 'PairedDigestForest', 'sign',
     'fors_field (bits_to_bytes digest) t',
     'fors_field (bits_to_bytes digest) ((t+1) %% 12)', 'digest_forest_sign'),
    ('forest-recover-digest', 'PairedDigestForest', 'recover',
     'fors_field (bits_to_bytes digest) t',
     'fors_field (bits_to_bytes []) t', 'digest_forest_recover'),
    ('finish-ht-field', 'PairedDigestSigner', 'finish',
     'ht <- ht_field (bits_to_bytes digest)',
     'ht <- ht_field (bits_to_bytes digest)+1', 'digest_signer_finish'),
    ('verify-ht-field', 'PairedDigestSigner', 'verify',
     'ht <- ht_field (bits_to_bytes digest)',
     'ht <- ht_field (bits_to_bytes digest)+1', 'digest_signer_verify'),
    ('finish-layer-coordinate', 'PairedDigestSigner', 'finish',
     'idx_tree <- idx_tree %/ 512', 'idx_tree <- idx_tree %/ 256', 'digest_signer_finish'),
    ('wots-exhaustion', 'PairedDigestWots', 'sign',
     'return result;', 'return if result = None then Some ([],0) else result;', 'digest_wots_sign'),
]

DIGEST_CALLER_REASONS = {name: '[by]: cannot close goals' for name, *_ in DIGEST_CALLER_CHANGES}


def digest_caller_outputs(port):
    source = (port / 'cdrafts-split/C10DigestCallers.ec').read_text()
    preserving = mutate(source, 'PairedDigestWots', 'fill',
                        'wots_field (bits_to_bytes accepted) i',
                        'wots_field (bits_to_bytes accepted) (i+0)')
    preserving = mutate(preserving, 'PairedDigestSigner', 'verify',
                        'ht <- ht_field (bits_to_bytes digest)',
                        'ht <- ht_field (bits_to_bytes digest)+0')
    outputs = {
        port / 'scratch/c10_digest_caller_positive.ec': source,
        port / 'scratch/c10_digest_caller_preserving.ec': preserving,
    }
    for name, module, procedure, before, after, _ in DIGEST_CALLER_CHANGES:
        changed = mutate(source, module, procedure, before, after)
        stem = 'c10_digest_caller_' + name.replace('-', '_')
        outputs[port / 'scratch' / (stem + '_typed.ec')] = definitions_only(changed).rstrip() + '\n'
        outputs[port / 'scratch' / (stem + '_reject.ec')] = changed
    return outputs


def digest_caller_rows():
    rows = ['scratch/c10_digest_caller_positive.ec\tMUST-PASS\t-',
            'scratch/c10_digest_caller_preserving.ec\tMUST-PASS\t-']
    for name, *_ in DIGEST_CALLER_CHANGES:
        stem = 'scratch/c10_digest_caller_' + name.replace('-', '_')
        rows.extend([stem + '_typed.ec\tMUST-PASS\t-',
                     stem + '_reject.ec\tMUST-FAIL\t' + DIGEST_CALLER_REASONS[name]])
    return rows
